import hashlib
import socket
import urllib.error

import openai
import requests
from celery import shared_task
from django.conf import settings
from django.core.cache import cache
from django.core.files.base import ContentFile
from django.db.models import Q
from django.utils import timezone

from .clients import URLScanIOClient
from .models import ReportJob, GeneratedReport, ScannedURL, URLScanIOResponse
from .services import generate_report as sync_generate_report
from .services import scan_url as sync_scan_url
from .services import urlscanio_request as sync_urlscanio_request
from .ws import notify_qr_scan_status, notify_report_status, notify_urlscan_status


_OPENAI_TRANSIENT_EXCEPTIONS = tuple(
    exc
    for exc in (
        getattr(openai, "APIConnectionError", None),
        getattr(openai, "APITimeoutError", None),
        getattr(openai, "RateLimitError", None),
        getattr(openai, "InternalServerError", None),
        getattr(openai, "APIError", None),
    )
    if isinstance(exc, type)
)

TRANSIENT_TASK_EXCEPTIONS = _OPENAI_TRANSIENT_EXCEPTIONS + (
    urllib.error.URLError,
    TimeoutError,
    ConnectionError,
    socket.timeout,
)


def _retry_countdown(retries: int, base: int = 4, cap: int = 180) -> int:
    return min(cap, base * (2 ** max(0, retries)))


def _extract_urlscan_screenshot_url(response: URLScanIOResponse | None) -> str | None:
    if not response:
        return None
    if response.screenshot:
        return response.screenshot.url
    payload = response.response or {}
    task = payload.get("task") if payload else None
    return task.get("screenshotURL") if task else None


@shared_task(
    bind=True,
    name="api.generate_report_task",
    max_retries=6,
    acks_late=True,
    reject_on_worker_lost=True,
)
def generate_report_task(
    self,
    job_id: int,
    ip: str,
    url: str,
    site_name: str,
    threat_type: str,
    description: str,
    threat_score: int,
):
    job = ReportJob.objects.filter(id=job_id).first()

    try:
        existing = GeneratedReport.objects.filter(url=url).first()
        if existing and (existing.openai_response is not None or existing.gemini_response is not None):
            if job:
                job.status = ReportJob.Status.SUCCESS
                job.generated_report = existing
                job.finished_at = timezone.now()
                job.last_error = ""
                job.save(update_fields=["status", "generated_report", "finished_at", "last_error", "updated_at"])
            GeneratedReport.objects.filter(url=url, is_processed=False).update(is_processed=True)
            notify_report_status(url, is_processed=True, job_status=ReportJob.Status.SUCCESS)
            return {"status": "already_exists", "url": url}

        if job:
            update_fields = ["status", "last_error", "updated_at"]
            job.status = ReportJob.Status.STARTED
            job.last_error = ""
            if not job.started_at:
                job.started_at = timezone.now()
                update_fields.append("started_at")
            job.save(update_fields=update_fields)
        notify_report_status(url, is_processed=False, job_status=ReportJob.Status.STARTED)

        generated = sync_generate_report(
            ip=ip,
            url=url,
            site_name=site_name,
            threat_type=threat_type,
            description=description,
            threat_score=threat_score,
            model=getattr(settings, "AGENT_MODEL", "openai"),
        )
        GeneratedReport.objects.filter(url=url, is_processed=False).update(is_processed=True)

        if job:
            job.status = ReportJob.Status.SUCCESS
            job.generated_report = generated
            job.finished_at = timezone.now()
            job.last_error = ""
            job.save(update_fields=["status", "generated_report", "finished_at", "last_error", "updated_at"])

        notify_report_status(url, is_processed=True, job_status=ReportJob.Status.SUCCESS)
        return {"status": "success", "url": url}

    except TRANSIENT_TASK_EXCEPTIONS as e:
        retry_count = self.request.retries + 1
        max_retries = self.max_retries or 0
        if self.request.retries >= max_retries:
            if job:
                job.status = ReportJob.Status.FAILURE
                job.last_error = str(e)
                job.finished_at = timezone.now()
                job.save(update_fields=["status", "last_error", "finished_at", "updated_at"])
            notify_report_status(
                url,
                is_processed=False,
                job_status=ReportJob.Status.FAILURE,
                last_error=str(e),
            )
            raise

        if job:
            job.status = ReportJob.Status.STARTED
            job.last_error = f"일시적 네트워크 오류로 재시도 중 ({retry_count}/{max_retries + 1})"
            job.save(update_fields=["status", "last_error", "updated_at"])
        notify_report_status(
            url,
            is_processed=False,
            job_status=ReportJob.Status.STARTED,
            last_error=str(e),
            retrying=True,
            retry_count=retry_count,
        )
        raise self.retry(exc=e, countdown=_retry_countdown(self.request.retries))

    except Exception as e:
        if job:
            job.status = ReportJob.Status.FAILURE
            job.last_error = str(e)
            job.finished_at = timezone.now()
            job.save(update_fields=["status", "last_error", "finished_at", "updated_at"])
        notify_report_status(
            url,
            is_processed=False,
            job_status=ReportJob.Status.FAILURE,
            last_error=str(e),
        )
        raise


@shared_task(
    bind=True,
    name="api.urlscanio_task",
    max_retries=6,
    acks_late=True,
    reject_on_worker_lost=True,
)
def urlscanio_task(self, ip: str, url: str):
    queue_lock_key = f"urlscan:queue:{hashlib.sha1(url.encode('utf-8')).hexdigest()}"
    try:
        resp = sync_urlscanio_request(ip=ip, url=url)
        screenshot_url = _extract_urlscan_screenshot_url(resp)
        screenshot_ready = bool(screenshot_url)
        notify_urlscan_status(url, screenshot_ready=screenshot_ready, screenshot_url=screenshot_url)
        cache.delete(queue_lock_key)
        return {
            "status": "success",
            "url": url,
            "scan_id": str(resp.scan_id) if resp else None,
        }

    except TRANSIENT_TASK_EXCEPTIONS as e:
        retry_count = self.request.retries + 1
        max_retries = self.max_retries or 0
        if self.request.retries >= max_retries:
            cache.delete(queue_lock_key)
            notify_urlscan_status(url, screenshot_ready=False, last_error=str(e))
            raise

        cache.set(queue_lock_key, "1", timeout=300)
        notify_urlscan_status(
            url,
            screenshot_ready=False,
            retrying=True,
            retry_count=retry_count,
            last_error=str(e),
        )
        raise self.retry(exc=e, countdown=_retry_countdown(self.request.retries, base=5, cap=180))

    except Exception as e:
        cache.delete(queue_lock_key)
        notify_urlscan_status(url, screenshot_ready=False, last_error=str(e))
        raise


@shared_task(name="api.urlscanio_screenshot_poll_task")
def urlscanio_screenshot_poll_task():
    client = URLScanIOClient()
    pending = URLScanIOResponse.objects.filter(Q(screenshot__isnull=True) | Q(screenshot=""))
    updated_count = 0

    for scanned in pending:
        if scanned.screenshot:
            continue

        response = scanned.response or {}
        task = response.get("task") if response else None
        screenshot_url = task.get("screenshotURL") if task else None

        if not screenshot_url and scanned.scan_id:
            result = client.get_result(str(scanned.scan_id))
            if result:
                scanned.response = result
                scanned.save(update_fields=["response", "updated_at"])
                task = result.get("task") if result else None
                screenshot_url = task.get("screenshotURL") if task else None

        if screenshot_url:
            resp = requests.get(screenshot_url, timeout=10)
            if resp.status_code == 200:
                screenshot_name = f"{scanned.scan_id}.png"
                scanned.screenshot = ContentFile(resp.content, name=screenshot_name)
                scanned.save(update_fields=["screenshot", "updated_at"])
                updated_count += 1
                notify_urlscan_status(
                    scanned.url,
                    screenshot_ready=True,
                    screenshot_url=scanned.screenshot.url,
                )

    return {"checked": pending.count(), "updated": updated_count}


@shared_task(
    bind=True,
    name="api.scan_url_task",
    max_retries=6,
    acks_late=True,
    reject_on_worker_lost=True,
)
def scan_url_task(self, ip: str, url: str):
    from .report_queue import ensure_generate_report_queued

    scan_lock_key = f"qrscan:scan:{hashlib.sha1(url.encode('utf-8')).hexdigest()}"
    notify_qr_scan_status(url, is_processing=True, job_status="SCANNING")
    try:
        scanned = ScannedURL.objects.filter(url=url).first()
        if not scanned:
            scanned = sync_scan_url(ip=ip, url=url, model=getattr(settings, "AGENT_MODEL", "openai"))
        job = ensure_generate_report_queued(scanned, ip)
        notify_qr_scan_status(
            url,
            is_processing=False,
            job_status="SCANNED",
            site_name=scanned.site_name,
            threat_type=scanned.threat_type,
            description=scanned.description,
            threat_score=scanned.threat_score,
            report_job_status=job.status if job else ReportJob.Status.SUCCESS,
        )
        cache.delete(scan_lock_key)
        return {"status": "success", "url": url, "job_id": job.id if job else None}

    except TRANSIENT_TASK_EXCEPTIONS as e:
        retry_count = self.request.retries + 1
        max_retries = self.max_retries or 0
        if self.request.retries >= max_retries:
            cache.delete(scan_lock_key)
            notify_qr_scan_status(url, is_processing=False, job_status="FAILURE", error=str(e))
            raise

        cache.set(scan_lock_key, "1", timeout=300)
        notify_qr_scan_status(
            url,
            is_processing=True,
            job_status="SCANNING",
            error=f"네트워크 오류로 재시도 중 ({retry_count}/{max_retries + 1})",
            retrying=True,
            retry_count=retry_count,
        )
        raise self.retry(exc=e, countdown=_retry_countdown(self.request.retries, base=4, cap=120))

    except Exception as e:
        cache.delete(scan_lock_key)
        notify_qr_scan_status(url, is_processing=False, job_status="FAILURE", error=str(e))
        raise
