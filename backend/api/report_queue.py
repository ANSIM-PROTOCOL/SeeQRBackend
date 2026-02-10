import uuid
import hashlib
from datetime import timedelta

from django.conf import settings
from django.core.cache import cache
from django.db import transaction
from django.utils import timezone

from .models import ReportJob, GeneratedReport, ScannedURL, URLScanIOResponse
from .tasks import generate_report_task, urlscanio_task


def ensure_urlscanio_queued(url: str, ip: str) -> None:
    existing = URLScanIOResponse.objects.filter(url=url).only("screenshot").first()
    if existing and existing.screenshot:
        return
    lock_key = f"urlscan:queue:{hashlib.sha1(url.encode('utf-8')).hexdigest()}"
    if cache.add(lock_key, "1", timeout=300):
        urlscanio_task.apply_async(kwargs={"url": url, "ip": ip})


def ensure_generate_report_queued(scanned: ScannedURL, ip: str) -> ReportJob | None:
    """
    - GeneratedReport가 이미 있으면 큐잉하지 않음
    - ReportJob(url unique)로 중복 실행 방지
    - 이미 PENDING/STARTED면 그대로 유지
    - 커밋 이후(on_commit)에만 celery task 발행
    """
    generated_report, _ = GeneratedReport.objects.get_or_create(
        url=scanned.url,
        defaults={"is_processed": False},
    )
    existing_report = generated_report
    if existing_report and existing_report.is_processed:
        ReportJob.objects.update_or_create(
            url=scanned.url,
            defaults={"status": ReportJob.Status.SUCCESS, "last_error": ""},
        )
        return None

    with transaction.atomic():
        job, _ = ReportJob.objects.select_for_update().get_or_create(url=scanned.url)

        # 진행 중 작업이 매우 오래 갱신되지 않으면 stale로 간주하고 자동 복구
        if job.status in (ReportJob.Status.PENDING, ReportJob.Status.STARTED) and job.task_id:
            stale_seconds = max(60, int(getattr(settings, "REPORT_JOB_STALE_SECONDS", 2700)))
            stale_cutoff = timezone.now() - timedelta(seconds=stale_seconds)
            if job.updated_at and job.updated_at >= stale_cutoff:
                return job
            job.status = ReportJob.Status.FAILURE
            job.last_error = (
                f"작업 상태 업데이트가 {stale_seconds}초 이상 없어 자동으로 재시도합니다."
            )
            job.finished_at = timezone.now()
            job.save(update_fields=["status", "last_error", "finished_at", "updated_at"])

        # (실패/성공 이후 재시도 포함) 새 task 발행
        task_id = uuid.uuid4().hex
        job.task_id = task_id
        job.status = ReportJob.Status.PENDING
        job.last_error = ""
        job.started_at = None
        job.finished_at = None
        job.save(update_fields=["task_id", "status", "last_error", "started_at", "finished_at", "updated_at"])

        job_id = job.id
    def _dispatch():
        generate_report_task.apply_async(
            kwargs={
                "job_id": job_id,
                "ip": ip,
                "url": scanned.url,
                "site_name": scanned.site_name,
                "threat_type": scanned.threat_type,
                "description": scanned.description,
                "threat_score": int(scanned.threat_score),
            },
            task_id=task_id,
        )

    transaction.on_commit(_dispatch)
    return job
