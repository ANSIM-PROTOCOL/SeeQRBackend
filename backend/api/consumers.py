import hashlib
from channels.db import database_sync_to_async
from channels.generic.websocket import AsyncJsonWebsocketConsumer
from django.core.cache import cache
from urllib.parse import unquote

from .models import GeneratedReport, URLScanIOResponse, ReportJob, ScannedURL
from .ws import qr_scan_group_name, qr_scan_status_cache_key


class ReportStatusConsumer(AsyncJsonWebsocketConsumer):
    async def connect(self):
        self.url = ""
        await self.accept()

    async def receive_json(self, content, **kwargs):
        url = content.get("url")
        if not url or not isinstance(url, str):
            await self.send_json({"type": "error", "message": "url required"})
            return
        if not self.url:
            self.url = unquote(url)
            self.group_name = "report_status"
            await self.channel_layer.group_add(self.group_name, self.channel_name)
        elif self.url != unquote(url):
            await self.send_json({"type": "error", "message": "url mismatch"})
            return

        status_payload = await self._get_status(self.url)
        await self.send_json(status_payload)

    async def disconnect(self, close_code):
        if getattr(self, "group_name", None):
            await self.channel_layer.group_discard(self.group_name, self.channel_name)

    async def report_status(self, event):
        await self.send_json(event["payload"])

    @database_sync_to_async
    def _get_status(self, url):
        report_ready = GeneratedReport.objects.filter(url=url, is_processed=True).exists()
        urlscan = (
            URLScanIOResponse.objects.filter(url=url)
            .only("screenshot", "response")
            .first()
        )
        screenshot_url = None
        screenshot_ready = False
        if urlscan:
            if urlscan.screenshot:
                screenshot_ready = True
                screenshot_url = urlscan.screenshot.url
            else:
                response = urlscan.response or {}
                task = response.get("task") if response else None
                screenshot_url = task.get("screenshotURL") if task else None
                screenshot_ready = bool(screenshot_url)
        job = ReportJob.objects.filter(url=url).only("status", "last_error").first()
        job_status = job.status if job else None
        last_error = job.last_error if job else ""
        return {
            "type": "status",
            "url": url,
            "is_processed": report_ready,
            "report_ready": report_ready,
            "screenshot_ready": screenshot_ready,
            "screenshot_url": screenshot_url,
            "job_status": job_status,
            "last_error": last_error,
        }


class QrScanStatusConsumer(AsyncJsonWebsocketConsumer):
    async def connect(self):
        self.url = ""
        self.group_name = None
        await self.accept()

    async def receive_json(self, content, **kwargs):
        url = content.get("url")
        if not url or not isinstance(url, str):
            await self.send_json({"type": "error", "message": "url required"})
            return

        normalized_url = unquote(url)
        if not self.url:
            self.url = normalized_url
            self.group_name = qr_scan_group_name(self.url)
            await self.channel_layer.group_add(self.group_name, self.channel_name)
        elif self.url != normalized_url:
            await self.send_json({"type": "error", "message": "url mismatch"})
            return

        payload = await self._get_qr_scan_status(self.url)
        await self.send_json(payload)

    async def disconnect(self, close_code):
        if self.group_name:
            await self.channel_layer.group_discard(self.group_name, self.channel_name)

    async def qr_scan_status(self, event):
        await self.send_json(event["payload"])

    @database_sync_to_async
    def _get_qr_scan_status(self, url):
        cached_status = cache.get(qr_scan_status_cache_key(url), {})
        scanned = ScannedURL.objects.filter(url=url).first()
        report_job = ReportJob.objects.filter(url=url).only("status", "last_error").first()
        report_job_status = report_job.status if report_job else None
        report_last_error = report_job.last_error if report_job else ""
        report_ready = GeneratedReport.objects.filter(url=url, is_processed=True).exists()
        urlscan = (
            URLScanIOResponse.objects.filter(url=url)
            .only("screenshot", "response")
            .first()
        )
        screenshot_url = None
        screenshot_ready = False
        if urlscan:
            if urlscan.screenshot:
                screenshot_ready = True
                screenshot_url = urlscan.screenshot.url
            else:
                response = urlscan.response or {}
                task = response.get("task") if response else None
                screenshot_url = task.get("screenshotURL") if task else None
                screenshot_ready = bool(screenshot_url)

        scan_lock_key = f"qrscan:scan:{hashlib.sha1(url.encode('utf-8')).hexdigest()}"
        scan_task_running = bool(cache.get(scan_lock_key))

        if scanned:
            is_processing = False
            job_status = "SCANNED"
        else:
            if scan_task_running:
                is_processing = True
                job_status = "SCANNING"
            else:
                job_status = cached_status.get("job_status") or "PENDING"
                is_processing = job_status not in ("SCANNED", "FAILURE")

        payload = {
            "type": "qr_scan_status",
            "url": url,
            "is_processing": is_processing,
            "job_status": job_status,
            "report_job_status": report_job_status,
            "report_ready": report_ready,
            "screenshot_ready": screenshot_ready,
            "screenshot_url": screenshot_url,
        }
        if report_last_error:
            payload["report_last_error"] = report_last_error
        if cached_status.get("error"):
            payload["error"] = cached_status["error"]
        if scanned:
            payload.update(
                {
                    "site_name": scanned.site_name,
                    "threat_type": scanned.threat_type,
                    "description": scanned.description,
                    "threat_score": scanned.threat_score,
                }
            )
        return payload
