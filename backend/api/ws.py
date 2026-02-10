import asyncio
import hashlib
import logging

from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer
from django.core.cache import cache

logger = logging.getLogger(__name__)


def _safe_group_send(group_name: str, event: dict) -> None:
    channel_layer = get_channel_layer()
    if not channel_layer:
        return
    try:
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None

        if loop and loop.is_running():
            loop.create_task(channel_layer.group_send(group_name, event))
        else:
            async_to_sync(channel_layer.group_send)(group_name, event)
    except Exception:
        # 상태 알림 실패가 비즈니스 작업 자체를 실패시키지 않도록 방어
        logger.exception("Failed to dispatch websocket status event. group=%s", group_name)


def _send_status(url: str, payload: dict) -> None:
    _safe_group_send(
        "report_status",
        {
            "type": "report_status",
            "payload": {"type": "status", "url": url, **payload},
        },
    )


def qr_scan_group_name(url: str) -> str:
    return f"qr_scan_status_{hashlib.sha1(url.encode('utf-8')).hexdigest()}"


def qr_scan_status_cache_key(url: str) -> str:
    return f"qr_scan:last_status:{hashlib.sha1(url.encode('utf-8')).hexdigest()}"


def _persist_qr_scan_status(url: str, payload: dict) -> dict:
    cache_key = qr_scan_status_cache_key(url)
    existing = cache.get(cache_key, {})
    merged = {"url": url, **existing, **payload}
    cache.set(cache_key, merged, timeout=600)
    return merged


def _send_qr_scan_status(url: str, payload: dict) -> None:
    merged_payload = _persist_qr_scan_status(url, payload)
    _safe_group_send(
        qr_scan_group_name(url),
        {
            "type": "qr_scan_status",
            "payload": {"type": "qr_scan_status", **merged_payload},
        },
    )


def notify_report_status(
    url: str,
    is_processed: bool,
    job_status: str | None = None,
    last_error: str | None = None,
    retrying: bool | None = None,
    retry_count: int | None = None,
):
    payload = {
        "is_processed": is_processed,
        "report_ready": is_processed,
    }
    if job_status:
        payload["job_status"] = job_status
    if last_error:
        payload["last_error"] = last_error
    if retrying is not None:
        payload["retrying"] = bool(retrying)
    if retry_count is not None:
        payload["retry_count"] = int(retry_count)
    _send_status(url, payload)
    _send_qr_scan_status(
        url,
        {
            "report_ready": is_processed,
            "report_job_status": job_status,
            "report_last_error": last_error,
        },
    )


def notify_urlscan_status(
    url: str,
    screenshot_ready: bool,
    screenshot_url: str | None = None,
    retrying: bool | None = None,
    retry_count: int | None = None,
    last_error: str | None = None,
):
    payload = {"screenshot_ready": screenshot_ready}
    if screenshot_url:
        payload["screenshot_url"] = screenshot_url
    if retrying is not None:
        payload["retrying"] = bool(retrying)
    if retry_count is not None:
        payload["retry_count"] = int(retry_count)
    if last_error:
        payload["last_error"] = last_error
    _send_status(url, payload)
    _send_qr_scan_status(url, payload)


def notify_qr_scan_status(url: str, **payload):
    _send_qr_scan_status(url, payload)
