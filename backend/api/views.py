
import hashlib
import urllib.parse

from django.core.cache import cache
from django.contrib.auth import authenticate, login
from django.core.paginator import Paginator
from django.shortcuts import render
from django.shortcuts import redirect
from django.utils import timezone

from rest_framework.views import APIView
from rest_framework.response import Response

from .utils import get_client_ip, extract_and_classify_url
from .report_queue import ensure_generate_report_queued, ensure_urlscanio_queued
from .tasks import scan_url_task
from .models import (
    ScannedURL,
    GeneratedReport,
    ReportJob,
    URLScanIOResponse,
    Inquire,
    ScannedURLEditLog,
    GeneratedReportEditLog,
)
from .ws import notify_qr_scan_status


def _serialize_scanned_url(scanned_url: ScannedURL) -> dict:
    report_job_status = (
        ReportJob.objects.filter(url=scanned_url.url).values_list("status", flat=True).first()
    )
    return {
        "url": scanned_url.url,
        "site_name": scanned_url.site_name,
        "threat_type": scanned_url.threat_type,
        "description": scanned_url.description,
        "threat_score": scanned_url.threat_score,
        "is_processing": False,
        "job_status": "SCANNED",
        "report_job_status": report_job_status,
        "status_ws_path": "/ws/qr-scan/status/",
    }


def _processing_response(url: str) -> dict:
    return {
        "url": url,
        "site_name": "분석 대기",
        "threat_type": "분석중",
        "description": "분석 작업이 시작되었습니다. 잠시 후 다시 확인해주세요.",
        "threat_score": 2,
        "is_processing": True,
        "job_status": "SCANNING",
        "status_ws_path": "/ws/qr-scan/status/",
    }


def _get_urlscan_screenshot(url: str) -> tuple[bool, str | None]:
    urlscanio_response = (
        URLScanIOResponse.objects.filter(url=url)
        .only("screenshot", "response")
        .first()
    )
    if not urlscanio_response:
        return False, None
    if urlscanio_response.screenshot:
        return True, urlscanio_response.screenshot.url
    response = urlscanio_response.response or {}
    task = response.get("task") if response else None
    screenshot_url = task.get("screenshotURL") if task else None
    return bool(screenshot_url), screenshot_url


def _queue_qr_scan_followups(url: str, ip: str) -> None:
    ensure_urlscanio_queued(url, ip)
    scanned_url = ScannedURL.objects.filter(url=url).first()
    if scanned_url:
        ensure_generate_report_queued(scanned_url, ip)
    else:
        _queue_scan_url_task(url=url, ip=ip)


def _queue_scan_url_task(url: str, ip: str) -> None:
    GeneratedReport.objects.get_or_create(url=url, defaults={"is_processed": False})
    lock_key = f"qrscan:scan:{hashlib.sha1(url.encode('utf-8')).hexdigest()}"
    if cache.add(lock_key, "1", timeout=300):
        scan_url_task.apply_async(kwargs={"ip": ip, "url": url})


def _threat_label_from_score(score: int | None) -> str:
    if score == 1:
        return "안전"
    if score == 2:
        return "주의"
    if score == 3:
        return "위험"
    return "알 수 없음"


def _actual_threat_label(value: str | None) -> str:
    mapping = {
        Inquire.ActualThreat.SAFE: "안전",
        Inquire.ActualThreat.WARN: "주의",
        Inquire.ActualThreat.RISK: "위험",
    }
    return mapping.get(value, "알 수 없음")


def _is_admin_user(request) -> bool:
    user = getattr(request, "user", None)
    return bool(user and user.is_authenticated and user.is_staff)


def _admin_redirect(request):
    next_url = urllib.parse.quote(request.get_full_path(), safe="")
    return redirect(f"/api/login/?next={next_url}")


class QrScanView(APIView):
    def get(self, request) -> Response:
        url, url_kind = extract_and_classify_url(request.query_params.get("url", ""))
        ip = get_client_ip(request)
        if not url:
            return Response({"error": "URL이 아닙니다."})
        if url_kind == "deeplink":
            return Response({"error": "딥링크입니다."})

        scanned_url = ScannedURL.objects.filter(url=url).first()
        result = _serialize_scanned_url(scanned_url) if scanned_url else _processing_response(url)
        notify_qr_scan_status(
            url,
            is_processing=result["is_processing"],
            job_status=result["job_status"],
            site_name=result.get("site_name"),
            threat_type=result.get("threat_type"),
            description=result.get("description"),
            threat_score=result.get("threat_score"),
            report_job_status=result.get("report_job_status"),
        )
        response = Response(result)

        # 응답 반환 직후(close 시점) 후속 작업을 비동기로 큐잉
        def _enqueue_after_response():
            try:
                _queue_qr_scan_followups(url=url, ip=ip)
            except Exception:
                # qr-scan 응답은 빠르게 반환하고, 큐잉 실패는 서버 로그로만 처리
                return

        if hasattr(response, "_resource_closers"):
            response._resource_closers.append(_enqueue_after_response)
        else:
            _enqueue_after_response()
        return response


class GenerateReportView(APIView):
    def get(self, request):
        url, url_kind = extract_and_classify_url(request.query_params.get("url", ""))
        ip = get_client_ip(request)
        payload = {
            "input_payload": {},
            "report_json": None,
            "api_error": None,
            "is_processing": False,
            "job_status": None,
            "screenshot": None,
        }

        if not url:
            payload["api_error"] = "URL이 아닙니다."
            return render(request, "reports.html", payload)
        if url_kind == "deeplink":
            payload["api_error"] = "딥링크입니다."
            return render(request, "reports.html", payload)

        payload["input_payload"]["url"] = url

        screenshot_ready, screenshot_url = _get_urlscan_screenshot(url)
        if screenshot_ready and screenshot_url:
            payload["screenshot"] = screenshot_url

        generated = GeneratedReport.objects.filter(url=url, is_processed=True).first()
        if generated:
            payload["report_json"] = {
                "url": generated.url,
                "site_name": generated.site_name,
                "threat_type": generated.threat_type,
                "description": generated.description,
                "probability": generated.probability,
                "reason": generated.reason,
                "depth": generated.depth,
            }
            payload["job_status"] = ReportJob.Status.SUCCESS
        else:
            job_status = (
                ReportJob.objects.filter(url=url).values_list("status", flat=True).first()
                or None
            )
            scanned_url = ScannedURL.objects.filter(url=url).first()
            if scanned_url:
                payload["input_payload"].update(
                    {
                        "site_name": scanned_url.site_name,
                        "threat_type": scanned_url.threat_type,
                        "description": scanned_url.description,
                        "threat_score": scanned_url.threat_score,
                    }
                )
                try:
                    job = ensure_generate_report_queued(scanned_url, ip)
                except Exception as e:
                    payload["api_error"] = f"보고서 생성 큐잉 실패: {e}"
                    return render(request, "reports.html", payload)
                job_status = job.status if job else ReportJob.Status.PENDING
            else:
                _queue_scan_url_task(url=url, ip=ip)
                job_status = job_status or "SCANNING"

            payload["job_status"] = job_status or ReportJob.Status.PENDING

        if not payload["screenshot"]:
            ensure_urlscanio_queued(url, ip)

        payload["is_processing"] = not (payload["report_json"] and payload["screenshot"])
        return render(request, "reports.html", payload)


class InquireView(APIView):
    def get(self, request):
        raw_url = request.query_params.get("url", "")
        url, url_kind = extract_and_classify_url(raw_url)
        if not url or url_kind == "deeplink":
            url = ""
        scanned = ScannedURL.objects.filter(url=url).first() if url else None
        ai_score = scanned.threat_score if scanned else None
        context = {
            "target_url": url,
            "ai_threat_label": _threat_label_from_score(ai_score),
            "success": False,
            "error": None,
        }
        return render(request, "inquire.html", context)


    def post(self, request):
        ip = get_client_ip(request)
        raw_url = (request.POST.get("url") or "").strip()
        actual_threat = (request.POST.get("actual_threat") or "").strip()
        details = (request.POST.get("details") or "").strip()

        url, url_kind = extract_and_classify_url(raw_url)
        error = None
        if not url or url_kind == "deeplink":
            error = "유효한 URL을 입력해주세요."
        if actual_threat not in dict(Inquire.ActualThreat.choices):
            error = "실제 위험도를 선택해주세요."

        scanned = ScannedURL.objects.filter(url=url).first() if url else None
        ai_score = scanned.threat_score if scanned else None
        ai_label = _threat_label_from_score(ai_score)

        if error:
            return render(
                request,
                "inquire.html",
                {
                    "target_url": url,
                    "ai_threat_label": ai_label,
                    "success": False,
                    "error": error,
                },
            )

        Inquire.objects.create(
            url=url,
            ai_threat_score=ai_score,
            ai_threat_label=ai_label,
            actual_threat=actual_threat,
            details=details,
            ip=ip,
        )

        return render(
            request,
            "inquire.html",
            {
                "target_url": url,
                "ai_threat_label": ai_label,
                "success": True,
                "error": None,
            },
        )


class DashboardView(APIView):
    def get(self, request):
        if not _is_admin_user(request):
            return _admin_redirect(request)
        status = request.query_params.get("status", "all")
        q = (request.query_params.get("q") or "").strip()
        page_number = request.query_params.get("page", "1")

        inquiries = Inquire.objects.all().order_by("-created_at")
        if status == "accepted":
            inquiries = inquiries.filter(is_accept=True)
        elif status == "pending":
            inquiries = inquiries.filter(is_accept=False)

        if q:
            inquiries = inquiries.filter(url__icontains=q)

        paginator = Paginator(inquiries, 12)
        page_obj = paginator.get_page(page_number)

        return render(
            request,
            "dashboard.html",
            {
                "inquiries": page_obj.object_list,
                "page_obj": page_obj,
                "paginator": paginator,
                "status": status,
                "q": q,
            },
        )


class InquireEditView(APIView):
    def get(self, request, inquire_id: int):
        if not _is_admin_user(request):
            return _admin_redirect(request)
        inquiry = Inquire.objects.filter(id=inquire_id).first()
        if not inquiry:
            return render(request, "edit.html", {"error": "문의 정보를 찾을 수 없습니다."})

        scanned = ScannedURL.objects.filter(url=inquiry.url).first()
        report = GeneratedReport.objects.filter(url=inquiry.url).first()

        return render(
            request,
            "edit.html",
            {
                "inquiry": inquiry,
                "scanned": scanned,
                "report": report,
                "actual_threat_label": _actual_threat_label(inquiry.actual_threat),
                "ai_threat_label": inquiry.ai_threat_label or "알 수 없음",
                "success": False,
                "error": None,
            },
        )


    def post(self, request, inquire_id: int):
        if not _is_admin_user(request):
            return _admin_redirect(request)
        inquiry = Inquire.objects.filter(id=inquire_id).first()
        if not inquiry:
            return render(request, "edit.html", {"error": "문의 정보를 찾을 수 없습니다."})

        scanned = ScannedURL.objects.filter(url=inquiry.url).first()
        report = GeneratedReport.objects.filter(url=inquiry.url).first()
        ip = get_client_ip(request)

        if scanned:
            ScannedURLEditLog.objects.create(
                scanned_url=scanned,
                site_name=scanned.site_name,
                threat_type=scanned.threat_type,
                description=scanned.description,
                threat_score=scanned.threat_score,
                edited_ip=ip,
            )

            scanned.site_name = (request.POST.get("scanned_site_name") or "").strip() or None
            scanned.threat_type = (request.POST.get("scanned_threat_type") or "").strip() or None
            scanned.description = (request.POST.get("scanned_description") or "").strip() or None
            threat_score_raw = (request.POST.get("scanned_threat_score") or "").strip()
            try:
                scanned.threat_score = int(threat_score_raw) if threat_score_raw else None
            except ValueError:
                scanned.threat_score = None
            scanned.is_edit = True
            scanned.save(update_fields=[
                "site_name",
                "threat_type",
                "description",
                "threat_score",
                "is_edit",
                "updated_at",
            ])

        if report:
            GeneratedReportEditLog.objects.create(
                generated_report=report,
                site_name=report.site_name,
                threat_type=report.threat_type,
                description=report.description,
                probability=report.probability,
                reason=report.reason,
                edited_ip=ip,
            )

            report.site_name = (request.POST.get("report_site_name") or "").strip() or None
            report.threat_type = (request.POST.get("report_threat_type") or "").strip() or None
            report.description = (request.POST.get("report_description") or "").strip() or None
            probability_raw = (request.POST.get("report_probability") or "").strip()
            try:
                report.probability = int(probability_raw) if probability_raw else None
            except ValueError:
                report.probability = None
            report.reason = (request.POST.get("report_reason") or "").strip() or None
            report.is_edit = True
            report.save(update_fields=[
                "site_name",
                "threat_type",
                "description",
                "probability",
                "reason",
                "is_edit",
                "updated_at",
            ])

        if not inquiry.is_accept:
            inquiry.is_accept = True
            inquiry.accept_at = timezone.now()
            inquiry.save(update_fields=["is_accept", "accept_at", "updated_at"])

        return render(
            request,
            "edit.html",
            {
                "inquiry": inquiry,
                "scanned": scanned,
                "report": report,
                "actual_threat_label": _actual_threat_label(inquiry.actual_threat),
                "ai_threat_label": inquiry.ai_threat_label or "알 수 없음",
                "success": True,
                "error": None,
            },
        )


class LoginView(APIView):
    def get(self, request):
        return render(
            request,
            "login.html",
            {
                "error": None,
                "next": request.query_params.get("next", "")
            },
        )


    def post(self, request):
        username = (request.POST.get("username") or "").strip()
        password = (request.POST.get("password") or "").strip()
        next_url = (request.POST.get("next") or "").strip()
        user = authenticate(request, username=username, password=password)

        if user and user.is_staff:
            login(request, user)
            return redirect(next_url or "/api/dashboard/")

        return render(
            request,
            "login.html",
            {
                "error": "관리자 계정으로 로그인해주세요.",
                "next": next_url,
            },
        )
