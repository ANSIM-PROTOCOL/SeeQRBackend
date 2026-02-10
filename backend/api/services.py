
import json
import time

import requests

from django.core.files.base import ContentFile
from django.db import IntegrityError

from .clients import (
    URLScanIOClient,
    OpenAIClient,
    GeminiClient,
    EnumModel,
    # EnumOpenAIModel,
    # EnumGeminiModel,
)
from .models import (
    URLScanIOResponse,
    EnumCategory,
    OpenAIResponse,
    GeminiResponse,
    GeneratedReport,
    ScannedURL,
)


def _serialize_openai_response(response):
    try:
        return response.model_dump(mode="json", warnings="none")
    except Exception:
        return {
            "id": getattr(response, "id", None),
            "model": getattr(response, "model", None),
            "output_text": getattr(response, "output_text", None),
        }


def _serialize_gemini_response(response):
    try:
        return response.model_dump(mode="json", warnings="none")
    except Exception:
        return {
            "model": getattr(response, "model", None),
            "text": getattr(response, "text", None),
        }


def _extract_gemini_text(response):
    text = getattr(response, "text", None)
    if text:
        return text
    try:
        candidates = getattr(response, "candidates", None) or []
        if candidates:
            content = getattr(candidates[0], "content", None)
            parts = getattr(content, "parts", None) or []
            if parts:
                return getattr(parts[0], "text", None)
    except Exception:
        pass
    return None


def urlscanio_request(
    ip: str,
    url: str,
    retries: int = 2,
    poll_delay: int = 10,
    poll_interval: int = 2,
    poll_timeout: int = 120,
):
    if not url:
        raise ValueError("URL은 필수 입력값입니다.")
    last_error = None
    for _ in range(max(0, retries) + 1):
        try:
            urlscan_client = URLScanIOClient()
            scanned = URLScanIOResponse.objects.filter(url=url).first()
            if scanned:
                if not scanned.screenshot and scanned.scan_id:
                    screenshot_bytes = urlscan_client.screenshot(str(scanned.scan_id))
                    if screenshot_bytes:
                        screenshot_name = f"{scanned.scan_id}.png"
                        scanned.screenshot = ContentFile(screenshot_bytes, name=screenshot_name)
                        scanned.save(update_fields=["screenshot", "updated_at"])
                    else:
                        task = (scanned.response or {}).get("task")
                        screenshot_url = task.get("screenshotURL") if task else None
                        if screenshot_url:
                            resp = requests.get(screenshot_url, timeout=10)
                            if resp.status_code == 200:
                                screenshot_name = f"{scanned.scan_id}.png"
                                scanned.screenshot = ContentFile(resp.content, name=screenshot_name)
                                scanned.save(update_fields=["screenshot", "updated_at"])
                return scanned

            submit_response = urlscan_client.scan_url(url=url)
            scan_id = submit_response.get("uuid") or submit_response.get("task", {}).get("uuid")
            if not scan_id:
                raise RuntimeError("urlscan 응답에 scan_id가 없습니다.")

            time.sleep(max(0, poll_delay))
            deadline = time.monotonic() + max(1, poll_timeout)
            result = None
            while time.monotonic() < deadline:
                result = urlscan_client.get_result(scan_id)
                if result:
                    break
                time.sleep(max(1, poll_interval))

            if not result:
                raise TimeoutError("urlscan 결과 대기 시간이 초과되었습니다.")

            screenshot_content = None
            screenshot_bytes = urlscan_client.screenshot(scan_id)
            if screenshot_bytes:
                screenshot_name = f"{scan_id}.png"
                screenshot_content = ContentFile(screenshot_bytes, name=screenshot_name)

            urlscan_io_response = URLScanIOResponse(
                url=url,
                ip=ip,
                scan_id=scan_id,
                response=result,
            )
            if screenshot_content:
                urlscan_io_response.screenshot = screenshot_content
            else:
                task = result.get("task")
                if task and task.get("screenshotURL"):
                    screenshot_url = task["screenshotURL"]
                    if not screenshot_bytes:
                        resp = requests.get(screenshot_url, timeout=10)
                        if resp.status_code == 200:
                            screenshot_name = f"{scan_id}.png"
                            screenshot_content = ContentFile(resp.content, name=screenshot_name)
                            urlscan_io_response.screenshot = screenshot_content
            try:
                urlscan_io_response.save()
            except IntegrityError:
                return URLScanIOResponse.objects.get(url=url)
            return urlscan_io_response
        except Exception as e:
            last_error = e
            continue
    if last_error:
        raise last_error


def _scan_url_with_openai(
    ip: str,
    url: str,
):
    client = OpenAIClient()
    response = client.scan_url(url=url)
    output_text = response.output_text
    openai_response = OpenAIResponse(
        ip=ip,
        category=EnumCategory.SCAN_URL,
        url=url,
        prompt=url,
        response=output_text,
        response_detail=_serialize_openai_response(response),
    )
    openai_response.save()
    return openai_response


def _scan_url_with_gemini(
    ip: str,
    url: str,
):
    client = GeminiClient()
    response = client.scan_url(url=url)
    output_text = _extract_gemini_text(response)
    gemini_response = GeminiResponse(
        ip=ip,
        category=EnumCategory.SCAN_URL,
        url=url,
        prompt=url,
        response=output_text,
        response_detail=_serialize_gemini_response(response),
    )
    gemini_response.save()
    return gemini_response


def scan_url(
    ip: str,
    url: str,
    model: str = EnumModel.OPENAI,
    retries: int = 3,
):
    try:
        if model == EnumModel.OPENAI:
            ai_response = _scan_url_with_openai(ip=ip, url=url)
        elif model == EnumModel.GEMINI:
            ai_response = _scan_url_with_gemini(ip=ip, url=url)
        else:
            ai_response = _scan_url_with_openai(ip=ip, url=url)

        result = json.loads(ai_response.response)
        site_name = result["site_name"]
        threat_type = result["threat_type"]
        description = result["description"]
        threat_score = result["threat_score"]

        defaults = {
            "site_name": site_name,
            "threat_type": threat_type,
            "description": description,
            "threat_score": threat_score,
            "model": model,
            "is_edit": False,
            "openai_response": ai_response if isinstance(ai_response, OpenAIResponse) else None,
            "gemini_response": ai_response if isinstance(ai_response, GeminiResponse) else None,
        }
        try:
            scanned_url, _ = ScannedURL.objects.update_or_create(url=url, defaults=defaults)
        except IntegrityError:
            scanned_url = ScannedURL.objects.filter(url=url).first()
            if scanned_url is None:
                raise
        return scanned_url
    except Exception as e:
        if retries > 0:
            return scan_url(ip, url, model=model, retries=retries - 1)
        else:
            raise e


def _generate_report_with_openai(
    ip: str,
    url: str,
    site_name: str,
    threat_type: str,
    description: str,
    threat_score: int,
):
    client = OpenAIClient()
    response = client.generate_report(
        url=url,
        site_name=site_name,
        threat_type=threat_type,
        description=description,
        threat_score=threat_score
    )
    output_text = response.output_text
    openai_response = OpenAIResponse(
        ip=ip,
        category=EnumCategory.GENERATE_REPORT,
        url=url,
        prompt=str({
            "url": url,
            "site_name": site_name,
            "threat_type": threat_type,
            "description": description,
            "threat_score": threat_score,
        }),
        response=output_text,
        response_detail=_serialize_openai_response(response),
    )
    openai_response.save()
    return openai_response


def _generate_report_with_gemini(
    ip: str,
    url: str,
    site_name: str,
    threat_type: str,
    description: str,
    threat_score: int,
):
    client = GeminiClient()
    response = client.generate_report(
        url=url,
        site_name=site_name,
        threat_type=threat_type,
        description=description,
        threat_score=threat_score
    )
    output_text = _extract_gemini_text(response)
    gemini_response = GeminiResponse(
        ip=ip,
        category=EnumCategory.GENERATE_REPORT,
        url=url,
        prompt=str({
            "url": url,
            "site_name": site_name,
            "threat_type": threat_type,
            "description": description,
            "threat_score": threat_score,
        }),
        response=output_text,
        response_detail=_serialize_gemini_response(response),
    )
    gemini_response.save()
    return gemini_response


def generate_report(
    ip: str,
    url: str,
    site_name: str,
    threat_type: str,
    description: str,
    threat_score: int,
    model: str = EnumModel.OPENAI,
    retries: int = 3
):
    try:
        threat_score = int(threat_score)
        ai_response = None
        if model == EnumModel.OPENAI:
            ai_response = _generate_report_with_openai(
                ip=ip,
                url=url,
                site_name=site_name,
                threat_type=threat_type,
                description=description,
                threat_score=threat_score
            )
        elif model == EnumModel.GEMINI:
            ai_response = _generate_report_with_gemini(
                ip=ip,
                url=url,
                site_name=site_name,
                threat_type=threat_type,
                description=description,
                threat_score=threat_score
            )
        else:
            ai_response = _generate_report_with_openai(
                ip=ip,
                url=url,
                site_name=site_name,
                threat_type=threat_type,
                description=description,
                threat_score=threat_score
            )

        result = json.loads(ai_response.response)
        result_description = (result["description"]
                                    .replace("[]()", "")
                                    .replace("()[]", "")
                                    .replace("[]", "")
                                    .replace("()", ""))
        result_reason = (result["reason"]
                                .replace("[]()", "")
                                .replace("()[]", "")
                                .replace("[]", "")
                                .replace("()", ""))

        generated_report, _ = GeneratedReport.objects.update_or_create(
            url=result["url"],
            defaults={
                "site_name": result["site_name"],
                "threat_type": result["threat_type"],
                "description": result_description,
                "probability": result["probability"],
                "reason": result_reason,
                "depth": result["depth"],
                "openai_response": ai_response if isinstance(ai_response, OpenAIResponse) else None,
                "gemini_response": ai_response if isinstance(ai_response, GeminiResponse) else None,
                "is_processed": True,
            },
        )
    except Exception as e:
        if retries > 0:
            return generate_report(
                ip=ip,
                url=url,
                site_name=site_name,
                threat_type=threat_type,
                description=description,
                threat_score=threat_score,
                model=model,
                retries=retries - 1,
            )
        else:
            raise e
    return generated_report

