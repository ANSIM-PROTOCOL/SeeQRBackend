
import json
import time
import urllib.error
import urllib.request

import openai
from google import genai
from google.genai import types as genai_types

from django.conf import settings

from .prompts import PROMPTS, EnumCategory


_URLSCANIO_API_KEY = settings.URLSCANIO_API_KEY
_OPENAI_API_KEY = settings.OPENAI_API_KEY
_GEMINI_API_KEY = settings.GEMINI_API_KEY


class EnumModel:
    OPENAI = "openai"
    GEMINI = "gemini"


class EnumOpenAIModel:
    GPT_4 = "gpt-4"
    GPT_4_TURBO = "gpt-4-turbo"
    GPT_4O = "gpt-4o"
    GPT_4O_MINI = "gpt-4o-mini"
    GPT_4O_SEARCH_PREVIEW = "gpt-4o-search-preview"
    GPT_5_MINI = "gpt-5-mini"
    GPT_5_2 = "gpt-5.2"


class EnumGeminiModel:
    GEMINI_3_PRO_PREVIEW = "gemini-3-pro-preview"
    GEMINI_3_FLASH_PREVIEW = "gemini-3-flash-preview"
    GEMINI_2_5_PRO = "gemini-2.5-pro"
    GEMINI_2_5_FLASH = "gemini-2.5-flash"
    GEMINI_2_5_FLASH_LITE = "gemini-2.5-flash-lite"


class URLScanIOClient:
    def __init__(self, api_key: str = _URLSCANIO_API_KEY):
        self.api_key = api_key
        self.base_url = "https://urlscan.io"


    def _request(self, method: str, path: str, json_body: dict | None = None, timeout: int = 30):
        url = f"{self.base_url}{path}"
        data = None
        headers = {"api-key": self.api_key}
        if json_body is not None:
            data = json.dumps(json_body).encode("utf-8")
            headers["Content-Type"] = "application/json"
            headers["Accept"] = "application/json"

        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.status, resp.read(), resp.headers
        except urllib.error.HTTPError as e:
            return e.code, e.read(), e.headers


    def scan_url(self, url: str):
        status, body, _ = self._request(
            "POST",
            "/api/v1/scan",
            json_body={"url": url, "visibility": "public"},
        )
        if status != 200:
            raise RuntimeError(f"urlscan scan failed (status={status})")
        return json.loads(body)


    def get_result(self, scan_id: str):
        status, body, _ = self._request("GET", f"/api/v1/result/{scan_id}/")
        if status == 404:
            return None
        if status == 410:
            raise RuntimeError("urlscan result deleted (410)")
        if status != 200:
            raise RuntimeError(f"urlscan result failed (status={status})")
        return json.loads(body)


    def screenshot(self, scan_id: str):
        status, body, _ = self._request("GET", f"/screenshots/{scan_id}.png")
        if status == 404:
            return None
        if status != 200:
            raise RuntimeError(f"urlscan screenshot failed (status={status})")
        return body


class OpenAIClient:
    def __init__(
        self,
        api_key: str = _OPENAI_API_KEY,
        request_timeout: int = 30,
        poll_interval: int = 2,
        poll_timeout: int = 240,
        use_background: bool = True,
    ):
        self.api_key = api_key
        self.client = openai.OpenAI(
            api_key=self.api_key,
            timeout=request_timeout,
            max_retries=2,
        )
        self.poll_interval = max(1, poll_interval)
        self.poll_timeout = max(10, poll_timeout)
        self.use_background = use_background


    def _wait_for_response(self, response_id: str):
        deadline = time.monotonic() + self.poll_timeout
        delay = self.poll_interval
        while time.monotonic() < deadline:
            resp = self.client.responses.retrieve(response_id)
            status = getattr(resp, "status", None)
            if status == "completed":
                return resp
            if status in ("failed", "canceled"):
                raise RuntimeError(f"OpenAI 응답이 실패했습니다. status={status}")
            time.sleep(delay)
            delay = min(delay * 1.5, 10)
        raise TimeoutError("OpenAI 응답 대기 시간이 초과되었습니다.")


    def _create_response(self, **kwargs):
        use_background = kwargs.pop("use_background", self.use_background)
        if not use_background:
            return self.client.responses.create(**kwargs)
        try:
            initial = self.client.responses.create(
                **kwargs,
                background=True,
                store=True,
            )
            return self._wait_for_response(initial.id)
        except openai.BadRequestError:
            # 배경 모드가 허용되지 않는 경우(예: ZDR) 일반 요청으로 폴백
            return self.client.responses.create(**kwargs)


    def scan_url(
        self,
        url: str,
        model: str = EnumOpenAIModel.GPT_5_MINI
    ):
        response = self._create_response(
            model=model,
            tools=[{"type": "web_search"}],
            tool_choice="auto",
            reasoning={"effort": "low"},
            text={"verbosity": "low"},
            input=[
                {"role": "developer", "content": PROMPTS[EnumCategory.SCAN_URL]},
                {"role": "user", "content": url},
            ],
        )
        return response


    def generate_report(
        self,
        url: str,
        site_name: str,
        threat_type: str,
        description: str,
        threat_score: int,
        model: str = EnumOpenAIModel.GPT_5_MINI
    ):
        input_content = str({
            "url": url,
            "site_name": site_name,
            "threat_type": threat_type,
            "description": description,
            "threat_score": threat_score,
        })
        response = self._create_response(
            model=model,
            tools=[{"type": "web_search"}],
            tool_choice="auto",
            reasoning={"effort": "medium"},
            text={"verbosity": "low"},
            input=[
                {"role": "developer", "content": PROMPTS[EnumCategory.GENERATE_REPORT]},
                {"role": "user", "content": input_content},
            ],
        )
        return response


class GeminiClient:
    def __init__(self, api_key: str = _GEMINI_API_KEY):
        self.api_key = api_key
        self.client = genai.Client(api_key=self.api_key)


    def _build_contents(self, prompt: str, user_content: str):
        return [
            genai_types.Content(role="system", parts=[genai_types.Part(text=prompt)]),
            genai_types.Content(role="user", parts=[genai_types.Part(text=user_content)]),
        ]


    def scan_url(
        self,
        url: str,
        model: str = EnumGeminiModel.GEMINI_3_FLASH_PREVIEW
    ):
        response = self.client.models.generate_content(
            model=model,
            contents=self._build_contents(PROMPTS[EnumCategory.SCAN_URL], url),
            config=genai_types.GenerateContentConfig(
                tools=[genai_types.Tool(google_search=genai_types.GoogleSearch())],
                thinking_config=genai_types.ThinkingConfig(thinking_level="low"),
                response_mime_type="application/json",
            )
        )
        return response


    def generate_report(
        self,
        url: str,
        site_name: str,
        threat_type: str,
        description: str,
        threat_score: int,
        model: str = EnumGeminiModel.GEMINI_3_FLASH_PREVIEW
    ):
        input_content = str({
            "url": url,
            "site_name": site_name,
            "threat_type": threat_type,
            "description": description,
            "threat_score": threat_score,
        })
        response = self.client.models.generate_content(
            model=model,
            contents=self._build_contents(PROMPTS[EnumCategory.GENERATE_REPORT], input_content),
            config=genai_types.GenerateContentConfig(
                tools=[genai_types.Tool(google_search=genai_types.GoogleSearch())],
                thinking_config=genai_types.ThinkingConfig(thinking_level="medium"),
                response_mime_type="application/json",
            )
        )
        return response

