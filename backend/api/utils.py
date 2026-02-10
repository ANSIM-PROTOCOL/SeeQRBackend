
import re
from urllib.parse import urlparse

from django.http import HttpRequest


def get_client_ip(request: HttpRequest) -> str:
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[-1].strip()
    elif request.META.get('HTTP_X_REAL_IP'):
        ip = request.META.get('HTTP_X_REAL_IP')
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip


_URL_REGEX = re.compile(
    r"([a-zA-Z][a-zA-Z0-9+.-]*:(//)?[^\s<>\"]+)",
    re.IGNORECASE,
)


def extract_and_classify_url(raw: str | None) -> tuple[str | None, str | None]:
    if not raw:
        return None, None
    raw = raw.strip()
    match = _URL_REGEX.search(raw)
    if not match:
        return None, None
    candidate = match.group(1).strip()
    parsed = urlparse(candidate)
    scheme = (parsed.scheme or "").lower()
    if scheme in ("http", "https"):
        if not parsed.netloc:
            return None, None
        return candidate, "http"
    # deep link scheme
    if scheme and (parsed.netloc or parsed.path):
        return candidate, "deeplink"
    return None, None

