"""Bounded HTTPS requests to fixed upstreams, with retries and no redirects."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CISA_FEED = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
MAX_BODY_BYTES = 100 * 1024 * 1024


class FetchError(RuntimeError):
    """A sanitized upstream failure; credentials never appear in the message."""


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


@dataclass
class JsonResponse:
    status: int
    data: object
    headers: dict[str, str]


def retry_delay(value: str | None, attempt: int) -> float:
    if value:
        try:
            delay = float(value)
        except ValueError:
            try:
                moment = parsedate_to_datetime(value)
                if moment.tzinfo is None:
                    moment = moment.replace(tzinfo=timezone.utc)
                delay = (moment - datetime.now(timezone.utc)).total_seconds()
            except (TypeError, ValueError, OverflowError):
                delay = 0
        if delay > 0:
            return min(delay, 120.0)
    return min(2.0 ** attempt, 60.0)


class JsonClient:
    def __init__(self, *, min_interval: float = 0.0, timeout: float = 45.0, max_attempts: int = 5):
        self.min_interval = min_interval
        self.timeout = timeout
        self.max_attempts = max_attempts
        self._last_request: float | None = None
        self._opener = build_opener(NoRedirect())

    def get(self, url: str, headers: dict[str, str] | None = None) -> JsonResponse:
        parts = urlsplit(url)
        allowed = ((parts.scheme, parts.netloc, parts.path) == ("https", "services.nvd.nist.gov", "/rest/json/cves/2.0")
                   or (parts.scheme, parts.netloc, parts.path) == ("https", "www.cisa.gov", "/sites/default/files/feeds/known_exploited_vulnerabilities.json"))
        if not allowed or parts.fragment:
            raise FetchError("Only the fixed NVD API and CISA KEV HTTPS feed are allowed")
        supplied = headers or {}
        if any(not isinstance(value, str) or any(ord(char) < 32 or ord(char) > 126 for char in value) or len(value) > 1024 for value in supplied.values()):
            raise FetchError("Invalid upstream request header")
        if any(name.lower() == "apikey" for name in supplied) and parts.netloc != "services.nvd.nist.gov":
            raise FetchError("NVD credentials cannot be sent to another upstream")
        request = Request(url, headers={"User-Agent": "VulnerabilityLandscape/1.0 (portfolio cache)", "Accept": "application/json", **supplied})
        for attempt in range(self.max_attempts):
            if self._last_request is not None:
                time.sleep(max(0.0, self.min_interval - (time.monotonic() - self._last_request)))
            self._last_request = time.monotonic()
            try:
                with self._opener.open(request, timeout=self.timeout) as response:
                    if response.status != 200:
                        raise FetchError(f"Upstream returned HTTP {response.status}")
                    body = response.read(MAX_BODY_BYTES + 1)
                    if len(body) > MAX_BODY_BYTES:
                        raise FetchError("Upstream response exceeded the size limit")
                    try:
                        data = json.loads(body.decode("utf-8"), parse_constant=lambda value: (_ for _ in ()).throw(ValueError("Non-finite JSON number")))
                    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
                        raise FetchError("Upstream returned invalid JSON") from exc
                    return JsonResponse(200, data, {key.lower(): value for key, value in response.headers.items()})
            except HTTPError as exc:
                if exc.code == 304:
                    exc.close()
                    return JsonResponse(304, None, {key.lower(): value for key, value in exc.headers.items()})
                retryable = exc.code == 429 or 500 <= exc.code <= 599
                delay = retry_delay(exc.headers.get("Retry-After"), attempt)
                status = exc.code
                exc.close()
                if not retryable or attempt + 1 == self.max_attempts:
                    raise FetchError(f"Upstream returned HTTP {status}; cache checkpoint was preserved") from None
                time.sleep(delay)
            except (URLError, TimeoutError, ConnectionError, OSError):
                if attempt + 1 == self.max_attempts:
                    raise FetchError("Upstream connection failed; cache checkpoint was preserved") from None
                time.sleep(retry_delay(None, attempt))
        raise FetchError("Upstream request failed")
