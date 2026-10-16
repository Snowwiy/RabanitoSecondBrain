from __future__ import annotations

import json
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

from .model import InvalidFeed
from .model import identifier


ALLOWED_ENDPOINTS = {
    "www.cisa.gov": ("/sites/default/files/feeds/known_exploited_vulnerabilities.json",),
    "raw.githubusercontent.com": ("/cisagov/kev-data/develop/known_exploited_vulnerabilities.json",),
    "services.nvd.nist.gov": ("/rest/json/cves/2.0",),
    "api.first.org": ("/data/v1/epss",),
    "api.osv.dev": ("/v1/vulns/",),
}


class FetchError(RuntimeError):
    def __init__(self, code: str, status: int | None = None, retry_after: int | None = None):
        super().__init__(code)
        self.code, self.status, self.retry_after = code, status, retry_after


@dataclass
class Response:
    data: object
    url: str
    etag: str | None = None
    last_modified: str | None = None
    not_modified: bool = False
    fetched_at: str | None = None


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def validate_endpoint(url: str) -> str:
    parsed = urlsplit(url)
    allowed = ALLOWED_ENDPOINTS.get(parsed.hostname or "", ())
    if (parsed.scheme != "https" or parsed.username or parsed.password or parsed.fragment
            or parsed.port not in (None, 443) or not any(
                parsed.path.startswith(path) if path.endswith("/") else parsed.path == path for path in allowed
            )):
        raise ValueError("Unapproved public endpoint")
    if parsed.hostname == "api.osv.dev":
        identifier(parsed.path.removeprefix("/v1/vulns/"))
        if parsed.query:
            raise ValueError("OSV lookup does not accept query parameters")
    return parsed.hostname or ""


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise InvalidFeed("duplicate_json_key")
        result[key] = value
    return result


def _retry_seconds(value: str | None) -> int | None:
    if not value:
        return None
    try:
        if value.strip().isdigit():
            return min(int(value), 86400)
        when = parsedate_to_datetime(value)
        return min(max(int((when - datetime.now(timezone.utc)).total_seconds()), 0), 86400)
    except (ValueError, TypeError, OverflowError):
        return None


class PublicHttpClient:
    """GET-only allowlisted client. No credentials, private payloads, proxies or redirects."""

    def __init__(self, *, opener=None, sleep=time.sleep, monotonic=time.monotonic,
                 max_bytes: int = 8 * 1024 * 1024, attempts: int = 3):
        self.opener = opener or build_opener(ProxyHandler({}), NoRedirect())
        self.sleep, self.monotonic = sleep, monotonic
        self.max_bytes = min(max(int(max_bytes), 1024), 16 * 1024 * 1024)
        self.attempts = min(max(int(attempts), 1), 3)
        self.last_request: dict[str, float] = {}

    def get(self, url: str, cache: dict | None = None) -> Response:
        host = validate_endpoint(url)
        headers = {"Accept": "application/json", "User-Agent": "RabanitoSecondBrain/0.1 public-feed-client"}
        if cache:
            for key, header in (("etag", "If-None-Match"), ("last_modified", "If-Modified-Since")):
                value = cache.get(key)
                if isinstance(value, str) and len(value) <= 1000 and "\n" not in value and "\r" not in value:
                    headers[header] = value
        for attempt in range(self.attempts):
            interval = 6.1 if host == "services.nvd.nist.gov" else 1.0
            elapsed = self.monotonic() - self.last_request.get(host, -1e20)
            if elapsed < interval:
                self.sleep(interval - elapsed)
            self.last_request[host] = self.monotonic()
            try:
                with self.opener.open(Request(url, headers=headers, method="GET"), timeout=25) as response:
                    if response.status != 200:
                        raise FetchError("unexpected_http_status", response.status)
                    if response.headers.get("Content-Encoding", "identity").casefold() not in {"identity", ""}:
                        raise FetchError("unsupported_content_encoding")
                    raw = response.read(self.max_bytes + 1)
                    if len(raw) > self.max_bytes:
                        raise FetchError("response_too_large")
                    try:
                        data = json.loads(raw.decode("utf-8-sig"), object_pairs_hook=_unique_object,
                                          parse_constant=lambda _: (_ for _ in ()).throw(InvalidFeed("nonfinite_json")))
                    except (UnicodeError, json.JSONDecodeError, RecursionError):
                        raise InvalidFeed("invalid_json") from None
                    return Response(data, url, response.headers.get("ETag"), response.headers.get("Last-Modified"))
            except HTTPError as error:
                status = error.code
                retry_after = _retry_seconds(error.headers.get("Retry-After"))
                error.close()
                if status == 304:
                    if not cache or "data" not in cache:
                        raise FetchError("cache_miss_for_304", status) from None
                    return Response(cache["data"], url, cache.get("etag"), cache.get("last_modified"), True)
                if status not in {429, 500, 502, 503, 504}:
                    raise FetchError("http_error", status) from None
                if attempt + 1 == self.attempts or (retry_after is not None and retry_after > 30):
                    raise FetchError("rate_limited" if status == 429 else "provider_unavailable", status, retry_after) from None
                self.sleep(max(retry_after or 0, 2 ** attempt))
            except (URLError, TimeoutError, OSError):
                if attempt + 1 == self.attempts:
                    raise FetchError("network_error") from None
                self.sleep(2 ** attempt)
        raise FetchError("request_failed")
