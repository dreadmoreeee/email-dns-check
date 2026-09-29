"""The one HTTPS GET this tool makes: the MTA-STS policy file."""

from __future__ import annotations

import time
import urllib.error
import urllib.request
from dataclasses import dataclass

USER_AGENT = "email-dns-check/1.0 (+https://github.com/dreadmoreeee/email-dns-check)"


class FetchError(Exception):
    """The request could not be completed (DNS, TLS, connection, timeout)."""


@dataclass
class HttpResponse:
    status: int
    content_type: str
    text: str


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    # RFC 8461: the policy fetch must not follow redirects.
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class UrllibFetcher:
    """GET with a fixed User-Agent, no redirects, a size cap and >= 1 s between requests."""

    def __init__(self, timeout: float = 10.0, min_interval: float = 1.0, max_bytes: int = 65536):
        self.timeout = timeout
        self.min_interval = min_interval
        self.max_bytes = max_bytes
        self.requests = 0
        self._last: float | None = None

    def get(self, url: str) -> HttpResponse:
        if self._last is not None:
            wait = self.min_interval - (time.monotonic() - self._last)
            if wait > 0:
                time.sleep(wait)
        opener = urllib.request.build_opener(_NoRedirect)
        request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "text/plain"})
        self.requests += 1
        try:
            with opener.open(request, timeout=self.timeout) as resp:
                body = resp.read(self.max_bytes + 1)
                return HttpResponse(resp.status, resp.headers.get("Content-Type", ""),
                                    body[: self.max_bytes].decode("utf-8", errors="replace"))
        except urllib.error.HTTPError as exc:
            return HttpResponse(exc.code, exc.headers.get("Content-Type", "") if exc.headers else "", "")
        except (urllib.error.URLError, OSError, ValueError) as exc:
            reason = getattr(exc, "reason", exc)
            raise FetchError(f"{reason}") from exc
        finally:
            self._last = time.monotonic()
