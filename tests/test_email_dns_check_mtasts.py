import http.server
import threading
import time

import pytest

from email_dns_check import FakeResolver
from email_dns_check.fetch import USER_AGENT, FetchError, HttpResponse, UrllibFetcher
from email_dns_check.mtasts import check_bimi, check_mta_sts, check_tls_rpt, mx_matches, parse_policy

POLICY = "version: STSv1\r\nmode: enforce\r\nmx: smtp.google.com\r\nmx: *.example.net\r\nmax_age: 604800\r\n"


class FakeFetcher:
    def __init__(self, response=None, error=None):
        self.response, self.error, self.urls = response, error, []

    def get(self, url):
        self.urls.append(url)
        if self.error:
            raise self.error
        return self.response


def with_sts(records):
    records["_mta-sts.example.com"] = {"TXT": ["v=STSv1; id=20260101"]}
    return FakeResolver(records)


def test_missing_sts_is_info_and_no_fetch(records):
    fetcher = FakeFetcher()
    result = check_mta_sts(FakeResolver(records), "example.com", fetcher, ["smtp.google.com"])
    assert result.status == "info"
    assert fetcher.urls == []
    assert result.findings[0].record.startswith('_mta-sts.example.com. TXT "v=STSv1; id=')


def test_valid_policy_passes(records):
    fetcher = FakeFetcher(HttpResponse(200, "text/plain", POLICY))
    result = check_mta_sts(with_sts(records), "example.com", fetcher, ["smtp.google.com"])
    assert result.status == "pass"
    assert fetcher.urls == ["https://mta-sts.example.com/.well-known/mta-sts.txt"]
    assert result.data["policy"]["mode"] == "enforce"


def test_no_https_skips_fetch(records):
    fetcher = FakeFetcher(HttpResponse(200, "text/plain", POLICY))
    result = check_mta_sts(with_sts(records), "example.com", fetcher, ["smtp.google.com"], https=False)
    assert fetcher.urls == []
    assert "--no-https" in result.summary


def test_policy_mx_mismatch_fails_in_enforce(records):
    fetcher = FakeFetcher(HttpResponse(200, "text/plain", POLICY))
    result = check_mta_sts(with_sts(records), "example.com", fetcher, ["smtp.google.com", "backup.example.org"])
    assert result.status == "fail"
    assert "MX hosts missing from the MTA-STS policy" in [f.title for f in result.findings]


def test_unreachable_policy_fails(records):
    fetcher = FakeFetcher(error=FetchError("certificate verify failed"))
    result = check_mta_sts(with_sts(records), "example.com", fetcher, ["smtp.google.com"])
    assert result.status == "fail"


def test_testing_mode_and_bad_id(records):
    records["_mta-sts.example.com"] = {"TXT": ["v=STSv1; id=bad-id!"]}
    body = POLICY.replace("enforce", "testing").replace("604800", "3600")
    result = check_mta_sts(FakeResolver(records), "example.com",
                           FakeFetcher(HttpResponse(200, "text/html", body)), ["smtp.google.com"])
    titles = [f.title for f in result.findings]
    assert "Invalid MTA-STS record" in titles
    assert "MTA-STS in testing mode" in titles
    assert "Short max_age (3600 s)" in titles
    assert "Policy is not served as text/plain" in titles


def test_parse_policy_errors():
    policy, errors = parse_policy("version: STSv1\nmode: sometimes\nmax_age: 99999999999\n")
    assert len(errors) == 2
    assert mx_matches("a.example.net", "*.example.net")
    assert not mx_matches("a.b.example.net", "*.example.net")


def test_tls_rpt(records):
    assert check_tls_rpt(FakeResolver(records), "example.com").status == "info"
    assert check_tls_rpt(FakeResolver(records), "example.com", sts_published=True).status == "warn"
    records["_smtp._tls.example.com"] = {"TXT": ["v=TLSRPTv1; rua=mailto:tls@example.com"]}
    assert check_tls_rpt(FakeResolver(records), "example.com").status == "pass"
    records["_smtp._tls.example.com"] = {"TXT": ["v=TLSRPTv1; rua=tls@example.com"]}
    assert check_tls_rpt(FakeResolver(records), "example.com").status == "fail"


def test_bimi(records):
    assert check_bimi(FakeResolver(records), "example.com", "reject").status == "info"
    records["default._bimi.example.com"] = {"TXT": ["v=BIMI1; l=https://example.com/logo.svg"]}
    assert check_bimi(FakeResolver(records), "example.com", "reject").status == "pass"
    assert check_bimi(FakeResolver(records), "example.com", "none").status == "warn"


class _Handler(http.server.BaseHTTPRequestHandler):
    seen = []

    def do_GET(self):
        _Handler.seen.append((self.path, self.headers.get("User-Agent"), time.monotonic()))
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/.well-known/mta-sts.txt")
            self.end_headers()
            return
        body = POLICY.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


@pytest.fixture
def local_server():
    server = http.server.HTTPServer(("127.0.0.1", 0), _Handler)  # random free port
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    _Handler.seen = []
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()
    server.server_close()


def test_fetcher_user_agent_no_redirect_and_spacing(local_server):
    fetcher = UrllibFetcher(timeout=5, min_interval=0.3)
    resp = fetcher.get(local_server + "/.well-known/mta-sts.txt")
    assert resp.status == 200 and resp.content_type == "text/plain"
    assert parse_policy(resp.text)[1] == []
    redirected = fetcher.get(local_server + "/redirect")
    assert redirected.status == 302
    assert [s[0] for s in _Handler.seen] == ["/.well-known/mta-sts.txt", "/redirect"]
    assert all(s[1] == USER_AGENT for s in _Handler.seen)
    assert _Handler.seen[1][2] - _Handler.seen[0][2] >= 0.25


def test_fetcher_connection_error():
    fetcher = UrllibFetcher(timeout=2, min_interval=0)
    with pytest.raises(FetchError):
        fetcher.get("http://127.0.0.1:1/nothing")
