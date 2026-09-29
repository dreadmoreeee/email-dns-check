import json

import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.resolver
import dns.rrset
import pytest

from email_dns_check import DnsPythonResolver, FakeResolver, check_domain
from email_dns_check.cli import main, normalize_domain
from email_dns_check.model import txt_record
from email_dns_check.resolver import DNSLookupError, rdata_to_text


def run(capsys, argv, records):
    code = main(argv, resolver=FakeResolver(records))
    return code, capsys.readouterr().out


def test_text_output_and_exit_zero(capsys, records):
    code, out = run(capsys, ["example.com", "--no-https"], records)
    assert code == 0
    assert out.startswith("example.com: PASS")
    assert "SPF      PASS" in out


def test_json_output(capsys, records):
    code, out = run(capsys, ["Example.COM.", "--format", "json", "--no-https"], records)
    doc = json.loads(out)
    assert doc["status"] == "pass"
    domain = doc["domains"][0]
    assert domain["domain"] == "example.com"
    assert [c["name"] for c in domain["checks"]] == ["MX", "SPF", "DMARC", "DKIM", "MTA-STS", "TLS-RPT", "BIMI"]


def test_markdown_output_and_exit_one_on_failure(capsys, records):
    del records["_dmarc.example.com"]
    code, out = run(capsys, ["example.com", "-f", "markdown", "--no-https"], records)
    assert code == 1
    assert "| DMARC | FAIL | No DMARC record |" in out
    assert 'Publish: `_dmarc.example.com. TXT "v=DMARC1; p=none; rua=mailto:dmarc@example.com"`' in out


def test_warnings_do_not_fail(capsys, records):
    records["_dmarc.example.com"]["TXT"] = ["v=DMARC1; p=none; rua=mailto:dmarc@example.com"]
    code, out = run(capsys, ["example.com", "--no-https"], records)
    assert code == 0
    assert out.startswith("example.com: WARN")


def test_selector_option(capsys, records, rsa_key):
    records["custom._domainkey.example.com"] = {"TXT": ["v=DKIM1; p=" + rsa_key(2048)]}
    code, out = run(capsys, ["example.com", "--selector", "custom", "-s", "other", "-f", "json", "--no-https"], records)
    dkim = json.loads(out)["domains"][0]["checks"][3]
    assert dkim["data"]["probed"][:2] == ["custom", "other"]


def test_multiple_domains(capsys, records):
    code, out = run(capsys, ["example.com", "example.org", "-f", "json", "--no-https"], records)
    doc = json.loads(out)
    assert [d["domain"] for d in doc["domains"]] == ["example.com", "example.org"]
    assert code == 1


def test_invalid_domain_is_usage_error(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["not a domain"], resolver=FakeResolver({}))
    assert exc.value.code == 2


def test_normalize_domain():
    assert normalize_domain("Example.COM.") == "example.com"
    assert normalize_domain("b\u00fccher.example") == "xn--bcher-kva.example"
    with pytest.raises(ValueError):
        normalize_domain("localhost")


def test_dns_failure_becomes_failed_check(records):
    records["example.com"]["MX"] = DNSLookupError("MX lookup for example.com failed: LifetimeTimeout")
    report = check_domain("example.com", FakeResolver(records), https=False)
    assert report.check("MX").status == "fail"
    assert report.status == "fail"


def test_https_fetch_used_only_when_sts_exists(records):
    class Fetcher:
        urls = []

        def get(self, url):
            self.urls.append(url)
            raise AssertionError("should not fetch")

    fetcher = Fetcher()
    check_domain("example.com", FakeResolver(records), fetcher=fetcher)
    assert fetcher.urls == []


def test_txt_record_splits_long_values():
    rec = txt_record("k._domainkey.example.com", "p=" + "A" * 400)
    assert rec.startswith('k._domainkey.example.com. TXT "p=')
    assert rec.count('"') == 4


def rdata(rtype, text):
    return dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.from_text(rtype), text)


def test_rdata_to_text():
    assert rdata_to_text(rdata("MX", "10 ASPMX.L.Google.com.")) == "10 aspmx.l.google.com"
    assert rdata_to_text(rdata("MX", "0 .")) == "0 ."
    assert rdata_to_text(rdata("TXT", '"v=spf1 include:_spf.goo" "gle.com ~all"')) == "v=spf1 include:_spf.google.com ~all"
    assert rdata_to_text(rdata("A", "192.0.2.1")) == "192.0.2.1"
    assert rdata_to_text(rdata("CNAME", "Target.Example.net.")) == "target.example.net"


def test_dnspython_resolver_mapping(monkeypatch):
    class Answer:
        def __init__(self, rrset):
            self.rrset = rrset

    def fake_resolve(qname, rtype, raise_on_no_answer=True):
        if qname == "gone.example.com.":
            raise dns.resolver.NXDOMAIN()
        if qname == "slow.example.com.":
            raise dns.resolver.LifetimeTimeout(timeout=1.0, errors=[])
        if rtype == "MX":
            return Answer(dns.rrset.from_text(qname, 300, "IN", "MX", "10 mx.example.com."))
        return Answer(None)

    resolver = DnsPythonResolver()
    monkeypatch.setattr(resolver._resolver, "resolve", fake_resolve)
    assert resolver.resolve("Example.com.", "mx") == ["10 mx.example.com"]
    assert resolver.resolve("example.com", "TXT") == []
    assert resolver.resolve("gone.example.com", "A") == []
    with pytest.raises(DNSLookupError):
        resolver.resolve("slow.example.com", "A")
    resolver.resolve("example.com", "MX")
    assert resolver.queries == 4  # the repeated MX query came from the cache
