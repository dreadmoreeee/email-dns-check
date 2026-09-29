from email_dns_check import FakeResolver
from email_dns_check.dmarc import check_dmarc


def check(records, value=None):
    if value is not None:
        records["_dmarc.example.com"] = {"TXT": [value]}
    return check_dmarc(FakeResolver(records), "example.com")


def finding(result, prefix):
    return next(f for f in result.findings if f.title.startswith(prefix))


def test_reject_with_reports_passes(records):
    result = check(records)
    assert result.status == "pass"
    assert result.findings == []


def test_missing_dmarc_fails_with_record(records):
    del records["_dmarc.example.com"]
    result = check(records)
    assert result.status == "fail"
    f = finding(result, "No DMARC record")
    assert f.record == '_dmarc.example.com. TXT "v=DMARC1; p=none; rua=mailto:dmarc@example.com"'
    assert "quarantine" in f.explanation and "reject" in f.explanation


def test_p_none_explained_and_next_stage(records):
    result = check(records, "v=DMARC1; p=none; rua=mailto:dmarc@example.com")
    assert result.status == "warn"
    f = finding(result, "DMARC policy is p=none")
    assert "no action" in f.explanation
    assert f.record == '_dmarc.example.com. TXT "v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com"'


def test_quarantine_suggests_reject(records):
    result = check(records, "v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com")
    assert result.status == "pass"
    assert finding(result, "DMARC policy is p=quarantine").record.endswith('"v=DMARC1; p=reject; rua=mailto:dmarc@example.com"')


def test_missing_rua_and_partial_pct(records):
    result = check(records, "v=DMARC1; p=reject; pct=25")
    assert result.status == "warn"
    assert finding(result, "No aggregate reports").record == \
        '_dmarc.example.com. TXT "v=DMARC1; p=reject; pct=25; rua=mailto:dmarc@example.com"'
    assert finding(result, "Policy applies to only 25%").record == '_dmarc.example.com. TXT "v=DMARC1; p=reject"'


def test_sp_none_weakens_subdomains(records):
    result = check(records, "v=DMARC1; p=reject; sp=none; rua=mailto:dmarc@example.com")
    assert result.status == "warn"
    assert finding(result, "Subdomains are not protected").record == \
        '_dmarc.example.com. TXT "v=DMARC1; p=reject; rua=mailto:dmarc@example.com"'


def test_external_rua_needs_authorisation(records):
    result = check(records, "v=DMARC1; p=reject; rua=mailto:abc@reports.example.net")
    f = finding(result, "rua goes to an external domain")
    assert f.severity == "info"
    assert f.record == 'example.com._report._dmarc.reports.example.net. TXT "v=DMARC1"'


def test_invalid_values_fail(records):
    result = check(records, "v=DMARC1; p=block; adkim=x; fo=2; pct=150; rua=mailto:not-an-address")
    assert result.status == "fail"
    titles = [f.title for f in result.findings]
    for expected in ("Invalid policy p=block", "Invalid adkim=x", "Invalid fo=2", "Invalid pct=150",
                     "Invalid rua address: mailto:not-an-address"):
        assert expected in titles


def test_missing_p_tag_fails(records):
    result = check(records, "v=DMARC1; rua=mailto:dmarc@example.com")
    assert result.status == "fail"
    assert finding(result, "DMARC record has no p=").record == \
        '_dmarc.example.com. TXT "v=DMARC1; p=none; rua=mailto:dmarc@example.com"'


def test_multiple_records_fail(records):
    records["_dmarc.example.com"]["TXT"].append("v=DMARC1; p=none")
    result = check(records)
    assert result.status == "fail"
    assert "Multiple DMARC records" in [f.title for f in result.findings]


def test_alignment_and_fo_details(records):
    result = check(records, "v=DMARC1; p=reject; adkim=s; aspf=r; fo=1; rua=mailto:dmarc@example.com")
    assert any("adkim=s (strict" in d for d in result.details)
    assert finding(result, "fo= has no effect").severity == "info"


def test_subdomain_inherits_parent_policy_none_is_a_warning():
    res = FakeResolver({"_dmarc.example.com": {"TXT": ["v=DMARC1; p=none; rua=mailto:d@example.com"]}})
    result = check_dmarc(res, "shop.example.com")
    assert result.status == "warn"
    assert result.summary == "Inherited from example.com: policy none for subdomains"
    assert finding(result, "Inherited DMARC policy is none")


def test_subdomain_inherits_sp_reject_and_passes():
    res = FakeResolver({"_dmarc.example.com": {"TXT": ["v=DMARC1; p=none; sp=reject"]}})
    result = check_dmarc(res, "shop.example.com")
    assert result.status in ("pass", "info")
    assert "reject" in result.summary


def test_subdomain_without_any_record_still_fails():
    result = check_dmarc(FakeResolver({}), "shop.example.com")
    assert result.status == "fail"


def test_org_domain():
    from email_dns_check.dmarc import org_domain
    assert org_domain("marvin.demarkstudio.ca") == "demarkstudio.ca"
    assert org_domain("a.b.example.co.uk") == "example.co.uk"
    assert org_domain("example.com") == "example.com"


def test_subdomain_without_mail_gets_spf_dash_all():
    from email_dns_check.checker import check_domain
    res = FakeResolver({"_dmarc.example.com": {"TXT": ["v=DMARC1; p=reject"]}})
    report = check_domain("www2.example.com", res, https=False)
    spf = next(c for c in report.checks if c.name == "SPF")
    assert spf.findings[0].record == 'www2.example.com. TXT "v=spf1 -all"'
    dmarc = next(c for c in report.checks if c.name == "DMARC")
    assert "reject" in dmarc.summary
