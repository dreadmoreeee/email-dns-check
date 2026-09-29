from email_dns_check import FakeResolver
from email_dns_check.mx import check_mx, detect_provider


def titles(result):
    return [f.title for f in result.findings]


def test_google_mx_passes(records):
    result = check_mx(FakeResolver(records), "example.com")
    assert result.status == "pass"
    assert result.data["provider"] == "Google Workspace"
    assert result.data["records"] == [{"priority": 1, "host": "smtp.google.com"}]


def test_priorities_sorted(records):
    records["example.com"]["MX"] = ["20 mx2.example.com", "10 mx1.example.com"]
    records["mx1.example.com"] = {"A": ["192.0.2.10"]}
    records["mx2.example.com"] = {"A": ["192.0.2.11"]}
    result = check_mx(FakeResolver(records), "example.com")
    assert result.details[0].startswith("10 mx1.example.com")
    assert result.details[1].startswith("20 mx2.example.com")


def test_null_mx_is_flagged(records):
    records["example.com"]["MX"] = ["0 ."]
    result = check_mx(FakeResolver(records), "example.com")
    assert "Null MX published" in titles(result)
    assert result.status == "pass"


def test_null_mx_mixed_fails(records):
    records["example.com"]["MX"] = ["0 .", "10 smtp.google.com"]
    result = check_mx(FakeResolver(records), "example.com")
    assert result.status == "fail"


def test_cname_target_warns(records):
    records["example.com"]["MX"] = ["10 mail.example.com"]
    records["mail.example.com"] = {"CNAME": ["host.example.net"]}
    records["host.example.net"] = {"A": ["192.0.2.20"]}
    result = check_mx(FakeResolver(records), "example.com")
    assert result.status == "warn"
    assert "MX target mail.example.com is a CNAME" in titles(result)


def test_unresolvable_target_fails(records):
    records["example.com"]["MX"] = ["10 gone.example.com"]
    result = check_mx(FakeResolver(records), "example.com")
    assert result.status == "fail"
    assert "MX target gone.example.com does not resolve" in titles(result)


def test_no_mx_with_a_record_warns(records):
    del records["example.com"]["MX"]
    result = check_mx(FakeResolver(records), "example.com")
    assert result.status == "warn"


def test_no_mx_and_no_address_fails():
    result = check_mx(FakeResolver({}), "example.com")
    assert result.status == "fail"


def test_detect_provider():
    assert detect_provider(["example-com.mail.protection.outlook.com"])["spf_include"] == "spf.protection.outlook.com"
    assert detect_provider(["mx.example.org"]) is None
