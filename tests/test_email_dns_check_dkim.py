import base64

from email_dns_check import FakeResolver
from email_dns_check.dkim import COMMON_SELECTORS, check_dkim, estimate_rsa_bits


def finding(result, prefix):
    return next(f for f in result.findings if f.title.startswith(prefix))


def test_2048_key_passes(records):
    result = check_dkim(FakeResolver(records), "example.com")
    assert result.status == "pass"
    assert result.data["keys"][0]["bits"] == 2048


def test_revoked_key_is_flagged(records):
    records["google._domainkey.example.com"] = {"TXT": ["v=DKIM1; k=rsa; p="]}
    result = check_dkim(FakeResolver(records), "example.com")
    assert result.status == "warn"
    f = finding(result, "Selector 'google' is revoked")
    assert "empty p=" in f.title
    assert result.data["keys"][0]["revoked"] is True


def test_revoked_is_info_when_another_key_is_active(records, rsa_key):
    records["s1._domainkey.example.com"] = {"TXT": ["v=DKIM1; p="]}
    result = check_dkim(FakeResolver(records), "example.com")
    assert result.status == "pass"
    assert finding(result, "Selector 's1' is revoked").severity == "info"


def test_weak_512_key_fails(records, rsa_key):
    records["google._domainkey.example.com"] = {"TXT": ["v=DKIM1; k=rsa; p=" + rsa_key(512)]}
    result = check_dkim(FakeResolver(records), "example.com")
    assert result.status == "fail"
    f = finding(result, "Selector 'google': weak 512-bit")
    assert "2048" in f.explanation
    assert f.record.startswith('google._domainkey.example.com. TXT "v=DKIM1; k=rsa; p=')


def test_1024_key_warns(records, rsa_key):
    records["google._domainkey.example.com"] = {"TXT": ["v=DKIM1; k=rsa; p=" + rsa_key(1024)]}
    result = check_dkim(FakeResolver(records), "example.com")
    assert result.status == "warn"
    assert "2048" in finding(result, "Selector 'google': 1024-bit").explanation


def test_user_selector_probed_first(records, rsa_key):
    records["mandrill._domainkey.example.com"] = {"TXT": ["k=rsa; p=" + rsa_key(2048, pkcs1=True)]}
    result = check_dkim(FakeResolver(records), "example.com", ["mandrill", "missing"])
    assert result.data["probed"][:2] == ["mandrill", "missing"]
    assert [k["selector"] for k in result.data["keys"]] == ["mandrill", "google"]
    assert result.data["keys"][0]["bits"] == 2048
    assert finding(result, "Selector 'missing' not found").severity == "warn"


def test_no_key_found_explains_selectors(records):
    del records["google._domainkey.example.com"]
    result = check_dkim(FakeResolver(records), "example.com", provider={"dkim_selectors": ["google"]})
    assert result.status == "warn"
    f = finding(result, "No DKIM key found")
    assert "--selector" in f.explanation
    assert f.record.startswith("google._domainkey.example.com. TXT")
    assert len(result.data["probed"]) == len(COMMON_SELECTORS)


def test_bad_base64_fails(records):
    records["google._domainkey.example.com"] = {"TXT": ["v=DKIM1; k=rsa; p=abc$$def"]}
    result = check_dkim(FakeResolver(records), "example.com")
    assert result.status == "fail"


def test_ed25519_key(records):
    key = base64.b64encode(b"\x01" * 32).decode()
    records["google._domainkey.example.com"] = {"TXT": [f"v=DKIM1; k=ed25519; p={key}"]}
    result = check_dkim(FakeResolver(records), "example.com")
    assert result.status == "pass"


def test_estimate_from_length_when_der_is_unparseable():
    for bits, der_len in ((1024, 162), (2048, 294), (4096, 550)):
        fake = base64.b64encode(b"\xff" * der_len).decode()
        assert estimate_rsa_bits(fake) == (bits, False)


def test_exact_bits_from_der(rsa_key):
    assert estimate_rsa_bits(rsa_key(3072)) == (3072, True)
