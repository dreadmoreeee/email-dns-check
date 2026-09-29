from email_dns_check import FakeResolver
from email_dns_check.resolver import DNSLookupError
from email_dns_check.spf import check_spf, parse_spf


def titles(result):
    return [f.title for f in result.findings]


def finding(result, prefix):
    return next(f for f in result.findings if f.title.startswith(prefix))


def test_healthy_google_record_passes(records):
    result = check_spf(FakeResolver(records), "example.com")
    assert result.status == "pass"
    assert result.data["lookups"] == 4
    assert "4/10 DNS lookups" in result.summary


def test_nested_includes_over_ten_lookups(records):
    # example.com -> 3 includes, each with 4 includes = 15 lookups
    records["example.com"]["TXT"] = ["v=spf1 include:a.example.net include:b.example.net include:c.example.net -all"]
    for letter in "abc":
        records[f"{letter}.example.net"] = {"TXT": [
            "v=spf1 " + " ".join(f"include:{letter}{i}.example.net" for i in range(4)) + " -all"]}
        for i in range(4):
            records[f"{letter}{i}.example.net"] = {"TXT": [f"v=spf1 ip4:192.0.2.{i} -all"]}
    result = check_spf(FakeResolver(records), "example.com")
    assert result.status == "fail"
    assert result.data["lookups"] == 15
    f = finding(result, "Too many DNS lookups")
    assert "15 > 10" in f.title
    assert "permerror" in f.explanation


def test_duplicate_includes_get_a_fixed_record(records):
    records["example.com"]["TXT"] = [
        "v=spf1 include:_spf.google.com include:_spf.google.com include:_spf.google.com ~all"]
    result = check_spf(FakeResolver(records), "example.com")
    f = finding(result, "Too many DNS lookups")
    assert f.record == 'example.com. TXT "v=spf1 include:_spf.google.com ~all"'


def test_include_loop_detected(records):
    records["example.com"]["TXT"] = ["v=spf1 include:loop.example.net -all"]
    records["loop.example.net"] = {"TXT": ["v=spf1 include:example.com -all"]}
    result = check_spf(FakeResolver(records), "example.com")
    assert result.status == "fail"
    f = finding(result, "SPF include loop")
    assert "example.com -> loop.example.net -> example.com" in f.explanation


def test_self_include_loop_has_fix(records):
    records["example.com"]["TXT"] = ["v=spf1 ip4:192.0.2.1 include:example.com -all"]
    result = check_spf(FakeResolver(records), "example.com")
    f = finding(result, "SPF include loop")
    assert f.record == 'example.com. TXT "v=spf1 ip4:192.0.2.1 -all"'


def test_multiple_spf_records(records):
    records["example.com"]["TXT"] = ["v=spf1 include:_spf.google.com ~all", "v=spf1 ip4:192.0.2.1 -all"]
    result = check_spf(FakeResolver(records), "example.com")
    assert result.status == "fail"
    f = finding(result, "Multiple SPF records")
    assert f.record == 'example.com. TXT "v=spf1 include:_spf.google.com ip4:192.0.2.1 ~all"'


def test_plus_all_fails_with_fix(records):
    records["example.com"]["TXT"] = ["v=spf1 include:_spf.google.com +all"]
    result = check_spf(FakeResolver(records), "example.com")
    assert result.status == "fail"
    f = finding(result, "SPF ends with +all")
    assert f.record == 'example.com. TXT "v=spf1 include:_spf.google.com ~all"'


def test_bare_all_is_plus_all(records):
    records["example.com"]["TXT"] = ["v=spf1 mx all"]
    result = check_spf(FakeResolver(records), "example.com")
    assert "SPF ends with +all" in titles(result)


def test_question_all_warns(records):
    records["example.com"]["TXT"] = ["v=spf1 include:_spf.google.com ?all"]
    result = check_spf(FakeResolver(records), "example.com")
    assert result.status == "warn"
    assert "SPF ends with ?all" in titles(result)


def test_missing_all_warns_and_appends(records):
    records["example.com"]["TXT"] = ["v=spf1 include:_spf.google.com"]
    result = check_spf(FakeResolver(records), "example.com")
    f = finding(result, "SPF has no 'all'")
    assert f.record == 'example.com. TXT "v=spf1 include:_spf.google.com ~all"'


def test_redirect_without_all_is_fine(records):
    records["example.com"]["TXT"] = ["v=spf1 redirect=_spf.google.com"]
    result = check_spf(FakeResolver(records), "example.com")
    assert result.status == "pass"
    assert result.data["lookups"] == 4


def test_minus_all_is_info_policy_choice(records):
    records["example.com"]["TXT"] = ["v=spf1 include:_spf.google.com -all"]
    result = check_spf(FakeResolver(records), "example.com")
    assert result.status == "pass"
    assert "policy choice" in finding(result, "SPF ends with -all").explanation


def test_ptr_warns(records):
    records["example.com"]["TXT"] = ["v=spf1 ptr include:_spf.google.com ~all"]
    result = check_spf(FakeResolver(records), "example.com")
    assert result.status == "warn"
    f = finding(result, "Uses the ptr")
    assert f.record == 'example.com. TXT "v=spf1 include:_spf.google.com ~all"'


def test_void_lookups_over_two(records):
    records["example.com"]["TXT"] = ["v=spf1 a:gone1.example.com a:gone2.example.com mx:gone3.example.com -all"]
    result = check_spf(FakeResolver(records), "example.com")
    assert result.data["void_lookups"] == 3
    assert any(t.startswith("Too many void lookups") for t in titles(result))


def test_include_without_spf_is_permerror(records):
    records["example.com"]["TXT"] = ["v=spf1 include:nospf.example.net ~all"]
    result = check_spf(FakeResolver(records), "example.com")
    assert result.status == "fail"
    assert "Broken include or redirect" in titles(result)


def test_no_spf_suggests_provider_include(records):
    records["example.com"]["TXT"] = ["google-site-verification=abc"]
    provider = {"spf_include": "_spf.google.com"}
    result = check_spf(FakeResolver(records), "example.com", provider)
    assert result.status == "fail"
    assert result.findings[0].record == 'example.com. TXT "v=spf1 include:_spf.google.com ~all"'


def test_syntax_errors():
    terms, errors = parse_spf("v=spf1 ip4:300.1.1.1 include: foo:bar ip6:2001:db8::/129 a/33 mx:example.com/24 -all")
    assert len(errors) == 5
    assert [t.name for t in terms] == ["mx", "all"]


def test_valid_syntax_variants():
    terms, errors = parse_spf(
        "v=spf1 a mx/24 a:mail.example.com/28//64 ip4:192.0.2.0/24 ip6:2001:db8::/32 "
        "exists:%{i}._spf.example.com ~include:_spf.example.net exp=explain.example.com -all")
    assert errors == []
    assert terms[-2].kind == "modifier" and terms[-2].name == "exp"


def test_dns_error_during_expansion_is_reported(records):
    records["_spf.google.com"]["TXT"] = DNSLookupError("SERVFAIL")
    result = check_spf(FakeResolver(records), "example.com")
    assert "DNS error during SPF expansion" in titles(result)
