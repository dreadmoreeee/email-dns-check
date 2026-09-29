"""MTA-STS (with the optional policy fetch), TLS-RPT and BIMI checks."""

from __future__ import annotations

import datetime
import re

from .fetch import FetchError
from .model import FAIL, INFO, PASS, WARN, CheckResult, parse_tags, txt_record
from .resolver import Resolver

MAX_AGE_LIMIT = 31557600
_STS_ID = re.compile(r"^[A-Za-z0-9]{1,32}$")
_RUA_URI = re.compile(r"^(mailto:[^@\s,]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}|https://[^\s,]+)$")


def _policy_text(domain: str, mx_hosts: list[str], mode: str = "enforce") -> str:
    lines = ["version: STSv1", f"mode: {mode}"]
    lines += [f"mx: {h}" for h in (mx_hosts or [f"mx.{domain}"])]
    lines.append("max_age: 604800")
    return "(one line each) " + " | ".join(lines)


def parse_policy(text: str) -> tuple[dict, list[str]]:
    """Parse an MTA-STS policy body. Returns ({version, mode, max_age, mx[]}, errors)."""
    policy: dict = {"mx": []}
    errors: list[str] = []
    for raw in text.replace("\r\n", "\n").split("\n"):
        line = raw.strip()
        if not line:
            continue
        if ":" not in line:
            errors.append(f"line '{line}' is not 'key: value'")
            continue
        key, value = (x.strip() for x in line.split(":", 1))
        if key == "mx":
            policy["mx"].append(value.lower().rstrip("."))
        elif key in policy:
            errors.append(f"'{key}' appears more than once")
        else:
            policy[key] = value
    if policy.get("version") != "STSv1":
        errors.append("'version: STSv1' is missing")
    if policy.get("mode") not in ("enforce", "testing", "none"):
        errors.append("mode must be enforce, testing or none")
    age = policy.get("max_age", "")
    if not age.isdigit() or int(age) > MAX_AGE_LIMIT:
        errors.append(f"max_age must be an integer from 0 to {MAX_AGE_LIMIT}")
    if policy.get("mode") in ("enforce", "testing") and not policy["mx"]:
        errors.append("at least one 'mx:' line is required")
    return policy, errors


def mx_matches(host: str, pattern: str) -> bool:
    host, pattern = host.lower().rstrip("."), pattern.lower().rstrip(".")
    if pattern.startswith("*."):
        head, _, rest = host.partition(".")
        return bool(head) and rest == pattern[2:]
    return host == pattern


def check_mta_sts(resolver: Resolver, domain: str, fetcher=None, mx_hosts: list[str] | None = None,
                  https: bool = True) -> CheckResult:
    result = CheckResult("MTA-STS")
    mx_hosts = mx_hosts or []
    name = f"_mta-sts.{domain}"
    records = [t for t in resolver.resolve(name, "TXT") if t.startswith("v=STSv1")]
    policy_url = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"
    new_id = datetime.date.today().strftime("%Y%m%d") + "01"

    if not records:
        result.summary = "Not published (optional)"
        result.add(
            INFO,
            "No MTA-STS record",
            "MTA-STS makes senders require TLS with a valid certificate when delivering to your MX hosts, "
            "blocking downgrade attacks. To enable it, serve a policy file as text/plain at "
            f"{policy_url} (valid HTTPS certificate for mta-sts.{domain}) with mode: testing first, "
            f"then publish the TXT record. Policy file: {_policy_text(domain, mx_hosts, 'testing')}",
            txt_record(name, f"v=STSv1; id={new_id}"),
        )
        return result.settle(INFO)

    if len(records) > 1:
        result.summary = f"{len(records)} MTA-STS records"
        result.add(FAIL, "Multiple MTA-STS records",
                   "Senders ignore MTA-STS when more than one v=STSv1 record exists. Keep one.",
                   txt_record(name, f"v=STSv1; id={new_id}"))
        return result.settle()

    result.details.append(f"record: {records[0]}")
    tags, errors = parse_tags(records[0], lower_names=False)
    values = dict(tags)
    sts_id = values.get("id", "")
    if errors or not _STS_ID.match(sts_id):
        result.add(FAIL, "Invalid MTA-STS record",
                   "The record must be 'v=STSv1; id=' with an id of 1-32 letters/digits; change the id "
                   "whenever the policy file changes.",
                   txt_record(name, f"v=STSv1; id={new_id}"))

    if not https:
        result.summary = f"TXT record present (id={sts_id}); policy not fetched (--no-https)"
        result.details.append("policy fetch skipped (--no-https)")
        return result.settle()
    if fetcher is None:
        result.summary = f"TXT record present (id={sts_id}); policy not fetched"
        return result.settle()

    try:
        resp = fetcher.get(policy_url)
    except FetchError as exc:
        result.summary = "Policy file unreachable"
        result.add(
            FAIL,
            "MTA-STS policy cannot be fetched",
            f"GET {policy_url} failed ({exc}). With a TXT record but no reachable policy (valid HTTPS "
            "certificate required), senders cannot apply MTA-STS. Fix the host, or delete the TXT record.",
        )
        return result.settle()
    result.details.append(f"GET {policy_url} -> HTTP {resp.status}")
    if resp.status != 200:
        result.summary = f"Policy file returned HTTP {resp.status}"
        result.add(FAIL, f"MTA-STS policy returned HTTP {resp.status}",
                   f"{policy_url} must answer 200 with the policy (redirects are not followed). "
                   f"Serve this content: {_policy_text(domain, mx_hosts)}")
        return result.settle()
    if not resp.content_type.lower().startswith("text/plain"):
        result.add(WARN, "Policy is not served as text/plain",
                   f"RFC 8461 requires Content-Type text/plain; got '{resp.content_type or 'none'}'.")

    policy, perrors = parse_policy(resp.text)
    for e in perrors:
        result.add(FAIL, "Invalid MTA-STS policy", f"{e}. Expected something like: {_policy_text(domain, mx_hosts)}")
    mode = policy.get("mode", "?")
    result.data = {"policy": policy}
    result.details.append(f"policy: mode={mode}, max_age={policy.get('max_age')}, mx={', '.join(policy['mx']) or '-'}")
    if mode == "testing":
        result.add(INFO, "MTA-STS in testing mode",
                   "Senders report TLS failures (via TLS-RPT) but still deliver. Switch to mode: enforce once "
                   "reports are clean, and change the TXT id.", txt_record(name, f"v=STSv1; id={new_id}"))
    elif mode == "none":
        result.add(WARN, "MTA-STS mode is none", "mode: none disables the policy. Use testing or enforce.")
    age = policy.get("max_age", "")
    if age.isdigit() and int(age) < 86400:
        result.add(WARN, f"Short max_age ({age} s)",
                   "Senders cache the policy for max_age seconds; under a day gives little protection. "
                   "Use 604800 (one week) or more.")
    if mode in ("enforce", "testing") and policy["mx"]:
        unmatched = [h for h in mx_hosts if not any(mx_matches(h, p) for p in policy["mx"])]
        if unmatched:
            result.add(
                FAIL if mode == "enforce" else WARN,
                "MX hosts missing from the MTA-STS policy",
                f"{', '.join(unmatched)} not covered by the policy's mx: lines; senders enforcing the policy "
                f"will refuse to deliver to them. Use: {_policy_text(domain, mx_hosts, mode)}",
            )
    result.summary = f"mode={mode}, max_age={policy.get('max_age')}"
    return result.settle()


def check_tls_rpt(resolver: Resolver, domain: str, sts_published: bool = False) -> CheckResult:
    result = CheckResult("TLS-RPT")
    name = f"_smtp._tls.{domain}"
    records = [t for t in resolver.resolve(name, "TXT") if t.startswith("v=TLSRPTv1")]
    fix = txt_record(name, f"v=TLSRPTv1; rua=mailto:tlsrpt@{domain}")
    if not records:
        result.summary = "Not published (optional)"
        result.add(
            WARN if sts_published else INFO,
            "No TLS-RPT record",
            "TLS-RPT asks senders to email you daily reports of TLS problems delivering to your domain"
            + (", which you need to run MTA-STS safely." if sts_published else "; useful alongside MTA-STS."),
            fix,
        )
        return result.settle(INFO)
    if len(records) > 1:
        result.summary = f"{len(records)} TLS-RPT records"
        result.add(FAIL, "Multiple TLS-RPT records", "Publish exactly one v=TLSRPTv1 record.", fix)
        return result.settle()
    result.details.append(f"record: {records[0]}")
    tags, errors = parse_tags(records[0], lower_names=False)
    rua = dict(tags).get("rua", "")
    uris = [u.strip() for u in rua.split(",") if u.strip()]
    if errors or not uris or not all(_RUA_URI.match(u) for u in uris):
        result.add(FAIL, "Invalid TLS-RPT record", "rua= must list mailto: or https: destinations.", fix)
    result.summary = f"reports to {rua or '(none)'}"
    return result.settle()


def check_bimi(resolver: Resolver, domain: str, dmarc_policy: str | None = None, dmarc_pct: str | None = None) -> CheckResult:
    result = CheckResult("BIMI")
    name = f"default._bimi.{domain}"
    records = [t for t in resolver.resolve(name, "TXT") if t.startswith("v=BIMI1")]
    if not records:
        result.summary = "Not published (optional)"
        result.details.append(
            "BIMI shows your logo in some inboxes; it needs DMARC p=quarantine or p=reject and, for Gmail, "
            "a verified mark certificate.")
        return result.settle(INFO)
    result.details.append(f"record: {records[0]}")
    tags, errors = parse_tags(records[0], lower_names=False)
    values = dict(tags)
    logo = values.get("l", "")
    if errors or (logo and not (logo.startswith("https://") and logo.lower().endswith(".svg"))):
        result.add(FAIL, "Invalid BIMI record", "l= must be an https:// URL to an SVG Tiny PS logo.",
                   txt_record(name, f"v=BIMI1; l=https://{domain}/bimi/logo.svg"))
    enforcing = (dmarc_policy or "").lower() in ("quarantine", "reject") and (dmarc_pct in (None, "100"))
    if not enforcing:
        result.add(WARN, "BIMI needs an enforcing DMARC policy",
                   "Mailbox providers only show BIMI logos when DMARC is p=quarantine or p=reject at pct=100.")
    result.summary = "logo " + (logo or "(declined)") + (", VMC present" if values.get("a") else "")
    return result.settle(PASS)
