"""DMARC check: _dmarc TXT record, policy, reporting and alignment tags."""

from __future__ import annotations

import re

from .model import FAIL, INFO, WARN, CheckResult, join_tags, parse_tags, txt_record
from .resolver import Resolver

POLICIES = ("none", "quarantine", "reject")
KNOWN_TAGS = {"v", "p", "sp", "np", "pct", "rua", "ruf", "adkim", "aspf", "fo", "rf", "ri", "psd", "t"}
_MAILTO = re.compile(r"^mailto:([^@\s!,]+)@([A-Za-z0-9.-]+\.[A-Za-z]{2,63})(?:!\d+[kmgtKMGT]?)?$")

STAGED_PATH = (
    "Staged path: (1) p=none with rua reports while you check that every legitimate sender passes "
    "SPF or DKIM with alignment; (2) p=quarantine (optionally with pct below 100 at first) so failing "
    "mail goes to spam; (3) p=reject once reports stay clean."
)


def is_dmarc(txt: str) -> bool:
    return bool(re.match(r"^v\s*=\s*DMARC1\s*(;|$)", txt, re.IGNORECASE))


def _is_external(dest: str, domain: str) -> bool:
    dest, domain = dest.lower(), domain.lower()
    return not (dest == domain or dest.endswith("." + domain) or domain.endswith("." + dest))


def _record(domain: str, tags: list[tuple[str, str]]) -> str:
    return txt_record(f"_dmarc.{domain}", join_tags(tags))


def _with(tags: list[tuple[str, str]], name: str, value: str | None) -> list[tuple[str, str]]:
    """Copy of tags with ``name`` set (appended if new) or removed (value None)."""
    out = []
    done = False
    for k, v in tags:
        if k == name:
            if value is not None:
                out.append((k, value))
            done = True
        else:
            out.append((k, v))
    if not done and value is not None:
        out.append((name, value))
    return out


def check_dmarc(resolver: Resolver, domain: str) -> CheckResult:
    result = CheckResult("DMARC")
    name = f"_dmarc.{domain}"
    records = [t for t in resolver.resolve(name, "TXT") if is_dmarc(t)]
    result.data = {"records": records}
    default_rua = f"mailto:dmarc@{domain}"

    if not records and org_domain(domain) != domain:
        # RFC 7489 6.6.3: receivers fall back to the organizational domain's record (its sp= tag)
        org = org_domain(domain)
        parent = [t for t in resolver.resolve(f"_dmarc.{org}", "TXT") if is_dmarc(t)]
        if len(parent) == 1:
            ptags = dict(parse_tags(parent[0])[0])
            effective = (ptags.get("sp") or ptags.get("p") or "none").lower()
            result.data = {"records": [], "inherited_from": org, "inherited_record": parent[0]}
            result.summary = f"Inherited from {org}: policy {effective} for subdomains"
            result.details.append(f"_dmarc.{org}: {parent[0]}")
            if effective == "none":
                result.add(
                    WARN,
                    "Inherited DMARC policy is none",
                    f"{domain} has no record of its own, so receivers use {org}'s record, whose "
                    f"subdomain policy is none: spoofed mail using {domain} is still delivered. "
                    f"Set sp=quarantine or sp=reject on {org} (or publish a record here). " + STAGED_PATH,
                )
            else:
                result.add(INFO, f"Inherited DMARC policy: {effective}",
                           f"{domain} has no record of its own; receivers apply {org}'s subdomain "
                           f"policy ({effective}). Nothing to publish here.")
            return result.settle()

    if not records:
        result.summary = "No DMARC record"
        result.add(
            FAIL,
            "No DMARC record",
            f"There is no v=DMARC1 TXT record at {name}. Without DMARC, receivers have no instructions "
            "for mail that fails SPF and DKIM, you get no reports about who sends as your domain, and "
            "Gmail and Yahoo require DMARC from bulk senders. Start by monitoring. " + STAGED_PATH,
            txt_record(name, f"v=DMARC1; p=none; rua={default_rua}"),
        )
        return result.settle()

    if len(records) > 1:
        result.summary = f"{len(records)} DMARC records (receivers ignore them all)"
        result.details.extend(f"record: {r}" for r in records)
        result.add(
            FAIL,
            "Multiple DMARC records",
            f"{name} has {len(records)} v=DMARC1 records; receivers then apply no DMARC at all. "
            "Keep exactly one.",
            _record(domain, parse_tags(records[0])[0]),
        )
        return result.settle()

    record = records[0]
    result.details.append(f"record: {record}")
    tags, errors = parse_tags(record)
    values = dict(tags)
    for e in errors:
        result.add(FAIL, "DMARC syntax error", f"{e}. Fix the record so every tag is 'name=value'.")
    if tags and (tags[0][0] != "v" or tags[0][1] != "DMARC1"):
        result.add(WARN, "v=DMARC1 must be first", "The record must start with exactly 'v=DMARC1'.",
                   _record(domain, [("v", "DMARC1")] + _with(tags, "v", None)))
    clean = [(k, v) for k, v in tags if k != "v"]
    clean = [("v", "DMARC1")] + clean

    policy = values.get("p", "").lower()
    if "p" not in values:
        result.add(
            FAIL,
            "DMARC record has no p= tag",
            "The p= tag is required. Without it the record is invalid (receivers that still read it "
            "treat it as p=none). " + STAGED_PATH,
            _record(domain, [("v", "DMARC1"), ("p", "none")] + _with(clean[1:], "rua", values.get("rua") or default_rua)),
        )
    elif policy not in POLICIES:
        result.add(FAIL, f"Invalid policy p={values['p']}",
                   "p= must be none, quarantine or reject.", _record(domain, _with(clean, "p", "none")))
    elif policy == "none":
        result.add(
            WARN,
            "DMARC policy is p=none (monitoring only)",
            "p=none tells receivers to take no action on mail that fails DMARC: spoofed mail is still "
            "delivered normally. It is the right first stage while you read the aggregate reports, but it "
            "does not protect the domain. " + STAGED_PATH,
            _record(domain, _with(clean, "p", "quarantine")),
        )
    elif policy == "quarantine":
        result.add(
            INFO,
            "DMARC policy is p=quarantine",
            "Failing mail goes to spam. When the reports show that all legitimate mail passes, finish the "
            "staged path with p=reject.",
            _record(domain, _with(clean, "p", "reject")),
        )

    sp = values.get("sp")
    if sp is not None:
        if sp.lower() not in POLICIES:
            result.add(FAIL, f"Invalid subdomain policy sp={sp}", "sp= must be none, quarantine or reject.",
                       _record(domain, _with(clean, "sp", None)))
        elif sp.lower() == "none" and policy in ("quarantine", "reject"):
            result.add(
                WARN,
                "Subdomains are not protected (sp=none)",
                f"p={policy} protects {domain}, but sp=none lets anyone spoof made-up subdomains such as "
                f"billing.{domain}. Remove sp= so subdomains inherit p=, or set it to the same policy.",
                _record(domain, _with(clean, "sp", None)),
            )
    result.details.append(
        f"policy: p={values.get('p', '(missing)')}, subdomains sp={sp if sp is not None else '(inherits p)'}")

    pct = values.get("pct")
    if pct is not None:
        if not pct.isdigit() or int(pct) > 100:
            result.add(FAIL, f"Invalid pct={pct}", "pct= must be an integer from 0 to 100.",
                       _record(domain, _with(clean, "pct", None)))
        elif int(pct) < 100:
            result.add(
                WARN,
                f"Policy applies to only {int(pct)}% of failing mail",
                f"pct={pct} applies the policy to that share of failing mail; the rest is handled one step "
                "softer. Useful while ramping up; remove pct (default 100) once reports are clean.",
                _record(domain, _with(clean, "pct", None)),
            )

    for tag in ("rua", "ruf"):
        if tag not in values:
            continue
        for uri in [u.strip() for u in values[tag].split(",") if u.strip()]:
            m = _MAILTO.match(uri)
            if not m:
                if uri.lower().startswith("mailto:"):
                    result.add(FAIL, f"Invalid {tag} address: {uri}",
                               f"{tag}= must hold URIs like mailto:dmarc@{domain}. Fix the address.",
                               _record(domain, _with(clean, tag, default_rua)))
                else:
                    result.add(WARN, f"Unsupported {tag} URI: {uri}",
                               "Receivers only send DMARC reports to mailto: URIs in practice.",
                               _record(domain, _with(clean, tag, default_rua)))
                continue
            dest = m.group(2).lower()
            result.details.append(f"{tag}: {uri}")
            if _is_external(dest, domain):
                result.add(
                    INFO,
                    f"{tag} goes to an external domain ({dest})",
                    f"Reports for {domain} are sent to {dest} only if {dest} authorises it with the TXT "
                    "record below (report services usually publish it for you; this tool does not query "
                    "it).",
                    txt_record(f"{domain}._report._dmarc.{dest}", "v=DMARC1"),
                )
    if "rua" not in values:
        result.add(
            WARN,
            "No aggregate reports (rua)",
            "Without rua= you get no reports showing which servers send as your domain and whether they "
            "pass, so you cannot move safely to a stricter policy.",
            _record(domain, _with(clean, "rua", default_rua)),
        )
    if "ruf" in values:
        result.add(INFO, "Forensic reports (ruf) requested",
                   "Most large receivers do not send ruf failure reports for privacy reasons; rely on rua.")

    for tag, label in (("adkim", "DKIM"), ("aspf", "SPF")):
        v = values.get(tag, "r").lower()
        if v not in ("r", "s"):
            result.add(FAIL, f"Invalid {tag}={values[tag]}", f"{tag}= must be r (relaxed) or s (strict).",
                       _record(domain, _with(clean, tag, None)))
        else:
            mode = "strict: exact domain match" if v == "s" else "relaxed: subdomains of the same organisational domain align"
            result.details.append(f"{label} alignment {tag}={v} ({mode})")

    fo = values.get("fo")
    if fo is not None:
        parts = fo.split(":")
        if not all(p in ("0", "1", "d", "s") for p in parts):
            result.add(FAIL, f"Invalid fo={fo}", "fo= takes 0, 1, d or s, separated by ':'.",
                       _record(domain, _with(clean, "fo", None)))
        elif "ruf" not in values:
            result.add(INFO, "fo= has no effect without ruf=",
                       "fo= selects when failure reports are generated; with no ruf= destination nothing is sent.")

    unknown = [k for k, _ in tags if k not in KNOWN_TAGS]
    if unknown:
        result.add(WARN, "Unknown DMARC tags", f"Receivers ignore: {', '.join(unknown)}. Check for typos.",
                   _record(domain, [(k, v) for k, v in clean if k in KNOWN_TAGS]))

    result.summary = f"p={values.get('p', '(missing)')}" + (f", pct={pct}" if pct else "") + (
        ", aggregate reports on" if "rua" in values else ", no aggregate reports")
    return result.settle()


# Public suffixes with two labels that matter for the demo audience; the rest use the last two labels.
_TWO_LABEL_SUFFIXES = {"co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.nz",
                       "com.br", "com.mx", "com.co", "co.jp", "co.za", "com.ar", "gc.ca", "qc.ca", "on.ca",
                       "nb.ca", "ns.ca", "bc.ca", "ab.ca", "mb.ca", "sk.ca", "nl.ca", "pe.ca"}


def org_domain(domain: str) -> str:
    """Organizational domain (registrable domain) of ``domain``, from a short built-in suffix list."""
    labels = domain.lower().strip(".").split(".")
    if len(labels) <= 2:
        return ".".join(labels)
    n = 3 if ".".join(labels[-2:]) in _TWO_LABEL_SUFFIXES else 2
    return ".".join(labels[-n:])
