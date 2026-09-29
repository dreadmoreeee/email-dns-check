"""MX check: records exist, targets resolve, no null MX surprises or CNAMEs."""

from __future__ import annotations

import ipaddress

from .model import FAIL, INFO, WARN, CheckResult
from .resolver import Resolver

# Suffix of the MX host -> (provider name, SPF include, usual DKIM selectors)
PROVIDERS = [
    (("google.com", "googlemail.com"), "Google Workspace", "_spf.google.com", ["google"]),
    (("mail.protection.outlook.com",), "Microsoft 365", "spf.protection.outlook.com", ["selector1", "selector2"]),
    (("zoho.com", "zoho.eu", "zohomail.com"), "Zoho Mail", "zohomail.com", ["zmail"]),
    (("messagingengine.com",), "Fastmail", "spf.messagingengine.com", ["fm1", "fm2", "fm3"]),
    (("protonmail.ch",), "Proton Mail", "_spf.protonmail.ch", ["protonmail", "protonmail2", "protonmail3"]),
]


def detect_provider(hosts: list[str]) -> dict | None:
    for host in hosts:
        for suffixes, name, spf_include, selectors in PROVIDERS:
            if any(host == s or host.endswith("." + s) for s in suffixes):
                return {"name": name, "spf_include": spf_include, "dkim_selectors": selectors}
    return None


def parse_mx(value: str) -> tuple[int, str] | None:
    parts = value.split()
    if len(parts) != 2 or not parts[0].isdigit():
        return None
    host = parts[1]
    host = "." if host == "." else host.rstrip(".").lower()
    return int(parts[0]), host


def _is_ip(text: str) -> bool:
    try:
        ipaddress.ip_address(text)
    except ValueError:
        return False
    return True


def check_mx(resolver: Resolver, domain: str) -> CheckResult:
    result = CheckResult("MX")
    raw = resolver.resolve(domain, "MX")
    records = sorted(filter(None, (parse_mx(v) for v in raw)))
    result.data = {"records": [{"priority": p, "host": h} for p, h in records], "provider": None}

    if not records:
        addresses = resolver.resolve(domain, "A") + resolver.resolve(domain, "AAAA")
        if addresses:
            result.summary = "No MX records; mail falls back to the domain's A/AAAA address"
            result.add(
                WARN,
                "No MX records",
                f"{domain} has no MX records, so senders fall back to its A/AAAA address "
                f"({', '.join(addresses)}) as an implicit MX. That is usually a web server, not a mail "
                "server. Publish MX records for your mail provider, or a null MX if the domain never "
                "receives mail.",
                f"{domain}. MX 0 .",
            )
        else:
            result.summary = "No MX records and no A/AAAA fallback: the domain cannot receive mail"
            result.add(
                FAIL,
                "No MX records",
                f"{domain} has no MX, A or AAAA records, so mail to it cannot be delivered. Publish the "
                "MX records your mail provider gives you (or a null MX if the domain never receives mail).",
                f"{domain}. MX 10 mx.your-provider.example.",
            )
        return result.settle()

    null = [h for _, h in records if h == "."]
    if null:
        if len(records) == 1 and records[0][0] == 0:
            result.summary = "Null MX: the domain declares that it accepts no mail"
            result.details.append("0 . (null MX, RFC 7505)")
            result.add(
                INFO,
                "Null MX published",
                f"{domain} publishes a null MX ('0 .'), which tells senders it never accepts mail. "
                "That is correct for a domain that only sends or does not use email; remove it if you "
                "expect to receive mail. A no-mail domain should also publish 'v=spf1 -all' and a "
                "DMARC p=reject record.",
            )
            return result.settle()
        result.add(
            FAIL,
            "Null MX mixed with other MX records",
            "A null MX ('0 .') must be the only MX record (RFC 7505). Mixed with real MX hosts it "
            "confuses senders. Remove the null MX if the domain receives mail.",
        )
        records = [r for r in records if r[1] != "."]

    provider = detect_provider([h for _, h in records])
    result.data["provider"] = provider["name"] if provider else None
    unresolved = 0
    for priority, host in records:
        if _is_ip(host):
            result.details.append(f"{priority} {host} (IP address, not a host name)")
            result.add(
                FAIL,
                f"MX target {host} is an IP address",
                "An MX record must point to a host name, never an IP address. Create an A record for "
                "a name such as mail." + domain + " and point the MX at it.",
                f"{domain}. MX {priority} mail.{domain}.",
            )
            unresolved += 1
            continue
        addresses = resolver.resolve(host, "A") + resolver.resolve(host, "AAAA")
        cname = resolver.resolve(host, "CNAME")
        line = f"{priority} {host}"
        if cname:
            line += f" (CNAME to {cname[0]})"
            result.add(
                WARN,
                f"MX target {host} is a CNAME",
                "RFC 2181 and RFC 5321 require an MX to point at a name with its own A/AAAA records, "
                "not at an alias. Many senders cope, some do not. Point the MX at the canonical name.",
                f"{domain}. MX {priority} {cname[0]}.",
            )
        if addresses:
            line += " -> " + ", ".join(addresses)
        else:
            line += " -> does not resolve"
            unresolved += 1
            result.add(
                FAIL,
                f"MX target {host} does not resolve",
                f"{host} has no A or AAAA record, so senders cannot connect to it. Fix the host's "
                "address records or remove this MX.",
            )
        result.details.append(line)

    count = len(records)
    who = f" ({provider['name']})" if provider else ""
    if unresolved:
        result.summary = f"{count} MX host(s){who}, {unresolved} not resolving"
    else:
        result.summary = f"{count} MX host(s){who}, all resolve"
    return result.settle()
