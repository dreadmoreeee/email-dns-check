"""Run every check for a domain."""

from __future__ import annotations

from .dkim import check_dkim
from .dmarc import check_dmarc, org_domain
from .model import FAIL, CheckResult, DomainReport, parse_tags
from .mtasts import check_bimi, check_mta_sts, check_tls_rpt
from .mx import check_mx, detect_provider
from .resolver import DNSLookupError, Resolver
from .spf import check_spf


def _safe(name: str, func, *args, **kwargs) -> CheckResult:
    try:
        return func(*args, **kwargs)
    except DNSLookupError as exc:
        result = CheckResult(name, summary="DNS lookup failed")
        result.add(FAIL, "DNS lookup failed", f"{exc}. The check could not be completed; try again later.")
        return result.settle()


def check_domain(domain: str, resolver: Resolver, selectors: list[str] | None = None,
                 fetcher=None, https: bool = True) -> DomainReport:
    report = DomainReport(domain)
    mx = _safe("MX", check_mx, resolver, domain)
    report.checks.append(mx)
    hosts = [r["host"] for r in mx.data.get("records", []) if r["host"] != "."]
    # null MX, or a subdomain with no MX at all (e.g. a website host that never sends mail)
    no_mail = (bool(mx.data.get("records")) and not hosts) or (
        not mx.data.get("records") and org_domain(domain) != domain)
    provider = detect_provider(hosts)

    report.checks.append(_safe("SPF", check_spf, resolver, domain, provider, no_mail))
    dmarc = _safe("DMARC", check_dmarc, resolver, domain)
    report.checks.append(dmarc)
    report.checks.append(_safe("DKIM", check_dkim, resolver, domain, selectors, provider))
    sts = _safe("MTA-STS", check_mta_sts, resolver, domain, fetcher, hosts, https)
    report.checks.append(sts)
    sts_published = "Not published" not in sts.summary
    report.checks.append(_safe("TLS-RPT", check_tls_rpt, resolver, domain, sts_published))

    policy = pct = None
    records = dmarc.data.get("records") or []
    if len(records) == 1:
        tags = dict(parse_tags(records[0])[0])
        policy, pct = tags.get("p"), tags.get("pct")
    report.checks.append(_safe("BIMI", check_bimi, resolver, domain, policy, pct))
    return report
