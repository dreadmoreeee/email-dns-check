"""Command line: email-dns-check DOMAIN [DOMAIN ...]."""

from __future__ import annotations

import argparse
import re
import sys

from . import __version__
from .checker import check_domain
from .fetch import UrllibFetcher
from .model import FAIL
from .report import render

EXIT_OK = 0
EXIT_FAILED = 1
EXIT_USAGE = 2

_LABEL = re.compile(r"^(?!-)[a-z0-9_-]{1,63}(?<!-)$")


def normalize_domain(text: str) -> str:
    """Lower-case, strip a trailing dot, IDNA-encode and validate a domain name."""
    domain = text.strip().rstrip(".").lower()
    try:
        domain = domain.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError(f"invalid domain: {text!r}") from exc
    labels = domain.split(".")
    if len(labels) < 2 or len(domain) > 253 or not all(_LABEL.match(label) for label in labels):
        raise ValueError(f"invalid domain: {text!r}")
    return domain


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="email-dns-check",
        description="Check a domain's email authentication DNS records (MX, SPF, DMARC, DKIM, "
                    "MTA-STS, TLS-RPT, BIMI), explain each problem and print the record to publish.",
        epilog="Exit status: 0 if no check failed (warnings allowed), 1 if any check failed, "
               "2 on usage errors.",
    )
    parser.add_argument("domains", nargs="+", metavar="DOMAIN", help="domain to check")
    parser.add_argument("-s", "--selector", action="append", default=[], metavar="S",
                        help="extra DKIM selector to probe (repeatable)")
    parser.add_argument("-f", "--format", choices=["text", "json", "markdown"], default="text",
                        help="output format (default: text)")
    parser.add_argument("--no-https", action="store_true",
                        help="do not fetch the MTA-STS policy file over HTTPS")
    parser.add_argument("--timeout", type=float, default=5.0, metavar="SECONDS",
                        help="DNS timeout per query (default: 5)")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def main(argv: list[str] | None = None, resolver=None, fetcher=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        domains = [normalize_domain(d) for d in args.domains]
    except ValueError as exc:
        parser.error(str(exc))
    if resolver is None:
        from .resolver import DnsPythonResolver

        resolver = DnsPythonResolver(timeout=args.timeout)
    if fetcher is None and not args.no_https:
        fetcher = UrllibFetcher()
    reports = [
        check_domain(d, resolver, selectors=args.selector, fetcher=fetcher, https=not args.no_https)
        for d in dict.fromkeys(domains)
    ]
    sys.stdout.write(render(reports, args.format))
    sys.stdout.flush()
    return EXIT_FAILED if any(r.status == FAIL for r in reports) else EXIT_OK
