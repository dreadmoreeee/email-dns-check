"""Check a domain's email authentication DNS records (MX, SPF, DMARC, DKIM, MTA-STS, TLS-RPT, BIMI)."""

__version__ = "1.0.0"

from .checker import check_domain  # noqa: E402
from .model import CheckResult, DomainReport, Finding  # noqa: E402
from .resolver import DNSLookupError, DnsPythonResolver, FakeResolver  # noqa: E402

__all__ = [
    "__version__",
    "check_domain",
    "CheckResult",
    "DomainReport",
    "Finding",
    "DNSLookupError",
    "DnsPythonResolver",
    "FakeResolver",
]
