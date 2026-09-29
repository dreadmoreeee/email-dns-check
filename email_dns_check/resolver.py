"""DNS access behind a tiny interface so checks can run against fake data.

A resolver has one method, ``resolve(name, rtype) -> list[str]``:

* an empty list means NXDOMAIN or "no records of that type" (a void answer);
* ``DNSLookupError`` means the lookup could not be completed (timeout,
  SERVFAIL, no reachable name server);
* records come back as text: ``A``/``AAAA`` addresses, ``MX`` as
  ``"10 mx.example.com"`` (``"0 ."`` for a null MX), ``TXT`` with the
  character strings already joined, ``CNAME`` as the target name.
"""

from __future__ import annotations

from typing import Iterable, Mapping, Protocol


class DNSLookupError(Exception):
    """A DNS query failed for a reason other than 'no such record'."""


class Resolver(Protocol):
    def resolve(self, name: str, rtype: str) -> list[str]: ...


def normalize_name(name: str) -> str:
    name = name.strip().lower()
    if name != ".":
        name = name.rstrip(".")
    return name


def rdata_to_text(rdata) -> str:
    """Convert a dnspython rdata object to the text form described above."""
    rtype = rdata.rdtype.name if hasattr(rdata.rdtype, "name") else str(rdata.rdtype)
    if rtype in ("A", "AAAA"):
        return rdata.address
    if rtype == "MX":
        exchange = rdata.exchange.to_text()
        exchange = "." if exchange == "." else exchange.rstrip(".").lower()
        return f"{rdata.preference} {exchange}"
    if rtype == "TXT":
        return b"".join(rdata.strings).decode("utf-8", errors="replace")
    if rtype == "CNAME":
        return rdata.target.to_text().rstrip(".").lower()
    return rdata.to_text()


class DnsPythonResolver:
    """Real resolver built on dnspython, with a small per-run cache."""

    def __init__(self, timeout: float = 5.0, nameservers: Iterable[str] | None = None):
        import dns.resolver

        self._resolver = dns.resolver.Resolver()
        self._resolver.lifetime = timeout
        if nameservers:
            self._resolver.nameservers = list(nameservers)
        self._cache: dict[tuple[str, str], list[str]] = {}
        self.queries = 0

    def resolve(self, name: str, rtype: str) -> list[str]:
        import dns.exception
        import dns.resolver

        key = (normalize_name(name), rtype.upper())
        if key in self._cache:
            return list(self._cache[key])
        self.queries += 1
        try:
            answer = self._resolver.resolve(key[0] + ".", key[1], raise_on_no_answer=False)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            result: list[str] = []
        except dns.exception.DNSException as exc:
            raise DNSLookupError(f"{key[1]} lookup for {key[0]} failed: {exc.__class__.__name__}") from exc
        else:
            rrset = answer.rrset
            result = [] if rrset is None else [rdata_to_text(r) for r in rrset]
        self._cache[key] = result
        return list(result)


class FakeResolver:
    """Resolver backed by a dict, for tests and offline examples.

    ``records`` maps a name to ``{rtype: [values]}``::

        FakeResolver({"example.com": {"MX": ["10 mx.example.com"],
                                      "TXT": ["v=spf1 mx -all"]},
                      "mx.example.com": {"A": ["192.0.2.10"]}})

    A value may also be an exception instance, which is raised when that
    name/type is queried (use ``DNSLookupError(...)`` to simulate SERVFAIL).
    CNAMEs are followed for every type except CNAME itself.
    """

    def __init__(self, records: Mapping[str, Mapping[str, object]]):
        self.records = {
            normalize_name(name): {rtype.upper(): value for rtype, value in types.items()}
            for name, types in records.items()
        }
        self.queries: list[tuple[str, str]] = []

    def resolve(self, name: str, rtype: str) -> list[str]:
        name, rtype = normalize_name(name), rtype.upper()
        self.queries.append((name, rtype))
        seen = set()
        while True:
            entry = self.records.get(name, {})
            value = entry.get(rtype)
            if isinstance(value, Exception):
                raise value
            if value is not None:
                return list(value)
            cname = entry.get("CNAME")
            if rtype == "CNAME" or not cname or name in seen:
                return []
            seen.add(name)
            name = normalize_name(cname[0])
