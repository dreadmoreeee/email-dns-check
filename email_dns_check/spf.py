"""SPF check: one record, valid syntax, lookup limits, loops and the final 'all'."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field

from .model import FAIL, INFO, WARN, CheckResult, txt_record
from .resolver import DNSLookupError, Resolver

LOOKUP_LIMIT = 10
VOID_LIMIT = 2
MX_HOST_LIMIT = 10
# Stop expanding after this many lookups or this depth; the verdict is already clear.
HARD_LOOKUP_CAP = 40
MAX_DEPTH = 12

MECHANISMS = {"all", "include", "a", "mx", "ptr", "ip4", "ip6", "exists"}
LOOKUP_MECHANISMS = {"include", "a", "mx", "ptr", "exists"}
QUALIFIERS = {"+": "pass", "-": "fail", "~": "softfail", "?": "neutral"}

_SPF_START = re.compile(r"^v=spf1( |$)", re.IGNORECASE)
_MODIFIER = re.compile(r"^([A-Za-z][A-Za-z0-9_.-]*)=(.*)$")
_LABEL = re.compile(r"^(?!-)[A-Za-z0-9_-]{1,63}(?<!-)$")
_MACRO = re.compile(r"%(?:\{[slodiphcrtvSLODIPHCRTV]\d*r?[-.+,/_=]*\}|%|_|-)")


def is_spf(txt: str) -> bool:
    return bool(_SPF_START.match(txt))


def spf_records(txts: list[str]) -> list[str]:
    return [t for t in txts if is_spf(t)]


@dataclass
class Term:
    raw: str
    kind: str  # "mechanism" or "modifier"
    name: str
    qualifier: str = "+"
    value: str | None = None


def has_macro(text: str) -> bool:
    return "%" in text


def valid_domain_spec(spec: str) -> bool:
    if not spec:
        return False
    if has_macro(spec):
        rest = _MACRO.sub("", spec)
        return "%" not in rest and " " not in rest
    spec = spec.rstrip(".")
    labels = spec.split(".")
    if len(spec) > 253 or len(labels) < 2:
        return False
    if not all(_LABEL.match(label) for label in labels):
        return False
    return not labels[-1].isdigit()


def _valid_cidr(text: str | None, maximum: int) -> bool:
    return text is None or (text.isdigit() and 0 <= int(text) <= maximum and str(int(text)) == text)


def parse_spf(record: str) -> tuple[list[Term], list[str]]:
    """Parse an SPF record into terms. Returns (terms, syntax errors)."""
    tokens = record.split()
    errors: list[str] = []
    terms: list[Term] = []
    if not tokens or tokens[0].lower() != "v=spf1":
        return [], ["record does not start with 'v=spf1'"]
    modifiers_seen: set[str] = set()
    for tok in tokens[1:]:
        m = _MODIFIER.match(tok)
        if m and m.group(1).lower() not in MECHANISMS:
            name, value = m.group(1).lower(), m.group(2)
            if name in ("redirect", "exp"):
                if name in modifiers_seen:
                    errors.append(f"'{name}=' appears more than once")
                if not valid_domain_spec(value):
                    errors.append(f"'{tok}': '{value}' is not a valid domain")
            modifiers_seen.add(name)
            terms.append(Term(tok, "modifier", name, value=value))
            continue
        qualifier = "+"
        rest = tok
        if rest[:1] in QUALIFIERS:
            qualifier, rest = rest[0], rest[1:]
        m = re.match(r"[A-Za-z][A-Za-z0-9_.-]*", rest)
        name = m.group(0).lower() if m else ""
        if name not in MECHANISMS:
            if "=" in tok:
                errors.append(f"'{tok}' is not a valid modifier")
            else:
                errors.append(f"'{tok}' is not a known mechanism")
            continue
        arg = rest[len(name):]
        value: str | None = None
        ok = True
        if name == "all":
            ok = arg == ""
        elif name in ("include", "exists"):
            ok = arg.startswith(":") and valid_domain_spec(arg[1:])
            value = arg[1:]
        elif name in ("a", "mx"):
            m2 = re.fullmatch(r"(?::([^/]+))?(?:/(\d+))?(?://(\d+))?", arg)
            ok = bool(m2)
            if m2:
                value = m2.group(1)
                ok = (value is None or valid_domain_spec(value)) and _valid_cidr(m2.group(2), 32) and _valid_cidr(m2.group(3), 128)
        elif name == "ptr":
            if arg:
                ok = arg.startswith(":") and valid_domain_spec(arg[1:])
                value = arg[1:]
        elif name in ("ip4", "ip6"):
            ok = arg.startswith(":")
            value = arg[1:]
            if ok:
                addr, slash, prefix = value.partition("/")
                try:
                    if name == "ip4":
                        ipaddress.IPv4Address(addr)
                        ok = not slash or _valid_cidr(prefix, 32)
                    else:
                        ipaddress.IPv6Address(addr)
                        ok = not slash or _valid_cidr(prefix, 128)
                except ValueError:
                    ok = False
        if not ok:
            errors.append(f"'{tok}' has an invalid argument for '{name}'")
            continue
        terms.append(Term(tok, "mechanism", name, qualifier, value))
    return terms, errors


@dataclass
class Expansion:
    lookups: int = 0
    voids: int = 0
    loops: list[str] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)
    ptr_sites: list[str] = field(default_factory=list)
    tree: list[str] = field(default_factory=list)
    truncated: bool = False
    temp_errors: list[str] = field(default_factory=list)


def _lookup(resolver: Resolver, state: Expansion, name: str, rtype: str) -> list[str]:
    try:
        return resolver.resolve(name, rtype)
    except DNSLookupError as exc:
        state.temp_errors.append(str(exc))
        return []


def expand(resolver: Resolver, domain: str, record: str) -> Expansion:
    """Walk the record and every include/redirect, counting DNS-querying terms."""
    state = Expansion()
    _walk(resolver, domain, record, [domain], state, 0)
    return state


def _walk(resolver: Resolver, domain: str, record: str, stack: list[str], state: Expansion, depth: int) -> None:
    indent = "  " * depth
    terms, errors = parse_spf(record)
    if depth > 0:
        for e in errors:
            state.problems.append(f"{domain}: {e}")
    has_all = any(t.kind == "mechanism" and t.name == "all" for t in terms)
    for term in terms:
        if term.kind == "modifier" and term.name == "redirect":
            if has_all:
                state.tree.append(f"{indent}{term.raw} (ignored: record has an 'all' mechanism)")
                continue
            state.lookups += 1
            state.tree.append(f"{indent}{term.raw} [lookup {state.lookups}]")
            _follow(resolver, domain, term, stack, state, depth, "redirect")
            continue
        if term.kind != "mechanism" or term.name not in LOOKUP_MECHANISMS:
            continue
        state.lookups += 1
        line = f"{indent}{term.raw} [lookup {state.lookups}]"
        target = (term.value or domain).rstrip(".").lower()
        if term.name == "include":
            state.tree.append(line)
            _follow(resolver, domain, term, stack, state, depth, "include")
        elif term.name == "a":
            if has_macro(target):
                state.tree.append(line + " (macro, not expanded)")
                continue
            addrs = _lookup(resolver, state, target, "A") + _lookup(resolver, state, target, "AAAA")
            if not addrs:
                state.voids += 1
                line += " (no A/AAAA: void lookup)"
            state.tree.append(line)
        elif term.name == "mx":
            if has_macro(target):
                state.tree.append(line + " (macro, not expanded)")
                continue
            hosts = _lookup(resolver, state, target, "MX")
            if not hosts:
                state.voids += 1
                line += " (no MX: void lookup)"
            elif len(hosts) > MX_HOST_LIMIT:
                state.problems.append(
                    f"{domain}: '{term.raw}' matches {len(hosts)} MX hosts; SPF allows at most {MX_HOST_LIMIT}")
            state.tree.append(line)
        elif term.name == "ptr":
            state.ptr_sites.append(domain)
            state.tree.append(line + " (ptr is deprecated)")
        else:  # exists
            state.tree.append(line)


def _follow(resolver: Resolver, domain: str, term: Term, stack: list[str], state: Expansion, depth: int, kind: str) -> None:
    indent = "  " * (depth + 1)
    target = (term.value or "").rstrip(".").lower()
    if has_macro(target):
        state.tree.append(f"{indent}(macro, not expanded)")
        return
    if target in stack:
        chain = " -> ".join(stack + [target])
        state.loops.append(chain)
        state.tree.append(f"{indent}LOOP: {chain}")
        return
    if state.lookups > HARD_LOOKUP_CAP or depth >= MAX_DEPTH:
        state.truncated = True
        state.tree.append(f"{indent}(expansion stopped)")
        return
    txts = _lookup(resolver, state, target, "TXT")
    found = spf_records(txts)
    if not found:
        if not txts:
            state.voids += 1
        state.problems.append(f"{kind}:{target} has no SPF record (permerror for receivers)")
        state.tree.append(f"{indent}(no SPF record at {target})")
        return
    if len(found) > 1:
        state.problems.append(f"{kind}:{target} publishes {len(found)} SPF records (permerror for receivers)")
        state.tree.append(f"{indent}({len(found)} SPF records at {target})")
        return
    _walk(resolver, target, found[0], stack + [target], state, depth + 1)


def suggested_record(domain: str, provider: dict | None, no_mail: bool = False) -> str:
    if no_mail:
        return txt_record(domain, "v=spf1 -all")
    if provider:
        return txt_record(domain, f"v=spf1 include:{provider['spf_include']} ~all")
    return txt_record(domain, "v=spf1 mx ~all")


def _replace_all(terms: list[Term], qualifier: str) -> str:
    parts = ["v=spf1"]
    for t in terms:
        parts.append(f"{qualifier}all" if t.kind == "mechanism" and t.name == "all" else t.raw)
    return " ".join(parts)


def _without(terms: list[Term], drop) -> str:
    return " ".join(["v=spf1"] + [t.raw for t in terms if not drop(t)])


def check_spf(resolver: Resolver, domain: str, provider: dict | None = None, no_mail: bool = False) -> CheckResult:
    result = CheckResult("SPF")
    txts = resolver.resolve(domain, "TXT")
    records = spf_records(txts)
    result.data = {"records": records}
    if not records:
        result.summary = "No SPF record"
        result.add(
            FAIL,
            "No SPF record",
            f"{domain} publishes no 'v=spf1' TXT record, so receivers cannot tell which servers may send "
            "its mail and spoofed mail is easier to deliver. Publish one record that lists every service "
            "that sends as this domain.",
            suggested_record(domain, provider, no_mail),
        )
        return result.settle()

    if len(records) > 1:
        result.summary = f"{len(records)} SPF records (receivers return permerror)"
        for r in records:
            result.details.append(f"record: {r}")
        merged: list[str] = []
        for r in records:
            for tok in r.split()[1:]:
                low = tok.lower()
                if low.lstrip("+-~?") == "all" or low.startswith("redirect="):
                    continue
                if tok not in merged:
                    merged.append(tok)
        result.add(
            FAIL,
            "Multiple SPF records",
            "A domain must publish exactly one SPF record. With two or more, receivers stop and return "
            "permerror, which is treated like having no SPF at all. Merge them into a single record and "
            "delete the others.",
            txt_record(domain, " ".join(["v=spf1"] + merged + ["~all"])),
        )
        return result.settle()

    record = records[0]
    result.details.append(f"record: {record}")
    terms, errors = parse_spf(record)
    for e in errors:
        result.add(
            FAIL,
            "SPF syntax error",
            f"{e}. Receivers treat a record with a syntax error as permerror, as if no SPF existed. "
            "Fix or remove the term.",
        )

    state = expand(resolver, domain, record)
    result.data.update({"lookups": state.lookups, "void_lookups": state.voids})
    if state.tree:
        result.details.append("expansion:")
        result.details.extend("  " + line for line in state.tree)

    if state.lookups > LOOKUP_LIMIT:
        includes = [t.raw for t in terms if t.kind == "mechanism" and t.name == "include"]
        dupes = sorted({i for i in includes if includes.count(i) > 1})
        explanation = (
            f"Evaluating this record needs {state.lookups}{'+' if state.truncated else ''} DNS lookups "
            f"(include, a, mx, ptr, exists and redirect each count, including inside includes). The limit "
            f"is {LOOKUP_LIMIT}; past it receivers return permerror and SPF fails for every message. "
            "Remove includes for services that no longer send mail, replace 'a'/'mx' with ip4:/ip6: "
            "ranges, or move some senders to a subdomain."
        )
        fix = None
        if dupes:
            explanation += " Duplicate includes: " + ", ".join(dupes) + "."
            seen: set[str] = set()
            kept = []
            for t in terms:
                if t.raw in dupes and t.raw in seen:
                    continue
                seen.add(t.raw)
                kept.append(t)
            fix = txt_record(domain, _without(kept, lambda t: False))
        result.add(FAIL, f"Too many DNS lookups ({state.lookups} > {LOOKUP_LIMIT})", explanation, fix)

    if state.voids > VOID_LIMIT:
        result.add(
            FAIL,
            f"Too many void lookups ({state.voids} > {VOID_LIMIT})",
            "Terms that point at names with no records count as void lookups; more than two make "
            "receivers return permerror (RFC 7208, 4.6.4). Remove the terms that point at missing names.",
        )

    for chain in state.loops:
        looping = chain.split(" -> ")[1] if chain.count(" -> ") == 1 else None
        fix = None
        if looping:
            fix = txt_record(domain, _without(terms, lambda t: t.name in ("include", "redirect") and (t.value or "").rstrip(".").lower() == looping))
        result.add(
            FAIL,
            "SPF include loop",
            f"The record includes itself through {chain}. Receivers detect the loop (or run out of "
            "lookups) and return permerror. Remove the include that points back up the chain.",
            fix,
        )

    for problem in state.problems:
        result.add(
            FAIL,
            "Broken include or redirect",
            f"{problem}. Receivers return permerror when a referenced domain has no single valid SPF "
            "record. Remove the term or ask that service for the correct include.",
        )

    for err in state.temp_errors[:3]:
        result.add(WARN, "DNS error during SPF expansion", f"{err}. The lookup count may be incomplete.")

    ptr_top = [t for t in terms if t.kind == "mechanism" and t.name == "ptr"]
    if ptr_top:
        result.add(
            WARN,
            "Uses the ptr mechanism",
            "'ptr' is slow, unreliable and deprecated (RFC 7208, 5.5); many receivers ignore it. "
            "List the sending servers with ip4:/ip6: or include: instead.",
            txt_record(domain, _without(terms, lambda t: t.kind == "mechanism" and t.name == "ptr")),
        )
    nested_ptr = sorted({d for d in state.ptr_sites if d != domain})
    if nested_ptr:
        result.add(
            WARN,
            "An included record uses ptr",
            f"{', '.join(nested_ptr)} uses the deprecated 'ptr' mechanism; it still costs lookups here.",
        )

    all_terms = [t for t in terms if t.kind == "mechanism" and t.name == "all"]
    redirect = next((t for t in terms if t.kind == "modifier" and t.name == "redirect"), None)
    ending = "no 'all'"
    if all_terms:
        final = all_terms[0]
        ending = final.raw if final.raw[0] in QUALIFIERS else "+all"
        index = terms.index(final)
        ignored = [t.raw for t in terms[index + 1:] if t.kind == "mechanism"]
        if ignored:
            result.add(
                WARN,
                "Terms after 'all' are ignored",
                f"Evaluation stops at '{final.raw}', so {' '.join(ignored)} never match. Move them before 'all'.",
                txt_record(domain, " ".join(["v=spf1"] + [t.raw for t in terms if t is not final] + [final.raw])),
            )
        if final.qualifier == "+":
            result.add(
                FAIL,
                "SPF ends with +all",
                "'+all' authorises every server on the internet to send as this domain, which makes SPF "
                "useless and helps spoofers. End the record with '~all' (softfail) or '-all' (fail).",
                txt_record(domain, _replace_all(terms, "~")),
            )
        elif final.qualifier == "?":
            result.add(
                WARN,
                "SPF ends with ?all",
                "'?all' (neutral) says nothing about servers not listed, so SPF gives no protection. "
                "End the record with '~all' or '-all'.",
                txt_record(domain, _replace_all(terms, "~")),
            )
        elif final.qualifier == "~":
            result.add(
                INFO,
                "SPF ends with ~all (softfail)",
                "'~all' vs '-all' is a policy choice. With DMARC enforcing, '~all' is common and safe; "
                "'-all' asks receivers to reject unlisted senders outright, which can also break forwarded mail.",
            )
        else:
            result.add(
                INFO,
                "SPF ends with -all (fail)",
                "'-all' vs '~all' is a policy choice. '-all' asks receivers to reject unlisted senders; "
                "some reject before DMARC is evaluated, which can hurt forwarded mail. '~all' plus DMARC "
                "p=reject is the common alternative.",
            )
    elif redirect is None:
        result.add(
            WARN,
            "SPF has no 'all' mechanism",
            "Without a final 'all', mail from unlisted servers gets a neutral result, as with '?all'. "
            "End the record with '~all' or '-all'.",
            txt_record(domain, record.strip() + " ~all"),
        )
    else:
        ending = f"policy from {redirect.raw}"

    result.summary = (
        f"1 record, {state.lookups}/{LOOKUP_LIMIT} DNS lookups, {state.voids}/{VOID_LIMIT} void lookups, "
        f"ends with {ending}"
    )
    return result.settle()
