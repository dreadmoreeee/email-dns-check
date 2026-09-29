"""Result objects shared by all checks, plus small record helpers."""

from __future__ import annotations

from dataclasses import dataclass, field

PASS = "pass"
INFO = "info"
WARN = "warn"
FAIL = "fail"

_RANK = {PASS: 0, INFO: 1, WARN: 2, FAIL: 3}


@dataclass
class Finding:
    """One problem or note. ``record`` is the exact DNS record to publish."""

    severity: str
    title: str
    explanation: str
    record: str | None = None

    def to_dict(self) -> dict:
        return {
            "severity": self.severity,
            "title": self.title,
            "explanation": self.explanation,
            "record": self.record,
        }


@dataclass
class CheckResult:
    name: str
    status: str = PASS
    summary: str = ""
    details: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    data: dict = field(default_factory=dict)

    def add(self, severity: str, title: str, explanation: str, record: str | None = None) -> Finding:
        finding = Finding(severity, title, explanation, record)
        self.findings.append(finding)
        return finding

    def settle(self, default: str = PASS) -> "CheckResult":
        """Set the status from the findings: fail > warn > ``default``."""
        worst = default
        for f in self.findings:
            if f.severity in (FAIL, WARN) and _RANK[f.severity] > _RANK[worst]:
                worst = f.severity
        self.status = worst
        return self

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "status": self.status,
            "summary": self.summary,
            "details": list(self.details),
            "findings": [f.to_dict() for f in self.findings],
            "data": self.data,
        }


@dataclass
class DomainReport:
    domain: str
    checks: list[CheckResult] = field(default_factory=list)

    @property
    def status(self) -> str:
        """Overall status: fail if any check failed, else warn, else pass."""
        statuses = {c.status for c in self.checks}
        if FAIL in statuses:
            return FAIL
        if WARN in statuses:
            return WARN
        return PASS

    def check(self, name: str) -> CheckResult:
        for c in self.checks:
            if c.name == name:
                return c
        raise KeyError(name)

    def to_dict(self) -> dict:
        return {
            "domain": self.domain,
            "status": self.status,
            "checks": [c.to_dict() for c in self.checks],
        }


def txt_record(name: str, value: str) -> str:
    """Zone-file style TXT record, split into 255-byte strings if needed."""
    chunks = [value[i:i + 255] for i in range(0, len(value), 255)] or [""]
    quoted = " ".join('"' + c.replace("\\", "\\\\").replace('"', '\\"') + '"' for c in chunks)
    return f"{name}. TXT {quoted}"


def parse_tags(text: str, lower_names: bool = True) -> tuple[list[tuple[str, str]], list[str]]:
    """Parse ``tag=value; tag=value`` lists (DMARC, DKIM, MTA-STS, TLS-RPT, BIMI).

    Returns the tags in order and a list of syntax errors.
    """
    tags: list[tuple[str, str]] = []
    errors: list[str] = []
    seen: set[str] = set()
    for part in text.split(";"):
        part = part.strip()
        if not part:
            continue
        if "=" not in part:
            errors.append(f"'{part}' is not a tag=value pair")
            continue
        name, value = part.split("=", 1)
        name = name.strip()
        if lower_names:
            name = name.lower()
        value = value.strip()
        if not name:
            errors.append(f"'{part}' has an empty tag name")
            continue
        if name in seen:
            errors.append(f"tag '{name}' appears more than once")
            continue
        seen.add(name)
        tags.append((name, value))
    return tags, errors


def join_tags(tags: list[tuple[str, str]]) -> str:
    return "; ".join(f"{k}={v}" for k, v in tags)
