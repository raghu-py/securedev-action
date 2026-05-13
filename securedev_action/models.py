from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from hashlib import sha256
from typing import Any


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, raw: str) -> "Severity | None":
        value = (raw or "").strip().lower()
        aliases = {
            "info": cls.INFO,
            "informational": cls.INFO,
            "low": cls.LOW,
            "medium": cls.MEDIUM,
            "moderate": cls.MEDIUM,
            "high": cls.HIGH,
            "critical": cls.CRITICAL,
            "crit": cls.CRITICAL,
        }
        return aliases.get(value)

    @property
    def label(self) -> str:
        return self.name.lower()

    @property
    def sarif_level(self) -> str:
        if self in (Severity.CRITICAL, Severity.HIGH):
            return "error"
        if self == Severity.MEDIUM:
            return "warning"
        if self == Severity.LOW:
            return "note"
        return "none"


@dataclass(frozen=True)
class Rule:
    rule_id: str
    name: str
    severity: Severity
    category: str
    message: str
    recommendation: str
    cwe: str | None = None
    help_uri: str | None = None
    tags: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class Finding:
    rule_id: str
    title: str
    severity: Severity
    category: str
    message: str
    recommendation: str
    file_path: str
    line: int
    column: int
    snippet: str
    cwe: str | None = None
    confidence: str = "medium"
    fingerprint: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def with_fingerprint(self) -> "Finding":
        if self.fingerprint:
            return self
        digest_input = "|".join(
            [
                self.rule_id,
                self.file_path.replace("\\", "/"),
                str(self.line),
                self.snippet.strip(),
            ]
        )
        fp = sha256(digest_input.encode("utf-8", errors="ignore")).hexdigest()[:32]
        return Finding(
            rule_id=self.rule_id,
            title=self.title,
            severity=self.severity,
            category=self.category,
            message=self.message,
            recommendation=self.recommendation,
            file_path=self.file_path,
            line=self.line,
            column=self.column,
            snippet=self.snippet,
            cwe=self.cwe,
            confidence=self.confidence,
            fingerprint=fp,
            metadata=dict(self.metadata),
        )

    def to_dict(self, include_snippet: bool = True) -> dict[str, Any]:
        data: dict[str, Any] = {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.label,
            "category": self.category,
            "message": self.message,
            "recommendation": self.recommendation,
            "file": self.file_path,
            "line": self.line,
            "column": self.column,
            "cwe": self.cwe,
            "confidence": self.confidence,
            "fingerprint": self.fingerprint,
            "metadata": self.metadata,
        }
        if include_snippet:
            data["snippet"] = self.snippet
        return data


@dataclass
class ScanSummary:
    scanned_files: int = 0
    skipped_files: int = 0
    bytes_scanned: int = 0
    findings: list[Finding] = field(default_factory=list)
    skipped_reasons: dict[str, int] = field(default_factory=dict)

    def counts_by_severity(self) -> dict[str, int]:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for finding in self.findings:
            counts[finding.severity.label] += 1
        return counts

    def should_fail(self, threshold: Severity | None) -> bool:
        if threshold is None:
            return False
        return any(f.severity >= threshold for f in self.findings)
