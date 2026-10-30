"""Shared, serializable scan models. Findings never retain source excerpts."""

from dataclasses import asdict, dataclass, field
from enum import Enum


class Severity(str, Enum):
    CRYPT = "CRYPT"
    HAUNT = "HAUNT"
    SPOOK = "SPOOK"
    WHISPER = "WHISPER"

    @property
    def standard(self) -> str:
        return {
            "CRYPT": "CRITICAL",
            "HAUNT": "HIGH",
            "SPOOK": "MEDIUM",
            "WHISPER": "LOW",
        }[self.value]

    @property
    def penalty(self) -> int:
        return {"CRYPT": 25, "HAUNT": 12, "SPOOK": 5, "WHISPER": 1}[self.value]


@dataclass(frozen=True)
class Source:
    path: str
    text: str

    @property
    def lines(self) -> list[str]:
        return self.text.splitlines()


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: Severity
    title: str
    file: str
    line: int
    advice: str
    cwe: str
    evidence: str = ""

    def to_dict(self) -> dict:
        result = asdict(self)
        result["severity"] = self.severity.value
        result["standard_severity"] = self.severity.standard
        return result


@dataclass
class Report:
    target: str
    generated_at: str
    files_scanned: int = 0
    files_skipped: int = 0
    findings: list[Finding] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    osv_enabled: bool = False

    @property
    def counts(self) -> dict[str, int]:
        return {
            severity.value: sum(f.severity == severity for f in self.findings)
            for severity in Severity
        }

    @property
    def soul_integrity(self) -> int:
        return max(0, 100 - sum(f.severity.penalty for f in self.findings))

    @property
    def has_blockers(self) -> bool:
        return any(f.severity in (Severity.CRYPT, Severity.HAUNT) for f in self.findings)

    def to_dict(self) -> dict:
        return {
            "schema_version": 1,
            "tool": "SATAN Reborn",
            "target": self.target,
            "generated_at": self.generated_at,
            "files_scanned": self.files_scanned,
            "files_skipped": self.files_skipped,
            "osv_enabled": self.osv_enabled,
            "soul_integrity": self.soul_integrity,
            "counts": self.counts,
            "has_blockers": self.has_blockers,
            "warnings": self.warnings,
            "findings": [finding.to_dict() for finding in self.findings],
        }
