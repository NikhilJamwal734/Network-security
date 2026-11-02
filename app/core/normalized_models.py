"""API-009.3: vendor-neutral, JSON-safe security analysis data models.

These models describe static configuration analysis for firewall, IDS, and IPS.
They do NOT parse configuration files or execute anything from an upload.
Only registered, trusted adapters may produce analysis results.
"""

from dataclasses import dataclass
from collections.abc import Mapping
from types import MappingProxyType
from enum import Enum
from typing import Any

from app.core.platforms import DeviceFamily


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    UNKNOWN = "unknown"


class CoverageStatus(str, Enum):
    ASSESSED = "assessed"
    NOT_ASSESSED = "not_assessed"


@dataclass(frozen=True)
class PlatformIdentity:
    platform_id: str
    display_name: str
    family: DeviceFamily
    hostname: str | None = None
    detection_method: str | None = None

    def __post_init__(self) -> None:
        if not self.platform_id.strip() or not self.display_name.strip():
            raise ValueError("platform identity must be nonempty")
        if not isinstance(self.family, DeviceFamily):
            raise TypeError("family must be a DeviceFamily")
        if self.detection_method not in (None, "automatic", "explicit"):
            raise ValueError("unsupported detection method")

    def to_dict(self) -> dict[str, Any]:
        return {
            "platform_id": self.platform_id,
            "display_name": self.display_name,
            "family": self.family.value,
            "hostname": self.hostname,
            "detection_method": self.detection_method,
        }


@dataclass(frozen=True)
class FindingEvidence:
    """Structured references only; never store raw configuration commands."""

    line_number: int | None = None
    rule_id: int | str | None = None
    related_rule_id: int | str | None = None

    def __post_init__(self) -> None:
        if self.line_number is not None and (
            isinstance(self.line_number, bool)
            or not isinstance(self.line_number, int)
            or self.line_number < 1
        ):
            raise ValueError("line_number must be a positive integer or None")

    def to_dict(self) -> dict[str, Any]:
        return {
            "line_number": self.line_number,
            "rule_id": self.rule_id,
            "related_rule_id": self.related_rule_id,
        }


@dataclass(frozen=True)
class NormalizedFinding:
    finding_id: str
    code: str
    severity: Severity
    title: str
    description: str
    recommendation: str
    evidence: FindingEvidence

    def __post_init__(self) -> None:
        if not self.finding_id.strip() or not self.code.strip():
            raise ValueError("finding identifiers must be nonempty")
        if not isinstance(self.severity, Severity):
            raise TypeError("severity must be a Severity")
        if not isinstance(self.evidence, FindingEvidence):
            raise TypeError("evidence must be FindingEvidence")

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "code": self.code,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "recommendation": self.recommendation,
            "evidence": self.evidence.to_dict(),
        }


@dataclass(frozen=True)
class CoverageDomain:
    domain: str
    status: CoverageStatus

    def __post_init__(self) -> None:
        if not self.domain.strip():
            raise ValueError("coverage domain must be nonempty")
        if not isinstance(self.status, CoverageStatus):
            raise TypeError("status must be CoverageStatus")

    def to_dict(self) -> dict[str, str]:
        return {"domain": self.domain, "status": self.status.value}


@dataclass(frozen=True)
class AnalysisCoverage:
    assessment_type: str
    domains: tuple[CoverageDomain, ...]
    limitations: tuple[str, ...]

    def __post_init__(self) -> None:
        if self.assessment_type != "static_configuration":
            raise ValueError("only static_configuration is supported")
        if len({item.domain for item in self.domains}) != len(self.domains):
            raise ValueError("duplicate coverage domain")
        if not all(isinstance(item, CoverageDomain) for item in self.domains):
            raise TypeError("domains must contain CoverageDomain objects")

    def to_dict(self) -> dict[str, Any]:
        return {
            "assessment_type": self.assessment_type,
            "domains": [item.to_dict() for item in self.domains],
            "limitations": list(self.limitations),
        }


@dataclass(frozen=True)
class NormalizedSummary:
    """Source score is optional; scores are not cross-platform comparable."""

    total_findings: int
    severity_counts: Mapping[str, int]
    security_score: int | None = None
    risk_level: str | None = None

    def __post_init__(self) -> None:
        expected = {severity.value for severity in Severity}
        if set(self.severity_counts) != expected:
            raise ValueError("severity_counts must include every severity")
        if any(
            isinstance(n, bool) or not isinstance(n, int) or n < 0
            for n in self.severity_counts.values()
        ):
            raise ValueError("severity counts must be nonnegative integers")
        if self.total_findings != sum(self.severity_counts.values()):
            raise ValueError("total_findings must match severity counts")
        # Defensive copy: keep frozen summaries immutable even if callers change the input dict.
        object.__setattr__(self, "severity_counts", MappingProxyType(dict(self.severity_counts)))
        if self.security_score is not None and (
            isinstance(self.security_score, bool)
            or not isinstance(self.security_score, int)
            or not 0 <= self.security_score <= 100
        ):
            raise ValueError("security_score must be between 0 and 100")

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_findings": self.total_findings,
            "severity_counts": dict(self.severity_counts),
            "security_score": self.security_score,
            "risk_level": self.risk_level,
        }


@dataclass(frozen=True)
class NormalizedReport:
    """A common output contract; vendor-specific raw reports remain separate."""

    schema_version: str
    platform: PlatformIdentity
    summary: NormalizedSummary
    findings: tuple[NormalizedFinding, ...]
    coverage: AnalysisCoverage
    warnings: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.schema_version != "1.0":
            raise ValueError("unsupported normalized schema version")
        if self.summary.total_findings != len(self.findings):
            raise ValueError("summary and findings length disagree")
        if len({finding.finding_id for finding in self.findings}) != len(self.findings):
            raise ValueError("duplicate finding IDs")

    def to_dict(self) -> dict[str, Any]:
        """Return only plain JSON values, not dataclass or Enum objects."""
        return {
            "schema_version": self.schema_version,
            "platform": self.platform.to_dict(),
            "summary": self.summary.to_dict(),
            "findings": [finding.to_dict() for finding in self.findings],
            "coverage": self.coverage.to_dict(),
            "warnings": list(self.warnings),
        }
