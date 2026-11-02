"""API-009.3: convert verified Cisco ASA report dictionaries to a common schema.

The conversion is deliberately explicit: other vendors must implement their own
mapping and coverage declarations instead of being silently treated as Cisco ASA.
Existing API-008/009.2 reports are never modified in place.
"""

from collections.abc import Mapping
from typing import Any

from app.core.normalized_models import (
    AnalysisCoverage,
    CoverageDomain,
    CoverageStatus,
    FindingEvidence,
    NormalizedFinding,
    NormalizedReport,
    NormalizedSummary,
    PlatformIdentity,
    Severity,
)
from app.core.platforms import DeviceFamily, PlatformDescriptor


_ASA_DOMAINS = (
    "access_control",
    "network_objects",
    "service_objects",
    "nat_policies",
    "routing",
)

# A status of 'assessed' means the existing analyzer ran checks in that
# domain. It is NOT a statement about complete security coverage.
_ASA_COVERAGE = AnalysisCoverage(
    assessment_type="static_configuration",
    domains=tuple(
        CoverageDomain(domain, CoverageStatus.ASSESSED)
        for domain in _ASA_DOMAINS
    ) + (
        CoverageDomain("intrusion_detection_signatures", CoverageStatus.NOT_ASSESSED),
        CoverageDomain("runtime_traffic_detection", CoverageStatus.NOT_ASSESSED),
    ),
    limitations=(
        "Static analysis only; no traffic was replayed or monitored.",
        "Coverage is limited to checks implemented by the Cisco ASA analyzer.",
        "Scores are platform-specific and not directly comparable across vendors.",
    ),
)


def _text(value: Any) -> str:
    return value if isinstance(value, str) else "" if value is None else str(value)


def _reference(value: Any) -> int | str | None:
    """Retain simple identifiers, not arbitrary objects or executable content."""
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, (int, str)):
        return value
    return None


def _line_number(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int) and value >= 1:
        return value
    return None


def _severity(value: Any) -> Severity:
    if not isinstance(value, str):
        return Severity.UNKNOWN
    return next(
        (severity for severity in Severity if severity.value == value.strip().lower()),
        Severity.UNKNOWN,
    )


def normalize_cisco_asa_report(
    report: Mapping[str, Any],
    descriptor: PlatformDescriptor,
    *,
    detection_method: str | None = None,
) -> NormalizedReport:
    """Normalize the legacy Cisco ASA adapter result without mutating it.

    A future Snort or Suricata adapter must supply a separate normalizer and
    explicit domains/limits. Unknown platforms are never mapped with ASA rules.
    """
    if descriptor.platform_id != "cisco_asa" or descriptor.family is not DeviceFamily.FIREWALL:
        raise ValueError("Cisco ASA normalization requires a Cisco ASA descriptor")

    source_findings = report.get("findings")
    source_summary = report.get("summary")
    source_warnings = report.get("warnings", [])

    if not isinstance(source_findings, list) or not all(
        isinstance(item, Mapping) for item in source_findings
    ):
        raise ValueError("report findings must be a list of mappings")
    if not isinstance(source_summary, Mapping):
        raise ValueError("report summary must be a mapping")
    if not isinstance(source_warnings, list) or not all(
        isinstance(item, str) for item in source_warnings
    ):
        raise ValueError("report warnings must be a list of strings")

    findings: list[NormalizedFinding] = []
    counts = {item.value: 0 for item in Severity}

    for index, source in enumerate(source_findings, start=1):
        severity = _severity(source.get("severity"))
        counts[severity.value] += 1
        code = _text(source.get("code")).strip() or "UNCLASSIFIED"

        findings.append(
            NormalizedFinding(
                finding_id=f"cisco_asa:{index:06d}",
                code=code,
                severity=severity,
                title=_text(source.get("title")),
                description=_text(source.get("description")),
                recommendation=_text(source.get("recommendation")),
                evidence=FindingEvidence(
                    line_number=_line_number(source.get("line_number")),
                    rule_id=_reference(source.get("rule_id")),
                    related_rule_id=_reference(source.get("related_rule_id")),
                ),
            )
        )

    # Do not silently accept a summary with a different number of findings.
    expected_total = source_summary.get("total_findings")
    if expected_total != len(findings):
        raise ValueError("report summary total does not match findings")

    security_score = source_summary.get("security_score")
    if security_score is not None and (
        isinstance(security_score, bool) or not isinstance(security_score, int)
    ):
        raise ValueError("invalid Cisco ASA security score")

    return NormalizedReport(
        schema_version="1.0",
        platform=PlatformIdentity(
            platform_id=descriptor.platform_id,
            display_name=descriptor.display_name,
            family=descriptor.family,
            hostname=_text(report.get("hostname")) or None,
            detection_method=detection_method,
        ),
        summary=NormalizedSummary(
            total_findings=len(findings),
            severity_counts=counts,
            security_score=security_score,
            risk_level=_text(source_summary.get("risk_level")) or None,
        ),
        findings=tuple(findings),
        coverage=_ASA_COVERAGE,
        warnings=tuple(source_warnings),
    )
