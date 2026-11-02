"""FortiOS-to-API-009.3 normalized report conversion; score intentionally null."""

from collections.abc import Mapping
from typing import Any

from app.core.normalized_models import (
    AnalysisCoverage, CoverageDomain, CoverageStatus, FindingEvidence,
    NormalizedFinding, NormalizedReport, NormalizedSummary, PlatformIdentity, Severity,
)
from app.core.platforms import DeviceFamily, PlatformDescriptor

_COVERAGE = AnalysisCoverage(
    assessment_type="static_configuration",
    domains=(
        CoverageDomain("visible_firewall_policy_selectors", CoverageStatus.ASSESSED),
        CoverageDomain("visible_address_object_subnets", CoverageStatus.ASSESSED),
        CoverageDomain("visible_interface_management_access", CoverageStatus.ASSESSED),
        CoverageDomain("full_fortios_cli_grammar", CoverageStatus.NOT_ASSESSED),
        CoverageDomain("vdoms_and_group_expansion", CoverageStatus.NOT_ASSESSED),
        CoverageDomain("effective_policy_order_and_default_values", CoverageStatus.NOT_ASSESSED),
        CoverageDomain("runtime_traffic_and_security_profiles", CoverageStatus.NOT_ASSESSED),
    ),
    limitations=(
        "FortiOS configuration is parsed as an allowlisted CLI text subset only.",
        "Policies, referenced objects, VDOMs and defaults are not fully resolved.",
        "This is not a comprehensive firewall audit or runtime traffic analysis.",
        "No cross-vendor-comparable numeric security score is assigned.",
    ),
)


def normalize_fortios_report(
    report: Mapping[str, Any], descriptor: PlatformDescriptor,
    *, detection_method: str | None = None,
) -> NormalizedReport:
    if descriptor.platform_id != "fortios" or descriptor.family is not DeviceFamily.FIREWALL:
        raise ValueError("FortiOS normalization requires a FortiOS firewall descriptor")
    raw = report.get("findings")
    summary = report.get("summary")
    warnings = report.get("warnings", [])
    if not isinstance(raw, list) or not all(isinstance(v, Mapping) for v in raw):
        raise ValueError("FortiOS findings must be a list of mappings")
    if not isinstance(summary, Mapping) or summary.get("total_findings") != len(raw):
        raise ValueError("FortiOS summary does not match findings")
    if not isinstance(warnings, list) or not all(isinstance(x, str) for x in warnings):
        raise ValueError("FortiOS warnings must be strings")
    result: list[NormalizedFinding] = []
    counts = {s.value: 0 for s in Severity}
    for index, source in enumerate(raw, 1):
        severity_raw = str(source.get("severity", "")).lower()
        severity = Severity(severity_raw) if severity_raw in counts else Severity.UNKNOWN
        counts[severity.value] += 1
        line = source.get("line_number")
        if isinstance(line, bool) or not isinstance(line, int) or line < 1:
            line = None
        policy_id = source.get("rule_id")
        if not isinstance(policy_id, (int, str)) or isinstance(policy_id, bool):
            policy_id = None
        result.append(NormalizedFinding(
            finding_id=f"fortios:{index:06d}",
            code=str(source.get("code", "FORTIOS-UNKNOWN")),
            severity=severity,
            title=str(source.get("title", "")),
            description=str(source.get("description", "")),
            recommendation=str(source.get("recommendation", "")),
            evidence=FindingEvidence(line_number=line, rule_id=policy_id),
        ))
    return NormalizedReport(
        schema_version="1.0",
        platform=PlatformIdentity(
            platform_id="fortios",
            display_name=descriptor.display_name,
            family=descriptor.family,
            hostname=None,
            detection_method=detection_method,
        ),
        summary=NormalizedSummary(
            total_findings=len(result), severity_counts=counts,
            security_score=None, risk_level=None,
        ),
        findings=tuple(result), coverage=_COVERAGE, warnings=tuple(warnings),
    )
