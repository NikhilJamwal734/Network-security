"""Normalize a verified Snort static-analysis report to the API-009.3 schema."""

from collections.abc import Mapping
from typing import Any

from app.core.normalized_models import (
    AnalysisCoverage, CoverageDomain, CoverageStatus, FindingEvidence,
    NormalizedFinding, NormalizedReport, NormalizedSummary, PlatformIdentity, Severity,
)
from app.core.platforms import DeviceFamily, PlatformDescriptor


_SNORT_COVERAGE = AnalysisCoverage(
    assessment_type="static_configuration",
    domains=(
        CoverageDomain("snort2_rule_header_subset", CoverageStatus.ASSESSED),
        CoverageDomain("inline_sid_uniqueness", CoverageStatus.ASSESSED),
        CoverageDomain("visible_network_variables", CoverageStatus.ASSESSED),
        CoverageDomain("included_rule_files", CoverageStatus.NOT_ASSESSED),
        CoverageDomain("effective_loaded_rules", CoverageStatus.NOT_ASSESSED),
        CoverageDomain("runtime_traffic_detection", CoverageStatus.NOT_ASSESSED),
        CoverageDomain("snort3_lua_configuration", CoverageStatus.NOT_ASSESSED),
    ),
    limitations=(
        "Only a restricted Snort 2 text rule/config subset is parsed.",
        "Include paths are not opened; referenced files were not assessed.",
        "No packet traffic was analyzed, and installed rule effectiveness was not validated.",
        "No numeric IDS security score is calculated or compared to firewall scores.",
    ),
)


def normalize_snort_report(
    report: Mapping[str, Any],
    descriptor: PlatformDescriptor,
    *, detection_method: str | None = None,
) -> NormalizedReport:
    if descriptor.platform_id != "snort" or descriptor.family is not DeviceFamily.IDS:
        raise ValueError("Snort normalizer requires Snort IDS descriptor")
    raw_findings = report.get("findings")
    summary = report.get("summary")
    warnings = report.get("warnings", [])
    if not isinstance(raw_findings, list) or not all(isinstance(x, Mapping) for x in raw_findings):
        raise ValueError("Snort findings must be a list of mappings")
    if not isinstance(summary, Mapping) or summary.get("total_findings") != len(raw_findings):
        raise ValueError("Snort summary does not match findings")
    if not isinstance(warnings, list) or not all(isinstance(x, str) for x in warnings):
        raise ValueError("Snort warnings must be strings")

    result: list[NormalizedFinding] = []
    counts = {s.value: 0 for s in Severity}
    for index, source in enumerate(raw_findings, start=1):
        severity_raw = str(source.get("severity", "")).lower()
        severity = Severity(severity_raw) if severity_raw in counts else Severity.UNKNOWN
        counts[severity.value] += 1
        line = source.get("line_number")
        if isinstance(line, bool) or not isinstance(line, int) or line < 1:
            line = None
        sid = source.get("rule_id")
        related = source.get("related_rule_id")
        if not isinstance(sid, (str, int)) or isinstance(sid, bool):
            sid = None
        if not isinstance(related, (str, int)) or isinstance(related, bool):
            related = None
        result.append(NormalizedFinding(
            finding_id=f"snort:{index:06d}",
            code=str(source.get("code", "SNORT-UNKNOWN")),
            severity=severity,
            title=str(source.get("title", "")),
            description=str(source.get("description", "")),
            recommendation=str(source.get("recommendation", "")),
            evidence=FindingEvidence(
                line_number=line, rule_id=sid, related_rule_id=related,
            ),
        ))

    return NormalizedReport(
        schema_version="1.0",
        platform=PlatformIdentity(
            platform_id="snort",
            display_name=descriptor.display_name,
            family=DeviceFamily.IDS,
            hostname=None,
            detection_method=detection_method,
        ),
        summary=NormalizedSummary(
            total_findings=len(result),
            severity_counts=counts,
            security_score=None,
            risk_level=None,
        ),
        findings=tuple(result),
        coverage=_SNORT_COVERAGE,
        warnings=tuple(warnings),
    )
