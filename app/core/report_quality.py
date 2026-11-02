"""API-010.0: cross-platform consistency and assessment-scope validation.

This is an *accuracy gate*, not a second security scanner. It compares reports
created by the existing verified adapters/normalizers without reading files,
following include paths, executing configuration commands, or claiming the
source text at a line reference has been independently verified.

Issues here are REPORT-QUALITY diagnostics, NOT additional security findings.
They must never affect the report's severity counts or provisional score.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping
from typing import Any

from app.core.advanced_assessment import WEIGHTS

SUPPORTED_PLATFORMS = frozenset({"cisco_asa", "fortios", "snort", "suricata"})
SEVERITIES = ("critical", "high", "medium", "low", "info", "unknown")
MAX_ISSUES = 60

PLATFORM_NOTES = {
    "cisco_asa": (
        "Cisco ASA rules, objects, NAT and routes are assessed only by implemented static checks; "
        "policy effectiveness and live traffic were not verified."
    ),
    "fortios": (
        "FortiOS VDOMs, address/service group expansion and effective policy ordering "
        "are not established by this configuration subset."
    ),
    "snort": (
        "Snort include directives are inert references; only explicitly uploaded text is inspected. "
        "No loaded-rule effectiveness or live detection was verified."
    ),
    "suricata": (
        "Suricata rule-files entries are inert references. Referenced rule contents, "
        "complete YAML semantics and runtime detection were not verified."
    ),
}


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _sequence(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _nonnegative(value: Any) -> int | None:
    return value if type(value) is int and value >= 0 else None


def _line(value: Any) -> int | None:
    return value if type(value) is int and value > 0 else None


def _raw_severity(value: Any) -> str:
    if not isinstance(value, str):
        return "unknown"
    severity = value.strip().lower()
    return severity if severity in SEVERITIES else "unknown"


def _source_line(item: Mapping[str, Any]) -> int | None:
    return _line(item.get("line_number"))


def _declared_field(source: Mapping[str, Any], path: Any) -> tuple[bool, Any]:
    """Resolve only trusted adapter `summary.*` / `configuration.*` fields.

    Do not use eval(), getattr(), open(), or bracket expressions. This accepts
    simple dotted *report keys*, never paths to local files or imported code.
    """
    if not isinstance(path, str):
        return False, None
    parts = path.split(".")
    if len(parts) != 2 or parts[0] not in ("summary", "configuration"):
        return False, None
    parent = _mapping(source.get(parts[0]))
    if parts[1] not in parent:
        return False, None
    return True, parent[parts[1]]


def validate_report_quality(
    normalized: Mapping[str, Any],
    source: Mapping[str, Any],
    assessment: Mapping[str, Any],
) -> dict[str, Any]:
    """Validate a four-platform normalized report against its adapter output.

    This API intentionally never re-parses untrusted text. A matching parser
    source line number is a **reported** reference, not proof that line content
    was verified. Structural discrepancies are reported separately from risk.
    """
    if not isinstance(normalized, Mapping) or not isinstance(source, Mapping) or not isinstance(assessment, Mapping):
        raise TypeError("Validated report, source, and assessment must be mappings")
    identity = _mapping(normalized.get("platform"))
    platform_id = identity.get("platform_id")
    if not isinstance(platform_id, str) or platform_id not in SUPPORTED_PLATFORMS:
        raise ValueError("Quality validation requires a supported platform")

    issues: list[dict[str, Any]] = []
    errors = reviews = 0
    suppressed = 0

    def add(level: str, code: str, explanation: str, *, finding_id: str | None = None) -> None:
        nonlocal errors, reviews, suppressed
        if level == "error":
            errors += 1
        elif level == "review":
            reviews += 1
        else:
            raise ValueError("Unsupported validation level")
        if len(issues) >= MAX_ISSUES:
            suppressed += 1
            return
        issue: dict[str, Any] = {"level": level, "code": code, "explanation": explanation}
        if finding_id is not None:
            issue["finding_id"] = finding_id
        issues.append(issue)

    summary = _mapping(normalized.get("summary"))
    raw_summary = _mapping(source.get("summary"))
    findings = _sequence(normalized.get("findings"))
    raw_findings = _sequence(source.get("findings"))

    if _nonnegative(summary.get("total_findings")) != len(findings):
        add("error", "Q-COUNT-001", "Normalized finding total differs from the normalized finding list.")
    if _nonnegative(raw_summary.get("total_findings")) != len(raw_findings):
        add("error", "Q-COUNT-002", "Adapter finding total differs from its finding list.")
    if len(raw_findings) != len(findings):
        add("error", "Q-COUNT-003", "Adapter and normalized finding lists have different lengths.")

    reported_counts = _mapping(summary.get("severity_counts"))
    expected_counts = Counter(_mapping(item).get("severity") for item in findings)
    severity_totals_valid = True
    for severity in SEVERITIES:
        actual = _nonnegative(reported_counts.get(severity))
        if actual is None or actual != expected_counts.get(severity, 0):
            severity_totals_valid = False
    if set(reported_counts) != set(SEVERITIES) or not severity_totals_valid:
        add("error", "Q-SEVERITY-001", "Severity totals must exactly match findings in all six severity categories.")

    seen_ids: set[str] = set()
    matched_source = 0
    line_references = 0
    invalid_evidence = 0
    for index, entry in enumerate(findings):
        item = _mapping(entry)
        finding_id = item.get("finding_id")
        short_id = finding_id if isinstance(finding_id, str) and len(finding_id) <= 96 else None
        if not short_id or short_id in seen_ids:
            add("error", "Q-FINDING-001", "Finding IDs must be nonempty and unique.")
        else:
            seen_ids.add(short_id)
        if item.get("severity") not in SEVERITIES:
            add("error", "Q-FINDING-002", "Finding severity is not a recognized category.", finding_id=short_id)
        evidence = _mapping(item.get("evidence"))
        line_ref = evidence.get("line_number")
        if line_ref is not None and _line(line_ref) is None:
            invalid_evidence += 1
            add("error", "Q-EVIDENCE-001", "Finding line references must be positive integers or null.", finding_id=short_id)
        if _line(line_ref) is not None:
            line_references += 1
        if index >= len(raw_findings):
            continue
        original = _mapping(raw_findings[index])
        # Exact item order is preserved by all four API-009.3 normalizers.
        raw_code = original.get("code")
        if platform_id == "cisco_asa":
            raw_code = str(raw_code).strip() if raw_code is not None else ""
            raw_code = raw_code or "UNCLASSIFIED"
        else:
            raw_code = str(raw_code) if raw_code is not None else f"{platform_id.upper()}-UNKNOWN"
        aligned = (
            item.get("code") == raw_code
            and item.get("severity") == _raw_severity(original.get("severity"))
            and line_ref == _source_line(original)
        )
        if aligned:
            matched_source += 1
        else:
            add("error", "Q-SOURCE-001", "Normalized finding code, severity, or line reference differs from the source finding.", finding_id=short_id)

    if isinstance(identity.get("detection_method"), str) and identity.get("detection_method") not in ("automatic", "explicit"):
        add("error", "Q-IDENTITY-001", "Unexpected platform detection method.")
    if _nonnegative(raw_summary.get("security_score")) is not None and summary.get("security_score") != raw_summary.get("security_score"):
        add("error", "Q-SCORE-001", "Normalized source security score differs from adapter report.")

    coverage = _mapping(normalized.get("coverage"))
    domains = _sequence(coverage.get("domains"))
    seen_domains: set[str] = set()
    unassessed: list[str] = []
    for item in domains:
        domain = _mapping(item)
        key = domain.get("domain")
        status = domain.get("status")
        if not isinstance(key, str) or not key or key in seen_domains:
            add("error", "Q-COVERAGE-001", "Coverage domains must have unique nonempty names.")
        else:
            seen_domains.add(key)
        if status == "not_assessed":
            if isinstance(key, str):
                unassessed.append(key)
        elif status != "assessed":
            add("error", "Q-COVERAGE-002", "Coverage status must be assessed or not_assessed.")
    if not domains:
        add("review", "Q-COVERAGE-003", "The report declares no assessment coverage domains.")

    current_score = _mapping(_mapping(assessment.get("review_score")))
    deductions = _mapping(current_score.get("deductions"))
    if current_score.get("status") != "provisional" or current_score.get("comparable_across_platforms") is not False:
        add("error", "Q-SCORE-002", "The review score must be provisional and non-comparable across platforms.")
    if severity_totals_valid:
        expected_deductions = {s: int(reported_counts[s]) * WEIGHTS[s] for s in SEVERITIES}
        expected_max = 80 if unassessed else 100
        expected_value = min(expected_max, max(0, 100 - sum(expected_deductions.values())))
        if (
            deductions != expected_deductions
            or current_score.get("maximum") != expected_max
            or current_score.get("value") != expected_value
            or current_score.get("capped_for_incomplete_coverage") is not bool(unassessed)
        ):
            add("error", "Q-SCORE-003", "Provisional score or deductions disagree with finding severity and coverage.")
    if assessment.get("platform_id") != platform_id:
        add("error", "Q-SCORE-004", "Assessment platform does not match the normalized report platform.")

    observations_checked = 0
    for item in _sequence(assessment.get("observations")):
        observation = _mapping(item)
        evidence = _mapping(observation.get("evidence"))
        has_source, actual = _declared_field(source, evidence.get("source_field"))
        expected = evidence.get("value")
        if not has_source or expected is None:
            continue
        if isinstance(actual, list) and type(expected) is int:
            observed_value: Any = len(actual)
        elif isinstance(actual, list) and type(expected) is bool and evidence.get("source_field") == "configuration.network_variables":
            observed_value = "HOME_NET" in actual
        else:
            observed_value = actual
        observations_checked += 1
        if type(observed_value) is not type(expected) or observed_value != expected:
            add("error", "Q-INVENTORY-001", "A displayed inventory observation is inconsistent with the adapter's structured fields.")

    config = _mapping(source.get("configuration"))
    if platform_id in ("snort", "suricata"):
        parsed_rules = config.get("ids_rules")
        total = _nonnegative(raw_summary.get("total_rules"))
        if isinstance(parsed_rules, list) and total is not None and len(parsed_rules) != total:
            add("error", "Q-IDS-001", "Inline rule total differs from the parsed rules inventory.")
        if isinstance(parsed_rules, list):
            enabled = sum(item.get("enabled") is True for item in parsed_rules if isinstance(item, Mapping))
            declared_enabled = _nonnegative(raw_summary.get("active_rules"))
            declared_disabled = _nonnegative(raw_summary.get("disabled_rules"))
            if declared_enabled is not None and declared_disabled is not None and (
                enabled != declared_enabled or len(parsed_rules) - enabled != declared_disabled
            ):
                add("error", "Q-IDS-002", "Enabled/disabled rule totals differ from the parsed rules inventory.")
    if platform_id == "snort":
        count = _nonnegative(config.get("include_directives"))
        if count is not None and count > 0 and "included_rule_files" not in unassessed:
            add("review", "Q-SNORT-001", "Snort include-file references were visible but are not explicitly marked unassessed.")
    elif platform_id == "suricata":
        count = _nonnegative(config.get("rule_file_entries"))
        if count is not None and count > 0 and "referenced_rule_files" not in unassessed:
            add("review", "Q-SURICATA-001", "Referenced Suricata rule files were visible but not marked unassessed.")
        source_count = _nonnegative(raw_summary.get("rule_file_entries"))
        if count is not None and source_count is not None and count != source_count:
            add("error", "Q-SURICATA-002", "Rule-file reference counts differ across adapter fields.")
    elif platform_id == "fortios":
        for summary_key, config_key in (
            ("firewall_policies", "firewall_policies"),
            ("address_objects", "address_object_names"),
            ("custom_services", "custom_service_names"),
            ("interfaces", "interface_names"),
        ):
            source_count = _nonnegative(raw_summary.get(summary_key))
            inventory = config.get(config_key)
            if source_count is not None and isinstance(inventory, list) and source_count != len(inventory):
                add("error", "Q-FORTIOS-001", "FortiOS inventory and summary counts differ.")
    elif platform_id == "cisco_asa":
        # The legacy ASA serializer is not guaranteed to be an exhaustive
        # representation of all analyzer objects; do not equate empty arrays
        # with nonexistence or emit unfounded security findings.
        pass

    status = "review_needed" if errors else "limited_coverage" if unassessed else "internally_consistent"
    return {
        "version": "1.0",
        "platform_id": platform_id,
        "status": status,
        "scope": "post_analysis_report_consistency",
        "structural_checks_passed": errors == 0,
        "finding_evidence": {
            "findings_crosschecked_with_adapter": matched_source,
            "findings_total": len(findings),
            "findings_with_reported_line_references": line_references,
            "source_text_at_line_verified": False,
            "line_reference_note": (
                "Line references are reported by the parser; original source-line text was not independently rechecked."
            ),
        },
        "coverage": {
            "declared_domains": len(domains),
            "unassessed_domains": unassessed,
            "incomplete": bool(unassessed),
        },
        "summary": {
            "errors": errors,
            "review_items": reviews,
            "observation_values_checked": observations_checked,
            "issues_suppressed": suppressed,
        },
        "issues": issues,
        "platform_note": PLATFORM_NOTES[platform_id],
        "interpretation": (
            "Report-quality validation only. No additional security findings were created; "
            "this result does not verify the original source lines, include files, "
            "effective policy, packet inspection, or runtime security."
        ),
    }
