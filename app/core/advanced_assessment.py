"""API-009.8: conservative, vendor-aware assessment enrichment for four platforms.

Consumes ONLY structured, trusted-adapter output. Uploaded configuration text is
never executed, resolved as a path, or echoed into assessment observations.
No score here is a validated security grade or evidence of effective protection.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

PLATFORMS = frozenset({"cisco_asa", "fortios", "snort", "suricata"})
WEIGHTS = {"critical": 15, "high": 7, "medium": 3, "low": 1, "info": 0, "unknown": 0}


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _count(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None
    return value


def _observation(
    code: str, title: str, status: str, detail: str, source_field: str,
    value: int | bool | None = None,
) -> dict[str, Any]:
    if status not in ("observed", "not_visible", "not_assessed"):
        raise ValueError("Unsupported observation status")
    return {
        "code": code,
        "title": title,
        "status": status,
        "detail": detail,
        "evidence": {"source_field": source_field, "value": value, "line_number": None},
    }


def _count_observation(code: str, title: str, source: str, value: int | None) -> dict[str, Any]:
    if value is None:
        return _observation(code, title, "not_assessed", "No reliable count in the parsed report.", source)
    return _observation(
        code, title, "observed" if value else "not_visible",
        f"{value} item(s) visible in this upload; completeness and runtime state were not verified.",
        source, value,
    )


def _bool_observation(
    code: str, title: str, source: str, value: bool | None, *, negative_detail: str,
) -> dict[str, Any]:
    if value is None:
        return _observation(
            code, title, "not_assessed", "The effective setting was not established from this upload.", source
        )
    return _observation(
        code, title, "observed" if value else "not_visible",
        "Explicitly present in the parsed upload; runtime behavior was not verified." if value
        else negative_detail,
        source, value,
    )


def _inventory(platform_id: str, source: Mapping[str, Any]) -> list[dict[str, Any]]:
    summary = _mapping(source.get("summary"))
    configuration = _mapping(source.get("configuration"))

    if platform_id == "cisco_asa":
        # ASA is backed by the legacy, verified ASA parser and analyzer.
        return [
            _count_observation("ASA-REVIEW-RULES", "Firewall access rules", "summary.total_rules", _count(summary.get("total_rules"))),
            _count_observation("ASA-REVIEW-NETWORK", "Network object definitions", "summary.total_network_objects", _count(summary.get("total_network_objects"))),
            _count_observation("ASA-REVIEW-SERVICES", "Service object definitions", "summary.total_service_objects", _count(summary.get("total_service_objects"))),
            _count_observation("ASA-REVIEW-NAT", "NAT rules", "summary.total_nat_rules", _count(summary.get("total_nat_rules"))),
            _count_observation("ASA-REVIEW-ROUTES", "Route statements", "summary.total_routes", _count(summary.get("total_routes"))),
        ]
    if platform_id == "fortios":
        policies = configuration.get("firewall_policies")
        addresses = configuration.get("address_object_names")
        services = configuration.get("custom_service_names")
        interfaces = configuration.get("interface_names")
        return [
            _count_observation("FORTIOS-REVIEW-POLICIES", "Visible firewall policies", "configuration.firewall_policies", len(policies) if isinstance(policies, list) else None),
            _count_observation("FORTIOS-REVIEW-ADDRESSES", "Address objects", "configuration.address_object_names", len(addresses) if isinstance(addresses, list) else None),
            _count_observation("FORTIOS-REVIEW-SERVICES", "Custom service objects", "configuration.custom_service_names", len(services) if isinstance(services, list) else None),
            _count_observation("FORTIOS-REVIEW-INTERFACES", "Interface definitions", "configuration.interface_names", len(interfaces) if isinstance(interfaces, list) else None),
        ]
    if platform_id == "snort":
        variables = configuration.get("network_variables")
        includes = _count(configuration.get("include_directives"))
        outputs = _count(configuration.get("output_directives"))
        return [
            _count_observation("SNORT-REVIEW-RULES", "Inline IDS rules", "summary.total_rules", _count(summary.get("total_rules"))),
            _bool_observation("SNORT-REVIEW-HOME", "HOME_NET variable visible", "configuration.network_variables", ("HOME_NET" in variables) if isinstance(variables, list) else None, negative_detail="HOME_NET was not visible in the parsed variables; it may be defined in another file."),
            _count_observation("SNORT-REVIEW-INCLUDES", "Include directives", "configuration.include_directives", includes),
            _count_observation("SNORT-REVIEW-OUTPUT", "Output directives", "configuration.output_directives", outputs),
        ]
    if platform_id == "suricata":
        return [
            _count_observation("SURICATA-REVIEW-RULES", "Inline IDS/IPS rules", "summary.total_rules", _count(summary.get("total_rules"))),
            _bool_observation("SURICATA-REVIEW-HOME", "HOME_NET declaration visible", "configuration.home_net_visible", configuration.get("home_net_visible") if isinstance(configuration.get("home_net_visible"), bool) else None, negative_detail="HOME_NET was not visible in the supported YAML subset; other sources were not evaluated."),
            _count_observation("SURICATA-REVIEW-RULEFILES", "Referenced rule-file entries", "configuration.rule_file_entries", _count(configuration.get("rule_file_entries"))),
            _count_observation("SURICATA-REVIEW-CAPTURE", "AF-PACKET interface entries", "configuration.af_packet_interfaces", _count(configuration.get("af_packet_interfaces"))),
            _bool_observation("SURICATA-REVIEW-EVE", "EVE logging explicitly enabled", "configuration.eve_log_enabled", configuration.get("eve_log_enabled") if isinstance(configuration.get("eve_log_enabled"), bool) else None, negative_detail="EVE logging was explicitly disabled in the parsed subset; other logging outputs may still be enabled."),
        ]
    raise ValueError("Unregistered platform assessment requested")


def _review_score(normalized: Mapping[str, Any]) -> dict[str, Any]:
    summary = _mapping(normalized.get("summary"))
    counts = _mapping(summary.get("severity_counts"))
    breakdown: dict[str, int] = {}
    for severity, weight in WEIGHTS.items():
        n = _count(counts.get(severity))
        if n is None:
            raise ValueError("Missing or invalid severity count in verified normalized report")
        breakdown[severity] = n * weight

    domains = _list(_mapping(normalized.get("coverage")).get("domains"))
    missing = [d for d in domains if isinstance(d, Mapping) and d.get("status") == "not_assessed"]
    capped = bool(missing)
    maximum = 80 if capped else 100
    value = min(maximum, max(0, 100 - sum(breakdown.values())))
    if _count(counts.get("critical")):
        priority = "urgent_review"
    elif _count(counts.get("high")):
        priority = "high_priority_review"
    elif _count(counts.get("medium")):
        priority = "moderate_review"
    elif _count(counts.get("low")):
        priority = "lower_priority_review"
    else:
        priority = "no_risk_findings_in_assessed_scope"
    return {
        "value": value,
        "maximum": maximum,
        "method": "finding_weighted_provisional_v1",
        "label": "Provisional configuration-review score",
        "status": "provisional",
        "priority": priority,
        "deductions": breakdown,
        "capped_for_incomplete_coverage": capped,
        "comparable_across_platforms": False,
        "interpretation": (
            "A limited triage indicator derived from reported findings; higher means fewer weighted "
            "findings within this analyzer's supported checks. It is NOT a validated security score, "
            "cannot verify effective protections, and must not be compared across vendors. "
            "Any unassessed coverage domain caps the indicator at 80/100. "
            "Zero findings never proves the configuration is secure."
        ),
    }


def build_advanced_assessment(
    normalized: Mapping[str, Any], source: Mapping[str, Any],
) -> dict[str, Any]:
    """Create consistent assessment sections for all four registered adapters.

    No raw config is logged or copied into evidence. References are allowlisted
    summary/configuration fields from the trusted adapter.
    """
    platform = _mapping(normalized.get("platform"))
    platform_id = platform.get("platform_id")
    if platform_id not in PLATFORMS:
        raise ValueError("Advanced assessment requires a supported platform")
    coverage = _mapping(normalized.get("coverage"))
    domains = _list(coverage.get("domains"))
    unassessed = [d.get("domain") for d in domains if isinstance(d, Mapping) and d.get("status") == "not_assessed" and isinstance(d.get("domain"), str)]
    assessed = [d.get("domain") for d in domains if isinstance(d, Mapping) and d.get("status") == "assessed" and isinstance(d.get("domain"), str)]
    observations = _inventory(str(platform_id), source)
    return {
        "version": "1.0",
        "scope": "uploaded_text_only",
        "platform_id": platform_id,
        "review_score": _review_score(normalized),
        "observations": observations,
        "coverage_review": {
            "assessed_domain_count": len(assessed),
            "unassessed_domain_count": len(unassessed),
            "unassessed_domains": unassessed,
            "status": "partial" if unassessed else "declared_checks_only",
        },
        "notice": (
            "Observations are inventory/visibility checks, not additional security findings. "
            "The analyzer never opens referenced configuration files or verifies runtime behavior."
        ),
    }
