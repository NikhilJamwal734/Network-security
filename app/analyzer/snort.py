"""Static, appropriately scoped Snort 2 IDS policy checks.

Findings describe properties of visible text only. The analyzer never claims
loaded rule-set completeness, running IDS status, or traffic-detection efficacy.
"""

from typing import Any

from app.parsers.ids.snort import SnortConfiguration, SnortRule


def _finding(
    code: str, severity: str, title: str, description: str,
    recommendation: str, *, line_number: int | None = None,
    sid: int | None = None, related_sid: int | None = None,
) -> dict[str, Any]:
    return {
        "code": code, "severity": severity, "title": title,
        "description": description, "recommendation": recommendation,
        "line_number": line_number, "rule_id": sid,
        "related_rule_id": related_sid,
    }


def analyze_snort_configuration(config: SnortConfiguration) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    seen_sids: dict[int, SnortRule] = {}
    active = [r for r in config.rules if r.enabled]
    for rule in config.rules:
        if not rule.enabled:
            findings.append(_finding(
                "SNORT-004", "INFO", "Commented-out Snort rule",
                "This rule appears commented out in the uploaded text; it is not an active inline rule.",
                "Confirm whether the rule is intentionally disabled and whether another source loads it.",
                line_number=rule.line_number, sid=rule.sid,
            ))
            continue
        if rule.sid is None:
            findings.append(_finding(
                "SNORT-001", "HIGH", "Missing or invalid SID",
                "An enabled inline rule does not have a valid positive numeric sid option.",
                "Assign a valid unique SID and verify it loads in the intended Snort version.",
                line_number=rule.line_number,
            ))
        elif rule.sid in seen_sids:
            findings.append(_finding(
                "SNORT-002", "HIGH", "Duplicate enabled rule SID",
                f"Enabled inline rule SID {rule.sid} occurs more than once in this upload.",
                "Assign unique SIDs across all enabled rule sources.",
                line_number=rule.line_number, sid=rule.sid,
                related_sid=seen_sids[rule.sid].sid,
            ))
        else:
            seen_sids[rule.sid] = rule

        if rule.action == "pass" and all(
            value.lower() == "any" for value in (
                rule.source, rule.source_port, rule.destination, rule.destination_port,
            )
        ):
            findings.append(_finding(
                "SNORT-005", "MEDIUM", "Broad pass-rule header",
                "This pass rule uses any-to-any addresses and ports; additional options may constrain it.",
                "Review flow, content, and rule ordering to avoid unintended detection bypass.",
                line_number=rule.line_number, sid=rule.sid,
            ))
        if rule.action in ("alert", "log") and rule.protocol == "ip" and all(
            value.lower() == "any" for value in (
                rule.source, rule.source_port, rule.destination, rule.destination_port,
            )
        ) and not any(key in rule.option_names for key in ("content", "pcre", "flow", "dsize")):
            findings.append(_finding(
                "SNORT-006", "LOW", "Broad inline rule header",
                "The rule uses an any-to-any IP header without common content restrictions in this text.",
                "Review its matching options to confirm the intended detection scope.",
                line_number=rule.line_number, sid=rule.sid,
            ))

    home = config.variables.get("HOME_NET")
    if home is not None and home.lower() == "any":
        findings.append(_finding(
            "SNORT-003", "HIGH", "HOME_NET set to any",
            "The visible HOME_NET variable does not restrict the protected network scope.",
            "Set HOME_NET to the intended protected address ranges, if appropriate.",
        ))
    if home is None and any(
        "$HOME_NET" in (r.source, r.destination) for r in active
    ):
        findings.append(_finding(
            "SNORT-007", "INFO", "HOME_NET definition not visible",
            "Rules reference HOME_NET, but its definition is not in this upload. It may be defined elsewhere.",
            "Review the effective configuration and included variable definitions.",
        ))
    for line_number in config.malformed_rule_lines:
        findings.append(_finding(
            "SNORT-008", "MEDIUM", "Unparsed Snort rule line",
            "A rule-like line was not parsed by the supported Snort 2 subset.",
            "Validate syntax with Snort and review this rule manually.",
            line_number=line_number,
        ))
    if not active and not config.includes_count:
        findings.append(_finding(
            "SNORT-009", "MEDIUM", "No enabled inline rules found",
            "No enabled detection rules were found in the supplied text; other sources were not evaluated.",
            "Verify the effective rule-set and included configuration files.",
        ))
    if config.output_directives_count == 0:
        findings.append(_finding(
            "SNORT-010", "INFO", "Alert output configuration not visible",
            "No output directive was found in the uploaded text; this does not prove logging is disabled.",
            "Check the effective logging and alert-output configuration.",
        ))
    return findings
