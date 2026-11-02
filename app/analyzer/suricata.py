"""Conservative API-009.5 Suricata IDS/IPS static text checks only."""

from typing import Any

from app.parsers.ids.suricata import SuricataConfiguration, SuricataRule


def _finding(
    code: str, severity: str, title: str, description: str, recommendation: str,
    *, line_number: int | None = None, sid: int | None = None,
    related_sid: int | None = None,
) -> dict[str, Any]:
    return {
        "code": code, "severity": severity, "title": title,
        "description": description, "recommendation": recommendation,
        "line_number": line_number, "rule_id": sid, "related_rule_id": related_sid,
    }


def analyze_suricata_configuration(config: SuricataConfiguration) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    seen: dict[tuple[int, int], SuricataRule] = {}
    active = [r for r in config.rules if r.enabled]
    for rule in config.rules:
        if not rule.enabled:
            findings.append(_finding(
                "SURICATA-004", "INFO", "Commented-out inline rule",
                "This rule is commented out in the supplied text; loaded rules from other sources were not inspected.",
                "Confirm the intended effective rule set.",
                line_number=rule.line_number, sid=rule.sid,
            ))
            continue
        if rule.sid is None or rule.gid is None:
            findings.append(_finding(
                "SURICATA-001", "HIGH", "Missing or invalid rule SID/GID",
                "An enabled inline rule lacks a valid positive SID or GID in this text subset.",
                "Assign valid identifiers and validate with the installed Suricata version.",
                line_number=rule.line_number, sid=rule.sid,
            ))
        else:
            identity = (rule.gid, rule.sid)
            if identity in seen:
                findings.append(_finding(
                    "SURICATA-002", "HIGH", "Duplicate enabled GID/SID pair",
                    f"Enabled inline rules reuse GID {rule.gid} and SID {rule.sid} in this upload.",
                    "Use unique (gid, sid) combinations across the effective loaded rules.",
                    line_number=rule.line_number, sid=rule.sid,
                    related_sid=seen[identity].sid,
                ))
            else:
                seen[identity] = rule
        if rule.action == "pass" and all(x.lower() == "any" for x in (
            rule.source, rule.source_port, rule.destination, rule.destination_port,
        )):
            findings.append(_finding(
                "SURICATA-005", "MEDIUM", "Broad pass-rule header",
                "The pass rule has an any-to-any header; options may further constrain it.",
                "Review ordering, flow and content conditions for unintended bypass.",
                line_number=rule.line_number, sid=rule.sid,
            ))
        if rule.action == "alert" and rule.protocol == "ip" and all(
            x.lower() == "any" for x in (
                rule.source, rule.source_port, rule.destination, rule.destination_port,
            )
        ) and not any(k in rule.option_names for k in ("content", "pcre", "flow", "dsize")):
            findings.append(_finding(
                "SURICATA-006", "LOW", "Broad alert-rule header",
                "The rule has an any-to-any IP header and no commonly used content restriction in this text.",
                "Check the full rule options and intended alert scope.",
                line_number=rule.line_number, sid=rule.sid,
            ))
    if config.home_net is not None and config.home_net.strip().lower() == "any":
        findings.append(_finding(
            "SURICATA-003", "HIGH", "HOME_NET set to any",
            "The visible HOME_NET configuration uses an unrestricted value.",
            "Check the intended protected address groups and effective variable resolution.",
        ))
    if config.home_net is None and any(
        "$HOME_NET" in (r.source, r.destination) for r in active
    ):
        findings.append(_finding(
            "SURICATA-007", "INFO", "HOME_NET definition not visible",
            "Rules reference HOME_NET but its effective definition was not included in this upload.",
            "Review the effective Suricata YAML and any external configuration.",
        ))
    for line in config.malformed_rule_lines:
        findings.append(_finding(
            "SURICATA-008", "MEDIUM", "Unparsed rule-like line",
            "This rule line could not be parsed by the supported Suricata subset.",
            "Validate the rule using suricata -T in your own trusted environment.",
            line_number=line,
        ))
    if not active and not config.rule_file_count:
        findings.append(_finding(
            "SURICATA-009", "MEDIUM", "No enabled rules visible",
            "No enabled inline rule or rule-files entry was visible; other rule sources were not assessed.",
            "Inspect the effective rule sources and deployment configuration.",
        ))
    if config.yaml_recognized and config.eve_log_enabled is False:
        findings.append(_finding(
            "SURICATA-010", "LOW", "Visible EVE logging entry disabled",
            "The visible eve-log enabled setting is false; other outputs may still log alerts.",
            "Review the intended alert-output configuration.",
        ))
    elif config.eve_log_enabled is None:
        findings.append(_finding(
            "SURICATA-011", "INFO", "EVE logging status not visible",
            "The uploaded text does not establish whether EVE logging is enabled.",
            "Inspect the effective outputs section and runtime alert pipeline.",
        ))
    return findings
