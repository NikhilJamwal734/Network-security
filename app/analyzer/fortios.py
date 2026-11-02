"""API-009.6 FortiOS static checks for the explicitly supported config subset.

Findings describe only visible settings. They are NOT an effective-policy audit:
address/service groups, implicit defaults, NAT, VDOMs and policy order are not
resolved. Do not derive a numeric security score from these checks.
"""

from typing import Any

from app.parsers.firewalls.fortios import FortiOSConfiguration, FortiOSEntry


def _finding(
    code: str, severity: str, title: str, description: str, recommendation: str,
    *, line: int | None = None, policy_id: str | None = None,
) -> dict[str, Any]:
    return {
        "code": code,
        "severity": severity,
        "title": title,
        "description": description,
        "recommendation": recommendation,
        "line_number": line,
        "rule_id": policy_id,
        "related_rule_id": None,
    }


def _has(entry: FortiOSEntry, field: str, name: str) -> bool:
    return any(x.casefold() == name.casefold() for x in entry.get(field))


def analyze_fortios_configuration(config: FortiOSConfiguration) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for policy in config.policies:
        if _has(policy, "status", "disable"):
            findings.append(_finding(
                "FORTIOS-004", "INFO", "Policy explicitly disabled",
                "This policy has 'set status disable' in the supplied configuration.",
                "Confirm whether the disabled policy is intentional.",
                line=policy.line_number, policy_id=policy.identifier,
            ))
            continue
        if not _has(policy, "action", "accept"):
            # No assumption about defaults or effective behavior.
            continue
        source_any = _has(policy, "srcaddr", "all")
        destination_any = _has(policy, "dstaddr", "all")
        service_any = _has(policy, "service", "ALL")
        if source_any and destination_any and service_any:
            findings.append(_finding(
                "FORTIOS-001", "HIGH", "Broad accept-policy selectors",
                "An enabled accept policy explicitly selects all source addresses, "
                "all destination addresses and ALL services; schedules, interfaces "
                "and policy order may further restrict its effect.",
                "Review this policy's intent and narrow address/service selectors where appropriate.",
                line=policy.line_number, policy_id=policy.identifier,
            ))
        elif service_any:
            findings.append(_finding(
                "FORTIOS-002", "MEDIUM", "Accept policy uses ALL services",
                "The visible accept policy allows the ALL service object; effective reachability is not assessed.",
                "Restrict service selection to necessary application ports and protocols.",
                line=policy.line_number, policy_id=policy.identifier,
            ))
        if _has(policy, "logtraffic", "disable"):
            findings.append(_finding(
                "FORTIOS-003", "MEDIUM", "Policy traffic logging explicitly disabled",
                "This accept policy explicitly sets logtraffic to disable; other logging mechanisms may apply.",
                "Review logging requirements and enable the intended traffic/event logging.",
                line=policy.line_number, policy_id=policy.identifier,
            ))
        if _has(policy, "srcintf", "any") and _has(policy, "dstintf", "any"):
            findings.append(_finding(
                "FORTIOS-005", "MEDIUM", "Policy references any-to-any interfaces",
                "The visible source and destination interface selectors are both 'any'.",
                "Review interface scoping together with addresses, services, and policy order.",
                line=policy.line_number, policy_id=policy.identifier,
            ))
        if _has(policy, "utm-status", "disable"):
            findings.append(_finding(
                "FORTIOS-006", "INFO", "UTM inspection explicitly disabled on policy",
                "The visible accept policy has utm-status disable; inspection may be provided elsewhere.",
                "Confirm whether security profiles or another inspection layer are required.",
                line=policy.line_number, policy_id=policy.identifier,
            ))

    for interface in config.interfaces:
        protocols = {x.lower() for x in interface.get("allowaccess")}
        insecure = sorted(protocols.intersection({"http", "telnet"}))
        if insecure and not _has(interface, "status", "down"):
            findings.append(_finding(
                "FORTIOS-007", "HIGH", "Plaintext management protocol permitted",
                "Interface management access explicitly includes " + ", ".join(insecure) + ". "
                "Actual network exposure has not been verified.",
                "Review management-plane exposure; prefer encrypted management protocols.",
                line=interface.line_number,
            ))

    for address in config.addresses:
        if address.get("subnet") == ("0.0.0.0", "0.0.0.0"):
            findings.append(_finding(
                "FORTIOS-008", "LOW", "Address object covers the entire IPv4 space",
                "The visible address object subnet is 0.0.0.0/0; policy use and effective access were not assessed.",
                "Confirm that this broad address object is deliberate where referenced.",
                line=address.line_number,
            ))

    if not config.policies:
        findings.append(_finding(
            "FORTIOS-009", "INFO", "No firewall policies in supplied subset",
            "No config firewall policy entries were visible in the uploaded text. "
            "This does not establish that the device has no policies.",
            "For a fuller review, export the relevant firewall policy section.",
        ))
    if config.malformed_lines:
        # Summarize rather than one finding per malformed line.
        findings.append(_finding(
            "FORTIOS-010", "INFO", "Unbalanced or malformed configuration blocks",
            "Some configuration lines or block delimiters could not be parsed in this subset.",
            "Review the source export and compare with the FortiOS CLI configuration structure.",
            line=config.malformed_lines[0],
        ))
    return findings
