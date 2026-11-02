"""API-009.4 trusted adapter for Snort 2-style IDS static configuration.

Does not execute rules, resolve include paths, or infer a numeric security score.
"""

from typing import Any

from app.analyzer.snort import analyze_snort_configuration
from app.core.platforms import DeviceFamily, PlatformDescriptor
from app.parsers.ids.snort import SnortParser


class SnortAdapter:
    descriptor = PlatformDescriptor(
        platform_id="snort",
        display_name="Snort IDS (2.x rule/config subset)",
        family=DeviceFamily.IDS,
        extensions=(".conf", ".cfg", ".txt", ".rules"),
    )

    def analyze(self, lines: list[str]) -> dict[str, Any]:
        config = SnortParser().parse(lines)
        findings = analyze_snort_configuration(config)
        counts = {
            severity: sum(f["severity"] == severity for f in findings)
            for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
        }
        enabled_rules = sum(rule.enabled for rule in config.rules)
        return {
            "vendor": "Snort",
            "hostname": None,
            "device_family": "ids",
            "summary": {
                "total_findings": len(findings),
                "critical_findings": counts["CRITICAL"],
                "high_findings": counts["HIGH"],
                "medium_findings": counts["MEDIUM"],
                "low_findings": counts["LOW"],
                "info_findings": counts["INFO"],
                "security_score": None,
                "risk_level": None,
                "total_rules": len(config.rules),
                "active_rules": enabled_rules,
                "disabled_rules": len(config.rules) - enabled_rules,
                "unparsed_rule_lines": len(config.malformed_rule_lines),
                "include_directives": config.includes_count,
            },
            "findings": findings,
            "warnings": list(config.warnings),
            "configuration": {
                "ids_rules": [
                    {
                        "line_number": rule.line_number,
                        "action": rule.action,
                        "protocol": rule.protocol,
                        "sid": rule.sid,
                        "revision": rule.revision,
                        "enabled": rule.enabled,
                    }
                    for rule in config.rules
                ],
                "network_variables": sorted(config.variables),
                "include_directives": config.includes_count,
                "output_directives": config.output_directives_count,
            },
        }
