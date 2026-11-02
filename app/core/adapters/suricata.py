"""Trusted API-009.5 adapter: Suricata rule + restricted YAML analysis."""

from typing import Any

from app.analyzer.suricata import analyze_suricata_configuration
from app.core.platforms import DeviceFamily, PlatformDescriptor
from app.parsers.ids.suricata import SuricataParser


class SuricataAdapter:
    descriptor = PlatformDescriptor(
        platform_id="suricata",
        display_name="Suricata IDS/IPS (rule + YAML subset)",
        family=DeviceFamily.IDS,
        extensions=(".conf", ".cfg", ".txt", ".rules", ".yaml", ".yml"),
    )

    def analyze(self, lines: list[str]) -> dict[str, Any]:
        parsed = SuricataParser().parse(lines)
        findings = analyze_suricata_configuration(parsed)
        counts = {
            severity: sum(f["severity"] == severity for f in findings)
            for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
        }
        enabled = sum(rule.enabled for rule in parsed.rules)
        return {
            "vendor": "Suricata",
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
                "total_rules": len(parsed.rules),
                "active_rules": enabled,
                "disabled_rules": len(parsed.rules) - enabled,
                "unparsed_rule_lines": len(parsed.malformed_rule_lines),
                "rule_file_entries": parsed.rule_file_count,
            },
            "findings": findings,
            "warnings": list(parsed.warnings),
            "configuration": {
                "ids_rules": [
                    {
                        "line_number": rule.line_number,
                        "action": rule.action,
                        "protocol": rule.protocol,
                        "sid": rule.sid,
                        "gid": rule.gid,
                        "revision": rule.revision,
                        "enabled": rule.enabled,
                    }
                    for rule in parsed.rules
                ],
                "home_net_visible": parsed.home_net is not None,
                "rule_file_entries": parsed.rule_file_count,
                "af_packet_interfaces": parsed.af_packet_interfaces,
                "eve_log_enabled": parsed.eve_log_enabled,
                "yaml_recognized": parsed.yaml_recognized,
            },
        }
