"""Trusted Fortinet FortiOS static-analysis adapter for API-009.6."""

from typing import Any

from app.analyzer.fortios import analyze_fortios_configuration
from app.core.platforms import DeviceFamily, PlatformDescriptor
from app.parsers.firewalls.fortios import FortiOSParser


class FortiOSAdapter:
    descriptor = PlatformDescriptor(
        platform_id="fortios",
        display_name="Fortinet FortiOS (CLI export subset)",
        family=DeviceFamily.FIREWALL,
        extensions=(".conf", ".cfg", ".txt"),
    )

    def analyze(self, lines: list[str]) -> dict[str, Any]:
        parsed = FortiOSParser().parse(lines)
        findings = analyze_fortios_configuration(parsed)
        counts = {s: sum(f["severity"] == s for f in findings)
                  for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")}
        return {
            "vendor": "Fortinet",
            "hostname": None,  # No hostname extraction from this subset.
            "device_family": "firewall",
            "summary": {
                "total_findings": len(findings),
                "critical_findings": counts["CRITICAL"],
                "high_findings": counts["HIGH"],
                "medium_findings": counts["MEDIUM"],
                "low_findings": counts["LOW"],
                "info_findings": counts["INFO"],
                "security_score": None,
                "risk_level": None,
                "firewall_policies": len(parsed.policies),
                "address_objects": len(parsed.addresses),
                "custom_services": len(parsed.services),
                "interfaces": len(parsed.interfaces),
                "malformed_lines": len(parsed.malformed_lines),
            },
            "findings": findings,
            "warnings": list(parsed.warnings) + [
                "Static subset only; VDOMs, address/service groups, effective "
                "policy order, runtime traffic and device defaults were not assessed."
            ],
            "configuration": {
                "firewall_policies": [
                    {
                        "policy_id": p.identifier,
                        "line_number": p.line_number,
                        "action": next(iter(p.get("action")), None),
                        "status": next(iter(p.get("status")), None),
                        "srcaddr": list(p.get("srcaddr")),
                        "dstaddr": list(p.get("dstaddr")),
                        "service": list(p.get("service")),
                        "logtraffic": next(iter(p.get("logtraffic")), None),
                    }
                    for p in parsed.policies
                ],
                "address_object_names": [a.identifier for a in parsed.addresses],
                "custom_service_names": [s.identifier for s in parsed.services],
                "interface_names": [i.identifier for i in parsed.interfaces],
            },
        }
