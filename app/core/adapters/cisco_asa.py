"""Compatibility adapter for the existing, tested Cisco ASA pipeline.

No parsing, scoring, or serializer code is duplicated here.
"""

from typing import Any

from app.analyzer.engine import FirewallAnalyzer
from app.api.serializers import serialize_firewall
from app.parsers.cisco_asa import CiscoASAParser
from app.reporting.report import generate_report

from app.core.platforms import DeviceFamily, PlatformDescriptor


class CiscoASAAdapter:
    descriptor = PlatformDescriptor(
        platform_id="cisco_asa",
        display_name="Cisco ASA",
        family=DeviceFamily.FIREWALL,
        extensions=(".conf", ".cfg", ".txt"),
    )

    def analyze(self, lines: list[str]) -> dict[str, Any]:
        """Return the same report shape as POST /api/v1/analyze."""
        # Instantiate parser/analyzer per call to avoid shared request state.
        firewall = CiscoASAParser().parse(lines)
        findings = FirewallAnalyzer(firewall).analyze()
        report = generate_report(firewall=firewall, findings=findings)
        result: dict[str, Any] = report.to_dict()
        result["configuration"] = serialize_firewall(firewall)
        return result
