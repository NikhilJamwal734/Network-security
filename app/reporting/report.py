from dataclasses import asdict, dataclass, field
from typing import Dict, List

from app.analyzer.engine import Finding
from app.models.firewall import FirewallConfig


@dataclass
class ReportSummary:
    """High-level summary of the firewall security analysis."""

    total_rules: int = 0
    total_network_objects: int = 0
    total_service_objects: int = 0
    total_nat_rules: int = 0
    total_routes: int = 0

    total_findings: int = 0

    critical_findings: int = 0
    high_findings: int = 0
    medium_findings: int = 0
    low_findings: int = 0

    security_score: int = 100
    risk_level: str = "LOW"


@dataclass
class SecurityReport:
    """Structured firewall security report."""

    vendor: str
    hostname: str
    summary: ReportSummary
    findings: List[Dict] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        """Convert the report into a dictionary."""

        return {
            "vendor": self.vendor,
            "hostname": self.hostname,
            "summary": asdict(self.summary),
            "findings": self.findings,
            "warnings": self.warnings,
        }


class ReportGenerator:
    """Generate structured firewall security reports."""

    SEVERITY_ORDER = {
        "CRITICAL": 0,
        "HIGH": 1,
        "MEDIUM": 2,
        "LOW": 3,
    }

    def generate(
        self,
        firewall: FirewallConfig,
        findings: List[Finding],
    ) -> SecurityReport:
        """Generate a complete security report."""

        summary = self._build_summary(
            firewall,
            findings,
        )

        normalized_findings = self._normalize_findings(
            findings
        )

        normalized_findings.sort(
            key=self._finding_sort_key
        )

        return SecurityReport(
            vendor=firewall.vendor,
            hostname=firewall.hostname,
            summary=summary,
            findings=normalized_findings,
            warnings=list(firewall.warnings),
        )

    def _build_summary(
        self,
        firewall: FirewallConfig,
        findings: List[Finding],
    ) -> ReportSummary:
        """Build the report summary."""

        critical = 0
        high = 0
        medium = 0
        low = 0

        for finding in findings:

            severity = (
                finding.severity or ""
            ).strip().upper()

            if severity == "CRITICAL":
                critical += 1

            elif severity == "HIGH":
                high += 1

            elif severity == "MEDIUM":
                medium += 1

            elif severity == "LOW":
                low += 1

        security_score = self._calculate_security_score(
            critical,
            high,
            medium,
            low,
        )

        risk_level = self._calculate_risk_level(
            security_score,
            critical,
            high,
        )

        return ReportSummary(
            total_rules=len(firewall.rules),
            total_network_objects=len(firewall.networks),
            total_service_objects=len(firewall.services),
            total_nat_rules=len(firewall.nat_rules),
            total_routes=len(firewall.routes),
            total_findings=len(findings),
            critical_findings=critical,
            high_findings=high,
            medium_findings=medium,
            low_findings=low,
            security_score=security_score,
            risk_level=risk_level,
        )

    @staticmethod
    def _calculate_security_score(
        critical: int,
        high: int,
        medium: int,
        low: int,
    ) -> int:
        """
        Calculate a 0-100 security score.

        The scoring model uses category caps so that repeated
        findings do not overwhelm the entire score.

        Maximum penalty by severity:

            CRITICAL : 40 points
            HIGH     : 30 points
            MEDIUM   : 20 points
            LOW      : 10 points

        Individual findings have diminishing impact within
        each severity category.

        This is a heuristic security-health score. It is not
        a compliance score or a formal risk assessment.
        """

        critical_penalty = min(
            40.0,
            30.0 + max(0, critical - 1) * 5.0,
        )

        if critical == 0:
            critical_penalty = 0.0

        high_penalty = min(
            30.0,
            high * 10.0,
        )

        medium_penalty = min(
            20.0,
            medium * 3.0,
        )

        low_penalty = min(
            10.0,
            low * 0.5,
        )

        total_penalty = (
            critical_penalty
            + high_penalty
            + medium_penalty
            + low_penalty
        )

        score = round(
            100.0 - total_penalty
        )

        return max(
            0,
            min(
                100,
                score,
            ),
        )

    @staticmethod
    def _calculate_risk_level(
        security_score: int,
        critical: int,
        high: int,
    ) -> str:
        """
        Calculate the overall risk level.

        Critical findings always result in CRITICAL risk.
        Otherwise, the score and high-severity findings
        determine the overall risk classification.
        """

        if critical > 0:
            return "CRITICAL"

        if high >= 3:
            return "HIGH"

        if security_score < 50:
            return "HIGH"

        if security_score < 70:
            return "MEDIUM"

        if security_score < 85:
            return "LOW"

        return "LOW"

    @staticmethod
    def _normalize_findings(
        findings: List[Finding],
    ) -> List[Dict]:
        """Convert Finding objects into dictionaries."""

        result: List[Dict] = []

        for finding in findings:

            result.append(
                {
                    "severity": finding.severity,
                    "code": finding.code,
                    "rule_id": finding.rule_id,
                    "line_number": finding.line_number,
                    "title": finding.title,
                    "description": finding.description,
                    "recommendation": finding.recommendation,
                    "related_rule_id": finding.related_rule_id,
                }
            )

        return result

    def _finding_sort_key(
        self,
        finding: Dict,
    ):
        """Sort findings by severity, rule, line, and code."""

        severity = (
            finding.get("severity") or ""
        ).strip().upper()

        rule_id = finding.get("rule_id")
        line_number = finding.get("line_number")
        code = finding.get("code") or ""

        return (
            self.SEVERITY_ORDER.get(
                severity,
                99,
            ),
            rule_id
            if rule_id is not None
            else 999999,
            line_number
            if line_number is not None
            else 999999,
            code,
        )


def generate_report(
    firewall: FirewallConfig,
    findings: List[Finding],
) -> SecurityReport:
    """Convenience function for generating a report."""

    generator = ReportGenerator()

    return generator.generate(
        firewall,
        findings,
    )