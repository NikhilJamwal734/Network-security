import json
import sys
from pathlib import Path

from app.analyzer.engine import FirewallAnalyzer
from app.parsers.firewalls.cisco_asa import CiscoASAParser
from app.reporting.report import ReportGenerator


def main():
    if len(sys.argv) != 2:
        print("Usage: python -m app.main <config-file>")
        print("Example: python -m app.main configs\\firewall.conf")
        sys.exit(1)

    config_path = Path(sys.argv[1])

    if not config_path.exists():
        print(f"ERROR: File not found: {config_path}")
        sys.exit(1)

    if not config_path.is_file():
        print(f"ERROR: Path is not a file: {config_path}")
        sys.exit(1)

    try:
        config_text = config_path.read_text(
            encoding="utf-8",
            errors="ignore",
        )
    except OSError as exc:
        print(f"ERROR: Could not read file: {exc}")
        sys.exit(1)

    parser = CiscoASAParser()

    try:
        firewall = parser.parse(config_text.splitlines())
    except Exception as exc:
        print("PARSER ERROR:")
        print(exc)
        sys.exit(1)

    print()
    print("=" * 70)
    print("FIREWALL CONFIGURATION ANALYZER")
    print("=" * 70)
    print(f"Vendor       : {firewall.vendor}")
    print(f"Hostname     : {firewall.hostname or 'Unknown'}")
    print(f"Networks     : {len(firewall.networks)}")
    print(f"Services     : {len(firewall.services)}")
    print(f"Rules        : {len(firewall.rules)}")
    print(f"NAT rules    : {len(firewall.nat_rules)}")
    print(f"Routes       : {len(firewall.routes)}")
    print("=" * 70)

    try:
        analyzer = FirewallAnalyzer(firewall)
        findings = analyzer.analyze()
    except Exception as exc:
        print()
        print("ANALYSIS ERROR:")
        print(exc)
        sys.exit(1)

    print()
    print("=" * 70)
    print("SECURITY FINDINGS")
    print("=" * 70)

    if not findings:
        print("No findings.")
    else:
        for finding in findings:
            print()
            print(f"[{finding.severity}] {finding.code}")
            print(f"Rule         : {finding.rule_id}")
            print(f"Line         : {finding.line_number}")
            print(f"Title        : {finding.title}")
            print(f"Description  : {finding.description}")

            if finding.related_rule_id is not None:
                print(f"Related rule : {finding.related_rule_id}")

            print("Recommendation:")
            print(f"  {finding.recommendation}")

    print()
    print("=" * 70)
    print("GENERATING REPORT")
    print("=" * 70)

    try:
        report_generator = ReportGenerator()

        report = report_generator.generate(
            firewall,
            findings,
        )
    except Exception as exc:
        print("REPORTING ERROR:")
        print(exc)
        sys.exit(1)

    reports_directory = Path.cwd() / "reports"

    reports_directory.mkdir(
        parents=True,
        exist_ok=True,
    )

    report_path = reports_directory / "firewall_report.json"

    report_data = report.to_dict()

    report_data["source"] = {
        "configuration_file": str(config_path),
    }

    try:
        with report_path.open(
            "w",
            encoding="utf-8",
        ) as report_file:
            json.dump(
                report_data,
                report_file,
                indent=4,
            )
    except OSError as exc:
        print("REPORT FILE ERROR:")
        print(exc)
        sys.exit(1)

    summary = report.summary

    print()
    print("=" * 70)
    print("SECURITY REPORT SUMMARY")
    print("=" * 70)
    print(f"Security Score     : {summary.security_score}/100")
    print(f"Critical Findings  : {summary.critical_findings}")
    print(f"High Findings      : {summary.high_findings}")
    print(f"Medium Findings    : {summary.medium_findings}")
    print(f"Low Findings       : {summary.low_findings}")
    print(f"Total Findings     : {summary.total_findings}")
    print("=" * 70)

    print()
    print("=" * 70)
    print("ANALYSIS COMPLETE")
    print("=" * 70)
    print(f"Rules analyzed     : {len(firewall.rules)}")
    print(f"Findings generated : {len(findings)}")
    print(f"Security score     : {summary.security_score}/100")
    print(f"JSON report        : {report_path}")
    print("=" * 70)


if __name__ == "__main__":
    main()