"""Read-only check of one local Suricata YAML file after applying the fix.

Usage from project root:
  .\\.venv-win\\Scripts\\python.exe scripts\\check_suricata_false_positives.py "C:\\path\\suricata.yaml"

This never executes a configuration or opens referenced rule files.
"""

import argparse
from pathlib import Path
import sys

# Support direct execution via python scripts\check_suricata_false_positives.py
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.core.adapters.suricata import SuricataAdapter


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('file', type=Path, help='The YAML file to inspect (read-only).')
    args = parser.parse_args()
    try:
        with args.file.open('r', encoding='utf-8-sig') as handle:
            lines = handle.read().splitlines()
        report = SuricataAdapter().analyze(lines)
    except (OSError, UnicodeError) as exc:
        print(f'Unable to read file: {exc}')
        return 2
    summary = report['summary']
    print(f'Analyzed: {args.file.name}')
    print(f"Total findings: {summary['total_findings']}")
    print(f"Unparsed active rule lines: {summary['unparsed_rule_lines']}")
    print(f"Rule-file references (not opened): {summary['rule_file_entries']}")
    for f in report['findings']:
        print(f"{f['code']} {f['severity']}: {f['title']}")
    for warning in report.get('warnings', []):
        print('Note:', warning)
    bad = [f for f in report['findings'] if f['code'] == 'SURICATA-008']
    if bad:
        print('Unparsed rule-like lines remain; review active rule syntax.')
    else:
        print('No SURICATA-008 findings.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
