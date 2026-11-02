"""API-010.0: add report-quality diagnostics to the unified React dashboard.

Patches only known anchors; refuses unrecognized layouts. Creates backups.
Run from backend project root. Idempotent. Existing PDF routing is untouched.
"""
from __future__ import annotations

from pathlib import Path
import shutil
import sys

PROJECT = Path(__file__).resolve().parents[2]
FRONTEND = PROJECT / "frontend"
PATCH_ROOT = Path(__file__).resolve().parents[1]

QUALITY_INTERFACE = '''
/** Report-quality checks, not additional security findings. */
export interface ReportQuality {
  version: "1.0";
  platform_id: string;
  status: "review_needed" | "limited_coverage" | "internally_consistent";
  scope: "post_analysis_report_consistency";
  structural_checks_passed: boolean;
  finding_evidence: {
    findings_crosschecked_with_adapter: number;
    findings_total: number;
    findings_with_reported_line_references: number;
    source_text_at_line_verified: boolean;
    line_reference_note: string;
  };
  coverage: { declared_domains: number; unassessed_domains: string[]; incomplete: boolean };
  summary: { errors: number; review_items: number; observation_values_checked: number; issues_suppressed: number };
  issues: Array<{ level: "error" | "review"; code: string; explanation: string; finding_id?: string }>;
  platform_note: string;
  interpretation: string;
}
'''


def patch_api(contents: str) -> str:
    if 'export interface NormalizedReport {' not in contents:
        raise RuntimeError("Cannot locate NormalizedReport interface")
    if 'quality?: ReportQuality;' not in contents:
        contents = contents.replace('export interface NormalizedReport {',
            'export interface NormalizedReport {\n  quality?: ReportQuality;', 1)
    if 'export interface ReportQuality {' not in contents:
        contents += '\n' + QUALITY_INTERFACE
    if '/api/v1/analyze/validated' in contents:
        return contents
    # API-009.8 is expected to be the current frontend request. Allow the
    # original normalized route for installations that skipped the upgrade.
    if '/api/v1/analyze/assessment' in contents:
        return contents.replace('/api/v1/analyze/assessment', '/api/v1/analyze/validated', 1)
    if '/api/v1/analyze/normalized' in contents:
        return contents.replace('/api/v1/analyze/normalized', '/api/v1/analyze/validated', 1)
    raise RuntimeError("Cannot locate current analyzer endpoint; API file not modified")


def patch_dashboard(contents: str) -> str:
    import_line = 'import ReportQualityPanel from "../components/ReportQualityPanel";'
    call = '<ReportQualityPanel quality={report.quality} />'
    if (import_line in contents) != (call in contents):
        raise RuntimeError("Partial ReportQualityPanel integration found")
    if call in contents:
        return contents
    anchor = 'import "./UniversalAnalysis.css";'
    place = '<div className="ua-results" aria-live="polite">'
    if contents.count(anchor) != 1 or contents.count(place) != 1:
        raise RuntimeError("Unexpected dashboard structure; no files modified")
    contents = contents.replace(anchor, import_line + '\n' + anchor, 1)
    return contents.replace(place, place + '\n          ' + call, 1)


def prepare() -> dict[Path, bytes]:
    api = FRONTEND / 'src/api/universal.ts'
    page = FRONTEND / 'src/pages/UniversalAnalysis.tsx'
    if not (FRONTEND / 'package.json').is_file() or not api.is_file() or not page.is_file():
        raise RuntimeError('Expected frontend/package.json, src/api/universal.ts and src/pages/UniversalAnalysis.tsx')
    result = {
        api: patch_api(api.read_text(encoding='utf-8-sig')).encode('utf-8'),
        page: patch_dashboard(page.read_text(encoding='utf-8-sig')).encode('utf-8'),
    }
    for name in ('ReportQualityPanel.tsx', 'ReportQualityPanel.css'):
        result[FRONTEND / 'src/components' / name] = (PATCH_ROOT / 'src/components' / name).read_bytes()
    return result


def install() -> list[str]:
    updates = prepare()  # Dry-run validation BEFORE modifying files.
    messages = []
    for destination, content in updates.items():
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.is_file() and destination.read_bytes() == content:
            messages.append(f'Unchanged: {destination}')
            continue
        if destination.exists():
            backup = destination.with_name(destination.name + '.before_api0100.bak')
            if not backup.exists():
                shutil.copy2(destination, backup)
        destination.write_bytes(content)
        messages.append(f'Updated: {destination}')
    return messages


if __name__ == '__main__':
    try:
        print('\n'.join(install()))
    except (RuntimeError, OSError) as exc:
        print(f'ERROR: {exc}', file=sys.stderr)
        sys.exit(1)
