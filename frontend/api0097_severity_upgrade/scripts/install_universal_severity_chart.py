"""Install one normalized severity chart across ASA, FortiOS, Snort, Suricata.

Run from the React frontend directory containing src/App.tsx and package.json.
All replacements are validated before writing; files receive one-time backups.
"""
from __future__ import annotations

import re
import shutil
import sys
from pathlib import Path

VERSION = "api0097_universal_severity_v1"

CHART_SECTION = '''          <section className="ua-panel ua-chart-panel" aria-labelledby="ua-severity-chart-heading">
            <div className="ua-section-heading">
              <div>
                <p className="ua-eyebrow">SECURITY FINDINGS</p>
                <h2 id="ua-severity-chart-heading">Severity chart</h2>
                <p>Findings by severity for the selected firewall or IDS/IPS platform.</p>
              </div>
            </div>
            <UniversalSeverityChart counts={report.summary.severity_counts} />
          </section>
'''

# Works for both API-009.7 original and the later "dashboard cleanup" wrapper.
NORMALIZED_SEVERITY = re.compile(
    r'(?m)^          (?:\{!\(report\.platform\.platform_id === "cisco_asa" && legacyASAReady\) && \(\n)?'
    r'\s*<section className="ua-panel">\n'
    r'\s*<h2>Severity distribution</h2>\n'
    r'[\s\S]*?'
    r'^\s*</section>\n'
    r'(?:          \)\}\n)?'
)

LEGACY_ASA_CHART = re.compile(
    r'(?m)^        <div className="ua-asa-subpanel">\n'
    r'          <h3>Severity chart</h3>\n'
    r'          <SeverityChart\n'
    r'[\s\S]*?'
    r'^          />\n'
    r'        </div>\n'
)


def adjust_universal(source: str) -> str:
    if '<UniversalSeverityChart counts={report.summary.severity_counts}' in source:
        if '<h2>Severity distribution</h2>' in source:
            raise ValueError('Both chart and old severity distribution exist; review manually.')
        return source
    if source.count('<h2>Severity distribution</h2>') != 1:
        raise ValueError('Expected exactly one Severity distribution section in UniversalAnalysis.tsx.')
    updated, changed = NORMALIZED_SEVERITY.subn(CHART_SECTION, source)
    if changed != 1 or '<h2>Severity distribution</h2>' in updated:
        raise ValueError('Could not replace the old severity section safely.')
    anchor = 'import CiscoASAOverview from "./CiscoASAOverview";'
    if source.count(anchor) != 1:
        raise ValueError('Could not locate CiscoASAOverview import in UniversalAnalysis.tsx.')
    return updated.replace(anchor, 'import UniversalSeverityChart from "../components/UniversalSeverityChart";\n' + anchor, 1)


def adjust_asa_overview(source: str) -> str:
    if '<SeverityChart' not in source:
        if 'import SeverityChart from ' in source:
            raise ValueError('Orphaned SeverityChart import; review ASA overview.')
        return source
    updated, changed = LEGACY_ASA_CHART.subn('', source)
    if changed != 1 or '<SeverityChart' in updated:
        raise ValueError('Expected exactly one ASA-only severity chart block.')
    imports = re.findall(r'^import SeverityChart from [^\n]+\n', updated, re.M)
    if len(imports) != 1:
        raise ValueError('Expected exactly one ASA SeverityChart import.')
    updated = updated.replace(imports[0], '', 1)
    old_grid = 'className="ua-asa-visual-grid"'
    new_grid = 'className="ua-asa-visual-grid ua-asa-score-only"'
    if updated.count(old_grid) != 1:
        raise ValueError('Could not locate ASA score/chart grid.')
    return updated.replace(old_grid, new_grid, 1)


def main() -> int:
    frontend = Path.cwd()
    patch = Path(__file__).resolve().parent.parent
    universal = frontend / 'src/pages/UniversalAnalysis.tsx'
    overview = frontend / 'src/pages/CiscoASAOverview.tsx'
    css = frontend / 'src/components/UniversalSeverityChart.css'
    tsx = frontend / 'src/components/UniversalSeverityChart.tsx'
    extra_css = frontend / 'src/pages/UnifiedDashboardExtras.css'
    required = [frontend / 'package.json', frontend / 'src/App.tsx', universal, overview, extra_css,
                patch / 'components/UniversalSeverityChart.css', patch / 'components/UniversalSeverityChart.tsx']
    missing = [str(p) for p in required if not p.is_file()]
    if missing:
        print('ERROR: Missing required files. Run this from your frontend folder:\n  ' + '\n  '.join(missing), file=sys.stderr)
        return 2
    try:
        originals = {path: path.read_text(encoding='utf-8-sig') for path in (universal, overview, extra_css)}
        source_files = {
            tsx: (patch / 'components/UniversalSeverityChart.tsx').read_text(encoding='utf-8'),
            css: (patch / 'components/UniversalSeverityChart.css').read_text(encoding='utf-8'),
        }
        if 'UniversalSeverityChart.css' not in source_files[tsx]:
            raise ValueError('Invalid chart package.')
        changes = {
            universal: adjust_universal(originals[universal]),
            overview: adjust_asa_overview(originals[overview]),
            extra_css: originals[extra_css],
            **source_files,
        }
        css_rule = '\n/* Shared normalized chart is used in the dashboard; ASA keeps only its legacy score widget. */\n.ua-page .ua-asa-visual-grid.ua-asa-score-only { grid-template-columns: minmax(0, 1fr); }\n'
        if '.ua-asa-visual-grid.ua-asa-score-only' not in originals[extra_css]:
            changes[extra_css] = originals[extra_css].rstrip() + '\n' + css_rule
        for existing, incoming in source_files.items():
            if existing.exists() and existing.read_text(encoding='utf-8-sig') != incoming:
                raise ValueError(f'{existing.relative_to(frontend)} already exists with different content; refusing to overwrite.')
    except (OSError, ValueError) as exc:
        print(f'ERROR: {exc}\nNo files were changed.', file=sys.stderr)
        return 2

    for target, content in changes.items():
        if target.exists() and content == target.read_text(encoding='utf-8-sig'):
            print(f'Unchanged: {target.relative_to(frontend)}')
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.is_file():
            backup = target.with_name(target.name + '.' + VERSION + '.backup')
            if not backup.exists():
                shutil.copy2(target, backup)
                print(f'Backup: {backup.relative_to(frontend)}')
        target.write_text(content, encoding='utf-8')
        print(f'Updated: {target.relative_to(frontend)}')
    print('Done. Run npm run build from this frontend folder.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
