"""API-009.7: remove duplicated ASA metrics and redundant severity panel.

Run from React frontend root (folder containing package.json and src/App.tsx).
Updates only the unified-dashboard page, ASA overview, and scoped layout CSS.
Backs up changed files once; repeats are safe.
"""
from __future__ import annotations

import shutil
import sys
from pathlib import Path

VERSION = "api0097_dashboard_cleanup_v1"
SEVERITY_START = '          <section className="ua-panel">\n            <h2>Severity distribution</h2>'
SEVERITY_END = '          </section>\n\n          {report.platform.platform_id === "cisco_asa"'
SEVERITY_GUARD = '          {!(report.platform.platform_id === "cisco_asa" && legacyASAReady) && (\n'

OLD_CARDS_START = '      <div className="summary-cards">'
OLD_CARDS_END = '      <p className="ua-hint">Detailed Cisco ASA'
NEW_OVERVIEW = '''      {/* One responsive inventory summary (no duplicate icon cards). */}
      <section className="ua-asa-inventory ua-asa-subpanel" aria-label="Configuration summary">
        <ConfigurationSummary summary={summary} />
      </section>
      <section className="ua-asa-info ua-asa-subpanel" aria-label="Firewall information">
        <FirewallInfo report={analysis} />
      </section>
'''

CSS_MARKER = '/* API-009.7 dashboard cleanup: full-width inventory, responsive cards */'
CSS = '''
/* API-009.7 dashboard cleanup: full-width inventory, responsive cards */
.ua-page .ua-asa-overview .ua-asa-inventory {
  width: 100%;
  min-width: 0;
  margin: 20px 0;
  padding: clamp(16px, 2vw, 24px);
}
.ua-page .ua-asa-overview .ua-asa-info {
  width: 100%;
  min-width: 0;
  margin: 0 0 20px;
  padding: clamp(16px, 2vw, 24px);
}
/* The old 5-across columns caused labels to wrap into vertical letters.
   auto-fit always gives the cards enough room to display whole words. */
.ua-page .ua-asa-overview .ucs-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(min(100%, 168px), 1fr));
  gap: 14px;
}
.ua-page .ua-asa-overview .ucs-card {
  min-width: 0;
  min-height: 114px;
  padding: 18px;
  overflow-wrap: normal;
  word-break: normal;
}
.ua-page .ua-asa-overview .ucs-label {
  white-space: normal;
  overflow-wrap: normal;
  word-break: normal;
  hyphens: none;
  line-height: 1.4;
}
@media (max-width: 520px) {
  .ua-page .ua-asa-overview .ucs-grid {
    grid-template-columns: repeat(auto-fit, minmax(min(100%, 140px), 1fr));
    gap: 12px;
  }
  .ua-page .ua-asa-overview .ucs-card { padding: 14px; }
}
'''


def change_severity(source: str) -> str:
    if SEVERITY_GUARD in source:
        return source
    if source.count(SEVERITY_START) != 1 or source.count(SEVERITY_END) != 1:
        raise ValueError("Cannot find unique normalized severity section in UniversalAnalysis.tsx; no files changed")
    # Indent the existing section inside the new JSX conditional for readability.
    start = source.index(SEVERITY_START)
    end = source.index(SEVERITY_END, start) + len('          </section>')
    section = source[start:end]
    indented = '\n'.join('  ' + line if line.strip() else line for line in section.split('\n'))
    return source[:start] + SEVERITY_GUARD + indented + '\n          )}' + source[end:]


def change_overview(source: str) -> str:
    if 'className="ua-asa-inventory ua-asa-subpanel"' in source and OLD_CARDS_START not in source:
        return source
    if source.count(OLD_CARDS_START) != 1 or source.count(OLD_CARDS_END) != 1:
        raise ValueError("Cannot find unique duplicate summary-card block in CiscoASAOverview.tsx; no files changed")
    start = source.index(OLD_CARDS_START)
    end = source.index(OLD_CARDS_END, start)
    updated = source[:start] + NEW_OVERVIEW + source[end:]
    updated = updated.replace('import SummaryCard from "../components/SummaryCard";\n', '', 1)
    if '<SeverityChart' not in updated or '<ConfigurationSummary summary={summary}' not in updated:
        raise ValueError("Expected ASA severity chart and configuration summary not found; no files changed")
    return updated


def main() -> int:
    root = Path.cwd()
    u = root / 'src/pages/UniversalAnalysis.tsx'
    o = root / 'src/pages/CiscoASAOverview.tsx'
    c = root / 'src/pages/UnifiedDashboardExtras.css'
    required = [root / 'package.json', root / 'src/App.tsx', u, o, c]
    missing = [p.relative_to(root) for p in required if not p.is_file()]
    if missing:
        print('ERROR: Run from current React frontend folder. Missing:', ', '.join(map(str, missing)), file=sys.stderr)
        return 2
    try:
        originals = {p: p.read_text(encoding='utf-8-sig') for p in (u, o, c)}
        changes = {
            u: change_severity(originals[u]),
            o: change_overview(originals[o]),
            c: originals[c] if CSS_MARKER in originals[c] else originals[c].rstrip() + '\n\n' + CSS,
        }
    except (OSError, ValueError) as error:
        print(f'ERROR: {error}', file=sys.stderr)
        return 2

    # Validate all transformations before making any write.
    for path, updated in changes.items():
        if updated == originals[path]:
            print('Already updated:', path.relative_to(root))
            continue
        backup = path.with_name(path.name + '.' + VERSION + '.backup')
        if not backup.exists():
            shutil.copy2(path, backup)
            print('Backup:', backup.relative_to(root))
        path.write_text(updated, encoding='utf-8')
        print('Updated:', path.relative_to(root))
    print('Done. Run npm run build in this frontend folder.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
