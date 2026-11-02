"""API-009.7 Dashboard merge. Run from the React *frontend* directory.

Fail-closed transformation of the API-009.7 App.tsx layout and one staged page.
The script never touches the legacy AnalysisContext, backend, or other pages.
"""
from __future__ import annotations

from pathlib import Path
import shutil
import sys

APP = Path('src/App.tsx')
UNIVERSAL = Path('src/pages/UniversalAnalysis.tsx')
STAGED = Path('api0097_merge/src/pages')
APP_BACKUP = Path('src/App.tsx.before_unified_dashboard.backup')
UNIVERSAL_BACKUP = Path('src/pages/UniversalAnalysis.tsx.before_unified_dashboard.backup')


def replace_one(text: str, old: str, new: str) -> str:
    count = text.count(old)
    if count != 1:
        raise ValueError(f'Expected one matching App.tsx anchor; found {count}: {old[:100]!r}')
    return text.replace(old, new, 1)


def patch_app(text: str) -> str:
    """Merge the two navigation pages without touching legacy detailed pages."""
    if 'const [unifiedReport, setUnifiedReport]' in text:
        indicators = (
            '<UniversalAnalysis', 'report={unifiedReport}',
            'legacyASAReady', 'onReportChange={setUnifiedReport}',
            'item.label === "Dashboard" ||',
        )
        if all(t in text for t in indicators) and 'label: "Universal Analysis"' not in text:
            return text
        raise ValueError('Partial previous merge found. No files changed.')

    replacements = [
        ('const Dashboard = lazy(() => import("./pages/Dashboard"));\n', ''),
        ('  | "Universal Analysis"\n', ''),
        ('  { label: "Universal Analysis", icon: "◎" },\n', ''),
        (
            '    useState<PageName>("Universal Analysis");',
            '''    useState<PageName>("Dashboard");

  // State lives in App so normalized findings persist when switching to ASA details.
  const [unifiedReport, setUnifiedReport] = useState<NormalizedReport | null>(null);
  const [legacyASAReady, setLegacyASAReady] = useState(false);''',
        ),
        (
            '''            {activePage !== "Universal Analysis" && (''',
            '''            {unifiedReport?.platform.platform_id === "cisco_asa" && legacyASAReady && (''',
        ),
        (
            '''            {activePage === "Universal Analysis" && (
              <UniversalAnalysis />
            )}

''',
            '',
        ),
        (
            '''            {activePage === "Dashboard" && (
              <Dashboard />
            )}''',
            '''            {activePage === "Dashboard" && (
              <UniversalAnalysis
                report={unifiedReport}
                onReportChange={setUnifiedReport}
                legacyASAReady={legacyASAReady}
                onLegacyASAReadyChange={setLegacyASAReady}
              />
            )}''',
        ),
        (
            '''          {navItems.map((item, index) => (''',
            '''          {navItems
            .filter((item) => item.label === "Dashboard" ||
              (unifiedReport?.platform.platform_id === "cisco_asa" && legacyASAReady))
            .map((item, index) => (''',
        ),
        (
            '''          <AnalysisFeedback />''',
            '''          {unifiedReport?.platform.platform_id === "cisco_asa" && <AnalysisFeedback />}''',
        ),
    ]
    updated = text
    for old, new in replacements:
        updated = replace_one(updated, old, new)
    updated = replace_one(
        updated,
        'import AnalysisFeedback from "./components/AnalysisFeedback";',
        'import AnalysisFeedback from "./components/AnalysisFeedback";\nimport type { NormalizedReport } from "./api/universal";',
    )
    if 'label: "Universal Analysis"' in updated or '<Dashboard />' in updated:
        raise ValueError('Duplicate page references remain; refusing to update.')
    return updated


def main() -> int:
    needed = [
        APP, UNIVERSAL, Path('src/api/universal.ts'),
        Path('src/context/AnalysisContext.tsx'),
        Path('src/components/SummaryCard.tsx'),
        Path('src/components/ConfigurationSummary.tsx'),
        Path('src/components/FirewallInfo.tsx'),
        Path('src/components/SecurityScore.tsx'),
        Path('src/components/SeverityChart.tsx'),
        STAGED / 'UniversalAnalysis.tsx',
        STAGED / 'CiscoASAOverview.tsx',
        STAGED / 'UnifiedDashboardExtras.css',
    ]
    missing = [str(path) for path in needed if not path.is_file()]
    if missing:
        print('ERROR: Required file(s) missing from React frontend:', file=sys.stderr)
        for item in missing:
            print('  ' + item, file=sys.stderr)
        print('Run this script from ...\\config analyzer\\frontend, not the backend root.', file=sys.stderr)
        return 2
    original_app = APP.read_text(encoding='utf-8-sig')
    new_universal = (STAGED / 'UniversalAnalysis.tsx').read_text(encoding='utf-8')
    try:
        patched_app = patch_app(original_app)
    except ValueError as error:
        print(f'ERROR: {error}. No files changed.', file=sys.stderr)
        return 2
    if 'function UniversalAnalysis()' not in UNIVERSAL.read_text(encoding='utf-8-sig') and patched_app != original_app:
        print('ERROR: UniversalAnalysis.tsx differs from the API-009.7 baseline. No files changed.', file=sys.stderr)
        return 2
    if patched_app == original_app:
        if UNIVERSAL.read_text(encoding='utf-8-sig') == new_universal:
            print('Dashboard already merged. No changes needed.')
            return 0
        print('ERROR: App.tsx is merged but page differs. No files changed.', file=sys.stderr)
        return 2
    if APP_BACKUP.exists() or UNIVERSAL_BACKUP.exists():
        print('ERROR: A merge backup already exists. Inspect backups before rerunning.', file=sys.stderr)
        return 2
    # Backup originals before any edits.
    shutil.copy2(APP, APP_BACKUP)
    shutil.copy2(UNIVERSAL, UNIVERSAL_BACKUP)
    APP.write_text(patched_app, encoding='utf-8')
    UNIVERSAL.write_text(new_universal, encoding='utf-8')
    for name in ('CiscoASAOverview.tsx', 'UnifiedDashboardExtras.css'):
        shutil.copy2(STAGED / name, UNIVERSAL.parent / name)
    print('Merged: src/App.tsx and src/pages/UniversalAnalysis.tsx')
    print('Created: src/pages/CiscoASAOverview.tsx, UnifiedDashboardExtras.css')
    print('Backups: ' + str(APP_BACKUP) + ' and ' + str(UNIVERSAL_BACKUP))
    print('One Dashboard entry remains; Cisco ASA details are shown only for synced ASA reports.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
