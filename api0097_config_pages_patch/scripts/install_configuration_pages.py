"""API-009.7: platform-aware Rules, Network, Services, NAT, Routes, Configuration.

Run from the main project ROOT containing frontend/, app/ and .venv-win/.
Frontend-only update: backend APIs and regression expectations are unchanged.
Checks every anchor before writing; backs up modified files; safe to rerun.
"""
from __future__ import annotations
from pathlib import Path
import re
import shutil
import sys

ROOT = Path.cwd()
SOURCE = Path(__file__).resolve().parent.parent
VERSION = 'api0097_config_pages_v1'
APP = ROOT / 'frontend/src/App.tsx'
UNIVERSAL = ROOT / 'frontend/src/pages/UniversalAnalysis.tsx'
FILES = {
    ROOT / 'frontend/src/pages/PlatformConfigurationPage.tsx': SOURCE / 'src/pages/PlatformConfigurationPage.tsx',
    ROOT / 'frontend/src/pages/PlatformConfigurationPage.css': SOURCE / 'src/pages/PlatformConfigurationPage.css',
    ROOT / 'frontend/src/api/platformConfiguration.ts': SOURCE / 'src/api/platformConfiguration.ts',
}


def one(src: str, old: str, new: str, label: str) -> str:
    n = src.count(old)
    if n != 1:
        raise ValueError(f'{label}: expected 1 matching location, found {n}')
    return src.replace(old, new, 1)


def patch_app(src: str) -> str:
    if '<PlatformConfigurationPage report=' in src:
        if src.count('<PlatformConfigurationPage report=') == 6:
            return src
        raise ValueError('Partial platform page update found')
    for name in ('NormalizedCoveragePage', 'NormalizedReportsPage', 'unifiedReport', 'legacyASAReady'):
        if name not in src:
            raise ValueError(f'Missing {name}; install the all-platform reports patch first')
    src = one(src,
        'const NormalizedCoveragePage = lazy(() => import("./pages/NormalizedCoveragePage"));',
        'const NormalizedCoveragePage = lazy(() => import("./pages/NormalizedCoveragePage"));\n'
        'const PlatformConfigurationPage = lazy(() => import("./pages/PlatformConfigurationPage"));',
        'new page import')
    src = one(src,
        'import type { NormalizedReport } from "./api/universal";',
        'import type { NormalizedReport } from "./api/universal";\n'
        'import type { PlatformDetails } from "./api/platformConfiguration";',
        'API type import')
    src = one(src,
        '  const [legacyASAReady, setLegacyASAReady] = useState(false);',
        '  const [legacyASAReady, setLegacyASAReady] = useState(false);\n'
        '  const [platformDetails, setPlatformDetails] = useState<PlatformDetails | null>(null);',
        'configuration state')
    src = one(src,
        '                onReportChange={setUnifiedReport}',
        '                onReportChange={setUnifiedReport}\n'
        '                onConfigurationChange={setPlatformDetails}',
        'Dashboard details callback')
    pat = re.compile(r'(?s)          \{navItems\s*\n\s*\.filter\(\(item\) =>(.*?)\n\s*\.map\(\(item, index\) => \(')
    found = list(pat.finditer(src))
    if len(found) != 1 or 'Coverage' not in found[0].group(1):
        raise ValueError('Unrecognized sidebar visibility filter')
    src = pat.sub('          {navItems\n            .filter((item) => item.label === "Dashboard" || unifiedReport !== null)\n            .map((item, index) => (', src, count=1)
    for label, component in (
        ('Rules','FirewallRules'), ('Network Objects','NetworkObjects'),
        ('Service Objects','ServiceObjects'), ('NAT Rules','NATRules'),
        ('Routes','Routes'), ('Configuration','Configuration'),
    ):
        src = one(src,
            f'''            {{activePage === "{label}" && (
              <{component} />
            )}}''',
            f'''            {{activePage === "{label}" && unifiedReport && (
              unifiedReport.platform.platform_id === "cisco_asa" && legacyASAReady ? (
                <{component} />
              ) : (
                <PlatformConfigurationPage report={{unifiedReport}} section="{label}" details={{platformDetails}} />
              )
            )}}''',
            f'{label} page')
    return src


def patch_universal(src: str) -> str:
    if 'onConfigurationChange' in src:
        if 'getPlatformDetails' in src:
            return src
        raise ValueError('Partial UniversalAnalysis update found')
    src = one(src,
        'import { useAnalysis } from "../context/AnalysisContext";',
        'import { useAnalysis } from "../context/AnalysisContext";\n'
        'import { getPlatformDetails } from "../api/platformConfiguration";\n'
        'import type { PlatformDetails } from "../api/platformConfiguration";',
        'client import')
    src = one(src,
        '  onReportChange: (report: NormalizedReport | null) => void;',
        '  onReportChange: (report: NormalizedReport | null) => void;\n'
        '  onConfigurationChange: (details: PlatformDetails | null) => void;',
        'component props')
    src = one(src,
        '  report, onReportChange, legacyASAReady, onLegacyASAReadyChange,',
        '  report, onReportChange, onConfigurationChange, legacyASAReady, onLegacyASAReadyChange,',
        'destructure props')
    src = one(src,
        '  const [asaSyncError, setAsaSyncError] = useState<string | null>(null);',
        '  const [asaSyncError, setAsaSyncError] = useState<string | null>(null);\n'
        '  const [detailError, setDetailError] = useState<string | null>(null);',
        'detail error state')
    # All three calls onReportChange(null) must also clear the cached inventory.
    if src.count('    onReportChange(null);') != 3:
        raise ValueError('Upload/reset lifecycle changed; refusing to patch')
    src = src.replace('    onReportChange(null);', '    onReportChange(null);\n    onConfigurationChange(null);\n    setDetailError(null);')
    src = one(src,
        '      // Only Cisco ASA needs the legacy report as well:',
        '''      // Platform-specific structured inventory is provided by the existing
      // universal endpoint. This second request never opens referenced files.
      if (next.platform.platform_id !== "cisco_asa") {
        try {
          const details = await getPlatformDetails(file, next.platform.platform_id, controller.signal);
          if (inFlight.current !== controller || controller.signal.aborted) return;
          onConfigurationChange(details);
        } catch (reason) {
          if (inFlight.current === controller && !controller.signal.aborted) {
            setDetailError(reason instanceof Error ? reason.message : "Configuration details unavailable.");
          }
        }
      }

      // Only Cisco ASA needs the legacy report as well:''',
        'request platform inventory')
    src = one(src,
        '        {error && <p className="ua-alert ua-alert-error" role="alert">{error}</p>}',
        '        {error && <p className="ua-alert ua-alert-error" role="alert">{error}</p>}\n'
        '        {detailError && <p className="ua-alert ua-alert-info" role="status">Security findings are available, but the extra configuration inventory could not load: {detailError}</p>}',
        'detail warning')
    return src


def main() -> int:
    required = (APP, UNIVERSAL, ROOT / 'frontend/package.json', *FILES.values())
    missing = [str(p) for p in required if not p.is_file()]
    if missing:
        print('ERROR: Missing files. Run from the main project root:\n  ' + '\n  '.join(missing), file=sys.stderr)
        return 2
    try:
        changes = {
            APP: patch_app(APP.read_text(encoding='utf-8-sig')),
            UNIVERSAL: patch_universal(UNIVERSAL.read_text(encoding='utf-8-sig')),
        }
        for dst, source in FILES.items():
            content = source.read_text(encoding='utf-8')
            if dst.exists() and dst.read_text(encoding='utf-8-sig') != content:
                raise ValueError(f'{dst.relative_to(ROOT)} has custom content; refusing to overwrite')
            changes[dst] = content
    except (OSError, ValueError) as error:
        print(f'ERROR: {error}\nNo files changed.', file=sys.stderr)
        return 2
    for dst, content in changes.items():
        dst.parent.mkdir(parents=True, exist_ok=True)
        if dst.exists() and dst.read_text(encoding='utf-8-sig') == content:
            print('Unchanged:', dst.relative_to(ROOT))
            continue
        if dst.exists():
            backup = dst.with_name(dst.name + '.' + VERSION + '.backup')
            if not backup.exists():
                shutil.copy2(dst, backup)
                print('Backup:', backup.relative_to(ROOT))
        dst.write_text(content, encoding='utf-8')
        print('Updated:', dst.relative_to(ROOT))
    print('Done. No backend files changed. Run npm run build in frontend/.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
