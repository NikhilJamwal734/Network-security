"""API-009.7: enable shared Findings/Coverage/Reports navigation and PDF for all platforms.

Run this script from the React FRONTEND directory containing package.json and src/App.tsx.
Creates backups, validates the existing merged-dashboard layout, and is safe to rerun.
Does not touch the backend, Cisco ASA components, or existing uploaded data.
"""
from __future__ import annotations

from pathlib import Path
import re
import shutil
import sys

PATCH_ID = "api0097_all_platform_reports_v1"
PATCH = Path(__file__).resolve().parent.parent
FRONTEND = Path.cwd()
APP = FRONTEND / "src" / "App.tsx"
FILES = (
    "src/utils/normalizedPdf.ts",
    "src/components/NormalizedReportDownloads.tsx",
    "src/components/NormalizedReportDownloads.css",
    "src/pages/NormalizedFindingsPage.tsx",
    "src/pages/NormalizedCoveragePage.tsx",
    "src/pages/NormalizedReportsPage.tsx",
    "src/pages/NormalizedPlatformPages.css",
)


def only(source: str, old: str, new: str, label: str) -> str:
    count = source.count(old)
    if count != 1:
        raise ValueError(f"{label}: expected exactly 1 anchor, found {count}; no files changed")
    return source.replace(old, new, 1)


def patch_app(src: str) -> str:
    if "NormalizedReportDownloads" in src and "NormalizedCoveragePage" in src:
        return src  # already patched
    src = only(src,
        'const UniversalAnalysis = lazy(() => import("./pages/UniversalAnalysis"));',
        'const UniversalAnalysis = lazy(() => import("./pages/UniversalAnalysis"));\n'
        'const NormalizedFindingsPage = lazy(() => import("./pages/NormalizedFindingsPage"));\n'
        'const NormalizedCoveragePage = lazy(() => import("./pages/NormalizedCoveragePage"));\n'
        'const NormalizedReportsPage = lazy(() => import("./pages/NormalizedReportsPage"));',
        "normalized page imports")
    src = only(src,
        'import PdfReportDownload from "./components/PdfReportDownload";',
        'import PdfReportDownload from "./components/PdfReportDownload";\n'
        'import NormalizedReportDownloads from "./components/NormalizedReportDownloads";',
        "report downloads import")
    src = only(src,
        '  | "Reports";',
        '  | "Reports"\n  | "Coverage";',
        "PageName")
    src = only(src,
        '  { label: "Reports", icon: "▤" },',
        '  { label: "Reports", icon: "▤" },\n'
        '  { label: "Coverage", icon: "◉" },',
        "sidebar list")
    pattern = re.compile(
        r'\.filter\(\(item\) => item\.label === "Dashboard" \|\|\s*'
        r'\(unifiedReport\?\.platform\.platform_id === "cisco_asa" && legacyASAReady\)\)'
    )
    replacement = ('.filter((item) =>\n'
        '              item.label === "Dashboard" ||\n'
        '              (unifiedReport !== null &&\n'
        '                (item.label === "Findings" || item.label === "Reports" || item.label === "Coverage")) ||\n'
        '              (unifiedReport?.platform.platform_id === "cisco_asa" && legacyASAReady)\n'
        '            )')
    src, n = pattern.subn(replacement, src)
    if n != 1:
        raise ValueError(f"sidebar visibility: expected 1 ASA-only filter, found {n}; no files changed")
    old_actions = '''            {unifiedReport?.platform.platform_id === "cisco_asa" && legacyASAReady && (
              <div className="fa-topbar-downloads">
                <JsonReportDownload />
                <PdfReportDownload />
              </div>
            )}'''
    new_actions = '''            {unifiedReport?.platform.platform_id === "cisco_asa" && legacyASAReady ? (
              <div className="fa-topbar-downloads">
                <JsonReportDownload />
                <PdfReportDownload />
              </div>
            ) : unifiedReport ? (
              <NormalizedReportDownloads
                report={unifiedReport}
                filename={unifiedReport.platform.hostname || unifiedReport.platform.platform_id}
                compact
              />
            ) : null}'''
    src = only(src, old_actions, new_actions, "topbar exports")
    src = only(src,
        '''            {activePage === "Findings" && (
              <Findings />
            )}''',
        '''            {activePage === "Findings" && unifiedReport && (
              unifiedReport.platform.platform_id === "cisco_asa" && legacyASAReady ? (
                <Findings />
              ) : (
                <NormalizedFindingsPage report={unifiedReport} />
              )
            )}''', "findings page")
    src = only(src,
        '''            {activePage === "Reports" && (
              <Reports />
            )}''',
        '''            {activePage === "Reports" && unifiedReport && (
              unifiedReport.platform.platform_id === "cisco_asa" && legacyASAReady ? (
                <Reports />
              ) : (
                <NormalizedReportsPage
                  report={unifiedReport}
                  filename={unifiedReport.platform.hostname || unifiedReport.platform.platform_id}
                />
              )
            )}

            {/* ANALYSIS COVERAGE (ALL PLATFORMS) */}
            {activePage === "Coverage" && unifiedReport && (
              <NormalizedCoveragePage report={unifiedReport} />
            )}''', "reports page and coverage")
    return src


def main() -> int:
    required = [FRONTEND / "package.json", APP, FRONTEND / "src/pages/UniversalAnalysis.tsx"]
    missing = [str(p) for p in required if not p.is_file()]
    if missing:
        print("ERROR: Run from the real React frontend folder. Missing:\n" + "\n".join(missing), file=sys.stderr)
        return 2
    try:
        existing = APP.read_text(encoding="utf-8-sig")
        updated = patch_app(existing)
        additions = {}
        for rel in FILES:
            source = PATCH / rel
            if not source.is_file():
                raise ValueError(f"Patch package incomplete: {rel}")
            destination = FRONTEND / rel
            content = source.read_text(encoding="utf-8")
            if destination.exists() and destination.read_text(encoding="utf-8-sig") != content:
                raise ValueError(f"{rel} already exists with custom content; refusing to overwrite")
            additions[destination] = content
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    for target, content in {APP: updated, **additions}.items():
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists() and target.read_text(encoding="utf-8-sig") == content:
            print("Unchanged:", target.relative_to(FRONTEND))
            continue
        if target.exists():
            backup = target.with_name(f"{target.name}.{PATCH_ID}.backup")
            if not backup.exists():
                shutil.copy2(target, backup)
                print("Backup:", backup.relative_to(FRONTEND))
        target.write_text(content, encoding="utf-8")
        print("Updated:", target.relative_to(FRONTEND))
    print("Completed. Install the PDF library with: npm install jspdf")
    print("Then verify with: npm run build")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
