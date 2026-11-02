"""Route all four platform PDFs through normalizedPdf.ts's formal PDF renderer.

Run from the main project root:
  python unified_formal_pdf_patch/scripts/install_unified_pdf.py

This patch changes only the React frontend, saves backups, and is rerunnable.
No source changes are committed unless every expected anchor validates.
"""
from __future__ import annotations

import re
import shutil
import sys
from pathlib import Path

PACKAGE = Path(__file__).resolve().parents[1]
PROJECT = PACKAGE.parent
FRONTEND = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else PROJECT / "frontend"
BACKUP_SUFFIX = ".before_unified_formal_pdf.bak"


def patch_app(source: str) -> str:
    # App already has the normalized report in state, used by every platform.
    if "const [unifiedReport," not in source and "const [unifiedReport, setUnifiedReport]" not in source:
        raise ValueError("App.tsx does not have unifiedReport state; refusing patch")
    if 'activePage === "Reports"' not in source:
        raise ValueError("Reports page route not found; refusing patch")
    if 'className="topbar-right"' not in source:
        raise ValueError("App.tsx topbar not found; refusing patch")

    # All platforms receive the same topbar PDF button, not the legacy ASA PDF.
    topbar_match = re.search(
        r'(?P<open><div className="topbar-right">)(?P<actions>.*?)(?P<environment>\n\s*<span className="environment">)',
        source, re.S,
    )
    if topbar_match is None or "unifiedReport" not in topbar_match.group("actions"):
        raise ValueError("Topbar report-download block is unrecognized; refusing patch")
    new_actions = (
        "\n            {/* One PDF renderer for Cisco ASA, FortiOS, Snort and Suricata. */}\n"
        "            {unifiedReport && (\n"
        '              <div className="fa-topbar-downloads">\n'
        "                <NormalizedReportDownloads\n"
        "                  report={unifiedReport}\n"
        "                  filename={unifiedReport.platform.hostname || unifiedReport.platform.platform_id}\n"
        "                  compact\n"
        "                />\n"
        "              </div>\n"
        "            )}\n"
    )
    source = (
        source[:topbar_match.start("actions")]
        + new_actions.rstrip("\n")
        + source[topbar_match.end("actions"):]
    )

    # Previously Cisco ASA had an entirely different Reports page/exporter.
    # Route Reports to the existing normalized reports page for every platform.
    route_match = re.search(
        r'\{activePage === "Reports"\s*&&.*?\n\s{12}\)\}',
        source, re.S,
    )
    if route_match is None:
        raise ValueError("Could not locate the Reports page JSX branch")
    old_route = route_match.group()
    if "<Reports />" not in old_route and "<NormalizedReportsPage" not in old_route:
        raise ValueError("Reports route differs from the known layout; refusing patch")
    new_route = '''{activePage === "Reports" && unifiedReport && (
              <NormalizedReportsPage
                report={unifiedReport}
                filename={unifiedReport.platform.hostname || unifiedReport.platform.platform_id}
              />
            )}'''
    source = source[:route_match.start()] + new_route + source[route_match.end():]

    # Remove old components after switching the routes, to avoid TS6133.
    source = re.sub(
        r'(?m)^\s*const Reports = lazy\(\(\) => import\(["\']\./pages/Reports["\']\)\);\s*\n',
        "\n", source,
    )
    source = re.sub(
        r'(?m)^\s*import (?:PdfReportDownload|JsonReportDownload) from ["\'][^"\']+["\'];\s*\n',
        "\n", source,
    )
    # Some releases also used a normalized download component as a lazy constant.
    if 'import NormalizedReportDownloads from ' not in source:
        insertion = re.search(r'(?m)^import type \{ NormalizedReport \} from ["\']\./api/universal["\'];\s*$', source)
        if insertion is None:
            raise ValueError("Cannot safely add normalized PDF component import")
        source = (source[:insertion.end()]
                  + '\nimport NormalizedReportDownloads from "./components/NormalizedReportDownloads";'
                  + source[insertion.end():])

    if 'const NormalizedReportsPage = lazy(' not in source:
        anchor = re.search(r'(?m)^const UniversalAnalysis = lazy\([^\n]+\);\s*$', source)
        if not anchor:
            raise ValueError("Cannot safely locate lazy page imports")
        source = (source[:anchor.end()]
                  + '\nconst NormalizedReportsPage = lazy(() => import("./pages/NormalizedReportsPage"));'
                  + source[anchor.end():])

    if "<PdfReportDownload" in source or "<JsonReportDownload" in source or "<Reports />" in source:
        raise ValueError("Legacy report control remains after patch; refusing change")
    if re.search(r'\bPdfReportDownload\b|\bJsonReportDownload\b', source):
        raise ValueError("Unrecognized legacy download component reference remains")
    if re.search(r'\bReports\b\s*=\s*lazy\(', source):
        raise ValueError("Unused legacy Reports page remains")
    return source


def patch_report_page(source: str) -> str:
    if 'NormalizedReportsPage' not in source:
        raise ValueError("NormalizedReportsPage.tsx layout not recognized")
    source = source.replace(
        'Both files contain the same normalized findings and coverage. PDF is formatted for reading; JSON is suitable for further processing.',
        'Download a formal PDF report including numbered findings, evidence, recommendations and assessment coverage.',
    )
    source = re.sub(r'\bJSON\s+and\s+PDF\b', 'PDF', source)
    return source


def patch_pdf(source: str) -> str:
    required = ('renderNormalizedPdf(', 'downloadNormalizedPdf(', 'section("Executive summary")', 'section("Findings register")', 'section("Finding details and recommendations")')
    if not all(token in source for token in required):
        raise ValueError("Professional normalized PDF renderer not recognized; install the Professional Security PDF Report upgrade first")
    return source.replace('pdf.internal.getNumberOfPages()', 'pdf.getNumberOfPages()')


def plan() -> dict[Path, bytes]:
    if not (FRONTEND / "package.json").is_file():
        raise ValueError(f"React frontend not found: {FRONTEND}")
    files = {
        FRONTEND / "src/App.tsx": patch_app,
        FRONTEND / "src/pages/NormalizedReportsPage.tsx": patch_report_page,
        FRONTEND / "src/utils/normalizedPdf.ts": patch_pdf,
    }
    updates: dict[Path, bytes] = {}
    for target, transformer in files.items():
        if not target.is_file():
            raise ValueError(f"Required file missing: {target}")
        current = target.read_text(encoding="utf-8-sig")
        changed = transformer(current)
        if changed != current:
            updates[target] = changed.encode("utf-8")
    shared = FRONTEND / "src/components/NormalizedReportDownloads.tsx"
    if not shared.is_file():
        raise ValueError(f"Shared PDF download component not found: {shared}")
    target_contents = (PACKAGE / "src/components/NormalizedReportDownloads.tsx").read_bytes()
    if shared.read_bytes() != target_contents:
        updates[shared] = target_contents
    # Add a localized error color without overwriting existing button styles.
    css = FRONTEND / "src/components/NormalizedReportDownloads.css"
    if not css.is_file():
        raise ValueError(f"PDF button stylesheet missing: {css}")
    css_old = css.read_text(encoding="utf-8-sig")
    rule = '\n.normalized-download-error { color: #ef4444; font-size: 0.8rem; }\n'
    if '.normalized-download-error' not in css_old:
        updates[css] = (css_old.rstrip() + '\n' + rule).encode('utf-8')
    return updates


def install() -> list[str]:
    updates = plan()  # All validations complete before writing anything.
    changes: list[str] = []
    for target, data in updates.items():
        backup = target.with_name(target.name + BACKUP_SUFFIX)
        if target.exists() and not backup.exists():
            shutil.copy2(target, backup)
        target.write_bytes(data)
        changes.append(f"Updated: {target.relative_to(FRONTEND)}")
    return changes or ["Already installed: unified PDF report format"]


if __name__ == "__main__":
    try:
        print("Frontend:", FRONTEND)
        for message in install():
            print(message)
        print("Next: cd frontend; npm run build")
    except (OSError, ValueError) as error:
        print("ERROR:", error, file=sys.stderr)
        sys.exit(1)
