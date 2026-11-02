"""Attach API-010.1 vendor review and a full-height emerald sidebar.

Conservative, idempotent frontend installer. Validates known anchors before writing,
backs up existing files and does not change navigation state or backend logic.
"""
from __future__ import annotations

from pathlib import Path
import shutil
import sys

PACKAGE = Path(__file__).resolve().parents[1]
PROJECT = PACKAGE.parent
SUFFIX = ".before_api0101.bak"

INTERFACE = '''
/** Supplemental checks; intentionally excluded from original risk scoring. */
export interface VendorReview {
  version: "1.0";
  platform_id: "cisco_asa" | "fortios" | "snort" | "suricata";
  scope: "supplemental_vendor_specific_static_review";
  checks: Array<{
    code: string;
    severity: "HIGH" | "MEDIUM" | "LOW" | "INFO";
    title: string;
    detail: string;
    recommendation: string;
    line_number: number | null;
    rule_id: string | number | null;
  }>;
  suppressed_checks: number;
  limitations: string[];
  interpretation: string;
}
'''


def _replace_once(s: str, old: str, new: str, label: str) -> str:
    if new in s:
        return s
    if s.count(old) != 1:
        raise ValueError(f"Unrecognized {label}: expected 1 anchor, got {s.count(old)}")
    return s.replace(old, new, 1)


def patch_api(s: str) -> str:
    s = _replace_once(s, "/api/v1/analyze/validated", "/api/v1/analyze/deep-review", "analysis endpoint")
    s = _replace_once(s, "export interface NormalizedReport {",
                      "export interface NormalizedReport {\n  vendor_review?: VendorReview;", "NormalizedReport interface")
    if "export interface VendorReview {" not in s:
        s += "\n" + INTERFACE
    return s


def patch_dashboard(s: str) -> str:
    import_line = 'import VendorDeepReviewPanel from "../components/VendorDeepReviewPanel";'
    call = '<VendorDeepReviewPanel review={report.vendor_review} />'
    if (import_line in s) != (call in s):
        raise ValueError("Partial API-010.1 dashboard integration found")
    if call in s:
        return s
    s = _replace_once(s, 'import "./UniversalAnalysis.css";',
                      import_line + '\nimport "./UniversalAnalysis.css";', "dashboard CSS import")
    anchor = '<ReportQualityPanel quality={report.quality} />'
    return _replace_once(s, anchor, anchor + '\n          ' + call, "API-010.0 report-quality panel")


def patch_app(s: str) -> str:
    marker = 'import "./styles/SidebarGreen.css";'
    if marker in s:
        return s
    # Theme.css typically loads after index.css and AppResponsive.css.
    if 'import "./Theme.css";' in s:
        return s.replace('import "./Theme.css";', 'import "./Theme.css";\n' + marker, 1)
    if 'import "./AppResponsive.css";' in s:
        return s.replace('import "./AppResponsive.css";', 'import "./AppResponsive.css";\n' + marker, 1)
    if 'import "./index.css";' in s:
        return s.replace('import "./index.css";', 'import "./index.css";\n' + marker, 1)
    raise ValueError("Could not safely find a final App stylesheet import")


def patch_pdf(s: str) -> str:
    mark = 'section("Vendor-specific supplemental review")'
    if mark in s:
        return s
    if 'renderNormalizedPdf(' not in s:
        raise ValueError("Expected professional normalized PDF exporter")
    anchor = '  section("Assessment coverage");'
    addition = '''  if (report.vendor_review) {
    section("Vendor-specific supplemental review");
    text("The following extra review observations are not included in the original findings, severity totals, or provisional score.", {
      size: 8.5, color: COLORS.muted, spaceAfter: 8,
    });
    report.vendor_review.checks.slice(0, 40).forEach((item, i) => {
      ensure(64);
      text(`V-${String(i + 1).padStart(3, "0")}  ${item.title}  [${item.severity}]`, {
        bold: true, size: 9.6, color: COLORS.navy, spaceAfter: 3,
      });
      text(item.detail, { indent: 10, size: 8.6, spaceAfter: 5 });
      text(`Recommendation: ${item.recommendation}`, { indent: 10, size: 8.6, spaceAfter: 4 });
      text(`${item.code} | Line: ${item.line_number ?? "Not available"} | Rule/object: ${item.rule_id ?? "N/A"}`, {
        indent: 10, size: 8, color: COLORS.muted, spaceAfter: 12,
      });
    });
    text(report.vendor_review.interpretation, { size: 8.4, color: COLORS.muted, spaceAfter: 7 });
  }

'''
    return _replace_once(s, anchor, addition + anchor, "PDF coverage section")


def plan(frontend: Path = PROJECT / "frontend") -> dict[Path, bytes]:
    if not (frontend / "package.json").is_file():
        raise ValueError(f"Frontend package.json not found: {frontend}")
    transforms = {
        "src/App.tsx": patch_app,
        "src/api/universal.ts": patch_api,
        "src/pages/UniversalAnalysis.tsx": patch_dashboard,
        "src/utils/normalizedPdf.ts": patch_pdf,
    }
    changes: dict[Path, bytes] = {}
    for relative, transform in transforms.items():
        path = frontend / relative
        if not path.is_file():
            raise ValueError(f"Required frontend file missing: {relative}")
        old = path.read_text(encoding="utf-8-sig")
        new = transform(old)
        if old != new:
            changes[path] = new.encode("utf-8")
    for relative in (
        "src/components/VendorDeepReviewPanel.tsx",
        "src/components/VendorDeepReviewPanel.css",
        "src/styles/SidebarGreen.css",
    ):
        source = PACKAGE / relative
        target = frontend / relative
        if not target.is_file() or target.read_bytes() != source.read_bytes():
            changes[target] = source.read_bytes()
    return changes


def install(frontend: Path = PROJECT / "frontend") -> list[str]:
    changes = plan(frontend)
    for path, data in changes.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.is_file():
            backup = path.with_name(path.name + SUFFIX)
            if not backup.exists():
                shutil.copy2(path, backup)
        path.write_bytes(data)
    return [str(path.relative_to(frontend)) for path in changes]


if __name__ == "__main__":
    target = Path(sys.argv[1]).resolve() if len(sys.argv) == 2 else PROJECT / "frontend"
    try:
        modified = install(target)
    except (ValueError, OSError) as error:
        sys.exit(f"ERROR: {error}")
    print("Updated frontend files:" if modified else "API-010.1 frontend is already installed")
    for name in modified:
        print("  " + name)
    print("Next: cd frontend; npm run build")
