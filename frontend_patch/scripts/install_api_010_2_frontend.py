"""Wire precision review into the existing dashboard and professional PDF.

Does not add any theme CSS or change navigation/sidebar appearance.
Usage: python frontend_patch/scripts/install_api_010_2_frontend.py ./frontend
"""
from __future__ import annotations

from pathlib import Path
import shutil
import sys

PROJECT = Path(__file__).resolve().parents[2]
BACKUP = ".before_api0102.bak"


def replace_one(text: str, old: str, new: str, name: str) -> str:
    if new in text:
        return text
    if text.count(old) != 1:
        raise ValueError(f"Unknown {name} layout: {text.count(old)} matches")
    return text.replace(old, new, 1)


def patch_api(text: str) -> str:
    text = replace_one(text, "/api/v1/analyze/deep-review", "/api/v1/analyze/precision-review", "analysis URL")
    if "  precision?: {" in text:
        return text
    return replace_one(
        text,
        "export interface VendorReview {\n",
        '''export interface VendorReview {
  precision?: {
    version: string;
    status: "context_refined";
    suppressed_preliminary_checks: number;
    additional_evidence_checks: number;
    note: string;
  };
''',
        "VendorReview TypeScript interface",
    )


def patch_panel(text: str) -> str:
    if "vendor-deep-precision-summary" in text:
        return text
    anchor = "      {checks.length ? ("
    addition = '''      {review.precision && (
        <p className="vendor-deep-precision-summary">
          Context refinement: {review.precision.suppressed_preliminary_checks} preliminary observations removed;
          {" "}{review.precision.additional_evidence_checks} additional evidence checks added.
          {" "}{review.precision.note}
        </p>
      )}
'''
    return replace_one(text, anchor, addition + anchor, "vendor review panel")


def patch_pdf(text: str) -> str:
    if "Precision review:" in text:
        return text
    anchor = '    section("Vendor-specific supplemental review");\n'
    addition = anchor + '''    if (report.vendor_review.precision) {
      text(`Precision review: ${report.vendor_review.precision.suppressed_preliminary_checks} preliminary observations removed; ${report.vendor_review.precision.additional_evidence_checks} additional checks added.`, {
        size: 8.5, color: COLORS.muted, spaceAfter: 7,
      });
    }
'''
    return replace_one(text, anchor, addition, "normalized PDF vendor section")


def plan(frontend: Path) -> dict[Path, bytes]:
    frontend = frontend.resolve()
    if not (frontend / "package.json").is_file():
        raise ValueError(f"Frontend package.json not found: {frontend}")
    files = {
        frontend / "src/api/universal.ts": patch_api,
        frontend / "src/components/VendorDeepReviewPanel.tsx": patch_panel,
        frontend / "src/utils/normalizedPdf.ts": patch_pdf,
    }
    changes: dict[Path, bytes] = {}
    for target, transformer in files.items():
        if not target.is_file():
            raise ValueError(f"Required API-010.1 frontend file not found: {target}")
        original = target.read_text(encoding="utf-8-sig")
        result = transformer(original)
        if result != original:
            changes[target] = result.encode("utf-8")
    return changes


def install(frontend: Path) -> list[str]:
    frontend = frontend.resolve()
    changes = plan(frontend)
    for destination, data in changes.items():
        if destination.is_file():
            backup = destination.with_name(destination.name + BACKUP)
            if not backup.exists():
                shutil.copy2(destination, backup)
        destination.write_bytes(data)
    return [str(dest.relative_to(frontend)) for dest in changes]


if __name__ == "__main__":
    frontend = Path(sys.argv[1]).resolve() if len(sys.argv) == 2 else PROJECT / "frontend"
    try:
        changes = install(frontend)
    except (ValueError, OSError) as exc:
        sys.exit(f"ERROR: {exc}")
    print("API-010.2 frontend updated:" if changes else "API-010.2 frontend already installed.")
    for name in changes:
        print("  " + name)
