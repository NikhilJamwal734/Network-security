"""Install lazy jsPDF and optional IDS rule review without changing App.tsx.

Run from the backend project root. The installer patches only recognized anchors,
backs up touched files, and is idempotent.
"""
from __future__ import annotations

from pathlib import Path
import shutil
import sys

ROOT = Path(__file__).resolve().parents[2]
FRONTEND = ROOT / "frontend"
PACKAGE = Path(__file__).resolve().parents[1]


def patch_pdf(source: str) -> str:
    dynamic = 'const { jsPDF } = await import("jspdf");'
    if dynamic in source:
        return source
    static = 'import { jsPDF } from "jspdf";'
    signature = 'export function downloadNormalizedPdf(report: NormalizedReport, filename: string): void {'
    doc = '  const doc = new jsPDF('
    if source.count(static) != 1 or source.count(signature) != 1 or source.count(doc) != 1:
        raise RuntimeError("normalizedPdf.ts changed; cannot safely enable lazy loading")
    source = source.replace(static + "\n", "", 1)
    source = source.replace(signature,
        'export async function downloadNormalizedPdf(report: NormalizedReport, filename: string): Promise<void> {', 1)
    return source.replace(doc, f"  {dynamic}\n" + doc, 1)


def patch_dashboard(source: str) -> str:
    if '<IDSRuleBundlePanel' in source:
        if 'import IDSRuleBundlePanel from "../components/IDSRuleBundlePanel";' in source:
            return source
        raise RuntimeError("Partial IDS widget integration detected")
    import_anchor = 'import "./UniversalAnalysis.css";'
    if source.count(import_anchor) != 1:
        raise RuntimeError("UniversalAnalysis.tsx layout not recognized")
    # Place an optional review below the existing normalized findings/assessment,
    # inside the report-result container without changing the primary uploader.
    result_anchor = '<div className="ua-results" aria-live="polite">'
    if source.count(result_anchor) != 1:
        raise RuntimeError("Unable to locate dashboard's normalized result section")
    source = source.replace(import_anchor,
        'import IDSRuleBundlePanel from "../components/IDSRuleBundlePanel";\n' + import_anchor, 1)
    return source.replace(result_anchor,
        result_anchor + '\n          <IDSRuleBundlePanel platformId={report.platform.platform_id} configurationFile={file} />', 1)


def prepare() -> dict[Path, bytes]:
    page = FRONTEND / "src/pages/UniversalAnalysis.tsx"
    pdf = FRONTEND / "src/utils/normalizedPdf.ts"
    if not (FRONTEND / "package.json").is_file() or not page.is_file() or not pdf.is_file():
        raise RuntimeError("Expected frontend package.json, UniversalAnalysis.tsx and normalizedPdf.ts")
    files = {
        page: patch_dashboard(page.read_text(encoding="utf-8-sig")).encode(),
        pdf: patch_pdf(pdf.read_text(encoding="utf-8-sig")).encode(),
    }
    for extension in ("tsx", "css"):
        filename = f"IDSRuleBundlePanel.{extension}"
        files[FRONTEND / "src/components" / filename] = (PACKAGE / "src/components" / filename).read_bytes()
    return files


def install() -> list[str]:
    changes = prepare()  # Refuse changes if any anchor is unknown.
    info: list[str] = []
    for file, data in changes.items():
        file.parent.mkdir(parents=True, exist_ok=True)
        if file.exists() and file.read_bytes() == data:
            info.append(f"Unchanged: {file}")
            continue
        if file.exists():
            backup = file.with_name(file.name + ".api0098.backup")
            if not backup.exists():
                shutil.copy2(file, backup)
        file.write_bytes(data)
        info.append(f"Updated: {file}")
    return info


if __name__ == "__main__":
    try:
        for message in install():
            print(message)
    except (RuntimeError, OSError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        sys.exit(1)
