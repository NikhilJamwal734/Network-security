"""Install API-009.8 assessment UI into the real frontend project.

Run from any working directory with: python ...install_frontend_assessment.py
or pass the frontend folder as the sole argument. Edits are prevalidated and
backed up. Re-running is safe and will not duplicate markup.
"""

from __future__ import annotations

from pathlib import Path
import shutil
import sys

PACKAGE = Path(__file__).resolve().parents[1]
PROJECT = Path(__file__).resolve().parents[2]
DEFAULT_FRONTEND = PROJECT / "frontend"
FRONTEND = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else DEFAULT_FRONTEND

API_INTERFACE = '''export interface AdvancedAssessment {
  version: "1.0";
  scope: "uploaded_text_only";
  platform_id: string;
  review_score: {
    value: number;
    maximum: number;
    method: string;
    label: string;
    status: "provisional";
    priority: string;
    deductions: Record<Severity, number>;
    capped_for_incomplete_coverage: boolean;
    comparable_across_platforms: boolean;
    interpretation: string;
  };
  observations: Array<{
    code: string;
    title: string;
    status: "observed" | "not_visible" | "not_assessed";
    detail: string;
    evidence: { source_field: string; value: number | boolean | null; line_number: number | null };
  }>;
  coverage_review: {
    assessed_domain_count: number;
    unassessed_domain_count: number;
    unassessed_domains: string[];
    status: "partial" | "declared_checks_only";
  };
  notice: string;
}
'''


def prepare() -> dict[Path, bytes]:
    api = FRONTEND / "src/api/universal.ts"
    page = FRONTEND / "src/pages/UniversalAnalysis.tsx"
    pdf = FRONTEND / "src/utils/normalizedPdf.ts"
    if not api.is_file() or not page.is_file():
        raise RuntimeError("Expected frontend/src/api/universal.ts and frontend/src/pages/UniversalAnalysis.tsx")
    if not (FRONTEND / "package.json").is_file():
        raise RuntimeError("Not a React project; package.json was not found")

    result: dict[Path, bytes] = {}
    contents = api.read_text(encoding="utf-8")
    old_endpoint = '/api/v1/analyze/normalized'
    new_endpoint = '/api/v1/analyze/assessment'
    if new_endpoint not in contents:
        if old_endpoint not in contents:
            raise RuntimeError("Could not find normalized analysis endpoint in src/api/universal.ts")
        contents = contents.replace(old_endpoint, new_endpoint, 1)
    if 'assessment?: AdvancedAssessment;' not in contents:
        anchor = 'export interface NormalizedReport {'
        if anchor not in contents:
            raise RuntimeError("Expected NormalizedReport interface was not found")
        contents = contents.replace(anchor, anchor + '\n  assessment?: AdvancedAssessment;', 1)
    if 'export interface AdvancedAssessment {' not in contents:
        contents += '\n\n' + API_INTERFACE
    result[api] = contents.encode("utf-8")

    contents = page.read_text(encoding="utf-8")
    if 'AdvancedAssessmentPanel' not in contents:
        import_anchor = 'import "./UniversalAnalysis.css";'
        panel_anchor = '<div className="ua-results" aria-live="polite">'
        if import_anchor not in contents or panel_anchor not in contents:
            raise RuntimeError("UniversalAnalysis layout not recognized; no files changed")
        contents = contents.replace(import_anchor,
            'import AdvancedAssessmentPanel from "../components/AdvancedAssessmentPanel";\n' + import_anchor, 1)
        contents = contents.replace(panel_anchor,
            panel_anchor + '\n          <AdvancedAssessmentPanel assessment={report.assessment} />', 1)
    result[page] = contents.encode("utf-8")

    # Existing normalized PDF exporter, when installed by API-009.7, is enriched.
    if pdf.is_file():
        contents = pdf.read_text(encoding="utf-8")
        if 'API-009.8 configuration review' not in contents:
            anchor = '  heading("Security findings");'
            if anchor not in contents:
                raise RuntimeError("Normalized PDF renderer has changed; refusing partial install")
            section = '''  // API-009.8 configuration review: one common assessment for four platforms.
  if (report.assessment) {
    const a = report.assessment;
    heading("API-009.8 configuration review");
    line(`Provisional review score: ${a.review_score.value}/100 (maximum ${a.review_score.maximum})`);
    line(`Finding priority: ${a.review_score.priority.replace(/_/g, " ")}`);
    line(a.review_score.interpretation, { size: 9 });
    heading("Visible configuration evidence");
    a.observations.forEach((o) => {
      line(`${o.title}: ${o.status.replace(/_/g, " ")}`, { bold: true, indent: 10 });
      line(o.detail, { indent: 14 });
      line(`Source: ${o.evidence.source_field}`, { indent: 14, size: 9 });
    });
    heading("Unassessed domains");
    a.coverage_review.unassessed_domains.forEach((d) => line(d.replace(/_/g, " "), { indent: 12 }));
  }

'''
            contents = contents.replace(anchor, section + anchor, 1)
        result[pdf] = contents.encode("utf-8")

    components = PACKAGE / "src/components"
    for filename in ("AdvancedAssessmentPanel.tsx", "AdvancedAssessmentPanel.css"):
        result[FRONTEND / "src/components" / filename] = (components / filename).read_bytes()
    return result


def install() -> list[str]:
    updates = prepare()  # Validate everything before ANY file writes.
    messages: list[str] = []
    for destination, payload in updates.items():
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.exists() and destination.read_bytes() == payload:
            messages.append(f"Unchanged: {destination}")
            continue
        if destination.exists():
            backup = destination.with_name(destination.name + ".api0098.backup")
            if not backup.exists():
                shutil.copy2(destination, backup)
        destination.write_bytes(payload)
        messages.append(f"Installed: {destination}")
    if not (FRONTEND / "src/utils/normalizedPdf.ts").is_file():
        messages.append("Note: normalizedPdf.ts not found; PDF enrichment was skipped (dashboard still works).")
    return messages


if __name__ == "__main__":
    try:
        for message in install():
            print(message)
    except (RuntimeError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)
