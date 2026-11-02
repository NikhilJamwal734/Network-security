"""API-011.1 dashboard snippet and PDF-only detailed evidence integration."""
from __future__ import annotations
from pathlib import Path
import shutil
import sys

PACKAGE = Path(__file__).resolve().parents[1]
BACKUP = '.before_api0111.bak'

TYPES = '''
/** Advisory correlation accuracy for one configuration; not an FP rate or remediation engine. */
export interface CorrelationAccuracyReview {
  version: "1.0";
  platform_id: "cisco_asa" | "fortios" | "snort" | "suricata";
  scope: "single_upload_advisory_link_validation";
  status: "reviewed_subset" | "limited";
  summary: {
    links_checked: number; plausible_links: number; unsupported_links: number;
    uncertain_links: number; finding_metadata_pairs: number;
    severity_conflicts: number; findings_without_line: number;
    items_omitted: number; incomplete: boolean;
  };
  decisions: Array<{
    reference: string; upstream_reference: string; source_line: number | null;
    classification: string; reason: string; recommended_action: string;
    confidence: string;
  }>;
  quality_observations: Array<{
    reference: string; kind: string; source_line: number | null;
    reason: string; recommendation: string; confidence: string;
  }>;
  limitations: string[];
}
'''


def replace_once(source: str, old: str, new: str, label: str) -> str:
    if new in source:
        return source
    if source.count(old) != 1:
        raise ValueError(f'{label}: expected exactly one API-011.0 anchor')
    return source.replace(old, new, 1)


def patch_api(source: str) -> str:
    source = replace_once(source, '/api/v1/analyze/consolidated',
                          '/api/v1/analyze/correlation-accuracy', 'upload endpoint')
    source = replace_once(source, '  consolidation_review?: ConsolidationReview;',
                          '  consolidation_review?: ConsolidationReview;\n  correlation_accuracy_review?: CorrelationAccuracyReview;',
                          'normalized review property')
    if 'export interface CorrelationAccuracyReview {' not in source:
        source += '\n' + TYPES
    return source


def patch_dashboard(source: str) -> str:
    source = replace_once(source, 'import ConsolidationSnippet from "../components/ConsolidationSnippet";',
                          'import ConsolidationSnippet from "../components/ConsolidationSnippet";\n'
                          'import CorrelationAccuracySnippet from "../components/CorrelationAccuracySnippet";',
                          'dashboard import')
    return replace_once(source, '<ConsolidationSnippet review={report.consolidation_review} />',
                        '<ConsolidationSnippet review={report.consolidation_review} />\n'
                        '          <CorrelationAccuracySnippet review={report.correlation_accuracy_review} />',
                        'dashboard location')


PDF_BLOCK = '''  if (report.correlation_accuracy_review) {
    section("Correlation accuracy and false-positive triage — Detailed evidence");
    const acc = report.correlation_accuracy_review;
    text("Static report-metadata validation for ONE uploaded configuration. An unsupported link does not mean a finding is a false positive. No findings, scores or severities were changed.", {
      size: 8.4, color: COLORS.muted, spaceAfter: 8,
    });
    text(`Platform: ${acc.platform_id} | Status: ${label(acc.status)} | Links inspected: ${acc.summary.links_checked} | Potential matches: ${acc.summary.plausible_links} | Unsupported links: ${acc.summary.unsupported_links} | Needs context: ${acc.summary.uncertain_links}`, {
      size: 8.4, spaceAfter: 7,
    });
    text(`Matching normalized finding metadata pairs: ${acc.summary.finding_metadata_pairs} | Severity disagreements: ${acc.summary.severity_conflicts} | Findings lacking a source line: ${acc.summary.findings_without_line} | Omitted items: ${acc.summary.items_omitted}`, {
      size: 8.2, spaceAfter: 7,
    });
    text("LINK-BY-LINK VALIDATION", { bold: true, color: COLORS.blue, size: 9, spaceAfter: 5 });
    if (acc.decisions.length === 0) {
      text("No candidate links were returned for validation; this does not establish that the upstream findings are unique or free of false positives.", { size: 8.2, color: COLORS.muted, spaceAfter: 7 });
    }
    acc.decisions.forEach((item) => {
      ensure(95);
      text(`${item.reference} | ${item.upstream_reference || "unreferenced"} | ${label(item.classification)}`, {
        bold: true, color: COLORS.navy, size: 8.7, spaceAfter: 4,
      });
      text(`Source line: ${item.source_line ?? "unavailable"} | Confidence: ${item.confidence}`, {
        size: 8, indent: 10, spaceAfter: 4,
      });
      text(`Evidence: ${item.reason}`, { size: 8.2, indent: 10, spaceAfter: 4 });
      text(`Analyst action: ${item.recommended_action}`, { size: 8.2, indent: 10, spaceAfter: 8 });
    });
    text("FINDING METADATA QUALITY OBSERVATIONS", {
      bold: true, color: COLORS.blue, size: 9, spaceAfter: 5,
    });
    if (acc.quality_observations.length === 0) {
      text("No bounded finding metadata observations were produced. This does not certify the absence of false positives.", {
        color: COLORS.muted, size: 8.2, spaceAfter: 7,
      });
    }
    acc.quality_observations.forEach((item) => {
      ensure(95);
      text(`${item.reference} | ${label(item.kind)} | Source line: ${item.source_line ?? "unavailable"}`, {
        bold: true, color: COLORS.navy, size: 8.7, spaceAfter: 4,
      });
      text(`Observed: ${item.reason}`, { indent: 10, size: 8.2, spaceAfter: 4 });
      text(`Recommended verification: ${item.recommendation}`, { indent: 10, size: 8.2, spaceAfter: 8 });
    });
    text("LIMITATIONS AND COVERAGE", { bold: true, color: COLORS.blue, size: 9, spaceAfter: 5 });
    acc.limitations.forEach((item) => text(`Limitation: ${item}`, {
      color: COLORS.muted, size: 8, spaceAfter: 5,
    }));
    if (acc.summary.incomplete) {
      text("Coverage is partial. Do not interpret unassessed or omitted evidence as a clean pass.", {
        color: COLORS.muted, size: 8.2, spaceAfter: 7,
      });
    }
  }

'''


def patch_pdf(source: str) -> str:
    if 'section("Correlation accuracy and false-positive triage — Detailed evidence")' in source:
        return source
    return replace_once(source, '  section("Assessment coverage");',
                        PDF_BLOCK + '  section("Assessment coverage");', 'PDF evidence section')


def plan(root: Path) -> dict[Path, bytes]:
    root = root.resolve()
    if not (root / 'package.json').is_file():
        raise ValueError(f'Frontend package.json is missing: {root}')
    changes: dict[Path, bytes] = {}
    for rel, fn in (('src/api/universal.ts', patch_api),
                    ('src/pages/UniversalAnalysis.tsx', patch_dashboard),
                    ('src/utils/normalizedPdf.ts', patch_pdf)):
        dst = root / rel
        if not dst.is_file():
            raise ValueError(f'Install the API-011.0 frontend first: {dst}')
        old = dst.read_text(encoding='utf-8-sig')
        new = fn(old)
        if old != new:
            changes[dst] = new.encode('utf-8')
    for rel in ('src/components/CorrelationAccuracySnippet.tsx',
                'src/components/CorrelationAccuracySnippet.css'):
        src = PACKAGE / rel
        if not src.is_file():
            raise ValueError(f'Missing packaged frontend asset: {src}')
        dst = root / rel
        if not dst.is_file() or dst.read_bytes() != src.read_bytes():
            changes[dst] = src.read_bytes()
    return changes


def install(root: Path) -> list[str]:
    root = root.resolve()
    changes = plan(root)
    for dst, payload in changes.items():
        dst.parent.mkdir(parents=True, exist_ok=True)
        backup = dst.with_name(dst.name + BACKUP)
        if dst.is_file() and not backup.exists():
            shutil.copy2(dst, backup)
        dst.write_bytes(payload)
    return [str(x.relative_to(root)) for x in changes]


if __name__ == '__main__':
    if len(sys.argv) > 2:
        sys.exit('Usage: install_api_011_1_frontend.py [frontend-directory]')
    target = Path(sys.argv[1]) if len(sys.argv) == 2 else Path.cwd() / 'frontend'
    try:
        changes = install(target)
    except (OSError, UnicodeError, ValueError) as error:
        sys.exit(f'ERROR: {error}')
    print('API-011.1 frontend installed:' if changes else 'API-011.1 frontend already installed:')
    for name in changes:
        print('  ' + name)
