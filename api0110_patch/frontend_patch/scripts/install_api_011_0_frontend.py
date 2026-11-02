"""PDF-first API-011.0 frontend change, preserving all earlier review cards."""
from __future__ import annotations
from pathlib import Path
import shutil
import sys

PACKAGE = Path(__file__).resolve().parents[1]
BACKUP = '.before_api0110.bak'

TYPES = '''
/** Advisory consolidation of one normalized upload: no findings or score changes. */
export interface ConsolidationReview {
  version: "1.0";
  platform_id: "cisco_asa" | "fortios" | "snort" | "suricata";
  scope: "cross_review_evidence_consistency_single_upload";
  status: "reviewed_subset" | "limited";
  summary: {
    sections_present: number; sections_unavailable: number;
    advisory_items_examined: number; candidate_links: number;
    quality_observations: number; limited_sections: number;
    items_omitted: number; incomplete: boolean;
  };
  sections: Array<{
    name: string; availability: string; status: string;
    items_examined: number; items_omitted: number; applicable: boolean;
  }>;
  issues: Array<{
    reference: string; kind: string; section: string;
    source_line: number | null; observation: string;
    recommendation: string; confidence: string;
  }>;
  links: Array<{
    reference: string; kind: string; source_line: number;
    signal: string; title: string;
    related: Array<{section: string; locator: string; reference: string; source_line: number}>;
    reason: string; recommendation: string; confidence: string;
  }>;
  limitations: string[];
}
'''


def replace(source: str, old: str, new: str, label: str) -> str:
    if new in source:
        return source
    if source.count(old) != 1:
        raise ValueError(f'{label}: expected one API-010.9 anchor, found {source.count(old)}')
    return source.replace(old, new, 1)


def patch_api(source: str) -> str:
    source = replace(source, '/api/v1/analyze/ids-configuration',
                     '/api/v1/analyze/consolidated', 'analysis URL')
    source = replace(source, '  ids_deep_review?: IdsDeepReview;',
                     '  ids_deep_review?: IdsDeepReview;\n  consolidation_review?: ConsolidationReview;',
                     'normalized response field')
    if 'export interface ConsolidationReview {' not in source:
        source += '\n' + TYPES
    return source


def patch_dashboard(source: str) -> str:
    source = replace(source, 'import IdsDeepSnippet from "../components/IdsDeepSnippet";',
                     'import IdsDeepSnippet from "../components/IdsDeepSnippet";\n'
                     'import ConsolidationSnippet from "../components/ConsolidationSnippet";',
                     'dashboard import')
    return replace(source, '<IdsDeepSnippet review={report.ids_deep_review} />',
                   '<IdsDeepSnippet review={report.ids_deep_review} />\n'
                   '          <ConsolidationSnippet review={report.consolidation_review} />',
                   'dashboard placement')

PDF_BLOCK = '''  if (report.consolidation_review) {
    section("Cross-platform review consolidation — Evidence quality and provenance");
    const con = report.consolidation_review;
    text("This assessment consolidates advisory evidence across review stages for ONE uploaded configuration. It does not compare separate devices or prove effective firewall/IDS behavior. No earlier findings, severity ratings, scores or recommendations were removed or changed.", {
      size: 8.4, color: COLORS.muted, spaceAfter: 8,
    });
    text(`Platform: ${con.platform_id} | Status: ${label(con.status)} | Review sections: ${con.summary.sections_present} | Advisory items inspected: ${con.summary.advisory_items_examined} | Candidate cross-review links: ${con.summary.candidate_links} | Metadata observations: ${con.summary.quality_observations}`, {
      size: 8.4, spaceAfter: 8,
    });
    text("REVIEW COVERAGE INVENTORY", { bold: true, color: COLORS.blue, size: 9, spaceAfter: 5 });
    con.sections.forEach((entry) => {
      text(`${entry.name.replace(/_/g, " ")} | ${entry.availability} | ${entry.status} | Items: ${entry.items_examined} | Omitted: ${entry.items_omitted} | Applicable: ${entry.applicable ? "yes" : "no"}`, {
        size: 8.1, spaceAfter: 4,
      });
    });
    if (con.issues.length > 0) {
      text("EVIDENCE QUALITY OBSERVATIONS", { bold: true, color: COLORS.blue, size: 9, spaceAfter: 5 });
      con.issues.forEach((item) => {
        ensure(88);
        text(`${item.reference} | ${item.kind.replace(/_/g, " ")} | ${item.section}`, {
          bold: true, color: COLORS.navy, size: 8.8, spaceAfter: 4,
        });
        text(`Source line: ${item.source_line ?? "unavailable"} | Confidence: ${item.confidence}`, {
          indent: 10, size: 8, spaceAfter: 4,
        });
        text(`Observed: ${item.observation}`, { indent: 10, size: 8.2, spaceAfter: 4 });
        text(`Recommended verification: ${item.recommendation}`, { indent: 10, size: 8.2, spaceAfter: 7 });
      });
    } else {
      text("No metadata inconsistencies were identified within the supported bounded review subset; this does NOT certify completeness or security.", {
        color: COLORS.muted, size: 8.2, spaceAfter: 7,
      });
    }
    if (con.links.length > 0) {
      text("POTENTIALLY RELATED ADVISORY SIGNALS — NOT VERIFIED DUPLICATES", {
        bold: true, color: COLORS.blue, size: 9, spaceAfter: 5,
      });
      con.links.forEach((link) => {
        ensure(88);
        text(`${link.reference} | Source line ${link.source_line} | Signal: ${link.signal} | ${link.title}`, {
          bold: true, size: 8.4, spaceAfter: 4,
        });
        link.related.forEach((ref) => {
          text(`Related: ${ref.section} | ${ref.reference || ref.locator} | line ${ref.source_line}`, {
            indent: 10, size: 8.1, spaceAfter: 3,
          });
        });
        text(`Basis: ${link.reason}`, { indent: 10, size: 8.2, spaceAfter: 4 });
        text(`Recommendation: ${link.recommendation}`, { indent: 10, size: 8.2, spaceAfter: 8 });
      });
    }
    text("SCOPE, INCOMPLETENESS AND SAFETY LIMITS", {
      bold: true, color: COLORS.blue, size: 9, spaceAfter: 5,
    });
    con.limitations.forEach((item) => text(`Limitation: ${item}`, {
      color: COLORS.muted, size: 8, spaceAfter: 5,
    }));
    if (con.summary.incomplete) {
      text(`Incomplete review: ${con.summary.items_omitted} item(s) explicitly omitted by bounded scanning or upstream review metadata; this is not a completeness certification.`, {
        size: 8.2, color: COLORS.muted, spaceAfter: 7,
      });
    }
  }

'''


def patch_pdf(source: str) -> str:
    if 'section("Cross-platform review consolidation — Evidence quality and provenance")' in source:
        return source
    return replace(source, '  section("Assessment coverage");',
                   PDF_BLOCK + '  section("Assessment coverage");',
                   'PDF assessment section')


def plan(frontend: Path) -> dict[Path, bytes]:
    frontend = frontend.resolve()
    if not (frontend / 'package.json').is_file():
        raise ValueError('Frontend package.json is missing')
    changes: dict[Path, bytes] = {}
    for rel, patch in [('src/api/universal.ts', patch_api),
                       ('src/pages/UniversalAnalysis.tsx', patch_dashboard),
                       ('src/utils/normalizedPdf.ts', patch_pdf)]:
        dst = frontend / rel
        if not dst.is_file():
            raise ValueError(f'API-010.9 frontend prerequisite missing: {dst}')
        old = dst.read_text(encoding='utf-8-sig')
        new = patch(old)
        if new != old:
            changes[dst] = new.encode('utf-8')
    for rel in ('src/components/ConsolidationSnippet.tsx', 'src/components/ConsolidationSnippet.css'):
        src = PACKAGE / rel
        if not src.is_file():
            raise ValueError(f'Packaged frontend asset missing: {src}')
        dst = frontend / rel
        if not dst.is_file() or dst.read_bytes() != src.read_bytes():
            changes[dst] = src.read_bytes()
    return changes


def install(frontend: Path) -> list[str]:
    root = frontend.resolve()
    changes = plan(root)
    for dst, data in changes.items():
        dst.parent.mkdir(parents=True, exist_ok=True)
        bak = dst.with_name(dst.name + BACKUP)
        if dst.exists() and not bak.exists():
            shutil.copy2(dst, bak)
        dst.write_bytes(data)
    return [str(p.relative_to(root)) for p in changes]


if __name__ == '__main__':
    if len(sys.argv) > 2:
        sys.exit('Usage: install_api_011_0_frontend.py [frontend-directory]')
    root = Path(sys.argv[1]) if len(sys.argv) == 2 else Path.cwd() / 'frontend'
    try:
        changes = install(root)
    except (OSError, UnicodeError, ValueError) as error:
        sys.exit(f'ERROR: {error}')
    print('API-011.0 frontend installed:' if changes else 'API-011.0 frontend already installed:')
    for change in changes:
        print('  ' + change)
