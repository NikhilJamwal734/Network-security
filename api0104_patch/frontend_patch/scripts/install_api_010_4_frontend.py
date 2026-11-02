"""Frontend-only API-010.4 installer; does not edit App, sidebar, or theme.

Usage: python api0104_patch/frontend_patch/scripts/install_api_010_4_frontend.py ".\\frontend"
"""
from __future__ import annotations
from pathlib import Path
import shutil
import sys

PACKAGE = Path(__file__).resolve().parents[1]
BACKUP = '.before_api0104.bak'
TS_TYPE = '''
/** Optional API-010.4: source-reference and ordering verification, advisory only. */
export interface CorrelationAssurance {
  version: "1.0";
  platform_id: "cisco_asa" | "fortios" | "snort" | "suricata";
  scope: "correlation_evidence_and_order_advisory";
  status: "limited" | "reviewed_subset";
  summary: {
    pairs_reviewed: number;
    evidence_present: number;
    evidence_unavailable: number;
    ordering_contradictions: number;
    by_status: Record<string, number>;
    truncated: boolean;
  };
  items: Array<{
    correlation_id: string;
    status: string;
    evidence_present: boolean;
    related_line_number: number | null;
    line_number: number | null;
    explanation: string;
    next_action: string;
  }>;
  limitations: string[];
}
'''


def replace_once(source: str, old: str, replacement: str, label: str) -> str:
    if replacement in source:
        return source
    if source.count(old) != 1:
        raise ValueError(f'Unexpected {label} layout: {source.count(old)} anchors; no files changed')
    return source.replace(old, replacement, 1)


def patch_api(source: str) -> str:
    source = replace_once(source, '/api/v1/analyze/rule-correlation',
                          '/api/v1/analyze/correlation-assurance', 'analysis endpoint')
    source = replace_once(source, '  rule_correlation?: RuleCorrelation;',
                          '  rule_correlation?: RuleCorrelation;\n  correlation_assurance?: CorrelationAssurance;',
                          'NormalizedReport correlation field')
    if 'export interface CorrelationAssurance {' not in source:
        source += '\n' + TS_TYPE
    return source


def patch_dashboard(source: str) -> str:
    source = replace_once(source, 'import RuleCorrelationPanel from "../components/RuleCorrelationPanel";',
                          'import RuleCorrelationPanel from "../components/RuleCorrelationPanel";\nimport CorrelationAssurancePanel from "../components/CorrelationAssurancePanel";',
                          'RuleCorrelationPanel import')
    return replace_once(source, '<RuleCorrelationPanel review={report.rule_correlation} />',
                        '<RuleCorrelationPanel review={report.rule_correlation} />\n          <CorrelationAssurancePanel assurance={report.correlation_assurance} />',
                        'Dashboard correlation panel')


def patch_pdf(source: str) -> str:
    if 'section("Correlation evidence and ordering review")' in source:
        return source
    anchor = '  section("Assessment coverage");'
    addition = '''  if (report.correlation_assurance) {
    section("Correlation evidence and ordering review");
    text("Advisory source-reference and ASA ordering checks. This does not confirm effective rule behavior or change security scores.", {
      size: 8.5, color: COLORS.muted, spaceAfter: 7,
    });
    const assurance = report.correlation_assurance;
    text(`Pairs reviewed: ${assurance.summary.pairs_reviewed} | References located: ${assurance.summary.evidence_present} | ASA order contradictions: ${assurance.summary.ordering_contradictions}`, {
      size: 8.5, spaceAfter: 9,
    });
    assurance.items.slice(0, 35).forEach((item) => {
      ensure(60);
      text(`${item.correlation_id}  ${item.status.replace(/_/g, " ")}`, {
        bold: true, size: 9.4, color: COLORS.navy, spaceAfter: 3,
      });
      text(item.explanation, { indent: 10, size: 8.4, spaceAfter: 3 });
      text(`Next check: ${item.next_action}`, { indent: 10, size: 8.4, spaceAfter: 5 });
      text(`Source lines: ${item.related_line_number ?? "unknown"}, ${item.line_number ?? "unknown"} | ${item.evidence_present ? "located" : "not confirmed"}`, {
        indent: 10, size: 8.1, color: COLORS.muted, spaceAfter: 9,
      });
    });
    assurance.limitations.slice(0, 4).forEach((limit) => {
      text(`Scope: ${limit}`, { size: 8, color: COLORS.muted, spaceAfter: 4 });
    });
  }

'''
    return replace_once(source, anchor, addition + anchor, 'professional PDF coverage section')


def plan(frontend: Path) -> dict[Path, bytes]:
    frontend = frontend.resolve()
    if not (frontend / 'package.json').is_file():
        raise ValueError(f'Not a React frontend folder: {frontend}')
    changed = {}
    for rel, transform in (
        ('src/api/universal.ts', patch_api),
        ('src/pages/UniversalAnalysis.tsx', patch_dashboard),
        ('src/utils/normalizedPdf.ts', patch_pdf),
    ):
        file = frontend / rel
        if not file.is_file():
            raise ValueError(f'Missing frontend prerequisite: {file}')
        current = file.read_text(encoding='utf-8-sig')
        update = transform(current)
        if current != update:
            changed[file] = update.encode('utf-8')
    for rel in ('src/components/CorrelationAssurancePanel.tsx', 'src/components/CorrelationAssurancePanel.css'):
        file = frontend / rel
        content = (PACKAGE / rel).read_bytes()
        if not file.is_file() or file.read_bytes() != content:
            changed[file] = content
    return changed


def install(frontend: Path) -> list[str]:
    frontend = frontend.resolve()
    changes = plan(frontend)
    for file, data in changes.items():
        file.parent.mkdir(parents=True, exist_ok=True)
        if file.exists():
            backup = file.with_name(file.name + BACKUP)
            if not backup.exists():
                shutil.copy2(file, backup)
        file.write_bytes(data)
    return [str(file.relative_to(frontend)) for file in changes]


if __name__ == '__main__':
    frontend = Path(sys.argv[1]) if len(sys.argv) == 2 else Path.cwd() / 'frontend'
    try:
        changed = install(frontend)
    except (OSError, ValueError) as error:
        sys.exit(f'ERROR: {error}')
    print('API-010.4 frontend installed:' if changed else 'API-010.4 frontend already installed.')
    for item in changed:
        print('  ' + item)
