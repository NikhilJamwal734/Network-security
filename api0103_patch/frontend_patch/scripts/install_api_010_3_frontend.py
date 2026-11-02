"""Wire API-010.3 into the unified dashboard and professional PDF only.

No sidebar, theme, navigation, backend scoring, or JSON download changes.
Usage from backend root:
  .\\.venv-win\\Scripts\\python.exe .\\api0103_patch\\frontend_patch\\scripts\\install_api_010_3_frontend.py ".\\frontend"
"""
from __future__ import annotations
from pathlib import Path
import shutil
import sys

PACKAGE = Path(__file__).resolve().parents[1]
BACKUP = '.before_api0103.bak'

INTERFACE = '''
/** Opt-in, advisory correlation; outside normalized security score. */
export interface RuleCorrelation {
  version: "1.0";
  platform_id: "cisco_asa" | "fortios" | "snort" | "suricata";
  scope: "static_rule_correlation_advisory";
  status: "limited" | "reviewed_subset";
  summary: {
    eligible_rules: number;
    relevant_rules_seen: number;
    rules_not_correlated: number;
    candidate_pairs: number;
    by_kind: Record<string, number>;
    truncated: boolean;
  };
  pairs: Array<{
    correlation_id: string;
    kind: string;
    confidence: "conditional" | "informational";
    title: string;
    detail: string;
    recommendation: string;
    scope: string;
    evidence: {
      line_number: number;
      related_line_number: number;
      rule_id: string;
      related_rule_id: string;
    };
  }>;
  limitations: string[];
}
'''


def _replace_exact(text: str, old: str, new: str, name: str) -> str:
    if new in text:
        return text
    if text.count(old) != 1:
        raise ValueError(f'Unknown {name} layout: {text.count(old)} matching anchors; no changes made')
    return text.replace(old, new, 1)


def patch_api(text: str) -> str:
    text = _replace_exact(text, '/api/v1/analyze/precision-review',
                          '/api/v1/analyze/rule-correlation', 'API-010.2 request URL')
    text = _replace_exact(text, 'export interface NormalizedReport {',
                          'export interface NormalizedReport {\n  rule_correlation?: RuleCorrelation;',
                          'NormalizedReport interface')
    if 'export interface RuleCorrelation {' not in text:
        text += '\n' + INTERFACE
    return text


def patch_dashboard(text: str) -> str:
    import_line = 'import RuleCorrelationPanel from "../components/RuleCorrelationPanel";'
    element = '<RuleCorrelationPanel review={report.rule_correlation} />'
    if (import_line in text) != (element in text):
        raise ValueError('Partially installed rule correlation panel; no changes made')
    if element in text:
        return text
    text = _replace_exact(text, 'import "./UniversalAnalysis.css";',
                          import_line + '\nimport "./UniversalAnalysis.css";',
                          'Dashboard stylesheet import')
    anchor = '<VendorDeepReviewPanel review={report.vendor_review} />'
    return _replace_exact(text, anchor, anchor + '\n          ' + element,
                          'Dashboard vendor-review panel')


def patch_pdf(text: str) -> str:
    if 'section("Rule correlation and conflict review")' in text:
        return text
    anchor = '  section("Assessment coverage");'
    addition = '''  if (report.rule_correlation) {
    section("Rule correlation and conflict review");
    text("Advisory correlation of supported rule selectors and headers. These candidates do not alter findings, severity totals, or scores.", {
      size: 8.5, color: COLORS.muted, spaceAfter: 7,
    });
    text(`Rules compared: ${report.rule_correlation.summary.eligible_rules} | Candidate pairs: ${report.rule_correlation.summary.candidate_pairs} | Unassessed: ${report.rule_correlation.summary.rules_not_correlated}`, {
      size: 8.5, spaceAfter: 8,
    });
    report.rule_correlation.pairs.slice(0, 40).forEach((item) => {
      ensure(68);
      text(`${item.correlation_id}  ${item.title}  [${item.kind}]`, {
        bold: true, size: 9.6, color: COLORS.navy, spaceAfter: 3,
      });
      text(item.detail, { indent: 10, size: 8.5, spaceAfter: 5 });
      text(`Review action: ${item.recommendation}`, { indent: 10, size: 8.5, spaceAfter: 4 });
      text(`Source lines: ${item.evidence.related_line_number}, ${item.evidence.line_number} | References: ${item.evidence.related_rule_id}, ${item.evidence.rule_id} | ${item.confidence}`, {
        indent: 10, size: 8, color: COLORS.muted, spaceAfter: 11,
      });
    });
    report.rule_correlation.limitations.slice(0, 5).forEach((limit) => {
      text(`Scope: ${limit}`, { size: 8.1, color: COLORS.muted, spaceAfter: 5 });
    });
  }

'''
    return _replace_exact(text, anchor, addition + anchor, 'professional PDF assessment coverage section')


def plan(frontend: Path) -> dict[Path, bytes]:
    frontend = frontend.resolve()
    if not (frontend / 'package.json').is_file():
        raise ValueError(f'No frontend package.json: {frontend}')
    changes = {}
    for rel, transform in [
        ('src/api/universal.ts', patch_api),
        ('src/pages/UniversalAnalysis.tsx', patch_dashboard),
        ('src/utils/normalizedPdf.ts', patch_pdf),
    ]:
        target = frontend / rel
        if not target.is_file():
            raise ValueError(f'Required frontend file missing: {rel}')
        original = target.read_text(encoding='utf-8-sig')
        update = transform(original)
        if original != update:
            changes[target] = update.encode('utf-8')
    for rel in ('src/components/RuleCorrelationPanel.tsx',
                'src/components/RuleCorrelationPanel.css'):
        source, target = PACKAGE / rel, frontend / rel
        data = source.read_bytes()
        if not target.is_file() or target.read_bytes() != data:
            changes[target] = data
    return changes


def install(frontend: Path) -> list[str]:
    frontend = frontend.resolve()
    changes = plan(frontend)
    for path, data in changes.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.is_file():
            backup = path.with_name(path.name + BACKUP)
            if not backup.exists():
                shutil.copy2(path, backup)
        path.write_bytes(data)
    return [str(x.relative_to(frontend)) for x in changes]


if __name__ == '__main__':
    frontend = Path(sys.argv[1]) if len(sys.argv) == 2 else Path.cwd() / 'frontend'
    try:
        changed = install(frontend)
    except (ValueError, OSError) as error:
        sys.exit('ERROR: ' + str(error))
    print('API-010.3 frontend installed:' if changed else 'API-010.3 frontend already installed.')
    for item in changed:
        print('  ' + item)
