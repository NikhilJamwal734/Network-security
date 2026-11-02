"""API-010.5 React+PDF installer, preserving existing styling and previous endpoints.

Run from project root with explicit frontend path:
  python api0105_patch/frontend_patch/scripts/install_api_010_5_frontend.py ".\\frontend"
"""
from __future__ import annotations
from pathlib import Path
import shutil
import sys

PACKAGE = Path(__file__).resolve().parents[1]
BACKUP_SUFFIX = '.before_api0105.bak'

TYPE_DECL = '''
/** Advisory object expansion for supported ASA/FortiOS IPv4 selectors. */
export interface ObjectResolution {
  version: "1.0";
  platform_id: "cisco_asa" | "fortios" | "snort" | "suricata";
  scope: "bounded_static_ipv4_object_resolution";
  status: "limited" | "reviewed_subset" | "not_assessed";
  summary: {
    definitions_seen: number;
    definitions_resolved: number;
    definitions_unresolved: number;
    rules_seen: number;
    rules_with_resolved_selectors: number;
    rules_not_resolved: number;
    candidate_pairs: number;
    truncated: boolean;
  };
  objects: Array<{
    name: string;
    kind: string;
    line_number: number;
    status: "resolved" | "unresolved";
    reason: string;
    value: string | null;
  }>;
  pairs: Array<{
    correlation_id: string;
    kind: string;
    confidence: string;
    order_status: string;
    explanation: string;
    recommendation: string;
    evidence: {
      related_line_number: number;
      line_number: number;
      related_rule_id: string;
      rule_id: string;
    };
    resolved_object_references: string[];
  }>;
  limitations: string[];
}
'''


def replace_once(source: str, old: str, new: str, label: str) -> str:
    if new in source:
        return source
    if source.count(old) != 1:
        raise ValueError(f'Unexpected {label}: expected one existing anchor, got {source.count(old)}')
    return source.replace(old, new, 1)


def patch_api(source: str) -> str:
    source = replace_once(source, '/api/v1/analyze/correlation-assurance',
                          '/api/v1/analyze/object-resolution', 'API endpoint')
    source = replace_once(source, '  correlation_assurance?: CorrelationAssurance;',
                          '  correlation_assurance?: CorrelationAssurance;\n  object_resolution?: ObjectResolution;',
                          'normalized report field')
    if 'export interface ObjectResolution {' not in source:
        source += '\n' + TYPE_DECL
    return source


def patch_dashboard(source: str) -> str:
    source = replace_once(source, 'import CorrelationAssurancePanel from "../components/CorrelationAssurancePanel";',
                          'import CorrelationAssurancePanel from "../components/CorrelationAssurancePanel";\nimport ObjectResolutionPanel from "../components/ObjectResolutionPanel";',
                          'dashboard import')
    return replace_once(source, '<CorrelationAssurancePanel assurance={report.correlation_assurance} />',
                        '<CorrelationAssurancePanel assurance={report.correlation_assurance} />\n          <ObjectResolutionPanel analysis={report.object_resolution} />',
                        'dashboard panel')


def patch_pdf(source: str) -> str:
    if 'section("Network object resolution and policy selectors")' in source:
        return source
    anchor = '  section("Assessment coverage");'
    block = '''  if (report.object_resolution) {
    section("Network object resolution and policy selectors");
    text("Limited IPv4 object expansion, not verified effective policy. Results are supplemental and do not affect existing findings or scores.", {
      size: 8.5, color: COLORS.muted, spaceAfter: 7,
    });
    const resolved = report.object_resolution;
    text(`Objects resolved: ${resolved.summary.definitions_resolved} | Unresolved: ${resolved.summary.definitions_unresolved} | Rules parsed: ${resolved.summary.rules_with_resolved_selectors} | Correlation candidates: ${resolved.summary.candidate_pairs}`, {
      size: 8.7, spaceAfter: 8,
    });
    resolved.pairs.slice(0, 30).forEach((pair) => {
      ensure(65);
      text(`${pair.correlation_id}  ${pair.kind.replace(/_/g, " ")}`, {
        bold: true, size: 9.4, color: COLORS.navy, spaceAfter: 4,
      });
      text(pair.explanation, { indent: 10, size: 8.3, spaceAfter: 4 });
      text(`Source lines: ${pair.evidence.related_line_number}, ${pair.evidence.line_number} | ${pair.order_status.replace(/_/g, " ")}`, {
        indent: 10, size: 8.1, color: COLORS.muted, spaceAfter: 4,
      });
      text(`Objects: ${pair.resolved_object_references.join(", ") || "none"}`, {
        indent: 10, size: 8.1, spaceAfter: 4,
      });
      text(`Review: ${pair.recommendation}`, { indent: 10, size: 8.3, spaceAfter: 9 });
    });
    resolved.limitations.slice(0, 4).forEach((limit) => {
      text(`Scope: ${limit}`, { size: 8, color: COLORS.muted, spaceAfter: 4 });
    });
    if (resolved.summary.truncated) {
      text("Object resolution was truncated; the assessment is incomplete.", {
        size: 8.5, color: COLORS.muted, spaceAfter: 5,
      });
    }
  }

'''
    return replace_once(source, anchor, block + anchor, 'professional PDF coverage heading')


def plan(frontend: Path) -> dict[Path, bytes]:
    frontend = frontend.resolve()
    if not (frontend / 'package.json').is_file():
        raise ValueError(f'Expected the frontend directory, not project root: {frontend}')
    changed: dict[Path, bytes] = {}
    for rel, transform in (
        ('src/api/universal.ts', patch_api),
        ('src/pages/UniversalAnalysis.tsx', patch_dashboard),
        ('src/utils/normalizedPdf.ts', patch_pdf),
    ):
        target = frontend / rel
        if not target.is_file(): raise ValueError(f'Frontend prerequisite missing: {target}')
        before = target.read_text(encoding='utf-8-sig')
        after = transform(before)
        if before != after: changed[target] = after.encode('utf-8')
    for rel in ('src/components/ObjectResolutionPanel.tsx', 'src/components/ObjectResolutionPanel.css'):
        source = PACKAGE / rel
        if not source.is_file(): raise ValueError(f'Installer package incomplete: {source}')
        target = frontend / rel
        data = source.read_bytes()
        if not target.is_file() or target.read_bytes() != data: changed[target] = data
    return changed


def install(frontend: Path) -> list[str]:
    frontend = frontend.resolve()
    changes = plan(frontend)
    for target, data in changes.items():
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.is_file():
            backup = target.with_name(target.name + BACKUP_SUFFIX)
            if not backup.exists(): shutil.copy2(target, backup)
        target.write_bytes(data)
    return [str(path.relative_to(frontend)) for path in changes]


if __name__ == '__main__':
    frontend = Path(sys.argv[1]) if len(sys.argv) == 2 else Path.cwd() / 'frontend'
    try:
        changed = install(frontend)
    except (OSError, ValueError) as exc:
        sys.exit(f'ERROR: {exc}')
    print('API-010.5 frontend installed:' if changed else 'API-010.5 frontend already installed.')
    for path in changed: print('  ' + path)
