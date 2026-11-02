"""Patch API request, ONE dashboard snippet, and full PDF-only IDS evidence."""
from __future__ import annotations
from pathlib import Path
import shutil
import sys

PACKAGE = Path(__file__).resolve().parents[1]
BACKUP = '.before_api0109.bak'
TYPE_DECL = '''
/** Static configuration evidence; never infers effective sensor protection. */
export interface IdsDeepReview {
  version: "1.0";
  platform_id: "cisco_asa" | "fortios" | "snort" | "suricata";
  scope: "bounded_static_ids_configuration_evidence";
  status: "reviewed_subset" | "limited" | "not_applicable";
  summary: {
    rules_inspected: number; duplicate_rule_ids: number; external_references: number;
    outputs_explicitly_enabled: number; outputs_explicitly_disabled: number; outputs_declared: number;
    interfaces_declared: number; evidence_items: number; items_omitted: number;
    incomplete: boolean;
  };
  evidence: Array<{
    reference: string; kind: string; line_number: number; title: string;
    setting: string; observation: string; implication: string;
    recommendation: string; confidence: string;
  }>;
  limitations: string[];
}
'''


def replace_once(source: str, old: str, new: str, label: str) -> str:
    if new in source:
        return source
    if source.count(old) != 1:
        raise ValueError(f'{label}: expected one exact anchor, got {source.count(old)}')
    return source.replace(old, new, 1)


def patch_api(src: str) -> str:
    src = replace_once(src, '/api/v1/analyze/nat-route-reachability',
                       '/api/v1/analyze/ids-configuration', 'API-010.8 endpoint')
    src = replace_once(src, '  nat_route_reachability?: NatRouteReachabilityReview;',
                       '  nat_route_reachability?: NatRouteReachabilityReview;\n  ids_deep_review?: IdsDeepReview;',
                       'API-010.8 normalized report type')
    if 'export interface IdsDeepReview {' not in src:
        src += '\n' + TYPE_DECL
    return src


def patch_dashboard(src: str) -> str:
    src = replace_once(src,
                       'import NatRouteSnippet from "../components/NatRouteSnippet";',
                       'import NatRouteSnippet from "../components/NatRouteSnippet";\n'
                       'import IdsDeepSnippet from "../components/IdsDeepSnippet";',
                       'API-010.8 component import')
    src = replace_once(src, '<NatRouteSnippet review={report.nat_route_reachability} />',
                       '<NatRouteSnippet review={report.nat_route_reachability} />\n'
                       '          <IdsDeepSnippet review={report.ids_deep_review} />',
                       'API-010.8 review component')
    return src


PDF_BLOCK = '''  if (report.ids_deep_review && report.ids_deep_review.status !== "not_applicable") {
    section("Snort and Suricata — Detailed IDS configuration evidence");
    const ids = report.ids_deep_review;
    text("Static advisory inspection of uploaded configuration text only. No rule loading, interface availability, inline enforcement, alert delivery or deployed runtime configuration was verified. Findings/severity/score from earlier stages are unchanged.", {
      size: 8.4, color: COLORS.muted, spaceAfter: 8,
    });
    text(`Platform: ${ids.platform_id} | Status: ${label(ids.status)} | Inspected inline rules: ${ids.summary.rules_inspected} | Repeated GID/SIDs: ${ids.summary.duplicate_rule_ids} | External references: ${ids.summary.external_references} | Suricata outputs enabled (explicit): ${ids.summary.outputs_explicitly_enabled} | Outputs disabled (explicit): ${ids.summary.outputs_explicitly_disabled} | Snort output directives: ${ids.summary.outputs_declared} | Interfaces declared: ${ids.summary.interfaces_declared}`, {
      size: 8.2, spaceAfter: 8,
    });
    if (ids.evidence.length > 0) {
      text("SOURCE CONFIGURATION OBSERVATIONS", { bold: true, color: COLORS.blue, size: 9, spaceAfter: 5 });
      ids.evidence.forEach((item) => {
        ensure(100);
        text(`${item.reference} | ${item.kind.replace(/_/g, " ")} | ${item.title}`, {
          bold: true, color: COLORS.navy, size: 9, spaceAfter: 4,
        });
        text(`Source line: ${item.line_number} | Setting: ${item.setting || "n/a"} | Confidence: ${item.confidence}`, {
          indent: 10, size: 8.1, spaceAfter: 4,
        });
        text(`Observed: ${item.observation}`, { indent: 10, size: 8.3, spaceAfter: 4 });
        text(`Interpretation: ${item.implication}`, { indent: 10, size: 8.3, spaceAfter: 4 });
        text(`Recommendation: ${item.recommendation}`, { indent: 10, size: 8.3, spaceAfter: 9 });
      });
    } else {
      text("No supported observations were emitted; this is not evidence that the deployed sensor is secure, fully configured or actively detecting threats.", {
        size: 8.3, color: COLORS.muted, spaceAfter: 8,
      });
    }
    text("REVIEW SCOPE AND VALIDATION LIMITATIONS", { bold: true, color: COLORS.blue, size: 9, spaceAfter: 5 });
    ids.limitations.forEach((limit) => {
      text(`Limitation: ${limit}`, { size: 8.1, color: COLORS.muted, spaceAfter: 5 });
    });
    if (ids.summary.incomplete) {
      text(`Partial coverage: ${ids.summary.items_omitted} items were omitted or not assessed. A missing observation does not prove a correct or safe sensor configuration.`, {
        size: 8.3, color: COLORS.muted, spaceAfter: 6,
      });
    }
  }

'''


def patch_pdf(src: str) -> str:
    if 'section("Snort and Suricata — Detailed IDS configuration evidence")' in src:
        return src
    return replace_once(src, '  section("Assessment coverage");',
                        PDF_BLOCK + '  section("Assessment coverage");',
                        'PDF assessment coverage section')


def plan(frontend: Path) -> dict[Path, bytes]:
    root = frontend.resolve()
    if not (root / 'package.json').is_file():
        raise ValueError(f'Frontend package.json missing: {root}')
    updates: dict[Path, bytes] = {}
    for rel, patch in [('src/api/universal.ts', patch_api),
                       ('src/pages/UniversalAnalysis.tsx', patch_dashboard),
                       ('src/utils/normalizedPdf.ts', patch_pdf)]:
        dst = root / rel
        if not dst.is_file():
            raise ValueError(f'API-010.8 frontend prerequisite missing: {dst}')
        old = dst.read_text(encoding='utf-8-sig')
        new = patch(old)
        if old != new:
            updates[dst] = new.encode('utf-8')
    for rel in ('src/components/IdsDeepSnippet.tsx', 'src/components/IdsDeepSnippet.css'):
        source = PACKAGE / rel
        if not source.is_file():
            raise ValueError(f'Patch asset missing: {source}')
        dst = root / rel
        data = source.read_bytes()
        if not dst.is_file() or dst.read_bytes() != data:
            updates[dst] = data
    return updates


def install(frontend: Path) -> list[str]:
    root = frontend.resolve()
    updates = plan(root)
    for dst, data in updates.items():
        dst.parent.mkdir(parents=True, exist_ok=True)
        if dst.exists():
            bak = dst.with_name(dst.name + BACKUP)
            if not bak.exists():
                shutil.copy2(dst, bak)
        dst.write_bytes(data)
    return [str(f.relative_to(root)) for f in updates]


if __name__ == '__main__':
    if len(sys.argv) > 2:
        sys.exit('Usage: install_api_010_9_frontend.py [frontend-dir]')
    root = Path(sys.argv[1]) if len(sys.argv) == 2 else Path.cwd() / 'frontend'
    try:
        paths = install(root)
    except (OSError, UnicodeError, ValueError) as err:
        sys.exit(f'ERROR: {err}')
    print('API-010.9 frontend installed:' if paths else 'API-010.9 frontend already installed:')
    for p in paths:
        print('  ' + p)
