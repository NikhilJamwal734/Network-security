"""Install the 10.7 endpoint, Dashboard snippets, and detailed PDF section.

From project root: python api0107_patch/frontend_patch/scripts/install_api_010_7_frontend.py ".\\frontend"
"""
from __future__ import annotations
from pathlib import Path
import shutil
import sys

PACKAGE = Path(__file__).resolve().parents[1]
BACKUP = '.before_api0107.bak'

TYPE_DECL = '''
/** Supplemental, bounded static resolution of supported IPv6 and TCP/UDP service groups. */
export interface ServiceIPv6Review {
  version: "1.0";
  platform_id: "cisco_asa" | "fortios" | "snort" | "suricata";
  scope: "static_bounded_service_group_ipv6_evidence";
  status: "reviewed_subset" | "limited" | "not_assessed";
  summary: {
    definitions_seen: number;
    definitions_resolved: number;
    definitions_unresolved: number;
    rules_seen: number;
    rules_eligible: number;
    rules_not_assessed: number;
    correlation_candidates: number;
    candidates_omitted: number;
    incomplete: boolean;
  };
  objects: Array<{
    kind: string; name: string; line_number: number;
    status: "resolved" | "unresolved"; value: string | null; reason: string;
  }>;
  pairs: Array<{
    reference: string; kind: string; confidence: string; ip_version: number;
    related_rule_id: string; rule_id: string;
    related_line_number: number; line_number: number;
    resolved_objects: string[]; order_status: string;
    explanation: string; recommendation: string;
  }>;
  limitations: string[];
}
'''


def replace(source: str, old: str, new: str, label: str) -> str:
    if new in source:
        return source
    if source.count(old) != 1:
        raise ValueError(f'{label}: expected one anchor, found {source.count(old)}')
    return source.replace(old, new, 1)


def patch_api(source: str) -> str:
    source = replace(source, '/api/v1/analyze/object-assurance',
                     '/api/v1/analyze/service-ipv6', 'analysis endpoint')
    source = replace(source, '  object_assurance?: ObjectAssurance;',
                     '  object_assurance?: ObjectAssurance;\n  service_ipv6?: ServiceIPv6Review;',
                     'optional normalized report field')
    if 'export interface ServiceIPv6Review {' not in source:
        source += '\n' + TYPE_DECL
    return source


def patch_dashboard(source: str) -> str:
    if 'import ServiceIPv6Snippet from' not in source:
        source = replace(source,
                         'import ObjectAssurancePanel from "../components/ObjectAssurancePanel";',
                         'import ServiceIPv6Snippet from "../components/ServiceIPv6Snippet";\n'
                         'import { CompactObjectResolution, CompactObjectAssurance } from "../components/CompactObjectReviews";',
                         'dashboard component imports')
        # Old full-detail imports are removed only when rendering is replaced.
        if 'import ObjectResolutionPanel from "../components/ObjectResolutionPanel";' not in source:
            raise ValueError('Network object review import missing; refusing uncertain Dashboard layout')
        source = source.replace('import ObjectResolutionPanel from "../components/ObjectResolutionPanel";\n', '', 1)
    source = replace(source, '<ObjectResolutionPanel analysis={report.object_resolution} />',
                     '<CompactObjectResolution analysis={report.object_resolution} />',
                     'summary-only object resolution')
    source = replace(source, '<ObjectAssurancePanel review={report.object_assurance} />',
                     '<CompactObjectAssurance review={report.object_assurance} />\n'
                     '          <ServiceIPv6Snippet review={report.service_ipv6} />',
                     'summary-only integrity and new service review')
    return source


PDF_SECTION = '''  if (report.service_ipv6) {
    section("Service groups and IPv6 — Detailed technical evidence");
    const sg6 = report.service_ipv6;
    text("Upload-only, supported-subset static analysis. The observations below are advisory and do not change the normalized security findings or scores.", {
      size: 8.5, color: COLORS.muted, spaceAfter: 8,
    });
    text(`Status: ${label(sg6.status)} | Objects resolved: ${sg6.summary.definitions_resolved} | Objects unresolved: ${sg6.summary.definitions_unresolved} | Eligible rules: ${sg6.summary.rules_eligible} | Candidate pairs: ${sg6.summary.correlation_candidates}`, {
      size: 8.6, spaceAfter: 8,
    });
    text("Interpretation: A correlation candidate means supported explicit network and TCP/UDP destination-port selectors overlap within the compared policy context. It does not establish effective policy order, NAT reachability, or deployed device behavior.", {
      size: 8.5, spaceAfter: 9,
    });
    if (sg6.objects.length > 0) {
      text("OBJECT DEFINITIONS — REVIEW INVENTORY", { bold: true, color: COLORS.blue, size: 9, spaceAfter: 5 });
      sg6.objects.forEach((item) => {
        text(`${item.kind.replace(/_/g, " ")} | ${item.name} | line ${item.line_number} | ${item.status}`, {
          bold: true, size: 8.3, spaceAfter: 2,
        });
        text(item.value ?? `Unresolved: ${item.reason}`, { indent: 10, size: 8.2, color: COLORS.muted, spaceAfter: 5 });
      });
      if (sg6.summary.definitions_seen > sg6.objects.length) {
        text(`${sg6.summary.definitions_seen - sg6.objects.length} additional definitions excluded by PDF inventory limit. The report is incomplete.`, {
          size: 8.3, color: COLORS.muted, spaceAfter: 6,
        });
      }
    }
    if (sg6.pairs.length > 0) {
      text("POLICY CORRELATION EVIDENCE", { bold: true, color: COLORS.blue, size: 9, spaceAfter: 5 });
      sg6.pairs.forEach((pair) => {
        ensure(66);
        text(`${pair.reference} | ${pair.kind.replace(/_/g, " ")} | IPv${pair.ip_version}`, {
          bold: true, size: 9.1, color: COLORS.navy, spaceAfter: 4,
        });
        text(`Rules: ${pair.related_rule_id} (line ${pair.related_line_number}) and ${pair.rule_id} (line ${pair.line_number})`, {
          indent: 10, size: 8.4, spaceAfter: 4,
        });
        text(`Objects: ${pair.resolved_objects.join(", ") || "literal selectors only"} | Order: ${pair.order_status.replace(/_/g, " ")}`, {
          indent: 10, size: 8.2, spaceAfter: 4,
        });
        text(pair.explanation, { indent: 10, size: 8.3, spaceAfter: 4 });
        text(`Recommendation: ${pair.recommendation}`, { indent: 10, size: 8.3, spaceAfter: 9 });
      });
    } else {
      text("No correlation candidates established within this explicitly supported subset; this is not proof that no conflicts exist.", {
        size: 8.4, color: COLORS.muted, spaceAfter: 8,
      });
    }
    sg6.limitations.forEach((limit) => {
      text(`Assessment limitation: ${limit}`, { size: 8.1, color: COLORS.muted, spaceAfter: 4 });
    });
    if (sg6.summary.incomplete || sg6.summary.candidates_omitted) {
      text(`Incomplete analysis: ${sg6.summary.candidates_omitted} candidate pairs omitted by output limits; unsupported or truncated source may not have been assessed.`, {
        size: 8.3, color: COLORS.muted, spaceAfter: 6,
      });
    }
  }

'''


def patch_pdf(source: str) -> str:
    if 'section("Service groups and IPv6 — Detailed technical evidence")' not in source:
        source = replace(source, '  section("Assessment coverage");',
                         PDF_SECTION + '  section("Assessment coverage");',
                         'professional PDF coverage anchor')
    source = source.replace('consult the dashboard for the available bounded list.',
                            'review the source configuration for any observations excluded by output limits.')
    source = source.replace('[shortened in PDF; full value in JSON]',
                            '[shortened in PDF; consult the source configuration]')
    return source


def plan(frontend: Path) -> dict[Path, bytes]:
    frontend = frontend.resolve()
    if not (frontend / 'package.json').is_file():
        raise ValueError(f'Expected React frontend directory containing package.json: {frontend}')
    updates: dict[Path, bytes] = {}
    for rel, fn in (('src/api/universal.ts', patch_api),
                    ('src/pages/UniversalAnalysis.tsx', patch_dashboard),
                    ('src/utils/normalizedPdf.ts', patch_pdf)):
        target = frontend / rel
        if not target.is_file():
            raise ValueError(f'Missing API-010.6 frontend prerequisite: {target}')
        original = target.read_text(encoding='utf-8-sig')
        modified = fn(original)
        if modified != original:
            updates[target] = modified.encode('utf-8')
    for rel in ('src/components/ServiceIPv6Snippet.tsx', 'src/components/ServiceIPv6Snippet.css',
                'src/components/CompactObjectReviews.tsx'):
        src = PACKAGE / rel
        if not src.is_file():
            raise ValueError(f'Incomplete API-010.7 package: {src}')
        dest = frontend / rel
        data = src.read_bytes()
        if not dest.is_file() or dest.read_bytes() != data:
            updates[dest] = data
    return updates


def install(frontend: Path) -> list[str]:
    frontend = frontend.resolve()
    updates = plan(frontend)  # fail before writes on unsupported layout
    for target, data in updates.items():
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists():
            backup = target.with_name(target.name + BACKUP)
            if not backup.exists():
                shutil.copy2(target, backup)
        target.write_bytes(data)
    return [str(p.relative_to(frontend)) for p in updates]


if __name__ == '__main__':
    if len(sys.argv) > 2:
        sys.exit('Usage: install_api_010_7_frontend.py [frontend-directory]')
    frontend = Path(sys.argv[1]) if len(sys.argv) == 2 else Path.cwd() / 'frontend'
    try:
        updated = install(frontend)
    except (OSError, ValueError, UnicodeError) as error:
        sys.exit(f'ERROR: {error}')
    print('API-010.7 frontend installed:' if updated else 'API-010.7 frontend already installed:')
    for item in updated:
        print('  ' + item)
    print('Unchanged: sidebar, existing four compact review panels, prior scores and normalized findings.')
