"""Fail-safe API-010.8 frontend/API/PDF installer. Root is frontend/ directory."""
from __future__ import annotations
from pathlib import Path
import shutil
import sys

PACKAGE = Path(__file__).resolve().parents[1]
BACKUP = '.before_api0108.bak'

TYPE_DECL = '''
/** Conservative upload-only NAT/static-routing evidence; not effective traffic reachability. */
export interface NatRouteReachabilityReview {
  version: "1.0";
  platform_id: "cisco_asa" | "fortios" | "snort" | "suricata";
  scope: "static_bounded_nat_route_reachability_evidence";
  status: "reviewed_subset" | "limited" | "not_assessed";
  summary: {
    routes_seen: number; routes_resolved: number; routes_unresolved: number;
    nat_seen: number; nat_resolved: number; nat_unresolved: number;
    policies_seen: number; policies_eligible: number;
    evidence_items: number; items_omitted: number; incomplete: boolean;
  };
  evidence: Array<{
    reference: string; kind: string; line_number: number;
    policy_id: string | null; route_line_number: number | null;
    title: string; destination: string | null;
    ingress_interface: string | null; egress_interface: string | null;
    mapped_destination: string | null; confidence: string;
    explanation: string; recommendation: string;
  }>;
  limitations: string[];
}
'''


def replace_once(source: str, old: str, new: str, label: str) -> str:
    if new in source:
        return source
    if source.count(old) != 1:
        raise ValueError(f'{label}: expected exactly one anchor, got {source.count(old)}')
    return source.replace(old, new, 1)


def patch_api(src: str) -> str:
    src = replace_once(src, '/api/v1/analyze/service-ipv6',
                       '/api/v1/analyze/nat-route-reachability', 'API-010.7 endpoint')
    src = replace_once(src, '  service_ipv6?: ServiceIPv6Review;',
                       '  service_ipv6?: ServiceIPv6Review;\n  nat_route_reachability?: NatRouteReachabilityReview;',
                       'normalized report type')
    if 'export interface NatRouteReachabilityReview {' not in src:
        src += '\n' + TYPE_DECL
    return src


def patch_dashboard(src: str) -> str:
    src = replace_once(src,
                       'import ServiceIPv6Snippet from "../components/ServiceIPv6Snippet";',
                       'import ServiceIPv6Snippet from "../components/ServiceIPv6Snippet";\n'
                       'import NatRouteSnippet from "../components/NatRouteSnippet";',
                       'API-010.7 component import')
    src = replace_once(src, '<ServiceIPv6Snippet review={report.service_ipv6} />',
                       '<ServiceIPv6Snippet review={report.service_ipv6} />\n'
                       '          <NatRouteSnippet review={report.nat_route_reachability} />',
                       'API-010.7 Dashboard snippet')
    return src

PDF_BLOCK = '''  if (report.nat_route_reachability) {
    section("NAT, routing and reachability — Detailed technical evidence");
    const nr = report.nat_route_reachability;
    text("Advisory static configuration evidence only. This section does not establish effective reachability, allow/deny behavior, deployed route selection, traffic direction or NAT precedence. Prior security findings and scores are unchanged.", {
      size: 8.5, color: COLORS.muted, spaceAfter: 8,
    });
    text(`Status: ${label(nr.status)} | Routes: ${nr.summary.routes_resolved}/${nr.summary.routes_seen} | NAT: ${nr.summary.nat_resolved}/${nr.summary.nat_seen} | Eligible policies: ${nr.summary.policies_eligible}/${nr.summary.policies_seen} | Evidence items: ${nr.summary.evidence_items}`, {
      size: 8.5, spaceAfter: 9,
    });
    if (nr.evidence.length > 0) {
      text("CONFIGURATION CORRELATION — SOURCE EVIDENCE", { bold: true, color: COLORS.blue, size: 9, spaceAfter: 5 });
      nr.evidence.forEach((item) => {
        ensure(86);
        text(`${item.reference} | ${item.kind.replace(/_/g, " ")} | ${item.title}`, {
          bold: true, color: COLORS.navy, size: 9, spaceAfter: 4,
        });
        text(`Source line: ${item.line_number} | Policy: ${item.policy_id ?? "n/a"} | Route line: ${item.route_line_number ?? "n/a"} | Confidence: ${item.confidence}`, {
          indent: 10, size: 8.2, spaceAfter: 4,
        });
        text(`Destination selector: ${item.destination ?? "n/a"} | Mapped address: ${item.mapped_destination ?? "n/a"}`, {
          indent: 10, size: 8.2, spaceAfter: 4,
        });
        text(`Interface selectors: ingress ${item.ingress_interface ?? "not established"} | egress ${item.egress_interface ?? "not established"}`, {
          indent: 10, size: 8.2, spaceAfter: 4,
        });
        text(item.explanation, { indent: 10, size: 8.3, spaceAfter: 4 });
        text(`Recommendation: ${item.recommendation}`, { indent: 10, size: 8.3, spaceAfter: 9 });
      });
    } else {
      text("No supported static route/NAT correlation was established in this upload; this does not prove that traffic is blocked or that the configuration is risk-free.", {
        size: 8.4, color: COLORS.muted, spaceAfter: 8,
      });
    }
    text("ASSESSMENT COVERAGE AND LIMITATIONS", { bold: true, color: COLORS.blue, size: 9, spaceAfter: 4 });
    nr.limitations.forEach((statement) => {
      text(`Limitation: ${statement}`, { size: 8.2, color: COLORS.muted, spaceAfter: 5 });
    });
    if (nr.summary.incomplete || nr.summary.items_omitted > 0) {
      text(`Incomplete coverage: ${nr.summary.items_omitted} source/analysis items were not reported or could not be correlated; no absence conclusion is supported.`, {
        size: 8.3, color: COLORS.muted, spaceAfter: 6,
      });
    }
  }

'''


def patch_pdf(src: str) -> str:
    if 'section("NAT, routing and reachability — Detailed technical evidence")' not in src:
        src = replace_once(src, '  section("Assessment coverage");',
                           PDF_BLOCK + '  section("Assessment coverage");',
                           'PDF assessment-coverage section')
    return src


def plan(frontend: Path) -> dict[Path, bytes]:
    root = frontend.resolve()
    if not (root / 'package.json').is_file():
        raise ValueError(f'Frontend package.json missing: {root}')
    updates: dict[Path, bytes] = {}
    for rel, action in [('src/api/universal.ts', patch_api),
                        ('src/pages/UniversalAnalysis.tsx', patch_dashboard),
                        ('src/utils/normalizedPdf.ts', patch_pdf)]:
        dest = root / rel
        if not dest.is_file():
            raise ValueError(f'API-010.7 frontend prerequisite absent: {dest}')
        old = dest.read_text(encoding='utf-8-sig')
        new = action(old)
        if new != old:
            updates[dest] = new.encode('utf-8')
    for rel in ('src/components/NatRouteSnippet.tsx', 'src/components/NatRouteSnippet.css'):
        src = PACKAGE / rel
        if not src.is_file():
            raise ValueError(f'Patch asset missing: {src}')
        dest = root / rel
        data = src.read_bytes()
        if not dest.is_file() or dest.read_bytes() != data:
            updates[dest] = data
    return updates


def install(frontend: Path) -> list[str]:
    root = frontend.resolve()
    changes = plan(root)  # all checks before any writes
    for dst, data in changes.items():
        dst.parent.mkdir(parents=True, exist_ok=True)
        if dst.exists():
            backup = dst.with_name(dst.name + BACKUP)
            if not backup.exists():
                shutil.copy2(dst, backup)
        dst.write_bytes(data)
    return [str(path.relative_to(root)) for path in changes]


if __name__ == '__main__':
    if len(sys.argv) > 2:
        sys.exit('Usage: install_api_010_8_frontend.py [frontend-dir]')
    root = Path(sys.argv[1]) if len(sys.argv) == 2 else Path.cwd() / 'frontend'
    try:
        changed = install(root)
    except (OSError, ValueError, UnicodeError) as error:
        sys.exit(f'ERROR: {error}')
    print('API-010.8 frontend installed:' if changed else 'API-010.8 frontend already installed:')
    for rel in changed:
        print(' ', rel)
