"""API-010.6 additive React/PDF patch; preserves existing theme/sidebar styling.

python api0106_patch/frontend_patch/scripts/install_api_010_6_frontend.py ".\\frontend"
"""
from __future__ import annotations
from pathlib import Path
import shutil
import sys

PACKAGE = Path(__file__).resolve().parents[1]
BACKUP_SUFFIX = '.before_api0106.bak'

TYPE_DECL = '''
/** Cross-reference diagnostics scoped to the uploaded configuration (not live-device proof). */
export interface ObjectAssurance {
  version: "1.0";
  platform_id: "cisco_asa" | "fortios" | "snort" | "suricata";
  scope: "uploaded_object_dependency_evidence";
  status: "limited" | "reviewed_subset" | "not_assessed";
  summary: {
    definitions_seen: number;
    references_checked: number;
    observations: number;
    missing_in_upload: number;
    cycles: number;
    repeated_definitions: number;
    incomplete: boolean;
    observations_omitted: number;
  };
  observations: Array<{
    reference: string;
    kind: string;
    status: "review_needed";
    object_name: string;
    line_number: number;
    related_line_numbers: number[];
    explanation: string;
    recommendation: string;
  }>;
  limitations: string[];
}
'''


def replace_once(before: str, original: str, replacement: str, label: str) -> str:
    if replacement in before:
        return before
    if before.count(original) != 1:
        raise ValueError(f'{label}: expected one anchor, found {before.count(original)}')
    return before.replace(original, replacement, 1)


def patch_api(source: str) -> str:
    source = replace_once(source, '/api/v1/analyze/object-resolution',
                          '/api/v1/analyze/object-assurance', 'new backend endpoint')
    source = replace_once(source, '  object_resolution?: ObjectResolution;',
                          '  object_resolution?: ObjectResolution;\n  object_assurance?: ObjectAssurance;',
                          'response type field')
    if 'export interface ObjectAssurance {' not in source:
        source += '\n' + TYPE_DECL
    return source


def patch_dashboard(source: str) -> str:
    source = replace_once(source, 'import ObjectResolutionPanel from "../components/ObjectResolutionPanel";',
                          'import ObjectResolutionPanel from "../components/ObjectResolutionPanel";\nimport ObjectAssurancePanel from "../components/ObjectAssurancePanel";',
                          'dashboard component import')
    source = replace_once(source, '<ObjectResolutionPanel analysis={report.object_resolution} />',
                          '<ObjectResolutionPanel analysis={report.object_resolution} />\n          <ObjectAssurancePanel review={report.object_assurance} />',
                          'dashboard component placement')
    return source


def patch_pdf(source: str) -> str:
    if 'section("Object reference integrity")' in source:
        return source
    anchor = '  section("Assessment coverage");'
    block = '''  if (report.object_assurance) {
    section("Object reference integrity");
    const review = report.object_assurance;
    text("Upload-scoped cross-reference review, not proof of effective device policy. Observations do not affect the security score.", {
      size: 8.5, color: COLORS.muted, spaceAfter: 7,
    });
    text(`References checked: ${review.summary.references_checked} | Not defined in upload: ${review.summary.missing_in_upload} | Cycles: ${review.summary.cycles} | Repeated definitions: ${review.summary.repeated_definitions}`, {
      size: 8.6, spaceAfter: 8,
    });
    review.observations.slice(0, 30).forEach((item) => {
      ensure(62);
      text(`${item.reference}  ${item.kind.replace(/_/g, " ")}  | line ${item.line_number}`, {
        bold: true, size: 9.3, color: COLORS.navy, spaceAfter: 3,
      });
      text(`Object: ${item.object_name} | ${item.explanation}`, {
        indent: 10, size: 8.3, spaceAfter: 4,
      });
      if (item.related_line_numbers.length) {
        text(`Related lines: ${item.related_line_numbers.join(", ")}`, {
          indent: 10, size: 8, color: COLORS.muted, spaceAfter: 3,
        });
      }
      text(`Review: ${item.recommendation}`, { indent: 10, size: 8.2, spaceAfter: 8 });
    });
    if (review.observations.length > 30 || review.summary.observations_omitted > 0) {
      text("Additional observations were omitted from the PDF; consult the dashboard for the available bounded list.", {
        size: 8, color: COLORS.muted, spaceAfter: 5,
      });
    }
    if (review.summary.incomplete) {
      text("The uploaded source or processing was incomplete; absence claims cannot be established.", {
        size: 8.4, color: COLORS.muted, spaceAfter: 5,
      });
    }
    review.limitations.slice(0, 3).forEach((item) => {
      text(`Scope: ${item}`, { size: 8.1, color: COLORS.muted, spaceAfter: 4 });
    });
  }

'''
    return replace_once(source, anchor, block + anchor, 'PDF coverage section')


def plan(frontend: Path) -> dict[Path, bytes]:
    frontend = frontend.resolve()
    if not (frontend / 'package.json').is_file():
        raise ValueError(f'Expected React frontend directory: {frontend}')
    changed: dict[Path, bytes] = {}
    for rel, transform in (
        ('src/api/universal.ts', patch_api),
        ('src/pages/UniversalAnalysis.tsx', patch_dashboard),
        ('src/utils/normalizedPdf.ts', patch_pdf),
    ):
        target = frontend / rel
        if not target.is_file():
            raise ValueError(f'API-010.5 frontend prerequisite missing: {target}')
        original = target.read_text(encoding='utf-8-sig')
        updated = transform(original)
        if updated != original:
            changed[target] = updated.encode('utf-8')
    for rel in ('src/components/ObjectAssurancePanel.tsx', 'src/components/ObjectAssurancePanel.css'):
        template = PACKAGE / rel
        if not template.is_file():
            raise ValueError(f'Installer package incomplete: {template}')
        target = frontend / rel
        payload = template.read_bytes()
        if not target.is_file() or target.read_bytes() != payload:
            changed[target] = payload
    return changed


def install(frontend: Path) -> list[str]:
    frontend = frontend.resolve()
    changes = plan(frontend)
    for target, payload in changes.items():
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists():
            backup = target.with_name(target.name + BACKUP_SUFFIX)
            if not backup.exists():
                shutil.copy2(target, backup)
        target.write_bytes(payload)
    return [str(path.relative_to(frontend)) for path in changes]


if __name__ == '__main__':
    target = Path(sys.argv[1]) if len(sys.argv) == 2 else Path.cwd() / 'frontend'
    try:
        changed = install(target)
    except (OSError, ValueError) as error:
        sys.exit(f'ERROR: {error}')
    print('API-010.6 frontend installed:' if changed else 'API-010.6 frontend already installed.')
    for item in changed:
        print('  ' + item)
