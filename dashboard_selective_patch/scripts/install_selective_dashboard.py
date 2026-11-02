r"""Restore pre-compact Dashboard and summarize only four detailed review panels.

Run at the project root:
    .\.venv-win\Scripts\python.exe dashboard_selective_patch\scripts\install_selective_dashboard.py ".\frontend"

Only updates UniversalAnalysis.tsx if the whole-Dashboard compaction was applied;
requires the exact pre-compaction backup made by that installer. Modifies four
existing React components. No PDF, CSS, backend, router or analysis API edits.
"""
from __future__ import annotations

from pathlib import Path
import shutil
import sys

BACKUP_SUFFIX = '.before_selective_dashboard.bak'
COMPACTION_BACKUP = '.before_dashboard_pdf_focus.bak'
PANELS = (
    'AdvancedAssessmentPanel.tsx',
    'VendorDeepReviewPanel.tsx',
    'RuleCorrelationPanel.tsx',
    'CorrelationAssurancePanel.tsx',
)


def replace_trailing_section(source: str, start: str, replacement: str, label: str) -> str:
    """Replace only the known verbose portion inside the component section."""
    if source.count(start) != 1:
        raise ValueError(f'{label}: expected one original content anchor, found {source.count(start)}')
    if source.count('    </section>') != 1:
        raise ValueError(f'{label}: unexpected section layout; refusing to modify')
    a = source.index(start)
    b = source.rindex('    </section>')
    if b <= a:
        raise ValueError(f'{label}: unexpected section ordering')
    return source[:a] + replacement + source[b:]


def summarize_advanced(source: str) -> str:
    if 'data-dashboard-snippet="configuration-evidence"' in source:
        return source
    start = '      <h3>Visible configuration evidence</h3>'
    return replace_trailing_section(source, start, '''      <div data-dashboard-snippet="configuration-evidence">
        <h3>Configuration review evidence</h3>
        <p className="ua-hint">
          {observations.length} evidence observations · {coverage.unassessed_domain_count} unassessed domains.
        </p>
        <div className="advanced-assessment-observations">
          {observations.slice(0, 2).map((check) => (
            <article className="advanced-assessment-observation" key={check.code}>
              <div className="advanced-assessment-observation-head">
                <strong>{check.title}</strong>
                <span className={`advanced-assessment-status advanced-assessment-status-${check.status}`}>
                  {label(check.status)}
                </span>
              </div>
            </article>
          ))}
        </div>
        {observations.length > 2 && <small>+{observations.length - 2} more observations in the PDF.</small>}
        <p className="ua-hint">See the PDF for source evidence, explanations, assessed scope and limitations.</p>
      </div>
''', 'AdvancedAssessmentPanel')


def summarize_vendor(source: str) -> str:
    if 'data-dashboard-snippet="vendor-review"' in source:
        return source
    start = '      {checks.length ? ('
    return replace_trailing_section(source, start, '''      <div data-dashboard-snippet="vendor-review">
        {checks.length ? (
          <ol className="vendor-deep-list">
            {checks.slice(0, 2).map((check, index) => (
              <li key={`${check.code}-${check.line_number ?? "n"}-${index}`} className="vendor-deep-item">
                <div className="vendor-deep-item-heading">
                  <strong>{check.title}</strong>
                  <span className={`vendor-deep-severity vendor-deep-${check.severity.toLowerCase()}`}>{check.severity}</span>
                </div>
                <small>{check.code}{check.line_number === null ? "" : ` · Line ${check.line_number}`}</small>
              </li>
            ))}
          </ol>
        ) : <p className="vendor-deep-empty">No supplemental issues identified by the implemented checks.</p>}
        {checks.length > 2 && <p className="ua-hint">+{checks.length - 2} more review items in the PDF.</p>}
        {review.suppressed_checks > 0 && <p className="ua-hint">{review.suppressed_checks} observations omitted by the analysis service.</p>}
        <p className="ua-hint">Read the PDF for all available evidence, recommendations and assessment limitations.</p>
      </div>
''', 'VendorDeepReviewPanel')


def summarize_rules(source: str) -> str:
    if 'data-dashboard-snippet="rule-correlation"' in source:
        return source
    start = '      <div className="rule-correlation-metrics">'
    return replace_trailing_section(source, start, '''      <div data-dashboard-snippet="rule-correlation">
        <p className="ua-hint">
          {summary.eligible_rules} rules compared · {summary.rules_not_correlated} outside comparison scope.
        </p>
        {pairs.length ? (
          <ol className="rule-correlation-list">
            {pairs.slice(0, 2).map((item) => (
              <li key={item.correlation_id} className="rule-correlation-item">
                <div className="rule-correlation-entry-title">
                  <strong>{item.correlation_id} · {item.title}</strong>
                  <span className="rule-correlation-kind">{kindLabel[item.kind] ?? item.kind}</span>
                </div>
                <small>Source lines {item.evidence.related_line_number} and {item.evidence.line_number}</small>
              </li>
            ))}
          </ol>
        ) : <p className="rule-correlation-empty">No candidate correlations within the supported rule subset.</p>}
        {pairs.length > 2 && <p className="ua-hint">+{pairs.length - 2} more candidate pairs in the PDF.</p>}
        {summary.truncated && <p className="rule-correlation-caution">Processing limit reached; the review is incomplete.</p>}
        <p className="ua-hint">See the PDF for candidate relationships, supporting evidence, recommendations and limitations.</p>
      </div>
''', 'RuleCorrelationPanel')


def summarize_assurance(source: str) -> str:
    if 'data-dashboard-snippet="correlation-assurance"' in source:
        return source
    start = '      <div className="ca-metrics">'
    return replace_trailing_section(source, start, '''      <div data-dashboard-snippet="correlation-assurance">
        <div className="ca-metrics">
          <div><strong>{summary.pairs_reviewed}</strong><span>Pairs reviewed</span></div>
          <div><strong>{summary.evidence_present}</strong><span>Source references located</span></div>
          <div><strong>{summary.ordering_contradictions}</strong><span>Ordering contradictions</span></div>
        </div>
        {summary.ordering_contradictions > 0 && (
          <p className="ca-warning">Some Cisco ASA rule-order assumptions contradict explicit ACL sequence evidence.</p>
        )}
        {assurance.items.length > 0 && (
          <ol className="ca-list">
            {assurance.items.slice(0, 2).map((item, index) => (
              <li className="ca-item" key={`${item.correlation_id}-${index}`}>
                <div className="ca-item-title">
                  <strong>{item.correlation_id} — {labels[item.status] ?? item.status}</strong>
                </div>
                <small>Referenced lines: {item.related_line_number ?? "?"}, {item.line_number ?? "?"}</small>
              </li>
            ))}
          </ol>
        )}
        {assurance.items.length > 2 && <p className="ua-hint">+{assurance.items.length - 2} more evidence checks in the PDF.</p>}
        {summary.truncated && <p className="ca-warning">Processing limit reached; review is incomplete.</p>}
        <p className="ua-hint">See the PDF for ordering explanations, next checks, and verification limitations.</p>
      </div>
''', 'CorrelationAssurancePanel')

TRANSFORMS = {
    PANELS[0]: summarize_advanced,
    PANELS[1]: summarize_vendor,
    PANELS[2]: summarize_rules,
    PANELS[3]: summarize_assurance,
}


def plan(frontend: Path) -> tuple[dict[Path, bytes], list[str]]:
    frontend = frontend.resolve()
    if not (frontend / 'package.json').is_file():
        raise ValueError(f'Expected React frontend containing package.json: {frontend}')
    page = frontend / 'src/pages/UniversalAnalysis.tsx'
    if not page.is_file():
        raise ValueError(f'Dashboard source not found: {page}')

    current_page = page.read_text(encoding='utf-8-sig')
    changed: dict[Path, bytes] = {}
    notes: list[str] = []
    if '<ExecutiveDashboardSummary' in current_page:
        backup = page.with_name(page.name + COMPACTION_BACKUP)
        if not backup.is_file():
            raise ValueError(
                'The compact Dashboard is active, but its exact pre-compaction backup '
                f'is missing: {backup}. No files were modified. Restore the original '
                'UniversalAnalysis.tsx from your own version control/backup first.'
            )
        restored = backup.read_text(encoding='utf-8-sig')
        if '<ExecutiveDashboardSummary' in restored or 'onReportChange(next)' not in restored or 'ua-results' not in restored:
            raise ValueError('Dashboard backup does not match the original layout; no files were modified.')
        changed[page] = restored.encode('utf-8')
        notes.append('Restores exact pre-compaction Dashboard from the local backup.')
    else:
        notes.append('Original Dashboard layout already present; leaves it untouched.')

    components = frontend / 'src/components'
    for name, fn in TRANSFORMS.items():
        component = components / name
        if not component.is_file():
            raise ValueError(f'Required review component missing: {component}; no files were modified.')
        old = component.read_text(encoding='utf-8-sig')
        new = fn(old)
        if old != new:
            changed[component] = new.encode('utf-8')

    page_text = changed.get(page, current_page.encode('utf-8')).decode('utf-8')
    for name in PANELS:
        component_name = name.removesuffix('.tsx')
        if f'<{component_name}' not in page_text:
            notes.append(f'Note: the restored Dashboard does not render {component_name}; no layout was invented.')

    return changed, notes


def install(frontend: Path) -> tuple[list[str], list[str]]:
    frontend = frontend.resolve()
    changes, notes = plan(frontend)  # Validate all files before writing anything.
    for path, content in changes.items():
        backup = path.with_name(path.name + BACKUP_SUFFIX)
        if not backup.exists():
            shutil.copy2(path, backup)
        path.write_bytes(content)
    return [str(path.relative_to(frontend)) for path in changes], notes


if __name__ == '__main__':
    if len(sys.argv) > 2:
        sys.exit('Usage: install_selective_dashboard.py [frontend-directory]')
    target = Path(sys.argv[1]) if len(sys.argv) == 2 else Path.cwd() / 'frontend'
    try:
        changes, notes = install(target)
    except (OSError, ValueError, UnicodeError) as error:
        sys.exit(f'ERROR: {error}')
    print('Selective Dashboard update installed:' if changes else 'Selective Dashboard update already applied:')
    for relative in changes:
        print('  Updated: ' + relative)
    for note in notes:
        print('  ' + note)
    print('Unchanged: existing PDF exporter, sidebar styles, all backend APIs and scoring.')
    print('Next: cd frontend; npm run build')
