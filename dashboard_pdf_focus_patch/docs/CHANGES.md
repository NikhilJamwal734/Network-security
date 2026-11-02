# Dashboard summary, PDF details

## Dashboard

The old unified Dashboard appended multiple detailed panels as each of the
API-010.x milestones was installed. This frontend-only change replaces those
report detail panels with an executive summary component:

- Four metrics: total findings, review/security score, most serious observed
  severity, and the number of domains the implemented checks assessed.
- Severity counts: all categories, explicitly distinguishing Unknown.
- Three previews: highest-severity findings first, showing title, code and
  source-line number (when available). The full list is in the PDF.
- Compact supplemental indicators: report consistency errors, vendor-specific
  observations, rule correlation candidates, ordering contradictions,
  unresolved objects, missing uploaded definitions, and reference cycles.
- One direct PDF report action and brief coverage caution.

The underlying analysis payload, other application pages, and legacy Cisco ASA
analysis context are preserved. Prior detailed panel source files are NOT
removed from the application and can be used in future Reports pages.

## Detailed professional PDF

- Adds a plain-language glossary covering score meanings, severity levels,
  vendor review, correlation, evidence/order verification, object expansion,
  reference integrity, and coverage limits.
- Includes report-quality notices and line-reference validation details from
  API-010.0 when present.
- Adds the available resolved-object inventory.
- Keeps source-line evidence, finding descriptions, remediation advice, vendor
  reviews, correlation entries, object diagnostics, and supported limitations.
- Removes misleading instructions to download JSON or consult Dashboard for
  detail; PDF is the user-facing report.
- Increases safety limits to 1500 detailed findings and 1000 assessment
  observations, and renders full available backend arrays in the supplemental
  sections; API-side truncations and PDF limits are still disclosed.

## Security constraints

- No evaluation or execution of uploaded configuration content.
- No new findings or score modifications.
- Text is rendered through React escaping/jsPDF text drawing.
- Unknown/unassessed remains unknown; no implicit safety conclusion.
- Unchanged network API request, backend routes, sidebar CSS, themes and score
  formulas.

## Local verification

6 installer tests passed and an isolated strict TypeScript check passed for the
compact component, dashboard wiring and combined professional PDF sections.
Actual Windows `npm run build` and full backend regression are still required.
