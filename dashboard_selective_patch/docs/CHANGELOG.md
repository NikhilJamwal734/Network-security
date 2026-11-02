# Targeted Dashboard restoration

- Restores the user's **own** pre-summary `UniversalAnalysis.tsx` from the backup created by `Dashboard-Summary-Detailed-PDF-Upgrade` (only when that compact layout is active).
- Does not substitute any bundled historical Dashboard fixture for the user's file.
- Retains upload form, original finding cards, filtering, severity chart, coverage, score, platform navigation, and all other panels present in their pre-summary Dashboard.
- Limits only these sections to two observation/correlation previews: configuration evidence, vendor supplemental checks, rule correlation/conflicts, evidence/ordering review.
- Preserves the score explanation inserted by the earlier score-scale patch by editing only the evidence block of `AdvancedAssessmentPanel`.
- All detailed recommendations, explanations, limitations and supported source-line evidence remain in the existing PDF, which is not changed by this patch.
- No modifications to API/backend, `src/api/universal.ts`, report score/severity logic, CSS/styles, PDF exporter, router or navigation.
- Every modified file gets a unique `.before_selective_dashboard.bak` local rollback copy.
- Installer checks all inputs before writing, refuses unrecognized code instead of guessing and can be re-run safely.
