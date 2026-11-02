# Unified Dashboard — Clean Layout & Red Download Buttons

This is a **frontend-only** cleanup for the current API-009.9 project. It does not alter the four-platform backend, existing assessment findings, PDF generation, IDS rule-bundle API, or regression tests.

- Hides the additional IDS rule-bundle upload panel from the main Dashboard. Its Python endpoint and component source files remain installed and can be presented in a dedicated Rules page later.
- Replaces developer milestone labels (e.g. “API-009.8”) and “schema version” dashboard headings with plain product copy.
- Removes the duplicated “Static analysis only” heading badge. The substantive analysis-coverage limitations remain visible.
- Colors the available PDF and JSON buttons **red after an analysis** for Cisco ASA, FortiOS, Snort and Suricata. The existing application renders the export controls only after a report exists; this update does **not** enable downloads before analysis.
- Highlights the dashboard’s “Export normalized JSON” button when a report exists.

## Install (PowerShell)

```powershell
cd "C:\IoT\Information security\project 2\config analyzer"
Expand-Archive -LiteralPath "$env:USERPROFILE\Downloads\Dashboard-Red-Downloads-UI-Cleanup.zip" -DestinationPath "." -Force
.\.venv-win\Scripts\python.exe dashboard_cleanup_patch\scripts\install_dashboard_cleanup.py
cd .\frontend
npm run build
npm run dev
```

The installer edits `frontend/src/App.tsx`, `frontend/src/pages/UniversalAnalysis.tsx`, and (if present) `frontend/src/components/AdvancedAssessmentPanel.tsx`, and creates `frontend/src/DashboardDownloadHighlight.css`. Existing files are backed up with `.before_dashboard_cleanup.bak` (once only). It is safe to rerun. A mismatched source anchor fails without writing any files.

## Verification

1. Before upload: no report downloads.
2. After a supported upload: top-right PDF/JSON actions are red and usable; the on-dashboard JSON export is red.
3. No “OPTIONAL · API-009.9” upload panel, “API-009.8” banner, or schema-version heading.
4. Severity chart, assessment evidence, findings, coverage and all four vendor integrations still work.

## Rollback

Restore the backed-up `.tsx` files, then remove the `DashboardDownloadHighlight.css` import and file. Do not overwrite other work created after this patch without first saving it.
