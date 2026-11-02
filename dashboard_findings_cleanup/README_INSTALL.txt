Dashboard security findings cleanup — UI-only change, compatible with API-011.2

Removes duplicated finding lists from both recognized dashboard views:
- frontend/src/pages/UniversalAnalysis.tsx: "Security findings" full list and now-unused filter state.
- frontend/src/pages/Dashboard.tsx: "Priority Findings" / FindingsOverview card and button.

Does NOT modify:
- frontend/src/pages/Findings.tsx or other Findings pane implementations
- FindingSummary, SeverityChart, score, summary widgets, API, rules, reports, or PDF generation
- API-010.x / API-011.x review snippets, which remain on the dashboard

From project root in PowerShell after extracting ZIP there:

  Test-Path .\dashboard_findings_cleanup\scripts\install_dashboard_findings_cleanup.py
  .\.venv-win\Scripts\python.exe .\dashboard_findings_cleanup\scripts\install_dashboard_findings_cleanup.py ".\frontend"

Run tests:
  .\.venv-win\Scripts\python.exe -m unittest discover -s .\dashboard_findings_cleanup\tests -p "test_*.py" -v

Build frontend:
  cd frontend
  npm run build

The installer makes per-file backups with suffix:
    .before_dashboard_findings_cleanup.bak

To undo from project root:
  .\.venv-win\Scripts\python.exe .\dashboard_findings_cleanup\scripts\rollback_dashboard_findings_cleanup.py ".\frontend"

Safe to rerun; if target dashboard details are already removed, no changes are made.
The installer validates both existing files before writing either.
If the installation rejects an unexpected dashboard structure, share the error instead of forcing the change.
