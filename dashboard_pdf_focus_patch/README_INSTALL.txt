DASHBOARD SUMMARY + DETAILED PDF  |  Frontend-only patch
=======================================================
Compatible with the four-platform normalized Dashboard through API-010.6.
No backend changes, API endpoint changes, theme/sidebar changes, or score changes.

From PowerShell:

cd "C:\IoT\Information security\project 2\config analyzer"
Expand-Archive -LiteralPath "$env:USERPROFILE\Downloads\Dashboard-Summary-Detailed-PDF-Upgrade.zip" -DestinationPath "." -Force
.\.venv-win\Scripts\python.exe .\dashboard_pdf_focus_patch\scripts\install_dashboard_pdf_focus.py ".\frontend"

Test the patch installer:
.\.venv-win\Scripts\python.exe -m unittest discover -s .\dashboard_pdf_focus_patch\tests -p 'test_*.py' -v

Build and start:
cd frontend
npm run build
npm run dev

Changes:
- Dashboard: Four KPI cards, severity counts, top three finding titles and compact review counts.
- PDF: glossary of all scores/checks, report-quality section, object inventory, detailed
  evidence and remediation retained; removes directions to download JSON/use Dashboard.
- Does NOT delete any prior analysis panel source components, and does NOT change backend.

The output PDF includes findings and observations returned by the analyzer, subject to
PDF safety limits (1500 findings, 1000 advanced observations) and any API-side caps.
When a cap is reached it is disclosed; the frontend cannot recreate omitted API data.

ROLLBACK
========
From the backend project root, run:

Copy-Item -LiteralPath ".\frontend\src\pages\UniversalAnalysis.tsx.before_dashboard_pdf_focus.bak" -Destination ".\frontend\src\pages\UniversalAnalysis.tsx" -Force
Copy-Item -LiteralPath ".\frontend\src\utils\normalizedPdf.ts.before_dashboard_pdf_focus.bak" -Destination ".\frontend\src\utils\normalizedPdf.ts" -Force

The newly created ExecutiveDashboardSummary.tsx/CSS files may remain unused; they do
not affect the frontend once the dashboard import is rolled back.

If the installer reports "Unknown ... layout", it refuses to edit any files.
Share your UniversalAnalysis.tsx file for a version-specific adjustment.
