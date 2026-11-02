# PDF-only report controls & clearer PDF numbering

This is a **frontend-only** update to the current Universal Network Security Analyzer. It supports Cisco ASA, FortiOS, Snort and Suricata without changing their analysis or scores.

## Changes

- **PDF section serial** (e.g. `01`) now uses the same **12.5 pt** font size as the adjacent section heading.
- **Finding register serial** (`F-001`) and row title both use **10 pt**.
- **Detailed finding serial** and detailed finding title both use **11.2 pt**.
- Removes visible JSON download controls from the top bar, Dashboard, shared normalized Report Downloads, and the old ASA `Reports.tsx` when present.
- Retains all PDF download controls and their red active styling after a successful analysis.
- Removes report copy that asks readers to export JSON.
- Uses the jsPDF public `pdf.getNumberOfPages()` method, fixing the earlier TS2339 build error.
- The underlying JSON API/report data remains available to application logic. Only the **user-facing JSON download options** are removed.

The PDF renderer limits unusually large reports to the first 300 findings and 80 observations; when a limit is reached the PDF explicitly says that more items exist. This patch **does not** change those safety limits.

## Installation (PowerShell)

From the main backend root:

```powershell
cd "C:\IoT\Information security\project 2\config analyzer"
Expand-Archive -LiteralPath "$env:USERPROFILE\Downloads\PDF-Only-Reports-Numbering-Upgrade.zip" -DestinationPath "." -Force
.\.venv-win\Scripts\python.exe .\pdf_only_ui_patch\scripts\apply_pdf_only_ui.py
cd .\frontend
npm run build
npm run dev
```

Open the dashboard, analyze a configuration, and download the PDF. Confirm that the only available export format is PDF. Existing reports do not change retroactively: regenerate PDFs to see the new styles.

## Files edited if present

- `frontend/src/utils/normalizedPdf.ts`
- `frontend/src/App.tsx`
- `frontend/src/pages/UniversalAnalysis.tsx`
- `frontend/src/components/NormalizedReportDownloads.tsx`
- `frontend/src/pages/NormalizedReportsPage.tsx`
- `frontend/src/pages/Reports.tsx` (only if it uses `JsonReportDownload`)

Each modified file is backed up once as `filename.before_pdf_only_ui.bak`. The installer is rerunnable. It validates the PDF layout and important anchors before editing any file, and exits with a clear error rather than overwriting an unrecognized layout.

## Rollback

Restore the desired `.before_pdf_only_ui.bak` backups to their corresponding `.tsx` paths. For example, in `frontend`:

```powershell
Copy-Item .\src\utils\normalizedPdf.ts.before_pdf_only_ui.bak .\src\utils\normalizedPdf.ts -Force
Copy-Item .\src\App.tsx.before_pdf_only_ui.bak .\src\App.tsx -Force
npm run build
```

## Isolated patch verification

```powershell
cd "C:\IoT\Information security\project 2\config analyzer"
.\.venv-win\Scripts\python.exe -m unittest discover -s pdf_only_ui_patch\tests -p "test_*.py" -v
```

This update does not modify backend modules or backend tests. Verify the production React build on your local machine before marking the update complete.
