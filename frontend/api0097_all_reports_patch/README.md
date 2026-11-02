# API-009.7 — All-platform Findings, Coverage, Reports, and PDF

This fixes the unified dashboard's ASA-only sidebar and PDF gating.

## What changes

- Cisco ASA, FortiOS, Snort, and Suricata all have **Dashboard**, **Findings**, **Coverage**, and **Reports** after a successful normalized analysis.
- Cisco ASA still shows its existing Rules, Objects, NAT, Routes, Configuration, and legacy detailed Reports when its legacy report has loaded.
- Snort, Suricata, and FortiOS show **only** the normalized data available to their adapters; no fictional firewall-rule inventories.
- A **Download PDF** button appears in the top bar for normalized reports and in their Reports page; JSON download remains available.
- ASA legacy PDF/JSON exports stay as before once ASA details are ready.
- PDF and JSON exports contain normalized findings, coverage, limitations, warnings, and optional score—not raw uploaded file text.
- All untrusted strings are put into PDF via `jsPDF.text()`, never interpreted as HTML.
- No changes to your FastAPI backend or 730-test regression suite.

## Install (PowerShell)

```powershell
cd "C:\IoT\Information security\project 2\config analyzer\frontend"
Expand-Archive -LiteralPath "$env:USERPROFILE\Downloads\API-009.7-All-Platform-Reports-PDF.zip" -DestinationPath "." -Force
..\.venv-win\Scripts\python.exe .\api0097_all_reports_patch\scripts\enable_multiplatform_reports.py
npm install jspdf
npm run build
npm run dev
```

**Important**: extract into `frontend`, not the backend root. The script preserves an `App.tsx.api0097_all_platform_reports_v1.backup` copy and is safe to rerun. If the script refuses to patch, do not replace `App.tsx` blindly. Share the error so it can be adapted to your specific app.

## Verify

1. Start FastAPI from the backend project root; start React from `frontend`.
2. Upload `suricata_sample.yaml` in the unified Dashboard.
3. Verify **Dashboard**, **Findings**, **Coverage**, **Reports** navigation is available.
4. Open **Reports** and click **Download PDF**; confirm downloaded file opens and lists your Suricata findings.
5. Repeat with Cisco ASA to verify the existing detailed pages and PDF exporter still work.

### PDF library

`jspdf` must be added to the React frontend dependencies by `npm install jspdf`. This is client-side PDF generation; no new server endpoint is required.
