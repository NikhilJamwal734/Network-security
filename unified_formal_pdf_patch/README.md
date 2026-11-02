# Unified formal PDF layout — Cisco ASA, FortiOS, Snort, Suricata

## What this fixes

Prior frontend releases chose between two PDF pipelines:
- Cisco ASA: `PdfReportDownload` -> legacy `src/services/pdfReport.ts`.
- Other platforms: `NormalizedReportDownloads` -> formal `src/utils/normalizedPdf.ts`.

This patch makes **every platform** use the latter formal PDF renderer, including the
Dashboard top bar and the Reports page. The format has a professional header,
report reference, executive summary, severity counts, numbered findings (F-001,
F-002…), evidence, recommendations, coverage, limitations, and page X of Y.

It preserves the Cisco ASA-specific Rules, NAT, and Objects pages and the legacy
report implementation on disk for rollback. It does not modify the backend,
analysis findings, score calculations, or JSON API. It does not add JSON buttons.

The patch is intended for your already-installed professional normalized PDF
exporter. It checks that file and refuses changes if it cannot recognize the
expected formal-report sections. If your `src/App.tsx` differs from the known
API-009.7 merged dashboard, the installer also stops without editing anything.

## Install — PowerShell from your **main project root**

```powershell
cd "C:\IoT\Information security\project 2\config analyzer"
Expand-Archive -LiteralPath "$env:USERPROFILE\Downloads\Unified-Formal-PDF-All-Platforms.zip" -DestinationPath "." -Force
.\.venv-win\Scripts\python.exe .\unified_formal_pdf_patch\scripts\install_unified_pdf.py
cd .\frontend
npm run build
npm run dev
```

If the ZIP is elsewhere, supply its actual location in `-LiteralPath`.

## Files updated (backups are saved once)

- `frontend/src/App.tsx` — topbar PDF and Reports route use the normalized PDF for **all** platforms, including Cisco ASA
- `frontend/src/components/NormalizedReportDownloads.tsx` — single PDF download button, loading/error states
- `frontend/src/components/NormalizedReportDownloads.css` — error text style only; original red PDF button styling stays intact
- `frontend/src/pages/NormalizedReportsPage.tsx` — user-facing PDF-only description if needed
- `frontend/src/utils/normalizedPdf.ts` — only fixes `pdf.internal.getNumberOfPages()` to `pdf.getNumberOfPages()` when necessary

Each changed file gets a sibling backup ending in `.before_unified_formal_pdf.bak`.
The installer can safely be run again and will report `Already installed`.

## Verification

1. `npm run build` succeeds.
2. Upload one Cisco ASA `.conf`, then click **Download PDF** in the top bar AND on the Reports page.
3. Upload a Suricata `.yaml` and repeat; also try Snort and FortiOS.
4. Each generated PDF has the same header, section order, F-001 finding numbering,
   coverage section, and page X of Y. Counts, observations and scores remain platform-specific.
5. On a platform with no findings, the findings register explains that zero
   findings doesn't prove security. If a score is unavailable, it says `Not scored`.

The existing legacy Cisco ASA PDF file remains in the codebase but is no longer
used by the unified Dashboard or Reports navigation. The exact original upload
filename may not be available to the parent `App.tsx`, so the topbar falls back
to the hostname/platform ID, as in the previous normalized report exporter.

## Rollback

From the frontend directory:

```powershell
Copy-Item .\src\App.tsx.before_unified_formal_pdf.bak .\src\App.tsx -Force
Copy-Item .\src\components\NormalizedReportDownloads.tsx.before_unified_formal_pdf.bak .\src\components\NormalizedReportDownloads.tsx -Force
npm run build
```

Also restore `.before_unified_formal_pdf.bak` backups for any other modified files
if needed.

## Installer self-tests

```powershell
cd "C:\IoT\Information security\project 2\config analyzer"
.\.venv-win\Scripts\python.exe -m unittest discover -s unified_formal_pdf_patch\tests -p 'test_*.py' -v
```

The 7 installer tests check both known Dashboard variants, repeat installation,
rollback backups and refusal of unrecognized layouts. A strict isolated TypeScript
check of the PDF exporter and PDF download component also passed. The complete
Vite build still needs to be tested locally.
