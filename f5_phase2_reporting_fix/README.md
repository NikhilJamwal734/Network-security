# F5 Phase 2 — PDF reporting corrections

This is a **targeted fix for the working F5 Phase 2 installation**. It does **not** reinstall Phase 1/2 and does not replace the Dashboard, Findings pane, Logs viewer, or other vendor modules.

## Changes

1. **Upload provenance:** In F5 reports, Section "Upload input validation" now states that the dedicated `/api/v1/analyze/f5/phase1` handler reuses API-011.6 input validation, then invokes the F5 analysis engine; it no longer incorrectly attributes F5 processing to `/api/v1/analyze/hardened` and the API-011.4 pipeline. Other vendors' wording is unchanged.
2. **Coverage reporting:** Assessment coverage now explicitly includes F5 Phase 2 logging associations and iRule inventory. UCS encryption and signature-update status are "not assessed" when independent evidence is absent. When operator evidence is supplied, the coverage indicates an *assessed, operator-supplied* subset, **not** verified live-device status. This also handles a "current" signature-update assertion that produces no review item.
3. **iRule contextual evidence:** F5-008 now adds the `ASM::disable` source line, recognized `HTTP_REQUEST` event, and a tightly constrained URI selector if present. The PDF includes a cautious explanation of potential WAF inspection suppression. Arbitrary iRule code is not exported, executed, or interpreted. The evidence is advisory and does not prove a working bypass.

### Files modified (only these three)

- `frontend/src/utils/normalizedPdf.ts`
- `frontend/src/api/f5Phase1.ts`
- `app/f5_phase2_addon/review.py`

## Installation on Windows

From the project root:

```powershell
cd "C:\IoT\Information security\project 2\config analyzer"
Expand-Archive -LiteralPath "$env:USERPROFILE\Downloads\FirewallAnalyzer-F5-Phase2-Reporting-Corrections.zip" -DestinationPath "." -Force
.\.venv-win\Scripts\python.exe .\f5_phase2_reporting_fix\scripts\install_report_corrections.py "." --dry-run
.\.venv-win\Scripts\python.exe .\f5_phase2_reporting_fix\scripts\install_report_corrections.py "."
.\.venv-win\Scripts\python.exe -m pytest -q .\f5_phase2_reporting_fix\tests
cd frontend
npm run build
cd ..
```

Restart FastAPI after installation and retest your F5 sample upload. Download **a new PDF** to see the changes. Old PDFs are not modified.

## Rollback

```powershell
.\.venv-win\Scripts\python.exe .\f5_phase2_reporting_fix\scripts\install_report_corrections.py "." --rollback
```

The installer verifies a change manifest and its backups. If another tool has since edited a patched file, rollback refuses to overwrite that work. It handles Windows CRLF and UTF-8 BOM, detects duplicate installs, and refuses ambiguous or customized anchors rather than forcing a replacement.

## Verification checklist

- A fresh PDF's **Upload Input Validation** section describes the F5 endpoint and not the general API-011.4 pipeline.
- **Assessment Coverage** includes Phase 2 virtual-server logging and iRule inventory; UCS and signature update evidence are marked not assessed without operator evidence.
- **F5-008** references `ASM::disable` and shows `/test` and the relevant source line for the included synthetic sample.
- Phase 1 and 2 finding counts remain unchanged for the sample (3 findings, 5 review observations).
- Existing other-vendor reports still generate; log files and dashboards are unchanged.

This code has been tested against the earlier distributed F5 Phase 1/2 source fixtures, **not against your latest Windows project files or EXE**. A passing dry run and `npm run build` in your project are still required before packaging a new Windows EXE.
