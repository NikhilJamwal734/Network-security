# API-009.7 unified dashboard — severity and layout cleanup

This patch works with the merged API-009.7 React dashboard. It does not change
`App.tsx`, the backend, API responses, the uploaded configuration, or findings.

## What changes

1. The normalized **Severity distribution** cards disappear **only when** the
   Cisco ASA `SeverityChart` is visible (`platform_id === 'cisco_asa'` and
   `legacyASAReady` is true). For Snort, Suricata, FortiOS, or when the legacy
   ASA chart has not loaded, the severity counts are retained.
2. `CiscoASAOverview.tsx` removes the old `SummaryCard` row of five tiny icon
   cards. This was duplicated with the actual `ConfigurationSummary`.
3. `ConfigurationSummary` now has the full panel width. Scoped CSS uses an
   auto-fitting grid so labels do not wrap into vertical letters.
4. Findings, filters, chart content, and existing export logic are preserved.

## Install (PowerShell)

```powershell
cd "C:\IoT\Information security\project 2\config analyzer\frontend"
Expand-Archive -LiteralPath "$env:USERPROFILE\Downloads\API-009.7-Dashboard-Layout-Severity-Cleanup.zip" -DestinationPath . -Force
..\.venv-win\Scripts\python.exe .\scripts\apply_dashboard_cleanup.py
npm run build
npm run dev
```

**You must run from `frontend`** (the directory containing `package.json` and
`src/App.tsx`). The installer backs up these three files before changing them:

- `src/pages/UniversalAnalysis.tsx`
- `src/pages/CiscoASAOverview.tsx`
- `src/pages/UnifiedDashboardExtras.css`

Backups end with `.api0097_dashboard_cleanup_v1.backup` and are not replaced on
reruns. The script is idempotent and refuses to edit unrecognized TSX layouts.
If it stops with a message about missing or nonunique anchors, do not blindly
replace the files: share the message and the current source to adapt the patch.

## Manual reference

The ZIP includes examples under `reference/` showing the result for the baseline
`UniversalAnalysis.tsx` and `CiscoASAOverview.tsx`. They are **not** placed in
`src/pages/` by extraction; the installer makes safe, backed-up edits instead. Prefer the installer so custom existing edits are preserved.

Backend regression baseline remains **730 passing tests**; no backend edits.
