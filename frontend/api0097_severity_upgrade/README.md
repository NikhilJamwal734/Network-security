# API-009.7 — Universal Severity Chart

Displays **one shared donut chart** for every supported normalized report: Cisco ASA, Fortinet FortiOS, Snort, and Suricata. Uses API-provided `summary.severity_counts`; includes Critical, High, Medium, Low, Info, and Unknown. A zero-findings report renders an empty chart without a divide-by-zero error. Removes the duplicate ASA-only severity chart in the unified dashboard; the original standalone `SeverityChart.tsx` component remains untouched for any legacy pages.

## Install in PowerShell

```powershell
cd "C:\IoT\Information security\project 2\config analyzer\frontend"
Expand-Archive -LiteralPath "$env:USERPROFILE\Downloads\API-009.7-Universal-Severity-Chart.zip" -DestinationPath . -Force
..\.venv-win\Scripts\python.exe .\api0097_severity_upgrade\scripts\install_universal_severity_chart.py
npm run build
npm run dev
```

This installer is for the **unified API-009.7 React frontend** after Dashboard + Universal Analysis have been merged. It backs up changed existing files with `.api0097_universal_severity_v1.backup`, verifies the expected JSX, refuses conflicting chart files, and can run again without duplicate sections. Don't extract into the backend-only project root.

Changes:

- `src/components/UniversalSeverityChart.tsx` — new platform-independent chart
- `src/components/UniversalSeverityChart.css` — new responsive styling
- `src/pages/UniversalAnalysis.tsx` — replace old severity distribution panel with shared chart
- `src/pages/CiscoASAOverview.tsx` — remove duplicate ASA chart from combined overview
- `src/pages/UnifiedDashboardExtras.css` — make ASA score widget use the full remaining row

The chart relies on **normalized report counts**, so it works even if the legacy Cisco ASA details request fails. No FastAPI, upload, scoring, rules, findings, PDF/JSON export, or platform detection changes. Backend regression baseline remains 730 tests.

## Restore

If you need to roll back, copy the corresponding `.api0097_universal_severity_v1.backup` files over the three changed source files and remove the two new chart component files. Restart Vite.
