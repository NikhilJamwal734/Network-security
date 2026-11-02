# API-009.7 — Merge Universal Analysis and Dashboard

This patch creates ONE Dashboard page with ONE upload form. It uses the richer API-009.7 universal platform selector (automatic, Cisco ASA, FortiOS, Snort, Suricata). It does not add or edit any backend endpoints.

## Behavior

- Sidebar has a single **Dashboard** entry; the separate **Universal Analysis** entry is removed.
- All four platforms display normalized findings, security score (or **Not scored**), coverage, warnings and normalized JSON download.
- For Cisco ASA only, a successful normalized analysis also calls the existing `AnalysisContext.analyze(file)` handler to populate detailed firewall rules, NAT, objects, routes, legacy PDF and JSON exports. This is a SECOND BACKEND REQUEST for ASA, not a second user upload.
- On the merged Dashboard, Cisco ASA also displays the original security score chart, severity chart, rule/object/NAT counts, firewall information and configuration summary. These elements are not shown for IDS/IPS or FortiOS, because their normalized reports don't have legacy ASA structure.
- The existing specialized Cisco ASA pages (Findings, Rules, Network Objects, Service Objects, NAT Rules, Routes, Configuration, Reports) only appear once the matching ASA legacy report has loaded.
- The old `Dashboard.tsx` and its `FirewallUpload` component stay on disk for rollback/compatibility, but are no longer mounted or linked by App. No second visible file upload remains.
- Top-bar legacy JSON/PDF export is hidden unless the current report is synced Cisco ASA. All platforms retain *normalized* JSON export within the dashboard.
- Normalized data stays in `App.tsx`, preserving the report while visiting ASA detail pages.

## Actual Windows paths

Frontend root:

`C:\IoT\Information security\project 2\config analyzer\frontend`

Installation script:

`frontend\scripts\merge_dashboard_and_universal.py`

Staged files inside ZIP:

- `frontend\api0097_merge\src\pages\UniversalAnalysis.tsx` — replacement merged page
- `frontend\api0097_merge\src\pages\CiscoASAOverview.tsx` — new ASA-only cards and charts
- `frontend\api0097_merge\src\pages\UnifiedDashboardExtras.css` — scoped responsive layout

Files patched/installed by script:

- `frontend\src\App.tsx` — **patched**, safely backed up
- `frontend\src\pages\UniversalAnalysis.tsx` — **replaced**, backed up
- `frontend\src\pages\CiscoASAOverview.tsx` — **new**
- `frontend\src\pages\UnifiedDashboardExtras.css` — **new**

No changes to the `src/api/universal.ts`, AnalysisContext, legacy Dashboard, or backend. This patch expects the prior API-009.7 App wiring and its universal page. If local files differ, the script refuses to patch; share the files for a targeted update.

## Install on Windows (PowerShell)

```powershell
cd "C:\IoT\Information security\project 2\config analyzer\frontend"

$zip = Join-Path $env:USERPROFILE "Downloads\API-009.7-Unified-Dashboard-Merge.zip"
Test-Path $zip  # True; otherwise provide full download location

Expand-Archive -LiteralPath $zip -DestinationPath "." -Force

..\.venv-win\Scripts\python.exe .\scripts\merge_dashboard_and_universal.py

npm run build
```

The installer backs up:

- `src\App.tsx.before_unified_dashboard.backup`
- `src\pages\UniversalAnalysis.tsx.before_unified_dashboard.backup`

Then, optionally from the frontend root:

```powershell
..\.venv-win\Scripts\python.exe -m unittest discover -s frontend_checks -p "test_dashboard_merge.py" -v
```

Run from backend root for API regression:

```powershell
cd ..
.\.venv-win\Scripts\python.exe -m pytest -q
```

Expect the previously established backend 730 tests, since no Python backend code changes.

## Test the merged flow

1. Start FastAPI from backend root on port 8000, then Vite from frontend root.
2. Open `http://localhost:5173`; the sidebar should show **Dashboard** once.
3. Select **Automatic detection** and upload `configs/firewall.conf` (Cisco ASA). The normalized findings appear first; when legacy detail analysis finishes, ASA charts/cards and detail navigation appear. Legacy JSON/PDF topbar options become available.
4. Upload a Snort, Suricata, or FortiOS configuration through the same form. ASA-only detail navigation and legacy topbar export should disappear immediately; only normalized results remain.
5. If uploading a standalone `.rules` file, choose Snort or Suricata explicitly.
6. Scores may be `null`; the UI shows **Not scored**, not 0.

## Rollback

From frontend root:

```powershell
Copy-Item .\src\App.tsx.before_unified_dashboard.backup .\src\App.tsx -Force
Copy-Item .\src\pages\UniversalAnalysis.tsx.before_unified_dashboard.backup .\src\pages\UniversalAnalysis.tsx -Force
npm run build
```

The new standalone `CiscoASAOverview.tsx` and `UnifiedDashboardExtras.css` can remain unused.

## Verification performed here

- 4 isolated Python tests: navigation, export gating, idempotence, back-up behavior — PASSED.
- TypeScript strict compatibility check using local React/Vite type shims — PASSED.
- Full Vite build against your real frontend and UI/browser smoke tests were NOT available here. Run `npm run build` on your PC.

All uploaded configuration remains untrusted text. The feature does not execute uploaded text, claim complete vendor coverage or compare platform-specific scores across vendors.
