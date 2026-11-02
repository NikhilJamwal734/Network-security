# API-009.7 — All-platform configuration pages

Run from the MAIN project root: `C:\IoT\Information security\project 2\config analyzer`.

1. Extract this ZIP into the main project root. The installer will be:
   `api0097_config_pages_patch\scripts\install_configuration_pages.py`.
2. Run `\.venv-win\Scripts\python.exe .\api0097_config_pages_patch\scripts\install_configuration_pages.py`.
3. `cd frontend` and run `npm run build`, then `npm run dev`.
4. Return to Dashboard and upload your Suricata YAML again. The Details pages use a second call to the existing universal API to retrieve the backend's parsed configuration inventory.
5. From the project root, run `\.venv-win\Scripts\python.exe -m pytest -q` to confirm your baseline of 730 tests remains intact.

Files updated by installer:
- `frontend/src/App.tsx`
- `frontend/src/pages/UniversalAnalysis.tsx`

Files created:
- `frontend/src/api/platformConfiguration.ts`
- `frontend/src/pages/PlatformConfigurationPage.tsx`
- `frontend/src/pages/PlatformConfigurationPage.css`

No Python backend code or tests change.

Supported detail pages appear for Cisco ASA, Snort, Suricata and FortiOS after successful analysis. Cisco ASA continues to use its existing detail pages if the legacy report was loaded. Other platforms use the structured subset returned from `/api/v1/analyze/universal`.

Suricata YAML often lists filenames under `rule-files`, but those files are **not** opened. The Rules page will show the reference count, not invented rules. To inspect actual inline rules, explicitly upload a `.rules` file as Suricata. NAT/Routes are not applicable to IDS/IPS engines; these sections explain this rather than showing fabricated data. FortiOS NAT/Routes remain unassessed in the current subset parser.

The installer validates both entry files BEFORE writing, creates one-time `.api0097_config_pages_v1.backup` copies and is idempotent. If it refuses to patch, send its exact error message with your current `App.tsx` and `UniversalAnalysis.tsx` for a tailored integration.
