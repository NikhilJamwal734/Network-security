# F5 Phase 1 — Configuration Inventory HTTP 400 fix

This patch corrects an F5-only compatibility error introduced when adding F5
Phase 1 to the existing multi-vendor frontend. F5 analysis is sent to
`/api/v1/analyze/f5/phase1`, but the previous frontend inventory code then
mistakenly sends a second request to `/api/v1/analyze/universal?platform=f5_bigip`.
F5 is not yet registered with that older endpoint, which returns HTTP 400.

The patch reuses already validated counts in the F5 response and displays a
bounded, accurate Phase 1 configuration summary. Other tabs say "Not assessed"
instead of implying empty F5 rules/objects. F5 findings/PDF stay unchanged.

**Modified files only**
- `frontend/src/pages/UniversalAnalysis.tsx`
- `frontend/src/pages/PlatformConfigurationPage.tsx`

**Prerequisites:** F5 Phase 1 backend, F5 Phase 1 frontend adapter and prior
PlatformConfigurationPage are installed. Otherwise the installer fails closed.

**Windows install** from main project folder:

```powershell
.\.venv-win\Scripts\python.exe .\f5_inventory_fix\scripts\install_f5_inventory_fix.py . --dry-run
.\.venv-win\Scripts\python.exe .\f5_inventory_fix\scripts\install_f5_inventory_fix.py .
.\.venv-win\Scripts\python.exe -m pytest -q .\f5_inventory_fix\tests
cd frontend
npm run build
npm run dev
```

Restart the backend if needed. Open the Vite URL, select F5 BIG-IP Phase 1,
then upload the example. Avoid testing an old EXE: it does not include the
latest frontend until rebuilt.

**Rollback** (from main project folder):

```powershell
.\.venv-win\Scripts\python.exe .\f5_inventory_fix\scripts\install_f5_inventory_fix.py . --rollback
```

No Python security checks, existing backend routes, JSON log files,
Dashboard layout, or PDF generator are changed.
