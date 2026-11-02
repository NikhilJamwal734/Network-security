# FirewallAnalyzer — F5 Phase 3: Optional Evidence Upload + Release Verification

**Purpose:** Finish the operator-evidence workflow for F5 Phase 2 and verify frontend, API, and report integration before building a Windows executable. The working F5 backend endpoint and existing PDF code are retained.

## Scope

- Adds an optional `.json` evidence selector **only when F5 BIG-IP is selected** in the existing configuration upload page.
- Sends evidence through the existing `evidence_json` multipart field of `POST /api/v1/analyze/f5/phase1`.
- Validates JSON structure and an approximately 16 KiB limit client-side; server-side Phase 2 validation remains authoritative.
- Reuses the existing F5 Findings/PDF report and its evidence/coverage handling. It does **not** alter Cisco ASA, FortiOS, Snort, or Suricata.
- Does **not** read UCS archive contents, credentials, backup passphrases, or connect to a BIG-IP appliance. Operator-provided assertions remain **unverified evidence**, not cryptographic attestation.

## Install (PowerShell in the project root)

1. Extract `FirewallAnalyzer-F5-Phase3-FINAL.zip` to your **existing** `config analyzer` project directory. Do not replace your existing `app`, `frontend`, or log directories wholesale.
2. Preview exact edits:

```powershell
.\.venv-win\Scripts\python.exe .\f5_phase3_patch\scripts\install_f5_phase3.py "." --dry-run
```

3. Install:

```powershell
.\.venv-win\Scripts\python.exe .\f5_phase3_patch\scripts\install_f5_phase3.py "."
```

Only the following two **existing files** are modified:

- `frontend/src/api/f5Phase1.ts`
- `frontend/src/pages/UniversalAnalysis.tsx`

A checksum manifest and backups are created automatically. **Do not rerun an older frontend patch installer after installing Phase 3.** If the installer detects customized or incompatible source, it stops instead of forcing changes.

## Verify

From the project root:

```powershell
.\.venv-win\Scripts\python.exe -m pytest -q .\f5_phase3_patch\tests
.\.venv-win\Scripts\python.exe -m pytest -q .\f5_phase2_patch\tests
```

Frontend compilation:

```powershell
cd frontend
npm run build
npm run dev
```

In another project-root terminal, start the backend:

```powershell
.\.venv-win\Scripts\python.exe -m uvicorn app.api.main:app --host 127.0.0.1 --port 8000 --reload
```

Run the API smoke verifier (backend must already be running):

```powershell
.\.venv-win\Scripts\python.exe .\f5_phase3_patch\tools\verify_phase3_api.py --root "."
```

In the frontend, choose **F5 BIG-IP (Phases 1 + 2)**, select `f5_phase2_patch/examples/f5_phase2_sample.conf`, and optionally choose `f5_phase3_patch/examples/f5_phase3_evidence.json`. Analyze and export a **new PDF**.

Expected example behavior:

- Without JSON metadata: **3 findings**; F5-005 and F5-006 remain **not assessed** (other observations remain).
- With included synthetic metadata: **4 findings** (the fourth is an **operator-reported**, unencrypted UCS backup) and an F5-006 signature-update **review observation** (not a confirmed vulnerability). The sample is not evidence of any real system.
- The PDF should contain the F5 Phase 1+2 technical evidence section and mark metadata-derived records as operator-supplied / unverified.
- Existing non-F5 sample uploads, findings, and PDF exports should continue to work.

If a test result differs, **do not package for release** until it is explained.

## Build the updated Windows EXE (after validation)

Close any existing `FirewallAnalyzer.exe` and Vite dev processes so files are not locked. Run from the project root using your working Windows EXE builder:

```powershell
.\.venv-win\Scripts\python.exe .\desktop_packaging\build_complete_exe.py --check
.\.venv-win\Scripts\python.exe .\desktop_packaging\build_complete_exe.py
.\.venv-win\Scripts\python.exe .\desktop_packaging\smoke_complete_exe.py
```

Use a builder already corrected to invoke `npm.cmd` on Windows. A Linux environment cannot produce or verify a Windows `.exe`; build and test on your Windows machine. After packaging, test the *newly built* EXE at its generated localhost origin, including F5 upload with and without evidence, JSON logs, Findings, and PDF export. `npm run build` success alone is not proof of runtime correctness.

## Rollback (if no subsequent changes have been made)

```powershell
.\.venv-win\Scripts\python.exe .\f5_phase3_patch\scripts\install_f5_phase3.py "." --rollback
```

The rollback refuses to overwrite post-installation changes. Existing backend modules and PDF generator are not modified by this package.

## Important integrity/security limits

- The evidence JSON contains operator assertions, **not actual protected UCS backups** or independent signature-update proof.
- Client validation improves usability, but backend validation is mandatory.
- Only send configuration files and metadata from systems you are authorized to assess.
- The current JSON report and PDF may contain configuration identifiers; protect exports and logs accordingly.
