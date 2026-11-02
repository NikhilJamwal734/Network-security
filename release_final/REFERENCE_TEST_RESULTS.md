# Local reference results — 31 October 2026

All counts below are for **reconstructed reference code and supplied patch packages**, not for the user's complete Windows checkout or a packaged EXE. The latest uploaded F5 PDF was independently inspected. No live external F5 device was contacted.

| Regression group | Result | Notes |
|---|---|---|
| F5 Phase 1 + Phase 2 parser, findings, FastAPI and installer suites | **38 PASS** | Assembled Phase 1 module with Phase 2 endpoint and reporting helper; includes invalid upload checks |
| Phase 2 reporting, Phase 3 evidence upload and file-picker order installer suites | **32 PASS** | Includes install rollback, BOM/CRLF and validation tests |
| Final release checker tests | **18 PASS** | Includes gate fail-closed, source-change protection, mock core API and vendor behavior |
| Complete Windows EXE builder's isolated test suite | **14 PASS** | Unit/fixture tests only; **no actual Windows binary built here** |
| JSON Logs standalone installer's isolated test suite | **10 PASS** | Installer regression only; no user local logs inspected |
| **TOTAL** | **112 PASS** | Isolated test count; not the user's complete project test count |

Additional direct checks:

- FastAPI TestClient endpoint: config-only HTTP **200**, **3 findings / 5 observations**; config+synthetic metadata HTTP **200**, **4 findings / 4 observations**; malformed JSON and ZIP-signature binary upload HTTP **422** each.
- Uploaded configuration sample SHA-256 in both API responses matches the configuration bytes.
- The Phase 3 adapter, after applying Phase 2 reporting/Phase 3 transformations, passes `tsc --noEmit --strict` with minimal Vite environment type declarations. This is **not** the full React production build.
- The uploaded seven-page F5 evidence PDF `f5_bigip.f5_bigip.security-report (5).pdf` passes PDF text/evidence marker checks, including F5-005, F5-006, operator evidence confidence, and four finding count.

## NOT yet verified

- **The user's actual current checkout**, all project Python tests, full React/Vite build, and full five-vendor API regression in the user's runtime.
- Windows PyInstaller build and post-build smoke test of actual EXE.
- Browser UI flows and visual PDF/layout acceptance in a packaged EXE.
- Authentication, packet-plane behavior and actual device WAF/UCS settings.

These are deliberately marked **pending**, not silently reported as passed. Run `verify_final.py` on the user's Windows project and then complete `MANUAL_ACCEPTANCE.md`.
