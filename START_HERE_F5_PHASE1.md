# Firewall Analyzer — F5 BIG-IP Phase 1 (FINAL, ONE ZIP)

This package is **self-contained**. You do **not** need either earlier F5 ZIP.

## What it adds

- Dedicated F5 BIG-IP tmsh export parser in `app/f5_phase1_addon/parser.py`
- F5 Phase 1 checks `F5-001`, `F5-002`, `F5-003`, `F5-007` with source-line evidence
- Profile/virtual-server association helper
- Independent FastAPI endpoint `POST /api/v1/analyze/f5/phase1`
- Automated tests, sample `.conf` file, dry-run installer and rollback

## Safety / compatibility

The installer preserves your existing `app/parsers/f5_bigip_parser.py` and other F5 modules; it does **not** overwrite them. It adds a new isolated `app/f5_phase1_addon/` package and updates `app/api/main.py` only when the expected API-012 release status router anchor exists exactly once. It uses your installed `app/core/input_hardening.py` for file validation. If integration would be unsafe, it refuses to modify your project.

**Not yet included:** F5 in the existing multi-vendor dropdown or shared PDF, F5-004 through F5-008, or an updated Windows EXE.

## Windows installation (PowerShell, project root)

```powershell
cd "C:\IoT\Information security\project 2\config analyzer"
Expand-Archive -LiteralPath "$env:USERPROFILE\Downloads\FirewallAnalyzer-F5-Phase1-FINAL.zip" -DestinationPath "." -Force
.\.venv-win\Scripts\python.exe .\f5_phase1_compat_patch\scripts\install_f5_compat.py "." --dry-run
.\.venv-win\Scripts\python.exe .\f5_phase1_compat_patch\scripts\install_f5_compat.py "."
.\.venv-win\Scripts\python.exe -m pytest -q .\f5_phase1_compat_patch\tests
```

## Start API and try sample

In a fresh terminal at project root:

```powershell
.\.venv-win\Scripts\python.exe -m uvicorn app.api.main:app --host 127.0.0.1 --port 8000 --reload
```

In a second terminal at project root:

```powershell
curl.exe -X POST "http://127.0.0.1:8000/api/v1/analyze/f5/phase1" -F "file=@f5_phase1_compat_patch/examples/f5_phase1_sample.conf"
```

If another F5 Phase 1 API endpoint is already installed, the installer will stop rather than create duplicates.

## Rollback

```powershell
.\.venv-win\Scripts\python.exe .\f5_phase1_compat_patch\scripts\install_f5_compat.py "." --rollback
```

Rollback uses backups and refuses to overwrite any files that have been modified since installation.
