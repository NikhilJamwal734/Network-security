# F5 Phase 1 collision-safe installer

This package installs F5 Phase 1 under `app/f5_phase1_addon/` and **never overwrites** the existing `app/parsers/f5_bigip_parser.py` or any of your previous F5 modules. It adds one router import and registration to `app/api/main.py`, without touching the Dashboard, other endpoints, or existing parsers.

## Windows PowerShell (project root)

```powershell
.\.venv-win\Scripts\python.exe .\f5_phase1_compat_patch\scripts\install_f5_compat.py "." --dry-run
.\.venv-win\Scripts\python.exe .\f5_phase1_compat_patch\scripts\install_f5_compat.py "."
.\.venv-win\Scripts\python.exe -m pytest -q .\f5_phase1_compat_patch\tests
```

Start backend using `python -m uvicorn app.api.main:app --host 127.0.0.1 --port 8000 --reload`. Test POST `/api/v1/analyze/f5/phase1` using `-F "file=@f5_phase1_compat_patch/examples/f5_phase1_sample.conf"`. The global vendor selector and PDF are not integrated yet.

### Rollback

```powershell
.\.venv-win\Scripts\python.exe .\f5_phase1_compat_patch\scripts\install_f5_compat.py "." --rollback
```

The installer refuses unsupported API layouts, existing conflicting add-on files, or a previously installed F5 Phase 1 router that could create duplicate API endpoints. Test it on a backed-up copy of your actual project.
