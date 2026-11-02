# Score and severity interpretation — frontend-only update

Adds two short explanations in the analyzer for **all four platforms** (Cisco ASA, FortiOS, Snort and Suricata).

- Provisional review score: findings-based limited configuration review; 0–100, higher means fewer concerns in assessed checks; cap shown when coverage is incomplete.
- Finding severity: priority of individual findings, not a second number; Info → Low → Medium → High → Critical; Unknown is unclassified.
- The same explanations appear in the professional shared PDF report.

## Installation (Windows PowerShell)

Open the project root `C:\IoT\Information security\project 2\config analyzer`:

```powershell
Expand-Archive -LiteralPath "$env:USERPROFILE\Downloads\Analyzer-Score-Severity-Explanations.zip" -DestinationPath . -Force
.\.venv-win\Scripts\python.exe .\score_scale_patch\scripts\install_score_explanations.py
cd frontend
npm run build
npm run dev
```

The installer updates three existing files and creates the new `AssessmentInterpretation.tsx` and `.css`. It backs up any existing file that it modifies with `.before_scale_help.bak`. It is safe to rerun. An unfamiliar layout makes it stop before changing files.

Only UI/PDF wording is changed; backend scoring, severity categories, reports and API responses are untouched. No arbitrary 0–20/20–40 etc. grade boundaries are invented.

## Rollback

Restore files from `*.before_scale_help.bak` and remove `src/components/AssessmentInterpretation.tsx` and `AssessmentInterpretation.css` if this installation added them. If you don't have backups for a file, leave it unchanged.
