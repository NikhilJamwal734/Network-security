Dashboard Review Heading Accents (visual-only patch)

What is highlighted:
  Report accuracy checks                  (aqua)
  Vendor-specific configuration review    (violet)
  Rule correlation and conflict review    (coral)
  Correlation evidence and ordering review (amber)
  Service groups & IPv6                  (blue)
  NAT, routing & reachability             (emerald)
  Configuration review / Visible configuration evidence (rose)

Only these files are affected:
  frontend/src/pages/UniversalAnalysis.tsx (one CSS import added)
  frontend/src/pages/ReviewHeadingAccents.css (new file)

No backend/PDF/Findings page changes. The patch does not add verbose content.
It is compatible with the previous general dashboard heading highlights patch,
but does not require it.

From the root of your project in Windows PowerShell:
  Expand-Archive -LiteralPath "$env:USERPROFILE\Downloads\Dashboard-Specific-Review-Heading-Accents.zip" -DestinationPath "." -Force
  .\.venv-win\Scripts\python.exe .\dashboard_review_heading_accents\scripts\install_review_heading_accents.py ".\frontend"
  .\.venv-win\Scripts\python.exe -m unittest discover -s .\dashboard_review_heading_accents\tests -p "test_*.py" -v
  cd frontend
  npm run build
  npm run dev

From project root to rollback:
  .\.venv-win\Scripts\python.exe .\dashboard_review_heading_accents\scripts\rollback_review_heading_accents.py ".\frontend"

The installer refuses unrecognized layouts and will not overwrite custom
changes in ReviewHeadingAccents.css.
