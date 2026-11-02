API-010.3 — Advanced Rule Correlation and Conflict Review
========================================================

This zip contains source code patches and installers, not your complete project.

PREREQUISITES
- API-010.2.1 installed (precision review already working).
- Project root: C:\IoT\Information security\project 2\config analyzer
- Python environment: .venv-win
- The green sidebar styling was previously removed; this package does NOT alter it.

1. EXTRACT (PowerShell):
   cd "C:\IoT\Information security\project 2\config analyzer"
   Expand-Archive -LiteralPath "$env:USERPROFILE\Downloads\API-010.3-Rule-Correlation.zip" -DestinationPath "." -Force

2. BACKEND INSTALL:
   .\.venv-win\Scripts\python.exe .\api0103_patch\scripts\install_api_010_3.py "."

3. FRONTEND INSTALL:
   .\.venv-win\Scripts\python.exe .\api0103_patch\frontend_patch\scripts\install_api_010_3_frontend.py ".\frontend"

4. VERIFY BACKEND:
   .\.venv-win\Scripts\python.exe -m pytest -q tests\test_api_010_3_correlation.py tests\test_api_010_3_installer.py
   .\.venv-win\Scripts\python.exe -m pytest -q

5. FRONTEND:
   cd frontend
   npm run build
   npm run dev

6. RESTART BACKEND (a separate terminal, after Ctrl+C):
   cd "C:\IoT\Information security\project 2\config analyzer"
   .\.venv-win\Scripts\python.exe -m uvicorn app.api.main:app --reload --host 127.0.0.1 --port 8000

7. CHECK SWAGGER: http://127.0.0.1:8000/docs
   New endpoint: POST /api/v1/analyze/rule-correlation

8. TEST: upload a file for each platform, inspect "Rule correlation and conflict review",
   then Download PDF to see its matching appendix.

IMPORTANT
- The new module does NOT alter scoring, findings, severity charts or prior endpoints.
- Everything is advisory and correlation is subset only. Unassessed syntax is not guessed.
- Prior backend 0102.1 tests may still require the route-introspection fix described in chat.
- Your project has NOT been compiled or regression-tested by this package author on Windows;
  follow local tests and share their actual output.
- Installers create .before_api0103.bak for modified existing files.
- The installers are idempotent. Passing "." avoids earlier project-root path mistakes.
- If a file structure is not recognized, installers fail before modifying anything.

ROLLBACK
Stop frontend/backend, then restore each .before_api0103.bak to its original
name for these files (if modified):
  app/api/main.py
  frontend/src/api/universal.ts
  frontend/src/pages/UniversalAnalysis.tsx
  frontend/src/utils/normalizedPdf.ts
Then remove new files:
  app/api/rule_correlation.py
  app/core/rule_correlation.py
  frontend/src/components/RuleCorrelationPanel.tsx
  frontend/src/components/RuleCorrelationPanel.css
Restart both servers. Avoid overwriting any later intentional edits to these files.
