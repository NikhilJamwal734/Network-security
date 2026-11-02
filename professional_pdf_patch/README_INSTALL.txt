Professional Security PDF Report — frontend-only layout upgrade

From:
  C:\IoT\Information security\project 2\config analyzer

Extract ZIP to current directory, then run:
  .\.venv-win\Scripts\python.exe professional_pdf_patch\scripts\install_professional_pdf.py

Verify:
  cd frontend
  npm run build
  npm run dev

Only changed application file:
  frontend\src\utils\normalizedPdf.ts
Backup:
  frontend\src\utils\normalizedPdf.ts.before_professional_layout.bak

Read professional_pdf_patch\docs\README.md for design, test and rollback details.
