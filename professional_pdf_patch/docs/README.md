# Professional Security PDF Report Layout

This is a **frontend-only** replacement for the normalized PDF renderer in the unified security dashboard. It supports normalized reports for **Cisco ASA, FortiOS, Snort, and Suricata** without changing their findings, scoring, parser behavior, or API responses.

## What the report includes

- Professional navy masthead, cyan accent, visible document reference and UTC timestamp
- Platform identity, file name, detection method, optional hostname
- Executive summary with total findings, risk level, native security score, and separate **provisional** configuration-review score (only when the backend supplies one)
- Severity counts for all six severities (Critical, High, Medium, Low, Info, Unknown)
- Findings register with serial references such as **F-001**, severity tags, and titles
- Matching detailed findings with descriptions, recommendations, finding code/ID, and source line/rule IDs when supplied
- Numbered configuration observations (O-01), with evidence field references
- Coverage (assessed / not assessed), limitations, parser warnings, and methodology notes
- Running headers and **Page X of Y** footers across multipage reports
- Explicit explanation that zero findings and provisional scores do not certify security

The *normalized JSON exporter* and download function names remain unchanged. `jsPDF` is still **lazy-loaded** only when a user requests a PDF. The existing dashboard export buttons need no changes.

No uploaded configuration is executed. All strings are written as PDF text, not parsed as HTML. For PDF readability and safety, individual overly-long fields and very large finding/observation inventories are shortened with explicit notices directing readers to JSON for the full data. The PDF is an explanatory presentation, not a lossless data archive.

## Install in PowerShell

Run these from the **backend project root**:

```powershell
cd "C:\IoT\Information security\project 2\config analyzer"

Expand-Archive `
  -LiteralPath "$env:USERPROFILE\Downloads\Professional-Security-PDF-Report.zip" `
  -DestinationPath "." `
  -Force

.\.venv-win\Scripts\python.exe professional_pdf_patch\scripts\install_professional_pdf.py
```

The installer updates **only**:

`frontend\src\utils\normalizedPdf.ts`

Backup:

`frontend\src\utils\normalizedPdf.ts.before_professional_layout.bak`

Build:

```powershell
cd .\frontend
npm run build
npm run dev
```

Upload any supported configuration and use the existing **Download PDF** button. Open the PDF and check the report reference, indexed findings and page numbering. If your Cisco ASA frontend also exposes a separate **legacy-specific PDF** control, that separate historical generator is intentionally untouched; select the **normalized report PDF** to see this design.

## Rollback

From `frontend`:

```powershell
Copy-Item ".\src\utils\normalizedPdf.ts.before_professional_layout.bak" ".\src\utils\normalizedPdf.ts" -Force
npm run build
```

## Check the package's installer tests

From the backend project root:

```powershell
.\.venv-win\Scripts\python.exe -m unittest discover -s professional_pdf_patch\tests -p "test_*.py" -v
```

They are separate from the backend pytest suite. The backend regression test count should not change because this patch does not modify backend code or tests.

## Limits

- This update changes PDF **presentation**, not security findings or score calculations.
- PDF authoring relies on jsPDF's built-in fonts. Uncommon non-Latin characters may require an embedded compatible font for perfect rendering.
- Original Cisco ASA legacy PDF export is not modified by this patch.
