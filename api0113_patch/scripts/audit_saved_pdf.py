"""Optional independent saved-PDF readability and text-section inspection.

Usage: python audit_saved_pdf.py path/to/export.pdf --require-11-3
Install: python -m pip install pypdf
This does not assert exact visual layout or security analysis correctness.
"""
from __future__ import annotations
import argparse
from pathlib import Path
import sys


def audit(path: Path, *, require_113: bool = False) -> dict:
    try:
        from pypdf import PdfReader
    except ImportError as exc:
        raise RuntimeError('Install optional dependency: python -m pip install pypdf') from exc
    data=path.read_bytes()
    if not data.startswith(b'%PDF-') or b'%%EOF' not in data[-1024:]:
        raise ValueError('Missing PDF header or end-of-file marker')
    reader=PdfReader(str(path),strict=True)
    if reader.is_encrypted: raise ValueError('Encrypted PDF cannot be inspected without authorization')
    if not reader.pages: raise ValueError('PDF has no pages')
    all_text=[]
    page_texts=[]
    for index,page in enumerate(reader.pages,1):
        text=(page.extract_text() or '')
        page_texts.append(text)
        all_text.append(text)
    extracted='\n'.join(all_text).upper()
    expected=['ASSESSMENT COVERAGE','REPORT INTERPRETATION']
    if require_113: expected.append('PDF EXPORT READINESS')
    missing=[item for item in expected if item not in extracted]
    issues=[f'Missing required heading: {h}' for h in missing]
    if not extracted.strip(): issues.append('No extractable PDF text found')
    # PDF contains page numbers; tolerate text extraction rearranging whitespace.
    for i,txt in enumerate(page_texts,1):
        if f'Page {i} of {len(reader.pages)}' not in txt:
            issues.append(f'Page {i}: page-count footer not found in extractable text')
    return {
        'passed':not issues,'page_count':len(reader.pages),'file_bytes':len(data),
        'issues':issues,
        'limitations':[
            'Extracted text and page structure do not prove accurate fonts, clipping or rendered appearance.',
            'PDF content cannot prove the correctness of firewall or IDS findings.',
        ],
    }


def main() -> int:
    parser=argparse.ArgumentParser(description='Validate a saved PDF with independent pypdf parsing')
    parser.add_argument('pdf',type=Path)
    parser.add_argument('--require-11-3',action='store_true')
    args=parser.parse_args()
    try: result=audit(args.pdf,require_113=args.require_11_3)
    except (OSError, ValueError, RuntimeError) as exc:
        print('FAILED:',exc,file=sys.stderr)
        return 2
    print(f'PDF parsed: {result["page_count"]} pages, {result["file_bytes"]} bytes')
    for issue in result['issues']: print('  -',issue)
    print('PASS (structural/text checks only)' if result['passed'] else 'FAIL (inspect details)')
    return 0 if result['passed'] else 1


if __name__=='__main__': sys.exit(main())
