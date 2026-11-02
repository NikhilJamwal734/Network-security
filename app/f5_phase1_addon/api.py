"""Standalone F5 BIG-IP phase-1 endpoint; intentionally does not route through Cisco/IDS pipeline."""
from __future__ import annotations
from typing import Any
from fastapi import APIRouter, File, Form, HTTPException, UploadFile
from app.f5_phase1_addon.checks import analyze
from app.f5_phase5_addon.assurance import build_assurance
from app.f5_phase2_addon.review import extend_report, EvidenceError
from app.f5_phase1_addon.parser import ParseError, parse
from app.core.input_hardening import MAX_CONFIG_BYTES, InputProblem, inspect_config_bytes

router = APIRouter(tags=['F5 BIG-IP Phase 1'])


@router.post('/api/v1/analyze/f5/phase1')
async def analyze_f5_phase1(file: UploadFile = File(...), evidence_json: str | None = Form(None)) -> dict[str, Any]:
    # F5 has its own fixed route because the installed vendor allowlist does not
    # yet contain f5_bigip. Reuse API-011.6 byte, filename and text validation.
    try:
        raw = await file.read(MAX_CONFIG_BYTES + 1)
        validation = inspect_config_bytes(raw, filename=file.filename, platform=None)
    except InputProblem as exc:
        raise HTTPException(status_code=exc.status_code, detail={'code': exc.code, 'message': exc.message}) from None
    finally:
        await file.close()
    try:
        decoded_text = raw.decode('utf-8-sig')
        objects = parse(decoded_text)
    except ParseError as exc:
        raise HTTPException(status_code=422, detail={'code': 'invalid_f5_config', 'message': str(exc)}) from None
    if not objects:
        raise HTTPException(status_code=422, detail={'code': 'unsupported_f5_export', 'message': 'No supported F5 LTM profiles or virtual servers were identified.'})
    report = analyze(objects)
    try:
        report = extend_report(report, objects, decoded_text, evidence_json)
    except EvidenceError as exc:
        raise HTTPException(status_code=422, detail={'code': 'invalid_f5_evidence', 'message': str(exc)}) from None
    report['f5_assurance_review'] = build_assurance(objects, decoded_text, report)
    return {**report, 'input_security_review': validation}
