from __future__ import annotations
from pathlib import Path
from importlib.util import module_from_spec, spec_from_file_location
import pytest

ROOT = Path(__file__).resolve().parents[1]


def load(rel, name):
    spec = spec_from_file_location(name, ROOT / rel)
    assert spec and spec.loader
    mod = module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def project(tmp_path):
    root = tmp_path / 'project'
    for rel, content in {
        'app/api/main.py': (
            'from app.api.pdf_export_readiness import router as pdf_export_readiness_router\n'
            'from app.api.pipeline_validation import router as pipeline_validation_router\n'
            'app.include_router(pdf_export_readiness_router)\n'
            'app.include_router(pipeline_validation_router)\n'
        ),
        'app/api/pipeline_validation.py': '# installed API-011.4\n',
        'app/core/pipeline_validation.py': '# installed API-011.4\n',
        'frontend/package.json': '{"name":"frontend"}',
        'frontend/src/api/universal.ts': (
            'export const endpoint = "/api/v1/analyze/pipeline-validation";\n'
            'interface Payload {\n  pipeline_validation_review?: PipelineValidationReview;\n}\n'
            'export interface PipelineValidationReview { version: string };\n'
        ),
        'frontend/src/utils/normalizedPdf.ts': (
            'const text = (s: string, options?: unknown) => {};\n'
            'const section = (s: string) => {};\n'
            'const ensure = (n: number) => {};\n'
            'const label = (v: string) => v;\n'
            'const COLORS = { blue: "#07f", muted: "#999" };\n'
            'function make(report: any) {\n'
            '  section("Assessment coverage");\n'
            '}\n'
        ),
    }.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content.encode('utf-8'))
    return root
