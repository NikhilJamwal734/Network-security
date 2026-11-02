from pathlib import Path
import sys
import pytest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
sys.path.insert(0,str(ROOT.parent))

@pytest.fixture
def project(tmp_path):
    root=tmp_path/'project'
    files={
      'app/api/main.py': (
       'from app.api.pipeline_validation import router as pipeline_validation_router\n'
       'from app.api.hardened_analysis import router as hardened_analysis_router\n'
       'app.include_router(pipeline_validation_router)\n'
       'app.include_router(hardened_analysis_router)\n'),
      'app/api/hardened_analysis.py':'# installed hardened endpoint\n',
      'app/api/pipeline_validation.py':'# installed pipeline route\n',
      'app/core/input_hardening.py':'# installed input gate\n',
      'app/core/pipeline_validation.py':'# installed pipeline review\n',
      'frontend/package.json':'{"scripts":{"build":"tsc -b && vite build"}}',
      'frontend/src/api/universal.ts':'const url = "/api/v1/analyze/hardened";',
      'frontend/src/utils/normalizedPdf.ts':'// normalized PDF source\n',
      'frontend/src/pages/UniversalAnalysis.tsx':'// unique dashboard untouched\n',
    }
    for rel,data in files.items():
        dest=root/rel;dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes(data.encode('utf-8'))
    return root
