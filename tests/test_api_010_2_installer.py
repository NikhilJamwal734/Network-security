from __future__ import annotations

from pathlib import Path
import importlib.util
import tempfile

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / 'scripts/install_api_010_2.py'
spec = importlib.util.spec_from_file_location('api0102_installer', SCRIPT)
installer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(installer)


def sample_project(folder: Path) -> Path:
    p = folder / 'config analyzer'
    contents = {
        'app/api/universal.py': (
            '    _vendor_review: bool = False,\n'
            '            report = {**report, "vendor_review": vendor_review}\n'
        ),
        'app/api/main.py': (
            'from app.api.deep_review import router as deep_review_router\n'
            'app.include_router(deep_review_router)\n'
        ),
    }
    for rel, text in contents.items():
        target = p / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding='utf-8')
    return p


def test_installer_idempotent_and_backup():
    with tempfile.TemporaryDirectory() as d:
        root = sample_project(Path(d))
        changed = installer.install(root)
        assert len(changed) == 5
        assert not installer.install(root)
        assert 'precision_review_router' in (root / 'app/api/main.py').read_text()
        assert '_precision_review: bool = False' in (root / 'app/api/universal.py').read_text()
        assert (root / 'app/api/main.py.before_api0102.bak').is_file()


def test_invalid_layout_no_partial_modifications():
    with tempfile.TemporaryDirectory() as d:
        root = sample_project(Path(d))
        main = root / 'app/api/main.py'
        main.write_text('unknown', encoding='utf-8')
        before = (root / 'app/api/universal.py').read_bytes()
        with pytest.raises(ValueError):
            installer.install(root)
        assert before == (root / 'app/api/universal.py').read_bytes()
        assert not (root / 'app/core/precision_review.py').exists()
