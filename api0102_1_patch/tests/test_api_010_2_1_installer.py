"""Safe, idempotent installer smoke tests independent of the user's project."""
from __future__ import annotations

from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
import shutil

import pytest

_SCRIPT = Path(__file__).resolve().parents[1] / 'scripts/install_api_010_2_1.py'
_spec = spec_from_file_location('installer_api0102_1', _SCRIPT)
installer = module_from_spec(_spec)
_spec.loader.exec_module(installer)


def _make_project(tmp_path: Path) -> Path:
    root = tmp_path / 'project'
    (root / 'app/core').mkdir(parents=True)
    (root / 'app/api').mkdir(parents=True)
    (root / 'frontend/src/styles').mkdir(parents=True)
    # API-010.2's actual return signature is the patch anchor.
    (root / 'app/core/precision_review.py').write_text(
        'def refine_vendor_review(platform, lines, review):\n'
        '    result = dict(review)\n'
        '    return result\n', encoding='utf-8')
    (root / 'app/api/precision_review.py').write_text('router = object()\n', encoding='utf-8')
    (root / 'frontend/src/styles/Sidebar.css').write_text('/* existing theme */', encoding='utf-8')
    return root


def test_installer_creates_only_expected_files(tmp_path):
    root = _make_project(tmp_path)
    changed = installer.install(root)
    assert sorted(changed) == [
        'app/core/precision_enhancements.py', 'app/core/precision_review.py',
        'tests/test_api_010_2_1_enhancements.py']
    updated = (root / 'app/core/precision_review.py').read_text()
    assert 'return augment_precision_review(platform, lines, result)' in updated
    assert (root / 'frontend/src/styles/Sidebar.css').read_text() == '/* existing theme */'
    assert (root / 'app/core/precision_review.py.before_api0102_1.bak').is_file()


def test_installer_idempotent_and_preserves_backups(tmp_path):
    root = _make_project(tmp_path)
    assert installer.install(root)
    backup = root / 'app/core/precision_review.py.before_api0102_1.bak'
    old = backup.read_bytes()
    assert installer.install(root) == []
    assert backup.read_bytes() == old


def test_preflight_rejects_unknown_layout_without_modifying_files(tmp_path):
    root = _make_project(tmp_path)
    target = root / 'app/core/precision_review.py'
    target.write_text('def refine_vendor_review(platform, lines, review):\n    return {}\n')
    original = target.read_bytes()
    with pytest.raises(ValueError, match='Unknown API-010.2'):
        installer.install(root)
    assert target.read_bytes() == original
    assert not (root / 'app/core/precision_enhancements.py').exists()


def test_preflight_requires_previous_milestone(tmp_path):
    root = _make_project(tmp_path)
    (root / 'app/api/precision_review.py').unlink()
    with pytest.raises(ValueError, match='API-010.2 must be installed'):
        installer.install(root)
    assert not (root / 'app/core/precision_enhancements.py').exists()


def test_partial_installer_replay_restores_missing_module(tmp_path):
    root = _make_project(tmp_path)
    installer.install(root)
    newfile = root / 'app/core/precision_enhancements.py'
    newfile.unlink()
    changes = installer.install(root)
    assert changes == ['app/core/precision_enhancements.py']
