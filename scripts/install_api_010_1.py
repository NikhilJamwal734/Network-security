"""Install API-010.1 opt-in vendor reviews; preserve all previous route formats.

Validates anchors before writing. Creates per-file *.before_api0101.bak backups.
Idempotent. Usage: python scripts/install_api_010_1.py [project-root]
"""
from __future__ import annotations

from pathlib import Path
import shutil
import sys

PACKAGE = Path(__file__).resolve().parents[1]
PROJECT = PACKAGE.parent
SUFFIX = ".before_api0101.bak"


def _replace_once(src: str, old: str, new: str, name: str) -> str:
    if new in src:
        return src
    if src.count(old) != 1:
        raise ValueError(f"Unknown {name} layout (found {src.count(old)} anchors); refusing to edit")
    return src.replace(old, new, 1)


def patch_universal(src: str) -> str:
    src = _replace_once(
        src,
        '    platform: str | None = Query(default=None, max_length=64),\n',
        '    platform: str | None = Query(default=None, max_length=64),\n'
        '    _vendor_review: bool = False,\n',
        'universal request parameters',
    )
    old = '        report = adapter.analyze(lines)\n'
    new = old + '''        if _vendor_review:
            from app.core.vendor_review import (
                review_cisco_asa, review_fortios, review_snort, review_suricata,
            )
            from app.parsers.firewalls.fortios import FortiOSParser
            from app.parsers.ids.snort import SnortParser
            from app.parsers.ids.suricata import SuricataParser
            if selected.platform_id == "cisco_asa":
                vendor_review = review_cisco_asa(lines)
            elif selected.platform_id == "fortios":
                vendor_review = review_fortios(FortiOSParser().parse(lines))
            elif selected.platform_id == "snort":
                vendor_review = review_snort(SnortParser().parse(lines))
            elif selected.platform_id == "suricata":
                vendor_review = review_suricata(SuricataParser().parse(lines))
            else:
                raise RuntimeError("Unsupported vendor review platform")
            report = {**report, "vendor_review": vendor_review}
'''
    return _replace_once(src, old, new, 'universal adapter result')


def patch_main(src: str) -> str:
    src = _replace_once(
        src,
        'from app.api.validated import router as validated_router\n',
        'from app.api.validated import router as validated_router\n'
        'from app.api.deep_review import router as deep_review_router\n',
        'FastAPI imports',
    )
    return _replace_once(
        src,
        'app.include_router(validated_router)\n',
        'app.include_router(validated_router)\napp.include_router(deep_review_router)\n',
        'FastAPI registration',
    )


def plan(project: Path = PROJECT) -> dict[Path, bytes]:
    patchers = {
        project / 'app/api/universal.py': patch_universal,
        project / 'app/api/main.py': patch_main,
    }
    changes: dict[Path, bytes] = {}
    for target, func in patchers.items():
        if not target.is_file():
            raise ValueError(f"API-010.0 source missing: {target}")
        old = target.read_text(encoding='utf-8-sig')
        new = func(old)
        if old != new:
            changes[target] = new.encode('utf-8')
    for relative in ('app/core/vendor_review.py', 'app/api/deep_review.py', 'tests/test_api_010_1_vendor_review.py'):
        source = PACKAGE / relative
        target = project / relative
        if not source.is_file():
            raise ValueError(f"Package source missing: {source}")
        if not target.is_file() or target.read_bytes() != source.read_bytes():
            changes[target] = source.read_bytes()
    return changes


def install(project: Path = PROJECT) -> list[str]:
    changes = plan(project)
    for path, data in changes.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.is_file():
            backup = path.with_name(path.name + SUFFIX)
            if not backup.exists():
                shutil.copy2(path, backup)
        path.write_bytes(data)
    return [str(path.relative_to(project)) for path in changes]


if __name__ == '__main__':
    root = Path(sys.argv[1]).resolve() if len(sys.argv) == 2 else PROJECT
    try:
        changed = install(root)
    except (OSError, ValueError) as exc:
        sys.exit(f"ERROR: {exc}")
    print('Updated backend files:' if changed else 'API-010.1 backend already installed')
    for path in changed:
        print('  ' + path)
    print('Next: python -m pytest -q tests/test_api_010_1_vendor_review.py')
