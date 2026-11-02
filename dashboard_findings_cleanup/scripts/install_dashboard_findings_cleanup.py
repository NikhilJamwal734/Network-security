"""Remove duplicate finding-detail cards from dashboard views only.

Supports API-011.2 multi-platform dashboard and older Cisco ASA dashboard.
Does not modify Findings pages, report data, backends, CSS, or PDF rendering.
"""
from __future__ import annotations

from pathlib import Path
import re
import shutil
import sys

BACKUP_SUFFIX = ".before_dashboard_findings_cleanup.bak"
MODERN = Path("src/pages/UniversalAnalysis.tsx")
LEGACY = Path("src/pages/Dashboard.tsx")
SECTION_TOKEN = re.compile(r"</?section\b[^>]*>", flags=re.I)
HEADING = re.compile(r"<h2(?:\s[^>]*)?>\s*Security findings\s*</h2>", flags=re.I)
LEGACY_PANEL = re.compile(r'<section\b[^>]*className=["\'][^"\']*\bfindings-panel\b[^"\']*["\'][^>]*>', flags=re.I)


def _section_range(src: str, start_tag: int) -> tuple[int, int]:
    """Find the entire JSX section, respecting nested section elements."""
    matches = list(SECTION_TOKEN.finditer(src))
    opening = next((i for i, m in enumerate(matches) if m.start() == start_tag), None)
    if opening is None or matches[opening].group().startswith("</"):
        raise ValueError("Unable to identify the target JSX section")
    depth = 0
    close = None
    for m in matches[opening:]:
        depth += -1 if m.group().startswith("</") else 1
        if depth == 0:
            close = m.end()
            break
    if close is None:
        raise ValueError("Unbalanced JSX section tags; no changes made")
    line_start = src.rfind("\n", 0, start_tag) + 1
    if src[line_start:start_tag].strip():
        raise ValueError("Unexpected JSX section formatting; no changes made")
    # Do not remove preceding/following non-whitespace JSX.
    rest = src[close:]
    line_tail = re.match(r"[ \t]*(?:\r?\n)", rest)
    if not line_tail:
        raise ValueError("Unexpected closing section formatting; no changes made")
    end = close + line_tail.end()
    # Remove a single following blank line so adjacent sections retain normal spacing.
    blank = re.match(r"(?:[ \t]*\r?\n)", src[end:])
    if blank:
        end += blank.end()
    return line_start, end


def _modern_section(src: str) -> tuple[int, int] | None:
    matches = list(HEADING.finditer(src))
    if not matches:
        return None
    if len(matches) != 1:
        raise ValueError("Multiple Security findings headings; refusing ambiguous edit")
    at = matches[0].start()
    opens = [m for m in SECTION_TOKEN.finditer(src[:at]) if not m.group().startswith("</")]
    for m in reversed(opens):
        start, end = _section_range(src, m.start())
        if start <= at < end:
            section = src[start:end]
            if 'className="ua-panel"' not in m.group():
                raise ValueError("Security findings heading isn't in the expected dashboard panel")
            if 'visibleFindings.map(' not in section or '<h2>Analysis coverage</h2>' in section:
                raise ValueError("Unexpected Security findings structure; no changes made")
            return start, end
    raise ValueError("Could not find enclosing Security findings panel")


def patch_modern(src: str) -> str:
    span = _modern_section(src)
    if span is None:
        return src
    src = src[:span[0]] + src[span[1]:]
    # These become unused when the dashboard's duplicate details are removed.
    edits = [
        (r'(?m)^[ \t]*const \[severityFilter, setSeverityFilter\] = useState<Severity \| "all">\("all"\);\r?\n', 1, "severity filter state"),
        (r'(?m)^[ \t]*setSeverityFilter\("all"\);\r?\n', 2, "severity filter reset"),
        (r'(?ms)^[ \t]*const visibleFindings = report\?\.findings\.filter\(\(finding\) =>\s*severityFilter === "all" \|\| finding\.severity === severityFilter\s*\) \?\? \[\];\r?\n(?:\r?\n)?', 1, "filtered findings mapping"),
    ]
    for pattern, count, label in edits:
        src, n = re.subn(pattern, "", src)
        if n != count:
            raise ValueError(f"Unexpected {label} structure ({n}/{count}); no changes made")
    if re.search(r'\b(severityFilter|setSeverityFilter|visibleFindings)\b', src):
        raise ValueError("Unremoved dashboard finding state references; no changes made")
    return src


def patch_legacy(src: str) -> str:
    matches = list(LEGACY_PANEL.finditer(src))
    if not matches:
        return src
    if len(matches) != 1:
        raise ValueError("Multiple legacy findings panels; refusing ambiguous edit")
    start, end = _section_range(src, matches[0].start())
    section = src[start:end]
    if '<FindingsOverview' not in section:
        raise ValueError("Legacy findings panel has unexpected contents; no changes made")
    src = src[:start] + src[end:]
    src, n = re.subn(r'(?m)^import FindingsOverview from ["\']\.\./components/FindingsOverview["\'];\r?\n', '', src)
    if n != 1:
        raise ValueError("Expected exactly one FindingsOverview import")
    if '<FindingsOverview' in src:
        raise ValueError("FindingsOverview used elsewhere; no changes made")
    # Preserve existing prop contract to avoid changing App.tsx; only stop destructuring
    # onViewFindings if the removed button was its sole use.
    if src.count('onViewFindings') == 2:
        src = re.sub(r'Dashboard\(\{\s*report,\s*onViewFindings\s*\}:',
                     'Dashboard({report}:', src, count=1)
    return src


def _decode(original: bytes) -> tuple[str, bytes]:
    bom = b"\xef\xbb\xbf" if original.startswith(b"\xef\xbb\xbf") else b""
    return original.decode("utf-8-sig"), bom


def plan(root: Path) -> dict[Path, bytes]:
    root = root.resolve()
    if not (root / 'package.json').is_file():
        raise ValueError(f"Expected a React frontend root containing package.json: {root}")
    candidates = [(MODERN, patch_modern), (LEGACY, patch_legacy)]
    if not any((root / rel).is_file() for rel, _ in candidates):
        raise ValueError("Neither known Dashboard component exists; no files modified")
    changes: dict[Path, bytes] = {}
    for rel, fn in candidates:
        path = root / rel
        if not path.is_file():
            continue
        original = path.read_bytes()
        src, bom = _decode(original)
        result = fn(src)
        out = bom + result.encode('utf-8')
        if out != original:
            changes[path] = out
    return changes


def install(root: Path) -> list[str]:
    root = root.resolve()
    changes = plan(root)  # Validate all edits before writing either file.
    for path in changes:
        backup = path.with_name(path.name + BACKUP_SUFFIX)
        if backup.exists() and backup.read_bytes() == changes[path]:
            raise ValueError(f"Backup appears overwritten with updated content: {backup}")
    for path, content in changes.items():
        backup = path.with_name(path.name + BACKUP_SUFFIX)
        if not backup.exists():
            shutil.copy2(path, backup)
        path.write_bytes(content)
    return [str(path.relative_to(root)) for path in changes]


if __name__ == '__main__':
    if len(sys.argv) > 2:
        sys.exit('Usage: install_dashboard_findings_cleanup.py [frontend-directory]')
    frontend = Path(sys.argv[1]) if len(sys.argv) == 2 else Path.cwd()/'frontend'
    try:
        changed = install(frontend)
    except (OSError, ValueError, UnicodeError) as exc:
        sys.exit(f"ERROR: {exc}")
    if changed:
        print('Removed duplicate dashboard findings from:')
        for rel in changed:
            print('  ' + rel)
    else:
        print('Dashboard finding panels are already absent; no files changed.')
