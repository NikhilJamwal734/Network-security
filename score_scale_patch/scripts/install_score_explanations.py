"""Install brief review-score and severity explanations in dashboard and PDF.

From the backend project root:
  .\\.venv-win\\Scripts\\python.exe score_scale_patch\\scripts\\install_score_explanations.py

May also pass an explicit frontend directory as the only positional argument.
Uses precise anchors; refuses unexpected layouts before writing anything.
Re-running makes no duplicate changes. Existing files get .before_scale_help.bak backups.
"""
from __future__ import annotations

from pathlib import Path
import shutil
import sys

PACKAGE = Path(__file__).resolve().parents[1]
DEFAULT_FRONTEND = PACKAGE.parent / "frontend"
NEW_COMPONENT = PACKAGE / "frontend_patch/src/components/AssessmentInterpretation.tsx"
NEW_CSS = PACKAGE / "frontend_patch/src/components/AssessmentInterpretation.css"
MARK_SCORE = "<ReviewScoreExplanation"
MARK_SEVERITY = "<SeverityExplanation"
MARK_PDF = "Review score (0-100):"


def patch_score(src: str) -> str:
    if MARK_SCORE in src:
        if 'from "./AssessmentInterpretation"' not in src:
            raise ValueError("Score explanation exists without recognized import")
        return src
    if "function AdvancedAssessmentPanel" not in src:
        raise ValueError("Unrecognized AdvancedAssessmentPanel component")
    anchor = '<small>Maximum {score.maximum}/100 while coverage is incomplete</small>'
    if src.count(anchor) != 1:
        raise ValueError("Provisional review score card not found exactly once")
    src = 'import { ReviewScoreExplanation } from "./AssessmentInterpretation";\n' + src
    src = src.replace(anchor, anchor + '\n          <ReviewScoreExplanation maximum={score.maximum} capped={score.capped_for_incomplete_coverage} />', 1)
    return src


def patch_severity(src: str) -> str:
    if MARK_SEVERITY in src:
        if 'from "./AssessmentInterpretation"' not in src:
            raise ValueError("Severity explanation exists without recognized import")
        return src
    if "function UniversalSeverityChart" not in src:
        raise ValueError("Unrecognized universal severity chart component")
    # The chart has a single legend/explanation slot on the right.
    anchor = '<ul className="usc-legend" aria-label="Severity counts">'
    if src.count(anchor) != 1:
        raise ValueError("Severity legend not found exactly once")
    src = 'import { SeverityExplanation } from "./AssessmentInterpretation";\n' + src
    src = src.replace(anchor, '<SeverityExplanation />\n        ' + anchor, 1)
    return src


def patch_pdf(src: str) -> str:
    if MARK_PDF in src:
        return src
    start = '  text("SEVERITY BREAKDOWN",'
    if src.count(start) != 1:
        raise ValueError("Professional PDF severity section not recognized")
    # Replace the existing provisional-score footnote when present. Keep
    # platform-specific legacy security score untouched.
    src = src.replace(
        '* Review score is provisional, based on implemented checks, and may be capped for missing coverage.',
        'Review score (0-100): higher means fewer concerns found in assessed checks. Missing coverage may cap this provisional indicator; it is not a security guarantee.',
    )
    if MARK_PDF not in src:
        raise ValueError("Professional PDF score footnote not recognized")
    explanation = (
        '  text("Severity indicates how serious each finding is, not another numeric score. " +\n'
        '    "Scale: Info -> Low -> Medium -> High -> Critical; Unknown is unclassified.", {\n'
        '    size: 8.1, color: COLORS.muted, spaceAfter: 9,\n'
        '  });\n'
    )
    src = src.replace(start, explanation + start, 1)
    return src


def install(frontend: Path) -> list[str]:
    if not (frontend / "package.json").is_file():
        raise ValueError(f"React frontend not found: {frontend} (missing package.json)")
    changes: dict[Path, bytes] = {}
    actions = (
        ("src/components/AdvancedAssessmentPanel.tsx", patch_score),
        ("src/components/UniversalSeverityChart.tsx", patch_severity),
        ("src/utils/normalizedPdf.ts", patch_pdf),
    )
    # All changes are calculated before any file is written.
    for relative, func in actions:
        path = frontend / relative
        if not path.is_file():
            raise ValueError(f"Expected frontend file not found: {relative}. No changes were made.")
        old = path.read_text(encoding="utf-8-sig")
        new = func(old)
        if old != new:
            changes[path] = new.encode("utf-8")
    for path, source in (
        (frontend / "src/components/AssessmentInterpretation.tsx", NEW_COMPONENT),
        (frontend / "src/components/AssessmentInterpretation.css", NEW_CSS),
    ):
        proposed = source.read_bytes()
        if not path.exists() or path.read_bytes() != proposed:
            changes[path] = proposed
    for path in changes:
        if path.is_file():
            backup = path.with_name(path.name + ".before_scale_help.bak")
            if not backup.exists():
                shutil.copy2(path, backup)
    for path, value in changes.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(value)
    return [f"Updated: {path.relative_to(frontend)}" for path in changes]


if __name__ == "__main__":
    if len(sys.argv) > 2:
        sys.exit("Usage: install_score_explanations.py [frontend-directory]")
    target = (Path(sys.argv[1]) if len(sys.argv) == 2 else DEFAULT_FRONTEND).resolve()
    try:
        results = install(target)
    except (ValueError, OSError) as exc:
        sys.exit(f"ERROR: {exc}")
    print("\n".join(results) if results else "Already installed: score and severity explanations")
    print("Next: cd frontend; npm run build")
