"""Apply API-009.7 configuration summary + findings spacing polish.

Run from the React frontend directory (the folder containing package.json and src/).
Backs up existing files and appends scoped CSS once. Does not touch backend code.
"""
from __future__ import annotations
from pathlib import Path
import shutil
import sys

MARKER = "/* API-009.7 UI polish: findings spacing */"
CSS = '''
/* API-009.7 UI polish: findings spacing */
.ua-page .ua-findings {
  display: grid;
  gap: 20px;
  margin-top: 20px;
}
.ua-page .ua-finding {
  padding: 22px 24px;
  border-radius: 14px;
}
.ua-page .ua-finding-top {
  gap: 12px;
  margin-bottom: 16px;
}
.ua-page .ua-finding h3 {
  margin: 0 0 14px;
  font-size: 1.06rem;
  line-height: 1.4;
}
.ua-page .ua-finding p {
  margin: 12px 0;
  line-height: 1.75;
}
.ua-page .ua-finding .ua-evidence {
  margin: 20px 0 0;
  padding-top: 14px;
  border-top: 1px solid var(--ua-border, rgba(148,163,184,.22));
}
.ua-page .ua-severities {
  gap: 14px;
}
.ua-page .ua-asa-detail-grid,
.ua-page .ua-asa-visual-grid {
  gap: 20px;
}
.ua-page .ua-asa-subpanel {
  padding: 20px;
}
/* The inventory itself uses five responsive metric cards; let it use panel width. */
.ua-page .ua-asa-detail-grid:has(.ucs-summary) {
  grid-template-columns: minmax(0, 1fr);
}
@media (max-width: 640px) {
  .ua-page .ua-findings { gap: 14px; }
  .ua-page .ua-finding { padding: 17px; }
  .ua-page .ua-asa-subpanel { padding: 16px; }
}
'''


def main() -> int:
    root = Path.cwd()
    expected = [
        root / "package.json",
        root / "src" / "App.tsx",
        root / "src" / "pages" / "UniversalAnalysis.css",
        root / "src" / "pages" / "UnifiedDashboardExtras.css",
        root / "src" / "components" / "ConfigurationSummary.tsx",
    ]
    missing = [str(path.relative_to(root)) for path in expected if not path.is_file()]
    if missing:
        print("ERROR: Run from the merged API-009.7 React frontend. Missing:", file=sys.stderr)
        for item in missing:
            print("  " + item, file=sys.stderr)
        return 2

    stage = root / "api0097_visual_polish" / "src" / "components"
    staged = [stage / "ConfigurationSummary.tsx", stage / "ConfigurationSummary.css"]
    if not all(path.is_file() for path in staged):
        print("ERROR: Package staging files absent. Extract ZIP into frontend root first.", file=sys.stderr)
        return 2

    component = root / "src" / "components" / "ConfigurationSummary.tsx"
    style = root / "src" / "components" / "ConfigurationSummary.css"
    extras = root / "src" / "pages" / "UnifiedDashboardExtras.css"

    for source, target in [(staged[0], component), (staged[1], style)]:
        target.parent.mkdir(parents=True, exist_ok=True)
        data = source.read_bytes()
        if target.exists():
            if target.read_bytes() == data:
                print(f"Already current: {target.relative_to(root)}")
                continue
            backup = target.with_name(target.name + ".before_ui_polish.backup")
            if not backup.exists():
                shutil.copy2(target, backup)
                print(f"Backup: {backup.relative_to(root)}")
        target.write_bytes(data)
        print(f"Installed: {target.relative_to(root)}")

    current_css = extras.read_text(encoding="utf-8-sig")
    if MARKER in current_css:
        print("Spacing styles already installed.")
    else:
        backup = extras.with_name(extras.name + ".before_ui_polish.backup")
        if not backup.exists():
            shutil.copy2(extras, backup)
        extras.write_text(current_css.rstrip() + "\n\n" + CSS, encoding="utf-8")
        print("Added spacing to src/pages/UnifiedDashboardExtras.css")
    print("Done. Run: npm run build")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
