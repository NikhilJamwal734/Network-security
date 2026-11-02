"""Lightweight installer contract tests; no app dependencies needed."""
from __future__ import annotations

from pathlib import Path
import importlib.util
import tempfile
import unittest

INSTALLER = Path(__file__).resolve().parents[1] / "scripts/install_professional_pdf.py"
SOURCE = Path(__file__).resolve().parents[1] / "frontend_patch/src/utils/normalizedPdf.ts"


class ProfessionalPdfInstallerTests(unittest.TestCase):
    def _module(self):
        spec = importlib.util.spec_from_file_location("professional_pdf_installer", INSTALLER)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def _fixture(self, root: Path):
        path = root / "src/utils/normalizedPdf.ts"
        path.parent.mkdir(parents=True)
        (root / "package.json").write_text("{}", encoding="utf-8")
        path.write_text('''import type { NormalizedReport } from "../api/universal";
export function normalizedFilename(name: string) { return name; }
export function downloadNormalizedJson() { return; }
export async function downloadNormalizedPdf() { return; }
''', encoding="utf-8")
        return path

    def test_installs_and_keeps_backup(self):
        module = self._module()
        with tempfile.TemporaryDirectory() as temp:
            front = Path(temp)
            target = self._fixture(front)
            original = target.read_bytes()
            module.FRONTEND = front
            module.DESTINATION = target
            module.BACKUP = target.with_name(target.name + ".before_professional_layout.bak")
            module.SOURCE = SOURCE
            self.assertIn("Updated", module.install())
            self.assertEqual(target.read_bytes(), SOURCE.read_bytes())
            self.assertEqual(module.BACKUP.read_bytes(), original)
            self.assertIn("Already installed", module.install())
            self.assertEqual(module.BACKUP.read_bytes(), original)

    def test_fails_closed_on_unknown_existing_code(self):
        module = self._module()
        with tempfile.TemporaryDirectory() as temp:
            front = Path(temp)
            target = self._fixture(front)
            target.write_text("const unrelated = 1;", encoding="utf-8")
            module.FRONTEND = front
            module.DESTINATION = target
            module.BACKUP = target.with_suffix(".bak")
            with self.assertRaisesRegex(RuntimeError, "differs"):
                module.install()
            self.assertFalse(module.BACKUP.exists())

    def test_lazily_imports_jspdf_and_preserves_api(self):
        source = SOURCE.read_text(encoding="utf-8")
        self.assertIn('await import("jspdf")', source)
        self.assertIn('import type { jsPDF } from "jspdf";', source)
        self.assertNotIn('import { jsPDF } from "jspdf";', source)
        self.assertIn("export async function downloadNormalizedPdf", source)
        self.assertIn("export function downloadNormalizedJson", source)
        self.assertIn("F-${String(i + 1).padStart(3, \"0\")}", source)
        self.assertIn("Page ${p} of ${totalPages}", source)

    def test_reporting_limitation_is_present(self):
        source = SOURCE.read_text(encoding="utf-8")
        self.assertIn("does not establish", source)
        self.assertIn("NOT ASSESSED", source)
        self.assertIn("Provisional review score", source)


if __name__ == "__main__":
    unittest.main()
