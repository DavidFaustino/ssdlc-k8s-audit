import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from package_audit import package, verify


class PackageTests(unittest.TestCase):
    def test_archive_excludes_evidence_and_detects_modified_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "README.md").write_text("kit")
            (root / "auditlib").mkdir()
            (root / "auditlib" / "core.py").write_text("# library")
            (root / "saidas").mkdir()
            (root / "saidas" / "confidential.json").write_text("CONFIDENTIAL")
            archive = root / "kit.zip"
            package(root, archive)
            with zipfile.ZipFile(archive) as z:
                self.assertFalse(any("confidential" in n for n in z.namelist()))
                z.extractall(root / "copy")
            extracted = root / "copy" / "auditoria-aws"
            self.assertTrue(verify(extracted))
            (extracted / "README.md").write_text("alterado")
            with self.assertRaises(ValueError):
                verify(extracted)


if __name__ == "__main__":
    unittest.main()
