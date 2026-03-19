import json
import shutil
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory


APP_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = APP_ROOT.parent.parent
if str(APP_ROOT) not in sys.path:
    sys.path.insert(0, str(APP_ROOT))

from src.cli.main import build_all_artifacts


CASE_002_DIR = REPO_ROOT / "cases" / "web" / "case-002"


class DocumentControlOptionalTest(unittest.TestCase):
    def test_case_build_succeeds_without_document_control_yaml(self) -> None:
        temp_parent = REPO_ROOT / "cases" / "web"
        with TemporaryDirectory(dir=temp_parent) as temp_root:
            working_case = Path(temp_root) / "case-optional-document-control"
            shutil.copytree(CASE_002_DIR, working_case)
            (working_case / "input" / "document-control.yaml").unlink()

            result = build_all_artifacts(working_case)
            payload_path = Path(result["payload_path"])
            html_path = Path(result["html_path"])

            payload = json.loads(payload_path.read_text(encoding="utf-8"))
            preview_html = html_path.read_text(encoding="utf-8")

            self.assertEqual(payload["document_control"], {"history": [], "approvals": []})
            self.assertTrue(html_path.exists())
            self.assertNotIn("Initial multi-finding release", preview_html)
            self.assertNotIn("sample review approval", preview_html)


if __name__ == "__main__":
    unittest.main()
