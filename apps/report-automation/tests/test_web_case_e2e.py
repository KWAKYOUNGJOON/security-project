import json
import sys
import unittest
from pathlib import Path


APP_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = APP_ROOT.parent.parent
if str(APP_ROOT) not in sys.path:
    sys.path.insert(0, str(APP_ROOT))

from src.cli.main import build_all_artifacts


CASE_PATH = Path("cases/web/case-001")


class WebCaseE2ETest(unittest.TestCase):
    def test_build_all_keeps_legacy_case_001_compatible(self) -> None:
        result = build_all_artifacts(CASE_PATH)

        normalized_path = Path(result["normalized_path"])
        normalized_findings_path = Path(result["normalized_findings_path"])
        payload_path = Path(result["payload_path"])
        html_path = Path(result["html_path"])
        validation_path = Path(result["validation_path"])
        provenance_path = Path(result["provenance_path"])

        self.assertTrue(normalized_path.exists())
        self.assertTrue(normalized_findings_path.exists())
        self.assertTrue(payload_path.exists())
        self.assertTrue(html_path.exists())
        self.assertTrue(validation_path.exists())
        self.assertTrue(provenance_path.exists())

        normalized = json.loads(normalized_path.read_text(encoding="utf-8"))
        normalized_bundle = json.loads(normalized_findings_path.read_text(encoding="utf-8"))
        payload = json.loads(payload_path.read_text(encoding="utf-8"))
        preview_html = html_path.read_text(encoding="utf-8")

        self.assertEqual(normalized_path.name, "normalized-finding.json")
        self.assertEqual(normalized["finding_id"], "VUL-001")
        self.assertEqual(normalized_bundle["findings"], [normalized])
        self.assertEqual(normalized_bundle["case_id"], "web-case-001")
        self.assertEqual(payload["findings"][0]["code"], "AU")
        self.assertEqual(payload["findings"][0]["canonical_key"], "automated_attack")
        self.assertEqual(payload["document"]["date"], "2026-03-19")
        self.assertEqual(payload["engagement"]["customer_name"], "Example Customer")
        self.assertEqual(payload["tool_inventory"], [])
        self.assertEqual(payload["document_control"]["history"][0]["change"], "초안 작성")
        self.assertIn("로그인 실패 횟수 제한 미흡", preview_html)
        self.assertIn("cases/web/case-001/input/http/request.txt", preview_html)
        self.assertIn("Example Customer", preview_html)
        self.assertNotIn("HexStrike", preview_html)
        self.assertNotIn("Burp Suite", preview_html)


if __name__ == "__main__":
    unittest.main()
