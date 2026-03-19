import json
import sys
import unittest
from pathlib import Path


APP_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = APP_ROOT.parent.parent
if str(APP_ROOT) not in sys.path:
    sys.path.insert(0, str(APP_ROOT))

from src.cli.main import build_all_artifacts


CASE_PATH = Path("cases/web/case-002")


class WebCaseMultiE2ETest(unittest.TestCase):
    def test_build_all_generates_multi_finding_outputs(self) -> None:
        result = build_all_artifacts(CASE_PATH)

        normalized_path = Path(result["normalized_path"])
        normalized_findings_path = Path(result["normalized_findings_path"])
        payload_path = Path(result["payload_path"])
        html_path = Path(result["html_path"])
        validation_path = Path(result["validation_path"])
        provenance_path = Path(result["provenance_path"])
        pdf_path = Path(result["pdf_path"])

        self.assertTrue(normalized_path.exists())
        self.assertTrue(normalized_findings_path.exists())
        self.assertTrue(payload_path.exists())
        self.assertTrue(html_path.exists())
        self.assertTrue(validation_path.exists())
        self.assertTrue(provenance_path.exists())
        self.assertTrue(pdf_path.exists())

        normalized_bundle = json.loads(normalized_findings_path.read_text(encoding="utf-8"))
        payload = json.loads(payload_path.read_text(encoding="utf-8"))
        preview_html = html_path.read_text(encoding="utf-8")

        self.assertEqual(normalized_path.name, "normalized-findings.json")
        self.assertEqual(normalized_bundle["case_id"], "case-002")
        self.assertEqual([item["finding_id"] for item in normalized_bundle["findings"]], ["F-001", "F-002", "F-003"])
        self.assertEqual(payload["summary"]["total_findings"], 3)
        self.assertEqual(payload["summary"]["by_severity"], {"high": 1, "medium": 1, "low": 1})
        self.assertEqual([item["system_name"] for item in payload["target_sections"]], ["Admin Service", "Portal Service"])
        self.assertEqual([item["management_id"] for item in payload["findings"]], ["F-001", "F-002", "F-003"])
        self.assertEqual([item["name"] for item in payload["tool_inventory"]], ["HexStrike", "Burp Suite"])
        self.assertEqual(payload["document_control"]["history"][0]["change"], "Initial multi-finding release")
        self.assertIn("Portal Service", preview_html)
        self.assertIn("Admin Service", preview_html)
        self.assertIn("보고서 단위 집계 조치", preview_html)


if __name__ == "__main__":
    unittest.main()
