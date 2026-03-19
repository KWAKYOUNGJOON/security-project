import json
import sys
import unittest
from pathlib import Path


APP_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = APP_ROOT.parent.parent
if str(APP_ROOT) not in sys.path:
    sys.path.insert(0, str(APP_ROOT))

from src.cli.main import build_all_artifacts


CASE_003_PATH = Path("cases/web/case-003")


class ReviewResolutionTest(unittest.TestCase):
    def test_resolution_status_is_reflected_in_reviewed_artifact_payload_and_html(self) -> None:
        result = build_all_artifacts(CASE_003_PATH)

        reviewed = json.loads(Path(result["reviewed_path"]).read_text(encoding="utf-8"))
        payload = json.loads(Path(result["payload_path"]).read_text(encoding="utf-8"))
        html = Path(result["html_path"]).read_text(encoding="utf-8")

        accepted_risk = next(item for item in payload["findings"] if item["management_id"] == "F-003")
        self.assertEqual(accepted_risk["status"], "수용")
        self.assertEqual(accepted_risk["review"]["resolution"]["resolution"], "accepted_risk")

        false_positive = next(item for item in reviewed["findings"] if item["finding_id"] == "F-004")
        self.assertTrue(false_positive["false_positive"])
        self.assertFalse(false_positive["review"]["included_in_report"])
        self.assertEqual(false_positive["review"]["resolution"]["resolution"], "false_positive")
        self.assertNotIn("F-004", [item["management_id"] for item in payload["findings"]])

        self.assertIn("위험수용", html)
        self.assertIn("review resolution: accepted_risk", html)


if __name__ == "__main__":
    unittest.main()
