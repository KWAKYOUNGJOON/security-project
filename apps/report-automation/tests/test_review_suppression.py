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


class ReviewSuppressionTest(unittest.TestCase):
    def test_suppressed_finding_is_removed_from_payload_and_html(self) -> None:
        result = build_all_artifacts(CASE_003_PATH)

        payload = json.loads(Path(result["payload_path"]).read_text(encoding="utf-8"))
        reviewed = json.loads(Path(result["reviewed_path"]).read_text(encoding="utf-8"))
        html = Path(result["html_path"]).read_text(encoding="utf-8")

        self.assertEqual([item["management_id"] for item in payload["findings"]], ["F-001", "F-003"])

        suppressed = next(item for item in reviewed["findings"] if item["finding_id"] == "F-002")
        self.assertFalse(suppressed["review"]["included_in_report"])
        self.assertEqual(suppressed["review"]["suppression"]["reason_code"], "duplicate")

        self.assertNotIn("F-002", html)
        self.assertNotIn("디버그 응답 정보 노출", html)


if __name__ == "__main__":
    unittest.main()
