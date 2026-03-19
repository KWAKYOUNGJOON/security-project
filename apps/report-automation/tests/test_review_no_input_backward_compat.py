import json
import sys
import unittest
from pathlib import Path


APP_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = APP_ROOT.parent.parent
if str(APP_ROOT) not in sys.path:
    sys.path.insert(0, str(APP_ROOT))

from src.cli.main import build_all_artifacts


class ReviewNoInputBackwardCompatTest(unittest.TestCase):
    def test_cases_without_review_input_keep_semantic_behavior_and_emit_empty_review_state(self) -> None:
        expectations = {
            "cases/web/case-001": 1,
            "cases/web/case-002": 3,
        }

        for case_path, expected_total in expectations.items():
            with self.subTest(case=case_path):
                result = build_all_artifacts(Path(case_path))
                reviewed = json.loads(Path(result["reviewed_path"]).read_text(encoding="utf-8"))
                review_log = json.loads(Path(result["review_log_path"]).read_text(encoding="utf-8"))
                payload = json.loads(Path(result["payload_path"]).read_text(encoding="utf-8"))

                self.assertTrue(Path(result["reviewed_path"]).exists())
                self.assertTrue(Path(result["review_log_path"]).exists())
                self.assertEqual(review_log["actions"], [])
                self.assertEqual(payload["summary"]["total_findings"], expected_total)
                self.assertEqual(
                    payload["review_summary"],
                    {
                        "total_reviewed": 0,
                        "overridden_count": 0,
                        "suppressed_count": 0,
                        "resolved_count": 0,
                        "accepted_risk_count": 0,
                    },
                )
                for finding in reviewed["findings"]:
                    self.assertTrue(finding["review"]["included_in_report"])
                    self.assertEqual(finding["review"]["review_history"], [])


if __name__ == "__main__":
    unittest.main()
