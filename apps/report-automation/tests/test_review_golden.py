import json
import sys
import unittest
from pathlib import Path


APP_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = APP_ROOT.parent.parent
if str(APP_ROOT) not in sys.path:
    sys.path.insert(0, str(APP_ROOT))

from src.cli.main import build_all_artifacts


CASE_003_DIR = REPO_ROOT / "cases" / "web" / "case-003"


class ReviewGoldenTest(unittest.TestCase):
    def test_case_003_review_outputs_match_checked_in_golden_files(self) -> None:
        expected_reviewed = json.loads((CASE_003_DIR / "derived" / "reviewed-findings.json").read_text(encoding="utf-8"))
        expected_review_log = json.loads((CASE_003_DIR / "derived" / "review-log.json").read_text(encoding="utf-8"))
        expected_payload = json.loads((CASE_003_DIR / "derived" / "report-payload.json").read_text(encoding="utf-8"))
        expected_html = (CASE_003_DIR / "output" / "report-preview.html").read_text(encoding="utf-8")

        result = build_all_artifacts(CASE_003_DIR)

        rebuilt_reviewed = json.loads(Path(result["reviewed_path"]).read_text(encoding="utf-8"))
        rebuilt_review_log = json.loads(Path(result["review_log_path"]).read_text(encoding="utf-8"))
        rebuilt_payload = json.loads(Path(result["payload_path"]).read_text(encoding="utf-8"))
        rebuilt_html = Path(result["html_path"]).read_text(encoding="utf-8")

        expected_review_log["generated_at"] = "<dynamic>"
        rebuilt_review_log["generated_at"] = "<dynamic>"

        self.assertEqual(rebuilt_reviewed, expected_reviewed)
        self.assertEqual(rebuilt_review_log, expected_review_log)
        self.assertEqual(rebuilt_payload, expected_payload)
        self.assertEqual(rebuilt_html, expected_html)


if __name__ == "__main__":
    unittest.main()
