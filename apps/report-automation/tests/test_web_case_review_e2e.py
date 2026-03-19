import json
import sys
import unittest
from pathlib import Path


APP_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = APP_ROOT.parent.parent
if str(APP_ROOT) not in sys.path:
    sys.path.insert(0, str(APP_ROOT))

from src.cli.main import build_all_artifacts
from src.validators import validate_schema_file


CASE_PATH = Path("cases/web/case-003")
SCHEMA_DIR = REPO_ROOT / "shared" / "schemas"


class WebCaseReviewE2ETest(unittest.TestCase):
    def test_build_all_generates_review_artifacts_and_review_aware_outputs(self) -> None:
        result = build_all_artifacts(CASE_PATH)

        reviewed_path = Path(result["reviewed_path"])
        review_log_path = Path(result["review_log_path"])
        payload_path = Path(result["payload_path"])
        provenance_path = Path(result["provenance_path"])
        html_path = Path(result["html_path"])
        pdf_path = Path(result["pdf_path"])

        self.assertTrue(reviewed_path.exists())
        self.assertTrue(review_log_path.exists())
        self.assertTrue(payload_path.exists())
        self.assertTrue(provenance_path.exists())
        self.assertTrue(html_path.exists())
        self.assertTrue(pdf_path.exists())

        reviewed = json.loads(reviewed_path.read_text(encoding="utf-8"))
        review_log = json.loads(review_log_path.read_text(encoding="utf-8"))
        payload = json.loads(payload_path.read_text(encoding="utf-8"))
        provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
        html = html_path.read_text(encoding="utf-8")

        validate_schema_file(reviewed, SCHEMA_DIR / "reviewed-findings.schema.json")
        validate_schema_file(review_log, SCHEMA_DIR / "review-log.schema.json")
        validate_schema_file(payload, SCHEMA_DIR / "report-payload.schema.json")

        self.assertEqual(payload["summary"]["total_findings"], 2)
        self.assertEqual(payload["review_summary"]["overridden_count"], 1)
        self.assertEqual(payload["review_summary"]["suppressed_count"], 1)
        self.assertEqual(payload["review_summary"]["accepted_risk_count"], 1)
        self.assertEqual(len(review_log["actions"]), 5)
        self.assertIn("로그인 시도 제한 미흡", html)
        self.assertIn("위험수용", html)

        input_roles = {item["role"] for item in provenance["inputs"]}
        self.assertTrue(
            {"review-override", "review-suppression", "review-resolution", "review-exception"}.issubset(input_roles)
        )
        output_paths = {item["path"] for item in provenance["outputs"]}
        self.assertIn("cases/web/case-003/derived/reviewed-findings.json", output_paths)
        self.assertIn("cases/web/case-003/derived/review-log.json", output_paths)


if __name__ == "__main__":
    unittest.main()
