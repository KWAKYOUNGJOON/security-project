import sys
import unittest
from pathlib import Path


APP_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = APP_ROOT.parent.parent
if str(APP_ROOT) not in sys.path:
    sys.path.insert(0, str(APP_ROOT))

from src.cases import load_case_inputs
from src.normalizers.web_hexstrike import normalize_web_hexstrike_findings
from src.review import apply_review


CASE_003_DIR = REPO_ROOT / "cases" / "web" / "case-003"


class ReviewOverrideTest(unittest.TestCase):
    def test_override_changes_are_applied_and_audited(self) -> None:
        case_inputs = load_case_inputs(CASE_003_DIR, REPO_ROOT)
        normalized_findings = normalize_web_hexstrike_findings(case_inputs)

        reviewed_bundle, review_log = apply_review(
            case_inputs,
            normalized_findings,
            normalized_artifact_path="cases/web/case-003/derived/normalized-findings.json",
        )

        finding = next(item for item in reviewed_bundle["findings"] if item["finding_id"] == "F-001")
        self.assertEqual(finding["review_key"], "rk-8dbc9e44fc5e4261")
        self.assertEqual(finding["classification"]["severity"], "medium")
        self.assertEqual(finding["classification"]["title_ko"], "로그인 시도 제한 미흡")
        self.assertEqual(finding["title"], "로그인 시도 제한 미흡")
        self.assertEqual(
            finding["review"]["overridden_fields"],
            ["classification.severity", "classification.title_ko", "title"],
        )
        self.assertEqual(review_log["actions"][0]["review_key"], "rk-8dbc9e44fc5e4261")
        self.assertEqual(review_log["actions"][0]["action_type"], "override")


if __name__ == "__main__":
    unittest.main()
