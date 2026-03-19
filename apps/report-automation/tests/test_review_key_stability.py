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


class ReviewKeyStabilityTest(unittest.TestCase):
    def test_review_key_is_stable_across_reruns_and_review_application(self) -> None:
        case_inputs = load_case_inputs(CASE_003_DIR, REPO_ROOT)

        first = normalize_web_hexstrike_findings(case_inputs)
        second = normalize_web_hexstrike_findings(case_inputs)

        self.assertEqual(
            [finding["review_key"] for finding in first],
            [finding["review_key"] for finding in second],
        )

        reviewed_bundle, _ = apply_review(
            case_inputs,
            first,
            normalized_artifact_path="cases/web/case-003/derived/normalized-findings.json",
        )
        self.assertEqual(
            [finding["review_key"] for finding in first],
            [finding["review_key"] for finding in reviewed_bundle["findings"]],
        )


if __name__ == "__main__":
    unittest.main()
