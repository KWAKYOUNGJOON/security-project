import contextlib
import io
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

from src.cli.main import (
    assess_live_hexstrike_promotion_artifact,
    main,
    render_live_hexstrike_review_artifact,
    validate_live_hexstrike_artifact,
)
from src.intake import HexStrikeIntakeError
from src.validators import validate_schema_file


FIXTURE_ROOT = APP_ROOT / "tests" / "fixtures" / "hexstrike" / "live"
RUN_001 = FIXTURE_ROOT / "run-live-bridge-001"
RUN_002 = FIXTURE_ROOT / "run-live-bridge-002"
SCHEMA_DIR = REPO_ROOT / "shared" / "schemas"


class HexStrikeLiveReviewTest(unittest.TestCase):
    def test_summary_only_run_renders_blocked_review_summary(self) -> None:
        with self._copied_run_dir(RUN_001) as run_dir:
            validate_live_hexstrike_artifact(run_dir)
            assess_live_hexstrike_promotion_artifact(run_dir)
            result = render_live_hexstrike_review_artifact(run_dir)

            review_path = Path(result["promotion_review_path"])
            markdown_path = Path(result["promotion_review_markdown_path"])
            self.assertTrue(review_path.exists())
            self.assertTrue(markdown_path.exists())

            review_summary = json.loads(review_path.read_text(encoding="utf-8"))
            validate_schema_file(review_summary, SCHEMA_DIR / "hexstrike-live-review-summary.schema.json")

            self.assertEqual(review_summary["review_status"], "blocked_summary_only")
            self.assertEqual(review_summary["promotion_status"], "blocked")
            self.assertEqual(review_summary["evidence_class"], "summary_only_smoke_evidence")
            self.assertFalse(review_summary["guessed_fields_used"])
            self.assertTrue(review_summary["raw_evidence_immutable"])

            checklist = {item["check_id"]: item for item in review_summary["review_checklist"]}
            self.assertEqual(checklist["validation_completed"]["status"], "met")
            self.assertEqual(checklist["finding_detail_records_present"]["status"], "missing")
            self.assertEqual(checklist["request_response_evidence_present"]["status"], "missing")
            self.assertEqual(checklist["case_input_promotion_allowed"]["status"], "blocked")

            markdown = markdown_path.read_text(encoding="utf-8")
            self.assertIn("Validation vs Promotion", markdown)
            self.assertIn("summary_only_smoke_evidence", markdown)

    def test_nonzero_summary_without_detail_renders_blocked_missing_detail_review(self) -> None:
        with self._copied_run_dir(RUN_002) as run_dir:
            assess_live_hexstrike_promotion_artifact(run_dir)
            result = render_live_hexstrike_review_artifact(run_dir)

            review_summary = json.loads(Path(result["promotion_review_path"]).read_text(encoding="utf-8"))
            validate_schema_file(review_summary, SCHEMA_DIR / "hexstrike-live-review-summary.schema.json")

            self.assertEqual(review_summary["review_status"], "blocked_missing_detail")
            self.assertEqual(review_summary["evidence_class"], "summary_nonzero_missing_detail")
            self.assertIn("non-zero summary but no detail", review_summary["reviewer_summary"])
            self.assertTrue(any(item["code"] == "finding_detail_records" for item in review_summary["missing_evidence"]))
            checklist = {item["check_id"]: item for item in review_summary["review_checklist"]}
            self.assertEqual(checklist["finding_detail_records_present"]["status"], "blocked")
            self.assertEqual(checklist["request_response_evidence_present"]["status"], "blocked")

    def test_cli_writes_review_json_and_markdown(self) -> None:
        with self._copied_run_dir(RUN_001) as run_dir:
            validate_live_hexstrike_artifact(run_dir)
            assess_live_hexstrike_promotion_artifact(run_dir)
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = main(["render-live-hexstrike-review", "--run", str(run_dir)])

            self.assertEqual(exit_code, 0)
            result = json.loads(stdout.getvalue())
            self.assertEqual(result["review_status"], "blocked_summary_only")
            self.assertEqual(result["promotion_status"], "blocked")
            self.assertTrue(Path(result["promotion_review_path"]).exists())
            self.assertTrue(Path(result["promotion_review_markdown_path"]).exists())

    def test_review_render_requires_promotion_decision_artifact(self) -> None:
        with self._copied_run_dir(RUN_001) as run_dir:
            validate_live_hexstrike_artifact(run_dir)
            with self.assertRaises(HexStrikeIntakeError) as context:
                render_live_hexstrike_review_artifact(run_dir)
            self.assertIn("validate-live-hexstrike --run <run>", str(context.exception))
            self.assertIn("assess-live-hexstrike-promotion --run <run>", str(context.exception))

    @contextlib.contextmanager
    def _copied_run_dir(self, source_run: Path):
        with TemporaryDirectory(dir=source_run.parent) as temp_dir:
            run_dir = Path(temp_dir) / source_run.name
            shutil.copytree(source_run, run_dir)
            yield run_dir


if __name__ == "__main__":
    unittest.main()
