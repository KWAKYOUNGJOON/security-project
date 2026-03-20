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

from src.cli.main import assess_live_hexstrike_promotion_artifact, main, validate_live_hexstrike_artifact
from src.intake import HexStrikeIntakeError, assess_hexstrike_live_promotion_from_artifacts
from src.parsers.hexstrike_live_adapter import COVERAGE_GAP_NONZERO_NO_DETAIL, SUMMARY_NOTE_NONZERO_NO_DETAIL
from src.validators import validate_schema_file


FIXTURE_ROOT = APP_ROOT / "tests" / "fixtures" / "hexstrike" / "live"
RUN_001 = FIXTURE_ROOT / "run-live-bridge-001"
RUN_002 = FIXTURE_ROOT / "run-live-bridge-002"
SCHEMA_DIR = REPO_ROOT / "shared" / "schemas"


class HexStrikeLivePromotionTest(unittest.TestCase):
    def test_zero_summary_no_detail_is_blocked_after_validation(self) -> None:
        with self._copied_run_dir(RUN_001) as run_dir:
            validate_live_hexstrike_artifact(run_dir)
            result = assess_live_hexstrike_promotion_artifact(run_dir)

            decision_path = Path(result["promotion_decision_path"])
            decision = json.loads(decision_path.read_text(encoding="utf-8"))
            validate_schema_file(decision, SCHEMA_DIR / "hexstrike-live-promotion-decision.schema.json")

            self.assertEqual(result["promotion_status"], "blocked")
            self.assertFalse(result["case_input_promotion_allowed"])
            self.assertEqual(result["evidence_class"], "summary_only_smoke_evidence")
            self.assertEqual(result["validation_status"], "passed")
            self.assertEqual(result["detail_coverage_status"], "zero_summary_no_detail")
            self.assertEqual(decision["summary_total_vulnerabilities"], 0)
            self.assertFalse(decision["guessed_fields_used"])
            self.assertTrue(decision["raw_evidence_immutable"])
            self.assertTrue(any(item["code"] == "no_findings_detected" for item in decision["blocking_reasons"]))
            self.assertIn("capture_finding_level_live_sample_before_promotion", decision["required_for_future_promotion"])

    def test_nonzero_summary_without_detail_is_blocked(self) -> None:
        with self._copied_run_dir(RUN_002) as run_dir:
            decision = self._build_nonzero_missing_detail_decision(run_dir)

            validate_schema_file(decision, SCHEMA_DIR / "hexstrike-live-promotion-decision.schema.json")

            self.assertEqual(decision["promotion_status"], "blocked")
            self.assertFalse(decision["case_input_promotion_allowed"])
            self.assertEqual(decision["evidence_class"], "summary_nonzero_missing_detail")
            self.assertEqual(decision["detail_coverage_status"], "nonzero_summary_no_detail")
            self.assertEqual(decision["summary_total_vulnerabilities"], 2)
            self.assertTrue(
                any(
                    item["code"] == "summary_claims_findings_but_no_detail_records"
                    for item in decision["blocking_reasons"]
                )
            )
            self.assertIn("capture_finding_level_live_sample_before_promotion", decision["required_for_future_promotion"])

    def test_cli_writes_promotion_decision_and_keeps_validation_passed_but_blocked(self) -> None:
        with self._copied_run_dir(RUN_001) as run_dir:
            validate_live_hexstrike_artifact(run_dir)
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = main(["assess-live-hexstrike-promotion", "--run", str(run_dir)])

            self.assertEqual(exit_code, 0)
            result = json.loads(stdout.getvalue())
            self.assertEqual(result["promotion_status"], "blocked")
            self.assertFalse(result["case_input_promotion_allowed"])
            self.assertEqual(result["validation_status"], "passed")
            self.assertTrue(Path(result["promotion_decision_path"]).exists())

    def test_promotion_assessment_requires_validate_live_hexstrike_outputs(self) -> None:
        with self._copied_run_dir(RUN_001) as run_dir:
            with self.assertRaises(HexStrikeIntakeError):
                assess_live_hexstrike_promotion_artifact(run_dir)

    @contextlib.contextmanager
    def _copied_run_dir(self, source_run: Path):
        with TemporaryDirectory(dir=source_run.parent) as temp_dir:
            run_dir = Path(temp_dir) / source_run.name
            shutil.copytree(source_run, run_dir)
            yield run_dir

    def _build_nonzero_missing_detail_decision(self, run_dir: Path) -> dict[str, object]:
        manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
        raw_payload = json.loads((run_dir / "raw" / "hexstrike-result.json").read_text(encoding="utf-8"))
        run_rel = run_dir.relative_to(REPO_ROOT).as_posix()

        format_observation = {
            "schema_version": "1.0",
            "platform": "web",
            "integration": "hexstrike-ai",
            "run_id": manifest["run_id"],
            "mode": manifest["mode"],
            "finding_count_detected": 0,
            "detected_top_level_keys": sorted(raw_payload.keys()),
            "unknown_fields": [],
            "missing_expected_fields": [],
            "parser_warnings": [SUMMARY_NOTE_NONZERO_NO_DETAIL],
            "evidence_shape_summary": {
                "request_field_shapes": {},
                "response_field_shapes": {},
                "evidence_field_shapes": {},
                "severity_field_shapes": {},
                "status_field_shapes": {},
                "evidence_item_shapes": {},
                "evidence_item_kinds": {},
            },
        }
        shape_bridge_report = {
            "coverage_summary": {"coverage_confidence": "medium"},
            "coverage_gaps": [COVERAGE_GAP_NONZERO_NO_DETAIL],
            "guessed_fields_absent": True,
        }
        live_raw_shape_summary = {
            "summary_total_vulnerabilities": 2,
            "unknown_topology_notes": [SUMMARY_NOTE_NONZERO_NO_DETAIL],
        }
        provenance = {
            "subject_type": "intake-run",
            "inputs": [{"role": "intake-raw", "path": f"{run_rel}/raw/hexstrike-result.json"}],
            "outputs": [],
        }

        return assess_hexstrike_live_promotion_from_artifacts(
            manifest=manifest,
            format_observation=format_observation,
            shape_bridge_report=shape_bridge_report,
            live_raw_shape_summary=live_raw_shape_summary,
            provenance=provenance,
            source_paths={
                "manifest": f"{run_rel}/manifest.json",
                "notes": f"{run_rel}/notes.md",
                "format_observation": f"{run_rel}/derived/format-observation.json",
                "shape_bridge_report": f"{run_rel}/derived/shape-bridge-report.json",
                "live_raw_shape_summary": f"{run_rel}/derived/live-raw-shape-summary.json",
                "provenance": f"{run_rel}/derived/provenance.json",
            },
        )


if __name__ == "__main__":
    unittest.main()
