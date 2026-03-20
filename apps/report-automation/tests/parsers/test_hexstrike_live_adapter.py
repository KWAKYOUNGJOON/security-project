import contextlib
import io
import json
import shutil
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory


APP_ROOT = Path(__file__).resolve().parents[2]
REPO_ROOT = APP_ROOT.parent.parent
if str(APP_ROOT) not in sys.path:
    sys.path.insert(0, str(APP_ROOT))

from src.cli.main import main, validate_live_hexstrike_artifact
from src.intake import HexStrikeIntakeError
from src.intake.hexstrike_intake import load_hexstrike_intake_run
from src.parsers.hexstrike_live_adapter import bridge_live_hexstrike_run, is_known_live_hexstrike_shape
from src.validators import validate_schema_file


FIXTURE_RUN_DIR = APP_ROOT / "tests" / "fixtures" / "hexstrike" / "live" / "run-live-bridge-001"
SCHEMA_DIR = REPO_ROOT / "shared" / "schemas"


class HexStrikeLiveAdapterTest(unittest.TestCase):
    def test_known_live_shape_is_detected_and_bridged(self) -> None:
        intake_run = load_hexstrike_intake_run(FIXTURE_RUN_DIR, REPO_ROOT)
        raw_payload = intake_run.raw_payloads[0].payload

        self.assertTrue(is_known_live_hexstrike_shape(raw_payload))

        bridged = bridge_live_hexstrike_run(intake_run)
        canonical = bridged["payload_sources"][0]["validation_payload"]
        report = bridged["shape_bridge_report"]

        self.assertTrue(bridged["adapter_applied"])
        self.assertEqual(sorted(canonical.keys()), ["engagement", "findings", "scan", "tool"])
        self.assertEqual(canonical["findings"], [])
        validate_schema_file(report, SCHEMA_DIR / "hexstrike-shape-bridge-report.schema.json")
        self.assertTrue(report["guessed_fields_absent"])
        self.assertEqual(report["coverage_summary"]["adapted_payload_count"], 1)
        self.assertFalse(report["status"]["report_ready"])
        self.assertFalse(report["status"]["promotable_to_cases"])
        self.assertEqual(report["status"]["observation_kind"], "summary-only-live-smoke")

    def test_validate_live_hexstrike_artifact_writes_bridge_outputs_for_live_shape(self) -> None:
        with self._copied_run_dir() as run_dir:
            result = validate_live_hexstrike_artifact(run_dir)

            observation_path = Path(result["format_observation_path"])
            provenance_path = Path(result["provenance_path"])
            report_path = Path(result["shape_bridge_report_path"])
            delta_path = Path(result["synthetic_live_delta_path"])

            self.assertTrue(observation_path.exists())
            self.assertTrue(provenance_path.exists())
            self.assertTrue(report_path.exists())
            self.assertTrue(delta_path.exists())
            self.assertTrue(result["adapter_applied"])

            observation = json.loads(observation_path.read_text(encoding="utf-8"))
            provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
            report = json.loads(report_path.read_text(encoding="utf-8"))
            delta = json.loads(delta_path.read_text(encoding="utf-8"))

            validate_schema_file(observation, SCHEMA_DIR / "format-observation.schema.json")
            validate_schema_file(provenance, SCHEMA_DIR / "provenance.schema.json")
            validate_schema_file(report, SCHEMA_DIR / "hexstrike-shape-bridge-report.schema.json")
            validate_schema_file(delta, SCHEMA_DIR / "hexstrike-synthetic-live-delta.schema.json")

            self.assertEqual(observation["finding_count_detected"], 0)
            self.assertEqual(
                observation["detected_top_level_keys"],
                ["scan_type", "success", "summary", "target", "timestamp"],
            )
            self.assertEqual(observation["missing_expected_fields"], [])
            self.assertEqual(report["coverage_summary"]["adapted_payload_count"], 1)
            self.assertFalse(report["status"]["report_ready"])
            self.assertFalse(report["status"]["promotable_to_cases"])
            self.assertTrue(delta["linkage_comparison_succeeded"])
            self.assertTrue(delta["conclusion"]["promotion_decision_remains_blocked"])
            self.assertTrue(any(output["path"].endswith("/derived/shape-bridge-report.json") for output in provenance["outputs"]))
            self.assertTrue(any(output["path"].endswith("/derived/synthetic-vs-live-delta.json") for output in provenance["outputs"]))

    def test_validate_live_hexstrike_cli_uses_adapter_path_for_known_live_shape(self) -> None:
        with self._copied_run_dir() as run_dir:
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = main(["validate-live-hexstrike", "--run", str(run_dir)])

            self.assertEqual(exit_code, 0)
            result = json.loads(stdout.getvalue())
            self.assertTrue(result["adapter_applied"])
            self.assertIn("shape_bridge_report_path", result)
            self.assertIn("synthetic_live_delta_path", result)
            self.assertFalse(result["report_ready"])
            self.assertFalse(result["promotable_to_cases"])

    def test_validate_live_hexstrike_fails_for_positive_total_without_findings(self) -> None:
        with self._copied_run_dir() as run_dir:
            self._patch_summary(run_dir, total_vulnerabilities=2, vulnerability_breakdown={"high": 2})

            with self.assertRaises(HexStrikeIntakeError) as excinfo:
                validate_live_hexstrike_artifact(run_dir)

            self.assertIn("positive_total_without_finding_objects", str(excinfo.exception))
            self.assertFalse((run_dir / "derived" / "format-observation.json").exists())

    def test_validate_live_hexstrike_fails_for_missing_or_invalid_total(self) -> None:
        for invalid_value in (None, "unknown", -1):
            with self.subTest(total_vulnerabilities=invalid_value):
                with self._copied_run_dir() as run_dir:
                    self._patch_summary(run_dir, total_vulnerabilities=invalid_value)

                    with self.assertRaises(HexStrikeIntakeError) as excinfo:
                        validate_live_hexstrike_artifact(run_dir)

                    self.assertIn("missing_or_invalid_total_vulnerabilities", str(excinfo.exception))
                    self.assertFalse((run_dir / "derived" / "format-observation.json").exists())

    def test_validate_live_hexstrike_fails_for_inconsistent_or_ambiguous_breakdown(self) -> None:
        scenarios = [
            ("summary_breakdown_nonzero_when_total_zero", {"high": 1}),
            ("ambiguous_vulnerability_breakdown", {"high": "one"}),
        ]
        for expected_code, breakdown in scenarios:
            with self.subTest(expected_code=expected_code):
                with self._copied_run_dir() as run_dir:
                    self._patch_summary(run_dir, total_vulnerabilities=0, vulnerability_breakdown=breakdown)

                    with self.assertRaises(HexStrikeIntakeError) as excinfo:
                        validate_live_hexstrike_artifact(run_dir)

                    self.assertIn(expected_code, str(excinfo.exception))
                    self.assertFalse((run_dir / "derived" / "format-observation.json").exists())

    @contextlib.contextmanager
    def _copied_run_dir(self):
        synthetic_root = FIXTURE_RUN_DIR.parent
        with TemporaryDirectory(dir=synthetic_root) as temp_dir:
            run_dir = Path(temp_dir) / "run-live-bridge-001"
            shutil.copytree(FIXTURE_RUN_DIR, run_dir)
            yield run_dir

    def _patch_summary(
        self,
        run_dir: Path,
        *,
        total_vulnerabilities: object,
        vulnerability_breakdown: object | None = None,
    ) -> None:
        raw_path = run_dir / "raw" / "hexstrike-result.json"
        payload = json.loads(raw_path.read_text(encoding="utf-8"))
        payload["summary"]["total_vulnerabilities"] = total_vulnerabilities
        if vulnerability_breakdown is not None:
            payload["summary"]["vulnerability_breakdown"] = vulnerability_breakdown
        raw_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    unittest.main()
