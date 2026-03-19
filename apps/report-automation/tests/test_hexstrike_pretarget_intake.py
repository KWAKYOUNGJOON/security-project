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

from src.cli.main import main, validate_live_hexstrike_artifact
from src.intake import HexStrikeIntakeError
from src.validators import validate_schema_file


SYNTHETIC_RUN_DIR = REPO_ROOT / "intake" / "synthetic" / "hexstrike-ai" / "rehearsal-001"
SCHEMA_DIR = REPO_ROOT / "shared" / "schemas"


class HexStrikePretargetIntakeTest(unittest.TestCase):
    def test_validate_live_hexstrike_generates_observation_and_provenance_from_synthetic_run(self) -> None:
        with self._copied_run_dir() as run_dir:
            result = validate_live_hexstrike_artifact(run_dir)

            observation_path = Path(result["format_observation_path"])
            provenance_path = Path(result["provenance_path"])
            self.assertTrue(observation_path.exists())
            self.assertTrue(provenance_path.exists())

            observation = json.loads(observation_path.read_text(encoding="utf-8"))
            provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
            validate_schema_file(observation, SCHEMA_DIR / "format-observation.schema.json")
            validate_schema_file(provenance, SCHEMA_DIR / "provenance.schema.json")

            self.assertEqual(observation["finding_count_detected"], 1)
            self.assertEqual(
                observation["detected_top_level_keys"],
                ["engagement", "findings", "metadata", "scan", "tool"],
            )
            self.assertEqual(observation["missing_expected_fields"], [])

            unknown_fields = {(item["path"], item["field"]) for item in observation["unknown_fields"]}
            self.assertIn(("$", "metadata"), unknown_fields)
            self.assertIn(("$.findings[0]", "confidence"), unknown_fields)
            self.assertIn(("$.findings[0]", "experimental_trace"), unknown_fields)

            summary = observation["evidence_shape_summary"]
            self.assertEqual(summary["request_field_shapes"], {"object": 1})
            self.assertEqual(summary["response_field_shapes"], {"object": 1})
            self.assertEqual(summary["evidence_field_shapes"], {"array": 1})
            self.assertEqual(summary["severity_field_shapes"], {"string": 1})
            self.assertEqual(summary["status_field_shapes"], {"string": 1})
            self.assertEqual(summary["evidence_item_shapes"], {"object": 2, "string": 1})
            self.assertEqual(summary["evidence_item_kinds"], {"http": 1, "screenshot": 1})

            input_roles = {item["role"] for item in provenance["inputs"]}
            self.assertEqual(input_roles, {"intake-raw", "manifest", "notes"})
            self.assertEqual(provenance["subject_type"], "intake-run")
            self.assertEqual(len(provenance["outputs"]), 1)
            self.assertTrue(provenance["outputs"][0]["path"].endswith("/derived/format-observation.json"))

    def test_validate_live_hexstrike_cli_command_runs_without_network_activity(self) -> None:
        with self._copied_run_dir() as run_dir:
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = main(["validate-live-hexstrike", "--run", str(run_dir)])

            self.assertEqual(exit_code, 0)
            result = json.loads(stdout.getvalue())
            self.assertEqual(result["finding_count_detected"], 1)

    def test_validate_live_hexstrike_fails_fast_when_required_fields_are_missing(self) -> None:
        with self._copied_run_dir() as run_dir:
            raw_path = run_dir / "raw" / "hexstrike-result.json"
            payload = json.loads(raw_path.read_text(encoding="utf-8"))
            del payload["findings"][0]["severity"]
            raw_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

            with self.assertRaises(HexStrikeIntakeError):
                validate_live_hexstrike_artifact(run_dir)

            self.assertFalse((run_dir / "derived" / "format-observation.json").exists())

    @contextlib.contextmanager
    def _copied_run_dir(self):
        synthetic_root = REPO_ROOT / "intake" / "synthetic"
        with TemporaryDirectory(dir=synthetic_root) as temp_dir:
            run_dir = Path(temp_dir) / "hexstrike-ai" / "rehearsal-001"
            run_dir.parent.mkdir(parents=True, exist_ok=True)
            shutil.copytree(SYNTHETIC_RUN_DIR, run_dir)
            yield run_dir


if __name__ == "__main__":
    unittest.main()
