import json
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory


APP_ROOT = Path(__file__).resolve().parents[1]
if str(APP_ROOT) not in sys.path:
    sys.path.insert(0, str(APP_ROOT))

from vuln_pipeline.cli.main import main
from vuln_pipeline.contracts import compare_run_directories, run_smoke


class Ready1SmokeTest(unittest.TestCase):
    def test_smoke_writes_required_artifacts(self) -> None:
        with TemporaryDirectory() as temp_dir:
            output_dir = Path(temp_dir) / "run-1"
            result = run_smoke(input_root=None, output_dir=output_dir)

            self.assertEqual(result["status"], "PASS")
            self.assertTrue((output_dir / "input_preflight.json").exists())
            self.assertTrue((output_dir / "release_readiness.json").exists())
            self.assertTrue((output_dir / "submission_gate.json").exists())

            gate = json.loads((output_dir / "submission_gate.json").read_text(encoding="utf-8"))
            self.assertEqual(gate["decision"]["status"], "PASS")
            self.assertTrue(gate["artifact_presence"]["input_preflight.json"])
            self.assertTrue(gate["artifact_presence"]["release_readiness.json"])
            self.assertTrue(gate["artifact_presence"]["submission_gate.json"])

    def test_compare_runs_is_stable(self) -> None:
        with TemporaryDirectory() as temp_dir:
            run_one = Path(temp_dir) / "run-1"
            run_two = Path(temp_dir) / "run-2"
            run_smoke(input_root=None, output_dir=run_one)
            run_smoke(input_root=None, output_dir=run_two)

            comparison = compare_run_directories([run_one, run_two])
            self.assertEqual(comparison["status"], "PASS")
            self.assertTrue(comparison["decision_status_equal"])
            self.assertTrue(comparison["required_keys_equal"])
            self.assertTrue(comparison["forbidden_path_results_equal"])

    def test_cli_smoke_command_returns_zero(self) -> None:
        with TemporaryDirectory() as temp_dir:
            output_dir = Path(temp_dir) / "run-1"
            exit_code = main(["smoke", "--output-dir", str(output_dir)])
            self.assertEqual(exit_code, 0)


if __name__ == "__main__":
    unittest.main()
