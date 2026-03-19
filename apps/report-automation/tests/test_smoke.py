import json
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory


APP_ROOT = Path(__file__).resolve().parents[1]
if str(APP_ROOT) not in sys.path:
    sys.path.insert(0, str(APP_ROOT))

from src.cli.main import DEFAULT_CONFIG_PATH, load_config, main, run_pipeline


class ReportAutomationSmokeTest(unittest.TestCase):
    def test_pipeline_returns_web_payload(self) -> None:
        payload = run_pipeline(load_config(DEFAULT_CONFIG_PATH))

        self.assertEqual(payload["meta"]["current_scope"], "web")
        self.assertEqual(payload["meta"]["target_scope"], ["web", "api", "server"])
        self.assertEqual(payload["meta"]["pipeline"], ["collect", "parse", "normalize", "enrich", "build"])
        self.assertEqual(payload["summary"]["total_findings"], 2)
        self.assertEqual(payload["summary"]["by_severity"]["medium"], 1)
        self.assertEqual(payload["summary"]["by_severity"]["low"], 1)

    def test_cli_writes_payload_file(self) -> None:
        with TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "payload.json"
            exit_code = main(["--output", str(output_path)])
            self.assertEqual(exit_code, 0)
            self.assertTrue(output_path.exists())
            payload = json.loads(output_path.read_text(encoding="utf-8"))

        self.assertEqual(payload["meta"]["primary_integration"], "HexStrike-AI")


if __name__ == "__main__":
    unittest.main()
