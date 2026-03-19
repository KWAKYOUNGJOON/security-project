import sys
import unittest
from pathlib import Path


APP_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = APP_ROOT.parent.parent
if str(APP_ROOT) not in sys.path:
    sys.path.insert(0, str(APP_ROOT))

from src.cases import load_case_inputs
from src.generators.template_bridge import build_template_dataset
from src.generators.web_report_payload import build_web_report_payload
from src.normalizers.web_hexstrike import normalize_web_hexstrike_findings


CASE_001_DIR = REPO_ROOT / "cases" / "web" / "case-001"
CASE_002_DIR = REPO_ROOT / "cases" / "web" / "case-002"


class ToolInventoryContractTest(unittest.TestCase):
    def test_bridge_does_not_guess_tool_inventory_for_legacy_case(self) -> None:
        case_inputs = load_case_inputs(CASE_001_DIR, REPO_ROOT)
        normalized_findings = normalize_web_hexstrike_findings(case_inputs)
        payload = build_web_report_payload(normalized_findings, case_inputs)
        dataset = build_template_dataset(payload, repo_root=REPO_ROOT)

        self.assertEqual(case_inputs.tool_inventory, [])
        self.assertEqual(payload["tool_inventory"], [])
        self.assertEqual(dataset["diagnostic_overview"]["tool_list"], [])

    def test_bridge_uses_only_explicit_tool_inventory_for_multi_case(self) -> None:
        case_inputs = load_case_inputs(CASE_002_DIR, REPO_ROOT)
        normalized_findings = normalize_web_hexstrike_findings(case_inputs)
        payload = build_web_report_payload(normalized_findings, case_inputs)
        dataset = build_template_dataset(payload, repo_root=REPO_ROOT)

        self.assertEqual([item["name"] for item in case_inputs.tool_inventory], ["HexStrike", "Burp Suite"])
        self.assertEqual([item["name"] for item in payload["tool_inventory"]], ["HexStrike", "Burp Suite"])
        self.assertEqual(
            dataset["diagnostic_overview"]["tool_list"],
            [
                {
                    "name": "HexStrike",
                    "usage": "raw scan source",
                    "note": "scanner / raw_scan / finding raw results",
                },
                {
                    "name": "Burp Suite",
                    "usage": "manual verification",
                    "note": "proxy / analyst_declared / request replay and response review",
                },
            ],
        )


if __name__ == "__main__":
    unittest.main()
