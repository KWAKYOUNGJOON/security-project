import sys
import unittest
from pathlib import Path


APP_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = APP_ROOT.parent.parent
if str(APP_ROOT) not in sys.path:
    sys.path.insert(0, str(APP_ROOT))

from src.cases import load_case_inputs
from src.generators.web_report_payload import build_web_report_payload
from src.normalizers.web_hexstrike import (
    build_normalized_findings_artifact,
    normalize_web_hexstrike_case,
    normalize_web_hexstrike_findings,
)
from src.validators import validate_schema_file


CASE_001_DIR = REPO_ROOT / "cases" / "web" / "case-001"
CASE_002_DIR = REPO_ROOT / "cases" / "web" / "case-002"
SCHEMA_DIR = REPO_ROOT / "shared" / "schemas"


class SchemaValidationTest(unittest.TestCase):
    def test_case_001_normalized_finding_matches_schema_and_preserves_unmapped_fields(self) -> None:
        case_inputs = load_case_inputs(CASE_001_DIR, REPO_ROOT)
        normalized = normalize_web_hexstrike_case(case_inputs)
        normalized_bundle = build_normalized_findings_artifact(case_inputs, [normalized])

        validate_schema_file(normalized, SCHEMA_DIR / "normalized-finding.schema.json")
        validate_schema_file(normalized_bundle, SCHEMA_DIR / "normalized-findings.schema.json")

        self.assertEqual(normalized["classification"]["code"], "AU")
        self.assertEqual(normalized["classification"]["taxonomy"]["name"], "web-kisa-2026")
        self.assertEqual(normalized["classification"]["taxonomy"]["version"], "2026")
        self.assertEqual(normalized["classification"]["canonical_key"], "automated_attack")
        self.assertIn("unexpected_signal", normalized["unmapped_fields"]["finding"])
        self.assertEqual(normalized["source"]["raw_file"], "cases/web/case-001/input/raw/hexstrike-result.json")
        self.assertEqual(normalized_bundle["findings"], [normalized])
        self.assertEqual(normalized_bundle["case_id"], "web-case-001")

    def test_case_002_normalized_bundle_and_payload_match_schema(self) -> None:
        case_inputs = load_case_inputs(CASE_002_DIR, REPO_ROOT)
        normalized_findings = normalize_web_hexstrike_findings(case_inputs)
        normalized_bundle = build_normalized_findings_artifact(case_inputs, normalized_findings)
        payload = build_web_report_payload(normalized_findings, case_inputs)

        validate_schema_file(normalized_bundle, SCHEMA_DIR / "normalized-findings.schema.json")
        for finding in normalized_findings:
            validate_schema_file(finding, SCHEMA_DIR / "normalized-finding.schema.json")
        validate_schema_file(payload, SCHEMA_DIR / "report-payload.schema.json")

        self.assertEqual(normalized_bundle["case_id"], "case-002")
        self.assertEqual(len(normalized_bundle["findings"]), 3)
        self.assertEqual(payload["summary"]["total_findings"], 3)
        self.assertEqual(payload["summary"]["by_severity"]["high"], 1)
        self.assertEqual(payload["summary"]["by_severity"]["medium"], 1)
        self.assertEqual(payload["summary"]["by_severity"]["low"], 1)
        self.assertEqual(payload["findings"][0]["management_id"], "F-001")
        self.assertEqual(payload["document"]["title"], "웹 취약점 진단 결과 보고서")
        self.assertEqual(payload["engagement"]["project_name"], "phase-1 web multi sample")
        self.assertEqual(payload["findings"][0]["canonical_key"], "automated_attack")
        self.assertEqual([item["name"] for item in payload["tool_inventory"]], ["HexStrike", "Burp Suite"])
        self.assertEqual(payload["document_control"]["approvals"][0]["role"], "Reviewer")


if __name__ == "__main__":
    unittest.main()
