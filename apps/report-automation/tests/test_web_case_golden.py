import json
import sys
import unittest
from pathlib import Path


APP_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = APP_ROOT.parent.parent
if str(APP_ROOT) not in sys.path:
    sys.path.insert(0, str(APP_ROOT))

from src.cli.main import build_all_artifacts


CASE_001_DIR = REPO_ROOT / "cases" / "web" / "case-001"
CASE_002_DIR = REPO_ROOT / "cases" / "web" / "case-002"


class WebCaseGoldenTest(unittest.TestCase):
    def test_case_001_outputs_match_checked_in_golden_files(self) -> None:
        self._assert_case_golden(
            CASE_001_DIR,
            required_snippets=[
                "웹 취약점 진단 결과 보고서",
                "Example Customer",
                "phase-1 web sample",
                "로그인 실패 횟수 제한 미흡",
                "자동화 공격",
                "Seoul",
                "Example Security",
                "VUL-001",
                "cases/web/case-001/input/http/request.txt",
            ],
            forbidden_snippets=[
                "{{기관명}}",
                "{{수행기관명}}",
                "{{작성일}}",
                "{{문서버전}}",
                "[summary comment]",
                "[assumptions]",
                "[exclusions]",
                "[limitations]",
                "[양호/취약/해당없음]",
                "Burp Suite Community Edition",
                "Nikto",
                "Burp Suite",
            ],
        )

    def test_case_002_outputs_match_checked_in_golden_files(self) -> None:
        self._assert_case_golden(
            CASE_002_DIR,
            required_snippets=[
                "웹 취약점 진단 결과 보고서",
                "Portal Service",
                "Admin Service",
                "HexStrike",
                "Burp Suite",
                "Example Reviewer",
                "Initial multi-finding release",
                "F-001",
                "F-002",
                "F-003",
                "보고서 단위 집계 조치",
            ],
            forbidden_snippets=[
                "{{기관명}}",
                "{{수행기관명}}",
                "{{작성일}}",
                "{{문서버전}}",
                "[summary comment]",
                "[assumptions]",
                "[exclusions]",
                "[limitations]",
                "[양호/취약/해당없음]",
                "Burp Suite Community Edition",
                "Nikto",
            ],
        )

    def _assert_case_golden(
        self,
        case_dir: Path,
        *,
        required_snippets: list[str],
        forbidden_snippets: list[str],
    ) -> None:
        normalized_golden_path = case_dir / "derived" / "normalized-findings.json"
        payload_golden_path = case_dir / "derived" / "report-payload.json"
        html_golden_path = case_dir / "output" / "report-preview.html"

        self.assertTrue(normalized_golden_path.exists(), f"golden normalized-findings.json is missing: {case_dir}")
        self.assertTrue(payload_golden_path.exists(), f"golden report-payload.json is missing: {case_dir}")
        self.assertTrue(html_golden_path.exists(), f"golden report-preview.html is missing: {case_dir}")

        expected_normalized = json.loads(normalized_golden_path.read_text(encoding="utf-8"))
        expected_payload = json.loads(payload_golden_path.read_text(encoding="utf-8"))
        expected_html = html_golden_path.read_text(encoding="utf-8")

        result = build_all_artifacts(case_dir)

        rebuilt_normalized = json.loads(Path(result["normalized_findings_path"]).read_text(encoding="utf-8"))
        rebuilt_payload = json.loads(Path(result["payload_path"]).read_text(encoding="utf-8"))
        rebuilt_html = Path(result["html_path"]).read_text(encoding="utf-8")

        self.assertEqual(rebuilt_normalized, expected_normalized)
        self.assertEqual(rebuilt_payload, expected_payload)

        for snippet in required_snippets:
            self.assertIn(snippet, expected_html)
            self.assertIn(snippet, rebuilt_html)

        for snippet in forbidden_snippets:
            self.assertNotIn(snippet, rebuilt_html)


if __name__ == "__main__":
    unittest.main()
