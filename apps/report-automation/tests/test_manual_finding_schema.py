import copy
import sys
import unittest
from pathlib import Path


APP_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = APP_ROOT.parent.parent
if str(APP_ROOT) not in sys.path:
    sys.path.insert(0, str(APP_ROOT))

from src.cases import load_case_inputs
from src.validators import SchemaValidationError, validate_manual_finding


CASE_DIR = REPO_ROOT / "cases" / "web" / "case-001"
SCHEMA_DIR = REPO_ROOT / "shared" / "schemas"


class ManualFindingSchemaTest(unittest.TestCase):
    def test_sample_manual_finding_is_valid(self) -> None:
        case_inputs = load_case_inputs(CASE_DIR, REPO_ROOT)

        validate_manual_finding(
            case_inputs.manual_finding,
            schema_dir=SCHEMA_DIR,
            repo_root=REPO_ROOT,
        )

        self.assertEqual(case_inputs.manual_finding["taxonomy"]["name"], "web-kisa-2026")
        self.assertEqual(case_inputs.manual_finding["taxonomy"]["version"], "2026")

    def test_missing_taxonomy_version_fails_validation(self) -> None:
        case_inputs = load_case_inputs(CASE_DIR, REPO_ROOT)
        invalid_manual = copy.deepcopy(case_inputs.manual_finding)
        invalid_manual["taxonomy"].pop("version")

        with self.assertRaises(SchemaValidationError):
            validate_manual_finding(
                invalid_manual,
                schema_dir=SCHEMA_DIR,
                repo_root=REPO_ROOT,
            )


if __name__ == "__main__":
    unittest.main()
