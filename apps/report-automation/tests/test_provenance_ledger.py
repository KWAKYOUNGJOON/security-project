import hashlib
import json
import sys
import unittest
from pathlib import Path


APP_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = APP_ROOT.parent.parent
if str(APP_ROOT) not in sys.path:
    sys.path.insert(0, str(APP_ROOT))

from src.cli.main import build_all_artifacts
from src.validators import validate_schema_file


CASE_PATH = Path("cases/web/case-002")
SCHEMA_DIR = REPO_ROOT / "shared" / "schemas"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    digest.update(path.read_bytes())
    return digest.hexdigest()


class ProvenanceLedgerTest(unittest.TestCase):
    def test_case_002_provenance_ledger_is_valid_and_reproducible(self) -> None:
        result = build_all_artifacts(CASE_PATH)
        provenance_path = Path(result["provenance_path"])

        self.assertTrue(provenance_path.exists())

        provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
        validate_schema_file(provenance, SCHEMA_DIR / "provenance.schema.json")

        self.assertEqual(provenance["case_id"], "case-002")
        self.assertTrue(provenance["generated_at"].endswith("Z"))
        self.assertEqual(len(provenance["inputs"]), 18)

        input_roles = {item["role"] for item in provenance["inputs"]}
        self.assertEqual(
            input_roles,
            {"document-control", "engagement", "evidence", "http", "manual-finding", "raw", "tool-inventory"},
        )

        expected_outputs = {
            "cases/web/case-002/derived/normalized-findings.json",
            "cases/web/case-002/derived/report-payload.json",
            "cases/web/case-002/output/report-preview.html",
            "cases/web/case-002/output/report-preview.validation.json",
        }
        output_paths = {item["path"] for item in provenance["outputs"]}
        self.assertTrue(expected_outputs.issubset(output_paths))

        for item in provenance["inputs"]:
            file_path = REPO_ROOT / item["path"]
            self.assertTrue(file_path.exists(), item["path"])
            self.assertEqual(item["sha256"], _sha256(file_path))

        for item in provenance["outputs"]:
            file_path = REPO_ROOT / item["path"]
            self.assertTrue(file_path.exists(), item["path"])
            self.assertEqual(item["sha256"], _sha256(file_path))


if __name__ == "__main__":
    unittest.main()
