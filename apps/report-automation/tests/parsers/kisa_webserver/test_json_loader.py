import json
import sys
import tempfile
import unittest
from pathlib import Path


APP_ROOT = Path(__file__).resolve().parents[3]
REPO_ROOT = APP_ROOT.parent.parent
if str(APP_ROOT) not in sys.path:
    sys.path.insert(0, str(APP_ROOT))

from src.parsers.kisa_webserver.catalog_extractor import extract_kisa_webserver_catalog
from src.parsers.kisa_webserver.json_loader import (
    load_kisa_webserver_item_json,
    load_kisa_webserver_run_all_json,
)
from src.validators import validate_schema_file


FIXTURE_ROOT = APP_ROOT / "tests" / "fixtures" / "kisa_webserver" / "synthetic"
SOURCE_REPO = FIXTURE_ROOT / "source_repo"
SINGLE_JSON_DIR = FIXTURE_ROOT / "json" / "single"
RUN_ALL_JSON_DIR = FIXTURE_ROOT / "json" / "run_all"
SCHEMA_PATH = REPO_ROOT / "shared" / "schemas" / "kisa-webserver-raw-record.schema.json"


class JsonLoaderTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.catalog_entries = extract_kisa_webserver_catalog(source_root=SOURCE_REPO)

    def test_load_item_json_enriches_catalog_and_preserves_multiline_output(self) -> None:
        records = load_kisa_webserver_item_json(
            SINGLE_JSON_DIR / "apache_WEB04_pass.synthetic.json",
            catalog_entries=self.catalog_entries,
        )

        self.assertEqual(len(records), 1)
        record = records[0]
        validate_schema_file(record, SCHEMA_PATH)

        self.assertEqual(record["item_key"], "apache:WEB-04")
        self.assertEqual(record["title"], "Apache Directory Listing")
        self.assertEqual(record["severity"], "중")
        self.assertEqual(record["guideline_reference"], "KISA-WS-APACHE-WEB04")
        self.assertEqual(record["check_type"], "config")
        self.assertIn("\n", record["command_output"])
        self.assertIn("/etc/apache2/apache2.conf", record["config_path"])

    def test_load_run_all_json_flattens_items_and_preserves_manual_status(self) -> None:
        records = load_kisa_webserver_run_all_json(
            RUN_ALL_JSON_DIR / "nginx_run_all.synthetic.json",
            catalog_entries=self.catalog_entries,
        )

        self.assertEqual(len(records), 2)
        self.assertEqual([record["raw_status"] for record in records], ["FAIL", "MANUAL"])
        for record in records:
            validate_schema_file(record, SCHEMA_PATH)

    def test_load_item_json_preserves_error_status(self) -> None:
        records = load_kisa_webserver_item_json(
            SINGLE_JSON_DIR / "iis_WEB24_error.synthetic.json",
            catalog_entries=self.catalog_entries,
        )

        self.assertEqual(records[0]["raw_status"], "ERROR")
        validate_schema_file(records[0], SCHEMA_PATH)

    def test_catalog_miss_adds_warning_and_lowers_confidence(self) -> None:
        payload = {
            "synthetic_fixture": True,
            "platform": "Apache",
            "item_id": "WEB-99",
            "item_name": "Synthetic Missing Catalog Entry",
            "inspection": {
                "summary": "Synthetic summary for catalog miss",
                "status": "취약"
            },
            "final_result": "FAIL",
            "command": "grep something /etc/apache2/apache2.conf",
            "command_result": "/etc/apache2/apache2.conf: dummy",
            "hostname": "synthetic-web-99",
            "timestamp": "2026-03-20T09:40:00+09:00"
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "apache_WEB99.synthetic.json"
            path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
            records = load_kisa_webserver_item_json(path, catalog_entries=self.catalog_entries)

        record = records[0]
        validate_schema_file(record, SCHEMA_PATH)
        self.assertEqual(record["parser_confidence"], "low")
        self.assertTrue(any("Catalog entry not found" in warning for warning in record["parse_warnings"]))
        self.assertTrue(any("severity could not be resolved" in warning for warning in record["parse_warnings"]))


if __name__ == "__main__":
    unittest.main()
