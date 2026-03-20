import json
import sys
import tempfile
import unittest
from pathlib import Path


APP_ROOT = Path(__file__).resolve().parents[2]
REPO_ROOT = APP_ROOT.parent.parent
if str(APP_ROOT) not in sys.path:
    sys.path.insert(0, str(APP_ROOT))

from src.adapters import (
    adapt_kisa_webserver_raw_record,
    adapt_kisa_webserver_raw_records,
)
from src.parsers.kisa_webserver.catalog_extractor import extract_kisa_webserver_catalog
from src.parsers.kisa_webserver.json_loader import load_kisa_webserver_item_json
from src.validators import validate_schema_file


FIXTURE_ROOT = APP_ROOT / "tests" / "fixtures" / "kisa_webserver" / "synthetic"
SOURCE_REPO = FIXTURE_ROOT / "source_repo"
SINGLE_JSON_DIR = FIXTURE_ROOT / "json" / "single"
SCHEMA_DIR = REPO_ROOT / "shared" / "schemas"


class KisaWebserverFailOnlyAdapterTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.catalog_entries = extract_kisa_webserver_catalog(source_root=SOURCE_REPO)

    def test_adapter_buckets_records_by_status_and_counts_summary(self) -> None:
        records = []
        for name in (
            "apache_WEB04_fail.synthetic.json",
            "apache_WEB04_pass.synthetic.json",
            "nginx_WEB23_fail.synthetic.json",
            "nginx_WEB25_manual.synthetic.json",
            "nginx_WEB26_na.synthetic.json",
            "iis_WEB24_error.synthetic.json",
            "iis_WEB04_pass.synthetic.json",
        ):
            records.extend(
                load_kisa_webserver_item_json(
                    SINGLE_JSON_DIR / name,
                    catalog_entries=self.catalog_entries,
                )
            )

        adapted = adapt_kisa_webserver_raw_records(records)
        validate_schema_file(
            adapted,
            SCHEMA_DIR / "kisa-webserver-adapter-output.schema.json",
        )

        self.assertEqual(len(adapted["finding_candidates"]), 2)
        self.assertEqual(len(adapted["review_queue"]), 2)
        self.assertEqual(len(adapted["checklist_items"]), 1)
        self.assertEqual(len(adapted["pass_records"]), 2)

        self.assertEqual(adapted["summary"]["total"], 7)
        self.assertEqual(adapted["summary"]["fail_count"], 2)
        self.assertEqual(adapted["summary"]["manual_count"], 1)
        self.assertEqual(adapted["summary"]["error_count"], 1)
        self.assertEqual(adapted["summary"]["na_count"], 1)
        self.assertEqual(adapted["summary"]["pass_count"], 2)
        self.assertEqual(adapted["summary"]["low_confidence_count"], 0)

        candidate = next(
            item for item in adapted["finding_candidates"] if item["item_key"] == "apache:WEB-04"
        )
        multiline_candidate = next(
            item for item in adapted["finding_candidates"] if item["item_key"] == "nginx:WEB-23"
        )
        validate_schema_file(
            candidate,
            SCHEMA_DIR / "kisa-webserver-finding-candidate.schema.json",
        )
        self.assertEqual(candidate["item_key"], "apache:WEB-04")
        self.assertFalse(candidate["triage_required"])
        self.assertIn("\n", multiline_candidate["command_output"])

        manual_item = adapted["review_queue"][0]
        error_item = adapted["review_queue"][1]
        validate_schema_file(
            manual_item,
            SCHEMA_DIR / "kisa-webserver-review-queue-item.schema.json",
        )
        validate_schema_file(
            error_item,
            SCHEMA_DIR / "kisa-webserver-review-queue-item.schema.json",
        )
        self.assertEqual(manual_item["review_type"], "manual_check")
        self.assertEqual(manual_item["review_reason"], "manual_verification_required")
        self.assertEqual(error_item["review_type"], "collection_error")
        self.assertEqual(error_item["review_reason"], "collection_or_execution_error")

        checklist_item = adapted["checklist_items"][0]
        validate_schema_file(
            checklist_item,
            SCHEMA_DIR / "kisa-webserver-checklist-item.schema.json",
        )
        self.assertEqual(checklist_item["raw_status"], "N/A")
        self.assertEqual(checklist_item["applicability"], "service_not_running")

    def test_adapter_marks_triage_for_low_confidence_fail_records(self) -> None:
        payload = {
            "synthetic_fixture": True,
            "platform": "Apache",
            "item_id": "WEB-99",
            "item_name": "Synthetic Missing Catalog Entry",
            "inspection": {
                "summary": "Synthetic FAIL summary for catalog miss",
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

        adapted = adapt_kisa_webserver_raw_records(records)
        candidate = adapted["finding_candidates"][0]

        validate_schema_file(
            candidate,
            SCHEMA_DIR / "kisa-webserver-finding-candidate.schema.json",
        )
        self.assertTrue(candidate["triage_required"])
        self.assertIn("severity_missing", candidate["triage_reasons"])
        self.assertIn("parser_confidence_low", candidate["triage_reasons"])
        self.assertIn("parse_warnings_present", candidate["triage_reasons"])
        self.assertIn("guideline_reference_missing", candidate["triage_reasons"])
        self.assertEqual(adapted["summary"]["low_confidence_count"], 1)

    def test_single_record_entrypoint_returns_same_bundle_shape(self) -> None:
        record = load_kisa_webserver_item_json(
            SINGLE_JSON_DIR / "apache_WEB04_fail.synthetic.json",
            catalog_entries=self.catalog_entries,
        )[0]

        adapted = adapt_kisa_webserver_raw_record(record)

        validate_schema_file(
            adapted,
            SCHEMA_DIR / "kisa-webserver-adapter-output.schema.json",
        )
        self.assertEqual(adapted["summary"]["total"], 1)
        self.assertEqual(len(adapted["finding_candidates"]), 1)
        self.assertEqual(adapted["finding_candidates"][0]["candidate_status"], "candidate")


if __name__ == "__main__":
    unittest.main()
