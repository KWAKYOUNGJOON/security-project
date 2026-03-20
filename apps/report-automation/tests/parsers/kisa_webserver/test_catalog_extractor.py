import sys
import unittest
from pathlib import Path


APP_ROOT = Path(__file__).resolve().parents[3]
REPO_ROOT = APP_ROOT.parent.parent
if str(APP_ROOT) not in sys.path:
    sys.path.insert(0, str(APP_ROOT))

from src.parsers.kisa_webserver.catalog_extractor import extract_kisa_webserver_catalog


FIXTURE_ROOT = (
    APP_ROOT / "tests" / "fixtures" / "kisa_webserver" / "synthetic" / "source_repo"
)


class CatalogExtractorTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.entries = extract_kisa_webserver_catalog(source_root=FIXTURE_ROOT)
        cls.catalog = {entry["item_key"]: entry for entry in cls.entries}

    def test_extract_catalog_builds_platform_scoped_item_keys(self) -> None:
        for item_key in ("apache:WEB-23", "nginx:WEB-23", "iis:WEB-23", "tomcat:WEB-23"):
            self.assertIn(item_key, self.catalog)

        self.assertNotEqual(
            self.catalog["apache:WEB-23"]["title"],
            self.catalog["nginx:WEB-23"]["title"],
        )

    def test_extract_catalog_records_warnings_confidence_and_check_types(self) -> None:
        nginx_web16 = self.catalog["nginx:WEB-16"]
        self.assertEqual(nginx_web16["severity"], "상")
        self.assertEqual(nginx_web16["metadata_confidence"], "medium")
        self.assertTrue(
            any("severity mismatch" in warning for warning in nginx_web16["warnings"])
        )

        tomcat_web26 = self.catalog["tomcat:WEB-26"]
        self.assertIsNone(tomcat_web26["reference"])
        self.assertTrue(any("reference is missing" in warning for warning in tomcat_web26["warnings"]))

        self.assertEqual(self.catalog["apache:WEB-23"]["check_type"], "manual")
        self.assertEqual(self.catalog["nginx:WEB-23"]["check_type"], "heuristic")
        self.assertEqual(self.catalog["iis:WEB-24"]["check_type"], "config")
        self.assertEqual(self.catalog["tomcat:WEB-25"]["check_type"], "version")


if __name__ == "__main__":
    unittest.main()
