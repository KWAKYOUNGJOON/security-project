import sys
import unittest
from pathlib import Path


APP_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = APP_ROOT.parent.parent
if str(APP_ROOT) not in sys.path:
    sys.path.insert(0, str(APP_ROOT))

from src.taxonomies import resolve_taxonomy_code


class TaxonomyMappingTest(unittest.TestCase):
    def test_legacy_sf_maps_to_session_fixation(self) -> None:
        mapping = resolve_taxonomy_code("web-legacy-template", "1.0", "SF", REPO_ROOT)

        self.assertEqual(mapping["taxonomy"]["name"], "web-legacy-template")
        self.assertEqual(mapping["canonical_key"], "session_fixation")

    def test_kisa_sf_maps_to_ssrf(self) -> None:
        mapping = resolve_taxonomy_code("web-kisa-2026", "2026", "SF", REPO_ROOT)

        self.assertEqual(mapping["taxonomy"]["name"], "web-kisa-2026")
        self.assertEqual(mapping["canonical_key"], "ssrf")

    def test_au_maps_consistently_across_taxonomies(self) -> None:
        legacy = resolve_taxonomy_code("web-legacy-template", "1.0", "AU", REPO_ROOT)
        kisa = resolve_taxonomy_code("web-kisa-2026", "2026", "AU", REPO_ROOT)

        self.assertEqual(legacy["canonical_key"], "automated_attack")
        self.assertEqual(kisa["canonical_key"], "automated_attack")


if __name__ == "__main__":
    unittest.main()
