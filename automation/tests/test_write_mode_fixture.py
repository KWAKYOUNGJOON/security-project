import unittest
from pathlib import Path


EXPECTED_CONTENT = (
    "# WRITE MODE TEST\n"
    "\n"
    "This file was created by the Codex orchestrator in write mode.\n"
)


class WriteModeFixtureTest(unittest.TestCase):
    def test_write_mode_fixture_matches_expected_content(self) -> None:
        fixture_path = Path(__file__).resolve().parents[1] / "WRITE_MODE_TEST.md"
        content = fixture_path.read_text(encoding="utf-8")

        self.assertEqual(content, EXPECTED_CONTENT)
        self.assertEqual(
            content.splitlines(),
            [
                "# WRITE MODE TEST",
                "",
                "This file was created by the Codex orchestrator in write mode.",
            ],
        )


if __name__ == "__main__":
    unittest.main()
