import unittest

from automation import orchestrator


class OrchestratorSafetyTest(unittest.TestCase):
    def test_sanitize_repo_relative_path_normalizes_valid_path(self) -> None:
        self.assertEqual(
            orchestrator.sanitize_repo_relative_path("./automation/file.txt"),
            "automation/file.txt",
        )

    def test_sanitize_repo_relative_path_rejects_invalid_paths(self) -> None:
        invalid_paths = ["", ".", "..", "/tmp/x", "../x", "a/../../x"]
        for path in invalid_paths:
            with self.subTest(path=path):
                self.assertIsNone(orchestrator.sanitize_repo_relative_path(path))

    def test_sanitize_allowlist_deduplicates_preserving_order(self) -> None:
        self.assertEqual(
            orchestrator.sanitize_allowlist(
                ["./automation/file.txt", "automation/file.txt", "automation/other.txt", "automation/other.txt"]
            ),
            ["automation/file.txt", "automation/other.txt"],
        )

    def test_normalize_plan_data_sanitizes_allowlist(self) -> None:
        plan = orchestrator.normalize_plan_data(
            "goal",
            '{"should_execute": true, "execution_mode": "WRITE", "execution_task": "task", '
            '"recommended_allowlist": ["./automation/file.txt", "../x", "automation/file.txt"]}',
        )
        self.assertEqual(plan["recommended_allowlist"], ["automation/file.txt"])

    def test_normalize_review_data_sanitizes_allowlist(self) -> None:
        review = orchestrator.normalize_review_data(
            1,
            '{"should_continue": true, "outcome": "ok", "reason": "r", "next_mode": "WRITE", '
            '"next_task": "task", "recommended_allowlist": ["./automation/file.txt", "/tmp/x", "automation/file.txt"]}',
        )
        self.assertEqual(review["recommended_allowlist"], ["automation/file.txt"])

    def test_apply_operator_scope_enforces_subset(self) -> None:
        self.assertEqual(
            orchestrator.apply_operator_scope(
                ["./automation/one.txt", "automation/two.txt", "../x"],
                ["automation/one.txt"],
            ),
            ["automation/one.txt"],
        )

    def test_empty_iteration_allowlist_means_no_allowed_writes_when_operator_scope_exists(self) -> None:
        self.assertEqual(
            orchestrator.get_disallowed_changed_files(
                ["automation/file.txt"],
                [],
                operator_scope_active=True,
            ),
            ["automation/file.txt"],
        )

    def test_empty_iteration_allowlist_remains_unrestricted_without_operator_scope(self) -> None:
        self.assertEqual(
            orchestrator.get_disallowed_changed_files(
                ["automation/file.txt"],
                [],
                operator_scope_active=False,
            ),
            [],
        )

    def test_get_safe_repo_path_rejects_outside_repo_path(self) -> None:
        self.assertIsNone(orchestrator.get_safe_repo_path("../outside.txt"))

    def test_rollback_disallowed_changes_skips_outside_repo_path(self) -> None:
        rolled_back_files, failed_rollbacks = orchestrator.rollback_disallowed_changes(["../outside.txt"])
        self.assertEqual(rolled_back_files, [])
        self.assertEqual(len(failed_rollbacks), 1)
        self.assertIn("outside the repository root or invalid", failed_rollbacks[0])


if __name__ == "__main__":
    unittest.main()
