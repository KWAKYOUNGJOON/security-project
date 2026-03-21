import json
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TASKS_PATH = REPO_ROOT / ".vscode" / "tasks.json"
ASSIST_SCRIPT_PATH = REPO_ROOT / "automation" / "chatgpt_codex_assist.py"


class VscodeTasksTest(unittest.TestCase):
    def load_tasks_config(self) -> dict:
        return json.loads(TASKS_PATH.read_text(encoding="utf-8"))

    def task_by_label(self, config: dict, label: str) -> dict:
        for task in config["tasks"]:
            if task["label"] == label:
                return task
        self.fail(f"Missing VS Code task: {label}")

    def test_tasks_json_is_valid_json(self) -> None:
        config = self.load_tasks_config()

        self.assertEqual(config["version"], "2.0.0")
        self.assertIsInstance(config["tasks"], list)
        self.assertIsInstance(config["inputs"], list)

    def test_tasks_use_wrapper_entrypoints_with_expected_labels(self) -> None:
        config = self.load_tasks_config()
        self.assertTrue(ASSIST_SCRIPT_PATH.exists(), ASSIST_SCRIPT_PATH)

        expected = {
            "ChatGPT-Codex: Start Loop": [
                "automation/chatgpt_codex_assist.py",
                "start",
                "--goal",
                "${input:chatgptCodexLoopGoal}",
            ],
            "ChatGPT-Codex: Advance From Clipboard": [
                "automation/chatgpt_codex_assist.py",
                "step",
                "--from-clipboard",
            ],
            "ChatGPT-Codex: Status": [
                "automation/chatgpt_codex_assist.py",
                "status",
            ],
            "ChatGPT-Codex: Doctor": [
                "automation/chatgpt_codex_assist.py",
                "doctor",
            ],
            "ChatGPT-Codex: History": [
                "automation/chatgpt_codex_assist.py",
                "history",
                "--limit",
                "10",
            ],
            "ChatGPT-Codex: Lock Status": [
                "automation/chatgpt_codex_assist.py",
                "lock-status",
            ],
        }

        for label, args in expected.items():
            task = self.task_by_label(config, label)
            self.assertEqual(task["type"], "shell")
            self.assertEqual(task["command"], "python3")
            self.assertEqual(task["args"], args)
            self.assertEqual(task["options"]["cwd"], "${workspaceFolder}")
            self.assertEqual(task["problemMatcher"], [])

    def test_start_task_uses_goal_prompt_input(self) -> None:
        config = self.load_tasks_config()

        self.assertIn(
            {
                "id": "chatgptCodexLoopGoal",
                "type": "promptString",
                "description": "Top-level goal for the ChatGPT <-> Codex loop",
                "default": "Find the next safe repo improvement",
            },
            config["inputs"],
        )


if __name__ == "__main__":
    unittest.main()
