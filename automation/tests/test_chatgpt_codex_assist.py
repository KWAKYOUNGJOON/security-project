import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from automation import chatgpt_codex_loop


REPO_ROOT = Path(__file__).resolve().parents[2]
ASSIST_SCRIPT_PATH = REPO_ROOT / "automation" / "chatgpt_codex_assist.py"
LOOP_SCRIPT_PATH = REPO_ROOT / "automation" / "chatgpt_codex_loop.py"


class ChatgptCodexAssistTest(unittest.TestCase):
    def create_fake_clipboard_env(self, clipboard_text: str = "") -> dict[str, str]:
        tools_dir = tempfile.TemporaryDirectory()
        self.addCleanup(tools_dir.cleanup)
        tools_path = Path(tools_dir.name)
        clipboard_file = tools_path / "clipboard.txt"
        clipboard_file.write_text(clipboard_text, encoding="utf-8")

        for name, script in {
            "wl-copy": "#!/bin/sh\ncat > \"$FAKE_CLIPBOARD_FILE\"\n",
            "wl-paste": "#!/bin/sh\ncat \"$FAKE_CLIPBOARD_FILE\"\n",
        }.items():
            script_path = tools_path / name
            script_path.write_text(script, encoding="utf-8")
            script_path.chmod(0o755)

        return {
            "PATH": f"{tools_path}{os.pathsep}{os.environ.get('PATH', '')}",
            "FAKE_CLIPBOARD_FILE": str(clipboard_file),
            "WSL_DISTRO_NAME": "",
            "WSL_INTEROP": "",
        }

    def run_cli(
        self,
        script_path: Path,
        *args: str,
        env: dict[str, str] | None = None,
        input_text: str | None = None,
    ) -> subprocess.CompletedProcess[str]:
        cli_env = os.environ.copy()
        if env:
            cli_env.update(env)
        return subprocess.run(
            [sys.executable, str(script_path), *args],
            cwd=REPO_ROOT,
            env=cli_env,
            input=input_text,
            text=True,
            capture_output=True,
            check=False,
        )

    def run_assist_cli(
        self,
        *args: str,
        env: dict[str, str] | None = None,
        input_text: str | None = None,
    ) -> subprocess.CompletedProcess[str]:
        return self.run_cli(ASSIST_SCRIPT_PATH, *args, env=env, input_text=input_text)

    def run_loop_cli(
        self,
        *args: str,
        env: dict[str, str] | None = None,
        input_text: str | None = None,
    ) -> subprocess.CompletedProcess[str]:
        return self.run_cli(LOOP_SCRIPT_PATH, *args, env=env, input_text=input_text)

    def test_start_initializes_loop_and_generates_first_request(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            override_dir = Path(temp_dir) / "loop-root"
            env = {
                chatgpt_codex_loop.LOOP_DIR_ENV_VAR: str(override_dir),
                **self.create_fake_clipboard_env(),
            }

            result = self.run_assist_cli("start", "--goal", "Goal", env=env)

            self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
            request_path = override_dir / "chatgpt" / "request_001.md"
            self.assertTrue(request_path.exists())
            self.assertEqual(
                Path(env["FAKE_CLIPBOARD_FILE"]).read_text(encoding="utf-8"),
                request_path.read_text(encoding="utf-8"),
            )
            self.assertIn("Initialized loop.", result.stdout)
            self.assertIn("Action: generated_chatgpt_request", result.stdout)
            self.assertIn("Copied: ChatGPT request to clipboard.", result.stdout)
            self.assertIn("step --from-clipboard", result.stdout)

    def test_step_from_clipboard_saves_chatgpt_reply_and_copies_codex_prompt(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            override_dir = Path(temp_dir) / "loop-root"
            env = {
                chatgpt_codex_loop.LOOP_DIR_ENV_VAR: str(override_dir),
                **self.create_fake_clipboard_env(),
            }

            self.assertEqual(self.run_assist_cli("start", "--goal", "Goal", env=env).returncode, 0)
            clipboard_file = Path(env["FAKE_CLIPBOARD_FILE"])
            clipboard_file.write_text(
                "## CODEX_PROMPT\nInspect automation/README.md.\n\n## WHY\nClipboard flow.\n",
                encoding="utf-8",
            )

            result = self.run_assist_cli("step", "--from-clipboard", env=env)

            self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
            prompt_path = override_dir / "prompts" / "codex_prompt_001.md"
            self.assertTrue(prompt_path.exists())
            self.assertEqual(
                clipboard_file.read_text(encoding="utf-8"),
                "Inspect automation/README.md.\n",
            )
            self.assertIn("Phase: needs_chatgpt_reply -> needs_codex_reply", result.stdout)
            self.assertIn("Action: saved_chatgpt_reply", result.stdout)
            self.assertIn("Copied: Codex prompt to clipboard.", result.stdout)
            self.assertIn("step --from-clipboard", result.stdout)

    def test_step_from_clipboard_saves_codex_reply_and_generates_next_request(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            override_dir = Path(temp_dir) / "loop-root"
            env = {
                chatgpt_codex_loop.LOOP_DIR_ENV_VAR: str(override_dir),
                **self.create_fake_clipboard_env(),
            }

            self.assertEqual(self.run_assist_cli("start", "--goal", "Goal", env=env).returncode, 0)
            clipboard_file = Path(env["FAKE_CLIPBOARD_FILE"])
            clipboard_file.write_text(
                "## CODEX_PROMPT\nInspect automation/chatgpt_codex_loop.py.\n\n## WHY\nNeed the next step.\n",
                encoding="utf-8",
            )
            self.assertEqual(self.run_assist_cli("step", "--from-clipboard", env=env).returncode, 0)

            clipboard_file.write_text("Implemented the requested change.\n", encoding="utf-8")
            result = self.run_assist_cli("step", "--from-clipboard", env=env)

            self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
            request_path = override_dir / "chatgpt" / "request_002.md"
            self.assertTrue(request_path.exists())
            state = json.loads((override_dir / "state.json").read_text(encoding="utf-8"))
            self.assertEqual(state["iteration"], 1)
            self.assertEqual(
                clipboard_file.read_text(encoding="utf-8"),
                request_path.read_text(encoding="utf-8"),
            )
            self.assertIn("Phase: needs_codex_reply -> needs_chatgpt_reply", result.stdout)
            self.assertIn("Action: saved_codex_reply_and_generated_next_chatgpt_request", result.stdout)
            self.assertIn("Copied: ChatGPT request to clipboard.", result.stdout)

    def test_start_degrades_clearly_when_clipboard_support_is_unavailable(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            override_dir = Path(temp_dir) / "loop-root"
            env = {
                chatgpt_codex_loop.LOOP_DIR_ENV_VAR: str(override_dir),
                "PATH": "",
                "WSL_DISTRO_NAME": "",
                "WSL_INTEROP": "",
            }

            result = self.run_assist_cli("start", "--goal", "Goal", env=env)

            self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
            self.assertTrue((override_dir / "chatgpt" / "request_001.md").exists())
            self.assertIn("Copied: no", result.stdout)

    def test_wrapper_respects_loop_root_override_and_underlying_loop_cli_still_works(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            override_dir = Path(temp_dir) / "loop-root"
            env = {
                chatgpt_codex_loop.LOOP_DIR_ENV_VAR: str(override_dir),
                **self.create_fake_clipboard_env(),
            }

            self.assertEqual(self.run_assist_cli("start", "--goal", "Goal", env=env).returncode, 0)
            result = self.run_loop_cli("status", "--json", env=env)

        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["loop_root"], str(override_dir.resolve()))
        self.assertEqual(payload["latest_chatgpt_request"], str(override_dir / "chatgpt" / "request_001.md"))

    def test_assist_doctor_reports_uninitialized_loop(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            override_dir = Path(temp_dir) / "loop-root"
            result = self.run_assist_cli(
                "doctor",
                env={chatgpt_codex_loop.LOOP_DIR_ENV_VAR: str(override_dir)},
            )

        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
        self.assertIn("Loop root:", result.stdout)
        self.assertIn("Diagnosis: Loop not initialized.", result.stdout)
        self.assertIn("init --goal", result.stdout)

    def test_assist_status_reports_healthy_loop_summary(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            override_dir = Path(temp_dir) / "loop-root"
            env = {
                chatgpt_codex_loop.LOOP_DIR_ENV_VAR: str(override_dir),
                **self.create_fake_clipboard_env(),
            }

            self.assertEqual(self.run_assist_cli("start", "--goal", "Goal", env=env).returncode, 0)
            result = self.run_assist_cli("status", env=env)

        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
        self.assertIn("Goal: Goal", result.stdout)
        self.assertIn("Iteration: 0", result.stdout)
        self.assertIn("State: Healthy partial cycle", result.stdout)
        self.assertIn("step --from-clipboard", result.stdout)

    def test_assist_history_reports_recent_events_under_override(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            override_dir = Path(temp_dir) / "loop-root"
            env = {chatgpt_codex_loop.LOOP_DIR_ENV_VAR: str(override_dir)}

            self.assertEqual(self.run_loop_cli("init", "--goal", "Goal", env=env).returncode, 0)
            self.assertEqual(self.run_loop_cli("next-chatgpt", env=env).returncode, 0)

            result = self.run_assist_cli("history", "--limit", "2", env=env)

        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
        self.assertIn(f"Loop root: {override_dir.resolve()}", result.stdout)
        self.assertIn("Recent events (showing 2 of 2):", result.stdout)
        self.assertIn("| init |", result.stdout)
        self.assertIn("| next-chatgpt |", result.stdout)
        self.assertIn("request_001.md", result.stdout)

    def test_assist_lock_status_reports_suspicious_lock_under_override(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            override_dir = Path(temp_dir) / "loop-root"
            (override_dir).mkdir(parents=True, exist_ok=True)
            (override_dir / chatgpt_codex_loop.WRITE_LOCK_FILE_NAME).write_text(
                json.dumps(
                    {
                        "timestamp": "2026-03-22T04:05:06+00:00",
                        "pid": 10_000_000,
                        "command": "advance",
                        "loop_root": str(override_dir.resolve()),
                        "root_mode": "override",
                    },
                    indent=2,
                )
                + "\n",
                encoding="utf-8",
            )

            result = self.run_assist_cli(
                "lock-status",
                env={chatgpt_codex_loop.LOOP_DIR_ENV_VAR: str(override_dir)},
            )

        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
        self.assertIn(f"Loop root: {override_dir.resolve()}", result.stdout)
        self.assertIn("Lock state: suspicious", result.stdout)
        self.assertIn("Lock command: advance", result.stdout)
        self.assertIn("Lock pid: 10000000", result.stdout)
        self.assertIn("clear-lock --force", result.stdout)


if __name__ == "__main__":
    unittest.main()
