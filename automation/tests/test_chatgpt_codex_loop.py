import argparse
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from automation import chatgpt_codex_loop


REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = REPO_ROOT / "automation" / "chatgpt_codex_loop.py"


class ChatgptCodexLoopTest(unittest.TestCase):
    def make_paths(self) -> chatgpt_codex_loop.LoopPaths:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        return chatgpt_codex_loop.build_paths(Path(self.temp_dir.name))

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

    def initialize_cycle(self, paths: chatgpt_codex_loop.LoopPaths, goal: str = "Goal") -> None:
        chatgpt_codex_loop.write_state(paths, chatgpt_codex_loop.default_state(goal))
        with redirect_stdout(io.StringIO()):
            chatgpt_codex_loop.command_next_chatgpt(argparse.Namespace(copy=False), paths)

    def save_valid_chatgpt_reply(
        self,
        paths: chatgpt_codex_loop.LoopPaths,
        reply: str | None = None,
    ) -> None:
        if reply is None:
            reply = (
                "## CODEX_PROMPT\n"
                "Do the next repo step.\n\n"
                "## WHY\n"
                "Because it is next.\n"
            )
        with patch("sys.stdin", io.StringIO(reply)):
            with redirect_stdout(io.StringIO()):
                chatgpt_codex_loop.command_save_chatgpt_reply(
                    argparse.Namespace(file=None, from_clipboard=False),
                    paths,
                )

    def save_valid_codex_reply(
        self,
        paths: chatgpt_codex_loop.LoopPaths,
        reply: str = "Codex completed the step.\n",
    ) -> None:
        with patch("sys.stdin", io.StringIO(reply)):
            with redirect_stdout(io.StringIO()):
                chatgpt_codex_loop.command_save_codex_reply(
                    argparse.Namespace(file=None, from_clipboard=False),
                    paths,
                )

    def run_cli(
        self,
        *args: str,
        env: dict[str, str] | None = None,
        input_text: str | None = None,
    ) -> subprocess.CompletedProcess[str]:
        cli_env = os.environ.copy()
        if env:
            cli_env.update(env)
        return subprocess.run(
            [sys.executable, str(SCRIPT_PATH), *args],
            cwd=REPO_ROOT,
            env=cli_env,
            input=input_text,
            text=True,
            capture_output=True,
            check=False,
        )

    def read_logged_events(self, loop_dir: Path) -> list[dict]:
        log_path = loop_dir / chatgpt_codex_loop.EVENTS_FILE_NAME
        if not log_path.exists():
            return []
        return [
            json.loads(line)
            for line in log_path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]

    def create_write_lock(
        self,
        loop_dir: Path,
        *,
        command: str = "advance",
        pid: int = 999999,
        timestamp: str = "2026-03-22T00:00:00+00:00",
    ) -> Path:
        loop_dir.mkdir(parents=True, exist_ok=True)
        lock_path = loop_dir / chatgpt_codex_loop.WRITE_LOCK_FILE_NAME
        lock_path.write_text(
            json.dumps(
                {
                    "timestamp": timestamp,
                    "pid": pid,
                    "command": command,
                    "loop_root": str(loop_dir.resolve()),
                    "root_mode": "override",
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        return lock_path

    def test_init_creates_state_and_directories(self) -> None:
        paths = self.make_paths()
        with redirect_stdout(io.StringIO()):
            chatgpt_codex_loop.command_init(
                argparse.Namespace(goal="Ship a safe repo-local loop."),
                paths,
            )

        self.assertTrue(paths.loop_dir.exists())
        self.assertTrue(paths.chatgpt_dir.exists())
        self.assertTrue(paths.codex_dir.exists())
        self.assertTrue(paths.prompts_dir.exists())
        state = json.loads(paths.state_file.read_text(encoding="utf-8"))
        self.assertEqual(state["goal"], "Ship a safe repo-local loop.")
        self.assertEqual(state["iteration"], 0)
        self.assertEqual(state["latest_chatgpt_request"], "")
        self.assertEqual(state["latest_chatgpt_reply"], "")
        self.assertEqual(state["latest_codex_prompt"], "")
        self.assertEqual(state["latest_codex_reply"], "")

    def test_init_refuses_existing_artifacts_without_force(self) -> None:
        paths = self.make_paths()
        paths.chatgpt_dir.mkdir(parents=True, exist_ok=True)
        (paths.chatgpt_dir / "request_001.md").write_text("existing request\n", encoding="utf-8")

        with self.assertRaises(SystemExit) as exc:
            chatgpt_codex_loop.command_init(
                argparse.Namespace(goal="Ship a safe repo-local loop."),
                paths,
            )

        self.assertIn("Refusing to overwrite existing loop state or artifacts", str(exc.exception))
        self.assertIn(str(paths.loop_dir), str(exc.exception))

    def test_guide_with_no_state_suggests_init(self) -> None:
        paths = self.make_paths()
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            chatgpt_codex_loop.command_guide(argparse.Namespace(), paths)

        output = stdout.getvalue()
        self.assertIn("Loop root:", output)
        self.assertIn("No loop state exists.", output)
        self.assertIn("init --goal", output)

    def test_guide_after_init_suggests_next_chatgpt(self) -> None:
        paths = self.make_paths()
        chatgpt_codex_loop.write_state(paths, chatgpt_codex_loop.default_state("Goal"))

        stdout = io.StringIO()
        with patch.object(chatgpt_codex_loop, "get_clipboard_copy_command", return_value=None):
            with patch.object(chatgpt_codex_loop, "get_clipboard_paste_command", return_value=None):
                with redirect_stdout(stdout):
                    chatgpt_codex_loop.command_guide(argparse.Namespace(), paths)

        output = stdout.getvalue()
        self.assertIn("next-chatgpt", output)

    def test_next_chatgpt_generates_and_saves_request(self) -> None:
        paths = self.make_paths()
        chatgpt_codex_loop.write_state(paths, chatgpt_codex_loop.default_state("Investigate the next repo task."))

        stdout = io.StringIO()
        with redirect_stdout(stdout):
            chatgpt_codex_loop.command_next_chatgpt(argparse.Namespace(copy=False), paths)

        request_path = paths.chatgpt_dir / "request_001.md"
        self.assertTrue(request_path.exists())
        request_text = request_path.read_text(encoding="utf-8")
        self.assertIn("## CODEX_PROMPT", request_text)
        self.assertIn("## WHY", request_text)
        self.assertIn("Investigate the next repo task.", request_text)
        self.assertEqual(stdout.getvalue(), request_text)

    def test_later_cycle_next_chatgpt_omits_prior_full_request_body(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            override_dir = Path(temp_dir) / "loop-root"
            env = {chatgpt_codex_loop.LOOP_DIR_ENV_VAR: str(override_dir)}

            self.assertEqual(self.run_cli("init", "--goal", "Keep loop prompts lean.", env=env).returncode, 0)
            first_request = self.run_cli("next-chatgpt", env=env)
            self.assertEqual(first_request.returncode, 0, first_request.stderr or first_request.stdout)

            self.assertEqual(
                self.run_cli(
                    "save-chatgpt-reply",
                    env=env,
                    input_text=(
                        "## CODEX_PROMPT\n"
                        "Inspect automation/chatgpt_codex_loop.py and trim recursive growth.\n\n"
                        "## WHY\n"
                        "The request should stay concise.\n"
                    ),
                ).returncode,
                0,
            )
            self.assertEqual(
                self.run_cli(
                    "save-codex-reply",
                    env=env,
                    input_text="Implemented bounded recent-context handling.\n",
                ).returncode,
                0,
            )

            second_request = self.run_cli("next-chatgpt", env=env)
            self.assertEqual(second_request.returncode, 0, second_request.stderr or second_request.stdout)
            output = second_request.stdout

            self.assertNotIn("## LATEST_CHATGPT_REQUEST", output)
            self.assertEqual(output.count("## TOP_LEVEL_GOAL"), 1)
            self.assertEqual(output.count("Required response format:"), 1)
            self.assertIn("Inspect automation/chatgpt_codex_loop.py and trim recursive growth.", output)
            self.assertIn("Implemented bounded recent-context handling.", output)

    def test_later_cycle_next_chatgpt_keeps_recent_context_bounded_and_readable(self) -> None:
        paths = self.make_paths()
        self.initialize_cycle(paths, goal="Keep loop prompts bounded across repeated cycles.")
        long_prompt = "Investigate prompt growth safeguards. " * 40
        long_why = "We want readable follow-up context. " * 40
        self.save_valid_chatgpt_reply(
            paths,
            reply=(
                "## CODEX_PROMPT\n"
                f"{long_prompt}\n\n"
                "## WHY\n"
                f"{long_why}\n"
            ),
        )
        long_codex_reply = ("Implemented bounded context. " * 50) + "TAIL_MARKER_SHOULD_NOT_APPEAR\n"
        self.save_valid_codex_reply(paths, reply=long_codex_reply)

        stdout = io.StringIO()
        with redirect_stdout(stdout):
            chatgpt_codex_loop.command_next_chatgpt(argparse.Namespace(copy=False), paths)

        request_text = stdout.getvalue()
        self.assertLess(len(request_text), 2200)
        self.assertIn("## LATEST_CHATGPT_REPLY", request_text)
        self.assertIn("## LATEST_CODEX_REPLY", request_text)
        self.assertIn("Investigate prompt growth safeguards.", request_text)
        self.assertIn("Implemented bounded context.", request_text)
        self.assertNotIn("TAIL_MARKER_SHOULD_NOT_APPEAR", request_text)

    def test_guide_after_next_chatgpt_suggests_save_chatgpt_reply(self) -> None:
        paths = self.make_paths()
        chatgpt_codex_loop.write_state(paths, chatgpt_codex_loop.default_state("Goal"))
        with redirect_stdout(io.StringIO()):
            chatgpt_codex_loop.command_next_chatgpt(argparse.Namespace(copy=False), paths)

        stdout = io.StringIO()
        with patch.object(chatgpt_codex_loop, "get_clipboard_copy_command", return_value=None):
            with patch.object(chatgpt_codex_loop, "get_clipboard_paste_command", return_value=None):
                with redirect_stdout(stdout):
                    chatgpt_codex_loop.command_guide(argparse.Namespace(), paths)

        output = stdout.getvalue()
        self.assertIn("save-chatgpt-reply", output)
        self.assertIn("request_001.md", output)

    def test_next_chatgpt_copy_invokes_clipboard_helper(self) -> None:
        paths = self.make_paths()
        chatgpt_codex_loop.write_state(paths, chatgpt_codex_loop.default_state("Investigate the next repo task."))

        with patch.object(chatgpt_codex_loop, "copy_to_clipboard") as copy_mock:
            with redirect_stdout(io.StringIO()):
                chatgpt_codex_loop.command_next_chatgpt(argparse.Namespace(copy=True), paths)

        copy_mock.assert_called_once()
        copied_text = copy_mock.call_args.args[0]
        self.assertIn("## CODEX_PROMPT", copied_text)

    def test_save_chatgpt_reply_extracts_codex_prompt(self) -> None:
        paths = self.make_paths()
        self.initialize_cycle(paths)
        reply = (
            "## CODEX_PROMPT\n"
            "Inspect automation/orchestrator.py and summarize the next fix.\n\n"
            "## WHY\n"
            "We need a concrete next step.\n"
        )

        with patch("sys.stdin", io.StringIO(reply)):
            with redirect_stdout(io.StringIO()):
                chatgpt_codex_loop.command_save_chatgpt_reply(
                    argparse.Namespace(file=None, from_clipboard=False),
                    paths,
                )

        reply_path = paths.chatgpt_dir / "reply_001.md"
        prompt_path = paths.prompts_dir / "codex_prompt_001.md"
        self.assertEqual(reply_path.read_text(encoding="utf-8"), reply)
        self.assertEqual(
            prompt_path.read_text(encoding="utf-8"),
            "Inspect automation/orchestrator.py and summarize the next fix.\n",
        )

    def test_save_chatgpt_reply_file_reads_from_file(self) -> None:
        paths = self.make_paths()
        self.initialize_cycle(paths)
        reply_path = Path(self.temp_dir.name) / "chatgpt_reply.md"
        reply_path.write_text(
            "## CODEX_PROMPT\nReview automation/README.md.\n\n## WHY\nNeed a doc follow-up.\n",
            encoding="utf-8",
        )

        with redirect_stdout(io.StringIO()):
            chatgpt_codex_loop.command_save_chatgpt_reply(
                argparse.Namespace(file=str(reply_path), from_clipboard=False),
                paths,
            )

        prompt_path = paths.prompts_dir / "codex_prompt_001.md"
        self.assertEqual(prompt_path.read_text(encoding="utf-8"), "Review automation/README.md.\n")

    def test_save_chatgpt_reply_fails_when_current_request_is_missing(self) -> None:
        paths = self.make_paths()
        chatgpt_codex_loop.write_state(paths, chatgpt_codex_loop.default_state("Goal"))
        reply = "## CODEX_PROMPT\nReview automation/README.md.\n\n## WHY\nNeed a doc follow-up.\n"

        with patch("sys.stdin", io.StringIO(reply)):
            with self.assertRaises(SystemExit) as exc:
                chatgpt_codex_loop.command_save_chatgpt_reply(
                    argparse.Namespace(file=None, from_clipboard=False),
                    paths,
                )

        self.assertIn("Current cycle ChatGPT request does not exist yet", str(exc.exception))
        self.assertIn("next-chatgpt", str(exc.exception))

    def test_save_chatgpt_reply_fails_when_codex_prompt_missing(self) -> None:
        paths = self.make_paths()
        self.initialize_cycle(paths)
        reply = "## WHY\nThere is no codex prompt here.\n"

        with patch("sys.stdin", io.StringIO(reply)):
            with self.assertRaises(SystemExit) as exc:
                chatgpt_codex_loop.command_save_chatgpt_reply(
                    argparse.Namespace(file=None, from_clipboard=False),
                    paths,
                )

        self.assertIn("## CODEX_PROMPT", str(exc.exception))

    def test_save_chatgpt_reply_rejects_current_request_with_actionable_guidance(self) -> None:
        paths = self.make_paths()
        self.initialize_cycle(paths)
        current_request = (paths.chatgpt_dir / "request_001.md").read_text(encoding="utf-8")

        with patch("sys.stdin", io.StringIO(current_request)):
            with self.assertRaises(SystemExit) as exc:
                chatgpt_codex_loop.command_save_chatgpt_reply(
                    argparse.Namespace(file=None, from_clipboard=False, copy_prompt=False),
                    paths,
                )

        self.assertIn("generated ChatGPT request", str(exc.exception))
        self.assertIn("ChatGPT's actual reply", str(exc.exception))
        self.assertFalse((paths.chatgpt_dir / "reply_001.md").exists())
        self.assertFalse((paths.prompts_dir / "codex_prompt_001.md").exists())

    def test_guide_after_save_chatgpt_reply_suggests_show_prompt_and_save_codex_reply_without_clipboard(self) -> None:
        paths = self.make_paths()
        self.initialize_cycle(paths)
        self.save_valid_chatgpt_reply(paths)

        stdout = io.StringIO()
        with patch.object(chatgpt_codex_loop, "get_clipboard_copy_command", return_value=None):
            with redirect_stdout(stdout):
                chatgpt_codex_loop.command_guide(argparse.Namespace(), paths)

        output = stdout.getvalue()
        self.assertIn("show-codex-prompt", output)
        self.assertIn("save-codex-reply", output)
        self.assertIn("codex_prompt_001.md", output)

    def test_save_reply_file_missing_or_empty_fails_clearly(self) -> None:
        paths = self.make_paths()
        self.initialize_cycle(paths)
        missing_path = Path(self.temp_dir.name) / "missing.md"
        empty_path = Path(self.temp_dir.name) / "empty.md"
        empty_path.write_text("", encoding="utf-8")

        with self.assertRaises(SystemExit) as missing_exc:
            chatgpt_codex_loop.command_save_chatgpt_reply(
                argparse.Namespace(file=str(missing_path), from_clipboard=False),
                paths,
            )
        self.assertIn("does not exist", str(missing_exc.exception))

        with self.assertRaises(SystemExit) as empty_exc:
            chatgpt_codex_loop.command_save_chatgpt_reply(
                argparse.Namespace(file=str(empty_path), from_clipboard=False),
                paths,
            )
        self.assertIn("empty", str(empty_exc.exception))

    def test_save_codex_reply_increments_iteration(self) -> None:
        paths = self.make_paths()
        self.initialize_cycle(paths)
        self.save_valid_chatgpt_reply(paths)

        with patch("sys.stdin", io.StringIO("Codex result\n")):
            with redirect_stdout(io.StringIO()):
                chatgpt_codex_loop.command_save_codex_reply(
                    argparse.Namespace(file=None, from_clipboard=False),
                    paths,
                )

        state = chatgpt_codex_loop.load_state(paths)
        self.assertEqual(state["iteration"], 1)
        self.assertTrue((paths.codex_dir / "reply_001.md").exists())

    def test_guide_after_save_codex_reply_suggests_next_chatgpt(self) -> None:
        paths = self.make_paths()
        self.initialize_cycle(paths)
        self.save_valid_chatgpt_reply(paths)
        with patch("sys.stdin", io.StringIO("Codex completed the step.\n")):
            with redirect_stdout(io.StringIO()):
                chatgpt_codex_loop.command_save_codex_reply(
                    argparse.Namespace(file=None, from_clipboard=False),
                    paths,
                )

        stdout = io.StringIO()
        with patch.object(chatgpt_codex_loop, "get_clipboard_copy_command", return_value=None):
            with patch.object(chatgpt_codex_loop, "get_clipboard_paste_command", return_value=None):
                with redirect_stdout(stdout):
                    chatgpt_codex_loop.command_guide(argparse.Namespace(), paths)

        output = stdout.getvalue()
        self.assertIn("next-chatgpt", output)
        self.assertIn("Iteration 1", output)

    def test_save_codex_reply_file_reads_from_file_and_increments_iteration(self) -> None:
        paths = self.make_paths()
        self.initialize_cycle(paths)
        self.save_valid_chatgpt_reply(paths)
        reply_path = Path(self.temp_dir.name) / "codex_reply.md"
        reply_path.write_text("Codex completed the requested repo task.\n", encoding="utf-8")

        with redirect_stdout(io.StringIO()):
            chatgpt_codex_loop.command_save_codex_reply(
                argparse.Namespace(file=str(reply_path), from_clipboard=False),
                paths,
            )

        state = chatgpt_codex_loop.load_state(paths)
        self.assertEqual(state["iteration"], 1)
        self.assertEqual(
            (paths.codex_dir / "reply_001.md").read_text(encoding="utf-8"),
            "Codex completed the requested repo task.\n",
        )

    def test_show_codex_prompt_copy_invokes_clipboard_helper(self) -> None:
        paths = self.make_paths()
        chatgpt_codex_loop.write_state(paths, chatgpt_codex_loop.default_state("Goal"))
        prompt_path = paths.prompts_dir / "codex_prompt_001.md"
        paths.prompts_dir.mkdir(parents=True, exist_ok=True)
        prompt_path.write_text("Review automation/task.txt\n", encoding="utf-8")
        chatgpt_codex_loop.update_state(
            paths,
            chatgpt_codex_loop.load_state(paths),
            latest_codex_prompt=str(prompt_path),
        )

        with patch.object(chatgpt_codex_loop, "copy_to_clipboard") as copy_mock:
            with redirect_stdout(io.StringIO()):
                chatgpt_codex_loop.command_show_codex_prompt(argparse.Namespace(copy=True), paths)

        copy_mock.assert_called_once_with("Review automation/task.txt\n")

    def test_save_chatgpt_reply_copy_prompt_invokes_clipboard_helper(self) -> None:
        paths = self.make_paths()
        self.initialize_cycle(paths)
        reply = (
            "## CODEX_PROMPT\n"
            "Review automation/chatgpt_codex_loop.py.\n\n"
            "## WHY\n"
            "Need the next repo step.\n"
        )

        with patch.object(chatgpt_codex_loop, "copy_to_clipboard") as copy_mock:
            with patch("sys.stdin", io.StringIO(reply)):
                stdout = io.StringIO()
                with redirect_stdout(stdout):
                    chatgpt_codex_loop.command_save_chatgpt_reply(
                        argparse.Namespace(file=None, from_clipboard=False, copy_prompt=True),
                        paths,
                    )

        copy_mock.assert_called_once_with("Review automation/chatgpt_codex_loop.py.\n")
        output = stdout.getvalue()
        self.assertIn("codex_prompt_001.md", output)
        self.assertIn("Copied Codex prompt to clipboard.", output)

    def test_copy_to_clipboard_fails_when_no_supported_command_exists(self) -> None:
        with patch.object(chatgpt_codex_loop.shutil, "which", return_value=None):
            with self.assertRaises(SystemExit) as exc:
                chatgpt_codex_loop.copy_to_clipboard("text")
        self.assertIn("No supported clipboard tool found", str(exc.exception))

    def test_status_verbose_includes_paths_and_previews(self) -> None:
        paths = self.make_paths()
        with redirect_stdout(io.StringIO()):
            chatgpt_codex_loop.command_init(argparse.Namespace(goal="Goal"), paths)

        with redirect_stdout(io.StringIO()):
            chatgpt_codex_loop.command_next_chatgpt(argparse.Namespace(copy=False), paths)
        with patch(
            "sys.stdin",
            io.StringIO("## CODEX_PROMPT\nDo the next repo step.\n\n## WHY\nBecause it is next.\n"),
        ):
            with redirect_stdout(io.StringIO()):
                chatgpt_codex_loop.command_save_chatgpt_reply(
                    argparse.Namespace(file=None, from_clipboard=False),
                    paths,
                )
        with patch("sys.stdin", io.StringIO("Codex completed the step and left notes.\n")):
            with redirect_stdout(io.StringIO()):
                chatgpt_codex_loop.command_save_codex_reply(
                    argparse.Namespace(file=None, from_clipboard=False),
                    paths,
                )

        stdout = io.StringIO()
        with redirect_stdout(stdout):
            chatgpt_codex_loop.command_status(argparse.Namespace(verbose=True), paths)

        output = stdout.getvalue()
        self.assertIn("Loop root:", output)
        self.assertIn("Verbose details:", output)
        self.assertIn("latest", output.lower())
        self.assertIn("request_001.md", output)
        self.assertIn("reply_001.md", output)
        self.assertIn("Do the next repo step.", output)
        self.assertIn("Codex completed the step and left notes.", output)

    def test_cycle_example_prints_usable_example(self) -> None:
        paths = self.make_paths()
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            chatgpt_codex_loop.command_cycle_example(argparse.Namespace(), paths)

        output = stdout.getvalue()
        self.assertIn("next-chatgpt --copy", output)
        self.assertIn("save-chatgpt-reply < chatgpt_reply.md", output)
        self.assertIn("save-chatgpt-reply --file", output)
        self.assertIn("status --verbose", output)

    def test_help_text_is_available_for_new_commands(self) -> None:
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            with self.assertRaises(SystemExit) as guide_exc:
                chatgpt_codex_loop.main(["guide", "-h"])
        self.assertEqual(guide_exc.exception.code, 0)
        self.assertIn("Print the next happy-path command to run.", stdout.getvalue())

        stdout = io.StringIO()
        with redirect_stdout(stdout):
            with self.assertRaises(SystemExit) as cycle_exc:
                chatgpt_codex_loop.main(["cycle-example", "-h"])
        self.assertEqual(cycle_exc.exception.code, 0)
        self.assertIn("Print a short example of one full loop cycle.", stdout.getvalue())

        stdout = io.StringIO()
        with redirect_stdout(stdout):
            with self.assertRaises(SystemExit) as advance_exc:
                chatgpt_codex_loop.main(["advance", "-h"])
        self.assertEqual(advance_exc.exception.code, 0)
        self.assertIn("Perform the next happy-path loop action for the current phase.", stdout.getvalue())

        stdout = io.StringIO()
        with redirect_stdout(stdout):
            with self.assertRaises(SystemExit) as doctor_exc:
                chatgpt_codex_loop.main(["doctor", "-h"])
        self.assertEqual(doctor_exc.exception.code, 0)
        self.assertIn("Diagnose loop-state inconsistencies and suggest the safest recovery step.", stdout.getvalue())

    def test_latest_file_pointers_update_correctly(self) -> None:
        paths = self.make_paths()
        with redirect_stdout(io.StringIO()):
            chatgpt_codex_loop.command_init(argparse.Namespace(goal="Goal"), paths)

        with redirect_stdout(io.StringIO()):
            chatgpt_codex_loop.command_next_chatgpt(argparse.Namespace(copy=False), paths)
        with patch(
            "sys.stdin",
            io.StringIO("## CODEX_PROMPT\nDo the next repo step.\n\n## WHY\nBecause it is next.\n"),
        ):
            with redirect_stdout(io.StringIO()):
                chatgpt_codex_loop.command_save_chatgpt_reply(
                    argparse.Namespace(file=None, from_clipboard=False),
                    paths,
                )
        with patch("sys.stdin", io.StringIO("Codex completed the step.\n")):
            with redirect_stdout(io.StringIO()):
                chatgpt_codex_loop.command_save_codex_reply(
                    argparse.Namespace(file=None, from_clipboard=False),
                    paths,
                )

        state = chatgpt_codex_loop.load_state(paths)
        self.assertTrue(state["latest_chatgpt_request"].endswith("request_001.md"))
        self.assertTrue(state["latest_chatgpt_reply"].endswith("reply_001.md"))
        self.assertTrue(state["latest_codex_prompt"].endswith("codex_prompt_001.md"))
        self.assertTrue(state["latest_codex_reply"].endswith("reply_001.md"))
        self.assertEqual(state["iteration"], 1)

    def test_default_paths_uses_env_override_for_loop_root(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            override_dir = Path(temp_dir) / "custom-loop-root"
            with patch.dict(os.environ, {chatgpt_codex_loop.LOOP_DIR_ENV_VAR: str(override_dir)}, clear=False):
                paths = chatgpt_codex_loop.default_paths()

        self.assertEqual(paths.loop_dir, override_dir.resolve())
        self.assertEqual(paths.state_file, override_dir.resolve() / "state.json")
        self.assertEqual(paths.chatgpt_dir, override_dir.resolve() / "chatgpt")
        self.assertEqual(paths.codex_dir, override_dir.resolve() / "codex")
        self.assertEqual(paths.prompts_dir, override_dir.resolve() / "prompts")

    def test_cli_override_runs_full_cycle_in_temporary_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            override_dir = Path(temp_dir) / "loop-root"
            env = {chatgpt_codex_loop.LOOP_DIR_ENV_VAR: str(override_dir)}

            init = self.run_cli("init", "--goal", "Ship a safe loop override.", env=env)
            self.assertEqual(init.returncode, 0, init.stderr or init.stdout)

            next_chatgpt = self.run_cli("next-chatgpt", env=env)
            self.assertEqual(next_chatgpt.returncode, 0, next_chatgpt.stderr or next_chatgpt.stdout)
            self.assertIn("## CODEX_PROMPT", next_chatgpt.stdout)

            save_chatgpt = self.run_cli(
                "save-chatgpt-reply",
                env=env,
                input_text=(
                    "## CODEX_PROMPT\n"
                    "Inspect automation/chatgpt_codex_loop.py.\n\n"
                    "## WHY\n"
                    "We need the next step.\n"
                ),
            )
            self.assertEqual(save_chatgpt.returncode, 0, save_chatgpt.stderr or save_chatgpt.stdout)

            show_codex = self.run_cli("show-codex-prompt", env=env)
            self.assertEqual(show_codex.returncode, 0, show_codex.stderr or show_codex.stdout)
            self.assertEqual(show_codex.stdout, "Inspect automation/chatgpt_codex_loop.py.\n")

            save_codex = self.run_cli(
                "save-codex-reply",
                env=env,
                input_text="Implemented the next safe improvement.\n",
            )
            self.assertEqual(save_codex.returncode, 0, save_codex.stderr or save_codex.stdout)

            state = json.loads((override_dir / "state.json").read_text(encoding="utf-8"))
            self.assertEqual(state["iteration"], 1)
            self.assertEqual(state["latest_chatgpt_request"], str(override_dir / "chatgpt" / "request_001.md"))
            self.assertEqual(state["latest_chatgpt_reply"], str(override_dir / "chatgpt" / "reply_001.md"))
            self.assertEqual(state["latest_codex_prompt"], str(override_dir / "prompts" / "codex_prompt_001.md"))
            self.assertEqual(state["latest_codex_reply"], str(override_dir / "codex" / "reply_001.md"))
            self.assertEqual(
                (override_dir / "prompts" / "codex_prompt_001.md").read_text(encoding="utf-8"),
                "Inspect automation/chatgpt_codex_loop.py.\n",
            )
            self.assertEqual(
                (override_dir / "codex" / "reply_001.md").read_text(encoding="utf-8"),
                "Implemented the next safe improvement.\n",
            )

    def test_cli_override_fails_clearly_when_path_is_a_file(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            invalid_path = Path(temp_dir) / "not-a-directory"
            invalid_path.write_text("content", encoding="utf-8")

            result = self.run_cli(
                "status",
                env={chatgpt_codex_loop.LOOP_DIR_ENV_VAR: str(invalid_path)},
            )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn(chatgpt_codex_loop.LOOP_DIR_ENV_VAR, result.stderr)
        self.assertIn("unusable loop directory", result.stderr)

    def test_cli_init_refuses_existing_state_without_force(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            override_dir = Path(temp_dir) / "loop-root"
            env = {chatgpt_codex_loop.LOOP_DIR_ENV_VAR: str(override_dir)}

            first_init = self.run_cli("init", "--goal", "First goal.", env=env)
            self.assertEqual(first_init.returncode, 0, first_init.stderr or first_init.stdout)

            second_init = self.run_cli("init", "--goal", "Second goal.", env=env)

        self.assertNotEqual(second_init.returncode, 0)
        self.assertIn("Refusing to overwrite existing loop state or artifacts", second_init.stderr)
        self.assertIn(str(override_dir.resolve()), second_init.stderr)
        self.assertIn("init --force --goal", second_init.stderr)

    def test_cli_init_force_overwrites_existing_state(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            override_dir = Path(temp_dir) / "loop-root"
            env = {chatgpt_codex_loop.LOOP_DIR_ENV_VAR: str(override_dir)}

            first_init = self.run_cli("init", "--goal", "First goal.", env=env)
            self.assertEqual(first_init.returncode, 0, first_init.stderr or first_init.stdout)

            forced_init = self.run_cli("init", "--force", "--goal", "Second goal.", env=env)
            self.assertEqual(forced_init.returncode, 0, forced_init.stderr or forced_init.stdout)

            state = json.loads((override_dir / "state.json").read_text(encoding="utf-8"))

        self.assertEqual(state["goal"], "Second goal.")
        self.assertEqual(state["iteration"], 0)

    def test_cli_guide_shows_default_loop_root(self) -> None:
        result = self.run_cli("guide")
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
        self.assertIn(f"Loop root: {chatgpt_codex_loop.LOOP_DIR}", result.stdout)
        self.assertIn("default repository path", result.stdout)

    def test_cli_guide_shows_override_loop_root(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            override_dir = Path(temp_dir) / "loop-root"
            result = self.run_cli(
                "guide",
                env={chatgpt_codex_loop.LOOP_DIR_ENV_VAR: str(override_dir)},
            )

        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
        self.assertIn(f"Loop root: {override_dir.resolve()}", result.stdout)
        self.assertIn(f"override via {chatgpt_codex_loop.LOOP_DIR_ENV_VAR}", result.stdout)

    def test_cli_status_json_reports_structured_state_under_override(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            override_dir = Path(temp_dir) / "loop-root"
            env = {chatgpt_codex_loop.LOOP_DIR_ENV_VAR: str(override_dir)}

            self.assertEqual(self.run_cli("init", "--goal", "Goal", env=env).returncode, 0)

            result = self.run_cli("status", "--json", env=env)

        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["loop_root"], str(override_dir.resolve()))
        self.assertEqual(payload["root_mode"], "override")
        self.assertEqual(payload["goal"], "Goal")
        self.assertEqual(payload["iteration"], 0)
        self.assertIsNone(payload["latest_chatgpt_request"])

    def test_cli_guide_json_reports_structured_guidance(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            override_dir = Path(temp_dir) / "loop-root"
            env = {
                chatgpt_codex_loop.LOOP_DIR_ENV_VAR: str(override_dir),
                "PATH": "",
                "WSL_DISTRO_NAME": "",
                "WSL_INTEROP": "",
            }

            self.assertEqual(self.run_cli("init", "--goal", "Goal", env=env).returncode, 0)
            result = self.run_cli("guide", "--json", env=env)

        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
        payload = json.loads(result.stdout)
        self.assertTrue(payload["initialized"])
        self.assertEqual(payload["phase"], "needs_chatgpt_request")
        self.assertIn("next-chatgpt", payload["recommended_command"])
        self.assertIn("complete or not started", payload["notes"])

    def test_cli_doctor_json_reports_structured_diagnosis(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            override_dir = Path(temp_dir) / "loop-root"
            env = {
                chatgpt_codex_loop.LOOP_DIR_ENV_VAR: str(override_dir),
                "PATH": "",
                "WSL_DISTRO_NAME": "",
                "WSL_INTEROP": "",
            }

            self.assertEqual(self.run_cli("init", "--goal", "Goal", env=env).returncode, 0)
            self.assertEqual(self.run_cli("next-chatgpt", env=env).returncode, 0)
            result = self.run_cli("doctor", "--json", env=env)

        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
        payload = json.loads(result.stdout)
        self.assertTrue(payload["initialized"])
        self.assertTrue(payload["healthy"])
        self.assertEqual(payload["iteration"], 0)
        self.assertEqual(payload["diagnosis"], "healthy")
        self.assertEqual(payload["phase"], "needs_chatgpt_reply")
        self.assertIn("save-chatgpt-reply", payload["recommended_command"])

    def test_cli_advance_json_reports_structured_reply_ingestion(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            override_dir = Path(temp_dir) / "loop-root"
            env = {
                chatgpt_codex_loop.LOOP_DIR_ENV_VAR: str(override_dir),
                **self.create_fake_clipboard_env(),
            }

            self.assertEqual(self.run_cli("init", "--goal", "Goal", env=env).returncode, 0)
            self.assertEqual(self.run_cli("advance", "--from-clipboard", "--copy", env=env).returncode, 0)

            clipboard_file = Path(env["FAKE_CLIPBOARD_FILE"])
            clipboard_file.write_text(
                "## CODEX_PROMPT\nInspect automation/README.md.\n\n## WHY\nClipboard flow.\n",
                encoding="utf-8",
            )

            result = self.run_cli("advance", "--from-clipboard", "--copy", "--json", env=env)

        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["root_mode"], "override")
        self.assertTrue(payload["initialized"])
        self.assertEqual(payload["phase_before"], "needs_chatgpt_reply")
        self.assertEqual(payload["action"], "saved_chatgpt_reply")
        self.assertEqual(payload["iteration_before"], 0)
        self.assertEqual(payload["iteration_after"], 0)
        self.assertEqual(payload["input_source"], "clipboard")
        self.assertTrue(payload["copied_to_clipboard"])
        self.assertTrue(payload["artifacts"]["chatgpt_reply"].endswith("reply_001.md"))
        self.assertTrue(payload["artifacts"]["codex_prompt"].endswith("codex_prompt_001.md"))
        self.assertIn("advance --from-clipboard --copy", payload["recommended_next_command"])

    def test_cli_status_without_json_remains_human_readable(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            override_dir = Path(temp_dir) / "loop-root"
            env = {chatgpt_codex_loop.LOOP_DIR_ENV_VAR: str(override_dir)}

            self.assertEqual(self.run_cli("init", "--goal", "Goal", env=env).returncode, 0)
            result = self.run_cli("status", env=env)

        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
        self.assertIn("Loop root:", result.stdout)
        self.assertFalse(result.stdout.lstrip().startswith("{"))

    def test_cli_doctor_diagnoses_uninitialized_loop(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            override_dir = Path(temp_dir) / "loop-root"
            result = self.run_cli(
                "doctor",
                env={chatgpt_codex_loop.LOOP_DIR_ENV_VAR: str(override_dir)},
            )

        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
        self.assertIn(f"Loop root: {override_dir.resolve()}", result.stdout)
        self.assertIn("Current iteration: (unknown)", result.stdout)
        self.assertIn("Loop not initialized", result.stdout)
        self.assertIn('init --goal "<your goal>"', result.stdout)

    def test_cli_doctor_diagnoses_healthy_loop_under_override(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            override_dir = Path(temp_dir) / "loop-root"
            env = {
                chatgpt_codex_loop.LOOP_DIR_ENV_VAR: str(override_dir),
                "PATH": "",
                "WSL_DISTRO_NAME": "",
                "WSL_INTEROP": "",
            }

            self.assertEqual(self.run_cli("init", "--goal", "Goal", env=env).returncode, 0)
            result = self.run_cli("doctor", env=env)

        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
        self.assertIn(f"Loop root: {override_dir.resolve()}", result.stdout)
        self.assertIn("Current iteration: 0", result.stdout)
        self.assertIn("Healthy: ready to generate the next ChatGPT request.", result.stdout)
        self.assertIn("next-chatgpt", result.stdout)

    def test_cli_doctor_diagnoses_partial_cycle_waiting_for_chatgpt_reply(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            override_dir = Path(temp_dir) / "loop-root"
            env = {
                chatgpt_codex_loop.LOOP_DIR_ENV_VAR: str(override_dir),
                "PATH": "",
                "WSL_DISTRO_NAME": "",
                "WSL_INTEROP": "",
            }

            self.assertEqual(self.run_cli("init", "--goal", "Goal", env=env).returncode, 0)
            self.assertEqual(self.run_cli("next-chatgpt", env=env).returncode, 0)
            result = self.run_cli("doctor", env=env)

        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
        self.assertIn("Healthy partial cycle: waiting for the ChatGPT reply", result.stdout)
        self.assertIn("save-chatgpt-reply", result.stdout)

    def test_cli_doctor_diagnoses_suspicious_cycle_skew(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            override_dir = Path(temp_dir) / "loop-root"
            env = {chatgpt_codex_loop.LOOP_DIR_ENV_VAR: str(override_dir)}

            self.assertEqual(self.run_cli("init", "--goal", "Goal", env=env).returncode, 0)
            self.assertEqual(self.run_cli("next-chatgpt", env=env).returncode, 0)
            self.assertEqual(
                self.run_cli(
                    "save-chatgpt-reply",
                    env=env,
                    input_text=(
                        "## CODEX_PROMPT\n"
                        "Inspect automation/chatgpt_codex_loop.py.\n\n"
                        "## WHY\n"
                        "Need the next step.\n"
                    ),
                ).returncode,
                0,
            )
            self.assertEqual(
                self.run_cli(
                    "save-codex-reply",
                    env=env,
                    input_text="Implemented the requested change.\n",
                ).returncode,
                0,
            )

            skew_path = override_dir / "codex" / "reply_005.md"
            skew_path.write_text("Skewed reply\n", encoding="utf-8")
            state = json.loads((override_dir / "state.json").read_text(encoding="utf-8"))
            state["latest_codex_reply"] = str(skew_path)
            (override_dir / "state.json").write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")

            result = self.run_cli("doctor", env=env)

        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
        self.assertIn("Suspicious cycle skew", result.stdout)
        self.assertIn("latest_codex_reply points to cycle 005", result.stdout)
        self.assertIn("reset-iteration 1", result.stdout)

    def test_cli_save_chatgpt_reply_from_clipboard_reads_clipboard(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            override_dir = Path(temp_dir) / "loop-root"
            env = {
                chatgpt_codex_loop.LOOP_DIR_ENV_VAR: str(override_dir),
                **self.create_fake_clipboard_env(
                    "## CODEX_PROMPT\nInspect automation/README.md.\n\n## WHY\nClipboard flow.\n"
                ),
            }

            self.assertEqual(self.run_cli("init", "--goal", "Goal", env=env).returncode, 0)
            self.assertEqual(self.run_cli("next-chatgpt", env=env).returncode, 0)

            save_chatgpt = self.run_cli("save-chatgpt-reply", "--from-clipboard", env=env)

            self.assertEqual(save_chatgpt.returncode, 0, save_chatgpt.stderr or save_chatgpt.stdout)
            self.assertEqual(
                (override_dir / "prompts" / "codex_prompt_001.md").read_text(encoding="utf-8"),
                "Inspect automation/README.md.\n",
            )

    def test_cli_advance_generates_first_chatgpt_request(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            override_dir = Path(temp_dir) / "loop-root"
            env = {chatgpt_codex_loop.LOOP_DIR_ENV_VAR: str(override_dir)}

            self.assertEqual(self.run_cli("init", "--goal", "Goal", env=env).returncode, 0)

            advance = self.run_cli("advance", env=env)

            self.assertEqual(advance.returncode, 0, advance.stderr or advance.stdout)
            self.assertIn("## CODEX_PROMPT", advance.stdout)
            state = json.loads((override_dir / "state.json").read_text(encoding="utf-8"))
            self.assertEqual(state["latest_chatgpt_request"], str(override_dir / "chatgpt" / "request_001.md"))
            self.assertTrue((override_dir / "chatgpt" / "request_001.md").exists())

    def test_cli_advance_from_clipboard_copy_saves_chatgpt_reply_and_copies_codex_prompt(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            override_dir = Path(temp_dir) / "loop-root"
            env = {
                chatgpt_codex_loop.LOOP_DIR_ENV_VAR: str(override_dir),
                **self.create_fake_clipboard_env(),
            }

            self.assertEqual(self.run_cli("init", "--goal", "Goal", env=env).returncode, 0)
            self.assertEqual(self.run_cli("advance", "--from-clipboard", "--copy", env=env).returncode, 0)

            clipboard_file = Path(env["FAKE_CLIPBOARD_FILE"])
            clipboard_file.write_text(
                "## CODEX_PROMPT\nInspect automation/README.md.\n\n## WHY\nClipboard flow.\n",
                encoding="utf-8",
            )

            advance = self.run_cli("advance", "--from-clipboard", "--copy", env=env)

            self.assertEqual(advance.returncode, 0, advance.stderr or advance.stdout)
            self.assertIn("codex_prompt_001.md", advance.stdout)
            self.assertIn("Copied Codex prompt to clipboard.", advance.stdout)
            self.assertEqual(
                clipboard_file.read_text(encoding="utf-8"),
                "Inspect automation/README.md.\n",
            )

    def test_cli_advance_from_clipboard_copy_saves_codex_reply_and_generates_next_request(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            override_dir = Path(temp_dir) / "loop-root"
            env = {
                chatgpt_codex_loop.LOOP_DIR_ENV_VAR: str(override_dir),
                **self.create_fake_clipboard_env(),
            }

            self.assertEqual(self.run_cli("init", "--goal", "Goal", env=env).returncode, 0)
            self.assertEqual(self.run_cli("advance", "--from-clipboard", "--copy", env=env).returncode, 0)

            clipboard_file = Path(env["FAKE_CLIPBOARD_FILE"])
            clipboard_file.write_text(
                "## CODEX_PROMPT\nInspect automation/chatgpt_codex_loop.py.\n\n## WHY\nNeed the next step.\n",
                encoding="utf-8",
            )
            self.assertEqual(self.run_cli("advance", "--from-clipboard", "--copy", env=env).returncode, 0)

            clipboard_file.write_text("Implemented the requested change.\n", encoding="utf-8")
            advance = self.run_cli("advance", "--from-clipboard", "--copy", env=env)

            self.assertEqual(advance.returncode, 0, advance.stderr or advance.stdout)
            self.assertIn("reply_001.md", advance.stdout)
            self.assertIn("request_002.md", advance.stdout)
            self.assertIn("Copied next ChatGPT request to clipboard.", advance.stdout)
            state = json.loads((override_dir / "state.json").read_text(encoding="utf-8"))
            self.assertEqual(state["iteration"], 1)
            self.assertEqual(state["latest_codex_reply"], str(override_dir / "codex" / "reply_001.md"))
            self.assertEqual(state["latest_chatgpt_request"], str(override_dir / "chatgpt" / "request_002.md"))
            self.assertEqual(
                clipboard_file.read_text(encoding="utf-8"),
                (override_dir / "chatgpt" / "request_002.md").read_text(encoding="utf-8"),
            )

    def test_cli_advance_copy_fails_clearly_without_clipboard_support(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            override_dir = Path(temp_dir) / "loop-root"
            env = {
                chatgpt_codex_loop.LOOP_DIR_ENV_VAR: str(override_dir),
                "PATH": "",
                "WSL_DISTRO_NAME": "",
                "WSL_INTEROP": "",
            }

            self.assertEqual(self.run_cli("init", "--goal", "Goal", env=env).returncode, 0)

            advance = self.run_cli("advance", "--copy", env=env)

            self.assertNotEqual(advance.returncode, 0)
            self.assertIn("No supported clipboard tool found", advance.stderr)
            self.assertFalse((override_dir / "chatgpt" / "request_001.md").exists())

    def test_cli_advance_fails_when_loop_not_initialized(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            override_dir = Path(temp_dir) / "loop-root"
            result = self.run_cli(
                "advance",
                env={chatgpt_codex_loop.LOOP_DIR_ENV_VAR: str(override_dir)},
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Loop state is missing", result.stderr)
            self.assertIn("init --goal", result.stderr)

    def test_cli_save_chatgpt_reply_copy_prompt_updates_clipboard(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            override_dir = Path(temp_dir) / "loop-root"
            env = {
                chatgpt_codex_loop.LOOP_DIR_ENV_VAR: str(override_dir),
                **self.create_fake_clipboard_env(
                    "## CODEX_PROMPT\nInspect automation/README.md.\n\n## WHY\nClipboard flow.\n"
                ),
            }

            self.assertEqual(self.run_cli("init", "--goal", "Goal", env=env).returncode, 0)
            self.assertEqual(self.run_cli("next-chatgpt", env=env).returncode, 0)

            save_chatgpt = self.run_cli(
                "save-chatgpt-reply",
                "--from-clipboard",
                "--copy-prompt",
                env=env,
            )

            self.assertEqual(save_chatgpt.returncode, 0, save_chatgpt.stderr or save_chatgpt.stdout)
            self.assertIn("codex_prompt_001.md", save_chatgpt.stdout)
            self.assertIn("Copied Codex prompt to clipboard.", save_chatgpt.stdout)
            self.assertEqual(
                Path(env["FAKE_CLIPBOARD_FILE"]).read_text(encoding="utf-8"),
                "Inspect automation/README.md.\n",
            )

    def test_cli_save_chatgpt_reply_copy_prompt_fails_clearly_without_clipboard_support(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            override_dir = Path(temp_dir) / "loop-root"
            env = {
                chatgpt_codex_loop.LOOP_DIR_ENV_VAR: str(override_dir),
                "PATH": "",
                "WSL_DISTRO_NAME": "",
                "WSL_INTEROP": "",
            }

            self.assertEqual(self.run_cli("init", "--goal", "Goal", env=env).returncode, 0)
            self.assertEqual(self.run_cli("next-chatgpt", env=env).returncode, 0)

            save_chatgpt = self.run_cli(
                "save-chatgpt-reply",
                "--copy-prompt",
                env=env,
                input_text=(
                    "## CODEX_PROMPT\n"
                    "Inspect automation/chatgpt_codex_loop.py.\n\n"
                    "## WHY\n"
                    "Need the next step.\n"
                ),
            )

            self.assertNotEqual(save_chatgpt.returncode, 0)
            self.assertIn("No supported clipboard tool found", save_chatgpt.stderr)
            self.assertFalse((override_dir / "chatgpt" / "reply_001.md").exists())
            self.assertFalse((override_dir / "prompts" / "codex_prompt_001.md").exists())

    def test_cli_save_codex_reply_from_clipboard_reads_clipboard(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            override_dir = Path(temp_dir) / "loop-root"
            env = {
                chatgpt_codex_loop.LOOP_DIR_ENV_VAR: str(override_dir),
                **self.create_fake_clipboard_env(
                    "## CODEX_PROMPT\nInspect automation/chatgpt_codex_loop.py.\n\n## WHY\nNeed the next step.\n"
                ),
            }

            self.assertEqual(self.run_cli("init", "--goal", "Goal", env=env).returncode, 0)
            self.assertEqual(self.run_cli("next-chatgpt", env=env).returncode, 0)
            self.assertEqual(
                self.run_cli("save-chatgpt-reply", "--from-clipboard", env=env).returncode,
                0,
            )

            clipboard_file = Path(env["FAKE_CLIPBOARD_FILE"])
            clipboard_file.write_text("Implemented the requested change.\n", encoding="utf-8")

            save_codex = self.run_cli("save-codex-reply", "--from-clipboard", env=env)

            self.assertEqual(save_codex.returncode, 0, save_codex.stderr or save_codex.stdout)
            state = json.loads((override_dir / "state.json").read_text(encoding="utf-8"))
            self.assertEqual(state["iteration"], 1)
            self.assertEqual(
                (override_dir / "codex" / "reply_001.md").read_text(encoding="utf-8"),
                "Implemented the requested change.\n",
            )

    def test_cli_save_codex_reply_rejects_current_prompt_from_file(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            override_dir = Path(temp_dir) / "loop-root"
            env = {chatgpt_codex_loop.LOOP_DIR_ENV_VAR: str(override_dir)}

            self.assertEqual(self.run_cli("init", "--goal", "Goal", env=env).returncode, 0)
            self.assertEqual(self.run_cli("next-chatgpt", env=env).returncode, 0)
            self.assertEqual(
                self.run_cli(
                    "save-chatgpt-reply",
                    env=env,
                    input_text=(
                        "## CODEX_PROMPT\n"
                        "Inspect automation/chatgpt_codex_loop.py.\n\n"
                        "## WHY\n"
                        "Need the next step.\n"
                    ),
                ).returncode,
                0,
            )

            save_codex = self.run_cli(
                "save-codex-reply",
                "--file",
                str(override_dir / "prompts" / "codex_prompt_001.md"),
                env=env,
            )

            self.assertNotEqual(save_codex.returncode, 0)
            self.assertIn("current Codex prompt", save_codex.stderr)
            self.assertIn("actual Codex result", save_codex.stderr)
            self.assertFalse((override_dir / "codex" / "reply_001.md").exists())

    def test_cli_save_codex_reply_rejects_chatgpt_request_from_file(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            override_dir = Path(temp_dir) / "loop-root"
            env = {chatgpt_codex_loop.LOOP_DIR_ENV_VAR: str(override_dir)}

            self.assertEqual(self.run_cli("init", "--goal", "Goal", env=env).returncode, 0)
            self.assertEqual(self.run_cli("next-chatgpt", env=env).returncode, 0)
            self.assertEqual(
                self.run_cli(
                    "save-chatgpt-reply",
                    env=env,
                    input_text=(
                        "## CODEX_PROMPT\n"
                        "Inspect automation/chatgpt_codex_loop.py.\n\n"
                        "## WHY\n"
                        "Need the next step.\n"
                    ),
                ).returncode,
                0,
            )

            save_codex = self.run_cli(
                "save-codex-reply",
                "--file",
                str(override_dir / "chatgpt" / "request_001.md"),
                env=env,
            )

            self.assertNotEqual(save_codex.returncode, 0)
            self.assertIn("generated ChatGPT request", save_codex.stderr)
            self.assertIn("actual Codex output", save_codex.stderr)
            self.assertFalse((override_dir / "codex" / "reply_001.md").exists())

    def test_cli_save_codex_reply_rejects_current_prompt_from_clipboard(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            override_dir = Path(temp_dir) / "loop-root"
            env = {
                chatgpt_codex_loop.LOOP_DIR_ENV_VAR: str(override_dir),
                **self.create_fake_clipboard_env(
                    "## CODEX_PROMPT\nInspect automation/chatgpt_codex_loop.py.\n\n## WHY\nNeed the next step.\n"
                ),
            }

            self.assertEqual(self.run_cli("init", "--goal", "Goal", env=env).returncode, 0)
            self.assertEqual(self.run_cli("next-chatgpt", env=env).returncode, 0)
            self.assertEqual(
                self.run_cli("save-chatgpt-reply", "--from-clipboard", "--copy-prompt", env=env).returncode,
                0,
            )

            save_codex = self.run_cli("save-codex-reply", "--from-clipboard", env=env)

            self.assertNotEqual(save_codex.returncode, 0)
            self.assertIn("current Codex prompt", save_codex.stderr)
            self.assertIn("actual Codex result", save_codex.stderr)
            self.assertFalse((override_dir / "codex" / "reply_001.md").exists())

    def test_cli_save_codex_reply_next_chatgpt_creates_next_request(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            override_dir = Path(temp_dir) / "loop-root"
            env = {chatgpt_codex_loop.LOOP_DIR_ENV_VAR: str(override_dir)}

            self.assertEqual(self.run_cli("init", "--goal", "Goal", env=env).returncode, 0)
            self.assertEqual(self.run_cli("next-chatgpt", env=env).returncode, 0)
            self.assertEqual(
                self.run_cli(
                    "save-chatgpt-reply",
                    env=env,
                    input_text=(
                        "## CODEX_PROMPT\n"
                        "Inspect automation/chatgpt_codex_loop.py.\n\n"
                        "## WHY\n"
                        "Need the next step.\n"
                    ),
                ).returncode,
                0,
            )

            save_codex = self.run_cli(
                "save-codex-reply",
                "--next-chatgpt",
                env=env,
                input_text="Implemented the requested change.\n",
            )

            self.assertEqual(save_codex.returncode, 0, save_codex.stderr or save_codex.stdout)
            self.assertIn("reply_001.md", save_codex.stdout)
            self.assertIn("request_002.md", save_codex.stdout)
            state = json.loads((override_dir / "state.json").read_text(encoding="utf-8"))
            self.assertEqual(state["iteration"], 1)
            self.assertEqual(state["latest_codex_reply"], str(override_dir / "codex" / "reply_001.md"))
            self.assertEqual(state["latest_chatgpt_request"], str(override_dir / "chatgpt" / "request_002.md"))
            self.assertTrue((override_dir / "chatgpt" / "request_002.md").exists())

    def test_cli_save_codex_reply_next_chatgpt_copy_updates_clipboard(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            override_dir = Path(temp_dir) / "loop-root"
            env = {
                chatgpt_codex_loop.LOOP_DIR_ENV_VAR: str(override_dir),
                **self.create_fake_clipboard_env(
                    "## CODEX_PROMPT\nInspect automation/chatgpt_codex_loop.py.\n\n## WHY\nNeed the next step.\n"
                ),
            }

            self.assertEqual(self.run_cli("init", "--goal", "Goal", env=env).returncode, 0)
            self.assertEqual(self.run_cli("next-chatgpt", env=env).returncode, 0)
            self.assertEqual(
                self.run_cli("save-chatgpt-reply", "--from-clipboard", "--copy-prompt", env=env).returncode,
                0,
            )

            clipboard_file = Path(env["FAKE_CLIPBOARD_FILE"])
            clipboard_file.write_text("Implemented the requested change.\n", encoding="utf-8")

            save_codex = self.run_cli(
                "save-codex-reply",
                "--from-clipboard",
                "--next-chatgpt",
                "--copy",
                env=env,
            )

            self.assertEqual(save_codex.returncode, 0, save_codex.stderr or save_codex.stdout)
            self.assertIn("request_002.md", save_codex.stdout)
            self.assertIn("Copied next ChatGPT request to clipboard.", save_codex.stdout)
            self.assertEqual(
                clipboard_file.read_text(encoding="utf-8"),
                (override_dir / "chatgpt" / "request_002.md").read_text(encoding="utf-8"),
            )

    def test_cli_save_codex_reply_next_chatgpt_copy_fails_clearly_without_clipboard_support(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            override_dir = Path(temp_dir) / "loop-root"
            env = {
                chatgpt_codex_loop.LOOP_DIR_ENV_VAR: str(override_dir),
                "PATH": "",
                "WSL_DISTRO_NAME": "",
                "WSL_INTEROP": "",
            }

            self.assertEqual(self.run_cli("init", "--goal", "Goal", env=env).returncode, 0)
            self.assertEqual(self.run_cli("next-chatgpt", env=env).returncode, 0)
            self.assertEqual(
                self.run_cli(
                    "save-chatgpt-reply",
                    env=env,
                    input_text=(
                        "## CODEX_PROMPT\n"
                        "Inspect automation/chatgpt_codex_loop.py.\n\n"
                        "## WHY\n"
                        "Need the next step.\n"
                    ),
                ).returncode,
                0,
            )

            save_codex = self.run_cli(
                "save-codex-reply",
                "--next-chatgpt",
                "--copy",
                env=env,
                input_text="Implemented the requested change.\n",
            )

            self.assertNotEqual(save_codex.returncode, 0)
            self.assertIn("No supported clipboard tool found", save_codex.stderr)
            self.assertFalse((override_dir / "codex" / "reply_001.md").exists())
            self.assertFalse((override_dir / "chatgpt" / "request_002.md").exists())

    def test_save_chatgpt_reply_rejects_duplicate_current_cycle_reply(self) -> None:
        paths = self.make_paths()
        self.initialize_cycle(paths)
        self.save_valid_chatgpt_reply(paths)

        with patch("sys.stdin", io.StringIO("## CODEX_PROMPT\nAnother prompt.\n\n## WHY\nDuplicate.\n")):
            with self.assertRaises(SystemExit) as exc:
                chatgpt_codex_loop.command_save_chatgpt_reply(
                    argparse.Namespace(file=None, from_clipboard=False),
                    paths,
                )

        self.assertIn("Current cycle ChatGPT reply already exists", str(exc.exception))
        self.assertIn("show-codex-prompt", str(exc.exception))

    def test_save_codex_reply_rejects_out_of_order_when_prompt_missing(self) -> None:
        paths = self.make_paths()
        chatgpt_codex_loop.write_state(paths, chatgpt_codex_loop.default_state("Goal"))

        with patch("sys.stdin", io.StringIO("Codex result\n")):
            with self.assertRaises(SystemExit) as exc:
                chatgpt_codex_loop.command_save_codex_reply(
                    argparse.Namespace(file=None, from_clipboard=False),
                    paths,
                )

        self.assertIn("Current cycle Codex prompt does not exist yet", str(exc.exception))
        self.assertIn("save-chatgpt-reply", str(exc.exception))

    def test_save_codex_reply_rejects_duplicate_current_cycle_reply(self) -> None:
        paths = self.make_paths()
        self.initialize_cycle(paths)
        self.save_valid_chatgpt_reply(paths)
        duplicate_reply_path = paths.codex_dir / "reply_001.md"
        paths.codex_dir.mkdir(parents=True, exist_ok=True)
        duplicate_reply_path.write_text("Existing reply\n", encoding="utf-8")

        with patch("sys.stdin", io.StringIO("Codex result\n")):
            with self.assertRaises(SystemExit) as exc:
                chatgpt_codex_loop.command_save_codex_reply(
                    argparse.Namespace(file=None, from_clipboard=False),
                    paths,
                )

        self.assertIn("Current cycle Codex reply already exists", str(exc.exception))
        self.assertIn("next-chatgpt", str(exc.exception))

    def test_cli_guide_prefers_clipboard_based_next_steps_when_supported(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            override_dir = Path(temp_dir) / "loop-root"
            env = {
                chatgpt_codex_loop.LOOP_DIR_ENV_VAR: str(override_dir),
                **self.create_fake_clipboard_env(
                    "## CODEX_PROMPT\nInspect automation/chatgpt_codex_loop.py.\n\n## WHY\nNeed the next step.\n"
                ),
            }

            self.assertEqual(self.run_cli("init", "--goal", "Goal", env=env).returncode, 0)

            guide_after_init = self.run_cli("guide", env=env)
            self.assertEqual(guide_after_init.returncode, 0, guide_after_init.stderr or guide_after_init.stdout)
            self.assertIn("advance --from-clipboard --copy", guide_after_init.stdout)

            self.assertEqual(self.run_cli("advance", "--from-clipboard", "--copy", env=env).returncode, 0)

            guide_after_request = self.run_cli("guide", env=env)
            self.assertEqual(guide_after_request.returncode, 0, guide_after_request.stderr or guide_after_request.stdout)
            self.assertIn("advance --from-clipboard --copy", guide_after_request.stdout)

            clipboard_file = Path(env["FAKE_CLIPBOARD_FILE"])
            clipboard_file.write_text(
                "## CODEX_PROMPT\nInspect automation/chatgpt_codex_loop.py.\n\n## WHY\nNeed the next step.\n",
                encoding="utf-8",
            )
            self.assertEqual(
                self.run_cli("advance", "--from-clipboard", "--copy", env=env).returncode,
                0,
            )

            guide_after_prompt = self.run_cli("guide", env=env)
            self.assertEqual(guide_after_prompt.returncode, 0, guide_after_prompt.stderr or guide_after_prompt.stdout)
            self.assertIn("advance --from-clipboard --copy", guide_after_prompt.stdout)
            self.assertIn("Optional inspection:", guide_after_prompt.stdout)
            self.assertIn("show-codex-prompt --copy", guide_after_prompt.stdout)

            clipboard_file.write_text("Implemented the requested change.\n", encoding="utf-8")

            self.assertEqual(
                self.run_cli("advance", "--from-clipboard", "--copy", env=env).returncode,
                0,
            )

            guide_next_cycle = self.run_cli("guide", env=env)
            self.assertEqual(guide_next_cycle.returncode, 0, guide_next_cycle.stderr or guide_next_cycle.stdout)
            self.assertIn("advance --from-clipboard --copy", guide_next_cycle.stdout)

    def test_cli_logs_successful_state_changing_commands_to_history(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            override_dir = Path(temp_dir) / "loop-root"
            env = {
                chatgpt_codex_loop.LOOP_DIR_ENV_VAR: str(override_dir),
                **self.create_fake_clipboard_env(),
            }
            clipboard_file = Path(env["FAKE_CLIPBOARD_FILE"])

            self.assertEqual(self.run_cli("init", "--goal", "Goal", env=env).returncode, 0)
            self.assertEqual(self.run_cli("next-chatgpt", "--copy", env=env).returncode, 0)

            clipboard_file.write_text(
                "## CODEX_PROMPT\nInspect automation/README.md.\n\n## WHY\nNeed the next step.\n",
                encoding="utf-8",
            )
            self.assertEqual(
                self.run_cli("save-chatgpt-reply", "--from-clipboard", "--copy-prompt", env=env).returncode,
                0,
            )

            clipboard_file.write_text("Implemented the requested change.\n", encoding="utf-8")
            self.assertEqual(
                self.run_cli(
                    "save-codex-reply",
                    "--from-clipboard",
                    "--next-chatgpt",
                    "--copy",
                    env=env,
                ).returncode,
                0,
            )

            clipboard_file.write_text(
                "## CODEX_PROMPT\nInspect automation/chatgpt_codex_loop.py.\n\n## WHY\nNeed another follow-up.\n",
                encoding="utf-8",
            )
            self.assertEqual(
                self.run_cli("advance", "--from-clipboard", "--copy", env=env).returncode,
                0,
            )
            self.assertEqual(self.run_cli("reset-iteration", "1", env=env).returncode, 0)

            events = self.read_logged_events(override_dir)

        self.assertEqual(
            [event["command"] for event in events],
            [
                "init",
                "next-chatgpt",
                "save-chatgpt-reply",
                "save-codex-reply",
                "advance",
                "reset-iteration",
            ],
        )
        self.assertEqual(events[0]["action"], "initialized_loop")
        self.assertEqual(events[1]["artifacts"]["chatgpt_request"], str(override_dir / "chatgpt" / "request_001.md"))
        self.assertTrue(events[1]["copied_to_clipboard"])
        self.assertEqual(events[2]["input_source"], "clipboard")
        self.assertEqual(events[2]["artifacts"]["codex_prompt"], str(override_dir / "prompts" / "codex_prompt_001.md"))
        self.assertEqual(events[3]["action"], "saved_codex_reply_and_generated_next_chatgpt_request")
        self.assertEqual(events[3]["iteration_before"], 0)
        self.assertEqual(events[3]["iteration_after"], 1)
        self.assertEqual(events[3]["artifacts"]["chatgpt_request"], str(override_dir / "chatgpt" / "request_002.md"))
        self.assertEqual(events[4]["command"], "advance")
        self.assertEqual(events[4]["action"], "saved_chatgpt_reply")
        self.assertEqual(events[4]["artifacts"]["chatgpt_reply"], str(override_dir / "chatgpt" / "reply_002.md"))
        self.assertEqual(events[5]["action"], "reset_iteration")
        self.assertEqual(events[5]["iteration_before"], 1)
        self.assertEqual(events[5]["iteration_after"], 1)

    def test_cli_history_human_readable_output_shows_recent_events(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            override_dir = Path(temp_dir) / "loop-root"
            env = {chatgpt_codex_loop.LOOP_DIR_ENV_VAR: str(override_dir)}

            self.assertEqual(self.run_cli("init", "--goal", "Goal", env=env).returncode, 0)
            self.assertEqual(self.run_cli("next-chatgpt", env=env).returncode, 0)
            self.assertEqual(
                self.run_cli(
                    "save-chatgpt-reply",
                    env=env,
                    input_text=(
                        "## CODEX_PROMPT\n"
                        "Inspect automation/chatgpt_codex_loop.py.\n\n"
                        "## WHY\n"
                        "Need the next step.\n"
                    ),
                ).returncode,
                0,
            )

            result = self.run_cli("history", "--limit", "2", env=env)

        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
        self.assertIn("Loop root:", result.stdout)
        self.assertIn("Recent events (showing 2 of 3):", result.stdout)
        self.assertNotIn("| init |", result.stdout)
        self.assertIn("| next-chatgpt |", result.stdout)
        self.assertIn("| save-chatgpt-reply |", result.stdout)
        self.assertIn("request_001.md", result.stdout)
        self.assertLess(result.stdout.index("| next-chatgpt |"), result.stdout.index("| save-chatgpt-reply |"))

    def test_cli_history_json_reports_structured_events(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            override_dir = Path(temp_dir) / "loop-root"
            env = {chatgpt_codex_loop.LOOP_DIR_ENV_VAR: str(override_dir)}

            self.assertEqual(self.run_cli("init", "--goal", "Goal", env=env).returncode, 0)
            self.assertEqual(self.run_cli("next-chatgpt", env=env).returncode, 0)

            result = self.run_cli("history", "--json", "--limit", "1", env=env)

        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["loop_root"], str(override_dir.resolve()))
        self.assertEqual(payload["root_mode"], "override")
        self.assertEqual(payload["limit"], 1)
        self.assertEqual(payload["total_events"], 2)
        self.assertEqual(len(payload["events"]), 1)
        self.assertEqual(payload["events"][0]["command"], "next-chatgpt")
        self.assertEqual(payload["events"][0]["artifacts"]["chatgpt_request"], str(override_dir / "chatgpt" / "request_001.md"))

    def test_cli_history_reports_no_log_when_missing(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            override_dir = Path(temp_dir) / "loop-root"
            env = {chatgpt_codex_loop.LOOP_DIR_ENV_VAR: str(override_dir)}

            human_result = self.run_cli("history", env=env)
            json_result = self.run_cli("history", "--json", env=env)

        self.assertEqual(human_result.returncode, 0, human_result.stderr or human_result.stdout)
        self.assertIn("Loop root:", human_result.stdout)
        self.assertIn("No loop history exists yet.", human_result.stdout)
        self.assertEqual(json_result.returncode, 0, json_result.stderr or json_result.stdout)
        payload = json.loads(json_result.stdout)
        self.assertEqual(payload["loop_root"], str(override_dir.resolve()))
        self.assertEqual(payload["total_events"], 0)
        self.assertEqual(payload["events"], [])

    def test_failed_cli_command_does_not_append_history_event(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            override_dir = Path(temp_dir) / "loop-root"
            env = {chatgpt_codex_loop.LOOP_DIR_ENV_VAR: str(override_dir)}

            self.assertEqual(self.run_cli("init", "--goal", "Goal", env=env).returncode, 0)
            failed = self.run_cli("save-codex-reply", env=env, input_text="Wrong phase.\n")
            events = self.read_logged_events(override_dir)

        self.assertNotEqual(failed.returncode, 0)
        self.assertEqual([event["command"] for event in events], ["init"])

    def test_cli_state_changing_command_fails_cleanly_when_write_lock_is_held(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            override_dir = Path(temp_dir) / "loop-root"
            env = {chatgpt_codex_loop.LOOP_DIR_ENV_VAR: str(override_dir)}

            self.assertEqual(self.run_cli("init", "--goal", "Goal", env=env).returncode, 0)
            self.create_write_lock(override_dir, command="save-codex-reply")

            blocked = self.run_cli("next-chatgpt", env=env)
            events = self.read_logged_events(override_dir)

        self.assertNotEqual(blocked.returncode, 0)
        self.assertIn("Another state-changing loop command is already in progress", blocked.stderr)
        self.assertIn("command=save-codex-reply", blocked.stderr)
        self.assertIn("doctor", blocked.stderr)
        self.assertFalse((override_dir / "chatgpt" / "request_001.md").exists())
        self.assertEqual([event["command"] for event in events], ["init"])

    def test_cli_read_only_commands_still_work_while_write_lock_is_held(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            override_dir = Path(temp_dir) / "loop-root"
            env = {chatgpt_codex_loop.LOOP_DIR_ENV_VAR: str(override_dir)}

            self.assertEqual(self.run_cli("init", "--goal", "Goal", env=env).returncode, 0)
            self.create_write_lock(override_dir, command="advance")

            status_result = self.run_cli("status", env=env)
            history_result = self.run_cli("history", env=env)
            events = self.read_logged_events(override_dir)

        self.assertEqual(status_result.returncode, 0, status_result.stderr or status_result.stdout)
        self.assertIn("Goal: Goal", status_result.stdout)
        self.assertEqual(history_result.returncode, 0, history_result.stderr or history_result.stdout)
        self.assertIn("Recent events (showing 1 of 1):", history_result.stdout)
        self.assertIn("| init |", history_result.stdout)
        self.assertEqual([event["command"] for event in events], ["init"])

    def test_cli_lock_status_reports_no_lock(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            override_dir = Path(temp_dir) / "loop-root"
            result = self.run_cli(
                "lock-status",
                env={chatgpt_codex_loop.LOOP_DIR_ENV_VAR: str(override_dir)},
            )

        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
        self.assertIn(f"Loop root: {override_dir.resolve()}", result.stdout)
        self.assertIn("Root mode: override via CHATGPT_CODEX_LOOP_DIR", result.stdout)
        self.assertIn("Lock state: absent", result.stdout)
        self.assertIn("No write lock present.", result.stdout)
        self.assertIn("Proceed normally.", result.stdout)

    def test_cli_lock_status_reports_active_lock(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            override_dir = Path(temp_dir) / "loop-root"
            self.create_write_lock(
                override_dir,
                command="advance",
                pid=os.getpid(),
                timestamp="2026-03-22T01:02:03+00:00",
            )
            result = self.run_cli(
                "lock-status",
                env={chatgpt_codex_loop.LOOP_DIR_ENV_VAR: str(override_dir)},
            )

        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
        self.assertIn("Lock state: active", result.stdout)
        self.assertIn("Lock command: advance", result.stdout)
        self.assertIn(f"Lock pid: {os.getpid()}", result.stdout)
        self.assertIn("Lock timestamp: 2026-03-22T01:02:03+00:00", result.stdout)
        self.assertIn("recorded pid appears active", result.stdout)
        self.assertIn("Wait for the other command to finish, then retry.", result.stdout)

    def test_cli_lock_status_json_reports_suspicious_lock(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            override_dir = Path(temp_dir) / "loop-root"
            self.create_write_lock(
                override_dir,
                command="save-codex-reply",
                pid=10_000_000,
                timestamp="2026-03-22T04:05:06+00:00",
            )
            result = self.run_cli(
                "lock-status",
                "--json",
                env={chatgpt_codex_loop.LOOP_DIR_ENV_VAR: str(override_dir)},
            )

        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["loop_root"], str(override_dir.resolve()))
        self.assertEqual(payload["root_mode"], "override")
        self.assertTrue(payload["lock_present"])
        self.assertEqual(payload["lock_state"], "suspicious")
        self.assertEqual(payload["lock_path"], str(override_dir / chatgpt_codex_loop.WRITE_LOCK_FILE_NAME))
        self.assertIn("looks stale because pid 10000000 is not running", payload["diagnosis"])
        self.assertIn("clear-lock --force", payload["recommended_action"])
        self.assertEqual(payload["metadata"]["command"], "save-codex-reply")

    def test_cli_doctor_surfaces_suspicious_lock_diagnosis(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            override_dir = Path(temp_dir) / "loop-root"
            env = {chatgpt_codex_loop.LOOP_DIR_ENV_VAR: str(override_dir)}

            self.assertEqual(self.run_cli("init", "--goal", "Goal", env=env).returncode, 0)
            self.create_write_lock(override_dir, command="next-chatgpt", pid=10_000_000)
            result = self.run_cli("doctor", env=env)

        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
        self.assertIn("Write lock is present but looks stale", result.stdout)
        self.assertIn("command=next-chatgpt", result.stdout)
        self.assertIn("clear-lock --force", result.stdout)

    def test_cli_clear_lock_reports_nothing_to_clear_when_no_lock_exists(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            override_dir = Path(temp_dir) / "loop-root"
            result = self.run_cli(
                "clear-lock",
                env={chatgpt_codex_loop.LOOP_DIR_ENV_VAR: str(override_dir)},
            )

        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
        self.assertIn(f"Loop root: {override_dir.resolve()}", result.stdout)
        self.assertIn("Lock present: no", result.stdout)
        self.assertIn("Lock state: absent", result.stdout)
        self.assertIn("Action taken: none", result.stdout)
        self.assertIn("No write lock present.", result.stdout)

    def test_cli_clear_lock_refuses_suspicious_lock_without_force(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            override_dir = Path(temp_dir) / "loop-root"
            env = {chatgpt_codex_loop.LOOP_DIR_ENV_VAR: str(override_dir)}

            self.assertEqual(self.run_cli("init", "--goal", "Goal", env=env).returncode, 0)
            self.create_write_lock(override_dir, command="advance", pid=10_000_000)

            result = self.run_cli("clear-lock", env=env)
            events = self.read_logged_events(override_dir)
            lock_still_exists = (override_dir / chatgpt_codex_loop.WRITE_LOCK_FILE_NAME).exists()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Lock present: yes", result.stderr)
        self.assertIn("Lock state: suspicious", result.stderr)
        self.assertIn("Action taken: none", result.stderr)
        self.assertIn("manual recovery operation", result.stderr)
        self.assertIn("clear-lock --force", result.stderr)
        self.assertTrue(lock_still_exists)
        self.assertEqual([event["command"] for event in events], ["init"])

    def test_cli_clear_lock_force_clears_suspicious_lock(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            override_dir = Path(temp_dir) / "loop-root"
            env = {chatgpt_codex_loop.LOOP_DIR_ENV_VAR: str(override_dir)}
            self.create_write_lock(override_dir, command="save-codex-reply", pid=10_000_000)

            result = self.run_cli("clear-lock", "--force", env=env)

        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
        self.assertIn("Lock present: no", result.stdout)
        self.assertIn("Lock state: suspicious", result.stdout)
        self.assertIn("Action taken: cleared_lock", result.stdout)
        self.assertIn("Cleared the suspicious write lock.", result.stdout)
        self.assertFalse((override_dir / chatgpt_codex_loop.WRITE_LOCK_FILE_NAME).exists())

    def test_cli_clear_lock_force_refuses_active_lock(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            override_dir = Path(temp_dir) / "loop-root"
            self.create_write_lock(override_dir, command="advance", pid=os.getpid())

            result = self.run_cli(
                "clear-lock",
                "--force",
                env={chatgpt_codex_loop.LOOP_DIR_ENV_VAR: str(override_dir)},
            )
            lock_still_exists = (override_dir / chatgpt_codex_loop.WRITE_LOCK_FILE_NAME).exists()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Lock state: active", result.stderr)
        self.assertIn("Action taken: none", result.stderr)
        self.assertIn("Wait for the other command to finish and retry.", result.stderr)
        self.assertTrue(lock_still_exists)

    def test_cli_clear_lock_json_reports_structured_success(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            override_dir = Path(temp_dir) / "loop-root"
            self.create_write_lock(override_dir, command="advance", pid=10_000_000)

            result = self.run_cli(
                "clear-lock",
                "--force",
                "--json",
                env={chatgpt_codex_loop.LOOP_DIR_ENV_VAR: str(override_dir)},
            )

        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["loop_root"], str(override_dir.resolve()))
        self.assertEqual(payload["root_mode"], "override")
        self.assertTrue(payload["cleared"])
        self.assertEqual(payload["action_taken"], "cleared_lock")
        self.assertEqual(payload["lock_state"], "suspicious")
        self.assertIn("doctor", payload["recommended_action"])
        self.assertFalse((override_dir / chatgpt_codex_loop.WRITE_LOCK_FILE_NAME).exists())


if __name__ == "__main__":
    unittest.main()
