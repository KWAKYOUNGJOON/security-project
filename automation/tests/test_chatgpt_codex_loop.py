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

    def test_guide_after_next_chatgpt_suggests_save_chatgpt_reply(self) -> None:
        paths = self.make_paths()
        chatgpt_codex_loop.write_state(paths, chatgpt_codex_loop.default_state("Goal"))
        with redirect_stdout(io.StringIO()):
            chatgpt_codex_loop.command_next_chatgpt(argparse.Namespace(copy=False), paths)

        stdout = io.StringIO()
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
        chatgpt_codex_loop.write_state(paths, chatgpt_codex_loop.default_state("Goal"))
        reply = (
            "## CODEX_PROMPT\n"
            "Inspect automation/orchestrator.py and summarize the next fix.\n\n"
            "## WHY\n"
            "We need a concrete next step.\n"
        )

        with patch("sys.stdin", io.StringIO(reply)):
            with redirect_stdout(io.StringIO()):
                chatgpt_codex_loop.command_save_chatgpt_reply(argparse.Namespace(file=None), paths)

        reply_path = paths.chatgpt_dir / "reply_001.md"
        prompt_path = paths.prompts_dir / "codex_prompt_001.md"
        self.assertEqual(reply_path.read_text(encoding="utf-8"), reply)
        self.assertEqual(
            prompt_path.read_text(encoding="utf-8"),
            "Inspect automation/orchestrator.py and summarize the next fix.\n",
        )

    def test_save_chatgpt_reply_file_reads_from_file(self) -> None:
        paths = self.make_paths()
        chatgpt_codex_loop.write_state(paths, chatgpt_codex_loop.default_state("Goal"))
        reply_path = Path(self.temp_dir.name) / "chatgpt_reply.md"
        reply_path.write_text(
            "## CODEX_PROMPT\nReview automation/README.md.\n\n## WHY\nNeed a doc follow-up.\n",
            encoding="utf-8",
        )

        with redirect_stdout(io.StringIO()):
            chatgpt_codex_loop.command_save_chatgpt_reply(
                argparse.Namespace(file=str(reply_path)),
                paths,
            )

        prompt_path = paths.prompts_dir / "codex_prompt_001.md"
        self.assertEqual(prompt_path.read_text(encoding="utf-8"), "Review automation/README.md.\n")

    def test_save_chatgpt_reply_fails_when_codex_prompt_missing(self) -> None:
        paths = self.make_paths()
        chatgpt_codex_loop.write_state(paths, chatgpt_codex_loop.default_state("Goal"))
        reply = "## WHY\nThere is no codex prompt here.\n"

        with patch("sys.stdin", io.StringIO(reply)):
            with self.assertRaises(SystemExit) as exc:
                chatgpt_codex_loop.command_save_chatgpt_reply(argparse.Namespace(file=None), paths)

        self.assertIn("## CODEX_PROMPT", str(exc.exception))

    def test_guide_after_save_chatgpt_reply_suggests_show_prompt_and_save_codex_reply(self) -> None:
        paths = self.make_paths()
        chatgpt_codex_loop.write_state(paths, chatgpt_codex_loop.default_state("Goal"))
        with redirect_stdout(io.StringIO()):
            chatgpt_codex_loop.command_next_chatgpt(argparse.Namespace(copy=False), paths)
        with patch(
            "sys.stdin",
            io.StringIO("## CODEX_PROMPT\nDo the next repo step.\n\n## WHY\nBecause it is next.\n"),
        ):
            with redirect_stdout(io.StringIO()):
                chatgpt_codex_loop.command_save_chatgpt_reply(argparse.Namespace(file=None), paths)

        stdout = io.StringIO()
        with redirect_stdout(stdout):
            chatgpt_codex_loop.command_guide(argparse.Namespace(), paths)

        output = stdout.getvalue()
        self.assertIn("show-codex-prompt", output)
        self.assertIn("save-codex-reply", output)
        self.assertIn("codex_prompt_001.md", output)

    def test_save_reply_file_missing_or_empty_fails_clearly(self) -> None:
        paths = self.make_paths()
        chatgpt_codex_loop.write_state(paths, chatgpt_codex_loop.default_state("Goal"))
        missing_path = Path(self.temp_dir.name) / "missing.md"
        empty_path = Path(self.temp_dir.name) / "empty.md"
        empty_path.write_text("", encoding="utf-8")

        with self.assertRaises(SystemExit) as missing_exc:
            chatgpt_codex_loop.command_save_chatgpt_reply(
                argparse.Namespace(file=str(missing_path)),
                paths,
            )
        self.assertIn("does not exist", str(missing_exc.exception))

        with self.assertRaises(SystemExit) as empty_exc:
            chatgpt_codex_loop.command_save_chatgpt_reply(
                argparse.Namespace(file=str(empty_path)),
                paths,
            )
        self.assertIn("empty", str(empty_exc.exception))

    def test_save_codex_reply_increments_iteration(self) -> None:
        paths = self.make_paths()
        chatgpt_codex_loop.write_state(paths, chatgpt_codex_loop.default_state("Goal"))

        with patch("sys.stdin", io.StringIO("Codex result\n")):
            with redirect_stdout(io.StringIO()):
                chatgpt_codex_loop.command_save_codex_reply(argparse.Namespace(file=None), paths)

        state = chatgpt_codex_loop.load_state(paths)
        self.assertEqual(state["iteration"], 1)
        self.assertTrue((paths.codex_dir / "reply_001.md").exists())

    def test_guide_after_save_codex_reply_suggests_next_chatgpt(self) -> None:
        paths = self.make_paths()
        chatgpt_codex_loop.write_state(paths, chatgpt_codex_loop.default_state("Goal"))
        with redirect_stdout(io.StringIO()):
            chatgpt_codex_loop.command_next_chatgpt(argparse.Namespace(copy=False), paths)
        with patch(
            "sys.stdin",
            io.StringIO("## CODEX_PROMPT\nDo the next repo step.\n\n## WHY\nBecause it is next.\n"),
        ):
            with redirect_stdout(io.StringIO()):
                chatgpt_codex_loop.command_save_chatgpt_reply(argparse.Namespace(file=None), paths)
        with patch("sys.stdin", io.StringIO("Codex completed the step.\n")):
            with redirect_stdout(io.StringIO()):
                chatgpt_codex_loop.command_save_codex_reply(argparse.Namespace(file=None), paths)

        stdout = io.StringIO()
        with redirect_stdout(stdout):
            chatgpt_codex_loop.command_guide(argparse.Namespace(), paths)

        output = stdout.getvalue()
        self.assertIn("next-chatgpt", output)
        self.assertIn("Iteration 1", output)

    def test_save_codex_reply_file_reads_from_file_and_increments_iteration(self) -> None:
        paths = self.make_paths()
        chatgpt_codex_loop.write_state(paths, chatgpt_codex_loop.default_state("Goal"))
        reply_path = Path(self.temp_dir.name) / "codex_reply.md"
        reply_path.write_text("Codex completed the requested repo task.\n", encoding="utf-8")

        with redirect_stdout(io.StringIO()):
            chatgpt_codex_loop.command_save_codex_reply(
                argparse.Namespace(file=str(reply_path)),
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
                chatgpt_codex_loop.command_save_chatgpt_reply(argparse.Namespace(file=None), paths)
        with patch("sys.stdin", io.StringIO("Codex completed the step and left notes.\n")):
            with redirect_stdout(io.StringIO()):
                chatgpt_codex_loop.command_save_codex_reply(argparse.Namespace(file=None), paths)

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
                chatgpt_codex_loop.command_save_chatgpt_reply(argparse.Namespace(file=None), paths)
        with patch("sys.stdin", io.StringIO("Codex completed the step.\n")):
            with redirect_stdout(io.StringIO()):
                chatgpt_codex_loop.command_save_codex_reply(argparse.Namespace(file=None), paths)

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


if __name__ == "__main__":
    unittest.main()
