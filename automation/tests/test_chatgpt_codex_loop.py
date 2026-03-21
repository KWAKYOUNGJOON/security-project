import argparse
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from automation import chatgpt_codex_loop


class ChatgptCodexLoopTest(unittest.TestCase):
    def make_paths(self) -> chatgpt_codex_loop.LoopPaths:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        return chatgpt_codex_loop.build_paths(Path(self.temp_dir.name))

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

    def test_guide_with_no_state_suggests_init(self) -> None:
        paths = self.make_paths()
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            chatgpt_codex_loop.command_guide(argparse.Namespace(), paths)

        output = stdout.getvalue()
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


if __name__ == "__main__":
    unittest.main()
