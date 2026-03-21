import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent
LOOP_DIR = BASE_DIR / "loop"
STATE_FILE = LOOP_DIR / "state.json"


@dataclass(frozen=True)
class LoopPaths:
    base_dir: Path
    loop_dir: Path
    state_file: Path
    chatgpt_dir: Path
    codex_dir: Path
    prompts_dir: Path


def default_paths() -> LoopPaths:
    return build_paths(BASE_DIR)


def build_paths(base_dir: Path) -> LoopPaths:
    loop_dir = base_dir / "loop"
    return LoopPaths(
        base_dir=base_dir,
        loop_dir=loop_dir,
        state_file=loop_dir / "state.json",
        chatgpt_dir=loop_dir / "chatgpt",
        codex_dir=loop_dir / "codex",
        prompts_dir=loop_dir / "prompts",
    )


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def ensure_loop_dirs(paths: LoopPaths) -> None:
    paths.loop_dir.mkdir(parents=True, exist_ok=True)
    paths.chatgpt_dir.mkdir(parents=True, exist_ok=True)
    paths.codex_dir.mkdir(parents=True, exist_ok=True)
    paths.prompts_dir.mkdir(parents=True, exist_ok=True)


def default_state(goal: str) -> dict:
    timestamp = utc_now()
    return {
        "goal": goal,
        "iteration": 0,
        "created_at": timestamp,
        "updated_at": timestamp,
        "latest_chatgpt_request": "",
        "latest_chatgpt_reply": "",
        "latest_codex_prompt": "",
        "latest_codex_reply": "",
    }


def write_state(paths: LoopPaths, state: dict) -> None:
    ensure_loop_dirs(paths)
    temp_path = paths.state_file.with_suffix(".tmp")
    temp_path.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
    temp_path.replace(paths.state_file)


def load_state(paths: LoopPaths) -> dict:
    if not paths.state_file.exists():
        raise SystemExit("Loop state is missing. Run `init --goal \"...\"` first.")
    try:
        state = json.loads(paths.state_file.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SystemExit(f"Failed to parse state file {paths.state_file}: {exc}") from exc
    required_keys = {
        "goal",
        "iteration",
        "created_at",
        "updated_at",
        "latest_chatgpt_request",
        "latest_chatgpt_reply",
        "latest_codex_prompt",
        "latest_codex_reply",
    }
    missing = sorted(required_keys - set(state))
    if missing:
        raise SystemExit(f"State file is missing required keys: {', '.join(missing)}")
    return state


def update_state(paths: LoopPaths, state: dict, **changes: str | int) -> dict:
    updated = dict(state)
    updated.update(changes)
    updated["updated_at"] = utc_now()
    write_state(paths, updated)
    return updated


def cycle_number(iteration: int) -> int:
    return iteration + 1


def numbered_path(directory: Path, prefix: str, number: int) -> Path:
    return directory / f"{prefix}_{number:03d}.md"


def read_optional_text(path_str: str) -> str:
    if not path_str:
        return ""
    path = Path(path_str)
    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8").strip()


def read_required_input(label: str, file_path: str | None = None) -> str:
    if file_path:
        path = Path(file_path)
        if not path.exists():
            raise SystemExit(f"{label} file does not exist: {path}")
        if not path.is_file():
            raise SystemExit(f"{label} path is not a file: {path}")
        content = path.read_text(encoding="utf-8")
        if not content.strip():
            raise SystemExit(f"{label} file is empty: {path}")
        return content

    content = sys.stdin.read()
    if not content.strip():
        raise SystemExit(f"No input received on stdin for {label}.")
    return content


def get_clipboard_command() -> list[str] | None:
    if sys.platform.startswith("win") or os.environ.get("WSL_DISTRO_NAME") or os.environ.get("WSL_INTEROP"):
        if shutil.which("clip.exe"):
            return ["clip.exe"]
    if sys.platform == "darwin" and shutil.which("pbcopy"):
        return ["pbcopy"]
    if shutil.which("wl-copy"):
        return ["wl-copy"]
    if shutil.which("xclip"):
        return ["xclip", "-selection", "clipboard"]
    if shutil.which("xsel"):
        return ["xsel", "--clipboard", "--input"]
    return None


def copy_to_clipboard(text: str) -> None:
    command = get_clipboard_command()
    if not command:
        raise SystemExit(
            "No supported clipboard tool found. Install one of: clip.exe, pbcopy, wl-copy, xclip, or xsel."
        )
    result = subprocess.run(
        command,
        input=text,
        text=True,
        capture_output=True,
    )
    if result.returncode != 0:
        details = result.stderr.strip() or result.stdout.strip() or "clipboard command failed"
        raise SystemExit(f"Clipboard copy failed via {' '.join(command)}: {details}")


def build_preview(content: str, limit: int = 160) -> str:
    flattened = " ".join(content.split())
    if len(flattened) <= limit:
        return flattened
    return flattened[: limit - 3] + "..."


def format_context_block(title: str, content: str) -> str:
    if not content:
        return ""
    return f"## {title}\n{content}\n"


def build_chatgpt_request(state: dict) -> str:
    next_iteration = cycle_number(int(state["iteration"]))
    sections = [
        "You are helping manage a manual ChatGPT <-> Codex loop for this repository.",
        "Return exactly one next Codex prompt in the required format below.",
        "",
        "Required response format:",
        "## CODEX_PROMPT",
        "<prompt>",
        "",
        "## WHY",
        "<brief rationale>",
        "",
        "Constraints:",
        "- Provide exactly one practical next Codex prompt.",
        "- Keep the prompt repository-task oriented.",
        "- Do not include extra sections before or after the required format.",
        "",
        f"Current completed iteration: {state['iteration']}",
        f"Next Codex cycle number: {next_iteration}",
        "",
        "## TOP_LEVEL_GOAL",
        str(state["goal"]).strip(),
    ]

    latest_request = read_optional_text(state["latest_chatgpt_request"])
    latest_reply = read_optional_text(state["latest_chatgpt_reply"])
    latest_codex_reply = read_optional_text(state["latest_codex_reply"])

    for block in (
        format_context_block("LATEST_CHATGPT_REQUEST", latest_request),
        format_context_block("LATEST_CHATGPT_REPLY", latest_reply),
        format_context_block("LATEST_CODEX_REPLY", latest_codex_reply),
    ):
        if block:
            sections.extend(["", block.rstrip()])

    sections.extend(
        [
            "",
            "Focus on the single most useful next Codex step given the latest repository state.",
        ]
    )
    return "\n".join(sections).strip() + "\n"


def format_status_output(state: dict, verbose: bool = False) -> str:
    lines = [
        f"Goal: {state['goal']}",
        f"Iteration: {state['iteration']}",
        f"Created: {state['created_at']}",
        f"Updated: {state['updated_at']}",
        f"Latest ChatGPT request: {Path(state['latest_chatgpt_request']).name if state['latest_chatgpt_request'] else '(none)'}",
        f"Latest ChatGPT reply: {Path(state['latest_chatgpt_reply']).name if state['latest_chatgpt_reply'] else '(none)'}",
        f"Latest Codex prompt: {Path(state['latest_codex_prompt']).name if state['latest_codex_prompt'] else '(none)'}",
        f"Latest Codex reply: {Path(state['latest_codex_reply']).name if state['latest_codex_reply'] else '(none)'}",
    ]
    if not verbose:
        return "\n".join(lines) + "\n"

    lines.append("")
    lines.append("Verbose details:")
    for label, path_key in (
        ("ChatGPT request", "latest_chatgpt_request"),
        ("ChatGPT reply", "latest_chatgpt_reply"),
        ("Codex prompt", "latest_codex_prompt"),
        ("Codex reply", "latest_codex_reply"),
    ):
        path_str = state[path_key]
        if not path_str:
            lines.append(f"- {label} path: (none)")
            continue
        content = read_optional_text(path_str)
        lines.append(f"- {label} path: {path_str}")
        lines.append(f"  Preview: {build_preview(content) if content else '(empty or missing)'}")
    return "\n".join(lines) + "\n"


def current_cycle_artifact_paths(paths: LoopPaths, iteration: int) -> dict[str, Path]:
    current_cycle = cycle_number(iteration)
    return {
        "chatgpt_request": numbered_path(paths.chatgpt_dir, "request", current_cycle),
        "chatgpt_reply": numbered_path(paths.chatgpt_dir, "reply", current_cycle),
        "codex_prompt": numbered_path(paths.prompts_dir, "codex_prompt", current_cycle),
        "codex_reply": numbered_path(paths.codex_dir, "reply", current_cycle),
    }


def has_current_cycle_artifact(state: dict, key: str, expected_path: Path) -> bool:
    return state.get(key, "") == str(expected_path) and expected_path.exists()


def format_guide_output(paths: LoopPaths) -> str:
    if not paths.state_file.exists():
        return (
            "No loop state exists.\n"
            "Next step: python3 automation/chatgpt_codex_loop.py init --goal \"<your goal>\"\n"
        )

    state = load_state(paths)
    current_paths = current_cycle_artifact_paths(paths, int(state["iteration"]))
    has_request = has_current_cycle_artifact(state, "latest_chatgpt_request", current_paths["chatgpt_request"])
    has_chatgpt_reply = has_current_cycle_artifact(state, "latest_chatgpt_reply", current_paths["chatgpt_reply"])
    has_codex_prompt = has_current_cycle_artifact(state, "latest_codex_prompt", current_paths["codex_prompt"])
    has_codex_reply = has_current_cycle_artifact(state, "latest_codex_reply", current_paths["codex_reply"])

    if not has_request:
        return (
            f"Iteration {state['iteration']} is complete or not started for the next cycle.\n"
            "Next step: python3 automation/chatgpt_codex_loop.py next-chatgpt --copy\n"
        )
    if not has_chatgpt_reply:
        return (
            f"ChatGPT request is ready at {current_paths['chatgpt_request']}.\n"
            "Next step: save the ChatGPT reply with:\n"
            "  python3 automation/chatgpt_codex_loop.py save-chatgpt-reply --file /path/to/chatgpt_reply.md\n"
        )
    if has_codex_prompt and not has_codex_reply:
        return (
            f"Codex prompt is ready at {current_paths['codex_prompt']}.\n"
            "Next steps:\n"
            "  python3 automation/chatgpt_codex_loop.py show-codex-prompt --copy\n"
            "  python3 automation/chatgpt_codex_loop.py save-codex-reply --file /path/to/codex_reply.md\n"
        )
    return (
        f"Codex reply is saved for iteration {state['iteration']}.\n"
        "Next step: python3 automation/chatgpt_codex_loop.py next-chatgpt --copy\n"
    )


def format_cycle_example_output() -> str:
    return (
        "Example cycle:\n"
        "  python3 automation/chatgpt_codex_loop.py init --goal \"Review automation/ and choose the next safe step\"\n"
        "  python3 automation/chatgpt_codex_loop.py next-chatgpt --copy\n"
        "  python3 automation/chatgpt_codex_loop.py save-chatgpt-reply < chatgpt_reply.md\n"
        "  python3 automation/chatgpt_codex_loop.py show-codex-prompt --copy\n"
        "  python3 automation/chatgpt_codex_loop.py save-codex-reply < codex_reply.md\n"
        "\n"
        "File-based variant:\n"
        "  python3 automation/chatgpt_codex_loop.py save-chatgpt-reply --file /path/to/chatgpt_reply.md\n"
        "  python3 automation/chatgpt_codex_loop.py save-codex-reply --file /path/to/codex_reply.md\n"
        "\n"
        "Check progress:\n"
        "  python3 automation/chatgpt_codex_loop.py guide\n"
        "  python3 automation/chatgpt_codex_loop.py status --verbose\n"
    )


def extract_codex_prompt(chatgpt_reply: str) -> str:
    match = re.search(
        r"(?ms)^##\s*CODEX_PROMPT\s*\n(?P<prompt>.*?)(?:\n##\s+[^\n]+|\Z)",
        chatgpt_reply.strip(),
    )
    if not match:
        raise SystemExit("ChatGPT reply is missing the required `## CODEX_PROMPT` section.")
    prompt = match.group("prompt").strip()
    if not prompt:
        raise SystemExit("ChatGPT reply has an empty `## CODEX_PROMPT` section.")
    return prompt + "\n"


def command_init(args: argparse.Namespace, paths: LoopPaths) -> int:
    goal = args.goal.strip()
    if not goal:
        raise SystemExit("`init --goal` requires non-empty text.")
    ensure_loop_dirs(paths)
    state = default_state(goal)
    write_state(paths, state)
    print(json.dumps(state, indent=2))
    return 0


def command_next_chatgpt(_: argparse.Namespace, paths: LoopPaths) -> int:
    state = load_state(paths)
    request_number = cycle_number(int(state["iteration"]))
    request_text = build_chatgpt_request(state)
    request_path = numbered_path(paths.chatgpt_dir, "request", request_number)
    request_path.write_text(request_text, encoding="utf-8")
    state = update_state(paths, state, latest_chatgpt_request=str(request_path))
    sys.stdout.write(request_text)
    if not request_text.endswith("\n"):
        sys.stdout.write("\n")
    if _.copy:
        copy_to_clipboard(request_text)
    return 0


def command_save_chatgpt_reply(args: argparse.Namespace, paths: LoopPaths) -> int:
    state = load_state(paths)
    reply_number = cycle_number(int(state["iteration"]))
    reply_text = read_required_input("ChatGPT reply", args.file)
    prompt_text = extract_codex_prompt(reply_text)

    reply_path = numbered_path(paths.chatgpt_dir, "reply", reply_number)
    prompt_path = numbered_path(paths.prompts_dir, "codex_prompt", reply_number)
    reply_path.write_text(reply_text, encoding="utf-8")
    prompt_path.write_text(prompt_text, encoding="utf-8")

    update_state(
        paths,
        state,
        latest_chatgpt_reply=str(reply_path),
        latest_codex_prompt=str(prompt_path),
    )
    print(prompt_path)
    return 0


def command_show_codex_prompt(_: argparse.Namespace, paths: LoopPaths) -> int:
    state = load_state(paths)
    prompt_path = state["latest_codex_prompt"]
    if not prompt_path:
        raise SystemExit("No Codex prompt has been extracted yet. Run `save-chatgpt-reply` first.")
    path = Path(prompt_path)
    if not path.exists():
        raise SystemExit(f"Latest Codex prompt file does not exist: {path}")
    prompt_text = path.read_text(encoding="utf-8")
    sys.stdout.write(prompt_text)
    if _.copy:
        copy_to_clipboard(prompt_text)
    return 0


def command_save_codex_reply(args: argparse.Namespace, paths: LoopPaths) -> int:
    state = load_state(paths)
    reply_number = cycle_number(int(state["iteration"]))
    reply_text = read_required_input("Codex reply", args.file)
    reply_path = numbered_path(paths.codex_dir, "reply", reply_number)
    reply_path.write_text(reply_text, encoding="utf-8")

    update_state(
        paths,
        state,
        iteration=reply_number,
        latest_codex_reply=str(reply_path),
    )
    print(reply_path)
    return 0


def find_existing_cycle_file(directory: Path, prefix: str, number: int) -> str:
    if number <= 0:
        return ""
    path = numbered_path(directory, prefix, number)
    if path.exists():
        return str(path)
    return ""


def command_status(args: argparse.Namespace, paths: LoopPaths) -> int:
    state = load_state(paths)
    sys.stdout.write(format_status_output(state, verbose=args.verbose))
    return 0


def command_guide(_: argparse.Namespace, paths: LoopPaths) -> int:
    sys.stdout.write(format_guide_output(paths))
    return 0


def command_cycle_example(_: argparse.Namespace, paths: LoopPaths) -> int:
    del paths
    sys.stdout.write(format_cycle_example_output())
    return 0


def command_reset_iteration(args: argparse.Namespace, paths: LoopPaths) -> int:
    state = load_state(paths)
    iteration = args.iteration
    if iteration < 0:
        raise SystemExit("Iteration must be >= 0.")
    updated_state = update_state(
        paths,
        state,
        iteration=iteration,
        latest_chatgpt_request=find_existing_cycle_file(paths.chatgpt_dir, "request", iteration),
        latest_chatgpt_reply=find_existing_cycle_file(paths.chatgpt_dir, "reply", iteration),
        latest_codex_prompt=find_existing_cycle_file(paths.prompts_dir, "codex_prompt", iteration),
        latest_codex_reply=find_existing_cycle_file(paths.codex_dir, "reply", iteration),
    )
    print(json.dumps(updated_state, indent=2))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Manage a repo-local ChatGPT <-> Codex handoff loop."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    init_parser = subparsers.add_parser("init", help="Initialize loop state with a top-level goal.")
    init_parser.add_argument("--goal", required=True, help="Top-level loop goal.")
    init_parser.set_defaults(func=command_init)

    next_parser = subparsers.add_parser("next-chatgpt", help="Generate the next ChatGPT request.")
    next_parser.add_argument("--copy", action="store_true", help="Also copy the generated request to the clipboard.")
    next_parser.set_defaults(func=command_next_chatgpt)

    save_chatgpt_parser = subparsers.add_parser(
        "save-chatgpt-reply",
        help="Save a ChatGPT reply and extract the next Codex prompt.",
    )
    save_chatgpt_parser.add_argument("--file", help="Read the ChatGPT reply from a file instead of stdin.")
    save_chatgpt_parser.set_defaults(func=command_save_chatgpt_reply)

    show_codex_parser = subparsers.add_parser(
        "show-codex-prompt",
        help="Print the latest extracted Codex prompt.",
    )
    show_codex_parser.add_argument("--copy", action="store_true", help="Also copy the latest prompt to the clipboard.")
    show_codex_parser.set_defaults(func=command_show_codex_prompt)

    save_codex_parser = subparsers.add_parser(
        "save-codex-reply",
        help="Save a Codex reply and advance the iteration.",
    )
    save_codex_parser.add_argument("--file", help="Read the Codex reply from a file instead of stdin.")
    save_codex_parser.set_defaults(func=command_save_codex_reply)

    status_parser = subparsers.add_parser("status", help="Show current loop status.")
    status_parser.add_argument("--verbose", action="store_true", help="Show latest file paths and short previews.")
    status_parser.set_defaults(func=command_status)

    guide_parser = subparsers.add_parser(
        "guide",
        help="Print the next happy-path command to run.",
        description="Print the next happy-path command to run.",
    )
    guide_parser.set_defaults(func=command_guide)

    cycle_example_parser = subparsers.add_parser(
        "cycle-example",
        help="Print a short example of one full loop cycle.",
        description="Print a short example of one full loop cycle.",
    )
    cycle_example_parser.set_defaults(func=command_cycle_example)

    reset_parser = subparsers.add_parser(
        "reset-iteration",
        help="Reset the loop to a specific completed iteration number.",
    )
    reset_parser.add_argument("iteration", type=int)
    reset_parser.set_defaults(func=command_reset_iteration)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args, default_paths())


if __name__ == "__main__":
    raise SystemExit(main())
