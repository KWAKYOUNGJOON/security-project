import argparse
import json
import subprocess
import sys
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent
LOOP_SCRIPT = BASE_DIR / "chatgpt_codex_loop.py"
ASSIST_STEP = "python3 automation/chatgpt_codex_assist.py step"
ASSIST_START = 'python3 automation/chatgpt_codex_assist.py start --goal "<your goal>"'
ASSIST_STATUS = "python3 automation/chatgpt_codex_assist.py status"
ASSIST_DOCTOR = "python3 automation/chatgpt_codex_assist.py doctor"
ASSIST_HISTORY = "python3 automation/chatgpt_codex_assist.py history --limit 10"
ASSIST_LOCK_STATUS = "python3 automation/chatgpt_codex_assist.py lock-status"


def run_loop_command(args: list[str], input_text: str | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(LOOP_SCRIPT), *args],
        text=True,
        input=input_text,
        capture_output=True,
        check=False,
    )


def command_error_message(result: subprocess.CompletedProcess[str]) -> str:
    return result.stderr.strip() or result.stdout.strip() or "Underlying loop command failed."


def run_loop_json(args: list[str], input_text: str | None = None) -> dict:
    result = run_loop_command([*args, "--json"], input_text=input_text)
    if result.returncode != 0:
        raise SystemExit(command_error_message(result))
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"Failed to parse JSON from {' '.join(args)}: {exc}") from exc


def run_loop(args: list[str], input_text: str | None = None) -> subprocess.CompletedProcess[str]:
    result = run_loop_command(args, input_text=input_text)
    if result.returncode != 0:
        raise SystemExit(command_error_message(result))
    return result


def wrapper_next_step(phase: str, recommended_command: str) -> str:
    if phase in ("needs_chatgpt_request", "cycle_complete"):
        return ASSIST_STEP
    if "--from-clipboard" in recommended_command:
        return f"{ASSIST_STEP} --from-clipboard"
    return f"{ASSIST_STEP} --file /path/to/reply.md"


def clipboard_label_for_action(action: str) -> str:
    if action == "saved_chatgpt_reply":
        return "Codex prompt"
    return "ChatGPT request"


def format_artifacts(artifacts: dict[str, str]) -> list[str]:
    labels = {
        "chatgpt_request": "ChatGPT request",
        "chatgpt_reply": "ChatGPT reply",
        "codex_prompt": "Codex prompt",
        "codex_reply": "Codex reply",
    }
    lines: list[str] = []
    for key, label in labels.items():
        path = artifacts.get(key)
        if path:
            lines.append(f"{label}: {path}")
    return lines


def format_history_artifacts(artifacts: dict[str, str]) -> str:
    if not artifacts:
        return "none"
    return ", ".join(f"{label}={Path(path).name}" for label, path in artifacts.items())


def read_stdin_if_needed(needs_input: bool) -> str | None:
    if not needs_input:
        return None
    return sys.stdin.read()


def command_start(args: argparse.Namespace) -> int:
    doctor = run_loop_json(["doctor"])
    if doctor["initialized"]:
        raise SystemExit(
            f"Loop already initialized. Use `{ASSIST_STEP}` or `{ASSIST_STATUS}` instead."
        )
    if doctor["diagnosis"] != "loop_not_initialized":
        raise SystemExit(
            f"{doctor['notes']} Recommended recovery: `{doctor['recommended_command']}`. "
            f"Run `{ASSIST_DOCTOR}` for more detail."
        )

    run_loop(["init", "--goal", args.goal])
    guide = run_loop_json(["guide"])
    advance_args = ["advance"]
    if "--copy" in guide["recommended_command"]:
        advance_args.append("--copy")
    result = run_loop_json(advance_args)
    next_guide = run_loop_json(["guide"])
    next_step = wrapper_next_step(next_guide["phase"], next_guide["recommended_command"])

    lines = [
        f"Loop root: {result['loop_root']}",
        "Initialized loop.",
        f"Action: {result['action']}",
        *format_artifacts(result["artifacts"]),
        f"Copied: {'ChatGPT request to clipboard.' if result['copied_to_clipboard'] else 'no'}",
        f"Next: paste the ChatGPT request into ChatGPT, then run `{next_step}`.",
    ]
    sys.stdout.write("\n".join(lines) + "\n")
    return 0


def command_step(args: argparse.Namespace) -> int:
    doctor = run_loop_json(["doctor"])
    if not doctor["initialized"]:
        raise SystemExit(f"Loop not initialized. Run `{ASSIST_START}` first.")
    if not doctor["healthy"]:
        raise SystemExit(
            f"{doctor['notes']} Recommended recovery: `{doctor['recommended_command']}`. "
            f"Run `{ASSIST_DOCTOR}` for more detail."
        )

    phase_before = doctor.get("phase", "unknown")
    guide = run_loop_json(["guide"])
    advance_args = ["advance"]
    if args.file:
        advance_args.extend(["--file", args.file])
    elif args.from_clipboard:
        advance_args.append("--from-clipboard")
    if "--copy" in guide["recommended_command"]:
        advance_args.append("--copy")

    input_text = read_stdin_if_needed(
        phase_before in ("needs_chatgpt_reply", "needs_codex_reply")
        and not args.file
        and not args.from_clipboard
    )
    result = run_loop_json(advance_args, input_text=input_text)
    next_guide = run_loop_json(["guide"])
    phase_after = next_guide["phase"]
    next_step = wrapper_next_step(phase_after, next_guide["recommended_command"])

    if phase_after == "needs_chatgpt_reply":
        next_action = "paste the ChatGPT request into ChatGPT"
    elif phase_after == "needs_codex_reply":
        next_action = "paste the Codex prompt into Codex"
    else:
        next_action = "review the current loop state"

    lines = [
        f"Loop root: {result['loop_root']}",
        f"Phase: {phase_before} -> {phase_after}",
        f"Action: {result['action']}",
        *format_artifacts(result["artifacts"]),
        f"Copied: {clipboard_label_for_action(result['action']) + ' to clipboard.' if result['copied_to_clipboard'] else 'no'}",
        f"Next: {next_action}, then run `{next_step}`.",
    ]
    sys.stdout.write("\n".join(lines) + "\n")
    return 0


def command_status(_: argparse.Namespace) -> int:
    doctor = run_loop_json(["doctor"])
    if not doctor["initialized"]:
        sys.stdout.write(
            f"Loop root: {doctor['loop_root']}\n"
            "State: Loop not initialized.\n"
            f"Next: {ASSIST_START}\n"
        )
        return 0

    status = run_loop_json(["status"])
    guide = run_loop_json(["guide"])
    next_step = wrapper_next_step(guide["phase"], guide["recommended_command"])
    lines = [
        f"Loop root: {status['loop_root']}",
        f"Goal: {status['goal']}",
        f"Iteration: {status['iteration']}",
        f"State: {doctor['notes']}",
    ]
    if doctor["healthy"]:
        lines.append(f"Next: {next_step}")
    else:
        lines.append(f"Recovery: {doctor['recommended_command']}")
    sys.stdout.write("\n".join(lines) + "\n")
    return 0


def command_doctor(_: argparse.Namespace) -> int:
    doctor = run_loop_json(["doctor"])
    lines = [
        f"Loop root: {doctor['loop_root']}",
        f"Iteration: {doctor['iteration'] if doctor['iteration'] is not None else '(unknown)'}",
        f"Diagnosis: {doctor['notes']}",
        f"Next: {doctor['recommended_command']}",
    ]
    details = doctor.get("details")
    if details:
        detail_value = next(iter(details.values()))
        if isinstance(detail_value, list):
            detail_value = detail_value[0] if detail_value else ""
        if detail_value:
            lines.insert(3, f"Details: {detail_value}")
    sys.stdout.write("\n".join(lines) + "\n")
    return 0


def command_history(args: argparse.Namespace) -> int:
    history = run_loop_json(["history", "--limit", str(args.limit)])
    lines = [f"Loop root: {history['loop_root']}"]
    events = history.get("events", [])
    total_events = history.get("total_events", 0)
    if not events:
        lines.append("Recent events: none")
        lines.append(f"Next: use `{ASSIST_START}` to initialize a new loop if needed.")
        sys.stdout.write("\n".join(lines) + "\n")
        return 0

    lines.append(f"Recent events (showing {len(events)} of {total_events}):")
    for event in events:
        clipboard = "yes" if event.get("copied_to_clipboard") else "no"
        lines.append(
            f"- {event.get('timestamp', '(unknown time)')} | {event.get('command', '(unknown command)')} "
            f"| iteration={event.get('iteration_before')} -> {event.get('iteration_after')} "
            f"| copied={clipboard} | artifacts={format_history_artifacts(event.get('artifacts') or {})}"
        )
    sys.stdout.write("\n".join(lines) + "\n")
    return 0


def command_lock_status(_: argparse.Namespace) -> int:
    payload = run_loop_json(["lock-status"])
    lines = [
        f"Loop root: {payload['loop_root']}",
        f"Lock state: {payload['lock_state']}",
    ]
    metadata = payload.get("metadata")
    if isinstance(metadata, dict):
        if metadata.get("command"):
            lines.append(f"Lock command: {metadata['command']}")
        if metadata.get("pid") is not None:
            lines.append(f"Lock pid: {metadata['pid']}")
        if metadata.get("timestamp"):
            lines.append(f"Lock timestamp: {metadata['timestamp']}")
    lines.append(f"Diagnosis: {payload['diagnosis']}")
    lines.append(f"Next: {payload['recommended_action']}")
    sys.stdout.write("\n".join(lines) + "\n")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Thin operator wrapper around the repo-local ChatGPT <-> Codex loop."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    start_parser = subparsers.add_parser("start", help="Initialize a new loop and generate the first ChatGPT request.")
    start_parser.add_argument("--goal", required=True, help="Top-level loop goal.")
    start_parser.set_defaults(func=command_start)

    step_parser = subparsers.add_parser("step", help="Perform the next happy-path loop step.")
    step_parser.add_argument("--file", help="Read the current reply from a file instead of stdin when input is needed.")
    step_parser.add_argument(
        "--from-clipboard",
        action="store_true",
        help="Read the current reply from the clipboard instead of stdin when input is needed.",
    )
    step_parser.set_defaults(func=command_step)

    status_parser = subparsers.add_parser("status", help="Show a concise operator-facing loop summary.")
    status_parser.set_defaults(func=command_status)

    doctor_parser = subparsers.add_parser("doctor", help="Show a concise operator-facing recovery diagnosis.")
    doctor_parser.set_defaults(func=command_doctor)

    history_parser = subparsers.add_parser("history", help="Show a concise operator-facing summary of recent loop actions.")
    history_parser.add_argument("--limit", type=int, default=10, help="Maximum number of recent events to show.")
    history_parser.set_defaults(func=command_history)

    lock_status_parser = subparsers.add_parser("lock-status", help="Show a concise operator-facing write-lock summary.")
    lock_status_parser.set_defaults(func=command_lock_status)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
