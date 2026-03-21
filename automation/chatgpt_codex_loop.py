import argparse
import io
import json
import os
import re
import shutil
import subprocess
import sys
from contextlib import contextmanager, redirect_stdout
from dataclasses import dataclass
from datetime import datetime, timezone
from difflib import SequenceMatcher
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent
LOOP_DIR = BASE_DIR / "loop"
STATE_FILE = LOOP_DIR / "state.json"
LOOP_DIR_ENV_VAR = "CHATGPT_CODEX_LOOP_DIR"
RECENT_CONTEXT_PREVIEW_LIMIT = 600
EVENTS_FILE_NAME = "events.jsonl"
WRITE_LOCK_FILE_NAME = "write.lock"
WRITE_COMMANDS = {
    "init",
    "next-chatgpt",
    "save-chatgpt-reply",
    "save-codex-reply",
    "advance",
    "reset-iteration",
}


@dataclass(frozen=True)
class LoopPaths:
    base_dir: Path
    loop_dir: Path
    state_file: Path
    chatgpt_dir: Path
    codex_dir: Path
    prompts_dir: Path


def default_paths() -> LoopPaths:
    override = os.environ.get(LOOP_DIR_ENV_VAR, "").strip()
    if not override:
        return build_paths(BASE_DIR)
    loop_dir = resolve_loop_dir_override(override)
    return build_loop_paths(loop_dir)


def build_paths(base_dir: Path) -> LoopPaths:
    loop_dir = base_dir / "loop"
    return build_loop_paths(loop_dir, base_dir=base_dir)


def build_loop_paths(loop_dir: Path, base_dir: Path | None = None) -> LoopPaths:
    return LoopPaths(
        base_dir=base_dir if base_dir is not None else loop_dir.parent,
        loop_dir=loop_dir,
        state_file=loop_dir / "state.json",
        chatgpt_dir=loop_dir / "chatgpt",
        codex_dir=loop_dir / "codex",
        prompts_dir=loop_dir / "prompts",
    )


def resolve_loop_dir_override(raw_path: str) -> Path:
    loop_dir = Path(raw_path).expanduser()
    if not loop_dir.is_absolute():
        loop_dir = (Path.cwd() / loop_dir).resolve()
    try:
        loop_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise SystemExit(
            f"{LOOP_DIR_ENV_VAR} points to an unusable loop directory {loop_dir}: {exc}"
        ) from exc
    if not loop_dir.is_dir():
        raise SystemExit(
            f"{LOOP_DIR_ENV_VAR} must point to a directory, got: {loop_dir}"
        )
    return loop_dir


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def ensure_loop_dirs(paths: LoopPaths) -> None:
    paths.loop_dir.mkdir(parents=True, exist_ok=True)
    paths.chatgpt_dir.mkdir(parents=True, exist_ok=True)
    paths.codex_dir.mkdir(parents=True, exist_ok=True)
    paths.prompts_dir.mkdir(parents=True, exist_ok=True)


def has_loop_artifacts(paths: LoopPaths) -> bool:
    for directory in (paths.chatgpt_dir, paths.codex_dir, paths.prompts_dir):
        if directory.exists() and any(directory.iterdir()):
            return True
    return False


def ensure_init_target_is_safe(paths: LoopPaths, force: bool) -> None:
    if force:
        return
    if not paths.state_file.exists() and not has_loop_artifacts(paths):
        return
    raise SystemExit(
        "Refusing to overwrite existing loop state or artifacts under "
        f"{paths.loop_dir}. Re-run `init --force --goal \"...\"` to replace it."
    )


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


def read_required_input(
    label: str,
    file_path: str | None = None,
    *,
    from_clipboard: bool = False,
) -> str:
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

    if from_clipboard:
        content = read_from_clipboard(label)
        if not content.strip():
            raise SystemExit(f"No input received from the clipboard for {label}.")
        return content

    content = sys.stdin.read()
    if not content.strip():
        raise SystemExit(f"No input received on stdin for {label}.")
    return content


def get_clipboard_copy_command() -> list[str] | None:
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


def get_clipboard_paste_command() -> list[str] | None:
    if sys.platform.startswith("win") or os.environ.get("WSL_DISTRO_NAME") or os.environ.get("WSL_INTEROP"):
        command = "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; Get-Clipboard -Raw"
        for candidate in ("powershell.exe", "powershell", "pwsh"):
            if shutil.which(candidate):
                return [candidate, "-NoProfile", "-Command", command]
    if sys.platform == "darwin" and shutil.which("pbpaste"):
        return ["pbpaste"]
    if shutil.which("wl-paste"):
        return ["wl-paste"]
    if shutil.which("xclip"):
        return ["xclip", "-selection", "clipboard", "-o"]
    if shutil.which("xsel"):
        return ["xsel", "--clipboard", "--output"]
    return None


def copy_to_clipboard(text: str) -> None:
    command = get_clipboard_copy_command()
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


def read_from_clipboard(label: str) -> str:
    command = get_clipboard_paste_command()
    if not command:
        raise SystemExit(
            f"No supported clipboard tool found for {label}. Re-run with `--file <path>` or pipe stdin instead. "
            "Install one of: powershell.exe, pbpaste, wl-paste, xclip, or xsel."
        )
    result = subprocess.run(
        command,
        text=True,
        encoding="utf-8",
        capture_output=True,
    )
    if result.returncode != 0:
        details = result.stderr.strip() or result.stdout.strip() or "clipboard command failed"
        raise SystemExit(f"Clipboard paste failed via {' '.join(command)}: {details}")
    return result.stdout


def build_preview(content: str, limit: int = 160) -> str:
    flattened = " ".join(content.split())
    if len(flattened) <= limit:
        return flattened
    return flattened[: limit - 3] + "..."


def format_context_block(title: str, content: str) -> str:
    if not content:
        return ""
    return f"## {title}\n{content}\n"


def read_bounded_optional_text(path_str: str, limit: int = RECENT_CONTEXT_PREVIEW_LIMIT) -> str:
    return build_preview(read_optional_text(path_str), limit=limit)


def normalize_for_comparison(text: str) -> str:
    return " ".join(text.split())


def texts_match_or_are_near(left: str, right: str) -> bool:
    normalized_left = normalize_for_comparison(left)
    normalized_right = normalize_for_comparison(right)
    if not normalized_left or not normalized_right:
        return False
    if normalized_left == normalized_right:
        return True
    if min(len(normalized_left), len(normalized_right)) < 80:
        return False
    return SequenceMatcher(a=normalized_left, b=normalized_right).ratio() >= 0.98


def looks_like_generated_chatgpt_request(text: str) -> bool:
    stripped = text.lstrip()
    if stripped.startswith("You are helping manage a manual ChatGPT <-> Codex loop for this repository."):
        return True
    markers = (
        "Required response format:",
        "## TOP_LEVEL_GOAL",
        "Focus on the single most useful next Codex step given the latest repository state.",
    )
    return all(marker in text for marker in markers)


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

    latest_reply = read_bounded_optional_text(state["latest_chatgpt_reply"])
    latest_codex_reply = read_bounded_optional_text(state["latest_codex_reply"])

    for block in (
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


def uses_default_loop_root(paths: LoopPaths) -> bool:
    return paths.loop_dir == LOOP_DIR


def root_mode(paths: LoopPaths) -> str:
    return "default" if uses_default_loop_root(paths) else "override"


def root_mode_description(paths: LoopPaths) -> str:
    return "default repository path" if uses_default_loop_root(paths) else f"override via {LOOP_DIR_ENV_VAR}"


def format_loop_root_line(paths: LoopPaths) -> str:
    return f"Loop root: {paths.loop_dir} ({root_mode_description(paths)})"


def lock_status_command() -> str:
    return "python3 automation/chatgpt_codex_loop.py lock-status"


def clear_lock_force_command() -> str:
    return "python3 automation/chatgpt_codex_loop.py clear-lock --force"


def event_log_path(paths: LoopPaths) -> Path:
    return paths.loop_dir / EVENTS_FILE_NAME


def write_lock_path(paths: LoopPaths) -> Path:
    return paths.loop_dir / WRITE_LOCK_FILE_NAME


def current_pid() -> int | None:
    try:
        return os.getpid()
    except OSError:
        return None


def build_write_lock_metadata(paths: LoopPaths, command: str) -> dict:
    return {
        "timestamp": utc_now(),
        "pid": current_pid(),
        "command": command,
        "loop_root": str(paths.loop_dir),
        "root_mode": root_mode(paths),
    }


def read_write_lock_metadata(paths: LoopPaths) -> dict | None:
    lock_path = write_lock_path(paths)
    if not lock_path.exists():
        return None
    try:
        raw = lock_path.read_text(encoding="utf-8").strip()
    except OSError:
        return {"lock_path": str(lock_path), "state": "unreadable"}
    if not raw:
        return {"lock_path": str(lock_path), "state": "empty"}
    try:
        metadata = json.loads(raw)
    except json.JSONDecodeError:
        return {"lock_path": str(lock_path), "state": "malformed"}
    if not isinstance(metadata, dict):
        return {"lock_path": str(lock_path), "state": "malformed"}
    metadata.setdefault("lock_path", str(lock_path))
    return metadata


def pid_appears_running(pid: int | None) -> bool | None:
    if pid is None:
        return None
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return True
    return True


def lock_metadata_pid(metadata: dict | None) -> int | None:
    if not isinstance(metadata, dict):
        return None
    pid = metadata.get("pid")
    if isinstance(pid, int) and pid > 0:
        return pid
    return None


def build_lock_status_payload(paths: LoopPaths) -> dict:
    payload = {
        "loop_root": str(paths.loop_dir),
        "root_mode": root_mode(paths),
        "lock_present": False,
        "lock_state": "absent",
        "lock_path": str(write_lock_path(paths)),
        "diagnosis": "No write lock present.",
        "recommended_action": "Proceed normally.",
    }
    metadata = read_write_lock_metadata(paths)
    if metadata is None:
        return payload

    payload["lock_present"] = True
    payload["metadata"] = metadata
    metadata_state = metadata.get("state")
    metadata_root = metadata.get("loop_root")
    pid = lock_metadata_pid(metadata)
    pid_running = pid_appears_running(pid)

    if metadata_state in {"unreadable", "empty", "malformed"}:
        payload.update(
            {
                "lock_state": "suspicious",
                "diagnosis": f"Write lock is present but its metadata is {metadata_state}.",
                "recommended_action": (
                    f"Inspect {lock_status_command()} and `python3 automation/chatgpt_codex_loop.py doctor`, "
                    f"then run `{clear_lock_force_command()}` only if you are sure no other loop command is active."
                ),
            }
        )
        return payload

    if metadata_root and metadata_root != str(paths.loop_dir):
        payload.update(
            {
                "lock_state": "suspicious",
                "diagnosis": (
                    "Write lock is present but its metadata points at a different loop root."
                ),
                "recommended_action": (
                    f"Inspect {lock_status_command()} and `python3 automation/chatgpt_codex_loop.py doctor`, "
                    f"then run `{clear_lock_force_command()}` only if you are sure no other loop command is active."
                ),
            }
        )
        return payload

    if pid_running is True:
        payload.update(
            {
                "lock_state": "active",
                "diagnosis": "Write lock is present and the recorded pid appears active.",
                "recommended_action": "Wait for the other command to finish, then retry.",
            }
        )
        return payload

    if pid_running is False:
        payload.update(
            {
                "lock_state": "suspicious",
                "diagnosis": f"Write lock is present but looks stale because pid {pid} is not running.",
                "recommended_action": (
                    f"Inspect {lock_status_command()} and `python3 automation/chatgpt_codex_loop.py doctor`, "
                    f"then run `{clear_lock_force_command()}` only if you are sure no other loop command is active."
                ),
            }
        )
        return payload

    payload.update(
        {
            "lock_state": "unknown",
            "diagnosis": (
                "Write lock is present, but process liveness could not be determined from its metadata."
            ),
            "recommended_action": (
                "Wait briefly and retry. If the lock keeps blocking progress, inspect it with "
                f"`{lock_status_command()}` and `python3 automation/chatgpt_codex_loop.py doctor`, "
                f"then run `{clear_lock_force_command()}` only if you are sure no other loop command is active."
            ),
        }
    )
    return payload


def summarize_lock_metadata(metadata: dict) -> str:
    parts: list[str] = []
    if metadata.get("command"):
        parts.append(f"command={metadata['command']}")
    if metadata.get("pid") is not None:
        parts.append(f"pid={metadata['pid']}")
    if metadata.get("timestamp"):
        parts.append(f"timestamp={metadata['timestamp']}")
    if metadata.get("loop_root"):
        parts.append(f"loop_root={metadata['loop_root']}")
    if metadata.get("state"):
        parts.append(f"metadata_state={metadata['state']}")
    return ", ".join(parts) if parts else "(no metadata)"


def format_lock_status_output(paths: LoopPaths) -> str:
    payload = build_lock_status_payload(paths)
    lines = [
        f"Loop root: {payload['loop_root']}",
        f"Root mode: {root_mode_description(paths)}",
        f"Lock state: {payload['lock_state']}",
        f"Lock path: {payload['lock_path']}",
    ]
    metadata = payload.get("metadata")
    if isinstance(metadata, dict):
        if metadata.get("command"):
            lines.append(f"Lock command: {metadata['command']}")
        if metadata.get("pid") is not None:
            lines.append(f"Lock pid: {metadata['pid']}")
        if metadata.get("timestamp"):
            lines.append(f"Lock timestamp: {metadata['timestamp']}")
        if metadata.get("loop_root"):
            lines.append(f"Metadata loop root: {metadata['loop_root']}")
        if metadata.get("state"):
            lines.append(f"Metadata state: {metadata['state']}")
    lines.append(f"Diagnosis: {payload['diagnosis']}")
    lines.append(f"Safest next action: {payload['recommended_action']}")
    return "\n".join(lines) + "\n"


def build_clear_lock_payload(paths: LoopPaths, force: bool) -> dict:
    lock_payload = build_lock_status_payload(paths)
    payload = {
        "loop_root": str(paths.loop_dir),
        "root_mode": root_mode(paths),
        "lock_present": lock_payload["lock_present"],
        "lock_state": lock_payload["lock_state"],
        "lock_path": lock_payload["lock_path"],
        "action_taken": "none",
        "cleared": False,
        "diagnosis": lock_payload["diagnosis"],
        "recommended_action": lock_payload["recommended_action"],
    }
    metadata = lock_payload.get("metadata")
    if isinstance(metadata, dict):
        payload["metadata"] = metadata

    if not lock_payload["lock_present"]:
        payload["diagnosis"] = "No write lock present."
        payload["recommended_action"] = "Proceed normally."
        return payload

    if lock_payload["lock_state"] == "active":
        payload["recommended_action"] = (
            f"Wait for the other command to finish and retry. If you need more detail, run `{lock_status_command()}` "
            "or `python3 automation/chatgpt_codex_loop.py doctor`."
        )
        return payload

    if not force:
        payload["recommended_action"] = (
            f"This is a manual recovery operation. Re-run `{clear_lock_force_command()}` only if you are sure "
            "no other loop command is active."
        )
        return payload

    try:
        write_lock_path(paths).unlink()
    except FileNotFoundError:
        payload.update(
            {
                "lock_present": False,
                "lock_state": "absent",
                "diagnosis": "Write lock disappeared before it could be cleared.",
                "recommended_action": "Proceed normally.",
            }
        )
        return payload

    payload.update(
        {
            "lock_present": False,
            "action_taken": "cleared_lock",
            "cleared": True,
            "diagnosis": f"Cleared the {lock_payload['lock_state']} write lock.",
            "recommended_action": "Re-run `python3 automation/chatgpt_codex_loop.py doctor` or retry the blocked command.",
        }
    )
    return payload


def format_clear_lock_output(payload: dict, paths: LoopPaths) -> str:
    lines = [
        f"Loop root: {payload['loop_root']}",
        f"Root mode: {root_mode_description(paths)}",
        f"Lock present: {'yes' if payload['lock_present'] else 'no'}",
        f"Lock state: {payload['lock_state']}",
        f"Action taken: {payload['action_taken']}",
    ]
    metadata = payload.get("metadata")
    if isinstance(metadata, dict):
        if metadata.get("command"):
            lines.append(f"Lock command: {metadata['command']}")
        if metadata.get("pid") is not None:
            lines.append(f"Lock pid: {metadata['pid']}")
        if metadata.get("timestamp"):
            lines.append(f"Lock timestamp: {metadata['timestamp']}")
        if metadata.get("loop_root"):
            lines.append(f"Metadata loop root: {metadata['loop_root']}")
        if metadata.get("state"):
            lines.append(f"Metadata state: {metadata['state']}")
    lines.append(f"Diagnosis: {payload['diagnosis']}")
    lines.append(f"Safest next step: {payload['recommended_action']}")
    return "\n".join(lines) + "\n"


def clear_lock_error_message(payload: dict, paths: LoopPaths) -> str:
    return format_clear_lock_output(payload, paths).rstrip()


def format_write_lock_error(paths: LoopPaths) -> str:
    payload = build_lock_status_payload(paths)
    metadata = payload.get("metadata")
    if isinstance(metadata, dict) and metadata:
        holder = f"Lock holder: {summarize_lock_metadata(metadata)}."
    else:
        holder = f"Lock file: {payload['lock_path']}."
    return (
        f"Another state-changing loop command is already in progress for {paths.loop_dir}. "
        f"{holder} {payload['diagnosis']} Safest next step: {payload['recommended_action']}"
    )


@contextmanager
def acquire_write_lock(paths: LoopPaths, command: str):
    paths.loop_dir.mkdir(parents=True, exist_ok=True)
    lock_path = write_lock_path(paths)
    metadata = build_write_lock_metadata(paths, command)
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
    try:
        fd = os.open(lock_path, flags, 0o644)
    except FileExistsError as exc:
        raise SystemExit(format_write_lock_error(paths)) from exc

    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(json.dumps(metadata, indent=2) + "\n")
    except Exception:
        try:
            lock_path.unlink()
        except OSError:
            pass
        raise

    try:
        yield
    finally:
        try:
            lock_path.unlink()
        except FileNotFoundError:
            pass
        except OSError:
            pass


def filtered_artifacts(**paths_by_label: str | None) -> dict[str, str]:
    return {label: path for label, path in paths_by_label.items() if path}


def input_source_for_args(file_path: str | None, from_clipboard: bool) -> str:
    if file_path:
        return "file"
    if from_clipboard:
        return "clipboard"
    return "stdin"


def should_log_event(args: argparse.Namespace) -> bool:
    return not getattr(args, "_skip_event_log", False)


def append_event(
    paths: LoopPaths,
    command: str,
    action: str,
    *,
    iteration_before: int | None,
    iteration_after: int | None,
    input_source: str = "none",
    copied_to_clipboard: bool = False,
    artifacts: dict[str, str] | None = None,
) -> None:
    ensure_loop_dirs(paths)
    event = {
        "timestamp": utc_now(),
        "command": command,
        "action": action,
        "loop_root": str(paths.loop_dir),
        "root_mode": root_mode(paths),
        "iteration_before": iteration_before,
        "iteration_after": iteration_after,
        "input_source": input_source,
        "copied_to_clipboard": copied_to_clipboard,
        "artifacts": artifacts or {},
    }
    try:
        with event_log_path(paths).open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(event) + "\n")
    except OSError:
        # Best-effort logging keeps successful loop commands from turning into failures.
        return


def build_status_payload(paths: LoopPaths, state: dict, verbose: bool = False) -> dict:
    payload = {
        "loop_root": str(paths.loop_dir),
        "root_mode": root_mode(paths),
        "goal": state["goal"],
        "iteration": int(state["iteration"]),
        "created_at": state["created_at"],
        "updated_at": state["updated_at"],
        "latest_chatgpt_request": state["latest_chatgpt_request"] or None,
        "latest_chatgpt_reply": state["latest_chatgpt_reply"] or None,
        "latest_codex_prompt": state["latest_codex_prompt"] or None,
        "latest_codex_reply": state["latest_codex_reply"] or None,
    }
    if verbose:
        payload["details"] = {
            "chatgpt_request": {
                "path": state["latest_chatgpt_request"] or None,
                "preview": build_preview(read_optional_text(state["latest_chatgpt_request"])) if state["latest_chatgpt_request"] else None,
            },
            "chatgpt_reply": {
                "path": state["latest_chatgpt_reply"] or None,
                "preview": build_preview(read_optional_text(state["latest_chatgpt_reply"])) if state["latest_chatgpt_reply"] else None,
            },
            "codex_prompt": {
                "path": state["latest_codex_prompt"] or None,
                "preview": build_preview(read_optional_text(state["latest_codex_prompt"])) if state["latest_codex_prompt"] else None,
            },
            "codex_reply": {
                "path": state["latest_codex_reply"] or None,
                "preview": build_preview(read_optional_text(state["latest_codex_reply"])) if state["latest_codex_reply"] else None,
            },
        }
    return payload


def format_status_output(paths: LoopPaths, state: dict, verbose: bool = False) -> str:
    lines = [
        format_loop_root_line(paths),
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


def artifact_paths_for_cycle(paths: LoopPaths, cycle: int) -> dict[str, Path]:
    return {
        "chatgpt_request": numbered_path(paths.chatgpt_dir, "request", cycle),
        "chatgpt_reply": numbered_path(paths.chatgpt_dir, "reply", cycle),
        "codex_prompt": numbered_path(paths.prompts_dir, "codex_prompt", cycle),
        "codex_reply": numbered_path(paths.codex_dir, "reply", cycle),
    }


def has_current_cycle_artifact(state: dict, key: str, expected_path: Path) -> bool:
    return state.get(key, "") == str(expected_path) and expected_path.exists()


def current_cycle_phase(paths: LoopPaths, state: dict) -> tuple[str, dict[str, Path]]:
    current_paths = current_cycle_artifact_paths(paths, int(state["iteration"]))
    has_request = has_current_cycle_artifact(state, "latest_chatgpt_request", current_paths["chatgpt_request"])
    has_chatgpt_reply = has_current_cycle_artifact(state, "latest_chatgpt_reply", current_paths["chatgpt_reply"])
    has_codex_prompt = has_current_cycle_artifact(state, "latest_codex_prompt", current_paths["codex_prompt"])
    has_codex_reply = has_current_cycle_artifact(state, "latest_codex_reply", current_paths["codex_reply"])

    if not has_request:
        return "needs_chatgpt_request", current_paths
    if not has_chatgpt_reply:
        return "needs_chatgpt_reply", current_paths
    if has_codex_prompt and not has_codex_reply:
        return "needs_codex_reply", current_paths
    return "cycle_complete", current_paths


def preferred_advance_command() -> str:
    if get_clipboard_copy_command() and get_clipboard_paste_command():
        return "python3 automation/chatgpt_codex_loop.py advance --from-clipboard --copy"
    return "python3 automation/chatgpt_codex_loop.py advance"


def preferred_next_chatgpt_command() -> str:
    suffix = " --copy" if get_clipboard_copy_command() else ""
    return f"python3 automation/chatgpt_codex_loop.py next-chatgpt{suffix}"


def preferred_show_codex_prompt_command() -> str:
    suffix = " --copy" if get_clipboard_copy_command() else ""
    return f"python3 automation/chatgpt_codex_loop.py show-codex-prompt{suffix}"


def preferred_save_chatgpt_reply_command() -> str:
    copy_suffix = " --copy-prompt" if get_clipboard_copy_command() else ""
    if get_clipboard_paste_command():
        return f"python3 automation/chatgpt_codex_loop.py save-chatgpt-reply --from-clipboard{copy_suffix}"
    if get_clipboard_copy_command():
        return "python3 automation/chatgpt_codex_loop.py save-chatgpt-reply --file /path/to/chatgpt_reply.md --copy-prompt"
    return "python3 automation/chatgpt_codex_loop.py save-chatgpt-reply --file /path/to/chatgpt_reply.md"


def preferred_save_codex_reply_command() -> str:
    next_suffix = " --next-chatgpt" if get_clipboard_copy_command() else ""
    copy_suffix = " --copy" if get_clipboard_copy_command() else ""
    if get_clipboard_paste_command():
        return f"python3 automation/chatgpt_codex_loop.py save-codex-reply --from-clipboard{next_suffix}{copy_suffix}"
    if get_clipboard_copy_command():
        return "python3 automation/chatgpt_codex_loop.py save-codex-reply --file /path/to/codex_reply.md --next-chatgpt --copy"
    return "python3 automation/chatgpt_codex_loop.py save-codex-reply --file /path/to/codex_reply.md"


def build_guide_payload(paths: LoopPaths) -> dict:
    payload = {
        "loop_root": str(paths.loop_dir),
        "root_mode": root_mode(paths),
    }
    if not paths.state_file.exists():
        payload.update(
            {
                "initialized": False,
                "iteration": None,
                "phase": "uninitialized",
                "recommended_command": 'python3 automation/chatgpt_codex_loop.py init --goal "<your goal>"',
                "notes": "No loop state exists.",
            }
        )
        return payload

    state = load_state(paths)
    phase, current_paths = current_cycle_phase(paths, state)
    low_friction_advance = get_clipboard_copy_command() and get_clipboard_paste_command()
    payload.update(
        {
            "initialized": True,
            "iteration": int(state["iteration"]),
            "phase": phase,
        }
    )
    if phase == "needs_chatgpt_request":
        payload["recommended_command"] = preferred_advance_command() if low_friction_advance else preferred_next_chatgpt_command()
        payload["notes"] = f"Iteration {state['iteration']} is complete or not started for the next cycle."
        return payload
    if phase == "needs_chatgpt_reply":
        payload["recommended_command"] = preferred_advance_command() if low_friction_advance else preferred_save_chatgpt_reply_command()
        payload["notes"] = f"ChatGPT request is ready at {current_paths['chatgpt_request']}."
        return payload
    if phase == "needs_codex_reply":
        payload["recommended_command"] = preferred_advance_command() if low_friction_advance else preferred_save_codex_reply_command()
        payload["notes"] = f"Codex prompt is ready at {current_paths['codex_prompt']}."
        return payload
    payload["recommended_command"] = preferred_advance_command() if low_friction_advance else preferred_next_chatgpt_command()
    payload["notes"] = f"Codex reply is saved for iteration {state['iteration']}."
    return payload


def inspect_state_file(paths: LoopPaths) -> tuple[dict | None, str | None]:
    if not paths.state_file.exists():
        return None, "Loop state file is missing."
    try:
        state = json.loads(paths.state_file.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return None, f"State file is malformed: {exc}"
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
        return None, f"State file is missing required keys: {', '.join(missing)}"
    try:
        iteration = int(state["iteration"])
    except (TypeError, ValueError):
        return None, f"State file has a non-integer iteration: {state['iteration']!r}"
    if iteration < 0:
        return None, f"State file has an invalid negative iteration: {iteration}"
    inspected = dict(state)
    inspected["iteration"] = iteration
    return inspected, None


def artifact_number_from_path(path_str: str, prefix: str) -> int | None:
    if not path_str:
        return None
    match = re.match(rf"^{re.escape(prefix)}_(\d+)\.md$", Path(path_str).name)
    if not match:
        return None
    return int(match.group(1))


def existing_artifact_numbers(directory: Path, prefix: str) -> set[int]:
    if not directory.exists():
        return set()
    pattern = re.compile(rf"^{re.escape(prefix)}_(\d+)\.md$")
    numbers: set[int] = set()
    for path in directory.iterdir():
        if not path.is_file():
            continue
        match = pattern.match(path.name)
        if match:
            numbers.add(int(match.group(1)))
    return numbers


def highest_completed_iteration_on_disk(paths: LoopPaths) -> int:
    completed = (
        existing_artifact_numbers(paths.chatgpt_dir, "request")
        & existing_artifact_numbers(paths.chatgpt_dir, "reply")
        & existing_artifact_numbers(paths.prompts_dir, "codex_prompt")
        & existing_artifact_numbers(paths.codex_dir, "reply")
    )
    return max(completed) if completed else 0


def find_missing_state_references(state: dict) -> list[str]:
    missing: list[str] = []
    for key in (
        "latest_chatgpt_request",
        "latest_chatgpt_reply",
        "latest_codex_prompt",
        "latest_codex_reply",
    ):
        path_str = state.get(key, "")
        if path_str and not Path(path_str).exists():
            missing.append(f"{key} -> missing {path_str}")
    return missing


def detect_cycle_skew(state: dict, iteration: int) -> str | None:
    request_num = artifact_number_from_path(state["latest_chatgpt_request"], "request")
    chatgpt_reply_num = artifact_number_from_path(state["latest_chatgpt_reply"], "reply")
    codex_prompt_num = artifact_number_from_path(state["latest_codex_prompt"], "codex_prompt")
    codex_reply_num = artifact_number_from_path(state["latest_codex_reply"], "reply")

    if codex_reply_num is not None and codex_reply_num > iteration:
        return (
            f"latest_codex_reply points to cycle {codex_reply_num:03d}, "
            f"which is ahead of iteration {iteration}."
        )
    if request_num is not None and chatgpt_reply_num is not None and request_num < chatgpt_reply_num:
        return (
            f"latest_chatgpt_request is cycle {request_num:03d}, "
            f"but latest_chatgpt_reply is later at cycle {chatgpt_reply_num:03d}."
        )
    if request_num is not None and codex_prompt_num is not None and request_num < codex_prompt_num:
        return (
            f"latest_chatgpt_request is cycle {request_num:03d}, "
            f"but latest_codex_prompt is later at cycle {codex_prompt_num:03d}."
        )
    if request_num is not None and codex_reply_num is not None and request_num < codex_reply_num:
        return (
            f"latest_chatgpt_request is cycle {request_num:03d}, "
            f"but latest_codex_reply is later at cycle {codex_reply_num:03d}."
        )
    return None


def find_latest_path_mismatches(paths: LoopPaths, state: dict) -> list[str]:
    iteration = int(state["iteration"])
    current_paths = current_cycle_artifact_paths(paths, iteration)
    previous_paths = artifact_paths_for_cycle(paths, iteration) if iteration > 0 else {}
    expected_paths = {
        "latest_chatgpt_request": {str(current_paths["chatgpt_request"])},
        "latest_chatgpt_reply": {str(current_paths["chatgpt_reply"])},
        "latest_codex_prompt": {str(current_paths["codex_prompt"])},
        "latest_codex_reply": set(),
    }
    if iteration > 0:
        expected_paths["latest_chatgpt_request"].add(str(previous_paths["chatgpt_request"]))
        expected_paths["latest_chatgpt_reply"].add(str(previous_paths["chatgpt_reply"]))
        expected_paths["latest_codex_prompt"].add(str(previous_paths["codex_prompt"]))
        expected_paths["latest_codex_reply"].add(str(previous_paths["codex_reply"]))

    mismatches: list[str] = []
    for key, allowed in expected_paths.items():
        path_str = state.get(key, "")
        if not path_str:
            continue
        if path_str not in allowed:
            allowed_display = ", ".join(sorted(allowed)) if allowed else "(none)"
            mismatches.append(f"{key} -> {path_str} (expected one of: {allowed_display})")
    return mismatches


def format_doctor_output(paths: LoopPaths) -> str:
    payload = build_doctor_payload(paths)
    lines = [format_loop_root_line(paths)]
    iteration = payload["iteration"]
    lines.append(f"Current iteration: {iteration if iteration is not None else '(unknown)'}")
    lines.append(f"Diagnosed state/phase: {payload['notes']}")
    details = payload.get("details")
    if details:
        if isinstance(details, dict):
            detail_text = next(iter(details.values()))
            if isinstance(detail_text, list):
                detail_text = detail_text[0] if detail_text else ""
            lines.append(f"Details: {detail_text}")
    lines.append(f"Safest next step: {payload['recommended_command']}")
    return "\n".join(lines) + "\n"


def build_doctor_payload(paths: LoopPaths) -> dict:
    payload = {
        "loop_root": str(paths.loop_dir),
        "root_mode": root_mode(paths),
    }
    lock_payload = build_lock_status_payload(paths)
    payload.update(
        {
            "lock_present": lock_payload["lock_present"],
            "lock_state": lock_payload["lock_state"],
            "lock_path": lock_payload["lock_path"],
        }
    )
    if "metadata" in lock_payload:
        payload["lock_metadata"] = lock_payload["metadata"]

    state, error = inspect_state_file(paths)
    if lock_payload["lock_state"] in {"active", "suspicious", "unknown"}:
        initialized = state is not None
        recommended_command = (
            clear_lock_force_command()
            if lock_payload["lock_state"] in {"suspicious", "unknown"}
            else lock_payload["recommended_action"]
        )
        payload.update(
            {
                "initialized": initialized,
                "healthy": False,
                "iteration": int(state["iteration"]) if state is not None else None,
                "diagnosis": (
                    "active_write_lock"
                    if lock_payload["lock_state"] == "active"
                    else "suspicious_write_lock"
                    if lock_payload["lock_state"] == "suspicious"
                    else "write_lock_liveness_unknown"
                ),
                "recommended_command": recommended_command,
                "notes": lock_payload["diagnosis"],
            }
        )
        metadata = lock_payload.get("metadata")
        if isinstance(metadata, dict) and metadata:
            payload["details"] = {"lock": summarize_lock_metadata(metadata)}
        return payload

    if state is None:
        payload.update(
            {
                "initialized": False,
                "healthy": False,
                "iteration": None,
            }
        )
        if error == "Loop state file is missing." and not has_loop_artifacts(paths):
            payload.update(
                {
                    "diagnosis": "loop_not_initialized",
                    "recommended_command": 'python3 automation/chatgpt_codex_loop.py init --goal "<your goal>"',
                    "notes": "Loop not initialized.",
                }
            )
            return payload
        if error == "Loop state file is missing.":
            payload.update(
                {
                    "diagnosis": "state_file_missing_with_artifacts",
                    "recommended_command": 'python3 automation/chatgpt_codex_loop.py init --force --goal "<your goal>"',
                    "notes": "Loop state file is missing while loop artifacts still exist.",
                    "details": {"state_error": error},
                }
            )
            return payload
        payload.update(
            {
                "diagnosis": "state_file_malformed",
                "recommended_command": 'python3 automation/chatgpt_codex_loop.py init --force --goal "<your goal>"',
                "notes": "State file is malformed.",
                "details": {"state_error": error},
            }
        )
        return payload

    iteration = int(state["iteration"])
    payload.update(
        {
            "initialized": True,
            "iteration": iteration,
        }
    )

    missing_references = find_missing_state_references(state)
    if missing_references:
        payload.update(
            {
                "healthy": False,
                "diagnosis": "missing_referenced_artifacts",
                "recommended_command": f"python3 automation/chatgpt_codex_loop.py reset-iteration {highest_completed_iteration_on_disk(paths)}",
                "notes": "State references missing artifacts.",
                "details": {"missing_references": missing_references},
            }
        )
        return payload

    skew = detect_cycle_skew(state, iteration)
    if skew:
        payload.update(
            {
                "healthy": False,
                "diagnosis": "suspicious_cycle_skew",
                "recommended_command": f"python3 automation/chatgpt_codex_loop.py reset-iteration {highest_completed_iteration_on_disk(paths)}",
                "notes": "Suspicious cycle skew.",
                "details": {"skew": skew},
            }
        )
        return payload

    mismatches = find_latest_path_mismatches(paths, state)
    if mismatches:
        payload.update(
            {
                "healthy": False,
                "diagnosis": "latest_artifact_path_mismatch",
                "recommended_command": f"python3 automation/chatgpt_codex_loop.py reset-iteration {highest_completed_iteration_on_disk(paths)}",
                "notes": "Latest artifact paths do not match the expected numbered files.",
                "details": {"mismatches": mismatches},
            }
        )
        return payload

    phase, current_paths = current_cycle_phase(paths, state)
    payload["phase"] = phase
    low_friction_advance = get_clipboard_copy_command() and get_clipboard_paste_command()
    if phase == "needs_chatgpt_request":
        payload.update(
            {
                "healthy": True,
                "diagnosis": "healthy",
                "recommended_command": preferred_advance_command() if low_friction_advance else preferred_next_chatgpt_command(),
                "notes": "Healthy: ready to generate the next ChatGPT request.",
            }
        )
        return payload
    if phase == "needs_chatgpt_reply":
        payload.update(
            {
                "healthy": True,
                "diagnosis": "healthy",
                "recommended_command": preferred_advance_command() if low_friction_advance else preferred_save_chatgpt_reply_command(),
                "notes": f"Healthy partial cycle: waiting for the ChatGPT reply to {current_paths['chatgpt_request']}.",
            }
        )
        return payload
    if phase == "needs_codex_reply":
        payload.update(
            {
                "healthy": True,
                "diagnosis": "healthy",
                "recommended_command": preferred_advance_command() if low_friction_advance else preferred_save_codex_reply_command(),
                "notes": f"Healthy partial cycle: waiting for the Codex reply to {current_paths['codex_prompt']}.",
            }
        )
        return payload
    payload.update(
        {
            "healthy": False,
            "diagnosis": "inconsistent_partial_cycle",
            "recommended_command": f"python3 automation/chatgpt_codex_loop.py reset-iteration {highest_completed_iteration_on_disk(paths)}",
            "notes": "Inconsistent partial cycle: current artifacts do not match a normal happy-path phase.",
        }
    )
    return payload


def format_guide_output(paths: LoopPaths) -> str:
    prefix = format_loop_root_line(paths) + "\n"
    if not paths.state_file.exists():
        return prefix + (
            "No loop state exists.\n"
            "Next step: python3 automation/chatgpt_codex_loop.py init --goal \"<your goal>\"\n"
        )

    state = load_state(paths)
    phase, current_paths = current_cycle_phase(paths, state)
    low_friction_advance = get_clipboard_copy_command() and get_clipboard_paste_command()

    if phase == "needs_chatgpt_request":
        if low_friction_advance:
            return prefix + (
                f"Iteration {state['iteration']} is complete or not started for the next cycle.\n"
                f"Next step: {preferred_advance_command()}\n"
            )
        return prefix + (
            f"Iteration {state['iteration']} is complete or not started for the next cycle.\n"
            f"Next step: {preferred_next_chatgpt_command()}\n"
        )
    if phase == "needs_chatgpt_reply":
        if low_friction_advance:
            return prefix + (
                f"ChatGPT request is ready at {current_paths['chatgpt_request']}.\n"
                "Next step:\n"
                f"  {preferred_advance_command()}\n"
            )
        return prefix + (
            f"ChatGPT request is ready at {current_paths['chatgpt_request']}.\n"
            "Next step: save the ChatGPT reply with:\n"
            f"  {preferred_save_chatgpt_reply_command()}\n"
        )
    if phase == "needs_codex_reply":
        if low_friction_advance:
            return prefix + (
                f"Codex prompt is ready at {current_paths['codex_prompt']}.\n"
                "Next step:\n"
                f"  {preferred_advance_command()}\n"
                "Optional inspection:\n"
                f"  {preferred_show_codex_prompt_command()}\n"
            )
        if get_clipboard_copy_command():
            return prefix + (
                f"Codex prompt is ready at {current_paths['codex_prompt']}.\n"
                "Next step:\n"
                f"  {preferred_save_codex_reply_command()}\n"
                "Optional inspection:\n"
                f"  {preferred_show_codex_prompt_command()}\n"
            )
        return prefix + (
            f"Codex prompt is ready at {current_paths['codex_prompt']}.\n"
            "Next steps:\n"
            f"  {preferred_show_codex_prompt_command()}\n"
            f"  {preferred_save_codex_reply_command()}\n"
        )
    return prefix + (
        f"Codex reply is saved for iteration {state['iteration']}.\n"
        f"Next step: {preferred_next_chatgpt_command()}\n"
    )


def read_history_events(paths: LoopPaths) -> list[dict]:
    log_path = event_log_path(paths)
    if not log_path.exists():
        return []

    events: list[dict] = []
    for line_number, raw_line in enumerate(log_path.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw_line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError as exc:
            raise SystemExit(f"Failed to parse history log {log_path} line {line_number}: {exc}") from exc
        if not isinstance(event, dict):
            raise SystemExit(f"Failed to parse history log {log_path} line {line_number}: expected an object.")
        events.append(event)
    return events


def build_history_payload(paths: LoopPaths, limit: int) -> dict:
    events = read_history_events(paths)
    selected = events[-limit:] if limit > 0 else []
    return {
        "loop_root": str(paths.loop_dir),
        "root_mode": root_mode(paths),
        "limit": limit,
        "total_events": len(events),
        "events": selected,
    }


def format_history_event(event: dict) -> str:
    artifacts = event.get("artifacts") or {}
    artifact_summary = ", ".join(
        f"{label}={Path(path).name}" for label, path in artifacts.items()
    ) if artifacts else "none"
    clipboard_summary = "yes" if event.get("copied_to_clipboard") else "no"
    iteration_before = event.get("iteration_before")
    iteration_after = event.get("iteration_after")
    return (
        f"- {event.get('timestamp', '(unknown time)')} | {event.get('command', '(unknown command)')} "
        f"| action={event.get('action', '(unknown action)')} "
        f"| iteration={iteration_before} -> {iteration_after} "
        f"| input={event.get('input_source', 'none')} "
        f"| copied={clipboard_summary} "
        f"| artifacts={artifact_summary}"
    )


def format_history_output(paths: LoopPaths, limit: int) -> str:
    payload = build_history_payload(paths, limit)
    lines = [format_loop_root_line(paths)]
    if not payload["events"]:
        lines.append("No loop history exists yet.")
        return "\n".join(lines) + "\n"

    lines.append(
        f"Recent events (showing {len(payload['events'])} of {payload['total_events']}):"
    )
    lines.extend(format_history_event(event) for event in payload["events"])
    return "\n".join(lines) + "\n"


def format_cycle_example_output() -> str:
    return (
        "Example cycle:\n"
        "  python3 automation/chatgpt_codex_loop.py init --goal \"Review automation/ and choose the next safe step\"\n"
        "  python3 automation/chatgpt_codex_loop.py next-chatgpt --copy\n"
        "  python3 automation/chatgpt_codex_loop.py save-chatgpt-reply < chatgpt_reply.md\n"
        "  python3 automation/chatgpt_codex_loop.py save-codex-reply < codex_reply.md\n"
        "  python3 automation/chatgpt_codex_loop.py next-chatgpt --copy\n"
        "\n"
        "File-based variant:\n"
        "  python3 automation/chatgpt_codex_loop.py save-chatgpt-reply --file /path/to/chatgpt_reply.md\n"
        "  python3 automation/chatgpt_codex_loop.py save-codex-reply --file /path/to/codex_reply.md\n"
        "\n"
        "Repeated-command variant:\n"
        "  python3 automation/chatgpt_codex_loop.py advance --from-clipboard --copy\n"
        "  python3 automation/chatgpt_codex_loop.py advance --from-clipboard --copy\n"
        "  python3 automation/chatgpt_codex_loop.py advance --from-clipboard --copy\n"
        "\n"
        "Clipboard-friendly variant:\n"
        "  python3 automation/chatgpt_codex_loop.py save-chatgpt-reply --from-clipboard --copy-prompt\n"
        "  python3 automation/chatgpt_codex_loop.py save-codex-reply --from-clipboard --next-chatgpt --copy\n"
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
    ensure_init_target_is_safe(paths, force=getattr(args, "force", False))
    ensure_loop_dirs(paths)
    state = default_state(goal)
    write_state(paths, state)
    print(json.dumps(state, indent=2))
    if should_log_event(args):
        append_event(
            paths,
            "init",
            "initialized_loop",
            iteration_before=None,
            iteration_after=int(state["iteration"]),
            artifacts={"state_file": str(paths.state_file)},
        )
    return 0


def command_next_chatgpt(_: argparse.Namespace, paths: LoopPaths) -> int:
    state = load_state(paths)
    iteration_before = int(state["iteration"])
    state, request_path, request_text = create_next_chatgpt_request(paths, state)
    sys.stdout.write(request_text)
    if not request_text.endswith("\n"):
        sys.stdout.write("\n")
    if _.copy:
        copy_to_clipboard(request_text)
    if should_log_event(_):
        append_event(
            paths,
            "next-chatgpt",
            "generated_chatgpt_request",
            iteration_before=iteration_before,
            iteration_after=int(state["iteration"]),
            copied_to_clipboard=bool(_.copy),
            artifacts={"chatgpt_request": str(request_path)},
        )
    return 0


def create_next_chatgpt_request(paths: LoopPaths, state: dict) -> tuple[dict, Path, str]:
    request_number = cycle_number(int(state["iteration"]))
    request_text = build_chatgpt_request(state)
    request_path = numbered_path(paths.chatgpt_dir, "request", request_number)
    request_path.write_text(request_text, encoding="utf-8")
    updated_state = update_state(paths, state, latest_chatgpt_request=str(request_path))
    return updated_state, request_path, request_text


def validate_chatgpt_reply_text(reply_text: str, current_request_text: str) -> None:
    if texts_match_or_are_near(reply_text, current_request_text) or looks_like_generated_chatgpt_request(reply_text):
        raise SystemExit(
            "This looks like the generated ChatGPT request for the current cycle, not ChatGPT's reply. "
            "Send the request to ChatGPT first, then save ChatGPT's actual reply including `## CODEX_PROMPT` and `## WHY`."
        )


def validate_codex_reply_text(reply_text: str, current_prompt_text: str, current_request_text: str) -> None:
    if reply_text.lstrip().startswith("## CODEX_PROMPT"):
        raise SystemExit(
            "This looks like a prompt or instruction block, not a Codex result. "
            "Run or paste the saved prompt into Codex first, then copy the actual Codex result and rerun `save-codex-reply`."
        )
    if texts_match_or_are_near(reply_text, current_prompt_text):
        raise SystemExit(
            "This looks identical or near-identical to the current Codex prompt, not Codex's result. "
            "Run or paste that prompt into Codex first, then copy the actual Codex result and rerun `save-codex-reply`."
        )
    if texts_match_or_are_near(reply_text, current_request_text) or looks_like_generated_chatgpt_request(reply_text):
        raise SystemExit(
            "This looks like the generated ChatGPT request, not Codex's result. "
            "Copy the actual Codex output, then rerun `save-codex-reply`."
        )


def command_save_chatgpt_reply(args: argparse.Namespace, paths: LoopPaths) -> int:
    state = load_state(paths)
    iteration_before = int(state["iteration"])
    reply_number = cycle_number(int(state["iteration"]))
    if getattr(args, "copy_prompt", False) and not get_clipboard_copy_command():
        raise SystemExit(
            "No supported clipboard tool found for `save-chatgpt-reply --copy-prompt`. "
            "Re-run without `--copy-prompt` or use `show-codex-prompt` later. "
            "Install one of: clip.exe, pbcopy, wl-copy, xclip, or xsel."
        )
    current_paths = current_cycle_artifact_paths(paths, int(state["iteration"]))
    if not has_current_cycle_artifact(state, "latest_chatgpt_request", current_paths["chatgpt_request"]):
        raise SystemExit(
            "Current cycle ChatGPT request does not exist yet. "
            f"Run `{preferred_next_chatgpt_command()}` first."
        )

    reply_path = current_paths["chatgpt_reply"]
    if reply_path.exists():
        raise SystemExit(
            f"Current cycle ChatGPT reply already exists at {reply_path}. "
            f"Refusing to overwrite it. Next step: run `{preferred_show_codex_prompt_command()}`."
        )

    reply_text = read_required_input(
        "ChatGPT reply",
        args.file,
        from_clipboard=getattr(args, "from_clipboard", False),
    )
    current_request_text = read_optional_text(str(current_paths["chatgpt_request"]))
    validate_chatgpt_reply_text(reply_text, current_request_text)
    prompt_text = extract_codex_prompt(reply_text)

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
    if getattr(args, "copy_prompt", False):
        copy_to_clipboard(prompt_text)
        print("Copied Codex prompt to clipboard.")
    if should_log_event(args):
        append_event(
            paths,
            "save-chatgpt-reply",
            "saved_chatgpt_reply",
            iteration_before=iteration_before,
            iteration_after=iteration_before,
            input_source=input_source_for_args(args.file, getattr(args, "from_clipboard", False)),
            copied_to_clipboard=bool(getattr(args, "copy_prompt", False)),
            artifacts={
                "chatgpt_reply": str(reply_path),
                "codex_prompt": str(prompt_path),
            },
        )
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
    iteration_before = int(state["iteration"])
    reply_number = cycle_number(int(state["iteration"]))
    if getattr(args, "copy", False) and not getattr(args, "next_chatgpt", False):
        raise SystemExit("`save-codex-reply --copy` requires `--next-chatgpt`.")
    if getattr(args, "copy", False) and not get_clipboard_copy_command():
        raise SystemExit(
            "No supported clipboard tool found for `save-codex-reply --next-chatgpt --copy`. "
            "Re-run without `--copy`, or run `next-chatgpt` later. "
            "Install one of: clip.exe, pbcopy, wl-copy, xclip, or xsel."
        )
    current_paths = current_cycle_artifact_paths(paths, int(state["iteration"]))
    if not has_current_cycle_artifact(state, "latest_codex_prompt", current_paths["codex_prompt"]):
        raise SystemExit(
            "Current cycle Codex prompt does not exist yet. "
            f"Run `{preferred_save_chatgpt_reply_command()}` first."
        )

    reply_path = current_paths["codex_reply"]
    if reply_path.exists():
        raise SystemExit(
            f"Current cycle Codex reply already exists at {reply_path}. "
            f"Refusing to overwrite it. Next step: run `{preferred_next_chatgpt_command()}`."
        )

    reply_text = read_required_input(
        "Codex reply",
        args.file,
        from_clipboard=getattr(args, "from_clipboard", False),
    )
    current_prompt_text = read_optional_text(str(current_paths["codex_prompt"]))
    current_request_text = read_optional_text(str(current_paths["chatgpt_request"]))
    validate_codex_reply_text(reply_text, current_prompt_text, current_request_text)
    reply_path.write_text(reply_text, encoding="utf-8")

    state = update_state(
        paths,
        state,
        iteration=reply_number,
        latest_codex_reply=str(reply_path),
    )
    print(reply_path)
    request_path: Path | None = None
    if getattr(args, "next_chatgpt", False):
        _, request_path, request_text = create_next_chatgpt_request(paths, state)
        print(request_path)
        if getattr(args, "copy", False):
            copy_to_clipboard(request_text)
            print("Copied next ChatGPT request to clipboard.")
    if should_log_event(args):
        append_event(
            paths,
            "save-codex-reply",
            "saved_codex_reply_and_generated_next_chatgpt_request" if getattr(args, "next_chatgpt", False) else "saved_codex_reply",
            iteration_before=iteration_before,
            iteration_after=reply_number,
            input_source=input_source_for_args(args.file, getattr(args, "from_clipboard", False)),
            copied_to_clipboard=bool(getattr(args, "copy", False)),
            artifacts=filtered_artifacts(
                codex_reply=str(reply_path),
                chatgpt_request=str(request_path) if request_path else None,
            ),
        )
    return 0


def command_advance(args: argparse.Namespace, paths: LoopPaths) -> int:
    if getattr(args, "json", False):
        return command_advance_json(args, paths)
    if not paths.state_file.exists():
        raise SystemExit("Loop state is missing. Run `init --goal \"...\"` first.")

    state = load_state(paths)
    iteration_before = int(state["iteration"])
    phase, _ = current_cycle_phase(paths, state)
    if phase == "needs_chatgpt_request":
        if getattr(args, "copy", False) and not get_clipboard_copy_command():
            raise SystemExit(
                "No supported clipboard tool found for `advance --copy`. "
                "Re-run without `--copy` or use `next-chatgpt` directly. "
                "Install one of: clip.exe, pbcopy, wl-copy, xclip, or xsel."
            )
        action = "generated_chatgpt_request"
        input_source = "none"
        result = command_next_chatgpt(
            argparse.Namespace(copy=getattr(args, "copy", False), _skip_event_log=True),
            paths,
        )
    elif phase == "needs_chatgpt_reply":
        action = "saved_chatgpt_reply"
        input_source = input_source_for_args(getattr(args, "file", None), getattr(args, "from_clipboard", False))
        result = command_save_chatgpt_reply(
            argparse.Namespace(
                file=getattr(args, "file", None),
                from_clipboard=getattr(args, "from_clipboard", False),
                copy_prompt=getattr(args, "copy", False),
                _skip_event_log=True,
            ),
            paths,
        )
    else:
        if phase != "needs_codex_reply":
            if getattr(args, "copy", False) and not get_clipboard_copy_command():
                raise SystemExit(
                    "No supported clipboard tool found for `advance --copy`. "
                    "Re-run without `--copy` or use `next-chatgpt` directly. "
                    "Install one of: clip.exe, pbcopy, wl-copy, xclip, or xsel."
                )
            action = "generated_chatgpt_request"
            input_source = "none"
            result = command_next_chatgpt(
                argparse.Namespace(copy=getattr(args, "copy", False), _skip_event_log=True),
                paths,
            )
        else:
            action = "saved_codex_reply_and_generated_next_chatgpt_request"
            input_source = input_source_for_args(getattr(args, "file", None), getattr(args, "from_clipboard", False))
            result = command_save_codex_reply(
                argparse.Namespace(
                    file=getattr(args, "file", None),
                    from_clipboard=getattr(args, "from_clipboard", False),
                    next_chatgpt=True,
                    copy=getattr(args, "copy", False),
                    _skip_event_log=True,
                ),
                paths,
            )

    state_after = load_state(paths)
    artifacts = {}
    if action == "generated_chatgpt_request":
        artifacts["chatgpt_request"] = state_after["latest_chatgpt_request"]
    elif action == "saved_chatgpt_reply":
        artifacts["chatgpt_reply"] = state_after["latest_chatgpt_reply"]
        artifacts["codex_prompt"] = state_after["latest_codex_prompt"]
    else:
        artifacts["codex_reply"] = state_after["latest_codex_reply"]
        artifacts["chatgpt_request"] = state_after["latest_chatgpt_request"]

    append_event(
        paths,
        "advance",
        action,
        iteration_before=iteration_before,
        iteration_after=int(state_after["iteration"]),
        input_source=input_source,
        copied_to_clipboard=bool(getattr(args, "copy", False)),
        artifacts=artifacts,
    )
    return result


def command_advance_json(args: argparse.Namespace, paths: LoopPaths) -> int:
    if not paths.state_file.exists():
        raise SystemExit("Loop state is missing. Run `init --goal \"...\"` first.")

    state_before = load_state(paths)
    iteration_before = int(state_before["iteration"])
    phase_before, _ = current_cycle_phase(paths, state_before)
    input_source = "none"
    copied_to_clipboard = bool(getattr(args, "copy", False))

    with redirect_stdout(io.StringIO()):
        if phase_before == "needs_chatgpt_request" or phase_before == "cycle_complete":
            command_next_chatgpt(
                argparse.Namespace(copy=getattr(args, "copy", False), _skip_event_log=True),
                paths,
            )
            action = "generated_chatgpt_request"
            input_source = "none"
        elif phase_before == "needs_chatgpt_reply":
            command_save_chatgpt_reply(
                argparse.Namespace(
                    file=getattr(args, "file", None),
                    from_clipboard=getattr(args, "from_clipboard", False),
                    copy_prompt=getattr(args, "copy", False),
                    _skip_event_log=True,
                ),
                paths,
            )
            action = "saved_chatgpt_reply"
            input_source = input_source_for_args(getattr(args, "file", None), getattr(args, "from_clipboard", False))
        else:
            command_save_codex_reply(
                argparse.Namespace(
                    file=getattr(args, "file", None),
                    from_clipboard=getattr(args, "from_clipboard", False),
                    next_chatgpt=True,
                    copy=getattr(args, "copy", False),
                    _skip_event_log=True,
                ),
                paths,
            )
            action = "saved_codex_reply_and_generated_next_chatgpt_request"
            input_source = input_source_for_args(getattr(args, "file", None), getattr(args, "from_clipboard", False))

    state_after = load_state(paths)
    artifacts: dict[str, str] = {}
    if action == "generated_chatgpt_request":
        artifacts["chatgpt_request"] = state_after["latest_chatgpt_request"]
    elif action == "saved_chatgpt_reply":
        artifacts["chatgpt_reply"] = state_after["latest_chatgpt_reply"]
        artifacts["codex_prompt"] = state_after["latest_codex_prompt"]
    else:
        artifacts["codex_reply"] = state_after["latest_codex_reply"]
        artifacts["chatgpt_request"] = state_after["latest_chatgpt_request"]

    payload = {
        "loop_root": str(paths.loop_dir),
        "root_mode": root_mode(paths),
        "initialized": True,
        "phase_before": phase_before,
        "action": action,
        "iteration_before": iteration_before,
        "iteration_after": int(state_after["iteration"]),
        "input_source": input_source,
        "copied_to_clipboard": copied_to_clipboard,
        "artifacts": artifacts,
        "recommended_next_command": build_guide_payload(paths)["recommended_command"],
    }
    append_event(
        paths,
        "advance",
        action,
        iteration_before=iteration_before,
        iteration_after=int(state_after["iteration"]),
        input_source=input_source,
        copied_to_clipboard=copied_to_clipboard,
        artifacts=artifacts,
    )
    sys.stdout.write(json.dumps(payload, indent=2) + "\n")
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
    if getattr(args, "json", False):
        sys.stdout.write(json.dumps(build_status_payload(paths, state, verbose=args.verbose), indent=2) + "\n")
        return 0
    sys.stdout.write(format_status_output(paths, state, verbose=args.verbose))
    return 0


def command_doctor(_: argparse.Namespace, paths: LoopPaths) -> int:
    if getattr(_, "json", False):
        sys.stdout.write(json.dumps(build_doctor_payload(paths), indent=2) + "\n")
        return 0
    sys.stdout.write(format_doctor_output(paths))
    return 0


def command_guide(_: argparse.Namespace, paths: LoopPaths) -> int:
    if getattr(_, "json", False):
        sys.stdout.write(json.dumps(build_guide_payload(paths), indent=2) + "\n")
        return 0
    sys.stdout.write(format_guide_output(paths))
    return 0


def command_lock_status(args: argparse.Namespace, paths: LoopPaths) -> int:
    payload = build_lock_status_payload(paths)
    if getattr(args, "json", False):
        sys.stdout.write(json.dumps(payload, indent=2) + "\n")
        return 0
    sys.stdout.write(format_lock_status_output(paths))
    return 0


def command_clear_lock(args: argparse.Namespace, paths: LoopPaths) -> int:
    payload = build_clear_lock_payload(paths, force=getattr(args, "force", False))
    if not payload["lock_present"] and not payload["cleared"]:
        if getattr(args, "json", False):
            sys.stdout.write(json.dumps(payload, indent=2) + "\n")
            return 0
        sys.stdout.write(format_clear_lock_output(payload, paths))
        return 0

    if payload["cleared"]:
        if getattr(args, "json", False):
            sys.stdout.write(json.dumps(payload, indent=2) + "\n")
            return 0
        sys.stdout.write(format_clear_lock_output(payload, paths))
        return 0

    raise SystemExit(clear_lock_error_message(payload, paths))


def command_history(args: argparse.Namespace, paths: LoopPaths) -> int:
    if args.limit < 1:
        raise SystemExit("`history --limit` must be >= 1.")
    if getattr(args, "json", False):
        sys.stdout.write(json.dumps(build_history_payload(paths, args.limit), indent=2) + "\n")
        return 0
    sys.stdout.write(format_history_output(paths, args.limit))
    return 0


def command_cycle_example(_: argparse.Namespace, paths: LoopPaths) -> int:
    del paths
    sys.stdout.write(format_cycle_example_output())
    return 0


def command_reset_iteration(args: argparse.Namespace, paths: LoopPaths) -> int:
    state = load_state(paths)
    iteration_before = int(state["iteration"])
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
    if should_log_event(args):
        append_event(
            paths,
            "reset-iteration",
            "reset_iteration",
            iteration_before=iteration_before,
            iteration_after=iteration,
            artifacts=filtered_artifacts(
                chatgpt_request=updated_state["latest_chatgpt_request"] or None,
                chatgpt_reply=updated_state["latest_chatgpt_reply"] or None,
                codex_prompt=updated_state["latest_codex_prompt"] or None,
                codex_reply=updated_state["latest_codex_reply"] or None,
            ),
        )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Manage a repo-local ChatGPT <-> Codex handoff loop."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    init_parser = subparsers.add_parser("init", help="Initialize loop state with a top-level goal.")
    init_parser.add_argument("--goal", required=True, help="Top-level loop goal.")
    init_parser.add_argument(
        "--force",
        action="store_true",
        help="Replace existing loop state or artifacts in the resolved loop root.",
    )
    init_parser.set_defaults(func=command_init)

    next_parser = subparsers.add_parser("next-chatgpt", help="Generate the next ChatGPT request.")
    next_parser.add_argument("--copy", action="store_true", help="Also copy the generated request to the clipboard.")
    next_parser.set_defaults(func=command_next_chatgpt)

    save_chatgpt_parser = subparsers.add_parser(
        "save-chatgpt-reply",
        help="Save a ChatGPT reply and extract the next Codex prompt.",
    )
    save_chatgpt_parser.add_argument("--file", help="Read the ChatGPT reply from a file instead of stdin.")
    save_chatgpt_parser.add_argument(
        "--from-clipboard",
        action="store_true",
        help="Read the ChatGPT reply from the clipboard instead of stdin.",
    )
    save_chatgpt_parser.add_argument(
        "--copy-prompt",
        action="store_true",
        help="Also copy the extracted Codex prompt to the clipboard after saving it.",
    )
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
    save_codex_parser.add_argument(
        "--from-clipboard",
        action="store_true",
        help="Read the Codex reply from the clipboard instead of stdin.",
    )
    save_codex_parser.add_argument(
        "--next-chatgpt",
        action="store_true",
        help="Also generate and save the next ChatGPT request after advancing the iteration.",
    )
    save_codex_parser.add_argument(
        "--copy",
        action="store_true",
        help="When used with `--next-chatgpt`, also copy the new ChatGPT request to the clipboard.",
    )
    save_codex_parser.set_defaults(func=command_save_codex_reply)

    advance_parser = subparsers.add_parser(
        "advance",
        help="Perform the next happy-path loop action for the current phase.",
        description="Perform the next happy-path loop action for the current phase.",
    )
    advance_parser.add_argument("--file", help="Read the current reply from a file instead of stdin when input is needed.")
    advance_parser.add_argument(
        "--from-clipboard",
        action="store_true",
        help="Read the current reply from the clipboard instead of stdin when input is needed.",
    )
    advance_parser.add_argument(
        "--copy",
        action="store_true",
        help="Copy the next generated artifact for the current phase when supported.",
    )
    advance_parser.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON output instead of human-readable text.",
    )
    advance_parser.set_defaults(func=command_advance)

    status_parser = subparsers.add_parser("status", help="Show current loop status.")
    status_parser.add_argument("--verbose", action="store_true", help="Show latest file paths and short previews.")
    status_parser.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON output instead of human-readable text.",
    )
    status_parser.set_defaults(func=command_status)

    doctor_parser = subparsers.add_parser(
        "doctor",
        help="Diagnose loop-state inconsistencies and suggest the safest recovery step.",
        description="Diagnose loop-state inconsistencies and suggest the safest recovery step.",
    )
    doctor_parser.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON output instead of human-readable text.",
    )
    doctor_parser.set_defaults(func=command_doctor)

    guide_parser = subparsers.add_parser(
        "guide",
        help="Print the next happy-path command to run.",
        description="Print the next happy-path command to run.",
    )
    guide_parser.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON output instead of human-readable text.",
    )
    guide_parser.set_defaults(func=command_guide)

    lock_status_parser = subparsers.add_parser(
        "lock-status",
        help="Inspect the current write lock for the resolved loop root.",
        description="Inspect the current write lock for the resolved loop root.",
    )
    lock_status_parser.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON output instead of human-readable text.",
    )
    lock_status_parser.set_defaults(func=command_lock_status)

    clear_lock_parser = subparsers.add_parser(
        "clear-lock",
        help="Manually clear a suspicious write lock for the resolved loop root.",
        description="Manually clear a suspicious write lock for the resolved loop root.",
    )
    clear_lock_parser.add_argument(
        "--force",
        action="store_true",
        help="Actually remove a suspicious or unknown-liveness write lock after explicit confirmation.",
    )
    clear_lock_parser.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON output instead of human-readable text.",
    )
    clear_lock_parser.set_defaults(func=command_clear_lock)

    history_parser = subparsers.add_parser(
        "history",
        help="Show recent successful state-changing loop actions.",
        description="Show recent successful state-changing loop actions.",
    )
    history_parser.add_argument(
        "--limit",
        type=int,
        default=10,
        help="Maximum number of recent events to show.",
    )
    history_parser.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON output instead of human-readable text.",
    )
    history_parser.set_defaults(func=command_history)

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
    paths = default_paths()
    if args.command in WRITE_COMMANDS:
        with acquire_write_lock(paths, args.command):
            return args.func(args, paths)
    return args.func(args, paths)


if __name__ == "__main__":
    raise SystemExit(main())
