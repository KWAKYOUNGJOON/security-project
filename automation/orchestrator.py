import json
import subprocess
import sys
from pathlib import Path
from pathlib import PurePosixPath
import shutil

BASE_DIR = Path(__file__).resolve().parent
OUTPUT_DIR = BASE_DIR / "runs"
OUTPUT_DIR.mkdir(exist_ok=True)
TASK_FILE = BASE_DIR / "task.txt"
READ_ONLY_MODE = True

READ_ONLY_INSTRUCTION = "Do not modify any files."
DEFAULT_TASK = "Analyze this repository and explain what this project does."
FOLLOW_UP_INSTRUCTION = (
    "Based on the previous output, suggest one small next action to improve this repository."
)
ALLOWLIST_VIOLATION_RETURN_CODE = -3

def sanitize_repo_relative_path(path: str) -> str | None:
    if not isinstance(path, str):
        return None
    raw_path = path.strip()
    if not raw_path:
        return None

    posix_path = raw_path.replace("\\", "/")
    candidate = PurePosixPath(posix_path)
    if candidate.is_absolute():
        return None

    normalized_parts = []
    for part in candidate.parts:
        if part in {"", "."}:
            continue
        if part == "..":
            if not normalized_parts:
                return None
            normalized_parts.pop()
            continue
        normalized_parts.append(part)

    if not normalized_parts:
        return None
    return PurePosixPath(*normalized_parts).as_posix()

def sanitize_allowlist(paths: list[str]) -> list[str]:
    sanitized_paths = []
    seen = set()
    for path in paths:
        sanitized_path = sanitize_repo_relative_path(path)
        if not sanitized_path or sanitized_path in seen:
            continue
        seen.add(sanitized_path)
        sanitized_paths.append(sanitized_path)
    return sanitized_paths

def apply_operator_scope(
    requested_allowlist: list[str],
    operator_allowlist: list[str],
) -> list[str]:
    sanitized_allowlist = sanitize_allowlist(requested_allowlist)
    if not operator_allowlist:
        return sanitized_allowlist
    operator_scope = set(operator_allowlist)
    return [path for path in sanitized_allowlist if path in operator_scope]

def get_safe_repo_path(path: str) -> Path | None:
    sanitized_path = sanitize_repo_relative_path(path)
    if not sanitized_path:
        return None

    repo_root = BASE_DIR.parent.resolve()
    candidate = (repo_root / sanitized_path).resolve(strict=False)
    if candidate != repo_root and repo_root not in candidate.parents:
        return None
    return candidate

def get_disallowed_changed_files(
    changed_files: list[str],
    iteration_allow_change_paths: list[str],
    operator_scope_active: bool,
) -> list[str]:
    if not changed_files:
        return []
    if not operator_scope_active and not iteration_allow_change_paths:
        return []
    allowed_paths = set(iteration_allow_change_paths)
    return [path for path in changed_files if path not in allowed_paths]

def run_codex(task: str, timeout: int = 180) -> dict:
    try:
        result = subprocess.run(
            ["codex", "exec", task],
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return {
            "success": result.returncode == 0,
            "returncode": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
        }
    except subprocess.TimeoutExpired as e:
        return {
            "success": False,
            "returncode": -1,
            "stdout": e.stdout or "",
            "stderr": f"TimeoutExpired: exceeded {timeout} seconds\n{e.stderr or ''}",
        }
    except Exception as e:
        return {
            "success": False,
            "returncode": -2,
            "stdout": "",
            "stderr": f"Exception: {str(e)}",
        }

def save_result(prefix: str, result: dict) -> None:
    (OUTPUT_DIR / f"{prefix}_stdout.txt").write_text(result["stdout"], encoding="utf-8")
    (OUTPUT_DIR / f"{prefix}_stderr.txt").write_text(result["stderr"], encoding="utf-8")
    (OUTPUT_DIR / f"{prefix}_status.txt").write_text(
        f"success={result['success']}\nreturncode={result['returncode']}\n",
        encoding="utf-8"
    )

def enforce_read_only_instruction(task: str, read_only_mode: bool) -> str:
    task = task.strip()
    if read_only_mode and READ_ONLY_INSTRUCTION not in task:
        if task:
            task = f"{task} {READ_ONLY_INSTRUCTION}"
        else:
            task = READ_ONLY_INSTRUCTION
    return task

def get_git_status() -> str:
    result = subprocess.run(
        ["git", "status", "--short", "--untracked-files=all"],
        capture_output=True,
        text=True,
        cwd=BASE_DIR.parent,
    )
    return result.stdout

def get_git_diff_names() -> str:
    result = subprocess.run(
        ["git", "diff", "--name-only"],
        capture_output=True,
        text=True,
        cwd=BASE_DIR.parent,
    )
    return result.stdout

def save_git_status(prefix: str, when: str, status: str) -> None:
    (OUTPUT_DIR / f"{prefix}_git_status_{when}.txt").write_text(status, encoding="utf-8")

def save_git_diff_names(prefix: str, when: str, diff_names: str) -> None:
    (OUTPUT_DIR / f"{prefix}_git_diff_names_{when}.txt").write_text(diff_names, encoding="utf-8")

def parse_git_status_files(status: str) -> set[str]:
    files = set()
    for line in status.splitlines():
        if not line:
            continue
        path = line[3:]
        if " -> " in path:
            path = path.split(" -> ", 1)[1]
        files.add(path)
    return files

def parse_git_diff_name_files(diff_names: str) -> set[str]:
    return {line for line in diff_names.splitlines() if line}

def get_changed_files_for_iteration(
    git_status_before: str,
    git_status_after: str,
    git_diff_names_before: str,
    git_diff_names_after: str,
) -> list[str]:
    before_files = parse_git_status_files(git_status_before) | parse_git_diff_name_files(git_diff_names_before)
    after_files = parse_git_status_files(git_status_after) | parse_git_diff_name_files(git_diff_names_after)
    return sorted(after_files - before_files)

def save_changed_files(prefix: str, changed_files: list[str]) -> None:
    content = "\n".join(changed_files)
    if changed_files:
        content += "\n"
    (OUTPUT_DIR / f"{prefix}_changed_files.txt").write_text(content, encoding="utf-8")

def save_text_output(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")

def save_summary(
    prefix: str,
    mode: str,
    iteration: int,
    max_iterations: int,
    task: str,
    result: dict,
    changed_files: list[str],
    allowlist: list[str],
    rollback_performed: bool,
    rolled_back_files: list[str],
    read_only_mode: bool,
) -> None:
    summary = {
        "mode": mode,
        "iteration": iteration,
        "max_iterations": max_iterations,
        "task": task,
        "success": result["success"],
        "returncode": result["returncode"],
        "changed_files": changed_files,
        "allowlist": allowlist,
        "rollback_performed": rollback_performed,
        "rolled_back_files": rolled_back_files,
        "read_only_mode": read_only_mode,
    }
    (OUTPUT_DIR / f"{prefix}_summary.json").write_text(
        json.dumps(summary, indent=2) + "\n",
        encoding="utf-8",
    )

def build_planner_task(goal: str) -> str:
    return (
        "Convert the following top-level goal into a structured execution plan for a repository automation loop. "
        "Respond with valid JSON only. Do not modify any files.\n\n"
        "Required JSON fields:\n"
        "- goal\n"
        "- should_execute\n"
        "- execution_mode\n"
        "- execution_task\n"
        "- recommended_allowlist\n"
        "- reason\n\n"
        "Rules:\n"
        "- Output JSON only\n"
        "- execution_mode must be either READ_ONLY or WRITE\n"
        "- recommended_allowlist must be a JSON array of repository-relative paths\n"
        '- If should_execute is false, execution_task must be ""\n'
        "- Keep the plan conservative and safe\n"
        "- Planner must not modify files\n\n"
        "Top-level goal:\n"
        f"{goal}\n"
    )

def normalize_plan_data(goal: str, raw_output: str) -> dict:
    fallback = {
        "goal": goal,
        "should_execute": True,
        "execution_mode": "READ_ONLY",
        "execution_task": goal,
        "recommended_allowlist": [],
        "reason": "Planner did not return valid JSON only; falling back to the original goal.",
    }

    try:
        data = json.loads(raw_output.strip())
    except json.JSONDecodeError:
        return fallback

    if not isinstance(data, dict):
        return fallback

    execution_mode = data.get("execution_mode", "READ_ONLY")
    if execution_mode not in {"READ_ONLY", "WRITE"}:
        execution_mode = "READ_ONLY"

    recommended_allowlist = data.get("recommended_allowlist", [])
    if not isinstance(recommended_allowlist, list):
        recommended_allowlist = []
    recommended_allowlist = sanitize_allowlist([path for path in recommended_allowlist if isinstance(path, str)])

    should_execute = bool(data.get("should_execute", False))
    execution_task = data.get("execution_task", "")
    if not isinstance(execution_task, str):
        execution_task = ""
    if not should_execute:
        execution_task = ""
    elif not execution_task.strip():
        execution_task = goal

    reason = data.get("reason", "")
    if not isinstance(reason, str):
        reason = str(reason)

    planned_goal = data.get("goal", goal)
    if not isinstance(planned_goal, str) or not planned_goal.strip():
        planned_goal = goal

    return {
        "goal": planned_goal,
        "should_execute": should_execute,
        "execution_mode": execution_mode,
        "execution_task": execution_task,
        "recommended_allowlist": recommended_allowlist,
        "reason": reason,
    }

def run_planner(goal: str, top_level_write_enabled: bool, operator_allowlist: list[str]) -> dict:
    plan_raw_path = OUTPUT_DIR / "plan_raw.txt"
    plan_json_path = OUTPUT_DIR / "plan.json"
    plan_task_path = OUTPUT_DIR / "plan_task.txt"

    planner_task = build_planner_task(goal)
    planner_result = run_codex(planner_task)
    raw_output = planner_result["stdout"]
    save_text_output(plan_raw_path, raw_output)

    plan_data = normalize_plan_data(goal, raw_output)
    plan_data["recommended_allowlist"] = apply_operator_scope(
        plan_data["recommended_allowlist"],
        operator_allowlist,
    )
    if plan_data["execution_mode"] == "WRITE" and not top_level_write_enabled:
        print("PLANNER: requested WRITE, but top-level run is not in --write mode. Downgrading to READ_ONLY.")
        plan_data["execution_mode"] = "READ_ONLY"

    save_text_output(plan_json_path, json.dumps(plan_data, indent=2) + "\n")
    save_text_output(plan_task_path, plan_data["execution_task"])
    return plan_data

def build_reviewer_task(summary_path: Path) -> str:
    summary_text = summary_path.read_text(encoding="utf-8")
    return (
        "Review the following iteration summary JSON and respond with valid JSON only. "
        "Do not modify any files.\n\n"
        "Required JSON fields:\n"
        "- iteration\n"
        "- should_continue\n"
        "- outcome\n"
        "- reason\n"
        "- next_mode\n"
        "- next_task\n"
        "- recommended_allowlist\n\n"
        "Rules:\n"
        "- Output JSON only\n"
        "- next_mode must be either READ_ONLY or WRITE\n"
        "- recommended_allowlist must be a JSON array of repository-relative paths\n"
        "- If the summary shows read_only_mode=true and success=true and iteration is less than max_iterations, "
        "normally propose one concrete non-empty next_task for continued analysis and set should_continue=true\n"
        '- If no next task is needed, next_task must be ""\n\n'
        f"Summary file: {summary_path.relative_to(BASE_DIR.parent)}\n"
        "Summary JSON:\n"
        f"{summary_text}"
    )

def normalize_review_data(iteration: int, raw_output: str) -> dict:
    fallback = {
        "iteration": iteration,
        "should_continue": False,
        "outcome": "invalid_reviewer_output",
        "reason": "Reviewer did not return valid JSON only.",
        "next_mode": "READ_ONLY",
        "next_task": "",
        "recommended_allowlist": [],
    }

    try:
        data = json.loads(raw_output.strip())
    except json.JSONDecodeError:
        return fallback

    if not isinstance(data, dict):
        return fallback

    next_mode = data.get("next_mode", "READ_ONLY")
    if next_mode not in {"READ_ONLY", "WRITE"}:
        next_mode = "READ_ONLY"

    recommended_allowlist = data.get("recommended_allowlist", [])
    if not isinstance(recommended_allowlist, list):
        recommended_allowlist = []
    recommended_allowlist = sanitize_allowlist([path for path in recommended_allowlist if isinstance(path, str)])

    next_task = data.get("next_task", "")
    if not isinstance(next_task, str):
        next_task = ""

    reason = data.get("reason", "")
    if not isinstance(reason, str):
        reason = str(reason)

    outcome = data.get("outcome", "")
    if not isinstance(outcome, str):
        outcome = str(outcome)

    return {
        "iteration": iteration,
        "should_continue": bool(data.get("should_continue", False)),
        "outcome": outcome,
        "reason": reason,
        "next_mode": next_mode,
        "next_task": next_task,
        "recommended_allowlist": recommended_allowlist,
    }

def run_reviewer(prefix: str, iteration: int, operator_allowlist: list[str]) -> dict:
    summary_path = OUTPUT_DIR / f"{prefix}_summary.json"
    review_raw_path = OUTPUT_DIR / f"{prefix}_review_raw.txt"
    review_json_path = OUTPUT_DIR / f"{prefix}_review.json"
    next_task_path = OUTPUT_DIR / f"{prefix}_next_task.txt"

    reviewer_task = build_reviewer_task(summary_path)
    reviewer_result = run_codex(reviewer_task)
    raw_output = reviewer_result["stdout"]
    save_text_output(review_raw_path, raw_output)

    review_data = normalize_review_data(iteration, raw_output)
    review_data["recommended_allowlist"] = apply_operator_scope(
        review_data["recommended_allowlist"],
        operator_allowlist,
    )
    save_text_output(review_json_path, json.dumps(review_data, indent=2) + "\n")
    save_text_output(next_task_path, review_data["next_task"])
    return review_data

def parse_allow_change_args(args: list[str]) -> list[str]:
    allowlist = []
    index = 0
    while index < len(args):
        if args[index] == "--allow-change":
            try:
                allowlist.append(args[index + 1])
            except IndexError:
                print("Invalid value for --allow-change. Expected a repository-relative path.")
                sys.exit(1)
            index += 2
            continue
        index += 1
    return sanitize_allowlist(allowlist)

def is_tracked_file(path: str) -> bool:
    result = subprocess.run(
        ["git", "ls-files", "--error-unmatch", "--", path],
        capture_output=True,
        text=True,
        cwd=BASE_DIR.parent,
    )
    return result.returncode == 0

def rollback_disallowed_changes(disallowed_files: list[str]) -> tuple[list[str], list[str]]:
    rolled_back_files = []
    failed_rollbacks = []

    for path in disallowed_files:
        file_path = get_safe_repo_path(path)
        if file_path is None:
            failed_rollbacks.append(f"{path}: rollback skipped because the path is outside the repository root or invalid")
            continue
        try:
            if is_tracked_file(path):
                result = subprocess.run(
                    ["git", "restore", "--source=HEAD", "--staged", "--worktree", "--", path],
                    capture_output=True,
                    text=True,
                    cwd=BASE_DIR.parent,
                )
                if result.returncode != 0:
                    message = result.stderr.strip() or result.stdout.strip() or "git restore failed"
                    failed_rollbacks.append(f"{path}: {message}")
                    continue
            else:
                if file_path.is_dir():
                    shutil.rmtree(file_path)
                elif file_path.exists() or file_path.is_symlink():
                    file_path.unlink()
            rolled_back_files.append(path)
        except Exception as exc:
            failed_rollbacks.append(f"{path}: {exc}")

    return rolled_back_files, failed_rollbacks

if __name__ == "__main__":
    max_iterations = 3
    args = sys.argv[1:]
    autopilot_enabled = "--autopilot" in args
    top_level_write_enabled = "--write" in args
    current_read_only_mode = not top_level_write_enabled if top_level_write_enabled else READ_ONLY_MODE
    operator_allow_change_paths = parse_allow_change_args(args)
    current_allow_change_paths = operator_allow_change_paths[:]

    if "--max-iterations" in args:
        index = args.index("--max-iterations")
        try:
            max_iterations = int(args[index + 1])
        except (IndexError, ValueError):
            print("Invalid value for --max-iterations. Expected an integer.")
            sys.exit(1)
        if max_iterations < 1:
            print("Invalid value for --max-iterations. Expected an integer >= 1.")
            sys.exit(1)

    if current_read_only_mode:
        print("=== MODE: READ_ONLY ===")
    else:
        print("=== MODE: WRITE ===")
        print("WRITE mode is enabled. File modifications are allowed.")
        if current_allow_change_paths:
            print("Active allowlist:")
            for path in current_allow_change_paths:
                print(path)
    print(f"Max iterations: {max_iterations}")
    print()

    goal = ""
    if TASK_FILE.exists():
        goal = TASK_FILE.read_text(encoding="utf-8").strip()
    if not goal:
        goal = DEFAULT_TASK

    print("=== PLANNER GOAL ===")
    print(goal)
    print()

    plan_data = run_planner(goal, top_level_write_enabled, operator_allow_change_paths)

    print("=== PLAN JSON ===")
    print(json.dumps(plan_data, indent=2))
    print()

    if not plan_data["should_execute"]:
        print("PLANNER: should_execute is false. Stopping cleanly before iteration 1.")
        print("\nSaved outputs to automation/runs/")
        sys.exit(0)

    current_read_only_mode = plan_data["execution_mode"] == "READ_ONLY"
    current_allow_change_paths = plan_data["recommended_allowlist"][:]
    task = enforce_read_only_instruction(plan_data["execution_task"], current_read_only_mode)

    previous_task = None

    for iteration in range(1, max_iterations + 1):
        iteration_read_only_mode = current_read_only_mode
        iteration_allow_change_paths = current_allow_change_paths[:]
        iteration_mode = "READ_ONLY" if iteration_read_only_mode else "WRITE"

        print(f"=== ITERATION {iteration} TASK ===")
        print(task)
        print()

        git_status_before = get_git_status()
        git_diff_names_before = get_git_diff_names()
        save_git_status(f"loop{iteration}", "before", git_status_before)
        save_git_diff_names(f"loop{iteration}", "before", git_diff_names_before)

        result = run_codex(task)
        git_status_after = get_git_status()
        git_diff_names_after = get_git_diff_names()
        save_git_status(f"loop{iteration}", "after", git_status_after)
        save_git_diff_names(f"loop{iteration}", "after", git_diff_names_after)
        changed_files = get_changed_files_for_iteration(
            git_status_before,
            git_status_after,
            git_diff_names_before,
            git_diff_names_after,
        )
        save_changed_files(f"loop{iteration}", changed_files)

        rolled_back_files = []
        failed_rollbacks = []
        disallowed_files = []

        if changed_files and iteration_read_only_mode:
            print(f"success: {result['success']}")
            print(f"returncode: {result['returncode']}\n")

            print(f"=== ITERATION {iteration} STDOUT ===")
            print(result["stdout"] or "(empty)")

            print(f"\n=== ITERATION {iteration} STDERR ===")
            print(result["stderr"] or "(empty)")

            print("\nChanged in this iteration:")
            print("\n".join(changed_files))
            save_result(f"loop{iteration}", result)
            save_summary(
                f"loop{iteration}",
                iteration_mode,
                iteration,
                max_iterations,
                task,
                result,
                changed_files,
                iteration_allow_change_paths,
                False,
                [],
                iteration_read_only_mode,
            )
            review_data = run_reviewer(f"loop{iteration}", iteration, operator_allow_change_paths)
            print("\nReviewer JSON:")
            print(json.dumps(review_data, indent=2))
            print("\nWarning: files were modified unexpectedly in read-only mode.")
            break

        if changed_files and not iteration_read_only_mode:
            disallowed_files = get_disallowed_changed_files(
                changed_files,
                iteration_allow_change_paths,
                bool(operator_allow_change_paths),
            )
            if disallowed_files:
                print("\nError: changes outside the allowed write scope were detected.")
                print("Disallowed changed files:")
                print("\n".join(disallowed_files))
                rolled_back_files, failed_rollbacks = rollback_disallowed_changes(disallowed_files)
                result["success"] = False
                result["returncode"] = ALLOWLIST_VIOLATION_RETURN_CODE

        save_result(f"loop{iteration}", result)
        save_summary(
            f"loop{iteration}",
            iteration_mode,
            iteration,
            max_iterations,
            task,
            result,
            changed_files,
            iteration_allow_change_paths,
            bool(rolled_back_files),
            rolled_back_files,
            iteration_read_only_mode,
        )
        review_data = run_reviewer(f"loop{iteration}", iteration, operator_allow_change_paths)

        print(f"success: {result['success']}")
        print(f"returncode: {result['returncode']}\n")

        print(f"=== ITERATION {iteration} STDOUT ===")
        print(result["stdout"] or "(empty)")

        print(f"\n=== ITERATION {iteration} STDERR ===")
        print(result["stderr"] or "(empty)")

        print("\nChanged in this iteration:")
        if changed_files:
            print("\n".join(changed_files))
        else:
            print("(none)")

        print("\nReviewer JSON:")
        print(json.dumps(review_data, indent=2))

        if disallowed_files:
            print("\nRolled back disallowed changes:")
            if rolled_back_files:
                print("\n".join(rolled_back_files))
            else:
                print("(none)")
            if failed_rollbacks:
                print("\nRollback failed for:")
                print("\n".join(failed_rollbacks))
            break

        if changed_files and not iteration_read_only_mode:
            print("\nFile modifications were detected in WRITE mode. Continuing.")

        if autopilot_enabled:
            next_task = review_data["next_task"].strip()
            if review_data["should_continue"] and next_task:
                next_mode = review_data["next_mode"]
                if next_mode == "WRITE" and not top_level_write_enabled:
                    print("\nAUTOPILOT: reviewer requested WRITE, but top-level run is not in --write mode. Downgrading to READ_ONLY.")
                    next_mode = "READ_ONLY"
                current_read_only_mode = next_mode == "READ_ONLY"
                current_allow_change_paths = review_data["recommended_allowlist"][:]
                previous_task = task
                task = enforce_read_only_instruction(next_task, current_read_only_mode)
                print("\nAUTOPILOT: using reviewer next_task for the next iteration")
                if not current_read_only_mode and current_allow_change_paths:
                    print("AUTOPILOT allowlist:")
                    print("\n".join(current_allow_change_paths))
                if task.strip() == previous_task.strip():
                    print("\nStopping: generated task matched the previous task.")
                    break
                continue
            print("\nAUTOPILOT: reviewer did not propose a usable next_task. Stopping cleanly.")
            break

        if not result["success"]:
            print("\nStopping: Codex returned success=False.")
            break

        stdout = result["stdout"].strip()
        if not stdout:
            print("\nStopping: stdout was empty.")
            break

        previous_task = task
        task = (
            "Previous stdout:\n"
            f"{stdout}\n\n"
            "Previous stderr:\n"
            f"{result['stderr'].strip() or '(empty)'}\n\n"
            f"{FOLLOW_UP_INSTRUCTION}"
        )
        task = enforce_read_only_instruction(task, iteration_read_only_mode)

        if task.strip() == previous_task.strip():
            print("\nStopping: generated task matched the previous task.")
            break

    print("\nSaved outputs to automation/runs/")
