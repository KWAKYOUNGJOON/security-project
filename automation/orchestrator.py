import subprocess
import sys
from pathlib import Path

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

if __name__ == "__main__":
    max_iterations = 3
    read_only_mode = READ_ONLY_MODE
    args = sys.argv[1:]

    if "--write" in args:
        read_only_mode = False
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

    if read_only_mode:
        print("=== MODE: READ_ONLY ===")
    else:
        print("=== MODE: WRITE ===")
        print("WRITE mode is enabled. File modifications are allowed.")
    print(f"Max iterations: {max_iterations}")
    print()

    task = ""
    if TASK_FILE.exists():
        task = TASK_FILE.read_text(encoding="utf-8").strip()
    if not task:
        task = DEFAULT_TASK
    task = enforce_read_only_instruction(task, read_only_mode)

    previous_task = None

    for iteration in range(1, max_iterations + 1):
        print(f"=== ITERATION {iteration} TASK ===")
        print(task)
        print()

        git_status_before = get_git_status()
        git_diff_names_before = get_git_diff_names()
        save_git_status(f"loop{iteration}", "before", git_status_before)
        save_git_diff_names(f"loop{iteration}", "before", git_diff_names_before)

        result = run_codex(task)
        save_result(f"loop{iteration}", result)
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

        if changed_files:
            if read_only_mode:
                print("\nWarning: files were modified unexpectedly in read-only mode.")
                break
            print("\nFile modifications were detected in WRITE mode. Continuing.")

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
        task = enforce_read_only_instruction(task, read_only_mode)

        if task.strip() == previous_task.strip():
            print("\nStopping: generated task matched the previous task.")
            break

    print("\nSaved outputs to automation/runs/")
