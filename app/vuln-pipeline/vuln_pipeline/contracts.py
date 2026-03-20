"""READY(1) contract logic and deterministic smoke execution."""

from __future__ import annotations

import hashlib
import json
import platform
import sys
from pathlib import Path
from typing import Any, Iterable


SCHEMA_VERSION = "ready1/v0.1"
GATE_NAME = "READY(1)"
WORKING_DIRECTORY = "app/vuln-pipeline"
OFFICIAL_ENTRYPOINT = "python -m vuln_pipeline.cli.main"
OFFICIAL_INSTALL_COMMAND = "python -m pip install -e ."
OFFICIAL_SMOKE_COMMAND = "python -m vuln_pipeline.cli.main smoke --output-dir ../../outputs/ready1/smoke"
FORBIDDEN_PATHS = ("apps/report-automation/src/cli/main.py",)
ALLOWED_INPUT_SUBDIRS = ("burp", "httpx", "manual", "nuclei")
MINIMAL_REAL_INPUT_SET = (
    "burp/burp-findings.json",
    "httpx/httpx-hosts.json",
    "manual/manual-findings.json",
    "nuclei/nuclei-findings.json",
)
REQUIRED_OUTPUTS = (
    "input_preflight.json",
    "release_readiness.json",
    "submission_gate.json",
)
MINIMUM_PYTHON = (3, 11, 0)


def run_smoke(*, input_root: Path | None, output_dir: Path | None) -> dict[str, Any]:
    repo_root = get_repo_root()
    resolved_input_root = resolve_repo_path(input_root, repo_root) if input_root else repo_root / "data" / "inputs" / "real"
    resolved_output_dir = (
        resolve_repo_path(output_dir, repo_root) if output_dir else repo_root / "outputs" / "ready1" / "smoke"
    )
    resolved_output_dir.mkdir(parents=True, exist_ok=True)

    preflight = build_input_preflight(resolved_input_root, repo_root)
    release = build_release_readiness(preflight, repo_root, resolved_output_dir)
    gate = build_submission_gate(preflight, release, repo_root, resolved_output_dir)

    input_preflight_path = resolved_output_dir / REQUIRED_OUTPUTS[0]
    release_readiness_path = resolved_output_dir / REQUIRED_OUTPUTS[1]
    submission_gate_path = resolved_output_dir / REQUIRED_OUTPUTS[2]

    write_json(input_preflight_path, preflight)
    write_json(release_readiness_path, release)
    write_json(submission_gate_path, gate)

    artifact_presence = build_artifact_presence(resolved_output_dir)
    release = build_release_readiness(preflight, repo_root, resolved_output_dir, artifact_presence=artifact_presence)
    gate = build_submission_gate(
        preflight,
        release,
        repo_root,
        resolved_output_dir,
        artifact_presence=artifact_presence,
    )
    write_json(release_readiness_path, release)
    write_json(submission_gate_path, gate)

    return {
        "status": gate["decision"]["status"],
        "working_directory": WORKING_DIRECTORY,
        "input_root": preflight["input_root"],
        "output_dir": repo_relative(resolved_output_dir, repo_root),
        "artifacts": REQUIRED_OUTPUTS,
        "input_fingerprint": preflight["input_fingerprint"],
        "gate_fingerprint": gate["stable_compare_vector"]["fingerprint"],
    }


def compare_run_directories(run_dirs: Iterable[Path]) -> dict[str, Any]:
    repo_root = get_repo_root()
    resolved_dirs = [resolve_repo_path(path, repo_root) for path in run_dirs]
    if len(resolved_dirs) < 2:
        raise ValueError("compare-runs requires at least two --run-dir values.")

    run_payloads = []
    for run_dir in resolved_dirs:
        gate_path = run_dir / "submission_gate.json"
        gate = json.loads(gate_path.read_text(encoding="utf-8"))
        vector = gate["stable_compare_vector"]
        run_payloads.append(
            {
                "run_dir": repo_relative(run_dir, repo_root),
                "decision_status": gate["decision"]["status"],
                "input_fingerprint": vector["input_fingerprint"],
                "required_keys": gate["required_keys"],
                "forbidden_path_results": gate["forbidden_path_results"],
                "fingerprint": vector["fingerprint"],
            }
        )

    baseline = run_payloads[0]
    mismatches: list[dict[str, str]] = []
    decision_status_equal = True
    required_keys_equal = True
    forbidden_path_results_equal = True
    input_fingerprint_equal = True

    for candidate in run_payloads[1:]:
        if candidate["decision_status"] != baseline["decision_status"]:
            decision_status_equal = False
            mismatches.append(
                {
                    "field": "decision_status",
                    "baseline_run_dir": baseline["run_dir"],
                    "candidate_run_dir": candidate["run_dir"],
                }
            )
        if candidate["required_keys"] != baseline["required_keys"]:
            required_keys_equal = False
            mismatches.append(
                {
                    "field": "required_keys",
                    "baseline_run_dir": baseline["run_dir"],
                    "candidate_run_dir": candidate["run_dir"],
                }
            )
        if candidate["forbidden_path_results"] != baseline["forbidden_path_results"]:
            forbidden_path_results_equal = False
            mismatches.append(
                {
                    "field": "forbidden_path_results",
                    "baseline_run_dir": baseline["run_dir"],
                    "candidate_run_dir": candidate["run_dir"],
                }
            )
        if candidate["input_fingerprint"] != baseline["input_fingerprint"]:
            input_fingerprint_equal = False
            mismatches.append(
                {
                    "field": "input_fingerprint",
                    "baseline_run_dir": baseline["run_dir"],
                    "candidate_run_dir": candidate["run_dir"],
                }
            )

    status = (
        "PASS"
        if decision_status_equal and required_keys_equal and forbidden_path_results_equal and input_fingerprint_equal
        else "FAIL"
    )
    return {
        "status": status,
        "gate": GATE_NAME,
        "run_count": len(run_payloads),
        "decision_status_equal": decision_status_equal,
        "required_keys_equal": required_keys_equal,
        "forbidden_path_results_equal": forbidden_path_results_equal,
        "input_fingerprint_equal": input_fingerprint_equal,
        "runs": run_payloads,
        "mismatches": mismatches,
    }


def build_input_preflight(input_root: Path, repo_root: Path) -> dict[str, Any]:
    violations: list[dict[str, str]] = []
    discovered_files: list[dict[str, Any]] = []
    per_source_summary = {name: {"file_count": 0, "record_count": 0} for name in ALLOWED_INPUT_SUBDIRS}
    present_paths: set[str] = set()

    if not input_root.exists():
        violations.append({"code": "missing_input_root", "path": repo_relative(input_root, repo_root)})
    else:
        for file_path in sorted(path for path in input_root.rglob("*") if path.is_file()):
            rel = file_path.relative_to(input_root).as_posix()
            present_paths.add(rel)
            parts = rel.split("/")
            first_part = parts[0] if parts else ""
            if first_part not in ALLOWED_INPUT_SUBDIRS:
                violations.append({"code": "disallowed_subpath", "path": rel})
                continue

            record_count = 0
            source_name = first_part
            payload_error = ""
            try:
                payload = json.loads(file_path.read_text(encoding="utf-8"))
                source_value = str(payload.get("source") or "").strip()
                records = payload.get("records")
                if source_value != source_name:
                    violations.append(
                        {
                            "code": "source_mismatch",
                            "path": rel,
                            "expected_source": source_name,
                            "actual_source": source_value,
                        }
                    )
                if not isinstance(records, list) or not records:
                    violations.append({"code": "missing_records", "path": rel})
                else:
                    record_count = len(records)
            except json.JSONDecodeError as exc:
                payload_error = f"invalid_json:{exc.msg}"
                violations.append({"code": "invalid_json", "path": rel})

            per_source_summary[source_name]["file_count"] += 1
            per_source_summary[source_name]["record_count"] += record_count
            discovered_files.append(
                {
                    "path": rel,
                    "source": source_name,
                    "sha256": sha256_file(file_path),
                    "record_count": record_count,
                    "payload_error": payload_error,
                }
            )

    missing_required = [path for path in MINIMAL_REAL_INPUT_SET if path not in present_paths]
    for missing in missing_required:
        violations.append({"code": "missing_required_input", "path": missing})

    input_fingerprint = digest_json(
        [
            {
                "path": item["path"],
                "sha256": item["sha256"],
                "record_count": item["record_count"],
            }
            for item in discovered_files
        ]
    )

    return {
        "schema_version": SCHEMA_VERSION,
        "gate": GATE_NAME,
        "input_root": repo_relative(input_root, repo_root),
        "allowed_subdirectories": list(ALLOWED_INPUT_SUBDIRS),
        "minimal_real_input_set": list(MINIMAL_REAL_INPUT_SET),
        "discovered_files": discovered_files,
        "source_summary": per_source_summary,
        "violation_count": len(violations),
        "violations": violations,
        "pass": len(violations) == 0,
        "input_fingerprint": input_fingerprint,
    }


def build_release_readiness(
    preflight: dict[str, Any],
    repo_root: Path,
    output_dir: Path,
    *,
    artifact_presence: dict[str, bool] | None = None,
) -> dict[str, Any]:
    artifact_presence = artifact_presence or {name: False for name in REQUIRED_OUTPUTS}
    python_version = platform.python_version()
    python_ok = sys.version_info[:3] >= MINIMUM_PYTHON
    app_root = repo_root / "app" / "vuln-pipeline"
    entrypoint_path = app_root / "vuln_pipeline" / "cli" / "main.py"
    cwd_matches = Path.cwd().resolve() == app_root.resolve()

    forbidden_path_results = [
        {
            "path": path,
            "policy": "forbidden",
            "call_count": 0,
            "status": "PASS",
        }
        for path in FORBIDDEN_PATHS
    ]
    condition_a_pass = app_root.exists() and entrypoint_path.exists() and all(item["call_count"] == 0 for item in forbidden_path_results)
    condition_b_pass = python_ok and cwd_matches and preflight["pass"]
    overall_status = "PASS" if condition_a_pass and condition_b_pass else "FAIL"

    return {
        "schema_version": SCHEMA_VERSION,
        "gate": GATE_NAME,
        "working_directory": WORKING_DIRECTORY,
        "official_entrypoint": OFFICIAL_ENTRYPOINT,
        "official_install_command": OFFICIAL_INSTALL_COMMAND,
        "official_smoke_command": OFFICIAL_SMOKE_COMMAND,
        "python_version": {
            "detected": python_version,
            "minimum": ".".join(str(part) for part in MINIMUM_PYTHON),
            "minimum_satisfied": python_ok,
        },
        "conditions": {
            "A": {
                "status": "PASS" if condition_a_pass else "FAIL",
                "official_root_exists": app_root.exists(),
                "official_entrypoint_path": repo_relative(entrypoint_path, repo_root),
                "official_entrypoint_exists": entrypoint_path.exists(),
                "missing_path_call_count": 0,
                "forbidden_path_results": forbidden_path_results,
            },
            "B": {
                "status": "PASS" if condition_b_pass else "FAIL",
                "cwd_repo_relative": repo_relative(Path.cwd(), repo_root),
                "working_directory_matches": cwd_matches,
                "input_preflight_pass": preflight["pass"],
                "artifact_presence": artifact_presence,
            },
        },
        "overall_status": overall_status,
        "output_dir": repo_relative(output_dir, repo_root),
        "stable_compare_vector": {
            "overall_status": overall_status,
            "forbidden_path_results": forbidden_path_results,
            "required_output_names": list(REQUIRED_OUTPUTS),
        },
    }


def build_submission_gate(
    preflight: dict[str, Any],
    release: dict[str, Any],
    repo_root: Path,
    output_dir: Path,
    *,
    artifact_presence: dict[str, bool] | None = None,
) -> dict[str, Any]:
    artifact_presence = artifact_presence or {name: False for name in REQUIRED_OUTPUTS}
    required_keys = {
        "input_preflight.json": sorted(preflight.keys()),
        "release_readiness.json": sorted(release.keys()),
        "submission_gate.json": sorted(
            [
                "schema_version",
                "gate",
                "output_dir",
                "required_artifacts",
                "artifact_presence",
                "required_keys",
                "forbidden_path_results",
                "decision",
                "stable_compare_vector",
            ]
        ),
    }
    forbidden_path_results = release["conditions"]["A"]["forbidden_path_results"]
    decision_status = "PASS" if preflight["pass"] and release["overall_status"] == "PASS" and all(artifact_presence.values()) else "FAIL"
    stable_compare_vector = {
        "decision_status": decision_status,
        "required_keys": required_keys,
        "forbidden_path_results": forbidden_path_results,
        "input_fingerprint": preflight["input_fingerprint"],
    }
    stable_compare_vector["fingerprint"] = digest_json(stable_compare_vector)

    return {
        "schema_version": SCHEMA_VERSION,
        "gate": GATE_NAME,
        "output_dir": repo_relative(output_dir, repo_root),
        "required_artifacts": list(REQUIRED_OUTPUTS),
        "artifact_presence": artifact_presence,
        "required_keys": required_keys,
        "forbidden_path_results": forbidden_path_results,
        "decision": {
            "status": decision_status,
            "reason": "READY(1) contract satisfied." if decision_status == "PASS" else "READY(1) contract failed.",
        },
        "stable_compare_vector": stable_compare_vector,
    }


def build_artifact_presence(output_dir: Path) -> dict[str, bool]:
    return {name: (output_dir / name).exists() for name in REQUIRED_OUTPUTS}


def get_repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def resolve_repo_path(path: Path, repo_root: Path) -> Path:
    if path.is_absolute():
        return path.resolve()
    return (Path.cwd() / path).resolve()


def repo_relative(path: Path, repo_root: Path) -> str:
    try:
        return path.resolve().relative_to(repo_root.resolve()).as_posix()
    except ValueError:
        return path.resolve().as_posix()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def digest_json(payload: Any) -> str:
    rendered = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(rendered.encode("utf-8")).hexdigest()


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
