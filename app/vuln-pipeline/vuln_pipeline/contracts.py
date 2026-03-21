"""READY contract logic and deterministic smoke execution."""

from __future__ import annotations

import hashlib
import json
import platform
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


SCHEMA_VERSION = "ready-contract/v1"
GATE_NAME = "READY(1)"
WORKING_DIRECTORY = "app/vuln-pipeline"
OFFICIAL_ENTRYPOINT = "python -m vuln_pipeline.cli.main"
OFFICIAL_ENVIRONMENT_PREPARATION = (
    "cd app/vuln-pipeline",
    "python -m pip install -e .",
)
OFFICIAL_SMOKE_COMMAND = "python -m vuln_pipeline.cli.main smoke --run-id <run_id>"
OFFICIAL_TEST_COMMAND = "python -m pytest -q -m must_pass tests/test_fixture_smoke_e2e.py"
RUN_ID_REGEX = r"^run-\d{8}T\d{6}Z$"
RUN_ID_PATTERN = re.compile(RUN_ID_REGEX)
REAL_INPUT_SCHEMA = (
    {
        "provider": "burp",
        "required_root": "data/inputs/real/burp",
        "relative_path": "burp/burp-findings.json",
        "repo_relative_path": "data/inputs/real/burp/burp-findings.json",
        "why_required": "Canonical Burp findings input consumed by the READY smoke flow.",
    },
    {
        "provider": "nuclei",
        "required_root": "data/inputs/real/nuclei",
        "relative_path": "nuclei/nuclei-findings.json",
        "repo_relative_path": "data/inputs/real/nuclei/nuclei-findings.json",
        "why_required": "Canonical Nuclei findings input consumed by the READY smoke flow.",
    },
    {
        "provider": "httpx",
        "required_root": "data/inputs/real/httpx",
        "relative_path": "httpx/httpx-hosts.json",
        "repo_relative_path": "data/inputs/real/httpx/httpx-hosts.json",
        "why_required": "Canonical HTTPX host inventory input consumed by the READY smoke flow.",
    },
    {
        "provider": "manual",
        "required_root": "data/inputs/real/manual",
        "relative_path": "manual/manual-findings.json",
        "repo_relative_path": "data/inputs/real/manual/manual-findings.json",
        "why_required": "Canonical manually reviewed findings input consumed by the READY smoke flow.",
    },
)
REAL_INPUT_SUBDIRS = tuple(item["provider"] for item in REAL_INPUT_SCHEMA)
REQUIRED_REAL_INPUT_FILES = tuple(item["relative_path"] for item in REAL_INPUT_SCHEMA)
REQUIRED_ARTIFACTS = (
    "input_preflight.json",
    "release_readiness.json",
    "submission_gate.json",
)
FORBIDDEN_PATH_RULES = (
    {
        "path": "apps/report-automation/src/cli/main.py",
        "evidence_root": "apps/report-automation",
    },
)
COMPARE_EXCLUDED_FIELDS = ("generated_at", "duration_ms", "temp path", "host/user 정보")
PLACEHOLDER_NAMES = {"README.md", ".gitkeep", ".keep"}
REQUIRED_PYTHON_MAJOR_MINOR = (3, 11)


def run_smoke(
    *,
    run_id: str,
    mode: str,
    input_root: Path | None,
    output_dir: Path | None,
) -> dict[str, Any]:
    repo_root = get_repo_root()
    resolved_input_root = resolve_repo_path(input_root, repo_root) if input_root else canonical_input_root(repo_root)
    resolved_output_dir = resolve_repo_path(output_dir, repo_root) if output_dir else canonical_run_dir(repo_root, run_id)
    resolved_output_dir.mkdir(parents=True, exist_ok=True)

    preflight = build_input_preflight(
        run_id=run_id,
        requested_mode=mode,
        input_root=resolved_input_root,
        repo_root=repo_root,
    )
    release = build_release_readiness(
        run_id=run_id,
        preflight=preflight,
        repo_root=repo_root,
        input_root=resolved_input_root,
        output_dir=resolved_output_dir,
    )

    input_preflight_path = resolved_output_dir / REQUIRED_ARTIFACTS[0]
    release_readiness_path = resolved_output_dir / REQUIRED_ARTIFACTS[1]
    submission_gate_path = resolved_output_dir / REQUIRED_ARTIFACTS[2]

    write_json(input_preflight_path, preflight)
    write_json(release_readiness_path, release)

    artifact_presence = {name: True for name in REQUIRED_ARTIFACTS}
    release = build_release_readiness(
        run_id=run_id,
        preflight=preflight,
        repo_root=repo_root,
        input_root=resolved_input_root,
        output_dir=resolved_output_dir,
        artifact_presence=artifact_presence,
    )
    gate = build_submission_gate(
        run_id=run_id,
        preflight=preflight,
        release=release,
        repo_root=repo_root,
        output_dir=resolved_output_dir,
        artifact_presence=artifact_presence,
    )

    write_json(release_readiness_path, release)
    write_json(submission_gate_path, gate)

    return {
        "status": gate["decision"]["status"],
        "run_id": run_id,
        "mode": preflight["effective_mode"],
        "input_root": preflight["input_root"],
        "run_dir": repo_relative(resolved_output_dir, repo_root),
        "artifacts": list(REQUIRED_ARTIFACTS),
        "reasons": gate["decision"]["reasons"],
        "input_fingerprint": preflight["input_fingerprint"],
        "gate_fingerprint": gate["stable_compare_vector"]["fingerprint"],
    }


def compare_run_directories(run_dirs: Iterable[Path]) -> dict[str, Any]:
    repo_root = get_repo_root()
    resolved_dirs = [resolve_repo_path(path, repo_root) for path in run_dirs]
    if not 2 <= len(resolved_dirs) <= 3:
        raise ValueError("compare-runs requires two or three --run-dir values.")

    runs: list[dict[str, Any]] = []
    for run_dir in resolved_dirs:
        input_preflight = json.loads((run_dir / REQUIRED_ARTIFACTS[0]).read_text(encoding="utf-8"))
        gate = json.loads((run_dir / REQUIRED_ARTIFACTS[2]).read_text(encoding="utf-8"))
        vector = gate["stable_compare_vector"]
        runs.append(
            {
                "run_dir": repo_relative(run_dir, repo_root),
                "decision_status": gate["decision"]["status"],
                "required_keys": gate["required_keys"],
                "forbidden_path_results": gate["forbidden_path_results"],
                "input_fingerprint": input_preflight["input_fingerprint"],
                "fingerprint": vector["fingerprint"],
            }
        )

    baseline = runs[0]
    mismatches: list[dict[str, str]] = []
    decision_status_equal = True
    required_keys_equal = True
    forbidden_path_results_equal = True
    input_fingerprint_equal = True

    for candidate in runs[1:]:
        if candidate["decision_status"] != baseline["decision_status"]:
            decision_status_equal = False
            mismatches.append(
                {
                    "field": "decision.status",
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

    return {
        "status": "PASS"
        if decision_status_equal and required_keys_equal and forbidden_path_results_equal and input_fingerprint_equal
        else "FAIL",
        "gate": GATE_NAME,
        "run_count": len(runs),
        "decision_status_equal": decision_status_equal,
        "required_keys_equal": required_keys_equal,
        "forbidden_path_results_equal": forbidden_path_results_equal,
        "input_fingerprint_equal": input_fingerprint_equal,
        "compare_excluded_fields": list(COMPARE_EXCLUDED_FIELDS),
        "runs": runs,
        "mismatches": mismatches,
    }


def build_input_preflight(
    *,
    run_id: str,
    requested_mode: str,
    input_root: Path,
    repo_root: Path,
) -> dict[str, Any]:
    missing_input_roots: list[str] = []
    placeholder_files: list[str] = []
    unexpected_files: list[str] = []
    present_real_inputs: list[dict[str, str]] = []
    missing_real_inputs: list[str] = []
    required_real_input_schema: list[dict[str, Any]] = []
    missing_real_input_details: list[dict[str, str]] = []
    blocking_reasons: list[str] = []
    root_status: dict[str, dict[str, Any]] = {
        item["provider"]: {
            "root_exists": False,
            "placeholder_files": [],
            "unexpected_files": [],
        }
        for item in REAL_INPUT_SCHEMA
    }

    for schema_entry in REAL_INPUT_SCHEMA:
        provider = schema_entry["provider"]
        expected_dir = input_root / provider
        if not expected_dir.exists():
            missing_input_roots.append(repo_relative(expected_dir, repo_root))
        else:
            root_status[provider]["root_exists"] = True
            for file_path in sorted(path for path in expected_dir.rglob("*") if path.is_file()):
                rel = file_path.relative_to(input_root).as_posix()
                if file_path.name in PLACEHOLDER_NAMES:
                    placeholder_files.append(rel)
                    root_status[provider]["placeholder_files"].append(rel)
                elif rel not in REQUIRED_REAL_INPUT_FILES:
                    unexpected_files.append(rel)
                    root_status[provider]["unexpected_files"].append(rel)

    for schema_entry in REAL_INPUT_SCHEMA:
        rel = schema_entry["relative_path"]
        provider = schema_entry["provider"]
        candidate = input_root / rel
        placeholder_only = (
            root_status[provider]["root_exists"]
            and not candidate.exists()
            and bool(root_status[provider]["placeholder_files"])
            and not root_status[provider]["unexpected_files"]
        )
        blocker_reason = None
        if candidate.exists():
            present_real_inputs.append(
                {
                    "provider": provider,
                    "path": rel,
                    "repo_relative_path": schema_entry["repo_relative_path"],
                    "sha256": sha256_file(candidate),
                }
            )
        else:
            missing_real_inputs.append(rel)
            missing_real_input_details.append(
                {
                    "provider": provider,
                    "path": rel,
                    "repo_relative_path": schema_entry["repo_relative_path"],
                    "why_required": schema_entry["why_required"],
                }
            )
            blocker_reason = (
                f"Missing canonical real input {schema_entry['repo_relative_path']}; "
                "placeholder files do not satisfy this requirement."
                if placeholder_only
                else f"Missing canonical real input {schema_entry['repo_relative_path']}."
            )
            blocking_reasons.append(blocker_reason)

        required_real_input_schema.append(
            {
                **schema_entry,
                "root_exists": root_status[provider]["root_exists"],
                "required_file_present": candidate.exists(),
                "placeholder_only": placeholder_only,
                "placeholder_files": root_status[provider]["placeholder_files"],
                "unexpected_files": root_status[provider]["unexpected_files"],
                "blocker_reason": blocker_reason,
            }
        )

    real_input_ready = not missing_input_roots and not missing_real_inputs
    effective_mode = requested_mode
    if requested_mode == "auto":
        effective_mode = "real" if real_input_ready else "dry-run"

    input_fingerprint = digest_json(
        {
            "present_real_inputs": present_real_inputs,
            "missing_real_inputs": missing_real_inputs,
            "missing_input_roots": missing_input_roots,
        }
    )

    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": utc_now(),
        "gate": GATE_NAME,
        "run_id": run_id,
        "requested_mode": requested_mode,
        "effective_mode": effective_mode,
        "input_root": repo_relative(input_root, repo_root),
        "required_input_roots": [item["required_root"] for item in REAL_INPUT_SCHEMA],
        "required_real_inputs": list(REQUIRED_REAL_INPUT_FILES),
        "required_real_input_schema": required_real_input_schema,
        "missing_input_roots": missing_input_roots,
        "present_real_inputs": present_real_inputs,
        "missing_real_inputs": missing_real_inputs,
        "missing_real_input_details": missing_real_input_details,
        "blocking_reasons": blocking_reasons,
        "placeholder_files": placeholder_files,
        "placeholder_files_are_ready_evidence": False,
        "unexpected_files": unexpected_files,
        "real_input_ready": real_input_ready,
        "input_fingerprint": input_fingerprint,
        "note": "Placeholder or missing real inputs are never READY(1) evidence.",
    }


def build_release_readiness(
    *,
    run_id: str,
    preflight: dict[str, Any],
    repo_root: Path,
    input_root: Path,
    output_dir: Path,
    artifact_presence: dict[str, bool] | None = None,
) -> dict[str, Any]:
    artifact_presence = artifact_presence or {name: False for name in REQUIRED_ARTIFACTS}
    app_root = canonical_app_root(repo_root)
    runs_root = canonical_runs_root(repo_root)
    entrypoint_path = app_root / "vuln_pipeline" / "cli" / "main.py"
    python_pin_path = app_root / ".python-version"
    cwd_matches = Path.cwd().resolve() == app_root.resolve()
    python_version = platform.python_version()
    python_version_matches = sys.version_info[:2] == REQUIRED_PYTHON_MAJOR_MINOR
    run_id_valid = validate_run_id(run_id)
    output_dir_is_canonical = output_dir.resolve() == canonical_run_dir(repo_root, run_id).resolve()
    forbidden_path_results = evaluate_forbidden_ready_paths([input_root, output_dir], repo_root)

    blocked_reasons: list[str] = []
    if not app_root.exists():
        blocked_reasons.append("canonical app root is missing")
    if not entrypoint_path.exists():
        blocked_reasons.append("canonical CLI entrypoint is missing")
    if not runs_root.exists():
        blocked_reasons.append("canonical data/runs root is missing")
    if not run_id_valid:
        blocked_reasons.append("run_id does not match ^run-\\d{8}T\\d{6}Z$")
    if not cwd_matches:
        blocked_reasons.append("current working directory is not app/vuln-pipeline")
    if not python_version_matches:
        blocked_reasons.append("python version is not 3.11.x")
    if not output_dir_is_canonical:
        blocked_reasons.append("output directory is not the canonical data/runs/<run_id> path")
    if any(item["status"] == "FAIL" for item in forbidden_path_results):
        blocked_reasons.append("legacy READY evidence path was selected")

    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": utc_now(),
        "gate": GATE_NAME,
        "run_id": run_id,
        "working_directory": WORKING_DIRECTORY,
        "official_entrypoint": OFFICIAL_ENTRYPOINT,
        "official_environment_preparation": list(OFFICIAL_ENVIRONMENT_PREPARATION),
        "official_smoke_command": OFFICIAL_SMOKE_COMMAND,
        "official_test_command": OFFICIAL_TEST_COMMAND,
        "python_version": {
            "executable": Path(sys.executable).resolve().as_posix(),
            "detected": python_version,
            "required": "3.11.x",
            "pin_file": repo_relative(python_pin_path, repo_root),
            "pin_value": python_pin_path.read_text(encoding="utf-8").strip() if python_pin_path.exists() else None,
            "matches_contract": python_version_matches,
        },
        "run_id_regex": RUN_ID_REGEX,
        "run_id_valid": run_id_valid,
        "cwd_repo_relative": repo_relative(Path.cwd(), repo_root),
        "working_directory_matches": cwd_matches,
        "input_root": repo_relative(input_root, repo_root),
        "canonical_output_dir": repo_relative(canonical_run_dir(repo_root, run_id), repo_root),
        "output_dir": repo_relative(output_dir, repo_root),
        "output_dir_is_canonical": output_dir_is_canonical,
        "artifact_presence": artifact_presence,
        "forbidden_path_results": forbidden_path_results,
        "blocked_reasons": blocked_reasons,
        "ready_contract_possible": not blocked_reasons,
        "note": "Install command success is verified by canonical tests, not inferred from this JSON alone.",
    }


def build_submission_gate(
    *,
    run_id: str,
    preflight: dict[str, Any],
    release: dict[str, Any],
    repo_root: Path,
    output_dir: Path,
    artifact_presence: dict[str, bool] | None = None,
) -> dict[str, Any]:
    artifact_presence = artifact_presence or {name: False for name in REQUIRED_ARTIFACTS}
    required_keys = {
        "input_preflight.json": sorted(preflight.keys()),
        "release_readiness.json": sorted(release.keys()),
        "submission_gate.json": sorted(
            [
                "artifact_presence",
                "compare_excluded_fields",
                "decision",
                "forbidden_path_results",
                "gate",
                "generated_at",
                "output_dir",
                "required_artifacts",
                "required_keys",
                "run_id",
                "schema_version",
                "stable_compare_vector",
            ]
        ),
    }

    blocked_reasons = list(release["blocked_reasons"])
    not_ready_reasons: list[str] = []
    if preflight["effective_mode"] != "real":
        blocked_reasons.append("dry-run evaluation is not READY(1) evidence")
    if preflight["missing_real_inputs"]:
        blocked_reasons.append("required real inputs are missing")
    if preflight["placeholder_files"] and preflight["missing_real_inputs"]:
        blocked_reasons.append("placeholder files do not satisfy the missing required real inputs")
    if not all(artifact_presence.values()):
        blocked_reasons.append("required artifacts are incomplete")

    if blocked_reasons:
        decision_status = "BLOCKED"
        reasons = blocked_reasons + not_ready_reasons
    elif not_ready_reasons:
        decision_status = "NOT_READY"
        reasons = not_ready_reasons
    else:
        decision_status = GATE_NAME
        reasons = ["All canonical READY(1) contract checks passed."]

    forbidden_path_results = release["forbidden_path_results"]
    stable_compare_vector = {
        "decision.status": decision_status,
        "required_keys": required_keys,
        "forbidden_path_results": forbidden_path_results,
        "input_fingerprint": preflight["input_fingerprint"],
    }
    stable_compare_vector["fingerprint"] = digest_json(stable_compare_vector)

    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": utc_now(),
        "gate": GATE_NAME,
        "run_id": run_id,
        "output_dir": repo_relative(output_dir, repo_root),
        "required_artifacts": list(REQUIRED_ARTIFACTS),
        "artifact_presence": artifact_presence,
        "required_keys": required_keys,
        "forbidden_path_results": forbidden_path_results,
        "compare_excluded_fields": list(COMPARE_EXCLUDED_FIELDS),
        "decision": {
            "status": decision_status,
            "reasons": reasons,
        },
        "stable_compare_vector": stable_compare_vector,
    }


def validate_run_id(run_id: str) -> bool:
    return bool(RUN_ID_PATTERN.fullmatch(run_id))


def canonical_app_root(repo_root: Path) -> Path:
    return repo_root / "app" / "vuln-pipeline"


def canonical_input_root(repo_root: Path) -> Path:
    return repo_root / "data" / "inputs" / "real"


def canonical_runs_root(repo_root: Path) -> Path:
    return repo_root / "data" / "runs"


def canonical_run_dir(repo_root: Path, run_id: str) -> Path:
    return canonical_runs_root(repo_root) / run_id


def evaluate_forbidden_ready_paths(
    candidate_paths: Iterable[Path],
    repo_root: Path,
    invoked_paths: Iterable[str] | None = None,
) -> list[dict[str, Any]]:
    invoked_paths = tuple(invoked_paths or ())
    resolved_candidates = [candidate.resolve() for candidate in candidate_paths]
    results: list[dict[str, Any]] = []
    for rule in FORBIDDEN_PATH_RULES:
        relative_path = rule["path"]
        relative_root = rule["evidence_root"]
        absolute_path = repo_root / relative_path
        absolute_root = repo_root / relative_root
        matched_paths = [
            repo_relative(candidate, repo_root)
            for candidate in resolved_candidates
            if is_relative_to(candidate, absolute_root.resolve())
        ]
        ready_evidence_detected = bool(matched_paths)
        call_count = sum(1 for candidate in invoked_paths if candidate == relative_path)
        results.append(
            {
                "path": relative_path,
                "evidence_root": relative_root,
                "exists": absolute_path.exists(),
                "call_count": call_count,
                "ready_evidence_allowed": False,
                "ready_evidence_detected": ready_evidence_detected,
                "matched_paths": matched_paths,
                "status": "FAIL" if ready_evidence_detected or call_count else "PASS",
            }
        )
    return results


def build_artifact_presence(output_dir: Path) -> dict[str, bool]:
    return {name: (output_dir / name).exists() for name in REQUIRED_ARTIFACTS}


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


def is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


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


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
