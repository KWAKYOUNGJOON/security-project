import json
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

from vuln_pipeline.contracts import REAL_INPUT_SCHEMA, build_submission_gate, evaluate_forbidden_ready_paths, validate_run_id


REPO_ROOT = Path(__file__).resolve().parents[3]
APP_ROOT = Path(__file__).resolve().parents[1]
RUN_IDS = (
    "run-20260321T010000Z",
    "run-20260321T010100Z",
    "run-20260321T010200Z",
)
LEGACY_SOURCE_RUN_ID = "run-20260321T010300Z"


def run_command(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, *args],
        cwd=APP_ROOT,
        text=True,
        capture_output=True,
        check=False,
    )


@pytest.mark.must_pass
def test_editable_install_and_contract_paths_exist() -> None:
    install = run_command("-m", "pip", "install", "-e", ".")
    assert install.returncode == 0, install.stderr or install.stdout
    assert APP_ROOT == REPO_ROOT / "app" / "vuln-pipeline"
    assert (REPO_ROOT / "data" / "inputs" / "real" / "burp").exists()
    assert (REPO_ROOT / "data" / "runs").exists()


@pytest.mark.must_pass
def test_run_id_regex_and_legacy_ready_path_policy() -> None:
    assert validate_run_id("run-20260321T010203Z")
    assert not validate_run_id("run-juice-001")
    assert not validate_run_id("rehearsal-001")


@pytest.mark.must_pass
def test_project_metadata_pins_python_to_contract_minor() -> None:
    pyproject = tomllib.loads((APP_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert pyproject["project"]["requires-python"] == ">=3.11,<3.12"


@pytest.mark.must_pass
def test_legacy_report_automation_source_is_blocked_for_ready_evidence() -> None:
    run_dir = REPO_ROOT / "data" / "runs" / LEGACY_SOURCE_RUN_ID
    if run_dir.exists():
        shutil.rmtree(run_dir)

    smoke = run_command(
        "-m",
        "vuln_pipeline.cli.main",
        "smoke",
        "--run-id",
        LEGACY_SOURCE_RUN_ID,
        "--input-root",
        "../../apps/report-automation",
    )
    assert smoke.returncode == 0, smoke.stderr or smoke.stdout

    payload = json.loads(smoke.stdout)
    assert payload["status"] == "BLOCKED"

    gate = json.loads((run_dir / "submission_gate.json").read_text(encoding="utf-8"))
    blocked_paths = [
        item
        for item in gate["forbidden_path_results"]
        if item["status"] == "FAIL" and item["evidence_root"] == "apps/report-automation"
    ]
    assert blocked_paths
    assert blocked_paths[0]["matched_paths"] == ["apps/report-automation"]


@pytest.mark.must_pass
def test_smoke_writes_required_artifacts_and_does_not_claim_ready_without_real_inputs() -> None:
    run_id = RUN_IDS[0]
    run_dir = REPO_ROOT / "data" / "runs" / run_id
    if run_dir.exists():
        shutil.rmtree(run_dir)

    smoke = run_command("-m", "vuln_pipeline.cli.main", "smoke", "--run-id", run_id)
    assert smoke.returncode == 0, smoke.stderr or smoke.stdout

    payload = json.loads(smoke.stdout)
    assert payload["status"] == "BLOCKED"
    assert (run_dir / "input_preflight.json").exists()
    assert (run_dir / "release_readiness.json").exists()
    assert (run_dir / "submission_gate.json").exists()

    preflight = json.loads((run_dir / "input_preflight.json").read_text(encoding="utf-8"))
    assert preflight["required_real_inputs"] == [item["relative_path"] for item in REAL_INPUT_SCHEMA]
    assert [item["repo_relative_path"] for item in preflight["required_real_input_schema"]] == [
        item["repo_relative_path"] for item in REAL_INPUT_SCHEMA
    ]
    assert all(item["placeholder_only"] is True for item in preflight["required_real_input_schema"])
    assert all(item["blocker_reason"] for item in preflight["required_real_input_schema"])
    assert preflight["missing_real_input_details"] == [
        {
            "provider": item["provider"],
            "path": item["relative_path"],
            "repo_relative_path": item["repo_relative_path"],
            "why_required": item["why_required"],
        }
        for item in REAL_INPUT_SCHEMA
    ]
    assert len(preflight["blocking_reasons"]) == len(REAL_INPUT_SCHEMA)
    assert preflight["placeholder_files_are_ready_evidence"] is False

    gate = json.loads((run_dir / "submission_gate.json").read_text(encoding="utf-8"))
    assert gate["decision"]["status"] == "BLOCKED"
    assert gate["forbidden_path_results"][0]["ready_evidence_allowed"] is False
    assert gate["forbidden_path_results"][0]["path"] == "apps/report-automation/src/cli/main.py"
    assert gate["forbidden_path_results"][0]["call_count"] == 0
    assert "required real inputs are missing" in gate["decision"]["reasons"]


@pytest.mark.must_pass
def test_compare_runs_is_stable_for_identical_placeholder_state() -> None:
    for run_id in RUN_IDS:
        run_dir = REPO_ROOT / "data" / "runs" / run_id
        if run_dir.exists():
            shutil.rmtree(run_dir)
        smoke = run_command("-m", "vuln_pipeline.cli.main", "smoke", "--run-id", run_id)
        assert smoke.returncode == 0, smoke.stderr or smoke.stdout

    compare = run_command(
        "-m",
        "vuln_pipeline.cli.main",
        "compare-runs",
        "--run-dir",
        "../../data/runs/run-20260321T010000Z",
        "--run-dir",
        "../../data/runs/run-20260321T010100Z",
        "--run-dir",
        "../../data/runs/run-20260321T010200Z",
    )
    assert compare.returncode == 0, compare.stderr or compare.stdout

    payload = json.loads(compare.stdout)
    assert payload["status"] == "PASS"
    assert payload["decision_status_equal"] is True
    assert payload["required_keys_equal"] is True
    assert payload["forbidden_path_results_equal"] is True
    assert payload["input_fingerprint_equal"] is True


@pytest.mark.must_pass
def test_submission_gate_uses_ready_gate_name_for_green_contract_state() -> None:
    preflight = {
        "effective_mode": "real",
        "missing_real_inputs": [],
        "placeholder_files": [],
        "input_fingerprint": "abc123",
    }
    release = {
        "blocked_reasons": [],
        "forbidden_path_results": [
            {
                "path": "apps/report-automation/src/cli/main.py",
                "evidence_root": "apps/report-automation",
                "exists": True,
                "call_count": 0,
                "ready_evidence_allowed": False,
                "ready_evidence_detected": False,
                "status": "PASS",
            }
        ],
    }

    gate = build_submission_gate(
        run_id="run-20260321T010203Z",
        preflight=preflight,
        release=release,
        repo_root=REPO_ROOT,
        output_dir=REPO_ROOT / "data" / "runs" / "run-20260321T010203Z",
        artifact_presence={
            "input_preflight.json": True,
            "release_readiness.json": True,
            "submission_gate.json": True,
        },
    )

    assert gate["decision"]["status"] == "READY(1)"


@pytest.mark.must_pass
def test_forbidden_path_result_tracks_exact_legacy_entrypoint() -> None:
    results = evaluate_forbidden_ready_paths(
        [REPO_ROOT / "data" / "runs" / "run-20260321T010203Z"],
        REPO_ROOT,
        invoked_paths=["apps/report-automation/src/cli/main.py"],
    )

    assert results == [
        {
            "path": "apps/report-automation/src/cli/main.py",
            "evidence_root": "apps/report-automation",
            "exists": True,
            "call_count": 1,
            "ready_evidence_allowed": False,
            "ready_evidence_detected": False,
            "matched_paths": [],
            "status": "FAIL",
        }
    ]
