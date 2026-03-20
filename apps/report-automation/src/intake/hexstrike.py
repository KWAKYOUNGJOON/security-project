"""File-based HexStrike intake validation for pre-target mode."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

from src.cases.provenance import build_file_provenance_ledger
from src.intake.hexstrike_intake import (
    HexStrikeIntakeError,
    HexStrikeIntakeRun,
    load_hexstrike_intake_run,
    resolve_intake_directory,
)
from src.parsers import (
    build_hexstrike_format_observation,
    build_synthetic_live_delta,
    bridge_live_hexstrike_run,
    summarize_live_raw_shape,
)
from src.validators import validate_schema_file


def validate_live_hexstrike_run(run_arg: str | Path, repo_root: Path, schema_dir: Path) -> dict[str, Any]:
    """Validate one file-based intake run and write observation artifacts."""

    run_dir = resolve_intake_directory(run_arg, repo_root)
    intake_run = load_hexstrike_intake_run(run_dir, repo_root)
    output_paths: list[Path] = []
    live_raw_shape_summary = summarize_live_raw_shape(intake_run)
    live_raw_shape_summary_path = run_dir / "derived" / "live-raw-shape-summary.json"
    _write_json(live_raw_shape_summary_path, live_raw_shape_summary)
    bridge = bridge_live_hexstrike_run(intake_run)

    shape_bridge_report_path: Path | None = None
    synthetic_live_delta_path: Path | None = None
    if bridge["adapter_applied"]:
        shape_bridge_report = bridge["shape_bridge_report"]
        validate_schema_file(shape_bridge_report, schema_dir / "hexstrike-shape-bridge-report.schema.json")
        shape_bridge_report_path = run_dir / "derived" / "shape-bridge-report.json"
        _write_json(shape_bridge_report_path, shape_bridge_report)
        output_paths.append(shape_bridge_report_path)

    try:
        observation = build_hexstrike_format_observation(
            intake_run,
            payload_sources=bridge["payload_sources"],
        )
        validate_schema_file(observation, schema_dir / "format-observation.schema.json")
    except Exception as exc:
        if shape_bridge_report_path is not None:
            raise HexStrikeIntakeError(
                f"Known live HexStrike shape bridge executed but canonical observation validation failed: {exc}; "
                f"see {shape_bridge_report_path}"
            ) from exc
        raise

    observation_path = run_dir / "derived" / "format-observation.json"
    _write_json(observation_path, observation)
    output_paths.append(observation_path)

    if shape_bridge_report_path is not None:
        synthetic_live_delta = build_synthetic_live_delta(
            intake_run,
            repo_root=repo_root,
            live_observation=observation,
            live_raw_shape_summary=live_raw_shape_summary,
            bridge_report=bridge["shape_bridge_report"],
        )
        validate_schema_file(synthetic_live_delta, schema_dir / "hexstrike-synthetic-live-delta.schema.json")
        synthetic_live_delta_path = run_dir / "derived" / "synthetic-vs-live-delta.json"
        _write_json(synthetic_live_delta_path, synthetic_live_delta)
        output_paths.append(synthetic_live_delta_path)

    provenance = _build_intake_provenance_ledger(intake_run, repo_root=repo_root, output_paths=output_paths)
    validate_schema_file(provenance, schema_dir / "provenance.schema.json")
    provenance_path = run_dir / "derived" / "provenance.json"
    _write_json(provenance_path, provenance)

    result = {
        "live_raw_shape_summary_path": str(live_raw_shape_summary_path),
        "format_observation_path": str(observation_path),
        "provenance_path": str(provenance_path),
        "finding_count_detected": int(observation["finding_count_detected"]),
        "warning_count": len(observation["parser_warnings"]),
        "adapter_applied": bool(bridge["adapter_applied"]),
        "validation_status": "success",
    }
    if shape_bridge_report_path is not None:
        result["shape_bridge_report_path"] = str(shape_bridge_report_path)
        if synthetic_live_delta_path is not None:
            result["synthetic_live_delta_path"] = str(synthetic_live_delta_path)
        result["coverage_confidence"] = bridge["shape_bridge_report"]["coverage_summary"]["coverage_confidence"]
        result.update(bridge["shape_bridge_report"]["status"])
    return result


def _build_intake_provenance_ledger(
    intake_run: HexStrikeIntakeRun,
    *,
    repo_root: Path,
    output_paths: list[Path],
) -> dict[str, Any]:
    input_files = [
        ("manifest", intake_run.manifest_path, None),
        ("notes", intake_run.notes_path, None),
    ]
    input_files.extend(("runtime-baseline", path, None) for path in intake_run.baseline_files)
    input_files.extend(("intake-raw", raw_payload.file_path, None) for raw_payload in intake_run.raw_payloads)
    return build_file_provenance_ledger(
        record_id=intake_run.run_id,
        repo_root=repo_root.resolve(),
        input_files=input_files,
        output_paths=output_paths,
        subject_type="intake-run",
    )


def _write_json(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
