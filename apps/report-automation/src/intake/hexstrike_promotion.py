"""Promotion policy assessment for validated live HexStrike intake runs."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from src.intake.hexstrike_intake import HexStrikeIntakeError, load_hexstrike_intake_run, resolve_intake_directory
from src.parsers.hexstrike_live_adapter import (
    COVERAGE_GAP_NO_DETAIL,
    COVERAGE_GAP_NONZERO_NO_DETAIL,
    SUMMARY_NOTE_NONZERO_NO_DETAIL,
    SUMMARY_NOTE_ZERO_DETAIL,
)
from src.validators import validate_schema_file


PROMOTION_STATUS_BLOCKED = "blocked"
PROMOTION_STATUS_ELIGIBLE = "eligible"
PROMOTION_STATUS_UNKNOWN = "unknown"

EVIDENCE_CLASS_SUMMARY_ONLY = "summary_only_smoke_evidence"
EVIDENCE_CLASS_SUMMARY_NONZERO = "summary_nonzero_missing_detail"
EVIDENCE_CLASS_DETAIL_READY = "finding_detail_ready"
EVIDENCE_CLASS_UNKNOWN = "unknown_live_evidence"

DETAIL_STATUS_ZERO_NO_DETAIL = "zero_summary_no_detail"
DETAIL_STATUS_NONZERO_NO_DETAIL = "nonzero_summary_no_detail"
DETAIL_STATUS_DETAIL_READY = "detail_ready"
DETAIL_STATUS_UNKNOWN = "unknown"

SOURCE_TYPE = "hexstrike_live_validation_artifacts"


def assess_hexstrike_live_promotion(
    run_arg: str | Path,
    repo_root: Path,
    schema_dir: Path,
) -> dict[str, Any]:
    """Assess whether a validated live HexStrike run may be promoted into case input."""

    run_dir = resolve_intake_directory(run_arg, repo_root)
    intake_run = load_hexstrike_intake_run(run_dir, repo_root)
    derived = run_dir / "derived"

    required_files = {
        "format_observation": derived / "format-observation.json",
        "shape_bridge_report": derived / "shape-bridge-report.json",
        "live_raw_shape_summary": derived / "live-raw-shape-summary.json",
        "provenance": derived / "provenance.json",
    }
    missing = [name for name, path in required_files.items() if not path.exists()]
    if missing:
        missing_text = ", ".join(missing)
        raise HexStrikeIntakeError(
            "Promotion assessment requires validated derived artifacts. "
            f"Missing: {missing_text}. Run 'validate-live-hexstrike' first."
        )

    observation = _load_json(required_files["format_observation"])
    shape_bridge_report = _load_json(required_files["shape_bridge_report"])
    live_shape_summary = _load_json(required_files["live_raw_shape_summary"])
    provenance = _load_json(required_files["provenance"])
    decision = assess_hexstrike_live_promotion_from_artifacts(
        manifest=intake_run.manifest,
        format_observation=observation,
        shape_bridge_report=shape_bridge_report,
        live_raw_shape_summary=live_shape_summary,
        provenance=provenance,
        source_paths={
            "manifest": intake_run.repo_relative(intake_run.manifest_path),
            "notes": intake_run.repo_relative(intake_run.notes_path),
            "format_observation": intake_run.repo_relative(required_files["format_observation"]),
            "shape_bridge_report": intake_run.repo_relative(required_files["shape_bridge_report"]),
            "live_raw_shape_summary": intake_run.repo_relative(required_files["live_raw_shape_summary"]),
            "provenance": intake_run.repo_relative(required_files["provenance"]),
        },
    )
    validate_schema_file(decision, schema_dir / "hexstrike-live-promotion-decision.schema.json")

    decision_path = derived / "promotion-decision.json"
    _write_json(decision_path, decision)
    return {
        "promotion_decision_path": str(decision_path),
        "promotion_status": decision["promotion_status"],
        "case_input_promotion_allowed": decision["case_input_promotion_allowed"],
        "evidence_class": decision["evidence_class"],
        "validation_status": decision["validation_status"],
        "finding_count_detected": decision["finding_count_detected"],
        "detail_coverage_status": decision["detail_coverage_status"],
        "blocking_reason_count": len(decision["blocking_reasons"]),
        "decision_confidence": decision["decision_confidence"],
    }


def assess_hexstrike_live_promotion_from_artifacts(
    *,
    manifest: Mapping[str, Any],
    format_observation: Mapping[str, Any],
    shape_bridge_report: Mapping[str, Any],
    live_raw_shape_summary: Mapping[str, Any] | None = None,
    provenance: Mapping[str, Any] | None = None,
    source_paths: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Assess promotion policy from validated live-run artifacts."""

    finding_count_detected = _int_or_zero(format_observation.get("finding_count_detected"))
    validation_status = _text(manifest.get("validation_status")) or "passed"
    coverage_confidence = _text(_path_get(shape_bridge_report, "coverage_summary.coverage_confidence")) or "unknown"
    adapter_applied = bool(_path_get(shape_bridge_report, "coverage_summary.adapted_payload_count"))
    guessed_fields_absent = bool(shape_bridge_report.get("guessed_fields_absent", True))
    guessed_fields_used = not guessed_fields_absent

    detail_coverage_status = _derive_detail_coverage_status(
        finding_count_detected=finding_count_detected,
        live_raw_shape_summary=live_raw_shape_summary,
        shape_bridge_report=shape_bridge_report,
    )

    promotion_status = PROMOTION_STATUS_UNKNOWN
    case_input_promotion_allowed = False
    evidence_class = EVIDENCE_CLASS_UNKNOWN
    decision_confidence = "medium"
    blocking_reasons: list[dict[str, str]] = []
    advisory_actions: list[str] = []
    required_for_future_promotion: list[str] = []

    if detail_coverage_status == DETAIL_STATUS_ZERO_NO_DETAIL:
        promotion_status = PROMOTION_STATUS_BLOCKED
        evidence_class = EVIDENCE_CLASS_SUMMARY_ONLY
        decision_confidence = "high"
        blocking_reasons = [
            _reason("no_findings_detected", "No finding-level records were detected in the validated live run."),
            _reason(
                "summary_only_payload_not_case_promotable",
                "Summary-only live payloads are smoke linkage evidence only and must not be promoted into cases input.",
            ),
            _reason(
                "no_request_response_evidence",
                "No request, response, or equivalent finding-level evidence references are available for case promotion.",
            ),
        ]
        advisory_actions = [
            "retain_as_smoke_linkage_evidence_only",
            "do_not_promote_to_cases_input",
        ]
        required_for_future_promotion = [
            "capture_finding_level_live_sample_before_promotion",
            "preserve_request_response_or_equivalent_evidence_references",
            "verify_stable_finding_identifiers_before_case_creation",
        ]
    elif detail_coverage_status == DETAIL_STATUS_NONZERO_NO_DETAIL:
        promotion_status = PROMOTION_STATUS_BLOCKED
        evidence_class = EVIDENCE_CLASS_SUMMARY_NONZERO
        decision_confidence = "medium"
        blocking_reasons = [
            _reason(
                "summary_claims_findings_but_no_detail_records",
                "The live summary reports vulnerabilities, but no finding detail records were captured.",
            ),
            _reason(
                "finding_detail_required_for_case_promotion",
                "Case promotion requires finding-level identifiers and evidence references.",
            ),
            _reason(
                "no_request_response_evidence",
                "No request, response, or equivalent finding-level evidence references are available for case promotion.",
            ),
        ]
        advisory_actions = [
            "capture_finding_level_live_sample_before_promotion",
            "keep_out_of_cases_input",
        ]
        required_for_future_promotion = [
            "capture_finding_level_live_sample_before_promotion",
            "preserve_request_response_or_equivalent_evidence_references",
            "verify_stable_finding_identifiers_before_case_creation",
        ]
    elif detail_coverage_status == DETAIL_STATUS_DETAIL_READY and not guessed_fields_used:
        promotion_status = PROMOTION_STATUS_ELIGIBLE
        case_input_promotion_allowed = True
        evidence_class = EVIDENCE_CLASS_DETAIL_READY
        decision_confidence = "medium"
        advisory_actions = ["review_before_case_promotion"]
    else:
        promotion_status = PROMOTION_STATUS_UNKNOWN
        evidence_class = EVIDENCE_CLASS_UNKNOWN
        decision_confidence = "low"
        blocking_reasons = [
            _reason(
                "promotion_state_unknown",
                "Promotion state could not be determined safely from the available validation artifacts.",
            )
        ]
        advisory_actions = ["re-run_validate_live_hexstrike_or_review_artifacts"]
        required_for_future_promotion = [
            "ensure_live_validation_artifacts_exist",
            "review_shape_bridge_report_for_missing_coverage",
        ]

    run_id = _text(manifest.get("run_id")) or _text(format_observation.get("run_id")) or "unknown-run"
    return {
        "run_id": run_id,
        "source_type": SOURCE_TYPE,
        "promotion_status": promotion_status,
        "case_input_promotion_allowed": case_input_promotion_allowed,
        "evidence_class": evidence_class,
        "decision_confidence": decision_confidence,
        "validation_status": validation_status,
        "adapter_applied": adapter_applied,
        "finding_count_detected": finding_count_detected,
        "detail_coverage_status": detail_coverage_status,
        "coverage_confidence": coverage_confidence,
        "summary_total_vulnerabilities": _summary_total_vulnerabilities(live_raw_shape_summary, shape_bridge_report),
        "blocking_reasons": blocking_reasons,
        "advisory_actions": advisory_actions,
        "required_for_future_promotion": required_for_future_promotion,
        "source_paths": {
            "manifest": _source_path(source_paths, "manifest"),
            "notes": _source_path(source_paths, "notes"),
            "format_observation": _source_path(source_paths, "format_observation"),
            "shape_bridge_report": _source_path(source_paths, "shape_bridge_report"),
            "live_raw_shape_summary": _source_path(source_paths, "live_raw_shape_summary"),
            "provenance": _source_path(source_paths, "provenance"),
        },
        "guessed_fields_used": guessed_fields_used,
        "raw_evidence_immutable": True,
        "generated_at": _generated_at(),
    }


def _derive_detail_coverage_status(
    *,
    finding_count_detected: int,
    live_raw_shape_summary: Mapping[str, Any] | None,
    shape_bridge_report: Mapping[str, Any],
) -> str:
    if finding_count_detected > 0:
        return DETAIL_STATUS_DETAIL_READY

    summary_total = _summary_total_vulnerabilities(live_raw_shape_summary, shape_bridge_report)
    if summary_total is not None and summary_total > 0:
        return DETAIL_STATUS_NONZERO_NO_DETAIL
    if summary_total == 0:
        return DETAIL_STATUS_ZERO_NO_DETAIL

    gaps = _string_list(shape_bridge_report.get("coverage_gaps"))
    if COVERAGE_GAP_NONZERO_NO_DETAIL in gaps:
        return DETAIL_STATUS_NONZERO_NO_DETAIL
    if COVERAGE_GAP_NO_DETAIL in gaps:
        return DETAIL_STATUS_ZERO_NO_DETAIL

    notes = _string_list((live_raw_shape_summary or {}).get("unknown_topology_notes"))
    if SUMMARY_NOTE_NONZERO_NO_DETAIL in notes:
        return DETAIL_STATUS_NONZERO_NO_DETAIL
    if SUMMARY_NOTE_ZERO_DETAIL in notes:
        return DETAIL_STATUS_ZERO_NO_DETAIL
    return DETAIL_STATUS_UNKNOWN


def _summary_total_vulnerabilities(
    live_raw_shape_summary: Mapping[str, Any] | None,
    shape_bridge_report: Mapping[str, Any],
) -> int | None:
    summary_total = (live_raw_shape_summary or {}).get("summary_total_vulnerabilities")
    if isinstance(summary_total, bool):
        return None
    if isinstance(summary_total, int):
        return summary_total
    if isinstance(summary_total, float):
        return int(summary_total)

    gaps = _string_list(shape_bridge_report.get("coverage_gaps"))
    if COVERAGE_GAP_NONZERO_NO_DETAIL in gaps:
        return 1
    notes = _string_list((live_raw_shape_summary or {}).get("unknown_topology_notes"))
    if SUMMARY_NOTE_ZERO_DETAIL in notes:
        return 0
    if SUMMARY_NOTE_NONZERO_NO_DETAIL in notes:
        return 1
    return None


def _source_path(source_paths: Mapping[str, str] | None, key: str) -> str | None:
    if source_paths is None:
        return None
    value = source_paths.get(key)
    return value if isinstance(value, str) and value.strip() else None


def _reason(code: str, message: str) -> dict[str, str]:
    return {"code": code, "message": message}


def _generated_at() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise HexStrikeIntakeError(f"Expected JSON object at {path}") from exc
    if not isinstance(payload, dict):
        raise HexStrikeIntakeError(f"Expected JSON object at {path}")
    return payload


def _write_json(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _path_get(payload: Mapping[str, Any] | None, dotted_path: str) -> Any:
    if not isinstance(payload, Mapping):
        return None
    current: Any = payload
    for part in dotted_path.split("."):
        if not isinstance(current, Mapping) or part not in current:
            return None
        current = current.get(part)
    return current


def _text(value: Any) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        value = str(value)
    cleaned = value.strip()
    return cleaned or None


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    items: list[str] = []
    for item in value:
        text = _text(item)
        if text is not None:
            items.append(text)
    return items


def _int_or_zero(value: Any) -> int:
    if isinstance(value, bool):
        return 0
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return 0
