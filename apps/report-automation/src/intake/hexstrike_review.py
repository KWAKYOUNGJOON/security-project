"""Review rendering for validated HexStrike live intake runs."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from src.intake.hexstrike_intake import HexStrikeIntakeError, resolve_intake_directory
from src.intake.hexstrike_promotion import (
    EVIDENCE_CLASS_DETAIL_READY,
    EVIDENCE_CLASS_SUMMARY_NONZERO,
    EVIDENCE_CLASS_SUMMARY_ONLY,
    EVIDENCE_CLASS_UNKNOWN,
    PROMOTION_STATUS_BLOCKED,
    PROMOTION_STATUS_ELIGIBLE,
    PROMOTION_STATUS_UNKNOWN,
)
from src.validators import validate_schema_file


SCHEMA_VERSION = "1.0"

REVIEW_STATUS_REVIEW_REQUIRED = "review_required"
REVIEW_STATUS_BLOCKED_SUMMARY_ONLY = "blocked_summary_only"
REVIEW_STATUS_BLOCKED_MISSING_DETAIL = "blocked_missing_detail"
REVIEW_STATUS_READY_FOR_MANUAL_CONFIRMATION = "ready_for_manual_confirmation"
REVIEW_STATUS_UNKNOWN = "unknown"

CHECK_STATUS_MET = "met"
CHECK_STATUS_MISSING = "missing"
CHECK_STATUS_BLOCKED = "blocked"
CHECK_STATUS_NOT_APPLICABLE = "not_applicable"

ACTION_LABELS = {
    "retain_as_smoke_linkage_evidence_only": "Keep this run as smoke linkage evidence only.",
    "do_not_promote_to_cases_input": "Do not promote this run into cases/web/<case-id>/input.",
    "capture_finding_level_live_sample_before_promotion": "Capture a future approved live sample that includes finding-level detail.",
    "keep_out_of_cases_input": "Keep this run out of cases input until finding detail exists.",
    "review_before_case_promotion": "Run manual reviewer confirmation before any future promotion action.",
    "re-run_validate_live_hexstrike_or_review_artifacts": "Review the validation and promotion artifacts before making any further decision.",
    "preserve_request_response_or_equivalent_evidence_references": (
        "Preserve request/response or equivalent evidence references for each finding."
    ),
    "verify_stable_finding_identifiers_before_case_creation": (
        "Verify stable finding identifiers before attempting case creation."
    ),
    "ensure_live_validation_artifacts_exist": "Generate the required validation artifacts before review.",
    "review_shape_bridge_report_for_missing_coverage": "Inspect shape-bridge-report.json for missing coverage before promotion review.",
    "keep_run_intake_only": "Keep this run under intake only. Do not move or copy it into cases input.",
    "capture_future_finding_level_live_sample": (
        "Capture a future approved live run that preserves finding detail, request/response, and per-finding evidence."
    ),
}

BLOCKING_REASON_LABELS = {
    "no_findings_detected": "No finding detail detected",
    "summary_only_payload_not_case_promotable": "Summary-only payload cannot be promoted",
    "no_request_response_evidence": "No request/response evidence",
    "summary_claims_findings_but_no_detail_records": "Summary claims findings without detail",
    "finding_detail_required_for_case_promotion": "Finding detail required for promotion",
    "promotion_state_unknown": "Promotion state unknown",
}


def render_hexstrike_live_review(
    run_arg: str | Path,
    repo_root: Path,
    schema_dir: Path,
) -> dict[str, Any]:
    """Render machine-readable and Markdown review artifacts for a live HexStrike run."""

    run_dir = resolve_intake_directory(run_arg, repo_root)
    derived_dir = run_dir / "derived"

    required_files = {
        "manifest": run_dir / "manifest.json",
        "promotion_decision": derived_dir / "promotion-decision.json",
        "format_observation": derived_dir / "format-observation.json",
        "shape_bridge_report": derived_dir / "shape-bridge-report.json",
        "provenance": derived_dir / "provenance.json",
    }
    missing = [name for name, path in required_files.items() if not path.exists()]
    if missing:
        missing_text = ", ".join(missing)
        raise HexStrikeIntakeError(
            "Live review rendering requires existing validation and promotion artifacts. "
            f"Missing: {missing_text}. Run 'validate-live-hexstrike --run <run>' and "
            "'assess-live-hexstrike-promotion --run <run>' first."
        )

    manifest = _load_json(required_files["manifest"])
    promotion_decision = _load_json(required_files["promotion_decision"])
    format_observation = _load_json(required_files["format_observation"])
    shape_bridge_report = _load_json(required_files["shape_bridge_report"])
    provenance = _load_json(required_files["provenance"])
    live_raw_shape_summary = _maybe_load_json(derived_dir / "live-raw-shape-summary.json")
    validate_log = _maybe_load_json(derived_dir / "validate-live-hexstrike.txt")

    review_summary = build_hexstrike_live_review_summary(
        run_dir=run_dir,
        repo_root=repo_root,
        manifest=manifest,
        promotion_decision=promotion_decision,
        format_observation=format_observation,
        shape_bridge_report=shape_bridge_report,
        provenance=provenance,
        live_raw_shape_summary=live_raw_shape_summary,
        validate_log=validate_log,
    )
    validate_schema_file(review_summary, schema_dir / "hexstrike-live-review-summary.schema.json")

    markdown = render_hexstrike_live_review_markdown(review_summary)
    review_json_path = derived_dir / "promotion-review.json"
    review_md_path = derived_dir / "promotion-review.md"
    _write_json(review_json_path, review_summary)
    review_md_path.write_text(markdown, encoding="utf-8")

    return {
        "promotion_review_path": str(review_json_path),
        "promotion_review_markdown_path": str(review_md_path),
        "review_status": review_summary["review_status"],
        "promotion_status": review_summary["promotion_status"],
        "evidence_class": review_summary["evidence_class"],
        "validation_status": review_summary["validation_status"],
        "blocking_reason_count": len(review_summary["blocking_reasons"]),
        "missing_evidence_count": len(review_summary["missing_evidence"]),
    }


def build_hexstrike_live_review_summary(
    *,
    run_dir: Path,
    repo_root: Path,
    manifest: Mapping[str, Any],
    promotion_decision: Mapping[str, Any],
    format_observation: Mapping[str, Any],
    shape_bridge_report: Mapping[str, Any],
    provenance: Mapping[str, Any],
    live_raw_shape_summary: Mapping[str, Any] | None,
    validate_log: Mapping[str, Any] | None,
) -> dict[str, Any]:
    """Build a review-oriented summary from promotion and validation artifacts."""

    shape_status = _mapping(shape_bridge_report.get("status"))
    referenced_artifacts = _build_referenced_artifacts(
        repo_root=repo_root,
        run_dir=run_dir,
        promotion_decision=promotion_decision,
    )

    run_id = _text(promotion_decision.get("run_id")) or _text(manifest.get("run_id")) or run_dir.name
    promotion_status = _promotion_status(promotion_decision.get("promotion_status"))
    evidence_class = _evidence_class(promotion_decision.get("evidence_class"))
    validation_status = (
        _text(shape_status.get("validation_status"))
        or _text(_mapping(validate_log).get("validation_status"))
        or _text(promotion_decision.get("validation_status"))
        or _text(manifest.get("validation_status"))
        or "unknown"
    )
    linkage_status = (
        _text(shape_status.get("linkage_status"))
        or _text(_mapping(validate_log).get("linkage_status"))
        or "unknown"
    )
    observation_kind = _text(shape_status.get("observation_kind")) or "unknown"
    adapter_applied = bool(shape_status.get("adapter_applied")) or bool(promotion_decision.get("adapter_applied"))
    finding_count_detected = _int_or_zero(
        promotion_decision.get("finding_count_detected", format_observation.get("finding_count_detected"))
    )
    detail_coverage_status = _text(promotion_decision.get("detail_coverage_status")) or "unknown"
    decision_confidence = _confidence(_text(promotion_decision.get("decision_confidence")), default="low")
    coverage_confidence = _confidence(
        _text(promotion_decision.get("coverage_confidence"))
        or _text(_mapping(shape_bridge_report.get("coverage_summary")).get("coverage_confidence")),
        default="unknown",
    )
    case_input_promotion_allowed = bool(promotion_decision.get("case_input_promotion_allowed"))
    summary_total_vulnerabilities = _int_or_none(promotion_decision.get("summary_total_vulnerabilities"))
    finding_detail_presence = bool(shape_status.get("finding_detail_presence")) or finding_count_detected > 0
    request_response_presence = bool(shape_status.get("request_response_presence"))
    evidence_presence = bool(shape_status.get("evidence_presence"))
    reproducibility_reference_present = _has_reproducibility_reference(referenced_artifacts)

    blocking_reasons = _decorate_blocking_reasons(promotion_decision.get("blocking_reasons"))
    missing_evidence = _build_missing_evidence(
        evidence_class=evidence_class,
        finding_detail_presence=finding_detail_presence,
        request_response_presence=request_response_presence,
        evidence_presence=evidence_presence,
    )
    recommended_next_actions = _build_recommended_next_actions(
        promotion_decision=promotion_decision,
        evidence_class=evidence_class,
    )
    review_status = _derive_review_status(
        promotion_status=promotion_status,
        evidence_class=evidence_class,
    )
    review_checklist = _build_review_checklist(
        promotion_decision=promotion_decision,
        validation_status=validation_status,
        adapter_applied=adapter_applied,
        finding_count_detected=finding_count_detected,
        evidence_class=evidence_class,
        finding_detail_presence=finding_detail_presence,
        request_response_presence=request_response_presence,
        reproducibility_reference_present=reproducibility_reference_present,
        referenced_artifacts=referenced_artifacts,
    )
    reviewer_summary = _build_reviewer_summary(
        run_id=run_id,
        validation_status=validation_status,
        linkage_status=linkage_status,
        promotion_status=promotion_status,
        evidence_class=evidence_class,
        finding_count_detected=finding_count_detected,
        summary_total_vulnerabilities=summary_total_vulnerabilities,
        case_input_promotion_allowed=case_input_promotion_allowed,
    )
    key_facts = _build_key_facts(
        validation_status=validation_status,
        linkage_status=linkage_status,
        observation_kind=observation_kind,
        promotion_status=promotion_status,
        case_input_promotion_allowed=case_input_promotion_allowed,
        evidence_class=evidence_class,
        detail_coverage_status=detail_coverage_status,
        finding_count_detected=finding_count_detected,
        coverage_confidence=coverage_confidence,
        decision_confidence=decision_confidence,
        adapter_applied=adapter_applied,
        raw_evidence_immutable=bool(promotion_decision.get("raw_evidence_immutable", True)),
        guessed_fields_used=bool(promotion_decision.get("guessed_fields_used", False)),
        provenance=provenance,
        live_raw_shape_summary=live_raw_shape_summary,
        format_observation=format_observation,
    )

    return {
        "schema_version": SCHEMA_VERSION,
        "run_id": run_id,
        "review_status": review_status,
        "promotion_status": promotion_status,
        "case_input_promotion_allowed": case_input_promotion_allowed,
        "evidence_class": evidence_class,
        "validation_status": validation_status,
        "linkage_status": linkage_status,
        "observation_kind": observation_kind,
        "adapter_applied": adapter_applied,
        "finding_count_detected": finding_count_detected,
        "detail_coverage_status": detail_coverage_status,
        "decision_confidence": decision_confidence,
        "coverage_confidence": coverage_confidence,
        "reviewer_summary": reviewer_summary,
        "key_facts": key_facts,
        "blocking_reasons": blocking_reasons,
        "missing_evidence": missing_evidence,
        "recommended_next_actions": recommended_next_actions,
        "review_checklist": review_checklist,
        "referenced_artifacts": referenced_artifacts,
        "raw_evidence_immutable": bool(promotion_decision.get("raw_evidence_immutable", True)),
        "guessed_fields_used": bool(promotion_decision.get("guessed_fields_used", False)),
        "generated_at": _generated_at(),
    }


def render_hexstrike_live_review_markdown(review_summary: Mapping[str, Any]) -> str:
    """Render a concise Markdown handoff for operator review."""

    lines: list[str] = []
    lines.append(f"# HexStrike Live Review: {review_summary['run_id']}")
    lines.append("")
    lines.append("## Run Summary")
    lines.append("")
    lines.extend(review_summary["reviewer_summary"].splitlines())
    lines.append("")
    lines.append("## Validation vs Promotion")
    lines.append("")
    lines.append(f"- validation_status: `{review_summary['validation_status']}`")
    lines.append(f"- linkage_status: `{review_summary['linkage_status']}`")
    lines.append(f"- observation_kind: `{review_summary['observation_kind']}`")
    lines.append(f"- promotion_status: `{review_summary['promotion_status']}`")
    lines.append(f"- review_status: `{review_summary['review_status']}`")
    lines.append(f"- case_input_promotion_allowed: `{str(review_summary['case_input_promotion_allowed']).lower()}`")
    lines.append("")
    lines.append("## Current Evidence Class")
    lines.append("")
    lines.append(f"- evidence_class: `{review_summary['evidence_class']}`")
    lines.append(f"- detail_coverage_status: `{review_summary['detail_coverage_status']}`")
    lines.append(f"- finding_count_detected: `{review_summary['finding_count_detected']}`")
    lines.append(f"- decision_confidence: `{review_summary['decision_confidence']}`")
    lines.append(f"- coverage_confidence: `{review_summary['coverage_confidence']}`")
    lines.append("")
    lines.append("## Blocking Reasons")
    lines.append("")
    if review_summary["blocking_reasons"]:
        for item in review_summary["blocking_reasons"]:
            lines.append(f"- `{item['code']}`: {item['message']}")
    else:
        lines.append("- none")
    lines.append("")
    lines.append("## Missing Evidence For Future Promotion")
    lines.append("")
    if review_summary["missing_evidence"]:
        for item in review_summary["missing_evidence"]:
            lines.append(f"- `{item['code']}`: {item['note']}")
    else:
        lines.append("- none")
    lines.append("")
    lines.append("## Reviewer Checklist")
    lines.append("")
    for item in review_summary["review_checklist"]:
        lines.append(f"- `{item['check_id']}` [{item['status']}]: {item['label']} ({item['note']})")
    lines.append("")
    lines.append("## Recommended Next Actions")
    lines.append("")
    if review_summary["recommended_next_actions"]:
        for item in review_summary["recommended_next_actions"]:
            lines.append(f"- `{item['code']}`: {item['action']}")
    else:
        lines.append("- none")
    lines.append("")
    lines.append("## Referenced Artifacts")
    lines.append("")
    for item in review_summary["referenced_artifacts"]:
        lines.append(f"- `{item['artifact_id']}`: `{item['path']}`")
        lines.append(f"  {item['note']}")
    lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def _derive_review_status(*, promotion_status: str, evidence_class: str) -> str:
    if promotion_status == PROMOTION_STATUS_BLOCKED and evidence_class == EVIDENCE_CLASS_SUMMARY_ONLY:
        return REVIEW_STATUS_BLOCKED_SUMMARY_ONLY
    if promotion_status == PROMOTION_STATUS_BLOCKED and evidence_class == EVIDENCE_CLASS_SUMMARY_NONZERO:
        return REVIEW_STATUS_BLOCKED_MISSING_DETAIL
    if promotion_status == PROMOTION_STATUS_ELIGIBLE and evidence_class == EVIDENCE_CLASS_DETAIL_READY:
        return REVIEW_STATUS_READY_FOR_MANUAL_CONFIRMATION
    if promotion_status == PROMOTION_STATUS_BLOCKED:
        return REVIEW_STATUS_REVIEW_REQUIRED
    if promotion_status == PROMOTION_STATUS_UNKNOWN or evidence_class == EVIDENCE_CLASS_UNKNOWN:
        return REVIEW_STATUS_UNKNOWN
    return REVIEW_STATUS_REVIEW_REQUIRED


def _decorate_blocking_reasons(value: Any) -> list[dict[str, str]]:
    if not isinstance(value, list):
        return []
    items: list[dict[str, str]] = []
    for record in value:
        if not isinstance(record, Mapping):
            continue
        code = _text(record.get("code"))
        message = _text(record.get("message"))
        if code is None or message is None:
            continue
        items.append(
            {
                "code": code,
                "label": BLOCKING_REASON_LABELS.get(code, code.replace("_", " ")),
                "message": message,
                "note": message,
            }
        )
    return items


def _build_missing_evidence(
    *,
    evidence_class: str,
    finding_detail_presence: bool,
    request_response_presence: bool,
    evidence_presence: bool,
) -> list[dict[str, str]]:
    if evidence_class == EVIDENCE_CLASS_DETAIL_READY:
        return []

    records: list[dict[str, str]] = []
    finding_note = (
        "The live payload is a non-zero summary but no detail capture. Finding-level records are required."
        if evidence_class == EVIDENCE_CLASS_SUMMARY_NONZERO
        else "No finding-level records were captured in the current live payload."
    )

    if not finding_detail_presence:
        records.append(
            {
                "code": "finding_detail_records",
                "label": "Finding detail records",
                "note": finding_note,
            }
        )
        records.append(
            {
                "code": "stable_finding_identifiers",
                "label": "Stable finding identifiers",
                "note": "Stable finding identifiers cannot be confirmed until finding-level records exist.",
            }
        )
    if not request_response_presence:
        records.append(
            {
                "code": "request_response_records",
                "label": "Request/response records",
                "note": "No request/response records or equivalent request references are present.",
            }
        )
    if not evidence_presence:
        records.append(
            {
                "code": "per_finding_evidence",
                "label": "Per-finding evidence",
                "note": "No per-finding evidence items, screenshots, or equivalent evidence references are present.",
            }
        )
    return records


def _build_recommended_next_actions(
    *,
    promotion_decision: Mapping[str, Any],
    evidence_class: str,
) -> list[dict[str, str]]:
    actions: list[dict[str, str]] = []
    seen: set[str] = set()

    combined_codes = _string_list(promotion_decision.get("advisory_actions")) + _string_list(
        promotion_decision.get("required_for_future_promotion")
    )
    if evidence_class in {EVIDENCE_CLASS_SUMMARY_ONLY, EVIDENCE_CLASS_SUMMARY_NONZERO}:
        combined_codes.extend(["keep_run_intake_only", "capture_future_finding_level_live_sample"])

    for code in combined_codes:
        if code in seen:
            continue
        seen.add(code)
        action = ACTION_LABELS.get(code, code.replace("_", " "))
        actions.append({"code": code, "action": action, "note": action})
    return actions


def _build_review_checklist(
    *,
    promotion_decision: Mapping[str, Any],
    validation_status: str,
    adapter_applied: bool,
    finding_count_detected: int,
    evidence_class: str,
    finding_detail_presence: bool,
    request_response_presence: bool,
    reproducibility_reference_present: bool,
    referenced_artifacts: list[dict[str, str]],
) -> list[dict[str, str]]:
    artifact_path = _artifact_path_map(referenced_artifacts)
    promotion_allowed = bool(promotion_decision.get("case_input_promotion_allowed"))

    finding_detail_status = CHECK_STATUS_MET if finding_detail_presence else CHECK_STATUS_MISSING
    request_response_status = CHECK_STATUS_MET if request_response_presence else CHECK_STATUS_MISSING
    if evidence_class == EVIDENCE_CLASS_SUMMARY_NONZERO and not finding_detail_presence:
        finding_detail_status = CHECK_STATUS_BLOCKED
        request_response_status = CHECK_STATUS_BLOCKED
    reproducibility_status = CHECK_STATUS_MET if reproducibility_reference_present else CHECK_STATUS_MISSING

    return [
        {
            "check_id": "validation_completed",
            "label": "Validation artifact is present",
            "status": CHECK_STATUS_MET if validation_status != "unknown" else CHECK_STATUS_MISSING,
            "evidence_source": artifact_path.get("format_observation", "derived/format-observation.json"),
            "note": f"validation_status={validation_status}",
        },
        {
            "check_id": "adapter_applied_or_not_needed",
            "label": "Adapter applied or canonical payload already available",
            "status": CHECK_STATUS_MET if adapter_applied or evidence_class == EVIDENCE_CLASS_DETAIL_READY else CHECK_STATUS_MISSING,
            "evidence_source": artifact_path.get("shape_bridge_report", "derived/shape-bridge-report.json"),
            "note": "adapter path confirmed" if adapter_applied else "adapter application was not confirmed in the current artifacts",
        },
        {
            "check_id": "promotion_decision_present",
            "label": "Promotion decision artifact is present",
            "status": CHECK_STATUS_MET,
            "evidence_source": artifact_path.get("promotion_decision", "derived/promotion-decision.json"),
            "note": "promotion decision available for review handoff",
        },
        {
            "check_id": "finding_detail_records_present",
            "label": "Finding detail records are available",
            "status": finding_detail_status,
            "evidence_source": artifact_path.get("format_observation", "derived/format-observation.json"),
            "note": f"finding_count_detected={finding_count_detected}",
        },
        {
            "check_id": "request_response_evidence_present",
            "label": "Request/response evidence references are available",
            "status": request_response_status,
            "evidence_source": artifact_path.get("shape_bridge_report", "derived/shape-bridge-report.json"),
            "note": "No request/response evidence is present in the current artifacts."
                if not request_response_presence
                else "Request/response evidence detected.",
        },
        {
            "check_id": "evidence_reproducibility_reference_present",
            "label": "Evidence reproducibility reference is available",
            "status": reproducibility_status,
            "evidence_source": artifact_path.get("provenance", "derived/provenance.json"),
            "note": (
                "Derived provenance and validator references exist for reviewer handoff."
                if reproducibility_reference_present
                else "No reproducibility reference is available for reviewer handoff."
            ),
        },
        {
            "check_id": "case_input_promotion_allowed",
            "label": "Case input promotion is allowed",
            "status": CHECK_STATUS_MET if promotion_allowed else CHECK_STATUS_BLOCKED,
            "evidence_source": artifact_path.get("promotion_decision", "derived/promotion-decision.json"),
            "note": "Promotion remains blocked." if not promotion_allowed else "Promotion is eligible for manual confirmation.",
        },
    ]


def _build_reviewer_summary(
    *,
    run_id: str,
    validation_status: str,
    linkage_status: str,
    promotion_status: str,
    evidence_class: str,
    finding_count_detected: int,
    summary_total_vulnerabilities: int | None,
    case_input_promotion_allowed: bool,
) -> str:
    if evidence_class == EVIDENCE_CLASS_SUMMARY_ONLY:
        lines = [
            f"Run {run_id} remains blocked for promotion review.",
            f"Validation status is {validation_status} and linkage status is {linkage_status}.",
            f"Promotion status is {promotion_status}, and case input promotion allowed is {str(case_input_promotion_allowed).lower()}.",
            f"Evidence class is {evidence_class} with finding_count_detected={finding_count_detected}.",
            "The current live payload is summary-only smoke linkage evidence, not a finding-ready capture.",
            "No request/response records or per-finding evidence references are present.",
            "Do not promote this run into case input.",
            "A future approved live capture must include finding detail, request/response, and per-finding evidence before promotion can be reconsidered.",
        ]
    elif evidence_class == EVIDENCE_CLASS_SUMMARY_NONZERO:
        total = summary_total_vulnerabilities if summary_total_vulnerabilities is not None else 0
        lines = [
            f"Run {run_id} remains blocked for promotion review.",
            f"Validation status is {validation_status} and promotion status is {promotion_status}.",
            f"Evidence class is {evidence_class}.",
            f"This is a non-zero summary but no detail live capture: summary_total_vulnerabilities={total} and finding_count_detected={finding_count_detected}.",
            "No request/response records or per-finding evidence references are present.",
            "Do not promote this run into case input.",
            "A future approved live capture must include finding detail, request/response, and per-finding evidence before promotion can be reconsidered.",
        ]
    elif promotion_status == PROMOTION_STATUS_ELIGIBLE:
        lines = [
            f"Run {run_id} is ready for manual confirmation review.",
            f"Validation status is {validation_status} and linkage status is {linkage_status}.",
            f"Promotion status is {promotion_status}, and case input promotion allowed is {str(case_input_promotion_allowed).lower()}.",
            "Finding detail records and evidence references appear to be present.",
            "Manual confirmation is still required before any operator promotion step.",
        ]
    else:
        lines = [
            f"Run {run_id} requires manual review because the promotion state could not be determined safely.",
            f"Validation status is {validation_status} and linkage status is {linkage_status}.",
            "Inspect the validation and promotion artifacts before taking any downstream action.",
        ]
    return "\n".join(lines)


def _build_key_facts(
    *,
    validation_status: str,
    linkage_status: str,
    observation_kind: str,
    promotion_status: str,
    case_input_promotion_allowed: bool,
    evidence_class: str,
    detail_coverage_status: str,
    finding_count_detected: int,
    coverage_confidence: str,
    decision_confidence: str,
    adapter_applied: bool,
    raw_evidence_immutable: bool,
    guessed_fields_used: bool,
    provenance: Mapping[str, Any],
    live_raw_shape_summary: Mapping[str, Any] | None,
    format_observation: Mapping[str, Any],
) -> list[dict[str, Any]]:
    top_level_keys = live_raw_shape_summary.get("top_level_keys") if isinstance(live_raw_shape_summary, Mapping) else None
    if isinstance(top_level_keys, list):
        top_level_key_count = len(top_level_keys)
    else:
        detected_top_level_keys = format_observation.get("detected_top_level_keys")
        top_level_key_count = len(detected_top_level_keys) if isinstance(detected_top_level_keys, list) else 0

    provenance_outputs = provenance.get("outputs")
    provenance_output_count = len(provenance_outputs) if isinstance(provenance_outputs, list) else 0

    return [
        {"code": "validation_status", "value": validation_status, "note": "Validation result for the current run."},
        {"code": "linkage_status", "value": linkage_status, "note": "Exporter to observation linkage state."},
        {"code": "observation_kind", "value": observation_kind, "note": "Observation class derived from the live payload."},
        {"code": "promotion_status", "value": promotion_status, "note": "Promotion decision remains independent from validation."},
        {
            "code": "case_input_promotion_allowed",
            "value": case_input_promotion_allowed,
            "note": "Whether cases/web/<case-id>/input promotion is currently allowed.",
        },
        {"code": "evidence_class", "value": evidence_class, "note": "Current live evidence class used for reviewer handoff."},
        {"code": "detail_coverage_status", "value": detail_coverage_status, "note": "Finding detail coverage state."},
        {"code": "finding_count_detected", "value": finding_count_detected, "note": "Detected finding count in format-observation."},
        {"code": "coverage_confidence", "value": coverage_confidence, "note": "Coverage confidence reported by the validation bridge."},
        {"code": "decision_confidence", "value": decision_confidence, "note": "Confidence of the promotion decision."},
        {"code": "adapter_applied", "value": adapter_applied, "note": "Whether the known live adapter path was observed."},
        {"code": "raw_evidence_immutable", "value": raw_evidence_immutable, "note": "Raw evidence remains immutable."},
        {"code": "guessed_fields_used", "value": guessed_fields_used, "note": "No guessed finding fields should be introduced."},
        {
            "code": "provenance_output_count",
            "value": provenance_output_count,
            "note": "Number of derived outputs recorded in provenance.",
        },
        {
            "code": "live_raw_top_level_key_count",
            "value": top_level_key_count,
            "note": "Top-level key count observed in the live payload.",
        },
    ]


def _build_referenced_artifacts(
    *,
    repo_root: Path,
    run_dir: Path,
    promotion_decision: Mapping[str, Any],
) -> list[dict[str, str]]:
    records: list[dict[str, str]] = []
    seen: set[str] = set()
    source_paths = promotion_decision.get("source_paths")
    if isinstance(source_paths, Mapping):
        for artifact_id, note in (
            ("manifest", "Run manifest used as immutable review input."),
            ("notes", "Run notes used for operator handoff context."),
            ("format_observation", "Validation observation consumed by the review renderer."),
            ("shape_bridge_report", "Bridge report describing validation and promotion readiness separation."),
            ("live_raw_shape_summary", "Shape summary describing the live raw payload structure."),
            ("provenance", "Derived provenance and lineage for the current run."),
        ):
            path_text = _text(source_paths.get(artifact_id))
            if path_text is None:
                continue
            records.append({"artifact_id": artifact_id, "path": path_text, "note": note})
            seen.add(artifact_id)

    derived_dir = run_dir / "derived"
    fallback_records = [
        ("promotion_decision", derived_dir / "promotion-decision.json", "Promotion decision used as direct review input."),
        ("validator_result", derived_dir / "validate-live-hexstrike.txt", "Stored validator output for the validated live run."),
        ("intake_raw", run_dir / "raw" / "hexstrike-result.json", "Immutable live raw evidence retained under intake only."),
    ]
    for artifact_id, path, note in fallback_records:
        if artifact_id in seen or not path.exists():
            continue
        records.append({"artifact_id": artifact_id, "path": _repo_relative(path, repo_root), "note": note})
        seen.add(artifact_id)
    return records


def _artifact_path_map(records: list[dict[str, str]]) -> dict[str, str]:
    return {
        item["artifact_id"]: item["path"]
        for item in records
        if "artifact_id" in item and "path" in item
    }


def _has_reproducibility_reference(records: list[dict[str, str]]) -> bool:
    artifact_ids = {item.get("artifact_id") for item in records}
    return "provenance" in artifact_ids or "validator_result" in artifact_ids


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _promotion_status(value: Any) -> str:
    text = _text(value)
    if text in {PROMOTION_STATUS_BLOCKED, PROMOTION_STATUS_ELIGIBLE, PROMOTION_STATUS_UNKNOWN}:
        return text
    return PROMOTION_STATUS_UNKNOWN


def _evidence_class(value: Any) -> str:
    text = _text(value)
    if text in {
        EVIDENCE_CLASS_SUMMARY_ONLY,
        EVIDENCE_CLASS_SUMMARY_NONZERO,
        EVIDENCE_CLASS_DETAIL_READY,
        EVIDENCE_CLASS_UNKNOWN,
    }:
        return text
    return EVIDENCE_CLASS_UNKNOWN


def _confidence(value: str | None, *, default: str) -> str:
    if value in {"high", "medium", "low", "unknown"}:
        return value
    return default


def _repo_relative(path: Path, repo_root: Path) -> str:
    try:
        return path.resolve().relative_to(repo_root.resolve()).as_posix()
    except ValueError:
        return path.resolve().as_posix()


def _load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise HexStrikeIntakeError(f"Expected JSON object at {path}") from exc
    if not isinstance(payload, dict):
        raise HexStrikeIntakeError(f"Expected JSON object at {path}")
    return payload


def _maybe_load_json(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    return _load_json(path)


def _write_json(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _generated_at() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


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
    parsed = _int_or_none(value)
    return parsed if parsed is not None else 0


def _int_or_none(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None
