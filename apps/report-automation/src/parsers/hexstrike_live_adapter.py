"""Adapter-first bridge for known live HexStrike raw payloads."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable, Mapping

from src.intake.hexstrike_intake import HexStrikeIntakeError, HexStrikeIntakeRun, load_hexstrike_intake_run
from src.parsers.hexstrike_observation import build_hexstrike_format_observation


REQUIRED_LIVE_KEYS = {"scan_type", "success", "summary", "target", "timestamp"}
CANONICAL_ROOT_GROUPS = ("tool", "scan", "engagement", "findings")
ADAPTER_VERSION = "1.1"
SYNTHETIC_REHEARSAL_RUN = Path("intake") / "synthetic" / "hexstrike-ai" / "rehearsal-001"
COVERAGE_GAP_NO_DETAIL = "No per-finding request/response/evidence records were present in the smoke payload."
COVERAGE_GAP_NONZERO_NO_DETAIL = "live raw summary reports vulnerabilities but no finding detail records exist"
SUMMARY_NOTE_ZERO_DETAIL = (
    "The payload is a summary-only smoke result. An empty findings array can be derived safely because "
    "total_vulnerabilities is 0."
)
SUMMARY_NOTE_NONZERO_NO_DETAIL = (
    "The payload reports vulnerabilities only through summary counters, so per-finding objects cannot be derived safely."
)
SUMMARY_ONLY_REASON_CODES = [
    "summary_only_payload",
    "zero_vuln_smoke_bridge",
    "no_finding_level_payload",
    "no_request_response_evidence",
]
SUMMARY_ONLY_BLOCKER_CODES = [
    "promotion_blocked_summary_only",
    "finding_level_detail_required",
    "request_response_evidence_required",
]
SUMMARY_ONLY_REQUIRED_FOR_PROMOTION = [
    "finding_level_payload",
    "per_finding_request_response",
    "per_finding_evidence",
    "reviewed_live_delta_after_future_capture",
]


def is_known_live_hexstrike_shape(payload: Mapping[str, Any]) -> bool:
    """Return True when a payload matches the confirmed live smoke shape."""

    keys = set(payload.keys())
    if set(CANONICAL_ROOT_GROUPS).issubset(keys):
        return False
    return REQUIRED_LIVE_KEYS.issubset(keys) and isinstance(payload.get("summary"), Mapping)


def bridge_live_hexstrike_run(intake_run: HexStrikeIntakeRun) -> dict[str, Any]:
    """Bridge known live raw payloads to canonical snapshots and a coverage report."""

    baseline = _load_first_baseline(intake_run.baseline_files)
    payload_sources: list[dict[str, Any]] = []
    report_entries: list[dict[str, Any]] = []
    adapted_payload_count = 0

    for raw_payload in intake_run.raw_payloads:
        source_path = raw_payload.repo_relative()
        payload = raw_payload.payload
        if is_known_live_hexstrike_shape(payload):
            bridged = _bridge_known_live_payload(
                payload,
                intake_run=intake_run,
                baseline=baseline,
                source_path=source_path,
            )
            payload_sources.append(
                {
                    "source": source_path,
                    "payload": payload,
                    "validation_payload": bridged["canonical_snapshot"],
                    "additional_warnings": bridged["observation_warnings"],
                }
            )
            report_entries.append(bridged["report_entry"])
            adapted_payload_count += 1
            continue

        payload_sources.append({"source": source_path, "payload": payload})
        report_entries.append(
            {
                "source_path": source_path,
                "known_live_shape": False,
                "adapter_applied": False,
                "summary_only_payload": False,
                "summary_total_vulnerabilities": None,
                "summary_breakdown_state": None,
                "finding_detail_presence": False,
                "request_response_presence": False,
                "evidence_presence": False,
                "raw_top_level_keys": sorted(str(key) for key in payload.keys()),
                "canonical_mapped_fields": {},
                "unmapped_fields": [],
                "null_filled_required_fields": [],
                "adapter_warnings": [],
                "coverage_gaps": [],
                "coverage_confidence": "high",
                "guessed_fields_absent": True,
            }
        )

    bridge_report = _build_shape_bridge_report(
        intake_run=intake_run,
        baseline=baseline,
        payload_entries=report_entries,
        adapted_payload_count=adapted_payload_count,
    )
    return {
        "payload_sources": payload_sources,
        "shape_bridge_report": bridge_report,
        "adapter_applied": adapted_payload_count > 0,
    }


def _bridge_known_live_payload(
    payload: Mapping[str, Any],
    *,
    intake_run: HexStrikeIntakeRun,
    baseline: Mapping[str, Any] | None,
    source_path: str,
) -> dict[str, Any]:
    warnings: list[str] = []
    coverage_gaps: list[str] = []
    null_filled_required_fields: list[str] = []

    summary = payload.get("summary")
    if not isinstance(summary, Mapping):
        summary = {}
        warnings.append("raw.summary is not an object")
        coverage_gaps.append("raw.summary could not be parsed as an object")

    bridge_gate = _summary_only_bridge_gate(summary)
    if not bridge_gate["allowed"]:
        raise HexStrikeIntakeError(_format_bridge_gate_error(source_path, bridge_gate))
    total_vulnerabilities = int(bridge_gate["total_vulnerabilities"])
    breakdown_state = str(bridge_gate["breakdown_state"])

    live_smoke_run = intake_run.manifest.get("live_smoke_run")
    live_smoke_parameters = None
    live_smoke_tool = None
    live_smoke_execution_mode = None
    if isinstance(live_smoke_run, Mapping):
        live_smoke_parameters = live_smoke_run.get("parameters")
        live_smoke_tool = _text(live_smoke_run.get("tool"))
        live_smoke_execution_mode = _text(live_smoke_run.get("execution_mode"))

    selected_entrypoint = _text(_path_get(baseline, "execution_feasibility.selected_smoke_entrypoint"))
    selected_parameters = _path_get(baseline, "execution_feasibility.selected_smoke_parameters")
    tool_source = _text(intake_run.manifest.get("source"))
    if tool_source is None:
        tool_source = intake_run.integration
    engagement_target = _coalesce(
        _text(payload.get("target")),
        _text(intake_run.manifest.get("target_url")),
    )
    if engagement_target is None:
        coverage_gaps.append("target URL unavailable in raw.target and manifest.target_url")
    if total_vulnerabilities == 0:
        coverage_gaps.append(COVERAGE_GAP_NO_DETAIL)

    canonical_snapshot = {
        "tool": {
            "integration": intake_run.integration,
            "source": tool_source,
            "entrypoint": _coalesce(live_smoke_tool, selected_entrypoint),
            "execution_mode": live_smoke_execution_mode,
        },
        "scan": {
            "scan_type": _text(payload.get("scan_type")),
            "success": payload.get("success") if isinstance(payload.get("success"), bool) else None,
            "timestamp": _text(payload.get("timestamp")),
            "summary": dict(summary),
            "parameters": live_smoke_parameters if isinstance(live_smoke_parameters, Mapping) else selected_parameters,
        },
        "engagement": {
            "run_id": intake_run.run_id,
            "target": engagement_target,
            "mode": intake_run.mode,
            "target_name": _text(intake_run.manifest.get("target_name")),
            "observed_entry_route": _text(intake_run.manifest.get("observed_entry_route")),
        },
        "findings": [],
    }

    if canonical_snapshot["scan"]["success"] is None:
        coverage_gaps.append("scan.success unavailable or not boolean in live raw")

    mapped_fields = {
        "tool.integration": "manifest.integration",
        "tool.source": "manifest.source",
        "tool.entrypoint": "manifest.live_smoke_run.tool or runtime-baseline.execution_feasibility.selected_smoke_entrypoint",
        "tool.execution_mode": "manifest.live_smoke_run.execution_mode",
        "scan.scan_type": "raw.scan_type",
        "scan.success": "raw.success",
        "scan.timestamp": "raw.timestamp",
        "scan.summary": "raw.summary",
        "scan.parameters": "manifest.live_smoke_run.parameters or runtime-baseline.execution_feasibility.selected_smoke_parameters",
        "engagement.run_id": "manifest.run_id",
        "engagement.target": "raw.target or manifest.target_url",
        "engagement.mode": "manifest.mode",
        "engagement.target_name": "manifest.target_name",
        "engagement.observed_entry_route": "manifest.observed_entry_route",
        "findings": "empty array preserved because live raw exposes no finding records",
    }

    report_entry = {
        "source_path": source_path,
        "known_live_shape": True,
        "adapter_applied": True,
        "summary_only_payload": True,
        "summary_total_vulnerabilities": total_vulnerabilities,
        "summary_breakdown_state": breakdown_state,
        "finding_detail_presence": False,
        "request_response_presence": False,
        "evidence_presence": False,
        "raw_top_level_keys": sorted(str(key) for key in payload.keys()),
        "canonical_mapped_fields": mapped_fields,
        "unmapped_fields": [],
        "null_filled_required_fields": sorted(dict.fromkeys(null_filled_required_fields)),
        "adapter_warnings": sorted(dict.fromkeys(warnings)),
        "coverage_gaps": sorted(dict.fromkeys(coverage_gaps)),
        "coverage_confidence": _coverage_confidence(null_filled_required_fields, coverage_gaps),
        "guessed_fields_absent": True,
    }
    observation_warnings = [
        f"Summary-only live payload detected: {source_path} contains no wrapper or embedded JSON envelope.",
        (
            "Derived root groups from raw summary fields and intake metadata because the live payload does not natively "
            "expose tool/scan/engagement/findings."
        ),
    ]
    if total_vulnerabilities == 0:
        observation_warnings.append(
            f"Derived empty findings array because {source_path}:$.summary.total_vulnerabilities == 0 and no per-finding objects were present."
        )
    return {
        "canonical_snapshot": canonical_snapshot,
        "report_entry": report_entry,
        "observation_warnings": observation_warnings,
    }


def _build_shape_bridge_report(
    *,
    intake_run: HexStrikeIntakeRun,
    baseline: Mapping[str, Any] | None,
    payload_entries: Iterable[Mapping[str, Any]],
    adapted_payload_count: int,
) -> dict[str, Any]:
    entries = [dict(entry) for entry in payload_entries]
    all_keys = sorted({key for entry in entries for key in entry.get("raw_top_level_keys", [])})
    all_unmapped = sorted({item for entry in entries for item in entry.get("unmapped_fields", [])})
    all_null_fills = sorted(
        {item for entry in entries for item in entry.get("null_filled_required_fields", [])}
    )
    all_warnings = sorted({item for entry in entries for item in entry.get("adapter_warnings", [])})
    all_gaps = sorted({item for entry in entries for item in entry.get("coverage_gaps", [])})

    summary = {
        "payload_count": len(entries),
        "adapted_payload_count": adapted_payload_count,
        "coverage_confidence": _overall_confidence(entries),
        "coverage_gap_count": len(all_gaps),
        "warning_count": len(all_warnings),
        "guessed_fields_absent": True,
    }
    status = _build_bridge_status(entries)

    return {
        "schema_version": "1.0",
        "run_id": intake_run.run_id,
        "integration": intake_run.integration,
        "mode": intake_run.mode,
        "adapter_version": ADAPTER_VERSION,
        "runtime_baseline_path": intake_run.repo_relative(intake_run.baseline_files[0])
        if intake_run.baseline_files
        else None,
        "bridge_contract": {
            "adapter_scope": "summary-only-zero-finding-live-smoke",
            "success_conditions": [
                "actual live payload shape is summary-only and matches the confirmed root keys",
                "summary.total_vulnerabilities is a non-negative integer",
                "summary.total_vulnerabilities equals 0",
                "finding-level objects are absent in the raw payload",
                "summary.vulnerability_breakdown is missing, empty, or contains only zero counts",
            ],
            "fail_fast_conditions": [
                "summary.total_vulnerabilities is missing, null, non-numeric, or negative",
                "summary.total_vulnerabilities is greater than 0 while finding-level objects are absent",
                "summary.vulnerability_breakdown contains positive counts while total_vulnerabilities is 0",
                "summary.vulnerability_breakdown contains ambiguous or non-numeric counts",
            ],
            "preservation_guarantees": [
                "raw payload is not overwritten",
                "raw top-level unknown fields stay observable through format-observation unknown_fields",
                "parser_warnings, unknown_fields, and detected_top_level_keys remain intact",
                "no guessed finding object, request, response, or evidence fields are invented",
            ],
        },
        "status": status,
        "raw_top_level_keys": all_keys,
        "canonical_root_groups": list(CANONICAL_ROOT_GROUPS),
        "unmapped_fields": all_unmapped,
        "null_filled_required_fields": all_null_fills,
        "adapter_warnings": all_warnings,
        "coverage_gaps": all_gaps,
        "guessed_fields_absent": True,
        "payloads": entries,
        "coverage_summary": summary,
        "baseline_keys": sorted(str(key) for key in baseline.keys()) if isinstance(baseline, Mapping) else [],
    }


def _load_first_baseline(paths: list[Path]) -> dict[str, Any] | None:
    for path in paths:
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(payload, dict):
            return payload
    return None


def summarize_live_raw_shape(intake_run: HexStrikeIntakeRun) -> dict[str, Any]:
    """Summarize the first raw live payload without rewriting the raw source."""

    if not intake_run.raw_payloads:
        raise ValueError("intake_run.raw_payloads must contain at least one payload")

    raw_payload = intake_run.raw_payloads[0]
    payload = raw_payload.payload
    summary = payload.get("summary") if isinstance(payload.get("summary"), Mapping) else {}
    total_vulnerabilities = _non_negative_int_or_none(summary.get("total_vulnerabilities"))
    bridge_gate = _summary_only_bridge_gate(summary)

    if set(CANONICAL_ROOT_GROUPS).issubset(payload.keys()):
        adapter_feasibility = "yes"
        finding_count_detection_method = "len($.findings)"
        notes = ["The payload already exposes the current validator root groups directly."]
    elif is_known_live_hexstrike_shape(payload) and bridge_gate["allowed"]:
        adapter_feasibility = "yes"
        finding_count_detection_method = "$.summary.total_vulnerabilities"
        notes = [
            "No MCP response wrapper, content array, stringified JSON blob, or result/payload envelope was found at the root.",
            SUMMARY_NOTE_ZERO_DETAIL,
        ]
    elif is_known_live_hexstrike_shape(payload):
        adapter_feasibility = "no"
        finding_count_detection_method = "$.summary.total_vulnerabilities"
        notes = [
            "No MCP response wrapper, content array, stringified JSON blob, or result/payload envelope was found at the root.",
            str(bridge_gate["message"]),
        ]
    else:
        adapter_feasibility = "partial"
        finding_count_detection_method = "unavailable"
        notes = [
            "The payload does not match the current validator contract and did not match the supported summary-only live adapter shape.",
        ]

    return {
        "raw_file": raw_payload.repo_relative(),
        "top_level_keys": sorted(str(key) for key in payload.keys()),
        "summary_total_vulnerabilities": total_vulnerabilities,
        "detail_records_present": False,
        "wrapper_detected": False,
        "wrapper_type": "none",
        "possible_payload_path": "$",
        "finding_count_detection_method": finding_count_detection_method,
        "candidate_paths_for_tool_scan_engagement_findings": {
            "tool": [
                "$.tool",
                "manifest.json:$.source",
                "manifest.json:$.live_smoke_run.tool",
                "raw/runtime-baseline.json:$.execution_feasibility.selected_smoke_entrypoint",
            ],
            "scan": [
                "$.scan",
                "$.scan_type",
                "$.timestamp",
                "$.summary",
                "manifest.json:$.live_smoke_run.parameters",
            ],
            "engagement": [
                "$.engagement",
                "$.target",
                "manifest.json:$.target_name",
                "manifest.json:$.target_url",
                "manifest.json:$.observed_entry_route",
            ],
            "findings": [
                "$.findings",
                "$.summary.total_vulnerabilities",
                "$.summary.vulnerability_breakdown",
            ],
        },
        "candidate_request_response_paths": [],
        "candidate_evidence_paths": [],
        "unknown_topology_notes": notes,
        "adapter_feasibility": adapter_feasibility,
        "detail_coverage_status": _detail_coverage_status(payload, bridge_gate),
    }


def build_synthetic_live_delta(
    live_run: HexStrikeIntakeRun,
    *,
    repo_root: Path,
    live_observation: Mapping[str, Any],
    live_raw_shape_summary: Mapping[str, Any],
    bridge_report: Mapping[str, Any],
) -> dict[str, Any]:
    """Compare the known live smoke payload against the canonical synthetic rehearsal."""

    synthetic_run = load_hexstrike_intake_run((repo_root / SYNTHETIC_REHEARSAL_RUN).resolve(), repo_root)
    synthetic_observation = build_hexstrike_format_observation(synthetic_run)
    synthetic_payload = synthetic_run.raw_payloads[0].payload
    synthetic_finding = _first_finding(synthetic_payload)
    synthetic_request_response_paths = []
    if "request" in synthetic_finding:
        synthetic_request_response_paths.append("$.findings[0].request")
    if "response" in synthetic_finding:
        synthetic_request_response_paths.append("$.findings[0].response")

    return {
        "schema_version": "1.0",
        "comparison_kind": "synthetic-vs-live-observation-delta",
        "synthetic_run_id": synthetic_run.run_id,
        "live_run_id": live_run.run_id,
        "linkage_comparison_succeeded": True,
        "status_reference": {
            "linkage_status": bridge_report["status"]["linkage_status"],
            "validation_status": bridge_report["status"]["validation_status"],
            "observation_kind": bridge_report["status"]["observation_kind"],
            "report_ready": bridge_report["status"]["report_ready"],
            "promotable_to_cases": bridge_report["status"]["promotable_to_cases"],
        },
        "comparison": {
            "top_level_keys": {
                "synthetic": sorted(str(key) for key in synthetic_payload.keys()),
                "live": list(live_raw_shape_summary["top_level_keys"]),
            },
            "finding_count_detection": {
                "synthetic_method": "len($.findings)",
                "synthetic_detected": int(synthetic_observation["finding_count_detected"]),
                "live_method": str(live_raw_shape_summary["finding_count_detection_method"]),
                "live_detected": int(live_observation["finding_count_detected"]),
            },
            "finding_identifier_fields": {
                "synthetic": [field for field in ("id", "title", "name") if field in synthetic_finding],
                "live": [],
            },
            "severity_status_enum": {
                "synthetic": {
                    "severity_values": _present_string_values(synthetic_finding, ("severity", "risk", "rating")),
                    "status_values": _present_string_values(synthetic_finding, ("status",)),
                    "severity_field_shapes": dict(synthetic_observation["evidence_shape_summary"]["severity_field_shapes"]),
                    "status_field_shapes": dict(synthetic_observation["evidence_shape_summary"]["status_field_shapes"]),
                },
                "live": {
                    "severity_values": [],
                    "status_values": [],
                    "severity_field_shapes": dict(live_observation["evidence_shape_summary"]["severity_field_shapes"]),
                    "status_field_shapes": dict(live_observation["evidence_shape_summary"]["status_field_shapes"]),
                },
            },
            "request_response_location": {
                "synthetic": synthetic_request_response_paths,
                "live": [],
            },
            "evidence_screenshot_structure": {
                "synthetic": {
                    "path": "$.findings[0].evidence" if "evidence" in synthetic_finding else None,
                    "evidence_field_shapes": dict(synthetic_observation["evidence_shape_summary"]["evidence_field_shapes"]),
                    "evidence_item_kinds": dict(synthetic_observation["evidence_shape_summary"]["evidence_item_kinds"]),
                },
                "live": {
                    "path": None,
                    "evidence_field_shapes": dict(live_observation["evidence_shape_summary"]["evidence_field_shapes"]),
                    "evidence_item_kinds": dict(live_observation["evidence_shape_summary"]["evidence_item_kinds"]),
                },
            },
            "unknown_fields": {
                "synthetic_count": len(synthetic_observation["unknown_fields"]),
                "synthetic_fields": _field_labels(synthetic_observation["unknown_fields"]),
                "live_count": len(live_observation["unknown_fields"]),
                "live_fields": _field_labels(live_observation["unknown_fields"]),
            },
            "missing_expected_fields": {
                "synthetic_count": len(synthetic_observation["missing_expected_fields"]),
                "live_count": len(live_observation["missing_expected_fields"]),
            },
            "parser_warnings": {
                "synthetic_count": len(synthetic_observation["parser_warnings"]),
                "synthetic_warnings": list(synthetic_observation["parser_warnings"]),
                "live_count": len(live_observation["parser_warnings"]),
                "live_warnings": list(live_observation["parser_warnings"]),
            },
        },
        "promotion_impact_summary": (
            "Linkage comparison succeeded, but promotion remains blocked because the live payload is summary-only "
            "and exposes no finding-level request, response, or evidence records."
        ),
        "conclusion": {
            "linkage_comparison_succeeded": True,
            "promotion_decision": "blocked",
            "promotion_decision_remains_blocked": True,
            "why_blocked": [
                "Live payload is summary-only and contains no finding-level objects.",
                "Live payload contains no request or response records.",
                "Live payload contains no evidence or screenshot records.",
                "Validator success confirms smoke linkage only, not report-ready case quality.",
            ],
        },
    }


def _path_get(payload: Mapping[str, Any] | None, dotted_path: str) -> Any:
    if not isinstance(payload, Mapping):
        return None
    current: Any = payload
    for part in dotted_path.split("."):
        if not isinstance(current, Mapping) or part not in current:
            return None
        current = current.get(part)
    return current


def _coverage_confidence(null_fills: list[str], gaps: list[str]) -> str:
    if gaps or len(null_fills) >= 3:
        return "medium"
    return "high"


def _overall_confidence(entries: list[dict[str, Any]]) -> str:
    if any(entry.get("coverage_confidence") == "medium" for entry in entries):
        return "medium"
    return "high"


def _pretty_integration_name(value: str) -> str:
    lowered = value.strip().lower()
    if lowered == "hexstrike-ai":
        return "HexStrike-AI"
    return value


def _coalesce(*values: Any) -> Any:
    for value in values:
        if _text(value) is not None:
            return value
    return None


def _text(value: Any) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        value = str(value)
    cleaned = value.strip()
    return cleaned or None


def _int_or_none(value: Any) -> int | None:
    if value is None:
        return None
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


def _non_negative_int_or_none(value: Any) -> int | None:
    parsed = _int_or_none(value)
    if parsed is None or parsed < 0:
        return None
    return parsed


def _summary_only_bridge_gate(summary: Mapping[str, Any]) -> dict[str, Any]:
    total_vulnerabilities = _non_negative_int_or_none(summary.get("total_vulnerabilities"))
    if total_vulnerabilities is None:
        return {
            "allowed": False,
            "code": "missing_or_invalid_total_vulnerabilities",
            "message": "summary.total_vulnerabilities must be a non-negative integer for the summary-only bridge.",
        }
    if total_vulnerabilities > 0:
        return {
            "allowed": False,
            "code": "positive_total_without_finding_objects",
            "message": "summary.total_vulnerabilities is greater than 0, but the live raw shape exposes no finding-level objects.",
        }

    breakdown = _analyze_breakdown(summary.get("vulnerability_breakdown"))
    if breakdown["ambiguous_paths"]:
        return {
            "allowed": False,
            "code": "ambiguous_vulnerability_breakdown",
            "message": (
                "summary.vulnerability_breakdown contains ambiguous counts at "
                + ", ".join(str(path) for path in breakdown["ambiguous_paths"])
                + "."
            ),
        }
    if breakdown["positive_paths"]:
        return {
            "allowed": False,
            "code": "summary_breakdown_nonzero_when_total_zero",
            "message": (
                "summary.total_vulnerabilities == 0 but summary.vulnerability_breakdown reports non-zero counts at "
                + ", ".join(str(path) for path in breakdown["positive_paths"])
                + "."
            ),
        }

    return {
        "allowed": True,
        "code": "zero_vuln_summary_only_bridge_allowed",
        "message": "summary-only zero-vulnerability bridge is allowed",
        "total_vulnerabilities": total_vulnerabilities,
        "breakdown_state": breakdown["state"],
    }


def _analyze_breakdown(value: Any) -> dict[str, Any]:
    positive_paths: list[str] = []
    ambiguous_paths: list[str] = []
    encountered_numeric = False

    def visit(current: Any, current_path: str) -> None:
        nonlocal encountered_numeric
        if current is None:
            return
        if isinstance(current, Mapping):
            for key, child in current.items():
                visit(child, f"{current_path}.{key}")
            return
        if isinstance(current, list):
            for index, child in enumerate(current):
                visit(child, f"{current_path}[{index}]")
            return

        parsed = _non_negative_int_or_none(current)
        if parsed is None:
            ambiguous_paths.append(current_path)
            return
        encountered_numeric = True
        if parsed > 0:
            positive_paths.append(current_path)

    if value is None:
        state = "missing"
    elif isinstance(value, Mapping) and not value:
        state = "empty"
    elif isinstance(value, list) and not value:
        state = "empty"
    else:
        visit(value, "$.summary.vulnerability_breakdown")
        if ambiguous_paths:
            state = "ambiguous"
        elif positive_paths:
            state = "nonzero"
        elif encountered_numeric:
            state = "all-zero"
        else:
            state = "empty"

    return {
        "state": state,
        "positive_paths": positive_paths,
        "ambiguous_paths": ambiguous_paths,
    }


def _format_bridge_gate_error(source_path: str, gate: Mapping[str, Any]) -> str:
    return f"{source_path}: summary-only live adapter blocked [{gate['code']}] {gate['message']}"


def _build_bridge_status(entries: list[dict[str, Any]]) -> dict[str, Any]:
    adapted_entries = [entry for entry in entries if entry.get("adapter_applied")]
    finding_detail_presence = any(bool(entry.get("finding_detail_presence")) for entry in adapted_entries)
    request_response_presence = any(bool(entry.get("request_response_presence")) for entry in adapted_entries)
    evidence_presence = any(bool(entry.get("evidence_presence")) for entry in adapted_entries)
    summary_only_payload = all(bool(entry.get("summary_only_payload")) for entry in adapted_entries) if adapted_entries else False

    if summary_only_payload and not finding_detail_presence:
        observation_kind = "summary-only-live-smoke"
        report_ready = False
        promotable_to_cases = False
        reason_codes = list(SUMMARY_ONLY_REASON_CODES)
        blocker_codes = list(SUMMARY_ONLY_BLOCKER_CODES)
        required_for_promotion = list(SUMMARY_ONLY_REQUIRED_FOR_PROMOTION)
    else:
        observation_kind = "finding-level-live"
        report_ready = True
        promotable_to_cases = True
        reason_codes = []
        blocker_codes = []
        required_for_promotion = []

    return {
        "linkage_status": "pass",
        "validation_status": "success",
        "observation_kind": observation_kind,
        "report_ready": report_ready,
        "promotable_to_cases": promotable_to_cases,
        "reason_codes": reason_codes,
        "blocker_codes": blocker_codes,
        "required_for_promotion": required_for_promotion,
        "evidence_presence": evidence_presence,
        "request_response_presence": request_response_presence,
        "finding_detail_presence": finding_detail_presence,
        "summary_only_payload": summary_only_payload,
        "adapter_applied": bool(adapted_entries),
    }


def _detail_coverage_status(payload: Mapping[str, Any], bridge_gate: Mapping[str, Any]) -> str:
    if set(CANONICAL_ROOT_GROUPS).issubset(payload.keys()):
        return "detail_ready"
    if is_known_live_hexstrike_shape(payload) and bridge_gate["allowed"]:
        return "zero_summary_no_detail"
    if is_known_live_hexstrike_shape(payload):
        return str(bridge_gate["code"])
    return "unknown"


def _first_finding(payload: Mapping[str, Any]) -> Mapping[str, Any]:
    findings = payload.get("findings")
    if isinstance(findings, list) and findings and isinstance(findings[0], Mapping):
        return findings[0]
    return {}


def _present_string_values(payload: Mapping[str, Any], aliases: Iterable[str]) -> list[str]:
    values: list[str] = []
    for alias in aliases:
        text = _text(payload.get(alias))
        if text is not None:
            values.append(text)
    return values


def _field_labels(records: Iterable[Mapping[str, Any]]) -> list[str]:
    labels: list[str] = []
    for record in records:
        path = _text(record.get("path")) or "$"
        field = _text(record.get("field")) or "unknown"
        labels.append(f"$.{field}" if path == "$" else f"{path}.{field}")
    return sorted(labels)
