"""FAIL-only adapter for KISA webserver raw records."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

SOURCE_TYPE = "kisa_webserver_raw_record"
CANDIDATE_STATUS = "candidate"
REVIEW_TYPE_MANUAL = "manual_check"
REVIEW_TYPE_COLLECTION_ERROR = "collection_error"
REVIEW_REASON_MANUAL = "manual_verification_required"
REVIEW_REASON_ERROR = "collection_or_execution_error"
RAW_STATUS_FAIL = "FAIL"
RAW_STATUS_MANUAL = "MANUAL"
RAW_STATUS_ERROR = "ERROR"
RAW_STATUS_NA = "N/A"
RAW_STATUS_PASS = "PASS"
CONFIDENCE_LOW = "low"


def adapt_kisa_webserver_raw_records(records: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """Bucket KISA webserver raw records into candidates, review, checklist, and pass records."""

    finding_candidates: list[dict[str, Any]] = []
    review_queue: list[dict[str, Any]] = []
    checklist_items: list[dict[str, Any]] = []
    pass_records: list[dict[str, Any]] = []

    summary = {
        "total": 0,
        "fail_count": 0,
        "manual_count": 0,
        "error_count": 0,
        "na_count": 0,
        "pass_count": 0,
        "low_confidence_count": 0,
    }

    for record in records:
        summary["total"] += 1
        if _text(record.get("parser_confidence")) == CONFIDENCE_LOW:
            summary["low_confidence_count"] += 1

        raw_status = _text(record.get("raw_status"))
        if raw_status == RAW_STATUS_FAIL:
            summary["fail_count"] += 1
            finding_candidates.append(_build_finding_candidate(record))
            continue
        if raw_status == RAW_STATUS_MANUAL:
            summary["manual_count"] += 1
            review_queue.append(_build_review_item(record, REVIEW_TYPE_MANUAL, REVIEW_REASON_MANUAL))
            continue
        if raw_status == RAW_STATUS_ERROR:
            summary["error_count"] += 1
            review_queue.append(
                _build_review_item(record, REVIEW_TYPE_COLLECTION_ERROR, REVIEW_REASON_ERROR)
            )
            continue
        if raw_status == RAW_STATUS_NA:
            summary["na_count"] += 1
            checklist_items.append(_build_checklist_item(record))
            continue

        summary["pass_count"] += 1
        pass_records.append(_build_pass_record(record))

    return {
        "finding_candidates": finding_candidates,
        "review_queue": review_queue,
        "checklist_items": checklist_items,
        "pass_records": pass_records,
        "summary": summary,
    }


def adapt_kisa_webserver_raw_record(record: Mapping[str, Any]) -> dict[str, Any]:
    """Adapt a single KISA webserver raw record using the same bundle shape."""

    return adapt_kisa_webserver_raw_records([record])


def _build_finding_candidate(record: Mapping[str, Any]) -> dict[str, Any]:
    triage_reasons = _build_triage_reasons(record)
    return {
        "source_type": SOURCE_TYPE,
        "platform": _text(record.get("platform")),
        "service_name": _text(record.get("service_name")),
        "hostname": _text(record.get("hostname")),
        "item_id": _text(record.get("item_id")),
        "item_key": _text(record.get("item_key")),
        "title": _text(record.get("title")),
        "severity": _text(record.get("severity")),
        "candidate_status": CANDIDATE_STATUS,
        "summary": _text(record.get("inspection_summary")),
        "evidence": _build_evidence(record),
        "executed_command": _text(record.get("executed_command")),
        "command_output": _text(record.get("command_output")),
        "config_path": _list_of_strings(record.get("config_path")),
        "registry_path": _list_of_strings(record.get("registry_path")),
        "guideline_reference": _text(record.get("guideline_reference")),
        "guideline_text": _text(record.get("guideline_text")),
        "parser_confidence": _text(record.get("parser_confidence")),
        "parse_warnings": _list_of_strings(record.get("parse_warnings")),
        "triage_required": bool(triage_reasons),
        "triage_reasons": triage_reasons,
        "raw_status": _text(record.get("raw_status")),
        "source_file": _text(record.get("source_file")),
        "timestamp": _text(record.get("timestamp")),
    }


def _build_review_item(
    record: Mapping[str, Any],
    review_type: str,
    review_reason: str,
) -> dict[str, Any]:
    return {
        "review_type": review_type,
        "review_reason": review_reason,
        "platform": _text(record.get("platform")),
        "service_name": _text(record.get("service_name")),
        "hostname": _text(record.get("hostname")),
        "item_id": _text(record.get("item_id")),
        "item_key": _text(record.get("item_key")),
        "title": _text(record.get("title")),
        "raw_status": _text(record.get("raw_status")),
        "severity": _text(record.get("severity")),
        "summary": _text(record.get("inspection_summary")),
        "executed_command": _text(record.get("executed_command")),
        "command_output": _text(record.get("command_output")),
        "config_path": _list_of_strings(record.get("config_path")),
        "registry_path": _list_of_strings(record.get("registry_path")),
        "parser_confidence": _text(record.get("parser_confidence")),
        "parse_warnings": _list_of_strings(record.get("parse_warnings")),
        "source_file": _text(record.get("source_file")),
        "timestamp": _text(record.get("timestamp")),
    }


def _build_checklist_item(record: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "platform": _text(record.get("platform")),
        "service_name": _text(record.get("service_name")),
        "hostname": _text(record.get("hostname")),
        "item_id": _text(record.get("item_id")),
        "item_key": _text(record.get("item_key")),
        "title": _text(record.get("title")),
        "raw_status": _text(record.get("raw_status")),
        "applicability": _text(record.get("applicability")),
        "summary": _text(record.get("inspection_summary")),
        "guideline_reference": _text(record.get("guideline_reference")),
        "source_file": _text(record.get("source_file")),
        "timestamp": _text(record.get("timestamp")),
    }


def _build_pass_record(record: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "source_type": SOURCE_TYPE,
        "platform": _text(record.get("platform")),
        "service_name": _text(record.get("service_name")),
        "hostname": _text(record.get("hostname")),
        "item_id": _text(record.get("item_id")),
        "item_key": _text(record.get("item_key")),
        "title": _text(record.get("title")),
        "severity": _text(record.get("severity")),
        "raw_status": _text(record.get("raw_status")),
        "summary": _text(record.get("inspection_summary")),
        "parser_confidence": _text(record.get("parser_confidence")),
        "parse_warnings": _list_of_strings(record.get("parse_warnings")),
        "source_file": _text(record.get("source_file")),
        "timestamp": _text(record.get("timestamp")),
    }


def _build_evidence(record: Mapping[str, Any]) -> dict[str, Any]:
    command_output = _text(record.get("command_output"))
    config_path = _list_of_strings(record.get("config_path"))
    registry_path = _list_of_strings(record.get("registry_path"))

    if command_output:
        return {
            "kind": "command_output",
            "summary": command_output.splitlines()[0],
            "artifacts": config_path or registry_path,
        }
    if config_path:
        return {
            "kind": "config_path",
            "summary": config_path[0],
            "artifacts": config_path,
        }
    if registry_path:
        return {
            "kind": "registry_path",
            "summary": registry_path[0],
            "artifacts": registry_path,
        }
    return {
        "kind": "none",
        "summary": None,
        "artifacts": [],
    }


def _build_triage_reasons(record: Mapping[str, Any]) -> list[str]:
    reasons: list[str] = []
    if _text(record.get("severity")) is None:
        reasons.append("severity_missing")
    if _text(record.get("parser_confidence")) == CONFIDENCE_LOW:
        reasons.append("parser_confidence_low")
    if _list_of_strings(record.get("parse_warnings")):
        reasons.append("parse_warnings_present")
    if _text(record.get("title")) is None:
        reasons.append("title_missing")
    if _text(record.get("guideline_reference")) is None:
        reasons.append("guideline_reference_missing")
    return reasons


def _text(value: Any) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        value = str(value)
    cleaned = value.strip()
    return cleaned or None


def _list_of_strings(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    items: list[str] = []
    for item in value:
        text = _text(item)
        if text is not None:
            items.append(text)
    return items
