"""Observe HexStrike raw payload shapes without normalizing them into findings."""

from __future__ import annotations

from collections import Counter
from typing import Any, Iterable, Mapping

from src.intake.hexstrike_intake import HexStrikeIntakeError, HexStrikeIntakeRun


ROOT_EXPECTED_KEYS = {"tool", "scan", "engagement", "findings"}
FINDING_EXPECTED_KEYS = {
    "asset",
    "description",
    "endpoint",
    "evidence",
    "id",
    "impact",
    "method",
    "name",
    "observation",
    "param",
    "parameter",
    "path",
    "rating",
    "references",
    "remediation",
    "request",
    "response",
    "risk",
    "severity",
    "status",
    "summary",
    "tags",
    "title",
}
REQUIRED_ROOT_GROUPS = {
    "tool": ("tool",),
    "scan": ("scan",),
    "engagement": ("engagement",),
    "findings": ("findings",),
}
REQUIRED_FINDING_GROUPS = {
    "id": ("id",),
    "title_or_name": ("title", "name"),
    "severity": ("severity", "risk", "rating"),
    "request": ("request",),
    "response": ("response",),
    "evidence": ("evidence",),
    "status": ("status",),
}
EXPECTED_SHAPES = {
    "severity": {"string"},
    "status": {"string"},
    "request": {"object"},
    "response": {"object"},
    "evidence": {"array"},
}


def build_hexstrike_format_observation(
    run: HexStrikeIntakeRun,
    *,
    payload_sources: Iterable[Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    """Build a format-observation artifact for one intake run."""

    if not run.raw_payloads:
        raise HexStrikeIntakeError(
            "manifest.json raw_payloads must list at least one raw HexStrike payload for validation"
        )

    detected_top_level_keys: set[str] = set()
    unknown_fields: list[dict[str, Any]] = []
    missing_expected_fields: list[dict[str, Any]] = []
    parser_warnings: list[str] = []
    finding_count_detected = 0
    request_shapes: Counter[str] = Counter()
    response_shapes: Counter[str] = Counter()
    evidence_shapes: Counter[str] = Counter()
    severity_shapes: Counter[str] = Counter()
    status_shapes: Counter[str] = Counter()
    evidence_item_shapes: Counter[str] = Counter()
    evidence_item_kinds: Counter[str] = Counter()
    required_failures: list[str] = []

    for source_record in _payload_sources(run, payload_sources):
        payload = source_record["payload"]
        validation_payload = source_record["validation_payload"]
        source_path = source_record["source"]
        parser_warnings.extend(source_record["additional_warnings"])
        detected_top_level_keys.update(str(key) for key in payload.keys())

        for missing_group in _missing_groups(validation_payload, REQUIRED_ROOT_GROUPS):
            required_failures.append(f"{source_path}: missing required root field group '{missing_group}'")

        for key, value in payload.items():
            if key not in ROOT_EXPECTED_KEYS:
                unknown_fields.append(_field_record(source_path, "$", key, value))
                parser_warnings.append(f"Unknown root field preserved: {source_path}:$.{key}")

        raw_findings = validation_payload.get("findings")
        if not isinstance(raw_findings, list):
            continue

        finding_count_detected += len(raw_findings)
        for index, raw_finding in enumerate(raw_findings):
            field_path = f"$.findings[{index}]"
            if not isinstance(raw_finding, Mapping):
                required_failures.append(f"{source_path}:{field_path} must be an object")
                continue

            for missing_group in _missing_groups(raw_finding, REQUIRED_FINDING_GROUPS):
                required_failures.append(f"{source_path}:{field_path} missing required field group '{missing_group}'")

            for key, value in raw_finding.items():
                if key not in FINDING_EXPECTED_KEYS:
                    unknown_fields.append(_field_record(source_path, field_path, key, value))
                    parser_warnings.append(f"Unknown finding field preserved: {source_path}:{field_path}.{key}")

            _observe_field_shape(
                raw_finding,
                aliases=("severity", "risk", "rating"),
                field_name="severity",
                source_path=source_path,
                field_path=field_path,
                counter=severity_shapes,
                parser_warnings=parser_warnings,
                required_failures=required_failures,
            )
            _observe_field_shape(
                raw_finding,
                aliases=("status",),
                field_name="status",
                source_path=source_path,
                field_path=field_path,
                counter=status_shapes,
                parser_warnings=parser_warnings,
                required_failures=required_failures,
            )
            _observe_field_shape(
                raw_finding,
                aliases=("request",),
                field_name="request",
                source_path=source_path,
                field_path=field_path,
                counter=request_shapes,
                parser_warnings=parser_warnings,
                required_failures=required_failures,
            )
            _observe_field_shape(
                raw_finding,
                aliases=("response",),
                field_name="response",
                source_path=source_path,
                field_path=field_path,
                counter=response_shapes,
                parser_warnings=parser_warnings,
                required_failures=required_failures,
            )

            evidence_value = raw_finding.get("evidence")
            if evidence_value is not None:
                evidence_shape = _shape_name(evidence_value)
                evidence_shapes[evidence_shape] += 1
                if evidence_shape not in EXPECTED_SHAPES["evidence"]:
                    required_failures.append(
                        f"Unexpected evidence shape at {source_path}:{field_path}.evidence -> {evidence_shape}"
                    )
                for evidence_item in _iter_evidence_items(evidence_value):
                    evidence_item_shapes[_shape_name(evidence_item)] += 1
                    if isinstance(evidence_item, Mapping) and evidence_item.get("kind") is not None:
                        evidence_item_kinds[str(evidence_item.get("kind"))] += 1

    if required_failures:
        raise HexStrikeIntakeError("; ".join(required_failures))

    return {
        "schema_version": "1.0",
        "platform": run.platform,
        "integration": run.integration,
        "run_id": run.run_id,
        "mode": run.mode,
        "finding_count_detected": finding_count_detected,
        "detected_top_level_keys": sorted(detected_top_level_keys),
        "unknown_fields": sorted(unknown_fields, key=lambda item: (item["source"], item["path"], item["field"])),
        "missing_expected_fields": sorted(
            missing_expected_fields,
            key=lambda item: (item["source"], item["path"], item["field_group"]),
        ),
        "parser_warnings": sorted(dict.fromkeys(parser_warnings)),
        "evidence_shape_summary": {
            "request_field_shapes": _counter_payload(request_shapes),
            "response_field_shapes": _counter_payload(response_shapes),
            "evidence_field_shapes": _counter_payload(evidence_shapes),
            "severity_field_shapes": _counter_payload(severity_shapes),
            "status_field_shapes": _counter_payload(status_shapes),
            "evidence_item_shapes": _counter_payload(evidence_item_shapes),
            "evidence_item_kinds": _counter_payload(evidence_item_kinds),
        },
    }


def _payload_sources(
    run: HexStrikeIntakeRun,
    payload_sources: Iterable[Mapping[str, Any]] | None,
) -> list[dict[str, Any]]:
    if payload_sources is None:
        return [
            {
                "source": raw_payload.repo_relative(),
                "payload": raw_payload.payload,
                "validation_payload": raw_payload.payload,
                "additional_warnings": [],
            }
            for raw_payload in run.raw_payloads
        ]

    records: list[dict[str, Any]] = []
    for index, item in enumerate(payload_sources, start=1):
        if not isinstance(item, Mapping):
            raise HexStrikeIntakeError(f"payload_sources[{index}] must be a mapping")
        source = item.get("source")
        payload = item.get("payload")
        validation_payload = item.get("validation_payload", payload)
        additional_warnings = item.get("additional_warnings", [])
        if not isinstance(source, str) or not source.strip():
            raise HexStrikeIntakeError(f"payload_sources[{index}] must define a non-empty 'source'")
        if not isinstance(payload, Mapping):
            raise HexStrikeIntakeError(f"payload_sources[{index}] must define an object 'payload'")
        if not isinstance(validation_payload, Mapping):
            raise HexStrikeIntakeError(f"payload_sources[{index}] must define an object 'validation_payload'")
        if not isinstance(additional_warnings, list) or not all(
            isinstance(warning, str) and warning.strip() for warning in additional_warnings
        ):
            raise HexStrikeIntakeError(f"payload_sources[{index}] additional_warnings must be a string array")
        records.append(
            {
                "source": source,
                "payload": dict(payload),
                "validation_payload": dict(validation_payload),
                "additional_warnings": [warning.strip() for warning in additional_warnings],
            }
        )
    return records


def _field_record(source_path: str, field_path: str, field_name: str, value: Any) -> dict[str, Any]:
    return {
        "source": source_path,
        "path": field_path,
        "field": field_name,
        "shape": _shape_name(value),
        "value": value,
    }


def _missing_groups(payload: Mapping[str, Any], field_groups: Mapping[str, Iterable[str]]) -> list[str]:
    missing: list[str] = []
    for group_name, aliases in field_groups.items():
        if not any(alias in payload and payload.get(alias) is not None for alias in aliases):
            missing.append(group_name)
    return missing


def _observe_field_shape(
    payload: Mapping[str, Any],
    *,
    aliases: tuple[str, ...],
    field_name: str,
    source_path: str,
    field_path: str,
    counter: Counter[str],
    parser_warnings: list[str],
    required_failures: list[str],
) -> None:
    value = _first_present_value(payload, aliases)
    if value is None:
        return
    shape = _shape_name(value)
    counter[shape] += 1
    if shape not in EXPECTED_SHAPES[field_name]:
        required_failures.append(f"Unexpected {field_name} shape at {source_path}:{field_path}.{aliases[0]} -> {shape}")


def _first_present_value(payload: Mapping[str, Any], aliases: Iterable[str]) -> Any:
    for alias in aliases:
        if alias in payload and payload.get(alias) is not None:
            return payload.get(alias)
    return None


def _iter_evidence_items(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return list(value)
    return [value]


def _counter_payload(counter: Counter[str]) -> dict[str, int]:
    return {key: counter[key] for key in sorted(counter)}


def _shape_name(value: Any) -> str:
    if isinstance(value, Mapping):
        return "object"
    if isinstance(value, list):
        return "array"
    if isinstance(value, str):
        return "string"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, (int, float)):
        return "number"
    if value is None:
        return "null"
    return type(value).__name__.lower()
