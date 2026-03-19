"""Lightweight JSON schema validation with an optional jsonschema backend."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping


class SchemaValidationError(ValueError):
    """Raised when a document does not satisfy a schema."""


def validate_schema_file(instance: Any, schema_path: Path) -> None:
    """Validate a JSON-compatible object against a local schema file."""

    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    try:
        import jsonschema  # type: ignore
    except ImportError:
        _validate(instance, schema, path="$")
        return

    try:
        jsonschema.validate(instance=instance, schema=schema)
    except jsonschema.ValidationError as exc:  # pragma: no cover - depends on optional package
        raise SchemaValidationError(exc.message) from exc


def _validate(instance: Any, schema: Mapping[str, Any], *, path: str) -> None:
    _validate_type(instance, schema, path=path)

    if "const" in schema and instance != schema["const"]:
        raise SchemaValidationError(f"{path}: expected constant value {schema['const']!r}")

    if "enum" in schema and instance not in schema["enum"]:
        raise SchemaValidationError(f"{path}: expected one of {schema['enum']!r}")

    schema_type = _schema_primary_type(schema, instance)
    if schema_type == "object":
        _validate_object(instance, schema, path=path)
    elif schema_type == "array":
        _validate_array(instance, schema, path=path)


def _validate_type(instance: Any, schema: Mapping[str, Any], *, path: str) -> None:
    expected = schema.get("type")
    if expected is None:
        return

    expected_types = expected if isinstance(expected, list) else [expected]
    if any(_matches_type(instance, item) for item in expected_types):
        return
    raise SchemaValidationError(f"{path}: expected type {expected_types!r}, got {type(instance).__name__}")


def _validate_object(instance: Any, schema: Mapping[str, Any], *, path: str) -> None:
    if not isinstance(instance, dict):
        return

    properties = schema.get("properties") or {}
    required = schema.get("required") or []
    for key in required:
        if key not in instance:
            raise SchemaValidationError(f"{path}: missing required property '{key}'")

    for key, value in instance.items():
        child_path = f"{path}.{key}"
        if key in properties:
            _validate(value, properties[key], path=child_path)
            continue

        additional = schema.get("additionalProperties", True)
        if additional is False:
            raise SchemaValidationError(f"{path}: unexpected property '{key}'")
        if isinstance(additional, dict):
            _validate(value, additional, path=child_path)


def _validate_array(instance: Any, schema: Mapping[str, Any], *, path: str) -> None:
    if not isinstance(instance, list):
        return

    min_items = schema.get("minItems")
    if min_items is not None and len(instance) < int(min_items):
        raise SchemaValidationError(f"{path}: expected at least {min_items} item(s)")

    item_schema = schema.get("items")
    if not isinstance(item_schema, dict):
        return
    for index, item in enumerate(instance):
        _validate(item, item_schema, path=f"{path}[{index}]")


def _schema_primary_type(schema: Mapping[str, Any], instance: Any) -> str | None:
    expected = schema.get("type")
    if isinstance(expected, list):
        for item in expected:
            if _matches_type(instance, str(item)):
                return str(item)
        for item in expected:
            if item != "null":
                return str(item)
        return "null"
    return str(expected) if expected is not None else None


def _matches_type(instance: Any, expected_type: str) -> bool:
    return {
        "object": isinstance(instance, dict),
        "array": isinstance(instance, list),
        "string": isinstance(instance, str),
        "integer": isinstance(instance, int) and not isinstance(instance, bool),
        "number": isinstance(instance, (int, float)) and not isinstance(instance, bool),
        "boolean": isinstance(instance, bool),
        "null": instance is None,
    }.get(expected_type, True)
