"""JSON loaders for KISA 03.웹서버 raw ingestion."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Iterable

from src.parsers.kisa_webserver.models import (
    KisaWebserverParseError,
    KisaWebserverRawRecord,
)

CATALOG_PATH = Path(
    r"D:\security-project\shared\catalogs\kisa-webserver-webxx.catalog.json"
)
CONFIG_PATH_PATTERN = re.compile(
    r"(/etc/[^\s\"']+|/usr/local/[^\s\"']+|[A-Za-z]:\\[^\r\n\"']+)",
    re.IGNORECASE,
)
REGISTRY_PATTERN = re.compile(r"(HKLM:|HKCU:|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER)[^\r\n\"']*")


def load_kisa_webserver_json(
    path: Path | str,
    platform: str | None = None,
    *,
    catalog_entries: Iterable[dict[str, Any]] | None = None,
    catalog_path: Path | str | None = None,
) -> list[dict[str, Any]]:
    payload = _read_json_payload(path)
    if isinstance(payload, dict) and isinstance(payload.get("items"), list):
        return load_kisa_webserver_run_all_json(
            path,
            platform=platform,
            catalog_entries=catalog_entries,
            catalog_path=catalog_path,
        )
    return load_kisa_webserver_item_json(
        path,
        platform=platform,
        catalog_entries=catalog_entries,
        catalog_path=catalog_path,
    )


def load_kisa_webserver_item_json(
    path: Path | str,
    platform: str | None = None,
    *,
    catalog_entries: Iterable[dict[str, Any]] | None = None,
    catalog_path: Path | str | None = None,
) -> list[dict[str, Any]]:
    source_path = Path(path)
    payload = _read_json_payload(source_path)
    if not isinstance(payload, dict):
        raise KisaWebserverParseError("Item JSON payload must be an object")
    if isinstance(payload.get("items"), list):
        raise KisaWebserverParseError("Item JSON loader received a run_all payload")

    catalog = _load_catalog_entries(catalog_entries=catalog_entries, catalog_path=catalog_path)
    resolved_platform, warnings = _resolve_platform(
        source_path=source_path,
        explicit_platform=platform,
        payload_platform=payload.get("platform"),
    )
    record = _build_raw_record(
        item_payload=payload,
        source_kind="item_json",
        source_file=source_path.as_posix(),
        platform=resolved_platform,
        envelope={},
        catalog=catalog,
        extra_warnings=warnings,
    )
    return [record.to_dict()]


def load_kisa_webserver_run_all_json(
    path: Path | str,
    platform: str | None = None,
    *,
    catalog_entries: Iterable[dict[str, Any]] | None = None,
    catalog_path: Path | str | None = None,
) -> list[dict[str, Any]]:
    source_path = Path(path)
    payload = _read_json_payload(source_path)
    if not isinstance(payload, dict):
        raise KisaWebserverParseError("run_all JSON payload must be an object")

    items = payload.get("items")
    if not isinstance(items, list):
        raise KisaWebserverParseError("run_all JSON payload must contain items[]")

    catalog = _load_catalog_entries(catalog_entries=catalog_entries, catalog_path=catalog_path)
    resolved_platform, warnings = _resolve_platform(
        source_path=source_path,
        explicit_platform=platform,
        payload_platform=payload.get("platform"),
    )
    records: list[dict[str, Any]] = []
    for item_payload in items:
        if not isinstance(item_payload, dict):
            raise KisaWebserverParseError("run_all JSON items[] must contain objects")
        record = _build_raw_record(
            item_payload=item_payload,
            source_kind="run_all_json",
            source_file=source_path.as_posix(),
            platform=resolved_platform,
            envelope=payload,
            catalog=catalog,
            extra_warnings=warnings,
        )
        records.append(record.to_dict())
    return records


def load_kisa_webserver_txt(path: Path | str, platform: str | None = None) -> list[dict[str, Any]]:
    raise NotImplementedError(
        "TXT parsing is intentionally out of scope for this phase. "
        "Use JSON first and keep TXT as a documented fallback only."
    )


def _read_json_payload(path: Path) -> Any:
    errors: list[str] = []
    for encoding in ("utf-8-sig", "utf-8", "cp949"):
        try:
            return json.loads(path.read_text(encoding=encoding))
        except UnicodeDecodeError as exc:
            errors.append(f"{encoding}: {exc}")
        except json.JSONDecodeError as exc:
            errors.append(f"{encoding}: {exc}")
    raise KisaWebserverParseError(f"Unable to parse JSON from {path}: {'; '.join(errors)}")


def _load_catalog_entries(
    *,
    catalog_entries: Iterable[dict[str, Any]] | None,
    catalog_path: Path | str | None,
) -> dict[str, dict[str, Any]]:
    if catalog_entries is not None:
        return _index_catalog_entries(catalog_entries)

    path = Path(catalog_path) if catalog_path is not None else CATALOG_PATH
    if not path.exists():
        return {}

    payload = _read_json_payload(path)
    if isinstance(payload, dict) and isinstance(payload.get("items"), list):
        return _index_catalog_entries(payload["items"])
    if isinstance(payload, list):
        return _index_catalog_entries(payload)
    raise KisaWebserverParseError(f"Unsupported catalog payload shape in {path}")


def _index_catalog_entries(entries: Iterable[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    catalog: dict[str, dict[str, Any]] = {}
    for entry in entries:
        item_key = entry.get("item_key")
        if isinstance(item_key, str) and item_key:
            catalog[item_key] = dict(entry)
    return catalog


def _resolve_platform(
    *,
    source_path: Path,
    explicit_platform: str | None,
    payload_platform: Any,
) -> tuple[str | None, list[str]]:
    warnings: list[str] = []
    path_platform = _platform_from_text(source_path.as_posix())
    explicit = _normalize_platform(explicit_platform)
    payload = _normalize_platform(payload_platform if isinstance(payload_platform, str) else None)

    chosen = path_platform or explicit or payload
    chosen_source = "source path" if path_platform else "explicit argument" if explicit else "payload"
    for label, candidate in (("explicit", explicit), ("payload", payload)):
        if chosen and candidate and candidate != chosen:
            warnings.append(
                f"platform conflict: using '{chosen}' from {chosen_source} instead of {label} value '{candidate}'"
            )
    return chosen, warnings


def _build_raw_record(
    *,
    item_payload: dict[str, Any],
    source_kind: str,
    source_file: str,
    platform: str | None,
    envelope: dict[str, Any],
    catalog: dict[str, dict[str, Any]],
    extra_warnings: list[str],
) -> KisaWebserverRawRecord:
    warnings = list(extra_warnings)
    item_id = _clean_text(item_payload.get("item_id"))
    item_key = f"{platform}:{item_id}" if platform and item_id else None
    catalog_entry = catalog.get(item_key or "")
    if item_key and catalog_entry is None:
        warnings.append(f"Catalog entry not found for {item_key}")

    inspection = item_payload.get("inspection")
    inspection_summary = None
    inspection_status = None
    if isinstance(inspection, dict):
        inspection_summary = _clean_text(inspection.get("summary"))
        inspection_status = _clean_text(inspection.get("status"))

    raw_status = _clean_text(item_payload.get("final_result")) or inspection_status
    command_output = _normalize_command_output(item_payload.get("command_result"))
    command_text = _clean_text(item_payload.get("command"))
    runtime_guideline_text, runtime_guideline_reference = _extract_guideline(item_payload)

    title = _clean_text(_catalog_value(catalog_entry, "title")) or _clean_text(item_payload.get("item_name"))
    severity = _clean_text(_catalog_value(catalog_entry, "severity"))
    guideline_reference = _clean_text(_catalog_value(catalog_entry, "guideline_reference")) or runtime_guideline_reference
    guideline_text = _clean_text(_catalog_value(catalog_entry, "guideline_text")) or runtime_guideline_text
    check_type = _clean_text(_catalog_value(catalog_entry, "check_type")) or "unknown"

    parser_confidence = _calculate_parser_confidence(catalog_entry=catalog_entry, raw_status=raw_status)
    if title is None:
        warnings.append("title could not be resolved")
        parser_confidence = _downgrade_confidence(parser_confidence)
    if severity is None:
        warnings.append("severity could not be resolved from catalog")
        parser_confidence = _downgrade_confidence(parser_confidence)

    return KisaWebserverRawRecord(
        source_kind=source_kind,
        source_file=source_file,
        platform=platform,
        service_name=platform,
        item_id=item_id,
        item_key=item_key,
        title=title,
        severity=severity,
        raw_status=raw_status,
        inspection_summary=inspection_summary,
        hostname=_clean_text(item_payload.get("hostname")) or _clean_text(envelope.get("hostname")),
        timestamp=_clean_text(item_payload.get("timestamp")) or _clean_text(envelope.get("timestamp")),
        check_type=check_type,
        executed_command=command_text,
        command_output=command_output,
        guideline_text=guideline_text,
        guideline_reference=guideline_reference,
        config_path=_extract_paths(command_text, command_output),
        registry_path=_extract_registry_paths(command_text, command_output),
        applicability=_derive_applicability(raw_status, inspection_summary),
        parser_confidence=parser_confidence,
        parse_warnings=_dedupe_warnings(warnings),
    )


def _extract_guideline(item_payload: dict[str, Any]) -> tuple[str | None, str | None]:
    guideline = item_payload.get("guideline")
    if not isinstance(guideline, dict):
        return None, None

    parts = []
    for key in (
        "purpose",
        "security_threat",
        "judgment_criteria_good",
        "judgment_criteria_bad",
        "remediation",
    ):
        value = _clean_text(guideline.get(key))
        if value:
            parts.append(value)
    reference = _clean_text(guideline.get("reference"))
    return ("\n".join(parts) if parts else None, reference)


def _extract_paths(*values: str | None) -> list[str]:
    paths: list[str] = []
    for value in values:
        if not value:
            continue
        for match in CONFIG_PATH_PATTERN.findall(value):
            normalized = match.replace("\\\\", "\\")
            if normalized not in paths:
                paths.append(normalized)
    return paths


def _extract_registry_paths(*values: str | None) -> list[str]:
    paths: list[str] = []
    for value in values:
        if not value:
            continue
        for match in REGISTRY_PATTERN.finditer(value):
            registry_path = match.group(0)
            if registry_path not in paths:
                paths.append(registry_path)
    return paths


def _normalize_command_output(value: Any) -> str | None:
    text = _clean_text(value)
    if text is None:
        return None
    normalized = text.replace("\r\n", "\n").replace("\r", "\n")
    if "\\n" in normalized and "\n" not in normalized:
        normalized = normalized.replace("\\n", "\n")
    return normalized


def _derive_applicability(raw_status: str | None, inspection_summary: str | None) -> str | None:
    if raw_status != "N/A":
        return None
    haystack = (inspection_summary or "").lower()
    if "실행 중이 아닙니다" in haystack or "not running" in haystack:
        return "service_not_running"
    return "not_applicable"


def _calculate_parser_confidence(
    *,
    catalog_entry: dict[str, Any] | None,
    raw_status: str | None,
) -> str:
    if catalog_entry is None:
        return "low"
    confidence = _clean_text(catalog_entry.get("metadata_confidence"))
    if confidence in {"high", "medium", "low"}:
        return confidence
    if raw_status in {"ERROR", "MANUAL", "N/A"}:
        return "medium"
    return "high"


def _downgrade_confidence(value: str) -> str:
    if value == "high":
        return "medium"
    return "low"


def _platform_from_text(text: str) -> str | None:
    return _normalize_platform(text)


def _normalize_platform(value: str | None) -> str | None:
    if not value:
        return None
    lowered = value.lower()
    if "apache" in lowered:
        return "apache"
    if "nginx" in lowered:
        return "nginx"
    if "iis" in lowered:
        return "iis"
    if "tomcat" in lowered:
        return "tomcat"
    return None


def _catalog_value(entry: dict[str, Any] | None, key: str) -> Any:
    if entry is None:
        return None
    return entry.get(key)


def _dedupe_warnings(warnings: list[str]) -> list[str]:
    ordered: list[str] = []
    for warning in warnings:
        if warning not in ordered:
            ordered.append(warning)
    return ordered


def _clean_text(value: Any) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        value = str(value)
    cleaned = value.strip()
    return cleaned or None
