"""Static metadata extractor for KISA 03.웹서버 WEBxx scripts."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Iterable

from src.parsers.kisa_webserver.models import (
    DEFAULT_KISA_WEBSERVER_ROOT,
    KisaWebserverCatalogEntry,
    KisaWebserverCatalogError,
)

SERVICE_DIRS = {
    "apache": "Apache",
    "nginx": "Nginx",
    "iis": "IIS",
    "tomcat": "Tomcat",
}

SH_HEADER_PATTERNS = {
    "item_id": re.compile(r"^\s*#\s*@?(?:ID|Item[_ -]?ID)\s*:\s*(.+?)\s*$", re.IGNORECASE),
    "title": re.compile(r"^\s*#\s*@?(?:Title|Item[_ -]?Name)\s*:\s*(.+?)\s*$", re.IGNORECASE),
    "severity": re.compile(r"^\s*#\s*@?Severity\s*:\s*(.+?)\s*$", re.IGNORECASE),
    "reference": re.compile(r"^\s*#\s*@?Reference\s*:\s*(.+?)\s*$", re.IGNORECASE),
    "guideline_reference": re.compile(
        r"^\s*#\s*@?Guideline(?:[_ -]?Reference)?\s*:\s*(.+?)\s*$", re.IGNORECASE
    ),
}
PS1_HEADER_PATTERNS = {
    key: re.compile(pattern.pattern.replace(r"#", r"(?:#|;)"), pattern.flags)
    for key, pattern in SH_HEADER_PATTERNS.items()
}
SH_VAR_PATTERN = re.compile(
    r'^\s*(?P<name>[A-Z0-9_]+)\s*=\s*(?P<quote>["\']?)(?P<value>.*?)(?P=quote)\s*$'
)
PS1_VAR_PATTERN = re.compile(
    r'^\s*\$(?P<name>[A-Za-z0-9_]+)\s*=\s*(?P<quote>["\']?)(?P<value>.*?)(?P=quote)\s*$'
)
ITEM_ID_FALLBACK_PATTERN = re.compile(r"(WEB-\d{2})", re.IGNORECASE)
REFERENCE_FALLBACK_PATTERN = re.compile(r"(?:KISA|CWE|OWASP)[^#\r\n]*", re.IGNORECASE)
PATH_PATTERN = re.compile(
    r"(/etc/[^\s\"']+|/usr/local/[^\s\"']+|[A-Za-z]:\\[^\r\n\"']+)",
    re.IGNORECASE,
)


def extract_kisa_webserver_catalog(
    source_root: Path | str | None = None,
) -> list[dict[str, object]]:
    """Extract a platform-scoped WEBxx catalog from a source repository."""

    root = Path(source_root) if source_root is not None else DEFAULT_KISA_WEBSERVER_ROOT
    if not root.exists():
        raise KisaWebserverCatalogError(
            f"Standard source root does not exist: {root}"
        )

    webserver_root = root / "03.웹서버"
    if not webserver_root.exists():
        raise KisaWebserverCatalogError(f"Expected webserver category not found: {webserver_root}")

    entries: list[KisaWebserverCatalogEntry] = []
    for platform, service_dir in SERVICE_DIRS.items():
        service_root = webserver_root / service_dir
        if not service_root.exists():
            continue
        for script_path in sorted(service_root.glob("WEB*_check.*")):
            if script_path.suffix.lower() not in {".sh", ".ps1"}:
                continue
            entries.append(_extract_script_metadata(script_path, platform, root))

    return [entry.to_dict() for entry in sorted(entries, key=_entry_sort_key)]


def build_catalog_document(
    entries: Iterable[dict[str, object]],
    *,
    source_root: Path | str | None = None,
    generation_mode: str = "generated",
    warnings: list[str] | None = None,
) -> dict[str, object]:
    root = Path(source_root) if source_root is not None else DEFAULT_KISA_WEBSERVER_ROOT
    return {
        "schema_version": "1.0",
        "catalog_name": "kisa-webserver-webxx",
        "source_root": root.as_posix(),
        "generation_mode": generation_mode,
        "items": list(entries),
        "warnings": warnings or [],
    }


def write_kisa_webserver_catalog(
    output_path: Path | str,
    *,
    source_root: Path | str | None = None,
) -> dict[str, object]:
    entries = extract_kisa_webserver_catalog(source_root=source_root)
    document = build_catalog_document(entries, source_root=source_root)
    target_path = Path(output_path)
    target_path.parent.mkdir(parents=True, exist_ok=True)
    target_path.write_text(
        json.dumps(document, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return document


def _extract_script_metadata(
    script_path: Path,
    platform: str,
    source_root: Path,
) -> KisaWebserverCatalogEntry:
    text = script_path.read_text(encoding="utf-8", errors="replace")
    script_type = script_path.suffix.lower().lstrip(".")
    header_patterns = SH_HEADER_PATTERNS if script_type == "sh" else PS1_HEADER_PATTERNS
    var_pattern = SH_VAR_PATTERN if script_type == "sh" else PS1_VAR_PATTERN

    header_values = _extract_headers(text, header_patterns)
    variable_values = _extract_variables(text, var_pattern, script_type)
    warnings: list[str] = []

    item_id = _first_value(
        header_values.get("item_id"),
        variable_values.get("ITEM_ID"),
        variable_values.get("item_id"),
        _extract_item_id_from_text(text),
    )
    if item_id is None:
        warnings.append("item_id is missing")

    title = _first_value(
        header_values.get("title"),
        variable_values.get("ITEM_NAME"),
        variable_values.get("ITEM_TITLE"),
        variable_values.get("TITLE"),
        _fallback_title(script_path),
    )
    if title is None:
        warnings.append("title is missing")

    severity = _first_value(
        header_values.get("severity"),
        variable_values.get("SEVERITY"),
        variable_values.get("severity"),
    )
    if severity is None:
        warnings.append("severity is missing")
    elif (
        header_values.get("severity")
        and variable_values.get("SEVERITY")
        and header_values["severity"] != variable_values["SEVERITY"]
    ):
        warnings.append(
            f"severity mismatch between header '{header_values['severity']}' "
            f"and variable '{variable_values['SEVERITY']}'"
        )

    reference = _first_value(
        header_values.get("reference"),
        variable_values.get("REFERENCE"),
        variable_values.get("reference"),
        _extract_reference_from_text(text),
    )
    if reference is None:
        warnings.append("reference is missing")

    guideline_reference = _first_value(
        header_values.get("guideline_reference"),
        variable_values.get("GUIDELINE_REFERENCE"),
        variable_values.get("guideline_reference"),
        reference,
    )
    guideline_text = _build_guideline_text(variable_values)
    check_type = _infer_check_type(text, title, script_path)
    if check_type == "unknown":
        warnings.append("check_type could not be determined confidently")

    metadata_confidence = _calculate_metadata_confidence(
        item_id=item_id,
        title=title,
        severity=severity,
        reference=reference,
        check_type=check_type,
        warnings=warnings,
    )
    item_key = f"{platform}:{item_id}" if item_id else f"{platform}:{script_path.stem}"
    relative_path = script_path.relative_to(source_root).as_posix()

    return KisaWebserverCatalogEntry(
        item_id=item_id,
        platform=platform,
        item_key=item_key,
        title=title,
        source_script_path=relative_path,
        source_script_type=script_type,
        severity=severity,
        reference=reference,
        guideline_text=guideline_text,
        guideline_reference=guideline_reference,
        check_type=check_type,
        metadata_confidence=metadata_confidence,
        warnings=warnings,
    )


def _extract_headers(text: str, patterns: dict[str, re.Pattern[str]]) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in text.splitlines():
        for key, pattern in patterns.items():
            match = pattern.match(line)
            if match and key not in values:
                values[key] = _clean_metadata_value(match.group(1))
    return values


def _extract_variables(
    text: str,
    pattern: re.Pattern[str],
    script_type: str,
) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in text.splitlines():
        match = pattern.match(line)
        if not match:
            continue
        name = match.group("name")
        value = _clean_metadata_value(match.group("value"))
        if not value:
            continue
        if script_type == "ps1":
            values[name] = value
        else:
            values[name.upper()] = value
    return values


def _build_guideline_text(values: dict[str, str]) -> str | None:
    candidate_keys = [
        "GUIDELINE_TEXT",
        "GUIDELINE",
        "GUIDELINE_PURPOSE",
        "GUIDELINE_THREAT",
        "GUIDELINE_CRITERIA_GOOD",
        "GUIDELINE_CRITERIA_BAD",
        "GUIDELINE_REMEDIATION",
        "purpose",
        "security_threat",
        "judgment_criteria_good",
        "judgment_criteria_bad",
        "remediation",
    ]
    parts = [values[key] for key in candidate_keys if values.get(key)]
    if not parts:
        return None
    return "\n".join(parts)


def _infer_check_type(text: str, title: str | None, script_path: Path) -> str:
    haystack = "\n".join([script_path.name, title or "", text]).lower()
    if any(token in haystack for token in ["수동진단", "수동으로", "manual review", "manual"]):
        return "manual"
    if any(token in haystack for token in ["webshell", "웹쉘", "suspicious", "heuristic", "의심"]):
        return "heuristic"
    if any(token in haystack for token in ["version", "버전", "patch", "패치"]):
        return "version"
    if any(token in haystack for token in ["get-acl", "icacls", "find ", "ls -", "test-path"]):
        return "file"
    if any(
        token in haystack
        for token in [
            "httpd.conf",
            "apache2.conf",
            "nginx.conf",
            "web.config",
            "server.xml",
            "tomcat-users.xml",
            "web.xml",
            "get-webconfiguration",
        ]
    ):
        return "config"
    if any(token in haystack for token in ["grep", "select-string", "get-website", "get-webbinding"]):
        return "command"
    if PATH_PATTERN.search(haystack):
        return "config"
    return "unknown"


def _calculate_metadata_confidence(
    *,
    item_id: str | None,
    title: str | None,
    severity: str | None,
    reference: str | None,
    check_type: str,
    warnings: list[str],
) -> str:
    missing_core = sum(value is None for value in [item_id, title, severity])
    if missing_core >= 2:
        return "low"
    if check_type == "unknown" or reference is None or warnings:
        return "medium" if missing_core == 0 else "low"
    return "high"


def _entry_sort_key(entry: KisaWebserverCatalogEntry) -> tuple[str, str, str]:
    return (entry.platform, entry.item_id or "", entry.source_script_path)


def _extract_item_id_from_text(text: str) -> str | None:
    match = ITEM_ID_FALLBACK_PATTERN.search(text)
    return match.group(1).upper() if match else None


def _extract_reference_from_text(text: str) -> str | None:
    match = REFERENCE_FALLBACK_PATTERN.search(text)
    return _clean_metadata_value(match.group(0)) if match else None


def _fallback_title(script_path: Path) -> str | None:
    return script_path.stem.replace("_check", "").replace("_", " ").strip() or None


def _clean_metadata_value(value: str | None) -> str | None:
    if value is None:
        return None
    cleaned = value.strip().strip('"').strip("'").strip()
    return cleaned or None


def _first_value(*values: str | None) -> str | None:
    for value in values:
        if value:
            return value
    return None
