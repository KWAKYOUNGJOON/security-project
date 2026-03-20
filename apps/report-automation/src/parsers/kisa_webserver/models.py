"""Data models for KISA webserver raw ingestion."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

DEFAULT_KISA_WEBSERVER_ROOT = Path(
    r"D:\security-project\resources\external-tools\kisa-ciip-2026"
)


class KisaWebserverCatalogError(ValueError):
    """Raised when the static catalog cannot be extracted safely."""


class KisaWebserverParseError(ValueError):
    """Raised when a KISA webserver JSON payload cannot be parsed."""


@dataclass(slots=True)
class KisaWebserverCatalogEntry:
    item_id: str | None
    platform: str
    item_key: str
    title: str | None
    source_script_path: str
    source_script_type: str
    severity: str | None
    reference: str | None
    guideline_text: str | None
    guideline_reference: str | None
    check_type: str
    metadata_confidence: str
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class KisaWebserverRawRecord:
    source_kind: str
    source_file: str
    platform: str | None
    service_name: str | None
    item_id: str | None
    item_key: str | None
    title: str | None
    severity: str | None
    raw_status: str | None
    inspection_summary: str | None
    hostname: str | None
    timestamp: str | None
    check_type: str
    executed_command: str | None
    command_output: str | None
    guideline_text: str | None
    guideline_reference: str | None
    config_path: list[str] = field(default_factory=list)
    registry_path: list[str] = field(default_factory=list)
    applicability: str | None = None
    parser_confidence: str = "medium"
    parse_warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
