"""Load immutable local case inputs for the Web automation flow."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from src.validators import (
    validate_document_control,
    validate_engagement_metadata,
    validate_manual_finding,
    validate_tool_inventory,
)


class CaseDataError(ValueError):
    """Raised when a case directory is missing required inputs."""


@dataclass(frozen=True)
class FindingInputs:
    """Resolved input files and parsed data for one finding."""

    repo_root: Path
    finding_key: str
    finding_dir: Path
    target_metadata: dict[str, Any] | None
    manual_finding: dict[str, Any]
    raw_scan: dict[str, Any]
    request_text: str
    response_text: str
    screenshot_files: list[Path]
    target_file: Path | None
    manual_finding_file: Path
    raw_scan_file: Path
    request_file: Path
    response_file: Path

    def repo_relative(self, path: Path) -> str:
        """Return a stable repo-relative path using forward slashes."""

        try:
            return path.resolve().relative_to(self.repo_root.resolve()).as_posix()
        except ValueError as exc:  # pragma: no cover - defensive boundary
            raise CaseDataError(f"Path is outside the repository root: {path}") from exc


@dataclass(frozen=True)
class CaseInputs:
    """Resolved case-level inputs for one report unit."""

    repo_root: Path
    case_dir: Path
    input_dir: Path
    engagement_metadata: dict[str, Any]
    document_control: dict[str, Any]
    tool_inventory: list[dict[str, Any]]
    findings: list[FindingInputs]
    engagement_file: Path
    document_control_file: Path | None
    tool_inventory_file: Path | None
    is_multi_finding: bool

    def repo_relative(self, path: Path) -> str:
        """Return a stable repo-relative path using forward slashes."""

        try:
            return path.resolve().relative_to(self.repo_root.resolve()).as_posix()
        except ValueError as exc:  # pragma: no cover - defensive boundary
            raise CaseDataError(f"Path is outside the repository root: {path}") from exc

    @property
    def first_finding(self) -> FindingInputs:
        return self.findings[0]

    @property
    def target(self) -> dict[str, Any]:
        return dict(self.first_finding.target_metadata or {})

    @property
    def manual_finding(self) -> dict[str, Any]:
        return self.first_finding.manual_finding

    @property
    def raw_scan(self) -> dict[str, Any]:
        return self.first_finding.raw_scan

    @property
    def request_text(self) -> str:
        return self.first_finding.request_text

    @property
    def response_text(self) -> str:
        return self.first_finding.response_text

    @property
    def screenshot_files(self) -> list[Path]:
        return self.first_finding.screenshot_files

    @property
    def target_file(self) -> Path | None:
        return self.first_finding.target_file

    @property
    def manual_finding_file(self) -> Path:
        return self.first_finding.manual_finding_file

    @property
    def raw_scan_file(self) -> Path:
        return self.first_finding.raw_scan_file

    @property
    def request_file(self) -> Path:
        return self.first_finding.request_file

    @property
    def response_file(self) -> Path:
        return self.first_finding.response_file


def resolve_case_directory(case_arg: str | Path, repo_root: Path) -> Path:
    """Resolve a case directory from a repo-relative or absolute argument."""

    raw_path = Path(case_arg)
    case_dir = raw_path if raw_path.is_absolute() else (repo_root / raw_path)
    resolved = case_dir.resolve()
    if not resolved.exists():
        raise CaseDataError(f"Case directory does not exist: {case_arg}")
    if not resolved.is_dir():
        raise CaseDataError(f"Case path must be a directory: {case_arg}")
    return resolved


def load_case_inputs(case_dir: Path, repo_root: Path) -> CaseInputs:
    """Read the immutable input files for one report unit."""

    input_dir = case_dir / "input"
    engagement_file = input_dir / "engagement.yaml"
    if not engagement_file.exists():
        raise CaseDataError(f"Missing required case input file: {engagement_file}")

    schema_dir = repo_root.resolve() / "shared" / "schemas"
    engagement_metadata = _load_mapping_file(engagement_file, description="engagement.yaml")
    validate_engagement_metadata(engagement_metadata, schema_dir=schema_dir)

    document_control_file = input_dir / "document-control.yaml"
    tool_inventory_file = input_dir / "tool-inventory.yaml"
    document_control = _load_document_control(
        engagement_metadata,
        document_control_file=document_control_file,
        schema_dir=schema_dir,
    )
    tool_inventory = _load_tool_inventory(
        tool_inventory_file=tool_inventory_file,
        schema_dir=schema_dir,
    )

    findings_root = input_dir / "findings"
    if findings_root.exists():
        findings = _load_multi_finding_inputs(
            findings_root=findings_root,
            repo_root=repo_root.resolve(),
            schema_dir=schema_dir,
        )
        is_multi_finding = True
    else:
        findings = [
            _load_legacy_finding_input(
                input_dir=input_dir,
                engagement_metadata=engagement_metadata,
                repo_root=repo_root.resolve(),
                schema_dir=schema_dir,
            )
        ]
        is_multi_finding = False

    return CaseInputs(
        repo_root=repo_root.resolve(),
        case_dir=case_dir.resolve(),
        input_dir=input_dir.resolve(),
        engagement_metadata=engagement_metadata,
        document_control=document_control,
        tool_inventory=tool_inventory,
        findings=findings,
        engagement_file=engagement_file.resolve(),
        document_control_file=document_control_file.resolve() if document_control_file.exists() else None,
        tool_inventory_file=tool_inventory_file.resolve() if tool_inventory_file.exists() else None,
        is_multi_finding=is_multi_finding,
    )


def _load_legacy_finding_input(
    *,
    input_dir: Path,
    engagement_metadata: dict[str, Any],
    repo_root: Path,
    schema_dir: Path,
) -> FindingInputs:
    target_file = input_dir / "target.json"
    manual_finding_file = input_dir / "manual-finding.yaml"
    raw_scan_file = input_dir / "raw" / "hexstrike-result.json"
    request_file = input_dir / "http" / "request.txt"
    response_file = input_dir / "http" / "response.txt"
    evidence_dir = input_dir / "evidence"

    required_files = [
        target_file,
        manual_finding_file,
        raw_scan_file,
        request_file,
        response_file,
    ]
    missing = [str(path) for path in required_files if not path.exists()]
    if missing:
        raise CaseDataError("Missing required legacy case input file(s): " + ", ".join(missing))

    screenshot_files = _evidence_files(evidence_dir)
    target = _load_json_file(target_file, description="target.json")
    manual_finding = _load_mapping_file(manual_finding_file, description="manual-finding.yaml")
    validate_manual_finding(manual_finding, schema_dir=schema_dir, repo_root=repo_root)
    _validate_target_alignment(target, engagement_metadata)

    return FindingInputs(
        repo_root=repo_root,
        finding_key=str(manual_finding.get("finding_id") or input_dir.parent.name),
        finding_dir=input_dir.resolve(),
        target_metadata=target,
        manual_finding=manual_finding,
        raw_scan=_load_json_file(raw_scan_file, description="hexstrike-result.json"),
        request_text=request_file.read_text(encoding="utf-8"),
        response_text=response_file.read_text(encoding="utf-8"),
        screenshot_files=screenshot_files,
        target_file=target_file.resolve(),
        manual_finding_file=manual_finding_file.resolve(),
        raw_scan_file=raw_scan_file.resolve(),
        request_file=request_file.resolve(),
        response_file=response_file.resolve(),
    )


def _load_multi_finding_inputs(
    *,
    findings_root: Path,
    repo_root: Path,
    schema_dir: Path,
) -> list[FindingInputs]:
    finding_dirs = sorted(path for path in findings_root.iterdir() if path.is_dir())
    if not finding_dirs:
        raise CaseDataError(f"No finding directories found under: {findings_root}")

    findings: list[FindingInputs] = []
    for finding_dir in finding_dirs:
        manual_finding_file = finding_dir / "manual-finding.yaml"
        raw_scan_file = finding_dir / "raw" / "hexstrike-result.json"
        request_file = finding_dir / "http" / "request.txt"
        response_file = finding_dir / "http" / "response.txt"
        evidence_dir = finding_dir / "evidence"
        required_files = [
            manual_finding_file,
            raw_scan_file,
            request_file,
            response_file,
        ]
        missing = [str(path) for path in required_files if not path.exists()]
        if missing:
            raise CaseDataError(
                f"Missing required multi-finding input file(s) in {finding_dir}: " + ", ".join(missing)
            )

        screenshot_files = _evidence_files(evidence_dir)
        manual_finding = _load_mapping_file(manual_finding_file, description=f"{finding_dir.name}/manual-finding.yaml")
        validate_manual_finding(manual_finding, schema_dir=schema_dir, repo_root=repo_root)
        findings.append(
            FindingInputs(
                repo_root=repo_root,
                finding_key=finding_dir.name,
                finding_dir=finding_dir.resolve(),
                target_metadata=None,
                manual_finding=manual_finding,
                raw_scan=_load_json_file(raw_scan_file, description=f"{finding_dir.name}/hexstrike-result.json"),
                request_text=request_file.read_text(encoding="utf-8"),
                response_text=response_file.read_text(encoding="utf-8"),
                screenshot_files=screenshot_files,
                target_file=None,
                manual_finding_file=manual_finding_file.resolve(),
                raw_scan_file=raw_scan_file.resolve(),
                request_file=request_file.resolve(),
                response_file=response_file.resolve(),
            )
        )
    return findings


def _load_tool_inventory(*, tool_inventory_file: Path, schema_dir: Path) -> list[dict[str, Any]]:
    if not tool_inventory_file.exists():
        return []

    tool_inventory_document = _load_mapping_file(tool_inventory_file, description="tool-inventory.yaml")
    validate_tool_inventory(tool_inventory_document, schema_dir=schema_dir)
    tool_inventory = tool_inventory_document["tool_inventory"]
    return [dict(item) for item in tool_inventory]


def _load_document_control(
    engagement_metadata: dict[str, Any],
    *,
    document_control_file: Path,
    schema_dir: Path,
) -> dict[str, Any]:
    if document_control_file.exists():
        document_control_document = _load_mapping_file(document_control_file, description="document-control.yaml")
        validate_document_control(document_control_document, schema_dir=schema_dir)
        document_control = document_control_document["document_control"]
        return {
            "history": [dict(item) for item in document_control.get("history") or []],
            "approvals": [dict(item) for item in document_control.get("approvals") or []],
        }

    legacy_document = engagement_metadata.get("document") or {}
    history = [
        {
            "version": str(item.get("version") or ""),
            "date": str(item.get("date") or ""),
            "author": str(item.get("author") or ""),
            "change": str(item.get("change") or item.get("change_log") or ""),
        }
        for item in legacy_document.get("history") or []
    ]
    approvals = [
        {
            "role": str(item.get("role") or item.get("kind") or ""),
            "name": str(item.get("name") or ""),
            "status": str(item.get("status") or ""),
            "note": str(item.get("note") or item.get("department") or ""),
        }
        for item in legacy_document.get("approvals") or []
    ]
    return {
        "history": history,
        "approvals": approvals,
    }


def _evidence_files(evidence_dir: Path) -> list[Path]:
    screenshot_files = sorted(path for path in evidence_dir.glob("*") if path.is_file())
    if not screenshot_files:
        raise CaseDataError(f"No evidence files found under: {evidence_dir}")
    return screenshot_files


def _load_json_file(path: Path, *, description: str) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8").strip()
    if not text:
        raise CaseDataError(f"{description} is empty: {path}")
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        raise CaseDataError(f"Invalid JSON in {description}: {path}") from exc
    if not isinstance(payload, dict):
        raise CaseDataError(f"{description} must contain a JSON object: {path}")
    return payload


def _load_mapping_file(path: Path, *, description: str) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8").strip()
    if not text:
        raise CaseDataError(f"{description} is empty: {path}")

    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        payload = _parse_simple_yaml(text)

    if not isinstance(payload, dict):
        raise CaseDataError(f"{description} must contain an object at the document root: {path}")
    return payload


def _validate_target_alignment(target: dict[str, Any], engagement_metadata: dict[str, Any]) -> None:
    targets = engagement_metadata["engagement"]["targets"]
    primary_target = targets[0]
    target_service_name = str(target.get("service_name") or "")
    target_base_url = str(target.get("base_url") or "")
    if target_service_name != str(primary_target["service_name"]):
        raise CaseDataError("target.json service_name must match engagement.targets[0].service_name")
    if target_base_url != str(primary_target["base_url"]):
        raise CaseDataError("target.json base_url must match engagement.targets[0].base_url")


def _parse_simple_yaml(text: str) -> Any:
    """Parse a conservative YAML subset used by the local sample cases."""

    processed_lines: list[tuple[int, str]] = []
    for raw_line in text.splitlines():
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if "\t" in raw_line:
            raise CaseDataError("Tabs are not supported in YAML indentation")
        indent = len(raw_line) - len(raw_line.lstrip(" "))
        processed_lines.append((indent, raw_line.lstrip()))

    if not processed_lines:
        return {}

    value, next_index = _parse_block(processed_lines, 0, processed_lines[0][0])
    if next_index != len(processed_lines):
        raise CaseDataError("Unexpected trailing content in YAML input")
    return value


def _parse_block(lines: list[tuple[int, str]], index: int, indent: int) -> tuple[Any, int]:
    current_indent, content = lines[index]
    if current_indent != indent:
        raise CaseDataError(f"Unexpected indentation near: {content}")
    if content.startswith("- "):
        return _parse_list(lines, index, indent)
    return _parse_mapping(lines, index, indent)


def _parse_mapping(lines: list[tuple[int, str]], index: int, indent: int) -> tuple[dict[str, Any], int]:
    result: dict[str, Any] = {}
    while index < len(lines):
        current_indent, content = lines[index]
        if current_indent < indent:
            break
        if current_indent != indent:
            raise CaseDataError(f"Invalid mapping indentation near: {content}")
        if content.startswith("- "):
            break

        key, separator, remainder = content.partition(":")
        if separator != ":":
            raise CaseDataError(f"Expected 'key: value' entry near: {content}")

        key_name = key.strip()
        value_text = remainder.lstrip()
        if not key_name:
            raise CaseDataError("Empty mapping key in YAML input")

        if value_text:
            result[key_name] = _parse_scalar(value_text)
            index += 1
            continue

        next_index = index + 1
        if next_index >= len(lines) or lines[next_index][0] <= indent:
            result[key_name] = None
            index = next_index
            continue

        child_indent = lines[next_index][0]
        child_value, index = _parse_block(lines, next_index, child_indent)
        result[key_name] = child_value

    return result, index


def _parse_list(lines: list[tuple[int, str]], index: int, indent: int) -> tuple[list[Any], int]:
    items: list[Any] = []
    while index < len(lines):
        current_indent, content = lines[index]
        if current_indent < indent:
            break
        if current_indent != indent or not content.startswith("- "):
            break

        value_text = content[2:].lstrip()
        if not value_text:
            next_index = index + 1
            if next_index >= len(lines) or lines[next_index][0] <= indent:
                items.append(None)
                index = next_index
                continue

            child_indent = lines[next_index][0]
            child_value, index = _parse_block(lines, next_index, child_indent)
            items.append(child_value)
            continue

        if ":" in value_text and not value_text.startswith(("'", '"')):
            inline_lines = [(indent + 2, value_text)]
            next_index = index + 1
            while next_index < len(lines) and lines[next_index][0] > indent:
                inline_lines.append(lines[next_index])
                next_index += 1
            item_value, _ = _parse_mapping(inline_lines, 0, indent + 2)
            items.append(item_value)
            index = next_index
            continue

        items.append(_parse_scalar(value_text))
        index += 1

    return items, index


def _parse_scalar(value: str) -> Any:
    lowered = value.lower()
    if lowered in {"null", "~"}:
        return None
    if lowered == "true":
        return True
    if lowered == "false":
        return False
    if value.startswith(("[", "{")) and value.endswith(("]", "}")):
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            pass
    if value.startswith('"') and value.endswith('"'):
        return bytes(value[1:-1], "utf-8").decode("unicode_escape")
    if value.startswith("'") and value.endswith("'"):
        return value[1:-1]
    if value.isdigit() or (value.startswith("-") and value[1:].isdigit()):
        return int(value)
    try:
        return float(value)
    except ValueError:
        return value
