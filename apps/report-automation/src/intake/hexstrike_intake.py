"""Load immutable HexStrike intake folders for pre-target validation."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class HexStrikeIntakeError(ValueError):
    """Raised when a pre-target intake folder is invalid."""


@dataclass(frozen=True)
class HexStrikeRawPayload:
    """Resolved raw payload file and parsed JSON content."""

    repo_root: Path
    file_path: Path
    payload: dict[str, Any]

    def repo_relative(self, path: Path | None = None) -> str:
        """Return a stable repo-relative path using forward slashes."""

        return _repo_relative(self.repo_root, path or self.file_path)


@dataclass(frozen=True)
class HexStrikeIntakeRun:
    """Resolved manifest, notes, baseline files, and raw payloads for one intake run."""

    repo_root: Path
    run_dir: Path
    manifest: dict[str, Any]
    manifest_path: Path
    notes_path: Path
    baseline_files: list[Path]
    raw_payloads: list[HexStrikeRawPayload]

    @property
    def run_id(self) -> str:
        return str(self.manifest["run_id"])

    @property
    def mode(self) -> str:
        return str(self.manifest["mode"])

    @property
    def platform(self) -> str:
        return str(self.manifest["platform"])

    @property
    def integration(self) -> str:
        return str(self.manifest["integration"])

    def repo_relative(self, path: Path) -> str:
        """Return a stable repo-relative path using forward slashes."""

        return _repo_relative(self.repo_root, path)


def resolve_intake_directory(run_arg: str | Path, repo_root: Path) -> Path:
    """Resolve an intake run directory from a repo-relative or absolute argument."""

    raw_path = Path(run_arg)
    run_dir = raw_path if raw_path.is_absolute() else (repo_root / raw_path)
    resolved = run_dir.resolve()
    if not resolved.exists():
        raise HexStrikeIntakeError(f"Intake run directory does not exist: {run_arg}")
    if not resolved.is_dir():
        raise HexStrikeIntakeError(f"Intake run path must be a directory: {run_arg}")
    return resolved


def load_hexstrike_intake_run(run_dir: Path, repo_root: Path) -> HexStrikeIntakeRun:
    """Read one immutable intake run folder."""

    resolved_run_dir = run_dir.resolve()
    resolved_repo_root = repo_root.resolve()
    manifest_path = resolved_run_dir / "manifest.json"
    notes_path = resolved_run_dir / "notes.md"
    if not manifest_path.exists():
        raise HexStrikeIntakeError(f"Missing required intake file: {manifest_path}")
    if not notes_path.exists():
        raise HexStrikeIntakeError(f"Missing required intake file: {notes_path}")

    manifest = _load_json_object(manifest_path, description="manifest.json")
    _validate_manifest(manifest)

    baseline_files = [
        _resolve_run_file(resolved_run_dir, rel_path, field_name="baseline_files")
        for rel_path in manifest.get("baseline_files") or []
    ]
    raw_payload_files = [
        _resolve_run_file(resolved_run_dir, rel_path, field_name="raw_payloads")
        for rel_path in manifest["raw_payloads"]
    ]
    raw_payloads = [
        HexStrikeRawPayload(
            repo_root=resolved_repo_root,
            file_path=path,
            payload=_load_json_object(path, description=path.name),
        )
        for path in raw_payload_files
    ]

    return HexStrikeIntakeRun(
        repo_root=resolved_repo_root,
        run_dir=resolved_run_dir,
        manifest=manifest,
        manifest_path=manifest_path.resolve(),
        notes_path=notes_path.resolve(),
        baseline_files=[path.resolve() for path in baseline_files],
        raw_payloads=raw_payloads,
    )


def _validate_manifest(manifest: dict[str, Any]) -> None:
    required_string_fields = ("schema_version", "platform", "integration", "run_id", "mode")
    for field_name in required_string_fields:
        value = manifest.get(field_name)
        if not isinstance(value, str) or not value.strip():
            raise HexStrikeIntakeError(f"manifest.json must define a non-empty string field '{field_name}'")

    platform = str(manifest["platform"]).strip().lower()
    if platform != "web":
        raise HexStrikeIntakeError("manifest.json platform must be 'web' for the current implementation")

    integration = str(manifest["integration"]).strip().lower()
    if integration != "hexstrike-ai":
        raise HexStrikeIntakeError("manifest.json integration must be 'hexstrike-ai'")

    for field_name in ("raw_payloads", "baseline_files"):
        value = manifest.get(field_name, [])
        if not isinstance(value, list):
            raise HexStrikeIntakeError(f"manifest.json field '{field_name}' must be an array")
        for index, item in enumerate(value):
            if not isinstance(item, str) or not item.strip():
                raise HexStrikeIntakeError(
                    f"manifest.json field '{field_name}[{index}]' must be a non-empty relative path string"
                )
            if Path(item).is_absolute():
                raise HexStrikeIntakeError(
                    f"manifest.json field '{field_name}[{index}]' must be repo-local and relative: {item}"
                )


def _load_json_object(path: Path, *, description: str) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise HexStrikeIntakeError(f"{description} must contain a JSON object: {path}") from exc
    if not isinstance(payload, dict):
        raise HexStrikeIntakeError(f"{description} must contain a JSON object: {path}")
    return payload


def _resolve_run_file(run_dir: Path, relative_path: str, *, field_name: str) -> Path:
    path = (run_dir / relative_path).resolve()
    try:
        path.relative_to(run_dir)
    except ValueError as exc:
        raise HexStrikeIntakeError(
            f"manifest.json field '{field_name}' points outside the intake run directory: {relative_path}"
        ) from exc
    if not path.exists():
        raise HexStrikeIntakeError(f"Missing intake file listed in manifest.json: {path}")
    if not path.is_file():
        raise HexStrikeIntakeError(f"Intake file listed in manifest.json must be a file: {path}")
    return path


def _repo_relative(repo_root: Path, path: Path) -> str:
    try:
        return path.resolve().relative_to(repo_root.resolve()).as_posix()
    except ValueError as exc:
        raise HexStrikeIntakeError(f"Path is outside the repository root: {path}") from exc
