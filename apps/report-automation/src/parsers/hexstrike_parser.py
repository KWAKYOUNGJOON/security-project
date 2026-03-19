"""HexStrike snapshot parsing utilities."""

from __future__ import annotations

from typing import Any, Iterable, Mapping


def _string_list(value: Any) -> list[str]:
    """Return a list of string values for flexible source fields."""

    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, Iterable):
        return [str(item).strip() for item in value if str(item).strip()]
    return [str(value).strip()]


def parse_hexstrike_snapshot(snapshot: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Convert a raw HexStrike snapshot into parser-stage finding records."""

    source = snapshot.get("source", {})
    engagement = snapshot.get("engagement", {})
    raw_findings = snapshot.get("findings", [])
    if not isinstance(raw_findings, list):
        return []

    parsed_findings: list[dict[str, Any]] = []
    for index, raw_finding in enumerate(raw_findings, start=1):
        if not isinstance(raw_finding, Mapping):
            continue

        parsed_findings.append(
            {
                "source_id": str(raw_finding.get("id") or f"finding-{index:03d}"),
                "sequence": index,
                "source_name": str(source.get("name") or "HexStrike-AI"),
                "project_key": str(engagement.get("name") or "sample-web-engagement"),
                "asset": str(raw_finding.get("asset") or engagement.get("primary_target") or "unknown-target"),
                "title": str(raw_finding.get("title") or "Untitled finding"),
                "severity": str(raw_finding.get("severity") or "unknown"),
                "description": str(raw_finding.get("description") or ""),
                "evidence": _string_list(raw_finding.get("evidence")),
                "references": _string_list(raw_finding.get("references")),
                "tags": _string_list(raw_finding.get("tags")),
            }
        )

    return parsed_findings
