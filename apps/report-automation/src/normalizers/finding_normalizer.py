"""Finding normalization helpers."""

from __future__ import annotations

from typing import Any, Iterable, Mapping


SEVERITY_ALIASES = {
    "critical": "critical",
    "crit": "critical",
    "p1": "critical",
    "high": "high",
    "p2": "high",
    "medium": "medium",
    "moderate": "medium",
    "p3": "medium",
    "low": "low",
    "p4": "low",
    "informational": "informational",
    "info": "informational",
}


def _normalized_severity(value: Any) -> str:
    """Normalize severity labels into a stable internal set."""

    raw_value = str(value or "").strip().lower()
    return SEVERITY_ALIASES.get(raw_value, "unknown")


def _clean_list(value: Any) -> list[str]:
    """Normalize list-like fields into deduplicated string lists."""

    if value is None:
        return []

    if isinstance(value, str):
        items = [value]
    elif isinstance(value, Iterable):
        items = [str(item) for item in value]
    else:
        items = [str(value)]

    ordered: list[str] = []
    seen: set[str] = set()
    for item in items:
        cleaned = item.strip()
        if not cleaned or cleaned in seen:
            continue
        seen.add(cleaned)
        ordered.append(cleaned)
    return ordered


def normalize_findings(findings: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Normalize parser-stage findings into a stable report model."""

    normalized_findings: list[dict[str, Any]] = []
    for finding in findings:
        normalized_findings.append(
            {
                "id": str(finding.get("source_id") or "unknown-finding"),
                "sequence": int(finding.get("sequence") or 0),
                "title": str(finding.get("title") or "Untitled finding").strip(),
                "severity": _normalized_severity(finding.get("severity")),
                "target": str(finding.get("asset") or "unknown-target").strip(),
                "summary": str(finding.get("description") or "No summary provided.").strip(),
                "evidence": _clean_list(finding.get("evidence")),
                "references": _clean_list(finding.get("references")),
                "tags": _clean_list(finding.get("tags")),
                "source": {
                    "name": str(finding.get("source_name") or "HexStrike-AI"),
                    "project_key": str(finding.get("project_key") or "sample-web-engagement"),
                },
            }
        )

    return normalized_findings
