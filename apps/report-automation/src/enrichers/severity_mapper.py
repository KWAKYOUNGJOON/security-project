"""Severity enrichment helpers."""

from __future__ import annotations

from typing import Any, Iterable, Mapping


SEVERITY_METADATA: dict[str, dict[str, Any]] = {
    "critical": {"label": "Critical", "rank": 5, "priority": "P1", "cvss_band": "9.0-10.0"},
    "high": {"label": "High", "rank": 4, "priority": "P2", "cvss_band": "7.0-8.9"},
    "medium": {"label": "Medium", "rank": 3, "priority": "P3", "cvss_band": "4.0-6.9"},
    "low": {"label": "Low", "rank": 2, "priority": "P4", "cvss_band": "0.1-3.9"},
    "informational": {"label": "Informational", "rank": 1, "priority": "P5", "cvss_band": "0.0"},
    "unknown": {"label": "Unknown", "rank": 0, "priority": "TBD", "cvss_band": "TBD"},
}


def enrich_findings(findings: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Add severity metadata used by later report generation steps."""

    enriched_findings: list[dict[str, Any]] = []
    for finding in findings:
        severity = str(finding.get("severity") or "unknown")
        metadata = SEVERITY_METADATA.get(severity, SEVERITY_METADATA["unknown"])

        enriched_findings.append(
            {
                **finding,
                "severity_label": metadata["label"],
                "severity_rank": metadata["rank"],
                "priority": metadata["priority"],
                "cvss_band": metadata["cvss_band"],
            }
        )

    return enriched_findings
