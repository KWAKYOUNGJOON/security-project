"""Report payload builder for the phase-1 automation pipeline."""

from __future__ import annotations

from collections import Counter
from typing import Any, Iterable, Mapping


PIPELINE_STAGES = ["collect", "parse", "normalize", "enrich", "build"]
SEVERITY_ORDER = ["critical", "high", "medium", "low", "informational", "unknown"]


def build_report_payload(
    findings: Iterable[Mapping[str, Any]],
    *,
    current_scope: str,
    target_scope: Iterable[str],
    integration_name: str,
    project_name: str,
) -> dict[str, Any]:
    """Build a report-ready payload from enriched findings."""

    finding_list = [dict(finding) for finding in findings]
    counts = Counter(str(finding.get("severity") or "unknown") for finding in finding_list)
    severity_summary = {severity: counts.get(severity, 0) for severity in SEVERITY_ORDER}

    return {
        "meta": {
            "project_name": project_name,
            "current_scope": current_scope,
            "target_scope": list(target_scope),
            "primary_integration": integration_name,
            "pipeline": PIPELINE_STAGES,
        },
        "summary": {
            "total_findings": len(finding_list),
            "by_severity": severity_summary,
        },
        "findings": finding_list,
    }
