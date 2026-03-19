"""Build a Web report payload from normalized findings and case metadata."""

from __future__ import annotations

from collections import Counter
from typing import Any, Mapping, Sequence

from src.cases import CaseInputs


SEVERITY_ORDER = ("high", "medium", "low")
SEVERITY_RANK = {
    "high": 0,
    "medium": 1,
    "low": 2,
}


def build_web_report_payload(
    normalized_findings: Sequence[Mapping[str, Any]],
    case_inputs: CaseInputs,
) -> dict[str, Any]:
    """Build the explicit report payload contract consumed by the template bridge."""

    if not normalized_findings:
        raise ValueError("At least one normalized finding is required")

    ordered_findings = sorted(normalized_findings, key=_finding_sort_key)
    reportable_findings = [finding for finding in ordered_findings if _included_in_report(finding)]
    document_meta = _document_payload(case_inputs.engagement_metadata)
    document_control = _document_control_payload(case_inputs.document_control)
    engagement_payload = _engagement_payload(case_inputs, ordered_findings)
    overview_payload = _overview_payload(case_inputs.engagement_metadata, ordered_findings)
    tool_inventory = [dict(item) for item in case_inputs.tool_inventory]
    review_summary = _review_summary(ordered_findings)
    finding_entries = [_finding_entry(finding, document_meta["date"]) for finding in reportable_findings]
    by_target = _by_target_summary(finding_entries)
    target_sections = _target_sections(finding_entries)

    return {
        "document": document_meta,
        "document_control": document_control,
        "engagement": engagement_payload,
        "overview": overview_payload,
        "tool_inventory": tool_inventory,
        "summary": {
            "total_findings": len(finding_entries),
            "by_severity": _severity_counts(finding_entries),
            "by_target": by_target,
            "comment": _summary_comment(finding_entries, by_target, review_summary),
            "priorities": _priority_items(finding_entries),
        },
        "review_summary": review_summary,
        "target_sections": target_sections,
        "findings": finding_entries,
        "remediation_plan": _remediation_plan(reportable_findings),
        "appendix": {
            "evidence": _appendix_evidence(finding_entries),
            "checklist": _checklist_items(reportable_findings),
        },
    }


def _document_payload(engagement_metadata: Mapping[str, Any]) -> dict[str, Any]:
    document = engagement_metadata["document"]
    return {
        "title": document["title"],
        "version": document["version"],
        "date": document["date"],
        "classification": document["classification"],
    }


def _document_control_payload(document_control: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "history": [
            {
                "version": str(item.get("version") or ""),
                "date": str(item.get("date") or ""),
                "author": str(item.get("author") or ""),
                "change": str(item.get("change") or ""),
            }
            for item in document_control.get("history") or []
        ],
        "approvals": [
            {
                "role": str(item.get("role") or ""),
                "name": str(item.get("name") or ""),
                "status": str(item.get("status") or ""),
                "note": str(item.get("note") or ""),
            }
            for item in document_control.get("approvals") or []
        ],
    }


def _engagement_payload(
    case_inputs: CaseInputs,
    normalized_findings: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    engagement = case_inputs.engagement_metadata["engagement"]
    target_lookup = _target_context_lookup(normalized_findings)
    return {
        "project_name": engagement["project_name"],
        "customer_name": engagement["customer_name"],
        "scope_type": engagement["scope_type"],
        "targets": [
            {
                "target_id": target.get("target_id"),
                "service_name": target["service_name"],
                "base_url": target["base_url"],
                "account_level": target["account_level"],
                "criticality": target.get("criticality"),
                "note": target["note"],
                "environment": target_lookup.get((target.get("target_id"), target["service_name"], target["base_url"]), {}).get("environment"),
                "auth_context": target_lookup.get((target.get("target_id"), target["service_name"], target["base_url"]), {}).get("auth_context"),
            }
            for target in engagement["targets"]
        ],
        "schedule": [
            {
                "phase": item["phase"],
                "date": item["date"],
                "deliverable": item["deliverable"],
                "content": item["content"],
            }
            for item in engagement["schedule"]
        ],
        "team": [
            {
                "company": member["company"],
                "name": member["name"],
                "role": member["role"],
                "scope": member["scope"],
                "contact": member["contact"],
            }
            for member in engagement["team"]
        ],
        "location": _location_payload(engagement["location"]),
    }


def _overview_payload(
    engagement_metadata: Mapping[str, Any],
    normalized_findings: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    engagement = engagement_metadata["engagement"]
    constraints = engagement.get("constraints") or {}
    auth_contexts = sorted({str(item["target"]["auth_context"]) for item in normalized_findings})
    environments = sorted({str(item["target"]["environment"]) for item in normalized_findings})
    target_urls = sorted({str(item["target"]["base_url"]) for item in normalized_findings})
    return {
        "purpose_text": engagement.get("purpose")
        or (
            f"본 웹 취약점 진단은 {engagement['customer_name']}의 "
            f"{engagement['project_name']} 대상 Web 서비스 보안 위험을 식별하기 위해 수행되었습니다."
        ),
        "purpose_note": engagement.get("purpose_note")
        or f"대상 URL: {', '.join(target_urls)} / 고객사: {engagement['customer_name']}",
        "constraints": {
            "assumptions": str(constraints.get("assumptions") or ""),
            "assumptions_status": str(constraints.get("assumptions_status") or ""),
            "exclusions": str(constraints.get("exclusions") or ""),
            "exclusions_status": str(constraints.get("exclusions_status") or ""),
            "limitations": str(constraints.get("limitations") or ""),
            "limitations_status": str(constraints.get("limitations_status") or ""),
        },
        "scope": {
            "type": "웹 애플리케이션 취약점 진단",
            "method": "수동 분석 기반 검증",
            "account_condition": ", ".join(auth_contexts),
            "environment": ", ".join(environments),
        },
    }


def _location_payload(value: Mapping[str, Any]) -> dict[str, str]:
    return {
        "name": str(value["name"]),
        "address": str(value["address"]),
        "ip": str(value["ip"]),
        "access_method": str(value["access_method"]),
        "note": str(value["note"]),
    }


def _finding_entry(normalized_finding: Mapping[str, Any], document_date: str) -> dict[str, Any]:
    severity = _severity(normalized_finding)
    finding_name = str(normalized_finding.get("title") or normalized_finding["classification"]["title_ko"])
    review = _review_payload(normalized_finding)
    result_text = _finding_result_text(normalized_finding, review)
    status_text = _finding_status_text(normalized_finding, review)
    evidence_items = _build_evidence_items(normalized_finding)
    return {
        "review_key": normalized_finding["review_key"],
        "management_id": normalized_finding["finding_id"],
        "taxonomy": dict(normalized_finding["classification"]["taxonomy"]),
        "canonical_key": normalized_finding["classification"]["canonical_key"],
        "target_id": normalized_finding["target"].get("target_id"),
        "system_name": normalized_finding["target"]["service_name"],
        "target_url": normalized_finding["target"]["base_url"],
        "finding_name": finding_name,
        "code": normalized_finding["classification"]["code"],
        "severity": severity,
        "result": result_text,
        "affected_url": normalized_finding["affected"]["url"],
        "summary": normalized_finding["summary"],
        "description": normalized_finding["description"],
        "cause": normalized_finding.get("cause", ""),
        "impact": normalized_finding["impact"],
        "risk_rationale": normalized_finding["risk"]["rationale"],
        "risk_difficulty": normalized_finding["risk"]["difficulty"],
        "risk_asset": normalized_finding["risk"]["asset"],
        "risk_precondition": normalized_finding["risk"]["precondition"],
        "repro_parameters": _repro_parameters(normalized_finding),
        "repro_request": normalized_finding["reproduction"]["request_summary"],
        "repro_response": normalized_finding["reproduction"]["response_summary"],
        "reproduction_steps": list(normalized_finding["reproduction"]["steps"]),
        "preconditions": list(normalized_finding["reproduction"]["preconditions"]),
        "evidence": evidence_items,
        "remediation": list(normalized_finding["remediation"]["actions"]),
        "references": list(normalized_finding.get("references") or []),
        "status": status_text,
        "found_at": _display_date(document_date),
        "due_date": normalized_finding.get("due_date"),
        "owner": normalized_finding.get("owner"),
        "reviewer": normalized_finding.get("reviewer"),
        "notes": normalized_finding.get("notes", ""),
        "false_positive": bool(normalized_finding["false_positive"]),
        "decision_basis": str(normalized_finding.get("decision_basis") or ""),
        "exception_note": str(normalized_finding.get("exception_note") or ""),
        "request_file": normalized_finding["evidence"]["request_file"],
        "request_file_sha256": normalized_finding["evidence"]["request_file_sha256"],
        "response_file": normalized_finding["evidence"]["response_file"],
        "response_file_sha256": normalized_finding["evidence"]["response_file_sha256"],
        "review": review,
        "source": {
            "tool": normalized_finding["source"]["tool"],
            "parser": normalized_finding["source"]["parser"],
            "raw_file": normalized_finding["source"]["raw_file"],
            "raw_file_sha256": normalized_finding["source"]["raw_file_sha256"],
            "manual_finding_file": normalized_finding["source"]["manual_finding_file"],
            "manual_finding_sha256": normalized_finding["source"]["manual_finding_sha256"],
        },
    }


def _severity(normalized_finding: Mapping[str, Any]) -> str:
    severity = str(normalized_finding["classification"]["severity"]).lower()
    return severity if severity in SEVERITY_ORDER else "low"


def _finding_sort_key(normalized_finding: Mapping[str, Any]) -> tuple[int, str, str, str]:
    severity = _severity(normalized_finding)
    return (
        SEVERITY_RANK.get(severity, 99),
        str(normalized_finding["target"]["service_name"]).lower(),
        str(normalized_finding["classification"]["code"]).lower(),
        str(normalized_finding["finding_id"]).lower(),
    )


def _status_text(value: object) -> str:
    status = str(value or "").strip().lower()
    if status == "closed":
        return "완료"
    if status == "accepted":
        return "수용"
    if status == "excluded":
        return "제외"
    if status == "in_progress":
        return "조치중"
    return "미조치"


def _included_in_report(normalized_finding: Mapping[str, Any]) -> bool:
    review = normalized_finding.get("review")
    if not isinstance(review, Mapping):
        return True
    return bool(review.get("included_in_report", True))


def _review_payload(normalized_finding: Mapping[str, Any]) -> dict[str, Any]:
    review = normalized_finding.get("review")
    if not isinstance(review, Mapping):
        return {
            "included_in_report": True,
            "overridden_fields": [],
            "resolution": None,
            "suppression": None,
            "exception": None,
            "review_history": [],
        }
    return {
        "included_in_report": bool(review.get("included_in_report", True)),
        "overridden_fields": [str(item) for item in review.get("overridden_fields") or []],
        "resolution": _optional_review_mapping(review.get("resolution")),
        "suppression": _optional_review_mapping(review.get("suppression")),
        "exception": _optional_review_mapping(review.get("exception")),
        "review_history": [dict(item) for item in review.get("review_history") or []],
    }


def _optional_review_mapping(value: Any) -> dict[str, Any] | None:
    return dict(value) if isinstance(value, Mapping) else None


def _finding_result_text(normalized_finding: Mapping[str, Any], review: Mapping[str, Any]) -> str:
    resolution = review.get("resolution")
    if isinstance(resolution, Mapping) and str(resolution.get("resolution")) == "false_positive":
        return "오탐"
    if bool(normalized_finding["false_positive"]):
        return "오탐"
    return "취약"


def _finding_status_text(normalized_finding: Mapping[str, Any], review: Mapping[str, Any]) -> str:
    resolution = review.get("resolution")
    if isinstance(resolution, Mapping) and str(resolution.get("resolution")) == "accepted_risk":
        return "수용"
    if bool(normalized_finding["false_positive"]):
        return "오탐"
    return _status_text(normalized_finding.get("status"))


def _repro_parameters(normalized_finding: Mapping[str, Any]) -> str:
    parameter = normalized_finding["affected"].get("parameter")
    if parameter is None:
        return "-"
    return str(parameter)


def _build_evidence_items(normalized_finding: Mapping[str, Any]) -> list[dict[str, Any]]:
    screenshots = [
        {
            "finding_id": normalized_finding["finding_id"],
            "type": "screenshot",
            "label": item.get("caption") or "스크린샷",
            "path": item["file"],
            "caption": item.get("caption") or "스크린샷",
            "sha256": item["sha256"],
        }
        for item in normalized_finding["evidence"]["screenshots"]
    ]
    request_entry = {
        "finding_id": normalized_finding["finding_id"],
        "type": "request",
        "label": "HTTP Request",
        "path": normalized_finding["evidence"]["request_file"],
        "caption": "재현 요청 전문",
        "sha256": normalized_finding["evidence"]["request_file_sha256"],
    }
    response_entry = {
        "finding_id": normalized_finding["finding_id"],
        "type": "response",
        "label": "HTTP Response",
        "path": normalized_finding["evidence"]["response_file"],
        "caption": "재현 응답 전문",
        "sha256": normalized_finding["evidence"]["response_file_sha256"],
    }
    return [request_entry, response_entry, *screenshots]


def _severity_counts(finding_entries: Sequence[Mapping[str, Any]]) -> dict[str, int]:
    counts = Counter(str(item["severity"]).lower() for item in finding_entries)
    return {level: int(counts.get(level, 0)) for level in SEVERITY_ORDER}


def _by_target_summary(finding_entries: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[tuple[str | None, str, str], list[Mapping[str, Any]]] = {}
    for finding in finding_entries:
        key = (finding.get("target_id"), str(finding["system_name"]), str(finding["target_url"]))
        grouped.setdefault(key, []).append(finding)

    summaries: list[dict[str, Any]] = []
    for (target_id, system_name, target_url), items in sorted(grouped.items(), key=lambda item: (item[0][1].lower(), item[0][2])):
        counts = Counter(str(entry["severity"]).lower() for entry in items)
        summaries.append(
            {
                "target_id": target_id,
                "system_name": system_name,
                "target_url": target_url,
                "total_findings": len(items),
                "high": int(counts.get("high", 0)),
                "medium": int(counts.get("medium", 0)),
                "low": int(counts.get("low", 0)),
            }
        )
    return summaries


def _target_sections(finding_entries: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[tuple[str | None, str, str], list[Mapping[str, Any]]] = {}
    for finding in finding_entries:
        key = (finding.get("target_id"), str(finding["system_name"]), str(finding["target_url"]))
        grouped.setdefault(key, []).append(finding)

    sections: list[dict[str, Any]] = []
    for (target_id, system_name, target_url), items in sorted(grouped.items(), key=lambda item: (item[0][1].lower(), item[0][2])):
        counts = Counter(str(entry["severity"]).lower() for entry in items)
        sections.append(
            {
                "target_id": target_id,
                "system_name": system_name,
                "target_url": target_url,
                "total_findings": len(items),
                "by_severity": {
                    "high": int(counts.get("high", 0)),
                    "medium": int(counts.get("medium", 0)),
                    "low": int(counts.get("low", 0)),
                },
                "findings": [
                    {
                        "management_id": entry["management_id"],
                        "finding_name": entry["finding_name"],
                        "code": entry["code"],
                        "severity": entry["severity"],
                        "status": entry["status"],
                    }
                    for entry in items
                ],
            }
        )
    return sections


def _summary_comment(
    finding_entries: Sequence[Mapping[str, Any]],
    by_target: Sequence[Mapping[str, Any]],
    review_summary: Mapping[str, Any],
) -> str:
    false_positive_count = sum(1 for item in finding_entries if item["false_positive"])
    if finding_entries and false_positive_count == len(finding_entries):
        base_comment = f"총 {len(finding_entries)}건의 수동 판정 항목이 정리되었으며 모두 오탐으로 분류되었습니다."
    elif finding_entries:
        base_comment = (
            f"총 {len(finding_entries)}건의 취약점이 발견되었으며, "
            f"대상은 {len(by_target)}개 시스템입니다."
        )
    else:
        base_comment = "수동 검토 결과 본문에 유지된 취약점은 없으며, 조치 완료 또는 제외 상태만 기록되었습니다."

    if int(review_summary.get("total_reviewed", 0) or 0) == 0:
        return base_comment

    parts: list[str] = [base_comment]
    if int(review_summary.get("overridden_count", 0) or 0):
        parts.append(f"재평가 override {int(review_summary['overridden_count'])}건이 반영되었습니다.")
    if int(review_summary.get("suppressed_count", 0) or 0):
        parts.append(f"보고서 본문에서 제외된 항목은 {int(review_summary['suppressed_count'])}건입니다.")
    if int(review_summary.get("resolved_count", 0) or 0):
        parts.append(f"resolution 상태가 지정된 항목은 {int(review_summary['resolved_count'])}건입니다.")
    if int(review_summary.get("accepted_risk_count", 0) or 0):
        parts.append(f"위험 수용 항목은 {int(review_summary['accepted_risk_count'])}건입니다.")
    return " ".join(parts)


def _priority_items(finding_entries: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "rank": f"{index}순위",
            "management_id": finding["management_id"],
            "title": finding["finding_name"],
            "severity": finding["severity"],
            "owner": finding["owner"],
            "due_date": finding["due_date"],
        }
        for index, finding in enumerate(finding_entries, start=1)
    ]


def _remediation_plan(normalized_findings: Sequence[Mapping[str, Any]]) -> dict[str, list[str]]:
    return {
        "short_term": _aggregate_track(normalized_findings, "short_term"),
        "mid_term": _aggregate_track(normalized_findings, "mid_term"),
        "long_term": _aggregate_track(normalized_findings, "long_term"),
    }


def _aggregate_track(normalized_findings: Sequence[Mapping[str, Any]], track: str) -> list[str]:
    seen: set[str] = set()
    results: list[str] = []
    for finding in normalized_findings:
        for action in finding["remediation"][track]:
            value = str(action)
            if value not in seen:
                seen.add(value)
                results.append(value)
    return results


def _appendix_evidence(finding_entries: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    evidence: list[dict[str, Any]] = []
    for finding in finding_entries:
        for item in finding["evidence"]:
            evidence.append(dict(item))
    return evidence


def _checklist_items(normalized_findings: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "taxonomy": dict(finding["classification"]["taxonomy"]),
            "code": finding["classification"]["code"],
            "title_ko": finding["classification"]["title_ko"],
            "severity": _severity(finding),
            "canonical_key": finding["classification"]["canonical_key"],
            "status": _checklist_status_text(finding),
            "finding_id": finding["finding_id"],
        }
        for finding in normalized_findings
    ]


def _checklist_status_text(normalized_finding: Mapping[str, Any]) -> str:
    review = _review_payload(normalized_finding)
    resolution = review.get("resolution")
    if isinstance(resolution, Mapping):
        resolution_value = str(resolution.get("resolution"))
        if resolution_value == "accepted_risk":
            return "위험수용"
        if resolution_value == "false_positive":
            return "오탐"
    if bool(normalized_finding["false_positive"]):
        return "오탐"
    return "취약"


def _review_summary(normalized_findings: Sequence[Mapping[str, Any]]) -> dict[str, int]:
    reviews = [_review_payload(finding) for finding in normalized_findings]
    return {
        "total_reviewed": sum(1 for review in reviews if review["review_history"]),
        "overridden_count": sum(1 for review in reviews if review["overridden_fields"]),
        "suppressed_count": sum(1 for review in reviews if review["suppression"] is not None),
        "resolved_count": sum(1 for review in reviews if review["resolution"] is not None),
        "accepted_risk_count": sum(
            1
            for review in reviews
            if isinstance(review["resolution"], Mapping)
            and str(review["resolution"].get("resolution")) == "accepted_risk"
        ),
    }


def _display_date(value: str) -> str:
    return str(value).replace("-", ".")


def _target_context_lookup(normalized_findings: Sequence[Mapping[str, Any]]) -> dict[tuple[Any, str, str], dict[str, str]]:
    lookup: dict[tuple[Any, str, str], dict[str, str]] = {}
    for finding in normalized_findings:
        key = (
            finding["target"].get("target_id"),
            str(finding["target"]["service_name"]),
            str(finding["target"]["base_url"]),
        )
        lookup[key] = {
            "environment": str(finding["target"]["environment"]),
            "auth_context": str(finding["target"]["auth_context"]),
        }
    return lookup
