"""Bridge the report payload into the existing report-template renderer."""

from __future__ import annotations

import importlib.util
import json
import logging
import sys
from functools import lru_cache
from pathlib import Path
from types import ModuleType
from typing import Any, Mapping


LOGGER = logging.getLogger(__name__)

RISK_KEY_BY_SEVERITY = {
    "high": "high",
    "medium": "mid",
    "low": "low",
}

RISK_LABEL_BY_KEY = {
    "high": "상",
    "mid": "중",
    "low": "하",
}


def render_report_preview(
    report_payload: Mapping[str, Any],
    *,
    case_dir: Path,
    repo_root: Path,
) -> dict[str, str | None]:
    """Render a case-specific HTML preview using the existing template app."""

    build_report = _load_build_report(repo_root)
    profile = build_report.resolve_profile("default", None)
    dataset = build_template_dataset(report_payload, repo_root=repo_root)
    partials = build_report.ordered_partials()
    css = build_report.join_files(build_report.CSS_DIR, build_report.CSS_ORDER)
    js = build_report.join_files(build_report.JS_DIR, build_report.JS_ORDER)
    body = build_report.join_partials(partials, dataset)
    html_source = build_report.render_document(
        css=css,
        body=body,
        js=js,
        profile=profile,
        dataset_name="case-preview",
    )
    html = build_report.resolve_page_tokens(html_source)

    output_dir = case_dir / "output"
    output_dir.mkdir(parents=True, exist_ok=True)
    html_path = output_dir / "report-preview.html"
    validation_path = output_dir / "report-preview.validation.json"
    pdf_path = output_dir / "report-preview.pdf"

    html_path.write_text(html, encoding="utf-8")
    page_map = build_report.build_page_map(html)
    validation = build_report.validate_print_safety(html, dataset, page_map)
    pdf_result = build_report.build_pdf(html_path, pdf_path, allow_local_file_access=False)
    validation["pdf"] = pdf_result
    validation_path.write_text(json.dumps(validation, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    pdf_output = str(pdf_path) if pdf_result.get("status") == "OK" and pdf_path.exists() else None
    LOGGER.info("Rendered report preview HTML to %s", html_path)
    return {
        "html_path": str(html_path),
        "validation_path": str(validation_path),
        "pdf_path": pdf_output,
    }


def build_template_dataset(
    report_payload: Mapping[str, Any],
    *,
    repo_root: Path,
) -> dict[str, Any]:
    """Convert the explicit report payload into the current template dataset shape."""

    _require_top_level(
        report_payload,
        "document",
        "document_control",
        "engagement",
        "overview",
        "tool_inventory",
        "summary",
        "review_summary",
        "target_sections",
        "findings",
        "remediation_plan",
        "appendix",
    )
    build_report = _load_build_report(repo_root)
    profile = build_report.resolve_profile("default", None)
    dataset = build_report.load_dataset("default", profile)
    finding_payloads = list(report_payload["findings"])
    summary = dict(report_payload["summary"])
    checklist_items = _checklist_items(report_payload)

    summary_systems = [
        {
            "system_name": target["system_name"],
            "total": target["total_findings"],
            "vuln": target["total_findings"],
            "ok": 0,
            "na": 0,
        }
        for target in summary["by_target"]
    ]
    summary_findings = []
    summary_priorities = []
    template_findings = []
    appendix_items: list[dict[str, Any]] = []
    figure_index = 2
    appendix_index = 1

    for finding_index, finding in enumerate(finding_payloads, start=1):
        _require_top_level(
            finding,
            "taxonomy",
            "canonical_key",
            "management_id",
            "finding_name",
            "code",
            "severity",
        )
        risk_key = _risk_key(str(finding["severity"]))
        risk_label = RISK_LABEL_BY_KEY[risk_key]
        finding_evidences = []
        evidence_refs: list[str] = []

        for evidence_offset, evidence in enumerate(finding["evidence"], start=1):
            evidence_id = f"EVD-{appendix_index:03d}"
            evidence_refs.append(evidence_id)
            figure_id = f"figure-{figure_index:02d}"
            figure_number = figure_index
            figure_index += 1
            appendix_index += 1
            appendix_item = _appendix_item(
                build_report,
                evidence,
                evidence_id=evidence_id,
                figure_id=figure_id,
                finding_id=str(finding["management_id"]),
                caption_index=evidence_offset,
                repo_root=repo_root,
            )
            appendix_items.append(appendix_item)
            if evidence["type"] == "screenshot":
                finding_evidences.append(
                    {
                        "evidence_id": evidence_id,
                        "title": evidence.get("caption") or evidence.get("label") or evidence_id,
                        "lead_label": "증빙 파일",
                        "lead_field": "file",
                        "lead_text": evidence["path"],
                        "io_text": evidence.get("caption") or evidence.get("label") or "",
                        "appendix_ref": f"Appendix C · {evidence_id}",
                        "box_text": f"[증빙 파일] {evidence['path']}",
                        "figure_id": figure_id,
                        "figure_caption": f"[그림 {figure_number}] {finding['management_id']} 재현 증빙 화면",
                        "image_src": appendix_item.get("image_src", ""),
                        "image_alt": appendix_item.get("title", ""),
                    }
                )

        if not finding_evidences:
            finding_evidences.append(
                {
                    "evidence_id": "EVD-000",
                    "title": "추가 증빙 없음",
                    "lead_label": "증빙 상태",
                    "lead_field": "status",
                    "lead_text": "스크린샷 증빙이 제공되지 않았습니다.",
                    "io_text": "HTTP 요청/응답 전문은 Appendix C를 참고하십시오.",
                    "appendix_ref": "Appendix C",
                    "box_text": "[증빙 이미지 없음]",
                    "figure_id": f"figure-{figure_index:02d}",
                    "figure_caption": f"[그림 {figure_index}] 증빙 이미지 없음",
                }
            )
            figure_index += 1

        note_parts = [
            str(finding.get("notes") or "").strip(),
            str(finding.get("decision_basis") or "").strip(),
            str(finding.get("exception_note") or "").strip(),
            _review_note(finding),
        ]
        note_text = " / ".join(part for part in note_parts if part)
        template_findings.append(
            {
                "id": finding["management_id"],
                "toc_number": f"{finding_index})",
                "toc_title": finding["finding_name"],
                "risk_key": risk_key,
                "risk_label": risk_label,
                "title": finding["finding_name"],
                "target_name": finding["system_name"],
                "target_url": finding["target_url"],
                "code": finding["code"],
                "path": finding["affected_url"],
                "result": finding["result"],
                "discovered_at": finding["found_at"],
                "due_at": finding["due_date"] or "-",
                "status": finding["status"],
                "owner": finding["owner"] or "-",
                "reviewer": finding["reviewer"] or "-",
                "summary": finding["summary"],
                "description": finding["description"],
                "cause": finding.get("cause") or finding["description"],
                "repro_parameters": finding.get("repro_parameters") or "-",
                "repro_request": finding.get("repro_request") or "",
                "repro_response": finding.get("repro_response") or "",
                "evidence_refs": ", ".join(evidence_refs),
                "repro_steps": list(finding["reproduction_steps"]),
                "evidences": finding_evidences,
                "impact": finding["impact"],
                "risk_rationale": finding.get("risk_rationale") or finding["impact"],
                "risk_difficulty": finding.get("risk_difficulty") or "보통",
                "risk_asset": finding.get("risk_asset") or finding["system_name"],
                "risk_precondition": finding.get("risk_precondition")
                or ", ".join(finding.get("preconditions") or [])
                or "-",
                "remediation_steps": list(finding["remediation"]),
                "references": list(finding.get("references") or []),
                "retest_date": "",
                "retest_result": "미수행",
                "retest_note": "이번 샘플 범위에서는 재점검을 수행하지 않았습니다.",
                "note": note_text,
                "_profile": profile,
            }
        )
        summary_findings.append(
            {
                "number": str(finding_index),
                "system_name": finding["system_name"],
                "finding_id": finding["management_id"],
                "title": finding["finding_name"],
                "risk_key": risk_key,
                "risk_label": risk_label,
                "status": finding["status"],
            }
        )
        summary_priorities.append(
            {
                "rank": f"{finding_index}순위",
                "finding_id": finding["management_id"],
                "title": finding["finding_name"],
                "risk_key": risk_key,
                "risk_label": risk_label,
                "due": finding["due_date"] or "-",
                "owner": finding["owner"] or "-",
            }
        )

    dataset["document"] = _document_dataset(report_payload)
    dataset["engagement"] = dict(report_payload["engagement"])
    dataset["overview"] = dict(report_payload["overview"])
    dataset["diagnostic_overview"] = {
        **dict(dataset["diagnostic_overview"]),
        "tool_list": _tool_list(report_payload),
        "checklist_items": checklist_items,
    }
    dataset["summary"] = {
        **summary,
        "systems": summary_systems,
        "findings": summary_findings,
        "priorities": summary_priorities,
    }
    dataset["findings"] = template_findings
    dataset["countermeasures"] = _countermeasure_tracks(report_payload)
    dataset["appendix_c"] = appendix_items
    dataset["_dataset_name"] = "case-preview"
    dataset["_profile"] = profile
    dataset["_profile_name"] = profile.name
    return dataset


def _appendix_item(
    build_report: ModuleType,
    evidence: Mapping[str, Any],
    *,
    evidence_id: str,
    figure_id: str,
    finding_id: str,
    caption_index: int,
    repo_root: Path,
) -> dict[str, Any]:
    repo_relative_path = str(evidence["path"])
    absolute_path = (repo_root / repo_relative_path).resolve()
    image_src = ""
    if evidence["type"] == "screenshot" and absolute_path.exists():
        image_src = build_report.image_file_to_data_uri(absolute_path)

    title = evidence.get("caption") or evidence.get("label") or evidence_id
    description = {
        "request": "재현 요청 전문 파일 경로를 보존합니다.",
        "response": "재현 응답 전문 파일 경로를 보존합니다.",
        "screenshot": "본문 재현 단계와 연결되는 스크린샷 증빙입니다.",
    }.get(str(evidence["type"]), "추가 증빙 자료입니다.")

    return {
        "evidence_id": evidence_id,
        "finding_ref": f"[관련 취약점: {finding_id}]",
        "title": title,
        "finding_id": finding_id,
        "evidence_type": evidence["type"],
        "body_ref": f"4장 상세 결과 · {evidence_id}",
        "box_text": f"[증빙 파일] {repo_relative_path}",
        "figure_id": figure_id,
        "figure_caption": f"[그림 {figure_id.split('-')[-1]}] Appendix C 추가 증빙 화면 (#{caption_index})",
        "description": f"{description} ({repo_relative_path})",
        "image_src": image_src,
        "image_alt": title,
        "image_file_name": absolute_path.name if absolute_path.exists() else None,
    }


def _countermeasure_tracks(report_payload: Mapping[str, Any]) -> dict[str, list[dict[str, Any]]]:
    tracks = {"short": [], "mid": [], "long": []}
    for finding in report_payload["findings"]:
        risk_key = _risk_key(str(finding["severity"]))
        risk_label = RISK_LABEL_BY_KEY[risk_key]
        actions = list(finding.get("remediation") or [])
        if actions:
            tracks["short"].append(
                {
                    "finding_id": finding["management_id"],
                    "title": finding["finding_name"],
                    "action": " / ".join(str(item) for item in actions),
                    "owner": finding["owner"] or "-",
                    "due": finding["due_date"] or "-",
                    "retest": "동일 재현 절차 및 회귀 테스트를 수행합니다.",
                    "risk_key": risk_key,
                    "risk_label": risk_label,
                }
            )

    for track_name in ("short_term", "mid_term", "long_term"):
        actions = list(report_payload["remediation_plan"][track_name])
        if not actions:
            continue
        track_key = "short" if track_name == "short_term" else "mid" if track_name == "mid_term" else "long"
        tracks[track_key].append(
            {
                "finding_id": "AGGREGATED",
                "title": "보고서 단위 집계 조치",
                "action": " / ".join(str(item) for item in actions),
                "owner": "-",
                "due": "-",
                "retest": "전체 조치 완료 후 다건 회귀 테스트를 수행합니다.",
                "risk_key": "low",
                "risk_label": RISK_LABEL_BY_KEY["low"],
            }
        )
    return tracks


def _checklist_items(report_payload: Mapping[str, Any]) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for item in report_payload["appendix"]["checklist"]:
        severity = str(item["severity"]).lower()
        risk_key = _risk_key(severity)
        items.append(
            {
                "code": item["code"],
                "name": item["title_ko"],
                "point": item["canonical_key"],
                "risk_key": risk_key,
                "risk_label": RISK_LABEL_BY_KEY[risk_key],
                "result_text": item["status"],
            }
        )
    return items


def _tool_list(report_payload: Mapping[str, Any]) -> list[dict[str, str]]:
    return [
        {
            "name": str(item["name"]),
            "usage": str(item["purpose"]),
            "note": " / ".join(
                part
                for part in [
                    str(item["category"]),
                    str(item["source_type"]),
                    str(item.get("note") or ""),
                ]
                if part
            ),
        }
        for item in report_payload["tool_inventory"]
    ]


def _document_dataset(report_payload: Mapping[str, Any]) -> dict[str, Any]:
    document = dict(report_payload["document"])
    document_control = report_payload["document_control"]
    document["history"] = [
        {
            "version": item["version"],
            "date": item["date"],
            "author": item["author"],
            "change_log": item["change"],
        }
        for item in document_control["history"]
    ]
    document["approvals"] = [
        {
            "kind": item["role"],
            "department": "",
            "name": item["name"],
            "status": item["status"],
            "note": item["note"],
        }
        for item in document_control["approvals"]
    ]
    return document


def _review_note(finding: Mapping[str, Any]) -> str:
    review = finding.get("review")
    if not isinstance(review, Mapping):
        return ""

    parts: list[str] = []
    if review.get("overridden_fields"):
        parts.append("review override: " + ", ".join(str(item) for item in review["overridden_fields"]))

    resolution = review.get("resolution")
    if isinstance(resolution, Mapping):
        parts.append(
            "review resolution: "
            f"{resolution.get('resolution')} ({resolution.get('reason')})"
        )

    suppression = review.get("suppression")
    if isinstance(suppression, Mapping):
        parts.append(
            "review suppression: "
            f"{suppression.get('reason_code')} ({suppression.get('reason')})"
        )

    review_exception = review.get("exception")
    if isinstance(review_exception, Mapping):
        parts.append(
            "review exception: "
            f"{review_exception.get('exception_type')} / {review_exception.get('note')}"
        )

    return " / ".join(part for part in parts if part)


def _risk_key(severity: str) -> str:
    return RISK_KEY_BY_SEVERITY.get(severity.lower(), "low")


def _require_top_level(payload: Mapping[str, Any], *keys: str) -> None:
    missing = [key for key in keys if key not in payload]
    if missing:
        raise ValueError("Missing required payload field(s): " + ", ".join(missing))


@lru_cache(maxsize=1)
def _load_build_report(repo_root: Path) -> ModuleType:
    build_report_path = repo_root / "apps" / "report-template" / "build_report.py"
    spec = importlib.util.spec_from_file_location("report_template_build_report", build_report_path)
    if spec is None or spec.loader is None:  # pragma: no cover - defensive boundary
        raise ImportError(f"Unable to load report-template renderer: {build_report_path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module
