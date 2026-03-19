"""Web-specific HexStrike normalizer for local case inputs."""

from __future__ import annotations

import hashlib
import logging
from typing import Any, Mapping
from urllib.parse import urljoin

from src.cases import CaseDataError, CaseInputs, FindingInputs
from src.cases.provenance import sha256_file
from src.taxonomies import resolve_taxonomy_code


LOGGER = logging.getLogger(__name__)

RAW_FINDING_MAPPED_KEYS = {
    "id",
    "name",
    "title",
    "severity",
    "risk",
    "rating",
    "endpoint",
    "url",
    "path",
    "method",
    "http_method",
    "parameter",
    "param",
    "description",
    "summary",
    "observation",
    "impact",
    "remediation",
    "request",
    "response",
}

RAW_ROOT_MAPPED_KEYS = {"tool", "scan", "engagement", "findings"}

SEVERITY_ALIASES = {
    "critical": "high",
    "high": "high",
    "medium": "medium",
    "moderate": "medium",
    "low": "low",
    "info": "low",
    "informational": "low",
}

SEVERITY_ORDER = {
    "high": 0,
    "medium": 1,
    "low": 2,
}


def normalize_web_hexstrike_case(case_inputs: CaseInputs) -> dict[str, Any]:
    """Backward-compatible single-finding normalizer."""

    return normalize_web_hexstrike_findings(case_inputs)[0]


def normalize_web_hexstrike_findings(case_inputs: CaseInputs) -> list[dict[str, Any]]:
    """Normalize every finding in a report unit."""

    normalized_findings = [
        _normalize_one_finding(case_inputs, finding_inputs)
        for finding_inputs in case_inputs.findings
    ]
    normalized_findings.sort(key=_finding_sort_key)
    _assert_unique_review_keys(normalized_findings)
    LOGGER.info(
        "Normalized case %s into %s finding(s)",
        case_inputs.case_dir.name,
        len(normalized_findings),
    )
    return normalized_findings


def build_normalized_findings_artifact(
    case_inputs: CaseInputs,
    normalized_findings: list[dict[str, Any]],
) -> dict[str, Any]:
    """Build the canonical case-level normalized-findings artifact."""

    case_id = normalized_findings[0]["target"]["case_id"] if normalized_findings else case_inputs.case_dir.name
    return {
        "schema_version": "1.0",
        "platform": "web",
        "case_id": case_id,
        "findings": normalized_findings,
    }


def _normalize_one_finding(case_inputs: CaseInputs, finding_inputs: FindingInputs) -> dict[str, Any]:
    raw_findings = finding_inputs.raw_scan.get("findings")
    if not isinstance(raw_findings, list) or not raw_findings:
        raise CaseDataError(f"{finding_inputs.raw_scan_file.name} must contain a non-empty findings array")

    raw_finding = raw_findings[0]
    if not isinstance(raw_finding, Mapping):
        raise CaseDataError(f"The first HexStrike finding must be an object in {finding_inputs.raw_scan_file}")

    manual = finding_inputs.manual_finding
    target = _resolve_target(case_inputs, finding_inputs, raw_finding)
    classification = _classification_from_inputs(manual, raw_finding, repo_root=case_inputs.repo_root)
    target_url = _target_url(target, raw_finding, manual)
    request_summary = _summarize_http_request(finding_inputs.request_text)
    response_summary = _summarize_http_response(finding_inputs.response_text)
    reproduction = manual.get("reproduction") or {}
    risk = manual.get("risk") or {}
    affected = manual.get("affected") or {}
    remediation = manual.get("remediation") or {}
    screenshot_captions = manual.get("screenshot_captions") or {}
    if not isinstance(screenshot_captions, Mapping):
        screenshot_captions = {}

    screenshots = [
        {
            "file": finding_inputs.repo_relative(path),
            "caption": str(screenshot_captions.get(path.name) or f"증빙 화면 {index}"),
            "sha256": sha256_file(path),
        }
        for index, path in enumerate(finding_inputs.screenshot_files, start=1)
    ]

    normalized_finding = {
        "schema_version": "1.0",
        "finding_id": str(manual.get("finding_id") or finding_inputs.finding_key),
        "platform": "web",
        "title": str(
            manual.get("finding_name")
            or raw_finding.get("title")
            or raw_finding.get("name")
            or "Untitled finding"
        ),
        "target": {
            "case_id": str(target.get("case_id") or case_inputs.case_dir.name),
            "target_id": target.get("target_id"),
            "service_name": str(target.get("service_name") or "Unknown service"),
            "base_url": str(target.get("base_url") or ""),
            "target_url": target_url,
            "environment": str(target.get("environment") or "unknown"),
            "auth_context": str(target.get("auth_context") or "unknown"),
            "criticality": target.get("criticality"),
        },
        "source": {
            "tool": _tool_name(finding_inputs.raw_scan),
            "raw_file": finding_inputs.repo_relative(finding_inputs.raw_scan_file),
            "raw_file_sha256": sha256_file(finding_inputs.raw_scan_file),
            "manual_finding_file": finding_inputs.repo_relative(finding_inputs.manual_finding_file),
            "manual_finding_sha256": sha256_file(finding_inputs.manual_finding_file),
            "parser": "web_hexstrike",
            "raw": finding_inputs.raw_scan,
        },
        "classification": classification,
        "summary": str(
            manual.get("summary")
            or raw_finding.get("summary")
            or raw_finding.get("observation")
            or raw_finding.get("description")
            or ""
        ),
        "description": _coalesce_text(
            manual.get("description"),
            raw_finding.get("description"),
            raw_finding.get("observation"),
        ),
        "cause": _coalesce_text(
            manual.get("cause"),
            raw_finding.get("observation"),
        ),
        "affected": {
            "system_name": str(target.get("service_name") or "Unknown service"),
            "url": target_url,
            "method": str(affected.get("method") or raw_finding.get("method") or raw_finding.get("http_method") or "GET"),
            "parameter": affected.get("parameter") or raw_finding.get("parameter") or raw_finding.get("param"),
        },
        "evidence": {
            "request_file": finding_inputs.repo_relative(finding_inputs.request_file),
            "request_file_sha256": sha256_file(finding_inputs.request_file),
            "response_file": finding_inputs.repo_relative(finding_inputs.response_file),
            "response_file_sha256": sha256_file(finding_inputs.response_file),
            "screenshots": screenshots,
        },
        "reproduction": {
            "preconditions": _string_list(reproduction.get("preconditions")),
            "steps": _string_list(reproduction.get("steps")),
            "request_summary": request_summary,
            "response_summary": response_summary,
        },
        "impact": str(manual.get("impact") or raw_finding.get("impact") or ""),
        "risk": {
            "rationale": str(risk.get("rationale") or manual.get("decision_basis") or manual.get("impact") or ""),
            "difficulty": str(risk.get("difficulty") or "보통"),
            "asset": str(risk.get("asset") or target.get("service_name") or ""),
            "precondition": str(risk.get("precondition") or target.get("auth_context") or ""),
        },
        "remediation": {
            "summary": str(remediation.get("summary") or _remediation_summary(raw_finding) or manual.get("summary") or ""),
            "actions": _string_list(
                list(remediation.get("short_term") or [])
                + list(remediation.get("mid_term") or [])
                + list(remediation.get("long_term") or [])
            ),
            "short_term": _string_list(remediation.get("short_term")),
            "mid_term": _string_list(remediation.get("mid_term")),
            "long_term": _string_list(remediation.get("long_term")),
        },
        "references": _string_list(manual.get("references")),
        "decision_basis": str(manual.get("decision_basis") or ""),
        "exception_note": str(manual.get("exception_note") or ""),
        "false_positive": bool(manual.get("false_positive", False)),
        "status": str(manual.get("status") or "open"),
        "owner": manual.get("owner"),
        "reviewer": manual.get("reviewer"),
        "due_date": manual.get("due_date"),
        "notes": str(manual.get("notes") or ""),
        "unmapped_fields": {
            "root": {
                key: value
                for key, value in finding_inputs.raw_scan.items()
                if key not in RAW_ROOT_MAPPED_KEYS
            },
            "finding": {
                key: value
                for key, value in raw_finding.items()
                if key not in RAW_FINDING_MAPPED_KEYS
            },
        },
    }
    normalized_finding["review_key"] = _review_key(normalized_finding)
    return normalized_finding


def _resolve_target(
    case_inputs: CaseInputs,
    finding_inputs: FindingInputs,
    raw_finding: Mapping[str, Any],
) -> dict[str, Any]:
    if finding_inputs.target_metadata is not None:
        target = dict(finding_inputs.target_metadata)
        target.setdefault("target_id", None)
        target.setdefault("criticality", None)
        return target

    engagement_targets = list(case_inputs.engagement_metadata["engagement"]["targets"])
    manual = finding_inputs.manual_finding
    target_ref = str(manual.get("target_ref") or "").strip()
    if target_ref:
        matches = [
            target
            for target in engagement_targets
            if str(target.get("target_id") or "") == target_ref
            or str(target.get("service_name") or "") == target_ref
            or str(target.get("base_url") or "") == target_ref
        ]
        if len(matches) == 1:
            return _target_metadata_from_engagement(case_inputs, matches[0])
        raise CaseDataError(f"Unable to resolve target_ref '{target_ref}' in {finding_inputs.manual_finding_file}")

    explicit_url = str((manual.get("affected") or {}).get("url") or "").strip()
    if not explicit_url:
        explicit_url = str(raw_finding.get("endpoint") or raw_finding.get("url") or "").strip()
    if not explicit_url and raw_finding.get("path"):
        path = str(raw_finding.get("path") or "")
        candidate_matches = [
            target
            for target in engagement_targets
            if str(target.get("base_url") or "").strip()
        ]
        if len(candidate_matches) == 1:
            base_url = str(candidate_matches[0]["base_url"])
            explicit_url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))

    matches = [
        target
        for target in engagement_targets
        if _url_matches_base(explicit_url, str(target.get("base_url") or ""))
    ]
    if len(matches) == 1:
        return _target_metadata_from_engagement(case_inputs, matches[0])

    if len(engagement_targets) == 1:
        only_target = engagement_targets[0]
        if explicit_url and not _url_matches_base(explicit_url, str(only_target.get("base_url") or "")):
            raise CaseDataError(
                f"Unable to align finding URL '{explicit_url}' with engagement target '{only_target.get('base_url')}'"
            )
        return _target_metadata_from_engagement(case_inputs, only_target)

    raise CaseDataError(
        f"Unable to resolve finding target for {finding_inputs.manual_finding_file}; add manual-finding.target_ref"
    )


def _target_metadata_from_engagement(case_inputs: CaseInputs, engagement_target: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "case_id": case_inputs.case_dir.name,
        "target_id": engagement_target.get("target_id"),
        "service_name": str(engagement_target.get("service_name") or ""),
        "base_url": str(engagement_target.get("base_url") or ""),
        "environment": str(engagement_target.get("environment") or "unknown"),
        "auth_context": str(engagement_target.get("auth_context") or engagement_target.get("account_level") or "unknown"),
        "criticality": engagement_target.get("criticality"),
    }


def _classification_from_inputs(
    manual: Mapping[str, Any],
    raw_finding: Mapping[str, Any],
    *,
    repo_root: Any,
) -> dict[str, Any]:
    taxonomy = manual.get("taxonomy") or {}
    taxonomy_name = str(taxonomy.get("name") or "")
    taxonomy_version = str(taxonomy.get("version") or "")
    code = str(manual.get("code") or "")
    mapping = resolve_taxonomy_code(taxonomy_name, taxonomy_version, code, repo_root)
    severity = str(
        manual.get("severity")
        or _normalized_severity(raw_finding.get("severity") or raw_finding.get("risk") or raw_finding.get("rating"))
    )
    return {
        "taxonomy": mapping["taxonomy"],
        "code": code,
        "title_ko": str(manual.get("title_ko") or mapping["title_ko"]),
        "severity": severity,
        "canonical_key": mapping["canonical_key"],
    }


def _finding_sort_key(finding: Mapping[str, Any]) -> tuple[int, str, str, str]:
    severity = str(finding["classification"]["severity"]).lower()
    return (
        SEVERITY_ORDER.get(severity, 99),
        str(finding["target"]["service_name"]).lower(),
        str(finding["classification"]["code"]).lower(),
        str(finding["finding_id"]).lower(),
    )


def _normalized_severity(value: Any) -> str:
    raw = str(value or "").strip().lower()
    return SEVERITY_ALIASES.get(raw, "unknown")


def _review_key(finding: Mapping[str, Any]) -> str:
    parts = [
        _normalized_review_component(finding["classification"]["taxonomy"]["name"]),
        _normalized_review_component(finding["classification"]["taxonomy"]["version"]),
        _normalized_review_component(finding["classification"]["canonical_key"]),
        _normalized_review_component(finding["target"]["service_name"]),
        _normalized_review_component(finding["target"]["base_url"]),
        _normalized_review_component(finding["affected"]["url"]),
        _normalized_review_method(finding["affected"]["method"]),
        _normalized_review_component(finding["affected"].get("parameter")),
        _normalized_review_component(finding["source"]["tool"]),
        _normalized_review_component(finding["source"]["raw_file"]),
    ]
    digest = hashlib.sha256("\x1f".join(parts).encode("utf-8")).hexdigest()[:16]
    return f"rk-{digest}"


def _normalized_review_component(value: Any) -> str:
    text = str(value or "").strip()
    if text.startswith(("http://", "https://")):
        return text.rstrip("/").lower()
    return " ".join(text.split()).lower()


def _normalized_review_method(value: Any) -> str:
    return str(value or "").strip().upper()


def _assert_unique_review_keys(normalized_findings: list[dict[str, Any]]) -> None:
    seen: dict[str, str] = {}
    for finding in normalized_findings:
        review_key = str(finding["review_key"])
        existing = seen.get(review_key)
        if existing is not None:
            raise CaseDataError(
                "Duplicate review_key detected for "
                f"{finding['finding_id']} and {existing}: {review_key}"
            )
        seen[review_key] = str(finding["finding_id"])


def _tool_name(raw_scan: Mapping[str, Any]) -> str:
    tool = raw_scan.get("tool")
    if isinstance(tool, Mapping):
        return str(tool.get("name") or "HexStrike")
    return str(raw_scan.get("source") or "HexStrike")


def _target_url(target: Mapping[str, Any], raw_finding: Mapping[str, Any], manual: Mapping[str, Any]) -> str:
    affected = manual.get("affected") or {}
    explicit_affected_url = str(affected.get("url") or "").strip()
    if explicit_affected_url:
        return explicit_affected_url

    explicit_target = str(target.get("target_url") or "").strip()
    if explicit_target:
        return explicit_target

    endpoint = str(raw_finding.get("endpoint") or raw_finding.get("url") or "").strip()
    if endpoint:
        return endpoint

    base_url = str(target.get("base_url") or "").strip()
    path = str(raw_finding.get("path") or "").strip()
    return urljoin(base_url.rstrip("/") + "/", path.lstrip("/")) if base_url and path else base_url


def _url_matches_base(url: str, base_url: str) -> bool:
    normalized_url = url.strip().rstrip("/")
    normalized_base = base_url.strip().rstrip("/")
    return bool(normalized_url and normalized_base) and (
        normalized_url == normalized_base or normalized_url.startswith(normalized_base + "/")
    )


def _coalesce_text(*values: Any) -> str:
    pieces = [str(value).strip() for value in values if str(value or "").strip()]
    if not pieces:
        return ""
    deduplicated: list[str] = []
    for piece in pieces:
        if piece not in deduplicated:
            deduplicated.append(piece)
    return "\n\n".join(deduplicated)


def _string_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [str(item) for item in value if str(item).strip()]
    return [str(value)]


def _summarize_http_request(request_text: str) -> str:
    lines = [line.rstrip() for line in request_text.splitlines()]
    request_line = next((line for line in lines if line.strip()), "")
    host = next((line.split(":", 1)[1].strip() for line in lines if line.lower().startswith("host:")), "")
    content_type = next((line.split(":", 1)[1].strip() for line in lines if line.lower().startswith("content-type:")), "")
    body = _body_excerpt(request_text)
    parts = [
        part
        for part in [
            request_line,
            f"Host: {host}" if host else "",
            f"Content-Type: {content_type}" if content_type else "",
            f"Body: {body}" if body else "",
        ]
        if part
    ]
    return " / ".join(parts)


def _summarize_http_response(response_text: str) -> str:
    lines = [line.rstrip() for line in response_text.splitlines()]
    status_line = next((line for line in lines if line.strip()), "")
    content_type = next((line.split(":", 1)[1].strip() for line in lines if line.lower().startswith("content-type:")), "")
    body = _body_excerpt(response_text)
    parts = [
        part
        for part in [
            status_line,
            f"Content-Type: {content_type}" if content_type else "",
            f"Body: {body}" if body else "",
        ]
        if part
    ]
    return " / ".join(parts)


def _body_excerpt(http_text: str, *, limit: int = 180) -> str:
    separator = "\r\n\r\n" if "\r\n\r\n" in http_text else "\n\n"
    body = http_text.split(separator, 1)[1] if separator in http_text else ""
    normalized = " ".join(body.split())
    if len(normalized) <= limit:
        return normalized
    return normalized[: limit - 3] + "..."


def _remediation_summary(raw_finding: Mapping[str, Any]) -> str:
    remediation = raw_finding.get("remediation")
    if isinstance(remediation, list):
        return "; ".join(str(item) for item in remediation if str(item).strip())
    return str(remediation or "")
