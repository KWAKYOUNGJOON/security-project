"""Apply the manual review layer to normalized Web findings."""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
from typing import Any, Mapping, Sequence

from src.cases import CaseInputs
from src.review.review_models import (
    ReviewException,
    ReviewOverride,
    ReviewResolution,
    ReviewSuppression,
)
from src.taxonomies import resolve_taxonomy_code


class ReviewEngineError(ValueError):
    """Raised when review input cannot be applied deterministically."""


def apply_review(
    case_inputs: CaseInputs,
    normalized_findings: Sequence[Mapping[str, Any]],
    *,
    normalized_artifact_path: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Apply review actions to normalized findings and build reviewed artifacts."""

    reviewed_findings = [deepcopy(dict(finding)) for finding in normalized_findings]
    finding_lookup = _build_finding_lookup(reviewed_findings)
    for finding in reviewed_findings:
        finding["review"] = _initial_review_state()

    overrides = _load_overrides(case_inputs)
    resolutions = _load_resolutions(case_inputs)
    suppressions = _load_suppressions(case_inputs)
    exceptions = _load_exceptions(case_inputs)

    actions: list[dict[str, Any]] = []
    order = 1

    for override in overrides:
        finding = _resolve_finding(finding_lookup, override.review_key)
        changed_fields = _apply_override(finding, override, case_inputs)
        order = _record_action(
            finding,
            actions,
            order=order,
            review_key=override.review_key,
            action_type="override",
            changed_fields=changed_fields,
            reason=override.reason,
            reviewer=override.reviewer,
            reviewed_at=override.reviewed_at,
            result="applied",
        )

    for resolution in resolutions:
        finding = _resolve_finding(finding_lookup, resolution.review_key)
        changed_fields = _apply_resolution(finding, resolution)
        order = _record_action(
            finding,
            actions,
            order=order,
            review_key=resolution.review_key,
            action_type="resolution",
            changed_fields=changed_fields,
            reason=resolution.reason,
            reviewer=resolution.reviewer,
            reviewed_at=resolution.reviewed_at,
            result=resolution.final_status,
        )

    for suppression in suppressions:
        finding = _resolve_finding(finding_lookup, suppression.review_key)
        changed_fields = _apply_suppression(finding, suppression)
        order = _record_action(
            finding,
            actions,
            order=order,
            review_key=suppression.review_key,
            action_type="suppression",
            changed_fields=changed_fields,
            reason=suppression.reason,
            reviewer=suppression.reviewer,
            reviewed_at=suppression.reviewed_at,
            result=suppression.reason_code,
        )

    for review_exception in exceptions:
        finding = _resolve_finding(finding_lookup, review_exception.review_key)
        changed_fields = _apply_exception(finding, review_exception)
        order = _record_action(
            finding,
            actions,
            order=order,
            review_key=review_exception.review_key,
            action_type="exception",
            changed_fields=changed_fields,
            reason=review_exception.note,
            reviewer=review_exception.approved_by,
            reviewed_at=review_exception.expires_at,
            result="tagged",
        )

    for finding in reviewed_findings:
        finding["review"]["included_in_report"] = _included_in_report(finding["review"])

    case_id = (
        str(reviewed_findings[0]["target"]["case_id"])
        if reviewed_findings
        else case_inputs.case_dir.name
    )
    reviewed_bundle = {
        "schema_version": "1.0",
        "platform": "web",
        "case_id": case_id,
        "source_artifact": normalized_artifact_path,
        "findings": reviewed_findings,
    }
    review_log = {
        "case_id": case_id,
        "generated_at": _generated_at(),
        "source_artifact": normalized_artifact_path,
        "actions": actions,
    }
    return reviewed_bundle, review_log


def _build_finding_lookup(reviewed_findings: Sequence[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    lookup: dict[str, dict[str, Any]] = {}
    for finding in reviewed_findings:
        review_key = str(finding["review_key"])
        if review_key in lookup:
            raise ReviewEngineError(f"Duplicate review_key in normalized findings: {review_key}")
        lookup[review_key] = finding
    return lookup


def _resolve_finding(finding_lookup: Mapping[str, dict[str, Any]], review_key: str) -> dict[str, Any]:
    finding = finding_lookup.get(review_key)
    if finding is None:
        raise ReviewEngineError(f"Review key not found in normalized findings: {review_key}")
    return finding


def _initial_review_state() -> dict[str, Any]:
    return {
        "included_in_report": True,
        "overridden_fields": [],
        "resolution": None,
        "suppression": None,
        "exception": None,
        "review_history": [],
    }


def _load_overrides(case_inputs: CaseInputs) -> list[ReviewOverride]:
    return _deduplicate_actions(
        [ReviewOverride.from_mapping(item) for item in case_inputs.review.overrides],
        action_name="override",
    )


def _load_resolutions(case_inputs: CaseInputs) -> list[ReviewResolution]:
    return _deduplicate_actions(
        [ReviewResolution.from_mapping(item) for item in case_inputs.review.resolutions],
        action_name="resolution",
    )


def _load_suppressions(case_inputs: CaseInputs) -> list[ReviewSuppression]:
    return _deduplicate_actions(
        [ReviewSuppression.from_mapping(item) for item in case_inputs.review.suppressions],
        action_name="suppression",
    )


def _load_exceptions(case_inputs: CaseInputs) -> list[ReviewException]:
    return _deduplicate_actions(
        [ReviewException.from_mapping(item) for item in case_inputs.review.exceptions],
        action_name="exception",
    )


def _deduplicate_actions(actions: list[Any], *, action_name: str) -> list[Any]:
    seen: set[str] = set()
    for action in actions:
        if action.review_key in seen:
            raise ReviewEngineError(f"Duplicate {action_name} action for review_key: {action.review_key}")
        seen.add(action.review_key)
    return actions


def _apply_override(
    finding: dict[str, Any],
    override: ReviewOverride,
    case_inputs: CaseInputs,
) -> list[str]:
    review_state = finding["review"]
    if review_state["overridden_fields"]:
        raise ReviewEngineError(f"Multiple override actions for review_key: {override.review_key}")

    changed_fields: list[str] = []
    changes = dict(override.changes)

    if "canonical_key" in changes and "code" not in changes:
        raise ReviewEngineError("Override changes.canonical_key requires changes.code for taxonomy validation")

    if "code" in changes:
        mapping = resolve_taxonomy_code(
            str(finding["classification"]["taxonomy"]["name"]),
            str(finding["classification"]["taxonomy"]["version"]),
            str(changes["code"]),
            case_inputs.repo_root,
        )
        expected_canonical_key = str(mapping["canonical_key"])
        provided_canonical_key = str(changes.get("canonical_key") or expected_canonical_key)
        if provided_canonical_key != expected_canonical_key:
            raise ReviewEngineError(
                "Override canonical_key does not match taxonomy mapping for code "
                f"{changes['code']}: expected {expected_canonical_key}, got {provided_canonical_key}"
            )
        finding["classification"]["code"] = str(changes["code"])
        finding["classification"]["canonical_key"] = expected_canonical_key
        if "title_ko" not in changes:
            finding["classification"]["title_ko"] = str(mapping["title_ko"])
            finding["title"] = str(mapping["title_ko"])
            changed_fields.extend(["classification.title_ko", "title"])
        changed_fields.extend(["classification.code", "classification.canonical_key"])

    if "severity" in changes:
        finding["classification"]["severity"] = str(changes["severity"])
        changed_fields.append("classification.severity")

    if "title_ko" in changes:
        finding["classification"]["title_ko"] = str(changes["title_ko"])
        finding["title"] = str(changes["title_ko"])
        changed_fields.extend(["classification.title_ko", "title"])

    if "title_en" in changes:
        finding["classification"]["title_en"] = str(changes["title_en"])
        changed_fields.append("classification.title_en")

    if "summary" in changes:
        finding["summary"] = str(changes["summary"])
        changed_fields.append("summary")

    if "impact" in changes:
        finding["impact"] = str(changes["impact"])
        changed_fields.append("impact")

    if "remediation" in changes:
        finding["remediation"]["summary"] = str(changes["remediation"])
        changed_fields.append("remediation.summary")

    review_state["overridden_fields"] = list(dict.fromkeys(changed_fields))
    return review_state["overridden_fields"]


def _apply_resolution(finding: dict[str, Any], resolution: ReviewResolution) -> list[str]:
    review_state = finding["review"]
    if review_state["resolution"] is not None:
        raise ReviewEngineError(f"Multiple resolution actions for review_key: {resolution.review_key}")

    review_state["resolution"] = {
        "resolution": resolution.resolution,
        "final_status": resolution.final_status,
        "reason": resolution.reason,
        "reviewer": resolution.reviewer,
        "reviewed_at": resolution.reviewed_at,
    }

    changed_fields: list[str] = ["review.resolution"]
    if resolution.resolution == "false_positive":
        finding["false_positive"] = True
        changed_fields.append("false_positive")

    status_value = {
        "excluded": "excluded",
        "accepted": "accepted",
        "closed": "closed",
    }[resolution.final_status]
    finding["status"] = status_value
    changed_fields.append("status")
    return changed_fields


def _apply_suppression(finding: dict[str, Any], suppression: ReviewSuppression) -> list[str]:
    review_state = finding["review"]
    if review_state["suppression"] is not None:
        raise ReviewEngineError(f"Multiple suppression actions for review_key: {suppression.review_key}")

    review_state["suppression"] = {
        "action": suppression.action,
        "reason_code": suppression.reason_code,
        "reason": suppression.reason,
        "reviewer": suppression.reviewer,
        "reviewed_at": suppression.reviewed_at,
    }
    review_state["included_in_report"] = False
    return ["review.suppression", "review.included_in_report"]


def _apply_exception(finding: dict[str, Any], review_exception: ReviewException) -> list[str]:
    review_state = finding["review"]
    if review_state["exception"] is not None:
        raise ReviewEngineError(f"Multiple exception actions for review_key: {review_exception.review_key}")

    review_state["exception"] = {
        "exception_type": review_exception.exception_type,
        "approved_by": review_exception.approved_by,
        "expires_at": review_exception.expires_at,
        "note": review_exception.note,
    }
    return ["review.exception"]


def _record_action(
    finding: dict[str, Any],
    actions: list[dict[str, Any]],
    *,
    order: int,
    review_key: str,
    action_type: str,
    changed_fields: list[str],
    reason: str,
    reviewer: str,
    reviewed_at: str,
    result: str,
) -> int:
    action = {
        "order": order,
        "review_key": review_key,
        "action_type": action_type,
        "changed_fields": changed_fields,
        "reason": reason,
        "reviewer": reviewer,
        "reviewed_at": reviewed_at,
        "result": result,
    }
    actions.append(action)
    finding["review"]["review_history"].append(dict(action))
    return order + 1


def _included_in_report(review_state: Mapping[str, Any]) -> bool:
    if review_state.get("suppression") is not None:
        return False
    resolution = review_state.get("resolution")
    if not isinstance(resolution, Mapping):
        return True
    if str(resolution.get("resolution")) == "fixed":
        return False
    return str(resolution.get("final_status")) != "excluded"


def _generated_at() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
