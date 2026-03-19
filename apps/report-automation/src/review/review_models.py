"""Typed review-layer models for manual finding review actions."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping


class ReviewValidationError(ValueError):
    """Raised when a review action payload is internally inconsistent."""


@dataclass(frozen=True)
class ReviewOverride:
    review_key: str
    changes: dict[str, Any]
    reason: str
    reviewer: str
    reviewed_at: str

    @classmethod
    def from_mapping(cls, payload: Mapping[str, Any]) -> "ReviewOverride":
        changes = dict(payload.get("changes") or {})
        if not changes:
            raise ReviewValidationError("Review override must contain at least one change")
        return cls(
            review_key=str(payload["review_key"]),
            changes=changes,
            reason=str(payload["reason"]),
            reviewer=str(payload["reviewer"]),
            reviewed_at=str(payload["reviewed_at"]),
        )


@dataclass(frozen=True)
class ReviewSuppression:
    review_key: str
    action: str
    reason_code: str
    reason: str
    reviewer: str
    reviewed_at: str

    @classmethod
    def from_mapping(cls, payload: Mapping[str, Any]) -> "ReviewSuppression":
        return cls(
            review_key=str(payload["review_key"]),
            action=str(payload["action"]),
            reason_code=str(payload["reason_code"]),
            reason=str(payload["reason"]),
            reviewer=str(payload["reviewer"]),
            reviewed_at=str(payload["reviewed_at"]),
        )


@dataclass(frozen=True)
class ReviewResolution:
    review_key: str
    resolution: str
    final_status: str
    reason: str
    reviewer: str
    reviewed_at: str

    @classmethod
    def from_mapping(cls, payload: Mapping[str, Any]) -> "ReviewResolution":
        action = cls(
            review_key=str(payload["review_key"]),
            resolution=str(payload["resolution"]),
            final_status=str(payload["final_status"]),
            reason=str(payload["reason"]),
            reviewer=str(payload["reviewer"]),
            reviewed_at=str(payload["reviewed_at"]),
        )
        action._validate()
        return action

    def _validate(self) -> None:
        expected_status = {
            "false_positive": "excluded",
            "accepted_risk": "accepted",
            "fixed": "closed",
            "duplicate": "excluded",
            "not_applicable": "excluded",
        }[self.resolution]
        if self.final_status != expected_status:
            raise ReviewValidationError(
                f"Resolution '{self.resolution}' requires final_status '{expected_status}', got '{self.final_status}'"
            )


@dataclass(frozen=True)
class ReviewException:
    review_key: str
    exception_type: str
    approved_by: str
    expires_at: str
    note: str

    @classmethod
    def from_mapping(cls, payload: Mapping[str, Any]) -> "ReviewException":
        return cls(
            review_key=str(payload["review_key"]),
            exception_type=str(payload["exception_type"]),
            approved_by=str(payload["approved_by"]),
            expires_at=str(payload["expires_at"]),
            note=str(payload["note"]),
        )
