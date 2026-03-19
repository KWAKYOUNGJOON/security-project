"""Validators for case input contracts."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping

from src.taxonomies import resolve_taxonomy_code
from src.validators.schema_validator import SchemaValidationError, validate_schema_file


def validate_manual_finding(
    manual_finding: Mapping[str, Any],
    *,
    schema_dir: Path,
    repo_root: Path,
) -> None:
    """Validate the manual-finding document and its taxonomy selection."""

    validate_schema_file(manual_finding, schema_dir / "manual-finding.schema.json")
    taxonomy = manual_finding["taxonomy"]
    resolve_taxonomy_code(
        str(taxonomy["name"]),
        str(taxonomy["version"]),
        str(manual_finding["code"]),
        repo_root,
    )


def validate_engagement_metadata(
    engagement_metadata: Mapping[str, Any],
    *,
    schema_dir: Path,
) -> None:
    """Validate the engagement metadata document."""

    validate_schema_file(engagement_metadata, schema_dir / "engagement-metadata.schema.json")
    if str(engagement_metadata["engagement"]["scope_type"]).lower() != "web":
        raise SchemaValidationError("engagement.scope_type must be 'web' for the current implementation")


def validate_tool_inventory(
    tool_inventory_document: Mapping[str, Any],
    *,
    schema_dir: Path,
) -> None:
    """Validate the tool-inventory document."""

    validate_schema_file(tool_inventory_document, schema_dir / "tool-inventory.schema.json")


def validate_document_control(
    document_control_document: Mapping[str, Any],
    *,
    schema_dir: Path,
) -> None:
    """Validate the document-control document."""

    validate_schema_file(document_control_document, schema_dir / "document-control.schema.json")


def validate_review_overrides(
    review_overrides: list[dict[str, Any]],
    *,
    schema_dir: Path,
) -> None:
    """Validate the review override input document."""

    validate_schema_file(review_overrides, schema_dir / "review-override.schema.json")


def validate_review_suppressions(
    review_suppressions: list[dict[str, Any]],
    *,
    schema_dir: Path,
) -> None:
    """Validate the review suppression input document."""

    validate_schema_file(review_suppressions, schema_dir / "review-suppression.schema.json")


def validate_review_resolutions(
    review_resolutions: list[dict[str, Any]],
    *,
    schema_dir: Path,
) -> None:
    """Validate the review resolution input document."""

    validate_schema_file(review_resolutions, schema_dir / "review-resolution.schema.json")


def validate_review_exceptions(
    review_exceptions: list[dict[str, Any]],
    *,
    schema_dir: Path,
) -> None:
    """Validate the review exception input document."""

    validate_schema_file(review_exceptions, schema_dir / "review-exception.schema.json")
