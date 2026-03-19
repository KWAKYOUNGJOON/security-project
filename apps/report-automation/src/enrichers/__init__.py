"""Enrichment stage exports for report automation."""

from src.enrichers.severity_mapper import enrich_findings

__all__ = ["enrich_findings"]
