"""Load and resolve explicit taxonomy mappings for Web findings."""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any


class TaxonomyError(ValueError):
    """Raised when a taxonomy or taxonomy code cannot be resolved."""


@lru_cache(maxsize=8)
def _taxonomy_catalog(repo_root: Path) -> dict[tuple[str, str], dict[str, Any]]:
    taxonomy_dir = repo_root / "shared" / "taxonomies"
    if not taxonomy_dir.exists():
        raise TaxonomyError(f"Taxonomy directory does not exist: {taxonomy_dir}")

    catalog: dict[tuple[str, str], dict[str, Any]] = {}
    for path in sorted(taxonomy_dir.glob("*.json")):
        payload = json.loads(path.read_text(encoding="utf-8"))
        name = str(payload.get("name") or "")
        version = str(payload.get("version") or "")
        if not name or not version:
            raise TaxonomyError(f"Invalid taxonomy metadata in {path}")
        key = (name, version)
        if key in catalog:
            raise TaxonomyError(f"Duplicate taxonomy registration for {name}@{version}")
        catalog[key] = payload
    return catalog


def load_taxonomy(name: str, version: str, repo_root: Path) -> dict[str, Any]:
    """Return one taxonomy definition by name and version."""

    catalog = _taxonomy_catalog(repo_root.resolve())
    key = (str(name), str(version))
    if key not in catalog:
        raise TaxonomyError(f"Unknown taxonomy: {name}@{version}")
    return catalog[key]


def resolve_taxonomy_code(name: str, version: str, code: str, repo_root: Path) -> dict[str, Any]:
    """Resolve one taxonomy code into its canonical entry."""

    taxonomy = load_taxonomy(name, version, repo_root)
    codes = taxonomy.get("codes") or {}
    entry = codes.get(str(code))
    if not isinstance(entry, dict):
        raise TaxonomyError(f"Unknown taxonomy code '{code}' for {name}@{version}")
    return {
        "taxonomy": {
          "name": taxonomy["name"],
          "version": taxonomy["version"]
        },
        "code": str(code),
        "title_ko": str(entry.get("title_ko") or ""),
        "canonical_key": str(entry.get("canonical_key") or ""),
    }
