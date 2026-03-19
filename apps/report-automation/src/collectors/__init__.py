"""Collection entry points for the report automation pipeline."""

from __future__ import annotations

from typing import Any

from src.integrations.hexstrike_client import HexStrikeClient


def collect_hexstrike_snapshot(client: HexStrikeClient | None = None) -> dict[str, Any]:
    """Collect a source snapshot through the current HexStrike adapter."""

    active_client = client or HexStrikeClient()
    return active_client.fetch_findings_snapshot()
