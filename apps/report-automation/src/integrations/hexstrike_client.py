"""Adapter-ready HexStrike client stub used by the phase-1 scaffold."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from typing import Any


DEFAULT_SNAPSHOT: dict[str, Any] = {
    "source": {
        "name": "HexStrike-AI",
        "mode": "stub",
    },
    "engagement": {
        "name": "sample-web-engagement",
        "primary_target": "https://sample-app.local",
        "current_scope": "web",
        "target_scope": ["web", "api", "server"],
    },
    "findings": [
        {
            "id": "HEX-001",
            "asset": "https://sample-app.local/login",
            "title": "Missing Content Security Policy",
            "severity": "medium",
            "description": "The application response does not define a baseline Content-Security-Policy header.",
            "evidence": [
                "Observed a successful HTML response without a CSP header.",
                "Browser-side content controls rely on defaults only.",
            ],
            "references": ["OWASP ASVS 14.4.1"],
            "tags": ["web", "headers"],
        },
        {
            "id": "HEX-002",
            "asset": "https://sample-app.local/search",
            "title": "Reflected parameter handling needs validation review",
            "severity": "low",
            "description": "A reflected search parameter was observed and should remain under validation review.",
            "evidence": ["Response reflected the search term in the results heading."],
            "references": ["OWASP Testing Guide WSTG-INPV-01"],
            "tags": ["web", "input-validation"],
        },
    ],
}


@dataclass(frozen=True)
class HexStrikeClientConfig:
    """Configuration for the HexStrike adapter."""

    base_url: str = "stub://hexstrike-ai"
    project_key: str = "sample-web-engagement"
    api_token: str | None = None
    use_live_service: bool = False


class HexStrikeClient:
    """Local-safe client stub for future HexStrike integration work."""

    def __init__(
        self,
        config: HexStrikeClientConfig | None = None,
        sample_snapshot: dict[str, Any] | None = None,
    ) -> None:
        self.config = config or HexStrikeClientConfig()
        self._sample_snapshot = sample_snapshot or DEFAULT_SNAPSHOT

    def fetch_findings_snapshot(self) -> dict[str, Any]:
        """Return a deterministic snapshot until a real adapter is introduced."""

        if self.config.use_live_service:
            raise RuntimeError(
                "Live HexStrike-AI integration is not implemented in phase 1. "
                "Use the default stub configuration for local runs."
            )

        snapshot = deepcopy(self._sample_snapshot)
        snapshot["source"]["project_key"] = self.config.project_key
        snapshot["source"]["base_url"] = self.config.base_url
        return snapshot
