"""Generation stage exports for report automation."""

from src.generators.report_payload_builder import build_report_payload
from src.generators.template_bridge import render_report_preview
from src.generators.web_report_payload import build_web_report_payload

__all__ = ["build_report_payload", "build_web_report_payload", "render_report_preview"]
