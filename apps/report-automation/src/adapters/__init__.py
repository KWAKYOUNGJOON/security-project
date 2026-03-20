"""Adapter exports for report automation."""

from src.adapters.kisa_webserver_fail_only_adapter import (
    adapt_kisa_webserver_raw_record,
    adapt_kisa_webserver_raw_records,
)

__all__ = [
    "adapt_kisa_webserver_raw_record",
    "adapt_kisa_webserver_raw_records",
]
