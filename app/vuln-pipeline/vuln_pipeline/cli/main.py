"""Canonical CLI entrypoint for READY contract checks."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from vuln_pipeline.contracts import REQUIRED_REAL_INPUT_FILES, compare_run_directories, run_smoke


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run the canonical READY contract checks.")
    subparsers = parser.add_subparsers(dest="command", required=True)
    canonical_schema = ", ".join(REQUIRED_REAL_INPUT_FILES)

    smoke = subparsers.add_parser(
        "smoke",
        help="Run the canonical READY smoke flow.",
        description=f"Canonical real-input schema: {canonical_schema}",
    )
    smoke.add_argument(
        "--run-id",
        required=True,
        help="Canonical run identifier matching ^run-\\d{8}T\\d{6}Z$.",
    )
    smoke.add_argument(
        "--mode",
        choices=("auto", "real", "dry-run"),
        default="auto",
        help="auto detects missing real inputs and falls back to dry-run without claiming READY(1).",
    )
    smoke.add_argument(
        "--input-root",
        type=Path,
        default=None,
        help=f"Optional override for the repo-relative or absolute input root. Required files remain: {canonical_schema}.",
    )
    smoke.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        help="Optional override for the repo-relative or absolute output directory.",
    )

    compare = subparsers.add_parser("compare-runs", help="Compare multiple canonical run directories.")
    compare.add_argument(
        "--run-dir",
        type=Path,
        dest="run_dirs",
        action="append",
        required=True,
        help="Repo-relative or absolute path to a canonical run directory. Repeat for 2-3 runs.",
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "smoke":
        result = run_smoke(
            run_id=args.run_id,
            mode=args.mode,
            input_root=args.input_root,
            output_dir=args.output_dir,
        )
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0

    result = compare_run_directories(args.run_dirs)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
