"""Canonical CLI entrypoint for READY(1)."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from vuln_pipeline.contracts import compare_run_directories, run_smoke


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run the READY(1) canonical vulnerability pipeline.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    smoke = subparsers.add_parser("smoke", help="Run the canonical READY(1) smoke flow.")
    smoke.add_argument(
        "--input-root",
        type=Path,
        default=None,
        help="Optional override for the repo-relative or absolute input root.",
    )
    smoke.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        help="Optional override for the repo-relative or absolute output directory.",
    )

    compare = subparsers.add_parser("compare-runs", help="Compare multiple READY(1) run directories.")
    compare.add_argument(
        "--run-dir",
        type=Path,
        dest="run_dirs",
        action="append",
        required=True,
        help="Repo-relative or absolute path to a smoke output directory. Repeat for 2-3 runs.",
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "smoke":
        result = run_smoke(input_root=args.input_root, output_dir=args.output_dir)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0 if result["status"] == "PASS" else 1

    result = compare_run_directories(args.run_dirs)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
