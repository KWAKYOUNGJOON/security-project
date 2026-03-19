"""Command-line entry point for the phase-1 report automation scaffold."""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Any, Mapping, Sequence

if __package__ in {None, ""}:
    APP_ROOT = Path(__file__).resolve().parents[2]
    if str(APP_ROOT) not in sys.path:
        sys.path.insert(0, str(APP_ROOT))

from src.cases import load_case_inputs, resolve_case_directory
from src.cases.provenance import build_provenance_ledger
from src.collectors import collect_hexstrike_snapshot
from src.enrichers import enrich_findings
from src.generators import build_report_payload, build_web_report_payload, render_report_preview
from src.intake.hexstrike import validate_live_hexstrike_run
from src.integrations import HexStrikeClient, HexStrikeClientConfig
from src.normalizers import normalize_findings
from src.normalizers.web_hexstrike import (
    build_normalized_findings_artifact,
    normalize_web_hexstrike_case,
    normalize_web_hexstrike_findings,
)
from src.review import apply_review
from src.parsers import parse_hexstrike_snapshot
from src.validators import validate_schema_file


APP_ROOT = Path(__file__).resolve().parents[2]
REPO_ROOT = APP_ROOT.parent.parent
DEFAULT_CONFIG_PATH = APP_ROOT / "configs" / "default.yaml"
SHARED_SCHEMA_DIR = REPO_ROOT / "shared" / "schemas"
CASE_COMMANDS = {"normalize", "apply-review", "build-payload", "render-report", "build-all"}
INTAKE_COMMANDS = {"validate-live-hexstrike"}
LOGGER = logging.getLogger(__name__)


def default_config() -> dict[str, Any]:
    """Return the built-in phase-1 configuration."""

    return {
        "project_name": "security-project",
        "current_scope": "web",
        "target_scope": ["web", "api", "server"],
        "primary_integration": "HexStrike-AI",
        "integration": {
            "base_url": "stub://hexstrike-ai",
            "project_key": "sample-web-engagement",
            "use_live_service": False,
        },
    }


def load_config(path: Path | None = None) -> dict[str, Any]:
    """Load a JSON-compatible YAML config file without external dependencies."""

    config_path = path or DEFAULT_CONFIG_PATH
    if not config_path.exists():
        return default_config()

    raw_text = config_path.read_text(encoding="utf-8").strip()
    if not raw_text:
        return default_config()

    loaded = json.loads(raw_text)
    if not isinstance(loaded, dict):
        raise ValueError(f"Config file must contain a JSON object: {config_path}")
    return loaded


def run_pipeline(config: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Execute the phase-1 local pipeline and return the report payload."""

    active_config = default_config()
    if config:
        active_config.update(config)

    integration_settings = active_config.get("integration", {})
    client = HexStrikeClient(
        HexStrikeClientConfig(
            base_url=str(integration_settings.get("base_url") or "stub://hexstrike-ai"),
            project_key=str(integration_settings.get("project_key") or "sample-web-engagement"),
            api_token=integration_settings.get("api_token") or None,
            use_live_service=bool(integration_settings.get("use_live_service", False)),
        )
    )

    snapshot = collect_hexstrike_snapshot(client)
    parsed_findings = parse_hexstrike_snapshot(snapshot)
    normalized_findings = normalize_findings(parsed_findings)
    enriched_findings = enrich_findings(normalized_findings)

    return build_report_payload(
        enriched_findings,
        current_scope=str(active_config.get("current_scope") or "web"),
        target_scope=active_config.get("target_scope") or ["web", "api", "server"],
        integration_name=str(active_config.get("primary_integration") or "HexStrike-AI"),
        project_name=str(active_config.get("project_name") or "security-project"),
    )


def build_legacy_argument_parser() -> argparse.ArgumentParser:
    """Create the CLI argument parser."""

    parser = argparse.ArgumentParser(description="Run the phase-1 report automation scaffold.")
    parser.add_argument(
        "--config",
        type=Path,
        default=DEFAULT_CONFIG_PATH,
        help="Path to a JSON-compatible YAML config file.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Optional path for writing the generated report payload JSON.",
    )
    return parser


def build_case_argument_parser() -> argparse.ArgumentParser:
    """Create the case-based CLI parser for the Web end-to-end flow."""

    parser = argparse.ArgumentParser(description="Run the local Web case pipeline.")
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=("DEBUG", "INFO", "WARNING", "ERROR"),
        help="Logging verbosity for case commands.",
    )
    case_parent = argparse.ArgumentParser(add_help=False)
    case_parent.add_argument(
        "--case",
        required=True,
        type=Path,
        help="Repo-relative or absolute path to the case directory.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    for command_name in sorted(CASE_COMMANDS):
        subparsers.add_parser(command_name, parents=[case_parent])
    return parser


def build_intake_argument_parser() -> argparse.ArgumentParser:
    """Create the pre-target intake parser."""

    parser = argparse.ArgumentParser(description="Validate HexStrike pre-target intake files without network activity.")
    parser.add_argument(
        "command",
        choices=sorted(INTAKE_COMMANDS),
    )
    parser.add_argument(
        "--run",
        required=True,
        type=Path,
        help="Repo-relative or absolute path to the intake run directory.",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=("DEBUG", "INFO", "WARNING", "ERROR"),
        help="Logging verbosity for intake commands.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """Run the CLI and print or save the report payload."""

    args_list = list(argv or sys.argv[1:])
    if args_list and args_list[0] in CASE_COMMANDS:
        return _run_case_cli(args_list)
    if args_list and args_list[0] in INTAKE_COMMANDS:
        return _run_intake_cli(args_list)

    parser = build_legacy_argument_parser()
    args = parser.parse_args(args_list)

    try:
        payload = run_pipeline(load_config(args.config))
    except Exception as exc:  # pragma: no cover - defensive CLI boundary
        parser.exit(status=1, message=f"report-automation error: {exc}\n")

    rendered = json.dumps(payload, indent=2, ensure_ascii=False)

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8")
        print(f"report payload written to {args.output}")
        return 0

    print(rendered)
    return 0


def _run_case_cli(argv: list[str]) -> int:
    parser = build_case_argument_parser()
    args = parser.parse_args(argv)
    logging.basicConfig(level=getattr(logging, args.log_level), format="%(levelname)s %(message)s")

    try:
        if args.command == "normalize":
            result = normalize_case_artifact(args.case)
        elif args.command == "apply-review":
            result = apply_review_artifact(args.case)
        elif args.command == "build-payload":
            result = build_payload_artifact(args.case)
        elif args.command == "render-report":
            result = render_report_artifact(args.case)
        else:
            result = build_all_artifacts(args.case)
    except Exception as exc:  # pragma: no cover - CLI boundary
        parser.exit(status=1, message=f"report-automation error: {exc}\n")

    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0


def _run_intake_cli(argv: list[str]) -> int:
    parser = build_intake_argument_parser()
    args = parser.parse_args(argv)
    logging.basicConfig(level=getattr(logging, args.log_level), format="%(levelname)s %(message)s")

    try:
        result = validate_live_hexstrike_artifact(args.run)
    except Exception as exc:  # pragma: no cover - CLI boundary
        parser.exit(status=1, message=f"report-automation error: {exc}\n")

    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0


def normalize_case_artifact(case_arg: Path) -> dict[str, str]:
    """Build and write the normalized finding artifact for one case."""

    case_dir = resolve_case_directory(case_arg, REPO_ROOT)
    result = _build_case_stage(case_dir, include_review=False, include_payload=False, include_render=False)
    return {
        "normalized_path": result["normalized_path"],
        "normalized_findings_path": result["normalized_findings_path"],
        "provenance_path": result["provenance_path"],
    }


def build_payload_artifact(case_arg: Path) -> dict[str, str]:
    """Build and write the report payload artifact for one case."""

    case_dir = resolve_case_directory(case_arg, REPO_ROOT)
    result = _build_case_stage(case_dir, include_review=True, include_payload=True, include_render=False)
    return {
        "normalized_path": result["normalized_path"],
        "normalized_findings_path": result["normalized_findings_path"],
        "reviewed_path": result["reviewed_path"],
        "review_log_path": result["review_log_path"],
        "payload_path": result["payload_path"],
        "provenance_path": result["provenance_path"],
    }


def apply_review_artifact(case_arg: Path) -> dict[str, str]:
    """Build and write the reviewed finding artifact for one case."""

    case_dir = resolve_case_directory(case_arg, REPO_ROOT)
    result = _build_case_stage(case_dir, include_review=True, include_payload=False, include_render=False)
    return {
        "normalized_path": result["normalized_path"],
        "normalized_findings_path": result["normalized_findings_path"],
        "reviewed_path": result["reviewed_path"],
        "review_log_path": result["review_log_path"],
        "provenance_path": result["provenance_path"],
    }


def render_report_artifact(case_arg: Path) -> dict[str, str | None]:
    """Render a report preview for one case."""

    case_dir = resolve_case_directory(case_arg, REPO_ROOT)
    result = _build_case_stage(case_dir, include_review=True, include_payload=True, include_render=True)
    return {
        "normalized_path": result["normalized_path"],
        "normalized_findings_path": result["normalized_findings_path"],
        "reviewed_path": result["reviewed_path"],
        "review_log_path": result["review_log_path"],
        "payload_path": result["payload_path"],
        "provenance_path": result["provenance_path"],
        "html_path": result["html_path"],
        "validation_path": result["validation_path"],
        "pdf_path": result["pdf_path"],
    }


def build_all_artifacts(case_arg: Path) -> dict[str, str | None]:
    """Run normalize, payload build, and report rendering for one case."""

    case_dir = resolve_case_directory(case_arg, REPO_ROOT)
    return _build_case_stage(case_dir, include_review=True, include_payload=True, include_render=True)


def validate_live_hexstrike_artifact(run_arg: Path) -> dict[str, Any]:
    """Validate one pre-target live intake run and write observation artifacts."""

    return validate_live_hexstrike_run(run_arg, REPO_ROOT, SHARED_SCHEMA_DIR)


def _build_case_stage(
    case_dir: Path,
    *,
    include_review: bool,
    include_payload: bool,
    include_render: bool,
) -> dict[str, str | None]:
    case_inputs = load_case_inputs(case_dir, REPO_ROOT)
    normalized_findings = normalize_web_hexstrike_findings(case_inputs)
    normalized_bundle = build_normalized_findings_artifact(case_inputs, normalized_findings)
    validate_schema_file(normalized_bundle, SHARED_SCHEMA_DIR / "normalized-findings.schema.json")
    for finding in normalized_findings:
        validate_schema_file(finding, SHARED_SCHEMA_DIR / "normalized-finding.schema.json")

    normalized_findings_path = case_dir / "derived" / "normalized-findings.json"
    _write_json(normalized_findings_path, normalized_bundle)
    legacy_normalized_path = _write_legacy_single_normalized(case_dir, normalized_findings)

    output_paths: list[Path] = [normalized_findings_path]
    result: dict[str, str | None] = {
        "normalized_path": str(legacy_normalized_path or normalized_findings_path),
        "normalized_findings_path": str(normalized_findings_path),
    }
    if legacy_normalized_path is not None:
        output_paths.append(legacy_normalized_path)

    reviewed_findings: Sequence[Mapping[str, Any]] = normalized_findings
    if include_review:
        reviewed_bundle, review_log = apply_review(
            case_inputs,
            normalized_findings,
            normalized_artifact_path=case_inputs.repo_relative(normalized_findings_path),
        )
        validate_schema_file(reviewed_bundle, SHARED_SCHEMA_DIR / "reviewed-findings.schema.json")
        validate_schema_file(review_log, SHARED_SCHEMA_DIR / "review-log.schema.json")
        reviewed_path = case_dir / "derived" / "reviewed-findings.json"
        review_log_path = case_dir / "derived" / "review-log.json"
        _write_json(reviewed_path, reviewed_bundle)
        _write_json(review_log_path, review_log)
        output_paths.extend([reviewed_path, review_log_path])
        reviewed_findings = list(reviewed_bundle["findings"])
        result["reviewed_path"] = str(reviewed_path)
        result["review_log_path"] = str(review_log_path)
        LOGGER.info("Wrote reviewed findings to %s", reviewed_path)
        LOGGER.info("Wrote review log to %s", review_log_path)

    if include_payload:
        payload = build_web_report_payload(reviewed_findings, case_inputs)
        validate_schema_file(payload, SHARED_SCHEMA_DIR / "report-payload.schema.json")
        payload_path = case_dir / "derived" / "report-payload.json"
        _write_json(payload_path, payload)
        output_paths.append(payload_path)
        result["payload_path"] = str(payload_path)
        LOGGER.info("Wrote report payload to %s", payload_path)

        if include_render:
            rendered = render_report_preview(payload, case_dir=case_dir, repo_root=REPO_ROOT)
            if rendered["html_path"]:
                output_paths.append(Path(str(rendered["html_path"])))
            if rendered["validation_path"]:
                output_paths.append(Path(str(rendered["validation_path"])))
            if rendered["pdf_path"]:
                output_paths.append(Path(str(rendered["pdf_path"])))
            result.update(rendered)

    provenance_path = _write_provenance_artifact(case_inputs, case_dir, output_paths)
    result["provenance_path"] = str(provenance_path)
    return result


def _write_legacy_single_normalized(case_dir: Path, normalized_findings: list[dict[str, Any]]) -> Path | None:
    if len(normalized_findings) != 1:
        return None
    output_path = case_dir / "derived" / "normalized-finding.json"
    _write_json(output_path, normalized_findings[0])
    LOGGER.info("Wrote legacy normalized finding to %s", output_path)
    return output_path


def _write_provenance_artifact(case_inputs: Any, case_dir: Path, output_paths: list[Path]) -> Path:
    provenance = build_provenance_ledger(case_inputs, output_paths)
    validate_schema_file(provenance, SHARED_SCHEMA_DIR / "provenance.schema.json")
    provenance_path = case_dir / "derived" / "provenance.json"
    _write_json(provenance_path, provenance)
    LOGGER.info("Wrote provenance ledger to %s", provenance_path)
    return provenance_path


def _write_json(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
