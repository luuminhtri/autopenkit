import argparse
from datetime import datetime, timezone
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parent
SRC_PATH = PROJECT_ROOT / "src"
sys.path.insert(0, str(SRC_PATH))

from autopenkit.ai_analysis import analyze_scan_output
from autopenkit.merger import merge_scan_output
from autopenkit.recon import build_initial_assets
from autopenkit.models import ScanMetadata
from autopenkit.normalizer import normalize_scan_output
from autopenkit.reporter import generate_reports
from autopenkit.scanner import run_nuclei_scan
from autopenkit.utils import (
    create_scan_output_dir,
    get_profile_config,
    load_yaml_config,
    print_error,
    print_step,
    print_success,
    save_json,
)
from autopenkit.validator import validate_target


def parse_args():
    parser = argparse.ArgumentParser(
        description="AutoPenKit - AI-assisted automated pentesting framework"
    )

    parser.add_argument(
        "--target",
        required=False,
        help="Authorized target URL, for example: http://localhost:3000",
    )

    parser.add_argument(
        "--profile",
        default="safe",
        help="Scan profile, for example: safe or medium",
    )

    parser.add_argument(
        "--config",
        default="config/settings.yaml",
        help="Path to settings YAML file",
    )

    parser.add_argument(
        "--skip-ai",
        action="store_true",
        help="Skip AI analysis",
    )

    parser.add_argument(
        "--normalize-output-dir",
        help=(
            "Normalize an existing scan output directory containing raw/nuclei.jsonl "
            "without running Nuclei again."
        ),
    )

    parser.add_argument(
        "--analyze-output-dir",
        help=(
            "Run AI analysis for an existing scan output directory containing "
            "normalized_findings.json without running Nuclei again."
        ),
    )

    parser.add_argument(
        "--report-output-dir",
        help=(
            "Merge existing normalized_findings.json and ai_analysis.json, then "
            "generate Markdown and HTML reports without running Nuclei again."
        ),
    )

    args = parser.parse_args()

    if (
        not args.target
        and not args.normalize_output_dir
        and not args.analyze_output_dir
        and not args.report_output_dir
    ):
        parser.error(
            "--target is required unless --normalize-output-dir or "
            "--analyze-output-dir or --report-output-dir is provided"
        )

    return args


def main():
    started_at = datetime.now(timezone.utc)

    try:
        args = parse_args()

        if args.normalize_output_dir:
            print_step("Normalizing existing scanner output...")
            normalization_result = normalize_scan_output(args.normalize_output_dir)
            print_success("Normalization completed successfully.")
            print_success(
                f"Normalized findings: {normalization_result['normalized_findings_count']}"
            )
            print_success(f"Output file: {normalization_result['normalized_output_path']}")
            return

        print_step("Loading configuration...")
        config = load_yaml_config(args.config)

        if args.analyze_output_dir:
            print_step("Running AI analysis for existing output...")
            ai_config = config.get("ai", {})
            ai_should_run = ai_config.get("enabled_by_default", True) and not args.skip_ai
            ai_result = analyze_scan_output(
                args.analyze_output_dir,
                ai_config,
                prompts_path="config/prompts.yaml",
                skip_ai=not ai_should_run,
            )
            print_success("AI analysis completed successfully.")
            print_success(f"Analyzed findings: {ai_result['ai_analyzed_count']}")
            print_success(f"Skipped findings: {ai_result['ai_skipped_count']}")
            print_success(f"Output file: {ai_result['ai_output_path']}")
            return

        if args.report_output_dir:
            print_step("Merging existing scan results...")
            merge_result = merge_scan_output(args.report_output_dir)
            print_success(f"Final findings: {merge_result['final_findings_count']}")
            print_success(f"Output file: {merge_result['final_output_path']}")

            print_step("Generating reports...")
            report_result = generate_reports(args.report_output_dir)
            print_success(f"Markdown report: {report_result['report_paths']['markdown']}")
            print_success(f"HTML report: {report_result['report_paths']['html']}")
            print_success(f"PDF report: {report_result['report_paths']['pdf']}")
            return

        print_step("Checking scan profile...")
        profile_config = get_profile_config(config, args.profile)

        print_step("Validating target...")
        validated_target = validate_target(args.target, config)

        print_step("Creating output directory...")
        base_dir = config.get("output", {}).get("base_dir", "outputs")
        scan_id, output_dir = create_scan_output_dir(base_dir, args.target)

        print_step("Saving validated target...")
        save_json(
            validated_target,
            str(Path(output_dir) / "validated_target.json"),
        )

        print_step("Building initial asset list...")
        assets = build_initial_assets(validated_target)
        save_json(
            assets,
            str(Path(output_dir) / "assets.json"),
        )

        print_step("Running scanner...")
        scan_result = run_nuclei_scan(assets, output_dir, profile_config)

        print_step("Normalizing scanner output...")
        normalization_result = normalize_scan_output(output_dir)

        print_step("Running AI analysis...")
        ai_config = config.get("ai", {})
        ai_should_run = ai_config.get("enabled_by_default", True) and not args.skip_ai
        ai_result = analyze_scan_output(
            output_dir,
            ai_config,
            prompts_path="config/prompts.yaml",
            skip_ai=not ai_should_run,
        )

        print_step("Merging scan results...")
        merge_result = merge_scan_output(output_dir)

        finished_at = datetime.now(timezone.utc)
        duration_seconds = (finished_at - started_at).total_seconds()

        print_step("Saving scan metadata...")
        metadata = ScanMetadata(
            scan_id=scan_id,
            project_name=config.get("project", {}).get("name", "AutoPenKit"),
            project_version=config.get("project", {}).get("version", "0.1.0"),
            target=args.target,
            profile=args.profile,
            started_at=started_at,
            finished_at=finished_at,
            duration_seconds=duration_seconds,
            modules_run=[
                "validator",
                "recon",
                "scanner",
                "normalizer",
                "ai_analysis",
                "merger",
                "reporter",
            ],
            tools_used=[scan_result["tool"]],
            total_assets=len(assets.live_urls),
            total_raw_findings=scan_result["raw_findings_count"],
            total_normalized_findings=normalization_result["normalized_findings_count"],
            total_ai_analyzed_findings=ai_result["ai_analyzed_count"],
            total_final_findings=merge_result["final_findings_count"],
            findings_by_severity=merge_result["findings_by_severity"],
            scan_status=scan_result["status"],
            scan_warning=scan_result.get("warning"),
            ai_enabled=ai_should_run,
            output_dir=output_dir,
        )

        save_json(
            metadata,
            str(Path(output_dir) / "scan_metadata.json"),
        )

        print_step("Generating reports...")
        report_result = generate_reports(output_dir)

        print_success("Phase 5 report generation completed successfully.")
        print_success(f"Output directory: {output_dir}")
        print_success(f"Markdown report: {report_result['report_paths']['markdown']}")
        print_success(f"HTML report: {report_result['report_paths']['html']}")
        print_success(f"PDF report: {report_result['report_paths']['pdf']}")

    except Exception as error:
        print_error(str(error))
        sys.exit(1)


if __name__ == "__main__":
    main()
