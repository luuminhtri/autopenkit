import argparse
from datetime import datetime, timezone
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parent
SRC_PATH = PROJECT_ROOT / "src"
sys.path.insert(0, str(SRC_PATH))

from autopenkit.recon import build_initial_assets
from autopenkit.models import ScanMetadata
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
        required=True,
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

    return parser.parse_args()


def main():
    started_at = datetime.now(timezone.utc)

    try:
        args = parse_args()

        print_step("Loading configuration...")
        config = load_yaml_config(args.config)

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
            modules_run=["validator", "recon", "scanner"],
            tools_used=[scan_result["tool"]],
            total_assets=len(assets.live_urls),
            total_raw_findings=scan_result["raw_findings_count"],
            ai_enabled=not args.skip_ai,
            output_dir=output_dir,
        )

        save_json(
            metadata,
            str(Path(output_dir) / "scan_metadata.json"),
        )

        print_success("Phase 2 scanner integration completed successfully.")
        print_success(f"Output directory: {output_dir}")

    except Exception as error:
        print_error(str(error))
        sys.exit(1)


if __name__ == "__main__":
    main()