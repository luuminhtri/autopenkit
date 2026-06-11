from datetime import datetime, timezone

from autopenkit.models import AssetHost, AssetsOutput, ValidatedTarget


def build_initial_assets(validated_target: ValidatedTarget) -> AssetsOutput:
    """
    Phase 1 basic recon.

    For now, we do not run real reconnaissance yet.
    We simply convert the validated target into one web asset.

    Future versions may add:
    - Nmap
    - HTTP probing
    - Subdomain discovery
    - Service detection
    """

    live_url = (
        f"{validated_target.scheme}://"
        f"{validated_target.host}:"
        f"{validated_target.port}"
    )

    asset = AssetHost(
        host=validated_target.host,
        port=validated_target.port,
        scheme=validated_target.scheme,
        status="alive",
        service="web",
    )

    return AssetsOutput(
        target=validated_target.original_input,
        scan_time=datetime.now(timezone.utc),
        hosts=[asset],
        live_urls=[live_url],
    )