from datetime import datetime, timezone
from typing import Any, Dict
from urllib.parse import urlparse

from autopenkit.models import ValidatedTarget


def validate_target(target: str, config: Dict[str, Any]) -> ValidatedTarget:
    parsed = urlparse(target)

    if parsed.scheme not in config.get("security", {}).get("allowed_schemes", []):
        raise ValueError(
            "Invalid URL scheme. Target must start with http:// or https://"
        )

    if not parsed.hostname:
        raise ValueError(
            "Invalid target. Please provide a valid URL, for example: http://localhost:3000"
        )

    host = parsed.hostname
    port = parsed.port

    if port is None:
        if parsed.scheme == "https":
            port = 443
        else:
            port = 80

    require_scope_check = config.get("security", {}).get("require_scope_check", True)
    allowed_hosts = config.get("security", {}).get("allowed_hosts", [])

    if require_scope_check and host not in allowed_hosts:
        raise ValueError(
            f"Target host '{host}' is not in the authorized scope. "
            "Add it to config/settings.yaml only if you have permission."
        )

    path = parsed.path if parsed.path else "/"

    return ValidatedTarget(
        original_input=target,
        scheme=parsed.scheme,
        host=host,
        port=port,
        path=path,
        is_authorized=True,
        validated_at=datetime.now(timezone.utc),
    )