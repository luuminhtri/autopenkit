import json
import re
from pathlib import Path
from typing import Any, Dict, Tuple

import yaml


def load_yaml_config(path: str) -> Dict[str, Any]:
    config_path = Path(path)

    if not config_path.exists():
        raise FileNotFoundError(f"Config file not found: {path}")

    with open(config_path, "r", encoding="utf-8") as file:
        data = yaml.safe_load(file)

    if data is None:
        return {}

    return data


def sanitize_target_for_folder(target: str) -> str:
    cleaned = target.replace("http://", "").replace("https://", "")
    cleaned = cleaned.strip("/")
    cleaned = re.sub(r"[^a-zA-Z0-9]+", "_", cleaned)
    cleaned = cleaned.strip("_")

    if not cleaned:
        return "target"

    return cleaned


def create_scan_output_dir(base_dir: str, target: str) -> Tuple[str, str]:
    from datetime import datetime

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_target = sanitize_target_for_folder(target)
    scan_id = f"{safe_target}_{timestamp}"

    output_dir = Path(base_dir) / scan_id
    output_dir.mkdir(parents=True, exist_ok=True)

    raw_dir = output_dir / "raw"
    reports_dir = output_dir / "reports"

    raw_dir.mkdir(exist_ok=True)
    reports_dir.mkdir(exist_ok=True)

    return scan_id, str(output_dir)


def save_json(data: Any, path: str) -> None:
    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    if hasattr(data, "model_dump"):
        data = data.model_dump(mode="json")

    with open(output_path, "w", encoding="utf-8") as file:
        json.dump(data, file, indent=2, ensure_ascii=False)


def print_step(message: str) -> None:
    print(f"[+] {message}")


def print_success(message: str) -> None:
    print(f"[✓] {message}")


def print_error(message: str) -> None:
    print(f"[!] {message}")


def get_profile_config(config: Dict[str, Any], profile: str) -> Dict[str, Any]:
    profiles = config.get("scan", {}).get("profiles", {})

    if profile not in profiles:
        allowed = list(profiles.keys())
        raise ValueError(f"Invalid profile: {profile}. Allowed profiles: {allowed}")

    return profiles[profile]