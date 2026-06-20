from pathlib import Path
import shutil
import subprocess
from typing import Any, Dict, List, Optional

from autopenkit.models import AssetsOutput


class NucleiNotInstalledError(RuntimeError):
    """Raised when the nuclei binary cannot be found on the system PATH."""


class NucleiScanError(RuntimeError):
    """Raised when nuclei exits with a non-zero status for an unexpected reason."""


DEFAULT_NUCLEI_SEVERITY = "info,low,medium"
DEFAULT_TIMEOUT_SECONDS = 300
DEFAULT_RATE_LIMIT = 5


def check_nuclei_available() -> str:
    """
    Return the absolute path to the nuclei binary if it is available.

    AutoPenKit does not install external security tools automatically. The user
    must install Nuclei themselves and ensure it is available on PATH.
    """

    nuclei_path = shutil.which("nuclei")
    if not nuclei_path:
        raise NucleiNotInstalledError(
            "Nuclei is not installed or not available on PATH. "
            "Install Nuclei before running Phase 2 scanner integration."
        )
    return nuclei_path


def write_targets_file(live_urls: List[str], output_dir: str) -> Path:
    """
    Write live URLs to raw/targets.txt for Nuclei's -l option.
    """

    if not live_urls:
        raise ValueError("No live URLs found in assets.json. Scanner has no targets to scan.")

    raw_dir = Path(output_dir) / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)

    targets_file = raw_dir / "targets.txt"
    targets_file.write_text("\n".join(live_urls) + "\n", encoding="utf-8")
    return targets_file


def _build_nuclei_command(
    nuclei_path: str,
    targets_file: Path,
    output_file: Path,
    severity: str,
    rate_limit: int,
    json_flag: str,
) -> List[str]:
    """
    Build a safe Nuclei command.

    Important safety choices:
    - no shell=True
    - severity is restricted by profile config
    - rate limit is passed explicitly
    - output is JSON Lines compatible
    """

    return [
        nuclei_path,
        "-l",
        str(targets_file),
        json_flag,
        "-silent",
        "-no-color",
        "-severity",
        severity,
        "-rate-limit",
        str(rate_limit),
        "-o",
        str(output_file),
    ]


def _run_command(command: List[str], timeout: int) -> subprocess.CompletedProcess:
    return subprocess.run(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=timeout,
        check=False,
    )


def _should_retry_with_json(stderr: str) -> bool:
    normalized = stderr.lower()
    return "jsonl" in normalized and (
        "flag provided but not defined" in normalized
        or "unknown flag" in normalized
        or "invalid flag" in normalized
    )


def count_jsonl_lines(path: Path) -> int:
    """
    Count non-empty lines in a JSONL file.

    This is a scanner-level raw count only. Real parsing and deduplication belong
    to normalizer.py in Phase 3.
    """

    if not path.exists():
        return 0

    with path.open("r", encoding="utf-8") as file:
        return sum(1 for line in file if line.strip())


def run_nuclei_scan(
    assets: AssetsOutput,
    output_dir: str,
    profile_config: Dict[str, Any],
    nuclei_path: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Run Nuclei against the live URLs from assets.json and save raw JSONL output.

    Parameters
    ----------
    assets:
        AssetsOutput created by recon.py.
    output_dir:
        Current scan output directory, e.g. outputs/<scan_id>/.
    profile_config:
        The selected scan profile from config/settings.yaml.
        Expected keys: nuclei_severity, timeout, rate_limit.
    nuclei_path:
        Optional explicit nuclei binary path, useful for tests.

    Returns
    -------
    dict
        Scanner summary containing paths, command metadata, and raw finding count.
    """

    binary = nuclei_path or check_nuclei_available()

    severity = str(profile_config.get("nuclei_severity", DEFAULT_NUCLEI_SEVERITY))
    timeout = int(profile_config.get("timeout", DEFAULT_TIMEOUT_SECONDS))
    rate_limit = int(profile_config.get("rate_limit", DEFAULT_RATE_LIMIT))

    targets_file = write_targets_file(assets.live_urls, output_dir)

    raw_dir = Path(output_dir) / "raw"
    output_file = raw_dir / "nuclei.jsonl"

    command = _build_nuclei_command(
        nuclei_path=binary,
        targets_file=targets_file,
        output_file=output_file,
        severity=severity,
        rate_limit=rate_limit,
        json_flag="-jsonl",
    )

    try:
        result = _run_command(command, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        raise TimeoutError(
            f"Nuclei scan timed out after {timeout} seconds. "
            "Try a smaller target scope or increase the safe profile timeout."
        ) from exc

    json_flag_used = "-jsonl"

    if result.returncode != 0 and _should_retry_with_json(result.stderr):
        command = _build_nuclei_command(
            nuclei_path=binary,
            targets_file=targets_file,
            output_file=output_file,
            severity=severity,
            rate_limit=rate_limit,
            json_flag="-json",
        )
        json_flag_used = "-json"

        try:
            result = _run_command(command, timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            raise TimeoutError(
                f"Nuclei scan timed out after {timeout} seconds. "
                "Try a smaller target scope or increase the safe profile timeout."
            ) from exc

    if result.returncode != 0:
        raise NucleiScanError(
            "Nuclei scan failed.\n"
            f"Command: {' '.join(command)}\n"
            f"stderr: {result.stderr.strip()}"
        )

    # Nuclei may create no output file if there are zero findings.
    if not output_file.exists():
        output_file.write_text("", encoding="utf-8")

    return {
        "tool": "nuclei",
        "raw_output_path": str(output_file),
        "targets_file": str(targets_file),
        "json_flag_used": json_flag_used,
        "severity": severity,
        "rate_limit": rate_limit,
        "timeout": timeout,
        "raw_findings_count": count_jsonl_lines(output_file),
        "stdout": result.stdout.strip(),
        "stderr": result.stderr.strip(),
    }
