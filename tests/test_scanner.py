import subprocess
from datetime import datetime, timezone

import pytest

from autopenkit.models import AssetHost, AssetsOutput
from autopenkit.scanner import _build_nuclei_command, run_nuclei_scan


def assets_output():
    return AssetsOutput(
        target="https://demo.testfire.net/",
        scan_time=datetime.now(timezone.utc),
        hosts=[
            AssetHost(
                host="demo.testfire.net",
                port=443,
                scheme="https",
                status="alive",
                service="web",
            )
        ],
        live_urls=["https://demo.testfire.net:443"],
    )


def test_build_nuclei_command_includes_safe_filters(tmp_path):
    command = _build_nuclei_command(
        nuclei_path="/usr/local/bin/nuclei",
        targets_file=tmp_path / "targets.txt",
        output_file=tmp_path / "nuclei.jsonl",
        severity="info,low,medium",
        rate_limit=5,
        json_flag="-jsonl",
        tags="exposure,misconfig,headers",
        template_ids=["swagger-api", "missing-security-headers"],
        templates=["http/exposures"],
    )

    assert "-tags" in command
    assert command[command.index("-tags") + 1] == "exposure,misconfig,headers"
    assert "-id" in command
    assert command[command.index("-id") + 1] == "swagger-api,missing-security-headers"
    assert "-templates" in command
    assert command[command.index("-templates") + 1] == "http/exposures"


def test_run_nuclei_scan_returns_partial_result_when_timeout_has_findings(
    monkeypatch,
    tmp_path,
):
    def fake_run_command(command, timeout):
        output_file = command[command.index("-o") + 1]
        with open(output_file, "w", encoding="utf-8") as file:
            file.write('{"template-id":"swagger-api","info":{"severity":"info"}}\n')
        raise subprocess.TimeoutExpired(
            cmd=command,
            timeout=timeout,
            output="partial stdout",
            stderr="partial stderr",
        )

    monkeypatch.setattr("autopenkit.scanner._run_command", fake_run_command)

    result = run_nuclei_scan(
        assets=assets_output(),
        output_dir=str(tmp_path),
        profile_config={
            "nuclei_severity": "info,low,medium",
            "nuclei_tags": "exposure,misconfig,headers",
            "timeout": 300,
            "rate_limit": 5,
        },
        nuclei_path="/usr/local/bin/nuclei",
    )

    assert result["status"] == "timeout_partial"
    assert result["raw_findings_count"] == 1
    assert result["tags"] == "exposure,misconfig,headers"
    assert "partial raw findings" in result["warning"]


def test_run_nuclei_scan_raises_when_timeout_has_no_findings(monkeypatch, tmp_path):
    def fake_run_command(command, timeout):
        output_file = command[command.index("-o") + 1]
        open(output_file, "w", encoding="utf-8").close()
        raise subprocess.TimeoutExpired(cmd=command, timeout=timeout)

    monkeypatch.setattr("autopenkit.scanner._run_command", fake_run_command)

    with pytest.raises(TimeoutError, match="Nuclei scan timed out after 300 seconds"):
        run_nuclei_scan(
            assets=assets_output(),
            output_dir=str(tmp_path),
            profile_config={
                "nuclei_severity": "info,low,medium",
                "timeout": 300,
                "rate_limit": 5,
            },
            nuclei_path="/usr/local/bin/nuclei",
        )
