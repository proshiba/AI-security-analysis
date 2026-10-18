from __future__ import annotations

from unpackers.batch_env_powershell import (
    BatchEnvPowershellLimits,
    recover_batch_env_powershell,
)

PAYLOAD = (
    "function Decode($value) { [Math]::Abs($value); return $value };"
    "$bytes=[Text.Encoding]::UTF8.GetBytes('constant');"
    "Decode $bytes;Get-Random -Minimum 1 -Maximum 2;" * 3
)


def _fixture(payload: str = PAYLOAD) -> bytes:
    return (
        "@echo off\n"
        f'set "Payload={payload}"\n'
        'set "Runner=%SystemRoot%\\syswow64\\WindowsPowerShell\\v1.0\\powershell.exe"\n'
        'if not exist "%Runner%" (\n'
        'set "Runner=%SystemRoot%\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"\n'
        ")\n"
        'echo %%Payload%% | "%Runner%" -windowstyle hidden -\n'
    ).encode("ascii")


def test_recovers_constant_environment_powershell() -> None:
    report, artifacts = recover_batch_env_powershell(_fixture())

    assert report["status"] == "artifacts_recovered"
    assert report["candidate_set_complete"] is True
    assert report["candidate_set_truncated"] is False
    assert report["candidate_count"] == 1
    assert report["candidates"][0]["launcher_assignment_count"] == 2
    assert artifacts == [("batch-environment-powershell.ps1", PAYLOAD.encode())]
    assert report["safety"]["sample_executed"] is False
    assert report["safety"]["network_contacted"] is False


def test_rejects_unreviewed_launcher() -> None:
    data = _fixture().replace(b"powershell.exe", b"other.exe")

    report, artifacts = recover_batch_env_powershell(data)

    assert report["status"] == "candidates_rejected"
    assert report["rejections"]["unreviewed_launcher_assignment"] == 1
    assert artifacts == []


def test_rejects_indirect_payload_assignment() -> None:
    data = _fixture().replace(b'set "Payload=', b'set "Payload=%Other%')

    report, artifacts = recover_batch_env_powershell(data)

    assert report["status"] == "candidates_rejected"
    assert report["rejections"]["payload_validation_failed"] == 1
    assert artifacts == []


def test_input_limit_fails_closed() -> None:
    limits = BatchEnvPowershellLimits(max_input_bytes=10)

    report, artifacts = recover_batch_env_powershell(_fixture(), limits=limits)

    assert report["status"] == "input_limit_exceeded"
    assert report["candidate_set_complete"] is False
    assert artifacts == []
