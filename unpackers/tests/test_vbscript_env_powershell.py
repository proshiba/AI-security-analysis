"""Process環境変数経由PowerShell loader復元器の専用テスト。"""

from __future__ import annotations

from dataclasses import replace

import pytest

from unpackers import static_unpacker
from unpackers import vbscript_env_powershell as recovery


def _encode_slice(
    output: str,
    *,
    start: int = 11,
    step: int = 5,
    tail: int = 12,
) -> str:
    return (
        "P" * (start - 1)
        + "".join(character + "Q" * (step - 1) for character in output)
        + "T" * tail
    )


def _call(value: str) -> str:
    return f'Recover("{_encode_slice(value).replace(chr(34), chr(34) * 2)}")'


def _decoder_function() -> str:
    return """
Function Recover(Encoded)
    Position = 5 + 6
    While Position <= Len(Encoded) - 12
        Decoded = Decoded & Mid(Encoded, Position, SliceWidth)
        Rem prose: punctuation is still a comment
        DecoyClock = TimeValue("12:34:56")
        Position = Position + 5
    Wend
    Recover = Decoded
End Function
"""


def _decoder_function_with_unrelated_randomize() -> str:
    return _decoder_function().replace(
        "    Recover = Decoded\n",
        "    Randomize\n    Recover = Decoded\n",
    )


def _loader_script(
    *,
    powershell_path: str = (
        r"c:\windows\syswow64\WindowsPowerShell\v1.0\powershell.exe"
    ),
    command_payload_name: str = "PayloadEnv",
    closing_character: str = ")",
    extra_payload_assignment: str = "",
) -> tuple[bytes, bytes]:
    payload = '$blob=[Convert]::FromBase64String("QUJD");$value=1;' + (
        "$padding='abcdef';" * 24
    )
    chunks = [payload[index : index + 73] for index in range(0, len(payload), 73)]
    append_lines = [
        f'PayloadBuffer = PayloadBuffer + "{chunk.replace(chr(34), chr(34) * 2)}"'
        for chunk in chunks
    ]
    command = f"cmd.exe /v:on /c echo ^%{command_payload_name}^% | !LauncherEnv! -"
    source = "\n".join(
        append_lines
        + ([extra_payload_assignment] if extra_payload_assignment else [])
        + [
            'Set ShellObject = CreateObject("WScript.Shell")',
            'Deadline = DateAdd("s", 2, Now())',
            "CommandDecoy = Command",
            "Do Until (Now() > Deadline)",
            f'Closer = Closer + "{closing_character}"',
            "Loop",
            "SliceWidth = Asc(Mid(Closer, 24223, 1))",
            "SliceWidth = SliceWidth - 40",
            f"PowerShellPath = {_call(powershell_path)}",
            f"CommandTemplate = {_call(command)}",
            f"ProcessScope = {_call('Process')}",
            f"PayloadName = {_call('PayloadEnv')}",
            f"LauncherName = {_call('LauncherEnv')}",
            "PayloadSetter = "
            + _call(
                "ShellObject.Environment(ProcessScope).Item(PayloadName)=PayloadBuffer"
            ),
            "LauncherSetter = "
            + _call(
                "ShellObject.Environment(ProcessScope).Item(LauncherName)="
                "Chr(34)+PowerShellPath+Chr(34)"
            ),
            "RunPrefix = " + _call("RunResult = ShellObject.Run(CommandTemplate, 0"),
            "Execute PayloadSetter",
            "Execute LauncherSetter",
            "Execute RunPrefix + Mid(Closer, 24223, 1)",
            _decoder_function(),
        ]
    )
    return source.encode(), payload.encode()


def test_recovers_process_environment_powershell_stdin_payload() -> None:
    source, expected = _loader_script()

    report, artifacts = recovery.recover_vbscript_env_powershell(source)

    assert report["status"] == "artifacts_recovered"
    assert report["candidate_set_complete"] is True
    assert report["candidate_count"] == 1
    assert report["environment_setter_count"] == 2
    assert report["candidates"][0]["payload_buffer"]["chunk_count"] > 1
    assert report["candidates"][0]["closing_suffix"]["requested_index"] == 24223
    assert artifacts == [("vbscript-env-powershell-001.ps1", expected)]
    assert report["safety"] == {
        "sample_executed": False,
        "network_contacted": False,
        "general_vbscript_interpreter_used": False,
        "eval_execute_invoked": False,
        "com_created": False,
        "powershell_started": False,
        "process_started": False,
        "raw_source_included": False,
        "raw_decoded_constants_in_report": False,
        "raw_payload_in_report": False,
    }
    assert "PayloadEnv" not in str(report)
    assert "powershell.exe" not in str(report).casefold()


def test_static_unpacker_routes_recovered_payload_to_ps1_child() -> None:
    source, expected = _loader_script()

    report, artifacts = static_unpacker.unpack_bytes(source, "delivery.vbs")

    assert report["format"] == "script"
    assert report["vbscript_env_powershell"]["status"] == "artifacts_recovered"
    assert ("vbscript-env-powershell-001.ps1", expected) in artifacts


def test_accepts_argumentless_randomize_unrelated_to_slice_state() -> None:
    source, expected = _loader_script()
    source = source.replace(
        _decoder_function().encode(),
        _decoder_function_with_unrelated_randomize().encode(),
    )

    report, artifacts = recovery.recover_vbscript_env_powershell(source)

    assert report["status"] == "artifacts_recovered"
    assert artifacts == [("vbscript-env-powershell-001.ps1", expected)]


@pytest.mark.parametrize(
    "source_options",
    [
        {"powershell_path": r"c:\windows\system32\cmd.exe"},
        {"command_payload_name": "DifferentPayloadEnv"},
        {"closing_character": "("},
        {"extra_payload_assignment": "PayloadBuffer = DynamicValue"},
    ],
)
def test_rejects_broken_or_ambiguous_loader_dataflow(
    source_options: dict[str, str],
) -> None:
    source, _expected = _loader_script(**source_options)

    report, artifacts = recovery.recover_vbscript_env_powershell(source)

    assert report["status"] == "candidates_rejected"
    assert report["candidate_count"] == 0
    assert report["rejections"]
    assert artifacts == []


def test_input_limit_fails_closed() -> None:
    source, _expected = _loader_script()
    limits = replace(recovery.DEFAULT_LIMITS, max_input_bytes=len(source) - 1)

    report, artifacts = recovery.recover_vbscript_env_powershell(
        source,
        limits=limits,
    )

    assert report["status"] == "input_limit_exceeded"
    assert report["candidate_set_complete"] is False
    assert artifacts == []


def test_unrelated_vbscript_function_call_is_not_a_rejected_loader() -> None:
    """loader anchorがない一般VBSを誤ってcandidate rejectionにしない。"""

    source = b"""
Value = Helper("constant")
Function Helper(Input)
    Helper = UnknownTransform(Input)
End Function
"""

    report, artifacts = recovery.recover_vbscript_env_powershell(source)

    assert report["status"] == "pattern_not_found"
    assert report["compound_execute_candidate_count"] == 0
    assert report["candidate_set_complete"] is True
    assert artifacts == []


def test_rejects_environment_name_defined_after_its_execute_sink() -> None:
    """参照定数がsink後に定義される不成立dataflowを拒否する。"""

    source, _expected = _loader_script()
    text = source.decode()
    payload_name_line = next(
        line for line in text.splitlines() if line.startswith("PayloadName = ")
    )
    text = text.replace(payload_name_line + "\n", "", 1).replace(
        "Execute PayloadSetter\n",
        "Execute PayloadSetter\n" + payload_name_line + "\n",
        1,
    )

    report, artifacts = recovery.recover_vbscript_env_powershell(text.encode())

    assert report["status"] == "candidates_rejected"
    assert report["candidate_count"] == 0
    assert report["rejections"]
    assert artifacts == []
