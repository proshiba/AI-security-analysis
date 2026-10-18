"""固定逆slice型VBScript ``Execute`` 引数復元器の専用テスト。"""

from __future__ import annotations

from dataclasses import replace

import pytest

from unpackers import static_unpacker
from unpackers import vbscript_constant_sink as recovery


def _encode_slice(
    output: str,
    *,
    start: int = 11,
    step: int = 5,
    tail: int = 12,
) -> str:
    assert start >= 1
    assert step >= 1
    prefix = "P" * (start - 1)
    body = "".join(character + "Q" * (step - 1) for character in output)
    return prefix + body + "T" * tail


def _function(
    *,
    name: str = "RecoverStage",
    parameter: str = "Encoded",
    index: str = "Position",
    output: str = "Decoded",
    width: str = "1",
    extra: str = 'Junk = "left" & "right"',
) -> str:
    return f"""
Function {name}({parameter})
    {index} = 5 + 6
    While {index} <= Len({parameter}) - 12
        {output} = {output} & Mid({parameter}, {index}, {width})
        {index} = {index} + 5
        {extra}
    Wend
    OtherJunk = 3 * (2 + 1)
    {name} = {output}
End Function
"""


def _script(*payloads: str, function_text: str | None = None) -> bytes:
    assignments: list[str] = []
    sinks: list[str] = []
    for index, payload in enumerate(payloads, 1):
        assignments.append(f'Stage{index} = RecoverStage("{_encode_slice(payload)}")')
        sinks.append(f"Execute Stage{index}")
    return (
        "\n".join(assignments + sinks)
        + "\n"
        + (function_text if function_text is not None else _function())
    ).encode()


def test_recovers_two_direct_execute_arguments_without_running_vbscript() -> None:
    first = "Registry.Value(Key).Write(Name)=Data"
    second = "Registry.Value(Key).Write(Name)=Chr(34)+Data+Chr(34)"
    third = "Registry.Value(Key).Write(Name)=Incomplete"
    source = (
        f'First = RecoverStage("{_encode_slice(first)}")\n'
        f'Second = RecoverStage("{_encode_slice(second)}")\n'
        f'Third = RecoverStage("{_encode_slice(third)}")\n'
        "Execute First\n"
        "execute(Second)\n"
        "Execute Third & Mid(DynamicValue, 1, 1)\n" + _function()
    ).encode()

    report, artifacts = recovery.recover_vbscript_constant_sinks(source)

    assert report["status"] == "artifacts_recovered"
    assert report["candidate_set_complete"] is True
    assert report["candidate_count"] == 2
    assert report["direct_sink_count"] == 2
    assert report["compound_sink_count"] == 1
    assert report["rejections"] == {"non_direct_execute_argument": 1}
    assert [data for _, data in artifacts] == [first.encode(), second.encode()]
    assert [name for name, _ in artifacts] == [
        "vbscript-constant-direct-execute-001",
        "vbscript-constant-direct-execute-002",
    ]
    assert all(
        candidate["slice"]["index_base"] == 1 for candidate in report["candidates"]
    )
    assert all(candidate["slice"]["start"] == 11 for candidate in report["candidates"])
    assert report["safety"] == {
        "sample_executed": False,
        "network_contacted": False,
        "general_vbscript_interpreter_used": False,
        "eval_execute_invoked": False,
        "com_created": False,
        "wmi_invoked": False,
        "powershell_started": False,
        "process_started": False,
        "raw_source_included": False,
        "raw_literal_included": False,
        "recovered_output_in_report": False,
    }


def test_static_unpacker_routes_recovered_execute_argument_to_child_layer() -> None:
    """共通pipelineが固定逆sliceを復元し、検証済み出力だけを子層へ渡す。"""

    decoded = "Registry.Value(Key).Write(Name)=DecodedData"
    source = (
        f'Payload = RecoverStage("{_encode_slice(decoded)}")\n'
        "Execute Payload\n" + _function()
    ).encode()

    report, artifacts = static_unpacker.unpack_bytes(source, "loader.vbs")

    assert report["format"] == "script"
    assert report["vbscript_constant_sink"]["status"] == "artifacts_recovered"
    assert (
        "vbscript-constant-direct-execute-001",
        decoded.encode(),
    ) in artifacts


def test_slice_is_vbscript_one_based_and_keeps_doubled_quotes() -> None:
    payload = 'Object.Method(Key).Property(Name)="A"'
    encoded = _encode_slice(payload).replace('"', '""')
    source = (
        f'Stage = RecoverStage("{encoded}") : Execute Stage\n' + _function()
    ).encode("utf-16")

    report, artifacts = recovery.recover_vbscript_constant_sinks(source)

    assert report["status"] == "artifacts_recovered"
    assert report["encoding"] == "utf-16-le"
    assert artifacts[0][1].decode() == payload


def test_constant_multi_character_mid_width_is_recovered_exactly() -> None:
    """固定幅 ``Mid`` をVBScriptの1-based semanticsどおり復元する。"""

    payload = "Object.Method(Key).Property(Name)=Values"
    chunks = [payload[index : index + 2] for index in range(0, len(payload), 2)]
    encoded = "P" * 10 + "QQQ".join(chunks) + "T" * 12
    function_text = _function(width="2")
    source = (
        f'Stage = RecoverStage("{encoded}")\nExecute Stage\n' + function_text
    ).encode()

    report, artifacts = recovery.recover_vbscript_constant_sinks(source)

    assert report["status"] == "artifacts_recovered"
    assert report["candidates"][0]["slice"]["width"] == 2
    assert artifacts == [("vbscript-constant-direct-execute-001", payload.encode())]


def test_slice_width_above_bound_is_rejected() -> None:
    """過大な固定幅は復元前にfail closedで拒否する。"""

    payload = "Object.Method(Key).Property(Name)=Value"
    limits = replace(recovery.DEFAULT_LIMITS, max_slice_width=2)
    source = _script(payload, function_text=_function(width="3"))

    report, artifacts = recovery.recover_vbscript_constant_sinks(
        source,
        limits=limits,
    )

    assert report["status"] == "candidates_rejected"
    assert report["rejections"] == {"unsupported_slice_width": 1}
    assert artifacts == []


def test_width_identifier_resolves_from_repeated_ascii_asc_mid_chain() -> None:
    """反復1文字bufferのAsc/Mid算術から固定幅だけを安全に解決する。"""

    payload = "Object.Method(Key).Property(Name)=Values"
    chunks = [payload[index : index + 2] for index in range(0, len(payload), 2)]
    encoded = "P" * 10 + "QQQ".join(chunks) + "T" * 12
    source = (
        'Padding = Padding & "A"\n'
        "WidthValue = Asc(Mid(Padding, 24223, 1))\n"
        "WidthValue = WidthValue - 63\n"
        f'Stage = RecoverStage("{encoded}")\n'
        "Execute Stage\n" + _function(width="WidthValue")
    ).encode()

    report, artifacts = recovery.recover_vbscript_constant_sinks(source)

    assert report["status"] == "artifacts_recovered"
    assert report["candidates"][0]["slice"]["width"] == 2
    assert report["candidates"][0]["slice"]["width_resolution"] == (
        "repeated_ascii_character_asc_mid_v1"
    )
    assert artifacts == [("vbscript-constant-direct-execute-001", payload.encode())]


def test_unreferenced_side_effect_free_builtin_decoys_are_ignored() -> None:
    """core stateを参照しないpure builtinのdecoy代入だけを許可する。"""

    payload = "Object.Method(Key).Property(Name)=Value"
    function_text = _function(
        extra=('DecoyClock = TimeValue("12:34:56")\n        DecoyNow = Now')
    )

    report, artifacts = recovery.recover_vbscript_constant_sinks(
        _script(payload, function_text=function_text)
    )

    assert report["status"] == "artifacts_recovered"
    assert artifacts == [("vbscript-constant-direct-execute-001", payload.encode())]


def test_rem_comment_colons_do_not_create_phantom_statements() -> None:
    """``Rem`` 後のcolonはcomment本文であり、文区切りとして扱わない。"""

    payload = "Object.Method(Key).Property(Name)=Value"
    function_text = _function(
        extra=(
            "Rem prose: punctuation, not executable code\n"
            '        DecoyClock = TimeValue("12:34:56")\n'
            "        Rem more prose: fake = UnknownFunction()\n"
            "        DecoyNow = Now"
        )
    )

    report, artifacts = recovery.recover_vbscript_constant_sinks(
        _script(payload, function_text=function_text)
    )

    assert report["status"] == "artifacts_recovered"
    assert report["rejections"] == {}
    assert artifacts == [("vbscript-constant-direct-execute-001", payload.encode())]


def test_inline_rem_comment_discards_all_remaining_colon_text() -> None:
    """先行文後の ``Rem`` も、同一行の残りを完全にcommentとして捨てる。"""

    assert recovery._split_line("Value = 1: Rem comment: Execute DynamicValue") == [
        "Value = 1"
    ]
    assert recovery._split_line('Value = "Rem: literal": Other = 2') == [
        'Value = "Rem: literal"',
        "Other = 2",
    ]
    assert recovery._split_line("Remembered = 1: Other = 2") == [
        "Remembered = 1",
        "Other = 2",
    ]


def test_literal_derived_pure_string_decoys_are_ignored() -> None:
    """既知literal由来の文字列変換とliteral-only sliceだけを許可する。"""

    payload = "Object.Method(Key).Property(Name)=Value"
    function_text = (
        _function(
            extra='LoopDecoy = LenB("text")',
        )
        .replace(
            "    While ",
            '    SeedDecoy = "constant"\n'
            "    FoldedDecoy = LCase(SeedDecoy)\n"
            "    While ",
            1,
        )
        .replace(
            "End Function",
            'PostDecoy = MidB("literal", 90, 64)\nEnd Function',
            1,
        )
    )

    report, artifacts = recovery.recover_vbscript_constant_sinks(
        _script(payload, function_text=function_text)
    )

    assert report["status"] == "artifacts_recovered"
    assert report["rejections"] == {}
    assert artifacts == [("vbscript-constant-direct-execute-001", payload.encode())]


@pytest.mark.parametrize(
    "extra",
    [
        "FoldedDecoy = LCase(UnknownValue)",
        'PostDecoy = MidB("literal", DynamicStart, 64)',
        'PostDecoy = MidB("literal", 0, 64)',
    ],
)
def test_nonconstant_or_invalid_pure_string_decoys_remain_rejected(
    extra: str,
) -> None:
    """未知入力と不正rangeをpure decoyとして誤って許可しない。"""

    report, artifacts = recovery.recover_vbscript_constant_sinks(
        _script(
            "Object.Method(Key).Property(Name)=Value",
            function_text=_function(extra=extra),
        )
    )

    assert report["status"] == "candidates_rejected"
    assert report["rejections"] == {"nonconstant_extra_statement": 1}
    assert artifacts == []


def test_rejects_compound_sink_without_publishing_partial_output() -> None:
    payload = "Object.Method(Key).Property(Name)=Value"
    source = (
        f'Stage = RecoverStage("{_encode_slice(payload)}")\n'
        "Execute Stage + Mid(ExternalState, 99, 1)\n" + _function()
    ).encode()

    report, artifacts = recovery.recover_vbscript_constant_sinks(source)

    assert report["status"] == "candidates_rejected"
    assert report["candidate_count"] == 0
    assert report["compound_sink_count"] == 1
    assert report["rejections"] == {"non_direct_execute_argument": 1}
    assert artifacts == []


def test_rejects_multiple_assignments_to_sink_variable_as_ambiguous() -> None:
    payload = "Object.Method(Key).Property(Name)=Value"
    literal = _encode_slice(payload)
    source = (
        f'Stage = RecoverStage("{literal}")\n'
        f'Stage = RecoverStage("{literal}")\n'
        "Execute Stage\n" + _function()
    ).encode()

    report, artifacts = recovery.recover_vbscript_constant_sinks(source)

    assert report["status"] == "candidates_rejected"
    assert report["rejections"] == {"ambiguous_sink_assignment": 1}
    assert artifacts == []


def test_rejects_duplicate_function_definition_as_ambiguous() -> None:
    payload = "Object.Method(Key).Property(Name)=Value"
    source = _script(payload) + _function().encode()

    report, artifacts = recovery.recover_vbscript_constant_sinks(source)

    assert report["status"] == "candidates_rejected"
    assert report["rejections"] == {"ambiguous_function_definition": 1}
    assert artifacts == []


@pytest.mark.parametrize(
    ("function_text", "reason"),
    [
        (
            _function(extra="Call Mutate(Position)"),
            "unsupported_control_flow",
        ),
        (
            _function(extra="Decoded = Decoded & DynamicValue"),
            "slice_state_referenced_by_extra_statement",
        ),
        (
            _function(extra="Junk = UnknownFunction()"),
            "nonconstant_extra_statement",
        ),
    ],
)
def test_rejects_nonconstant_or_state_mutating_decoder_shapes(
    function_text: str,
    reason: str,
) -> None:
    payload = "Object.Method(Key).Property(Name)=Value"

    report, artifacts = recovery.recover_vbscript_constant_sinks(
        _script(payload, function_text=function_text)
    )

    assert report["status"] == "candidates_rejected"
    assert report["rejections"] == {reason: 1}
    assert artifacts == []


def test_rejects_recovered_data_that_is_not_vbscript_token_stream() -> None:
    report, artifacts = recovery.recover_vbscript_constant_sinks(
        _script("ordinary words only")
    )

    assert report["status"] == "candidates_rejected"
    assert report["rejections"] == {"output_format_rejected": 1}
    assert artifacts == []


def test_invalid_decoy_does_not_consume_valid_output_quota() -> None:
    invalid = "ordinary words only " * 64
    valid = "Object.Method(Key).Property(Name)=Value"
    limits = replace(recovery.DEFAULT_LIMITS, max_output_bytes=len(valid))

    report, artifacts = recovery.recover_vbscript_constant_sinks(
        _script(invalid, valid),
        limits=limits,
    )

    assert report["status"] == "artifacts_recovered"
    assert report["candidate_count"] == 1
    assert report["rejections"] == {"output_format_rejected": 1}
    assert artifacts == [("vbscript-constant-direct-execute-001", valid.encode())]


def test_deep_integer_parentheses_are_rejected_without_recursion_error() -> None:
    nested = ("(" * 96) + "11" + (")" * 96)
    function_text = _function().replace("5 + 6", nested, 1)

    report, artifacts = recovery.recover_vbscript_constant_sinks(
        _script(
            "Object.Method(Key).Property(Name)=Value",
            function_text=function_text,
        )
    )

    assert report["status"] == "candidates_rejected"
    assert report["rejections"] == {"ambiguous_start": 1}
    assert artifacts == []


def test_input_limit_is_hard_and_no_candidate_is_returned() -> None:
    limits = replace(recovery.DEFAULT_LIMITS, max_input_bytes=8)

    report, artifacts = recovery.recover_vbscript_constant_sinks(
        b"A" * 9,
        limits=limits,
    )

    assert report["status"] == "input_limit_exceeded"
    assert report["candidate_set_complete"] is False
    assert artifacts == []


def test_output_limit_discards_previously_recovered_candidates() -> None:
    payload = "Object.Method(Key).Property(Name)=Value"
    limits = replace(recovery.DEFAULT_LIMITS, max_output_bytes=len(payload) - 1)

    report, artifacts = recovery.recover_vbscript_constant_sinks(
        _script(payload),
        limits=limits,
    )

    assert report["status"] == "limit_exceeded"
    assert report["limit"] == "max_output_bytes"
    assert report["candidate_set_complete"] is False
    assert artifacts == []


def test_attempt_limit_discards_partial_results() -> None:
    first = "Object.Method(Key).Property(Name)=First"
    second = "Object.Method(Key).Property(Name)=Second"
    limits = replace(recovery.DEFAULT_LIMITS, max_attempts=2)

    report, artifacts = recovery.recover_vbscript_constant_sinks(
        _script(first, second),
        limits=limits,
    )

    assert report["status"] == "limit_exceeded"
    assert report["limit"] == "max_attempts"
    assert report["candidate_set_complete"] is False
    assert artifacts == []


def test_work_limit_stops_before_parsing_and_returns_no_output() -> None:
    payload = "Object.Method(Key).Property(Name)=Value"
    source = _script(payload)
    limits = replace(recovery.DEFAULT_LIMITS, max_work_units=len(source) - 1)

    report, artifacts = recovery.recover_vbscript_constant_sinks(
        source,
        limits=limits,
    )

    assert report["status"] == "limit_exceeded"
    assert report["limit"] == "max_work_units"
    assert artifacts == []


def test_unterminated_procedure_is_rejected_without_interpretation() -> None:
    payload = "Object.Method(Key).Property(Name)=Value"
    source = _script(payload).replace(b"End Function", b"' End Function")

    report, artifacts = recovery.recover_vbscript_constant_sinks(source)

    assert report["status"] == "ambiguous_procedure_structure"
    assert report["candidate_set_complete"] is False
    assert artifacts == []


def test_unterminated_string_cannot_hide_an_ambiguous_assignment() -> None:
    payload = "Object.Method(Key).Property(Name)=Value"
    source = b'Stage = "unterminated\n' + _script(payload)

    report, artifacts = recovery.recover_vbscript_constant_sinks(source)

    assert report["status"] == "ambiguous_lexical_structure"
    assert report["lexical_rejection"] == "unterminated_string_literal"
    assert report["candidate_set_complete"] is False
    assert artifacts == []


def test_non_bytes_input_is_rejected_at_api_boundary() -> None:
    with pytest.raises(TypeError, match="bytes"):
        recovery.recover_vbscript_constant_sinks("not bytes")  # type: ignore[arg-type]
