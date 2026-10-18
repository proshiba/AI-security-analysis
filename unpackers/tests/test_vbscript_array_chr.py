from __future__ import annotations

from unpackers.vbscript_array_chr import (
    VbscriptArrayChrLimits,
    recover_vbscript_array_chr,
)

EXPECTED = b'alpha = "x"\nbeta = 1\ngamma = 2'


def _fixture(*, key_assignment: str = "delta = left Mod right") -> bytes:
    numbers = ", ".join(str(value + 7) for value in EXPECTED)
    source = f"""
noise = "ignored"
numbers = Array({numbers})
left = 17
right = 10
{key_assignment}
decoded = ""
For position = 0 To UBound(numbers)
  decoded = decoded + Chr(numbers(position) - (delta))
Next
Execute decoded
"""
    return source.encode("ascii")


def _fixture_for_output(output: bytes) -> bytes:
    numbers = ", ".join(str(value + 7) for value in output)
    return f"""
numbers = Array({numbers})
left = 17
right = 10
delta = left Mod right
decoded = ""
For position = 0 To UBound(numbers)
  decoded = decoded + Chr(numbers(position) - (delta))
Next
Execute decoded
""".encode("ascii")


def test_recovers_constant_array_chr_direct_execute() -> None:
    report, artifacts = recover_vbscript_array_chr(_fixture())

    assert report["status"] == "artifacts_recovered"
    assert report["candidate_set_complete"] is True
    assert report["candidate_set_truncated"] is False
    assert report["candidate_count"] == 1
    assert report["candidates"][0]["key_resolution"] == "constant_integer_modulo_v1"
    assert artifacts == [("vbscript-array-chr-direct-execute", EXPECTED)]
    assert report["safety"]["sample_executed"] is False
    assert report["safety"]["network_contacted"] is False


def test_recovers_strict_wscript_shell_run_without_executing_it() -> None:
    output = b'CreateObject("WScript.Shell").Run "powershell -NoProfile -c 1", 0'

    report, artifacts = recover_vbscript_array_chr(_fixture_for_output(output))

    assert report["status"] == "artifacts_recovered"
    assert report["candidates"][0]["output_validation"] == {
        "format": "bounded_vbscript_wscript_shell_run",
        "statement_count": 1,
        "command_character_count": 26,
        "wait_argument_present": False,
    }
    assert artifacts == [
        ("vbscript-array-chr-direct-execute", output),
        ("vbscript-wscript-shell-run-command.cmd", b"powershell -NoProfile -c 1"),
    ]
    assert report["candidates"][0]["derived_command"]["size"] == 26


def test_rejects_nonconstant_array_element() -> None:
    data = _fixture().replace(b"Array(104,", b"Array(variable,")

    report, artifacts = recover_vbscript_array_chr(data)

    assert report["status"] == "candidates_rejected"
    assert report["candidate_set_complete"] is True
    assert report["rejections"]["nonconstant_array"] == 1
    assert artifacts == []


def test_rejects_ambiguous_output_assignment() -> None:
    data = _fixture().replace(b'decoded = ""', b'decoded = ""\ndecoded = "other"')

    report, artifacts = recover_vbscript_array_chr(data)

    assert report["status"] == "candidates_rejected"
    assert report["rejections"]["ambiguous_output_state"] == 1
    assert artifacts == []


def test_array_item_limit_fails_closed() -> None:
    limits = VbscriptArrayChrLimits(max_array_items=4)

    report, artifacts = recover_vbscript_array_chr(_fixture(), limits=limits)

    assert report["status"] == "limit_exceeded"
    assert report["candidate_set_complete"] is False
    assert report["candidate_set_truncated"] is True
    assert report["limit"] == "max_array_items"
    assert artifacts == []


def test_rejects_compound_or_indirect_sink() -> None:
    data = _fixture().replace(b"Execute decoded", b"Execute decoded & noise")

    report, artifacts = recover_vbscript_array_chr(data)

    assert report["status"] == "candidates_rejected"
    assert report["rejections"]["ambiguous_direct_sink"] == 1
    assert artifacts == []
