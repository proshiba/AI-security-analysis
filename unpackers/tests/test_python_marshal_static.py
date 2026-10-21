"""CPython 3.8--3.10互換raw marshal定数候補復元の回帰テスト。"""

from __future__ import annotations

import base64
import struct

import pytest

from unpackers.python_marshal_static import (
    MAX_CANDIDATE_SIZE,
    MAX_CANDIDATE_TOTAL_SIZE,
    MAX_CANDIDATES,
    MAX_COLLECTION_ITEMS,
    MAX_DEPTH,
    MAX_INPUT_SIZE,
    MAX_NODES,
    MAX_SCALAR_SIZE,
)
from unpackers.python_marshal_static import (
    is_marshaled_code_entry_name as is_python39_marshaled_entry_name,
)
from unpackers.python_marshal_static import (
    recover_marshaled_constants as recover_python39_marshaled_constants,
)
from unpackers.static_unpacker import unpack_bytes


def _bytes(value: bytes, *, flagged: bool = False) -> bytes:
    tag = ord("s") | (0x80 if flagged else 0)
    return bytes((tag,)) + struct.pack("<i", len(value)) + value


def _text(value: str) -> bytes:
    encoded = value.encode("ascii")
    if len(encoded) <= 255:
        return b"z" + bytes((len(encoded),)) + encoded
    return b"a" + struct.pack("<i", len(encoded)) + encoded


def _unicode_bytes(value: bytes) -> bytes:
    return b"u" + struct.pack("<i", len(value)) + value


def _tuple(*values: bytes, small: bool = False) -> bytes:
    if small and len(values) <= 255:
        return b")" + bytes((len(values),)) + b"".join(values)
    return b"(" + struct.pack("<i", len(values)) + b"".join(values)


def _code(
    *constants: bytes,
    trailing: bytes = b"",
    bytecode: bytes = b"d\x00S\x00",
) -> bytes:
    fields = struct.pack("<6i", 0, 0, 0, 0, 2, 0x40)
    return (
        b"\xe3"
        + fields
        + b"".join(
            (
                _bytes(bytecode),
                _tuple(b"N", *constants),
                _tuple(),
                _tuple(),
                _tuple(),
                _tuple(),
                _text("fixture.py"),
                _text("<module>"),
                struct.pack("<i", 1),
                _bytes(b""),
                trailing,
            )
        )
    )


def _entry_name() -> str:
    return "outer.exe::pyinstaller-python_script-000-Program"


def test_recovers_base64_constant_with_exact_lineage_and_full_consumption() -> None:
    decoded = b"MZ" + b"A" * 510
    source = base64.b64encode(decoded)

    report, artifacts = recover_python39_marshaled_constants(
        _code(_bytes(source)),
        _entry_name(),
    )

    assert report["status"] == "artifacts_recovered"
    assert report["coverage"]["full_consumption"] is True
    assert report["coverage"]["code_object_count"] == 1
    assert report["candidate_set_complete"] is True
    assert artifacts == [("python-marshal-base64-decoded-000", decoded)]
    assert report["candidates"] == [
        {
            "index": 0,
            "artifact_kind": "python-marshal-base64-decoded-000",
            "source_offset": report["candidates"][0]["source_offset"],
            "source_size": len(source),
            "source_kind": "bytes",
            "source_path": "root.code_object.consts.item[1]",
            "source_fragment_count": 1,
            "source_fragments_sha256": report["candidates"][0][
                "source_fragments_sha256"
            ],
            "transform": "base64_decoded",
            "sha256": report["candidates"][0]["sha256"],
            "size": len(decoded),
        }
    ]
    assert report["safety"]["marshal_loads_used"] is False
    assert report["safety"]["python_bytecode_executed"] is False
    assert report["evidence_boundary"]["constant_candidate_confirms_c2"] is False


def test_canonical_hex_is_not_lost_to_canonical_base64_ambiguity() -> None:
    decoded = b"MZ" + b"A" * 62
    source = decoded.hex().encode("ascii")

    report, artifacts = recover_python39_marshaled_constants(
        _code(_bytes(source)),
        _entry_name(),
    )

    assert report["status"] == "artifacts_recovered"
    assert artifacts == [("python-marshal-hex-decoded-000", decoded)]
    assert report["candidates"][0]["transform"] == "hex_decoded"


def test_unresolved_hex_base64_ambiguity_keeps_both_bounded_candidates() -> None:
    source = (b"41414141" * 16).lower()
    expected_hex = bytes.fromhex(source.decode("ascii"))
    expected_base64 = base64.b64decode(source, validate=True)

    report, artifacts = recover_python39_marshaled_constants(
        _code(_bytes(source)),
        _entry_name(),
    )

    assert report["candidate_count"] == 2
    assert artifacts == [
        ("python-marshal-base64-decoded-000", expected_base64),
        ("python-marshal-hex-decoded-001", expected_hex),
    ]


def test_nested_code_constants_are_parsed_without_executing_bytecode() -> None:
    decoded = b"PK\x03\x04" + b"B" * 128
    nested = _code(_bytes(base64.b64encode(decoded)))

    report, artifacts = recover_python39_marshaled_constants(
        _code(nested),
        _entry_name(),
    )

    assert report["coverage"]["code_object_count"] == 2
    assert report["coverage"]["full_consumption"] is True
    assert artifacts == [("python-marshal-base64-decoded-000", decoded)]
    assert "code_object.consts" in report["candidates"][0]["source_path"]


def test_large_ordered_base64_fragment_sequence_is_reassembled_before_budget() -> None:
    decoded = b"MZ" + bytes(range(256)) * 32
    encoded = base64.b64encode(decoded)
    fragments = [
        encoded[offset : offset + 120] for offset in range(0, len(encoded), 120)
    ]
    sequence = _tuple(*(_bytes(fragment) for fragment in fragments))

    report, artifacts = recover_python39_marshaled_constants(
        _code(sequence),
        _entry_name(),
        max_candidates=2,
    )

    assert report["status"] == "artifacts_recovered"
    assert report["candidate_set_complete"] is True
    assert report["candidate_count"] == 1
    assert report["candidates"][0]["transform"] == "sequence_base64_decoded"
    assert report["candidates"][0]["source_fragment_count"] == len(fragments)
    assert artifacts == [("python-marshal-sequence-base64-decoded-000", decoded)]


def test_ordered_hex_fragments_use_hex_encoded_size_bound() -> None:
    decoded = b"MZ" + b"H" * 62
    encoded = decoded.hex().encode("ascii")
    sequence = _tuple(_bytes(encoded[:64]), _bytes(encoded[64:]))

    report, artifacts = recover_python39_marshaled_constants(
        _code(sequence),
        _entry_name(),
        max_candidate_size=len(decoded),
    )

    assert report["status"] == "artifacts_recovered"
    assert report["candidate_set_complete"] is True
    assert artifacts == [("python-marshal-sequence-hex-decoded-000", decoded)]


def test_reference_to_constant_is_deduplicated() -> None:
    decoded = b"\x7fELF" + b"C" * 128
    encoded = base64.b64encode(decoded)
    # root code objectがreference 0、flag付きbytesがreference 1になる。
    constant = _bytes(encoded, flagged=True)
    reference = b"r" + struct.pack("<i", 1)

    report, artifacts = recover_python39_marshaled_constants(
        _code(constant, reference),
        _entry_name(),
    )

    assert report["coverage"]["reference_read_count"] == 1
    assert report["candidate_count"] == 1
    assert artifacts == [("python-marshal-base64-decoded-000", decoded)]


def test_flagged_singleton_does_not_shift_reference_indices() -> None:
    decoded = b"MZ" + b"J" * 128
    encoded = base64.b64encode(decoded)
    flagged_none = bytes((ord("N") | 0x80,))
    reference = b"r" + struct.pack("<i", 1)

    report, artifacts = recover_python39_marshaled_constants(
        _code(flagged_none, _bytes(encoded, flagged=True), reference),
        _entry_name(),
    )

    assert report["status"] == "artifacts_recovered"
    assert report["coverage"]["reference_count"] == 2
    assert report["coverage"]["reference_read_count"] == 1
    assert artifacts == [("python-marshal-base64-decoded-000", decoded)]


def test_flagged_frozenset_self_reference_is_rejected_while_pending() -> None:
    flagged_frozenset = (
        bytes((ord(">") | 0x80,)) + struct.pack("<i", 1) + b"r" + struct.pack("<i", 1)
    )

    report, artifacts = recover_python39_marshaled_constants(
        _code(flagged_frozenset),
        _entry_name(),
    )

    assert report["status"] == "parse_failed"
    assert report["failure"]["reason"] == "forward_or_recursive_reference"
    assert artifacts == []


def test_set_self_reference_is_rejected_as_unhashable() -> None:
    flagged_set = (
        bytes((ord("<") | 0x80,)) + struct.pack("<i", 1) + b"r" + struct.pack("<i", 1)
    )

    report, artifacts = recover_python39_marshaled_constants(
        _code(flagged_set),
        _entry_name(),
    )

    assert report["status"] == "parse_failed"
    assert report["failure"]["reason"] == "unhashable_set_member"
    assert artifacts == []


def test_dict_self_key_is_rejected_as_unhashable() -> None:
    flagged_dict = bytes((ord("{") | 0x80,)) + b"r" + struct.pack("<i", 1) + b"N" + b"0"

    report, artifacts = recover_python39_marshaled_constants(
        _code(flagged_dict),
        _entry_name(),
    )

    assert report["status"] == "parse_failed"
    assert report["failure"]["reason"] == "unhashable_dict_key"
    assert artifacts == []


def test_duplicate_payload_does_not_consume_unique_candidate_budget() -> None:
    decoded = b"\x7fELF" + b"I" * 128
    encoded = base64.b64encode(decoded)

    report, artifacts = recover_python39_marshaled_constants(
        _code(_bytes(encoded), _bytes(encoded)),
        _entry_name(),
        max_candidates=1,
    )

    assert report["status"] == "artifacts_recovered"
    assert report["candidate_set_complete"] is True
    assert report["rejection_counts"]["duplicate_payload"] == 1
    assert artifacts == [("python-marshal-base64-decoded-000", decoded)]


def test_non_pyinstaller_lineage_is_not_parsed_even_with_code_magic() -> None:
    payload = _code(_bytes(base64.b64encode(b"MZ" + b"D" * 128)))

    report, artifacts = recover_python39_marshaled_constants(payload, "Program")

    assert is_python39_marshaled_entry_name("Program") is False
    assert report["status"] == "not_applicable"
    assert report["candidate_set_complete"] is True
    assert artifacts == []


def test_trailing_bytes_fail_closed_without_partial_artifacts() -> None:
    payload = _code(
        _bytes(base64.b64encode(b"MZ" + b"E" * 128)),
        trailing=b"unexpected",
    )

    report, artifacts = recover_python39_marshaled_constants(payload, _entry_name())

    assert report["status"] == "parse_failed"
    assert report["failure"]["reason"] == "trailing_bytes"
    assert report["coverage"]["full_consumption"] is False
    assert report["candidate_set_complete"] is False
    assert artifacts == []


def test_null_is_rejected_outside_dict_key_terminator() -> None:
    report, artifacts = recover_python39_marshaled_constants(
        _code(b"0"),
        _entry_name(),
    )

    assert report["status"] == "parse_failed"
    assert report["failure"]["reason"] == "null_outside_dict_terminator"
    assert artifacts == []


def test_flagged_null_is_accepted_only_as_unregistered_dict_terminator() -> None:
    flagged_null = bytes((ord("0") | 0x80,))

    report, artifacts = recover_python39_marshaled_constants(
        _code(b"{" + flagged_null),
        _entry_name(),
    )

    assert report["status"] == "validated_no_payload_candidate"
    assert report["coverage"]["reference_count"] == 1
    assert report["coverage"]["full_consumption"] is True
    assert artifacts == []


def test_marshaled_unicode_lone_surrogate_uses_surrogatepass_validation() -> None:
    report, artifacts = recover_python39_marshaled_constants(
        _code(_unicode_bytes(b"\xed\xa0\x80")),
        _entry_name(),
    )

    assert report["status"] == "validated_no_payload_candidate"
    assert report["coverage"]["full_consumption"] is True
    assert report["profile"].endswith("_candidate")
    assert report["evidence_boundary"]["runtime_python_version_confirmed"] is False
    assert artifacts == []


@pytest.mark.parametrize(
    ("kwargs", "reason"),
    [
        ({"max_nodes": 3}, "node_limit"),
        ({"max_depth": 1}, "depth_limit"),
        ({"max_scalar_size": 3}, "scalar_size_limit"),
    ],
)
def test_structural_budgets_fail_closed(kwargs: dict[str, int], reason: str) -> None:
    report, artifacts = recover_python39_marshaled_constants(
        _code(_bytes(b"not-a-payload")),
        _entry_name(),
        **kwargs,
    )

    assert report["status"] == "parse_failed"
    assert report["failure"]["reason"] == reason
    assert artifacts == []


@pytest.mark.parametrize(
    ("argument", "hard_maximum"),
    [
        ("max_input_size", MAX_INPUT_SIZE),
        ("max_nodes", MAX_NODES),
        ("max_depth", MAX_DEPTH),
        ("max_collection_items", MAX_COLLECTION_ITEMS),
        ("max_scalar_size", MAX_SCALAR_SIZE),
        ("max_candidates", MAX_CANDIDATES),
        ("max_candidate_size", MAX_CANDIDATE_SIZE),
        ("max_candidate_total_size", MAX_CANDIDATE_TOTAL_SIZE),
    ],
)
def test_public_budget_overrides_cannot_exceed_hard_maximum(
    argument: str,
    hard_maximum: int,
) -> None:
    with pytest.raises(ValueError, match="hard maximum"):
        recover_python39_marshaled_constants(
            _code(),
            _entry_name(),
            **{argument: hard_maximum + 1},
        )


def test_candidate_total_budget_is_visible_and_does_not_claim_completeness() -> None:
    decoded = b"MZ" + b"F" * 128

    report, artifacts = recover_python39_marshaled_constants(
        _code(_bytes(base64.b64encode(decoded))),
        _entry_name(),
        max_candidate_total_size=32,
    )

    assert report["status"] == "bounded_limit"
    assert report["candidate_set_complete"] is False
    assert report["blockers"] == ["candidate_total_size_limit"]
    assert report["rejection_counts"]["candidate_total_size_limit"] == 1
    assert artifacts == []


def test_invalid_code_field_contract_is_rejected() -> None:
    # wordcodeは2 byte境界でなければならない。
    report, artifacts = recover_python39_marshaled_constants(
        _code(bytecode=b"\x64\x00\x53"),
        _entry_name(),
    )

    assert report["status"] == "parse_failed"
    assert report["failure"]["reason"] == "invalid_wordcode"
    assert artifacts == []


@pytest.mark.parametrize(
    ("constant", "reason"),
    [
        (b"l" + struct.pack("<i", 1) + struct.pack("<h", 0), "unnormalized_long"),
        (
            b"l" + struct.pack("<i", 1) + struct.pack("<h", -1),
            "long_digit_out_of_range",
        ),
        (b"f\x03xxx", "invalid_float_text"),
    ],
)
def test_invalid_numeric_wire_values_fail_closed(
    constant: bytes,
    reason: str,
) -> None:
    report, artifacts = recover_python39_marshaled_constants(
        _code(constant, _bytes(base64.b64encode(b"MZ" + b"K" * 128))),
        _entry_name(),
    )

    assert report["status"] == "parse_failed"
    assert report["failure"]["reason"] == reason
    assert artifacts == []


def test_static_unpacker_routes_marshaled_constant_as_child_artifact() -> None:
    decoded = b"%PDF-" + b"G" * 128
    raw = _code(_bytes(base64.b64encode(decoded)))

    report, artifacts = unpack_bytes(raw, _entry_name())

    assert report["python_marshal"]["status"] == "artifacts_recovered"
    assert report["python_marshal"]["coverage"]["full_consumption"] is True
    assert ("python-marshal-base64-decoded-000", decoded) in artifacts
    assert {
        "kind": "python-marshal-base64-decoded-000",
        "size": len(decoded),
        "sha256": report["python_marshal"]["candidates"][0]["sha256"],
    } in report["recovered"]


def test_static_unpacker_does_not_add_marshal_report_to_unrelated_input() -> None:
    report, artifacts = unpack_bytes(b"ordinary fixture", "ordinary.bin")

    assert "python_marshal" not in report
    assert all(not kind.startswith("python-marshal-") for kind, _blob in artifacts)
