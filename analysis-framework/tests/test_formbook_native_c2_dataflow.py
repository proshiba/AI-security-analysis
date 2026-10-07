"""native FormBook／XLoader C2 dataflow検証器の合成回帰。"""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import struct
import sys
from collections import Counter
from dataclasses import replace
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
MODULE_DIR = (
    ROOT / "analysis-framework" / "malware" / "formbook_loader"
)
if str(MODULE_DIR) not in sys.path:
    sys.path.insert(0, str(MODULE_DIR))


def _load_module(name: str, filename: str) -> object:
    spec = importlib.util.spec_from_file_location(name, MODULE_DIR / filename)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


NATIVE = _load_module("native_xloader", "native_xloader.py")
PROTOCOL = _load_module("formbook_protocol", "formbook_protocol.py")
DATAFLOW = _load_module("native_c2_dataflow", "native_c2_dataflow.py")

CANDIDATE = 0x100
API_BUILDERS = (0x140, 0x180, 0x1C0)
KEY_HELPERS = (0x200, 0x240, 0x280)
BASE64_DECODER = 0x300
RC4_SUB = 0x380
NETWORK_CONSUMER = 0x500
ORCHESTRATOR = 0x600
SECOND_ORCHESTRATOR = 0x700

KEYS = (
    bytes(range(20)),
    bytes(range(20, 40)),
    bytes(reversed(range(20))),
)
PLAINTEXT = b"www.synthetic.invalid/unit/\x00"


def _direct_call(function_offset: int, current_size: int, target: int) -> bytes:
    call_offset = function_offset + current_size
    return b"\xe8" + struct.pack("<i", target - (call_offset + 5))


def _place(image: bytearray, offset: int, value: bytes) -> None:
    image[offset : offset + len(value)] = value


def _base64_decoder() -> bytes:
    return (
        b"\x55\x8b\xec"
        b"\x8b\x45\x08"
        b"\x83\xe0\x3f"
        b"\xc1\xe8\x02"
        b"\xc1\xe0\x04"
        b"\x3c\x3d"
        b"\x31\xc9"
        b"\x41"
        b"\x83\xf9\x04"
        b"\x72\xfa"
        b"\x5d\xc3"
    )


def _rc4_sub_fingerprint() -> bytes:
    function = bytearray(
        b"\x55\x8b\xec"
        b"\x8b\x45\x08"
        b"\x8b\x55\x0c"
    )
    loop_bodies = (
        b"\x28\x14\x08\x86\x14\x08\x30\x14\x08",
        b"\x28\x14\x08\x86\x14\x08",
        b"\x8a\x1c\x08",
        b"\x8a\x1c\x0a",
    )
    for body in loop_bodies:
        function.extend(b"\x31\xc9")
        loop_start = len(function)
        function.extend(body)
        function.extend(b"\x41\x81\xf9\x00\x01\x00\x00\x72")
        displacement = loop_start - (len(function) + 1)
        function.extend(struct.pack("b", displacement))
    function.extend(b"\x5d\xc3")
    return bytes(function)


def _network_consumer(offset: int) -> bytes:
    function = bytearray(b"\x55\x8b\xec")
    for target in API_BUILDERS:
        function.extend(_direct_call(offset, len(function), target))
    function.extend(b"\xff\xd0\x5d\xc3")
    return bytes(function)


def _lookup_base64_decoder(*, stores: int = 64) -> bytes:
    """256-byte stack lookup-tableを使うdecoder形状を合成する。"""

    function = bytearray(b"\x55\x8b\xec\x81\xec\x04\x01\x00\x00")
    for index in range(stores):
        displacement = -0x104 + index * 4
        function.extend(b"\xc7\x85")
        function.extend(struct.pack("<i", displacement))
        function.extend(struct.pack("<I", 0x57575757 ^ index))
    function.extend(b"\x8b\x45\x08\x8b\x55\x0c")
    function.extend(b"\xc1\xe8\x02\xc1\xe0\x04\xc1\xea\x06")
    indexed_read = b"\x8a\x84\x0d\xfc\xfe\xff\xff"
    for _ in range(2):
        function.extend(b"\x31\xc9")
        loop_start = len(function)
        function.extend(indexed_read * 4)
        function.extend(b"\x41\x81\xf9\x00\x01\x00\x00\x72")
        displacement = loop_start - (len(function) + 1)
        function.extend(struct.pack("b", displacement))
    function.extend(b"\xc9\xc3")
    return bytes(function)


def _network_api_thunk(
    offset: int, api_builder: int, *, include_indirect: bool = True
) -> bytes:
    function = bytearray(b"\x55\x8b\xec")
    function.extend(_direct_call(offset, len(function), api_builder))
    if include_indirect:
        function.extend(b"\xff\xd0")
    function.extend(b"\x5d\xc3")
    return bytes(function)


def _branched_thunk_consumer(offset: int, thunks: tuple[int, ...]) -> bytes:
    """最初のret後の分岐blockで3本目のAPI thunkを呼ぶ。"""

    function = bytearray(b"\x55\x8b\xec")
    for target in thunks[:2]:
        function.extend(_direct_call(offset, len(function), target))
    function.extend(b"\x85\xc0")
    branch_offset = len(function)
    function.extend(b"\x75\x00\x5d\xc3")
    branch_target = len(function)
    function[branch_offset + 1] = (
        branch_target - (branch_offset + 2)
    ) & 0xFF
    function.extend(_direct_call(offset, len(function), thunks[2]))
    function.extend(b"\x5d\xc3")
    return bytes(function)


def _exclusive_thunk_consumer(offset: int, thunks: tuple[int, ...]) -> bytes:
    """2分岐のAPI集合を合算すると3種だが、同一路径では揃わない。"""

    function = bytearray(b"\x55\x8b\xec\x85\xc0")
    branch_offset = len(function)
    function.extend(b"\x75\x00")
    for target in thunks[:2]:
        function.extend(_direct_call(offset, len(function), target))
    function.extend(b"\x5d\xc3")
    branch_target = len(function)
    function[branch_offset + 1] = (
        branch_target - (branch_offset + 2)
    ) & 0xFF
    function.extend(_direct_call(offset, len(function), thunks[2]))
    function.extend(b"\x5d\xc3")
    return bytes(function)


def _orchestrator(offset: int, *, include_network: bool = True) -> bytes:
    function = bytearray(b"\x55\x8b\xec\x83\xec\x70")

    function.extend(_direct_call(offset, len(function), CANDIDATE))
    function.extend(b"\x89\x45\xfc\xff\x75\xfc")
    function.extend(_direct_call(offset, len(function), BASE64_DECODER))
    function.extend(b"\x83\xc4\x04\x89\x45\xf8")

    previous = -8
    outputs = (-12, -16, -20)
    key_locals = (-32, -48, -64)
    for helper, key_local, output in zip(
        KEY_HELPERS, key_locals, outputs, strict=True
    ):
        function.extend(b"\x8d\x45" + bytes([key_local & 0xFF]))
        function.extend(b"\x50")
        function.extend(_direct_call(offset, len(function), helper))
        function.extend(b"\x83\xc4\x04")

        function.extend(b"\x8d\x45" + bytes([key_local & 0xFF]))
        function.extend(b"\x50")
        function.extend(b"\xff\x75" + bytes([previous & 0xFF]))
        function.extend(_direct_call(offset, len(function), RC4_SUB))
        function.extend(b"\x83\xc4\x08")
        function.extend(b"\x89\x45" + bytes([output & 0xFF]))
        previous = output

    if include_network:
        function.extend(b"\xff\x75" + bytes([previous & 0xFF]))
        function.extend(
            _direct_call(offset, len(function), NETWORK_CONSUMER)
        )
        function.extend(b"\x83\xc4\x04")
    function.extend(b"\xc9\xc3")
    return bytes(function)


def _encoded_candidate() -> bytes:
    encrypted = PLAINTEXT
    for key in reversed(KEYS):
        encrypted = NATIVE.encrypt_rc4_sub(encrypted, key)
    return base64.b64encode(encrypted)


def _stack_writes(value: bytes) -> bytes:
    assert len(value) % 4 == 0
    return b"".join(
        b"\xc7\x45"
        + bytes([(-len(value) + index) & 0xFF])
        + value[index : index + 4]
        for index in range(0, len(value), 4)
    )


def _builder_function(
    offset: int,
    decrypt_target: int,
    plaintext: bytes,
    base_key: bytes,
    *,
    tweak: int,
) -> bytes:
    encrypted = NATIVE.encrypt_rc4_sub(
        plaintext,
        bytes(value ^ tweak for value in base_key),
    )
    function = bytearray(b"\x55\x8b\xec")
    function.extend(_stack_writes(encrypted))
    function.extend(b"\x6a" + bytes([len(encrypted)]))
    function.extend(b"\xb3" + bytes([tweak]))
    function.extend(_direct_call(offset, len(function), decrypt_target))
    function.extend(b"\xc3")
    return bytes(function)


def _recoverable_key_helper(
    offset: int,
    key: bytes,
    *,
    mask: int,
    byte_xor: int,
) -> bytes:
    before_byte_xor = bytes(value ^ byte_xor for value in key)
    function = bytearray(b"\x55\x8b\xec\x83\xec\x24\xb8")
    function.extend(struct.pack("<I", mask))
    for index in range(0, len(before_byte_xor), 4):
        displacement = -0x24 + index
        word = int.from_bytes(before_byte_xor[index : index + 4], "little")
        function.extend(
            b"\xc7\x45"
            + bytes([displacement & 0xFF])
            + struct.pack("<I", word ^ mask)
        )
        function.extend(b"\x31\x45" + bytes([displacement & 0xFF]))
    function.extend(
        b"\x33\xc0"
        b"\x80\x74\x05\xdc"
        + bytes([byte_xor])
        + b"\x40\x83\xf8\x14\x72\xf5"
        b"\x6a\x14\x8d\x45\xdc\x50"
    )
    copy_target = offset + 0x180
    function.extend(_direct_call(offset, len(function), copy_target))
    function.extend(b"\xc3")
    return bytes(function)


def _public_fixture() -> bytes:
    candidate = 0x100
    api_builders = (0x180, 0x200, 0x280)
    decrypt_target = 0x380
    base_key_helper = 0x400
    c2_helpers = (0x600, 0x800, 0xA00)
    base64_decoder = 0xC00
    rc4_sub = 0xC80
    network_consumer = 0xD80
    orchestrator = 0xE00
    base_key = b"builder-base-key-123"
    assert len(base_key) == 20

    image = bytearray(b"\x90" * 0x1200)
    builder_values = (
        _encoded_candidate(),
        b"InternetConnectA",
        b"HttpOpenRequestA",
        b"HttpSendRequestA",
    )
    for index, (offset, value) in enumerate(
        zip((candidate, *api_builders), builder_values, strict=True)
    ):
        _place(
            image,
            offset,
            _builder_function(
                offset,
                decrypt_target,
                value,
                base_key,
                tweak=0x41 + index,
            ),
        )

    decrypt = bytearray(b"\x55\x8b\xec")
    decrypt.extend(
        _direct_call(decrypt_target, len(decrypt), base_key_helper)
    )
    decrypt.extend(b"\x5d\xc3")
    _place(image, decrypt_target, bytes(decrypt))
    _place(
        image,
        base_key_helper,
        _recoverable_key_helper(
            base_key_helper,
            base_key,
            mask=0x31415926,
            byte_xor=0x6D,
        ),
    )
    for index, (offset, key) in enumerate(
        zip(c2_helpers, KEYS, strict=True)
    ):
        _place(
            image,
            offset,
            _recoverable_key_helper(
                offset,
                key,
                mask=0x10203040 + index,
                byte_xor=0x51 + index,
            ),
        )

    _place(image, base64_decoder, _base64_decoder())
    _place(image, rc4_sub, _rc4_sub_fingerprint())

    sink = bytearray(b"\x55\x8b\xec")
    for target in api_builders:
        sink.extend(_direct_call(network_consumer, len(sink), target))
    sink.extend(b"\xff\xd0\x5d\xc3")
    _place(image, network_consumer, bytes(sink))

    function = bytearray(b"\x55\x8b\xec\x83\xec\x70")
    function.extend(_direct_call(orchestrator, len(function), candidate))
    function.extend(b"\x89\x45\xfc\xff\x75\xfc")
    function.extend(
        _direct_call(orchestrator, len(function), base64_decoder)
    )
    function.extend(b"\x83\xc4\x04\x89\x45\xf8")
    previous = -8
    for helper, key_local, output in zip(
        c2_helpers,
        (-32, -48, -64),
        (-12, -16, -20),
        strict=True,
    ):
        function.extend(b"\x8d\x45" + bytes([key_local & 0xFF]))
        function.extend(b"\x50")
        function.extend(_direct_call(orchestrator, len(function), helper))
        function.extend(b"\x83\xc4\x04")
        function.extend(b"\x8d\x45" + bytes([key_local & 0xFF]))
        function.extend(b"\x50\xff\x75" + bytes([previous & 0xFF]))
        function.extend(_direct_call(orchestrator, len(function), rc4_sub))
        function.extend(
            b"\x83\xc4\x08\x89\x45" + bytes([output & 0xFF])
        )
        previous = output
    function.extend(b"\xff\x75" + bytes([previous & 0xFF]))
    function.extend(
        _direct_call(orchestrator, len(function), network_consumer)
    )
    function.extend(b"\x83\xc4\x04\xc9\xc3")
    _place(image, orchestrator, bytes(function))
    return bytes(image)


def _fixture(*, second_path: bool = False, include_network: bool = True) -> tuple[
    bytes,
    tuple[object, ...],
    tuple[object, ...],
    tuple[int, ...],
]:
    image = bytearray(b"\x90" * 0x900)
    plain_function = b"\x55\x8b\xec\x5d\xc3"
    for offset in (CANDIDATE, *API_BUILDERS, *KEY_HELPERS):
        _place(image, offset, plain_function)
    _place(image, BASE64_DECODER, _base64_decoder())
    _place(image, RC4_SUB, _rc4_sub_fingerprint())
    _place(image, NETWORK_CONSUMER, _network_consumer(NETWORK_CONSUMER))
    _place(
        image,
        ORCHESTRATOR,
        _orchestrator(ORCHESTRATOR, include_network=include_network),
    )
    prologues = [
        CANDIDATE,
        *API_BUILDERS,
        *KEY_HELPERS,
        BASE64_DECODER,
        RC4_SUB,
        NETWORK_CONSUMER,
        ORCHESTRATOR,
    ]
    if second_path:
        _place(
            image,
            SECOND_ORCHESTRATOR,
            _orchestrator(SECOND_ORCHESTRATOR),
        )
        prologues.append(SECOND_ORCHESTRATOR)

    builders = (
        NATIVE.DecodedBuilder(CANDIDATE, 0x5A, _encoded_candidate()),
        NATIVE.DecodedBuilder(API_BUILDERS[0], 0x5A, b"InternetConnectA"),
        NATIVE.DecodedBuilder(API_BUILDERS[1], 0x5A, b"HttpOpenRequestA"),
        NATIVE.DecodedBuilder(API_BUILDERS[2], 0x5A, b"HttpSendRequestA"),
    )
    helpers = tuple(
        DATAFLOW._KeyHelper(offset, key)
        for offset, key in zip(KEY_HELPERS, KEYS, strict=True)
    )
    return bytes(image), builders, helpers, tuple(prologues)


def test_complete_same_path_promotes_only_strict_endpoint() -> None:
    data, builders, helpers, prologues = _fixture()

    result = DATAFLOW._analyze_provenance(
        data, builders, helpers, prologues
    )
    report = result.to_report()

    assert result.status == "resolved"
    assert result.blockers == ()
    assert len(result.paths) == 1
    assert result.paths[0].host == "www.synthetic.invalid"
    assert result.paths[0].path == "/unit/"
    assert result.paths[0].layer_helper_offsets == KEY_HELPERS
    assert report["static_config_recovered"] is True
    assert report["c2"] == [
        {
            "host": "www.synthetic.invalid",
            "path": "/unit/",
            "scheme": None,
            "evidence": "same_static_dataflow_path",
        }
    ]
    serialized = json.dumps(report, sort_keys=True)
    assert PLAINTEXT.decode("ascii") not in serialized
    assert _encoded_candidate().decode("ascii") not in serialized
    assert all(key.hex() not in serialized for key in KEYS)
    assert report["safety"] == {
        "sample_executed": False,
        "cpu_emulated": False,
        "network_contacted": False,
        "llm_used": False,
        "raw_builder_values_included": False,
        "key_material_included": False,
        "intermediate_plaintext_included": False,
    }


def test_public_entrypoint_recovers_complete_synthetic_chain() -> None:
    result = DATAFLOW.analyze_native_c2_dataflow(_public_fixture())

    assert result.status == "resolved"
    assert result.builder_count == 4
    assert result.canonical_base64_candidate_count == 4
    assert result.key_helper_count == 4
    assert result.paths[0].host == "www.synthetic.invalid"
    assert result.paths[0].path == "/unit/"


def test_native_builder_decode_does_not_retain_raw_input_globally() -> None:
    data = _public_fixture()

    first = NATIVE.auto_decode_stack_string_builders(data)
    second = NATIVE.auto_decode_stack_string_builders(data)

    assert second is not first
    assert second == first
    assert first.input_sha256 == hashlib.sha256(data).hexdigest()
    assert not hasattr(NATIVE, "_auto_decode_without_provided_key")


def test_public_dataflow_reuses_key_helper_disassembly_for_role_scan() -> None:
    data = _public_fixture()
    calls: Counter[int] = Counter()
    original = DATAFLOW._bounded_instructions

    def counted(candidate: bytes, function_offset: int) -> list[object]:
        calls[function_offset] += 1
        return original(candidate, function_offset)

    DATAFLOW._bounded_instructions = counted
    try:
        result = DATAFLOW.analyze_native_c2_dataflow(data)
    finally:
        DATAFLOW._bounded_instructions = original

    assert result.status == "resolved"
    assert calls
    assert max(calls.values()) == 1


def test_call_scope_cache_reuses_sha_bound_raw_functions() -> None:
    data = _public_fixture()
    decoded, snapshot = NATIVE.auto_decode_stack_string_builders_with_cache(
        data
    )
    assert snapshot is not None
    assert snapshot.input_sha256 == hashlib.sha256(data).hexdigest()
    assert snapshot.entry_count == len(snapshot.entries)
    assert snapshot.instruction_count <= (
        NATIVE.MAX_CALL_SCOPE_CACHE_INSTRUCTIONS
    )
    assert snapshot.decoded_bytes <= (
        NATIVE.MAX_CALL_SCOPE_CACHE_DECODED_BYTES
    )
    assert all(type(raw) is bytes for _offset, raw, _count in snapshot.entries)

    calls: Counter[int] = Counter()
    original = DATAFLOW._bounded_instructions

    def counted(candidate: bytes, function_offset: int) -> list[object]:
        calls[function_offset] += 1
        return original(candidate, function_offset)

    DATAFLOW._bounded_instructions = counted
    try:
        result = DATAFLOW.analyze_native_c2_dataflow(
            data,
            _decoded=decoded,
            _instruction_cache=snapshot,
        )
    finally:
        DATAFLOW._bounded_instructions = original

    assert result.status == "resolved"
    assert calls
    assert max(calls.values()) == 1
    assert "entries=" not in repr(snapshot)


@pytest.mark.parametrize(
    "tamper",
    (
        lambda snapshot: replace(snapshot, input_sha256="0" * 64),
        lambda snapshot: replace(
            snapshot,
            instruction_count=snapshot.instruction_count + 1,
        ),
        lambda snapshot: replace(
            snapshot,
            created_monotonic=0.0,
            deadline_monotonic=0.1,
        ),
    ),
)
def test_call_scope_cache_rejects_tampering_and_expiry(tamper: object) -> None:
    data = _public_fixture()
    decoded, snapshot = NATIVE.auto_decode_stack_string_builders_with_cache(
        data
    )
    assert snapshot is not None

    with pytest.raises(ValueError, match="命令snapshot"):
        DATAFLOW.analyze_native_c2_dataflow(
            data,
            _decoded=decoded,
            _instruction_cache=tamper(snapshot),
        )


def test_same_path_roles_share_one_bounded_disassembly_per_function() -> None:
    data, builders, helpers, prologues = _fixture()
    calls: Counter[int] = Counter()
    original = DATAFLOW._bounded_instructions

    def counted(candidate: bytes, function_offset: int) -> list[object]:
        calls[function_offset] += 1
        return original(candidate, function_offset)

    DATAFLOW._bounded_instructions = counted
    try:
        result = DATAFLOW._analyze_provenance(
            data, builders, helpers, prologues
        )
    finally:
        DATAFLOW._bounded_instructions = original

    assert result.status == "resolved"
    assert calls
    assert max(calls.values()) == 1


def test_encrypted_pool_without_consumer_dataflow_stays_unresolved() -> None:
    data, builders, helpers, prologues = _fixture(include_network=False)

    result = DATAFLOW._analyze_provenance(
        data, builders, helpers, prologues
    )

    assert result.status == "unresolved"
    assert result.paths == ()
    assert "layer_key_roles_unproven" in result.blockers
    assert "same_path_dataflow_unproven" in result.blockers
    assert result.to_report()["c2"] == []


def test_missing_required_transform_roles_skips_network_cfg_fail_closed() -> None:
    data, builders, helpers, prologues = _fixture()
    roleless_prologues = tuple(
        offset
        for offset in prologues
        if offset not in {BASE64_DECODER, RC4_SUB}
    )
    original = DATAFLOW._network_consumer_offsets

    def unexpected_network_scan(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("必須transform不在時にnetwork CFGを走査しました")

    DATAFLOW._network_consumer_offsets = unexpected_network_scan
    try:
        result = DATAFLOW._analyze_provenance(
            data,
            builders,
            helpers,
            roleless_prologues,
        )
    finally:
        DATAFLOW._network_consumer_offsets = original

    assert result.status == "unresolved"
    assert result.paths == ()
    assert result.base64_decoder_count == 0
    assert result.rc4_sub_transform_count == 0
    assert result.network_consumer_count == 0
    assert "base64_decoder_unproven" in result.blockers
    assert "rc4_sub_transform_unproven" in result.blockers
    assert (
        "network_consumer_not_scanned_missing_required_roles"
        in result.blockers
    )
    assert result.to_report()["c2"] == []


def test_complete_roles_still_scan_network_cfg_and_resolve() -> None:
    data, builders, helpers, prologues = _fixture()
    original = DATAFLOW._network_consumer_offsets
    calls = 0

    def counted(*args: object, **kwargs: object) -> object:
        nonlocal calls
        calls += 1
        return original(*args, **kwargs)

    DATAFLOW._network_consumer_offsets = counted
    try:
        result = DATAFLOW._analyze_provenance(
            data,
            builders,
            helpers,
            prologues,
        )
    finally:
        DATAFLOW._network_consumer_offsets = original

    assert calls == 1
    assert result.status == "resolved"
    assert len(result.paths) == 1


def test_two_complete_paths_fail_closed_as_ambiguous() -> None:
    data, builders, helpers, prologues = _fixture(second_path=True)

    result = DATAFLOW._analyze_provenance(
        data, builders, helpers, prologues
    )

    assert result.status == "ambiguous"
    assert result.blockers == ("multiple_complete_static_paths",)
    assert result.paths == ()
    assert result.to_report()["c2"] == []


def test_endpoint_grammar_mismatch_never_promotes() -> None:
    data, builders, helpers, prologues = _fixture()
    bad_plaintext = b"https://synthetic.invalid/not-xloader"
    encrypted = bad_plaintext
    for key in reversed(KEYS):
        encrypted = NATIVE.encrypt_rc4_sub(encrypted, key)
    bad_builders = (
        NATIVE.DecodedBuilder(
            CANDIDATE,
            0x5A,
            base64.b64encode(encrypted),
        ),
        *builders[1:],
    )

    result = DATAFLOW._analyze_provenance(
        data, bad_builders, helpers, prologues
    )

    assert result.status == "unresolved"
    assert result.paths == ()
    assert result.to_report()["c2"] == []


def test_public_entrypoint_rejects_oversized_input_before_scan() -> None:
    result = DATAFLOW.analyze_native_c2_dataflow(
        b"A" * (DATAFLOW.MAX_INPUT_SIZE + 1)
    )

    assert result.status == "scan_limit_exceeded"
    assert result.blockers == ("input_size_limit",)
    assert result.to_report()["c2"] == []


def test_lookup_table_base64_decoder_shape_is_detected() -> None:
    offset = 0x100
    image = bytearray(b"\x90" * 0x800)
    _place(image, offset, _lookup_base64_decoder())

    instructions = DATAFLOW._bounded_instructions(bytes(image), offset)

    assert DATAFLOW._looks_like_base64_decoder(instructions) is True


def test_partial_lookup_table_shape_is_rejected() -> None:
    offset = 0x100
    image = bytearray(b"\x90" * 0x800)
    _place(image, offset, _lookup_base64_decoder(stores=31))

    instructions = DATAFLOW._bounded_instructions(bytes(image), offset)

    assert DATAFLOW._looks_like_base64_decoder(instructions) is False


def test_network_sink_follows_one_level_thunks_and_branch_tail() -> None:
    api_builders = (0x100, 0x140, 0x180)
    thunks = (0x200, 0x240, 0x280)
    consumer = 0x300
    image = bytearray(b"\x90" * 0x600)
    for offset in api_builders:
        _place(image, offset, b"\x55\x8b\xec\x5d\xc3")
    for offset, builder in zip(thunks, api_builders, strict=True):
        _place(image, offset, _network_api_thunk(offset, builder))
    _place(image, consumer, _branched_thunk_consumer(consumer, thunks))
    builders = tuple(
        NATIVE.DecodedBuilder(offset, 0x5A, name)
        for offset, name in zip(
            api_builders,
            (
                b"InternetConnectA",
                b"HttpOpenRequestA",
                b"HttpSendRequestA",
            ),
            strict=True,
        )
    )

    consumers, limited = DATAFLOW._network_consumer_offsets(
        bytes(image),
        (*api_builders, *thunks, consumer),
        builders,
    )

    assert limited is False
    assert consumers == frozenset({consumer})


def test_unproven_api_wrapper_does_not_reach_network_sink() -> None:
    api_builders = (0x100, 0x140, 0x180)
    thunks = (0x200, 0x240, 0x280)
    consumer = 0x300
    image = bytearray(b"\x90" * 0x600)
    for offset in api_builders:
        _place(image, offset, b"\x55\x8b\xec\x5d\xc3")
    for offset, builder in zip(thunks, api_builders, strict=True):
        _place(
            image,
            offset,
            _network_api_thunk(
                offset,
                builder,
                include_indirect=offset != thunks[-1],
            ),
        )
    _place(image, consumer, _branched_thunk_consumer(consumer, thunks))
    builders = tuple(
        NATIVE.DecodedBuilder(offset, 0x5A, name)
        for offset, name in zip(
            api_builders,
            (
                b"InternetConnectA",
                b"HttpOpenRequestA",
                b"HttpSendRequestA",
            ),
            strict=True,
        )
    )

    consumers, limited = DATAFLOW._network_consumer_offsets(
        bytes(image),
        (*api_builders, *thunks, consumer),
        builders,
    )

    assert limited is False
    assert consumers == frozenset()


def test_network_api_names_on_exclusive_paths_are_not_merged() -> None:
    api_builders = (0x100, 0x140, 0x180)
    thunks = (0x200, 0x240, 0x280)
    consumer = 0x300
    image = bytearray(b"\x90" * 0x600)
    for offset in api_builders:
        _place(image, offset, b"\x55\x8b\xec\x5d\xc3")
    for offset, builder in zip(thunks, api_builders, strict=True):
        _place(image, offset, _network_api_thunk(offset, builder))
    _place(image, consumer, _exclusive_thunk_consumer(consumer, thunks))
    builders = tuple(
        NATIVE.DecodedBuilder(offset, 0x5A, name)
        for offset, name in zip(
            api_builders,
            (
                b"InternetConnectA",
                b"HttpOpenRequestA",
                b"HttpSendRequestA",
            ),
            strict=True,
        )
    )

    consumers, limited = DATAFLOW._network_consumer_offsets(
        bytes(image),
        (*api_builders, *thunks, consumer),
        builders,
    )

    assert limited is False
    assert consumers == frozenset()
