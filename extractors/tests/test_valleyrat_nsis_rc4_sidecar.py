"""NSIS／XOR／ZipCrypto／RC4 chainの安全境界を合成dataで検証する。"""

from __future__ import annotations

import hashlib
import json
import struct
from types import SimpleNamespace

import pytest
from capstone import CS_ARCH_X86, CS_MODE_64, Cs

from extractors.valleyrat import nsis_rc4_sidecar as route


def _minimal_pe(*, tail: bytes = b"") -> bytes:
    data = bytearray(0x400)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", data, 0x84, 0x8664, 1, 0, 0, 0, 0xF0, 0x2022)
    optional = 0x98
    struct.pack_into("<H", data, optional, 0x20B)
    struct.pack_into("<I", data, optional + 16, 0x1000)
    struct.pack_into("<Q", data, optional + 24, 0x180000000)
    struct.pack_into("<I", data, optional + 32, 0x1000)
    struct.pack_into("<I", data, optional + 36, 0x200)
    struct.pack_into("<I", data, optional + 56, 0x2000)
    struct.pack_into("<I", data, optional + 60, 0x200)
    struct.pack_into("<I", data, optional + 108, 16)
    section = 0x188
    data[section : section + 8] = b".text\0\0\0"
    struct.pack_into("<IIII", data, section + 8, 0x10, 0x1000, 0x200, 0x200)
    struct.pack_into("<I", data, section + 36, 0x60000020)
    data[0x200] = 0xC3
    return bytes(data) + tail


def _instructions(code: bytes) -> tuple[object, ...]:
    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    decoder.detail = True
    return tuple(decoder.disasm(code, 0x180001000))


def test_rc4_implementation_matches_public_test_vector() -> None:
    """標準RC4 test vectorと一致し、独自変種へ誤って変えない。"""

    assert route._rc4(b"Plaintext", b"Key").hex() == "bbf316e8d940af0ad3"


def test_decoded_pe_extent_binds_small_builder_tail_by_hash() -> None:
    """PE extent後の小さいpaddingを捨てず、sizeとSHA-256で固定する。"""

    tail = b"synthetic-padding"
    validated = route._validated_decoded_pe(_minimal_pe(tail=tail))

    assert validated is not None
    child, extent = validated
    assert len(child) == 0x400
    assert extent.extent == 0x400
    assert extent.trailing_size == len(tail)
    assert extent.trailing_sha256 == hashlib.sha256(tail).hexdigest()


def test_rc4_grammar_requires_distinct_ksa_and_prga_shapes() -> None:
    """KSAの256回初期化とPRGAのbyte XORを別々に要求する。"""

    ksa = _instructions(
        bytes.fromhex(
            "3d00010000"  # cmp eax, 0x100
            "75f9"        # jne backward
            "f7f1"        # div ecx
            "25ff000000"  # and eax, 0xff
            "81fa00010000"  # cmp edx, 0x100
            "75ed"        # jne backward
        )
    )
    prga = _instructions(
        bytes.fromhex(
            "25ff000000"  # and eax, 0xff
            "81e1ff000000"  # and ecx, 0xff
            "81e2ff000000"  # and edx, 0xff
            "3306"        # xor eax, [rsi]
            "8807"        # mov [rdi], al
            "75e6"        # jne backward
        )
    )

    assert route._is_rc4_ksa(ksa) is True
    assert route._is_rc4_prga(prga) is True
    assert route._is_rc4_ksa(prga) is False
    assert route._is_rc4_prga(ksa) is False


def test_full_chain_public_observation_omits_secrets_and_payloads(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """全段成功時も公開観測へkey、password、raw config、payloadを出さない。"""

    xor_secret = b"synthetic-xor-secret"
    archive_secret = b"synthetic-password"
    config_secret = "198.51.100.77:4242"
    xor_child = _minimal_pe()
    terminal = _minimal_pe()
    xor_stage = route._DecodedStage(
        controller=b"loader-a",
        source=xor_secret,
        decoded=xor_child,
        extent=route._PeExtent(len(xor_child), 0),
        proof="synthetic-xor-proof",
    )
    archive_stage = route._ArchiveStage(
        controller=xor_child,
        archive=archive_secret,
        members=(("sidecar.bin", b"encrypted-sidecar", 0x12345678),),
        proof="synthetic-archive-proof",
    )
    rc4_stage = route._DecodedStage(
        controller=b"loader-b",
        source=b"encrypted-sidecar",
        decoded=terminal,
        extent=route._PeExtent(len(terminal), 0),
        proof="synthetic-rc4-proof",
    )
    monkeypatch.setattr(route, "_recover_xor_stage", lambda _components: xor_stage)
    monkeypatch.setattr(
        route,
        "_recover_archive_stage",
        lambda _controller, _components: archive_stage,
    )
    monkeypatch.setattr(route, "_recover_rc4_stage", lambda _members: rc4_stage)
    monkeypatch.setattr(
        route,
        "_terminal_proof",
        lambda _data: {
            "family": "valleyrat",
            "variant": "vvas_reversed_config_terminal",
            "endpoint_count": 1,
            "config_to_connect_send_receive": True,
            "terminal_family_confirmed": True,
            "raw_config_included": False,
            "raw_network_values_included": False,
        },
    )

    result = route.analyze_nsis_rc4_sidecar_bundle({"input.bin": b"safe"})

    assert result is not None
    assert result.terminal_component == terminal
    serialized = json.dumps(result.observation, sort_keys=True)
    assert xor_secret.decode() not in serialized
    assert archive_secret.decode() not in serialized
    assert config_secret not in serialized
    assert "encrypted-sidecar" not in serialized
    assert result.observation["raw_key_included"] is False
    assert result.observation["raw_password_included"] is False
    assert result.observation["raw_config_included"] is False
    assert result.observation["raw_payload_included"] is False


def test_full_chain_rejects_missing_rc4_stage(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """途中段が一意に証明できない場合はcandidateへも昇格しない。"""

    child = _minimal_pe()
    monkeypatch.setattr(
        route,
        "_recover_xor_stage",
        lambda _components: route._DecodedStage(
            controller=b"loader",
            source=b"ciphertext",
            decoded=child,
            extent=route._PeExtent(len(child), 0),
            proof="synthetic-proof",
        ),
    )
    monkeypatch.setattr(
        route,
        "_recover_archive_stage",
        lambda _controller, _components: route._ArchiveStage(
            controller=child,
            archive=b"archive",
            members=(("member.bin", b"member", 0),),
            proof="synthetic-proof",
        ),
    )
    monkeypatch.setattr(route, "_recover_rc4_stage", lambda _members: None)

    assert route.analyze_nsis_rc4_sidecar_bundle({"input.bin": b"safe"}) is None


def test_xor_decode_attempt_limit_is_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """XOR候補上限後の部分成功を採用せず、復号自体も開始しない。"""

    filename = route._StringRecord("payload.bin", "utf-16le", 0x1000)
    key = route._StringRecord("fixture-key", "ascii", 0x2000)
    view = SimpleNamespace(
        strings=(filename, key),
        image_base=0,
        instructions=(),
        references=(),
    )
    monkeypatch.setattr(
        route,
        "_load_pe_view",
        lambda data: view if data == b"loader" else None,
    )
    monkeypatch.setattr(
        route,
        "_refs_by_target",
        lambda _view: {filename.address: (0x3000,), key.address: (0x3010,)},
    )
    monkeypatch.setattr(route, "_xor_loader_grammar", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(route, "MAXIMUM_XOR_DECODE_ATTEMPTS", 0)
    monkeypatch.setattr(
        route,
        "_repeating_xor",
        lambda *_args: pytest.fail("上限到達後にXORしてはならない"),
    )

    assert route._recover_xor_stage(
        {"loader.exe": b"loader", "payload.bin": b"ciphertext"}
    ) is None


def test_archive_password_attempt_limit_is_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """password候補上限後にarchive memberを展開しない。"""

    archive = route._StringRecord("bundle.zip", "ascii", 0x1000)
    password = route._StringRecord("fixture-password", "ascii", 0x2000)
    view = SimpleNamespace(strings=(archive, password))
    monkeypatch.setattr(route, "_load_pe_view", lambda _data: view)
    monkeypatch.setattr(
        route,
        "_refs_by_target",
        lambda _view: {archive.address: (0x3000,), password.address: (0x3010,)},
    )
    monkeypatch.setattr(route, "MAXIMUM_ARCHIVE_PASSWORD_ATTEMPTS", 0)
    monkeypatch.setattr(route, "_zip_declared_uncompressed_size", lambda _data: 1)
    monkeypatch.setattr(
        route,
        "_safe_zip_members",
        lambda *_args: pytest.fail("上限到達後にarchiveを展開してはならない"),
    )

    assert route._recover_archive_stage(
        b"controller", {"bundle.zip": b"PK-fixture"}
    ) is None


def test_rc4_reference_attempt_limit_is_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """RC4参照探索上限後にsidecarを復号しない。"""

    source = route._StringRecord("sidecar.dat", "ascii", 0x1000)
    key = route._StringRecord("fixture-key", "ascii", 0x2000)
    view = SimpleNamespace(
        strings=(source, key),
        instructions=(),
        references=(),
    )
    monkeypatch.setattr(
        route,
        "_load_pe_view",
        lambda data: view if data == b"loader" else None,
    )
    monkeypatch.setattr(
        route,
        "_refs_by_target",
        lambda _view: {source.address: (0x3000,), key.address: (0x3010,)},
    )
    monkeypatch.setattr(route, "MAXIMUM_RC4_REFERENCE_ATTEMPTS", 0)
    monkeypatch.setattr(
        route,
        "_rc4",
        lambda *_args: pytest.fail("上限到達後にRC4復号してはならない"),
    )

    assert route._recover_rc4_stage(
        (("loader.dll", b"loader", 0), ("sidecar.dat", b"ciphertext", 0))
    ) is None


def test_pe_view_count_is_lazy_and_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """多数のPE viewを同時保持せず、view上限超過時に探索を停止する。"""

    view = SimpleNamespace(strings=(), instructions=(), references=())
    calls: list[bytes] = []

    def fake_load(data: bytes) -> SimpleNamespace:
        calls.append(data)
        return view

    monkeypatch.setattr(route, "_load_pe_view", fake_load)
    monkeypatch.setattr(route, "MAXIMUM_PE_VIEW_COUNT", 1)

    assert route._recover_xor_stage({"one.exe": b"one", "two.exe": b"two"}) is None
    assert calls == [b"one", b"two"]


def test_archive_declared_size_consumes_transform_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """圧縮後sizeでなく宣言展開sizeをpassword試行予算へ計上する。"""

    archive = route._StringRecord("bundle.zip", "ascii", 0x1000)
    password = route._StringRecord("fixture-password", "ascii", 0x2000)
    view = SimpleNamespace(strings=(archive, password))
    monkeypatch.setattr(route, "_load_pe_view", lambda _data: view)
    monkeypatch.setattr(
        route,
        "_refs_by_target",
        lambda _view: {archive.address: (0x3000,), password.address: (0x3010,)},
    )
    monkeypatch.setattr(
        route,
        "_zip_declared_uncompressed_size",
        lambda _data: route.MAXIMUM_STAGE_TRANSFORM_BYTES + 1,
    )
    monkeypatch.setattr(
        route,
        "_safe_zip_members",
        lambda *_args: pytest.fail("展開予算超過後にarchiveを展開してはならない"),
    )

    assert route._recover_archive_stage(
        b"controller", {"bundle.zip": b"PK-small-compressed-input"}
    ) is None


def test_archive_candidate_count_is_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """同名archive参照の直積をlist化し続けず、専用上限で停止する。"""

    first = route._StringRecord("bundle.zip", "ascii", 0x1000)
    second = route._StringRecord("bundle.zip", "utf-16le", 0x2000)
    view = SimpleNamespace(strings=(first, second))
    monkeypatch.setattr(route, "_load_pe_view", lambda _data: view)
    monkeypatch.setattr(
        route,
        "_refs_by_target",
        lambda _view: {first.address: (0x3000,), second.address: (0x3010,)},
    )
    monkeypatch.setattr(route, "MAXIMUM_ARCHIVE_CANDIDATES", 1)

    assert route._recover_archive_stage(
        b"controller", {"bundle.zip": b"PK-fixture"}
    ) is None
