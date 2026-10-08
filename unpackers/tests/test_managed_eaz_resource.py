"""flattened managed Eaz resource復元器の合成fixture回帰テスト。"""

from __future__ import annotations

import importlib
import json
import struct
import time
import zlib
from pathlib import Path
from types import SimpleNamespace

import pytest

from unpackers import managed_eaz_resource as recovery

decrypt_keyed_eaz_resource = importlib.import_module(
    "malware.purehvnc.managed_resource_recovery"
).decrypt_keyed_eaz_resource


def _recipe() -> recovery.ResolverRecipe:
    return recovery.ResolverRecipe(
        method_token=0x060000F9,
        switch_targets=396,
        traced_states=51,
        helper_tokens=(0x0600010C, 0x0600010D),
        key=bytes(range(32)),
        key_local=1,
        key_alias=2,
        key_store_count=40,
        mask=bytes(range(16)),
        mask_local=3,
        mask_alias=4,
        mask_store_count=23,
        seed=1_488_532_303,
        addend=529_272_713,
        transform_core_offset=100,
        transform_core_end_offset=241,
        partial_word_profile=True,
    )


def _raw_deflate(data: bytes) -> bytes:
    encoder = zlib.compressobj(level=9, wbits=-zlib.MAX_WBITS)
    return encoder.compress(data) + encoder.flush()


def _fixture_with_remainder(remainder: int) -> tuple[bytes, bytes]:
    for length in range(32, 1_024):
        clear = bytes((index * 37 + length) & 0xFF for index in range(length))
        compressed = _raw_deflate(clear)
        if len(compressed) % 4 == remainder:
            return clear, compressed
    raise AssertionError("指定したpartial-word長のfixtureを作れません")


def _encrypt(compressed: bytes, recipe: recovery.ResolverRecipe) -> bytes:
    return decrypt_keyed_eaz_resource(
        compressed,
        recipe.key,
        key_mask=recipe.mask,
        seed=recipe.seed,
        addend=recipe.addend,
        allow_partial_word=True,
    )


@pytest.mark.parametrize("remainder", [0, 1, 2, 3])
def test_recover_model_handles_every_partial_word_length(remainder: int) -> None:
    recipe = _recipe()
    clear, compressed = _fixture_with_remainder(remainder)
    encrypted = _encrypt(compressed, recipe)

    report, artifacts = recovery.recover_model(
        recipe,
        [("protected.resource", encrypted)],
        validator=lambda candidate: candidate == clear,
    )

    assert report["status"] == "recovered_managed_resource"
    assert report["resource"]["partial_word_bytes"] == remainder
    assert report["family_attribution_allowed"] is False
    assert report["terminal_config_markers_confirmed"] is False
    assert artifacts == [("managed-eaz-resource-pe", clear)]
    serialized = json.dumps(report, sort_keys=True)
    assert recipe.key.hex() not in serialized
    assert recipe.mask.hex() not in serialized


def test_recover_model_requires_exactly_one_valid_resource() -> None:
    recipe = _recipe()
    clear, compressed = _fixture_with_remainder(3)
    encrypted = _encrypt(compressed, recipe)

    ambiguous, artifacts = recovery.recover_model(
        recipe,
        [("first", encrypted), ("second", encrypted)],
        validator=lambda candidate: candidate == clear,
    )
    assert ambiguous["status"] == "rejected"
    assert ambiguous["reason"] == "decoded_candidate_ambiguous"
    assert artifacts == []

    missing, artifacts = recovery.recover_model(
        recipe,
        [("invalid", b"not raw deflate")],
        validator=lambda _candidate: True,
    )
    assert missing["status"] == "rejected"
    assert missing["reason"] == "decoded_candidate_missing"
    assert artifacts == []


def test_recover_model_stops_after_second_valid_candidate() -> None:
    """曖昧確定後に追加resourceを展開せず、大容量出力の累積保持を防ぐ。"""

    recipe = _recipe()
    clear, compressed = _fixture_with_remainder(2)
    encrypted = _encrypt(compressed, recipe)

    def resources():
        yield "first", encrypted
        yield "second", encrypted
        raise AssertionError("ambiguous result must stop before a third resource")

    report, artifacts = recovery.recover_model(
        recipe,
        resources(),
        validator=lambda candidate: candidate == clear,
    )

    assert report["reason"] == "decoded_candidate_ambiguous"
    assert report["decoded_candidates"] == 2
    assert report["resource_attempts"] == 2
    assert artifacts == []


def test_raw_deflate_rejects_trailing_data_and_ratio_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stream = _raw_deflate(b"bounded output")
    deadline = time.monotonic() + 1
    with pytest.raises(recovery.RecoveryError, match="trailing"):
        recovery._inflate_raw_deflate(
            stream + b"trailing", deadline=deadline, clock=time.monotonic
        )

    compressed = _raw_deflate(b"A" * 10_000)
    monkeypatch.setattr(recovery, "MAX_DEFLATE_RATIO", 2.0)
    with pytest.raises(recovery.RecoveryError, match="ratio"):
        recovery._inflate_raw_deflate(
            compressed,
            deadline=time.monotonic() + 1,
            clock=time.monotonic,
        )


def test_raw_deflate_honors_elapsed_limit() -> None:
    with pytest.raises(recovery.RecoveryError, match="elapsed"):
        recovery._inflate_raw_deflate(
            _raw_deflate(b"data"), deadline=0.0, clock=lambda: 1.0
        )


def test_public_entry_is_fail_closed_for_non_managed_input() -> None:
    not_bytes, artifacts = recovery.recover_managed_eaz_resource("MZ")  # type: ignore[arg-type]
    assert not_bytes == {"status": "rejected", "reason": "input_not_bytes"}
    assert artifacts == []

    ordinary, artifacts = recovery.recover_managed_eaz_resource(b"not a PE")
    assert ordinary == {"status": "not_applicable", "reason": "not_managed_pe"}
    assert artifacts == []


def test_public_entry_contains_parser_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(recovery, "has_clr_metadata", lambda _data: True)

    def fail_parse(*, data: bytes, clr_lazy_load: bool) -> None:
        assert data == b"managed-shaped"
        assert clr_lazy_load is False
        raise RuntimeError("parser detail must not escape")

    monkeypatch.setattr(recovery.dnfile, "dnPE", fail_parse)
    report, artifacts = recovery.recover_managed_eaz_resource(b"managed-shaped")
    assert report["status"] == "rejected"
    assert report["reason"] == "static_analysis_failed"
    assert report["error_type"] == "RuntimeError"
    assert "parser detail" not in json.dumps(report)
    assert artifacts == []


def test_elapsed_limit_rejects_bool() -> None:
    report, artifacts = recovery.recover_managed_eaz_resource(
        b"not a PE", max_elapsed_seconds=True
    )
    assert report == {"status": "rejected", "reason": "elapsed_limit_invalid"}
    assert artifacts == []
    with pytest.raises(recovery.RecoveryError, match="elapsed"):
        recovery.recover_model(_recipe(), [], max_elapsed_seconds=True)


class _MethodSection:
    def __init__(self, size: int) -> None:
        self.PointerToRawData = 0
        self.SizeOfRawData = size


class _MethodPe:
    def __init__(self, section_size: int) -> None:
        self.section = _MethodSection(section_size)

    @staticmethod
    def get_offset_from_rva(_rva: int) -> int:
        return 0

    def get_section_by_rva(self, _rva: int) -> _MethodSection:
        return self.section


def test_decode_method_passes_only_declared_body_to_dncil(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """後続methodや大きなsection全体をdncilへ渡さない。"""

    data = b"\x06\x2a" + b"A" * 65_536  # tiny header、1-byte ret
    observed: list[bytes] = []

    def parse_bounded(candidate: bytes) -> SimpleNamespace:
        observed.append(candidate)
        instruction = SimpleNamespace(
            offset=0,
            opcode=SimpleNamespace(name="ret"),
            operand=None,
        )
        return SimpleNamespace(code_size=1, instructions=[instruction])

    monkeypatch.setattr(recovery, "read_method_body_from_bytes", parse_bounded)
    decoded = recovery._decode_method(
        data,
        _MethodPe(len(data)),
        SimpleNamespace(Rva=1),
        0x06000001,
        deadline=time.monotonic() + 1,
        clock=time.monotonic,
    )

    assert decoded.code_size == 1
    assert observed == [b"\x06\x2a"]


def test_decode_method_rejects_declared_code_limit_before_dncil(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """巨大な宣言code sizeはparser呼出し前に拒否する。"""

    header = struct.pack("<HHII", 0x3003, 8, recovery.MAX_METHOD_BYTES + 1, 0)
    called = False

    def must_not_parse(_candidate: bytes) -> None:
        nonlocal called
        called = True
        raise AssertionError("dncil must not receive an oversized method")

    monkeypatch.setattr(recovery, "read_method_body_from_bytes", must_not_parse)
    with pytest.raises(recovery.RecoveryError, match="method_byte_limit"):
        recovery._decode_method(
            header,
            _MethodPe(len(header)),
            SimpleNamespace(Rva=1),
            0x06000001,
            deadline=time.monotonic() + 1,
            clock=time.monotonic,
        )
    assert called is False


def test_decode_method_rejects_code_outside_containing_section(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """file内でもMethodDefのPE section外へ伸びる宣言bodyは拒否する。"""

    header = struct.pack("<HHII", 0x3003, 8, 8, 0)
    data = header + b"\x00" * 20
    monkeypatch.setattr(
        recovery,
        "read_method_body_from_bytes",
        lambda _candidate: pytest.fail("section外bodyをparserへ渡してはいけない"),
    )
    with pytest.raises(recovery.RecoveryError, match="outside_section"):
        recovery._decode_method(
            data,
            _MethodPe(16),
            SimpleNamespace(Rva=1),
            0x06000001,
            deadline=time.monotonic() + 1,
            clock=time.monotonic,
        )


def test_decode_method_bounds_declared_extra_sections(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """fat methodの追加sectionも宣言終端までに限定する。"""

    header = struct.pack("<HHII", 0x300B, 8, 1, 0)
    body = header + b"\x2a" + b"\x00" * 3 + b"\x01\x04\x00\x00"
    data = body + b"Z" * 65_536
    observed: list[bytes] = []

    def parse_bounded(candidate: bytes) -> SimpleNamespace:
        observed.append(candidate)
        instruction = SimpleNamespace(
            offset=0,
            opcode=SimpleNamespace(name="ret"),
            operand=None,
        )
        return SimpleNamespace(code_size=1, instructions=[instruction])

    monkeypatch.setattr(recovery, "read_method_body_from_bytes", parse_bounded)
    recovery._decode_method(
        data,
        _MethodPe(len(data)),
        SimpleNamespace(Rva=1),
        0x06000001,
        deadline=time.monotonic() + 1,
        clock=time.monotonic,
    )

    assert observed == [body]


def test_decode_method_rejects_extra_section_work_limit_before_dncil(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """追加sectionの宣言work上限もparser呼出し前に適用する。"""

    header = struct.pack("<HHII", 0x300B, 8, 1, 0)
    data = header + b"\x2a" + b"\x00" * 3 + b"\x01\x0c\x00\x00" + b"X" * 8
    monkeypatch.setattr(recovery, "MAX_METHOD_EXTRA_SECTION_BYTES", 8)
    monkeypatch.setattr(
        recovery,
        "read_method_body_from_bytes",
        lambda _candidate: pytest.fail("上限超過sectionをparserへ渡してはいけない"),
    )

    with pytest.raises(recovery.RecoveryError, match="extra_section_byte_limit"):
        recovery._decode_method(
            data,
            _MethodPe(len(data)),
            SimpleNamespace(Rva=1),
            0x06000001,
            deadline=time.monotonic() + 1,
            clock=time.monotonic,
        )


def test_cli_output_is_exclusive(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(recovery, "_read_bounded", lambda _path: b"fixture")
    monkeypatch.setattr(
        recovery,
        "recover_managed_eaz_resource",
        lambda _data: (
            {"status": "recovered_managed_resource"},
            [("managed-eaz-resource-pe", b"recovered")],
        ),
    )
    output = tmp_path / "output.bin"
    assert recovery.main(["input.bin", "--output", str(output)]) == 0
    assert output.read_bytes() == b"recovered"
    capsys.readouterr()

    assert recovery.main(["input.bin", "--output", str(output)]) == 2
    assert output.read_bytes() == b"recovered"
    assert "RecoveryError" in capsys.readouterr().out
