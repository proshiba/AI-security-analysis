"""宣言型変換の設定・共有予算・構造検証を合成入力だけで確認する。"""

from __future__ import annotations

import json
import io
import os
from pathlib import Path
import struct
import zipfile

import pytest

from unpackers import profiled_transform as transforms


def _profile(identifier: str = "fixture") -> dict:
    return {
        "id": identifier,
        "artifact_kind": "fixture-output",
        "operations": [{"operation": "reverse"}],
        "validator": {"type": "magic", "magic_hex": b"MAGIC".hex()},
    }


def _document(path: Path, profiles: list[dict]) -> Path:
    path.write_text(json.dumps({"schema_version": 1, "profiles": profiles}), encoding="utf-8")
    return path


@pytest.mark.parametrize("raw", [
    '{"schema_version":1,"schema_version":1,"profiles":[]}',
    '{"schema_version":true,"profiles":[]}',
    '{"schema_version":1,"profiles":[],"unknown":0}',
    '{"schema_version":1,"profiles":[],"value":NaN}',
    '{"schema_version":1,"profiles":[],"value":Infinity}',
    '{"schema_version":1,"profiles":[{"id":"x","id":"y"}]}',
    '[',
])
def test_profile_document_rejects_ambiguous_json(tmp_path: Path, raw: str) -> None:
    """重複key・真偽値schema・非有限値は有効な設定へ変換しない。"""

    path = tmp_path / "profiles.json"
    path.write_text(raw, encoding="utf-8")
    with pytest.raises(transforms.TransformProfileError):
        transforms.load_profiles(path)


def test_content_not_mtime_and_size_is_the_cache_key(tmp_path: Path) -> None:
    """同size・mtimeの内容変更でも旧設定を再利用しない。"""

    path = _document(tmp_path / "profiles.json", [_profile("first")])
    initial = path.stat()
    assert transforms.load_profiles(path)[0]["id"] == "first"
    _document(path, [_profile("other")])
    os.utime(path, ns=(initial.st_atime_ns, initial.st_mtime_ns))
    assert path.stat().st_size == initial.st_size
    assert transforms.load_profiles(path)[0]["id"] == "other"


def test_returned_profile_mutation_does_not_poison_cache(tmp_path: Path) -> None:
    """呼出し元の設定dict変更を他の検体へ持ち越さない。"""

    path = _document(tmp_path / "profiles.json", [_profile()])
    loaded = transforms.load_profiles(path)
    loaded[0]["operations"][0]["operation"] = "unknown"
    loaded[0]["validator"]["magic"] = b"wrong"
    assert transforms.load_profiles(path)[0]["operations"][0]["operation"] == "reverse"
    assert transforms.load_profiles(path)[0]["validator"]["magic"] == b"MAGIC"


def test_oversized_document_is_rejected_before_open(tmp_path: Path, monkeypatch) -> None:
    """容量上限は設定本文の読込前に確認する。"""

    path = _document(tmp_path / "profiles.json", [_profile()])
    monkeypatch.setattr(transforms, "MAX_PROFILE_DOCUMENT_SIZE", 8)
    monkeypatch.setattr(Path, "open", lambda *_args, **_kwargs: pytest.fail("本文を読んではいけない"))
    with pytest.raises(transforms.TransformProfileError):
        transforms.load_profiles(path)


def test_hardlinked_profile_is_rejected(tmp_path: Path) -> None:
    """設定fileの別名hardlinkを通常fileと同一視しない。"""

    path = _document(tmp_path / "profiles.json", [_profile()])
    alias = tmp_path / "alias.json"
    try:
        os.link(path, alias)
    except OSError:
        pytest.skip("このfilesystemはhardlinkを提供しない")
    with pytest.raises(transforms.TransformProfileError):
        transforms.load_profiles(path)


@pytest.mark.parametrize("change", [
    {"unknown": "not-allowed"},
    {"description": ["not-text"]},
    {"description": "bad\ncontrol"},
    {"input_formats": ["data", "data"]},
    {"input_formats": [[]]},
    {"name_suffixes": [".dat", ".DAT"]},
    {"name_suffixes": ["../bad"]},
    {"operations": [{"operation": "reverse", "unknown": 1}]},
    {"operations": [{"operation": "xor_byte", "key": True}]},
    {"operations": [{"operation": "xor_repeating", "key_hex": "00 01"}]},
    {"validator": {"type": "magic", "magic_hex": "4d 5a"}},
    {"validator": {"type": "donut_shellcode", "strides": [1, 1]}},
    {"validator": {"type": "donut_shellcode", "strides": list(range(1, 18))}},
    {"validator": {"type": "pe", "ignored": 1}},
])
def test_profile_schema_is_strict(change: dict) -> None:
    value = _profile()
    value.update(change)
    with pytest.raises(transforms.TransformProfileError):
        transforms.validate_profile(value)


@pytest.mark.parametrize("operations", [
    [],
    [{"operation": "reverse"}] * 17,
    [{"operation": "xor_byte", "key": -1}],
    [{"operation": "xor_byte", "key": "1"}],
    [{"operation": "xor_repeating", "key": b""}],
    [{"operation": "xor_repeating", "key": bytearray(b"a")}],
    [{"operation": "rotate_left", "amount": True}],
    [{"operation": "slice", "offset": -1, "length": 1}],
    [{"operation": "reverse", "extra": 0}],
])
def test_direct_operation_api_cannot_bypass_validation(operations) -> None:
    with pytest.raises(transforms.TransformProfileError):
        transforms.apply_operations(b"abcd", operations)


def test_multiple_profiles_share_work_budget_and_preserve_valid_candidate(tmp_path: Path) -> None:
    """先に検証した候補を残し、後続の未評価をpartialへ分離する。"""

    encoded = b"MAGIC-content"[::-1]
    path = _document(tmp_path / "profiles.json", [_profile("first"), _profile("second"), _profile("third")])
    report, artifacts = transforms.recover_profiled_transforms(encoded, input_format="data", profiles_path=path, max_work_bytes=len(encoded))
    assert artifacts == [("fixture-output", b"MAGIC-content")]
    assert report["status"] == "partial_shared_budget_limit"
    assert report["profile_evaluation_complete"] is False
    assert report["budget"]["operation_input_bytes"] == len(encoded)
    assert report["budget"]["retained_artifact_bytes"] == len(encoded)
    assert [item["status"] for item in report["attempts"]] == ["validated_artifact_recovered", "shared_budget_limit", "skipped_shared_budget_limit"]


def test_retention_budget_rejects_candidate_without_success(tmp_path: Path) -> None:
    path = _document(tmp_path / "profiles.json", [_profile()])
    report, artifacts = transforms.recover_profiled_transforms(b"MAGIC-content"[::-1], input_format="data", profiles_path=path, max_artifact_bytes=4)
    assert artifacts == []
    assert report["status"] == "partial_shared_budget_limit"
    assert report["limit_reasons"] == ["retained_artifact_bytes_limit"]
    assert report["budget"]["retained_artifact_bytes"] == 0


def test_operation_time_limit_has_explicit_partial_status(tmp_path: Path, monkeypatch) -> None:
    path = _document(tmp_path / "profiles.json", [_profile()])
    times = iter([0.0, 1.0])
    monkeypatch.setattr(transforms.time, "monotonic", lambda: next(times))
    report, artifacts = transforms.recover_profiled_transforms(b"abc", input_format="data", profiles_path=path, max_elapsed_seconds=0.5)
    assert artifacts == []
    assert report["status"] == "partial_shared_budget_limit"
    assert report["limit_reasons"] == ["elapsed_time_limit"]
    assert report["budget"]["operation_input_bytes"] == 0


@pytest.mark.parametrize("seconds", [float("nan"), float("inf"), float("-inf"), 0, True, 11])
def test_invalid_deadline_is_rejected(tmp_path: Path, seconds) -> None:
    path = _document(tmp_path / "profiles.json", [_profile()])
    with pytest.raises(transforms.TransformProfileError):
        transforms.recover_profiled_transforms(b"abc", input_format="data", profiles_path=path, max_elapsed_seconds=seconds)


def test_input_specific_transform_rejection_does_not_abort_other_profiles(tmp_path: Path) -> None:
    first = _profile("empty_slice")
    first["operations"] = [{"operation": "slice", "offset": 100}]
    path = _document(tmp_path / "profiles.json", [first, _profile("valid")])
    report, artifacts = transforms.recover_profiled_transforms(b"MAGIC-content"[::-1], input_format="data", profiles_path=path)
    assert artifacts == [("fixture-output", b"MAGIC-content")]
    assert report["profile_evaluation_complete"] is True
    assert report["attempts"][0]["status"] == "transform_rejected"


def _pe_fixture() -> bytes:
    """headerと通常sectionだけの無害なPE外形を作る。"""

    data = bytearray(0x400)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", data, 0x84, 0x14C, 1, 0, 0, 0, 0xE0, 0x102)
    struct.pack_into("<H", data, 0x98, 0x10B)
    struct.pack_into("<I", data, 0x98 + 28, 0x400000)
    struct.pack_into("<II", data, 0x98 + 32, 0x1000, 0x200)
    struct.pack_into("<II", data, 0x98 + 56, 0x2000, 0x200)
    struct.pack_into("<I", data, 0x98 + 92, 16)
    data[0x178:0x180] = b".text\0\0\0"
    struct.pack_into("<IIII", data, 0x180, 0x200, 0x1000, 0x200, 0x200)
    struct.pack_into("<I", data, 0x178 + 36, 0x60000020)
    return bytes(data)


def test_pe_validator_checks_declared_file_backed_extent() -> None:
    """PE parserがheaderを読めてもsectionの実file外参照は拒否する。"""

    data = _pe_fixture()
    assert transforms.validate_output(data, {"type": "pe"})[0] is True
    truncated = data[:0x300]
    matched, evidence = transforms.validate_output(truncated, {"type": "pe"})
    assert matched is False
    assert evidence["parse_status"] == "structural_bounds_rejected"
    assert evidence["reason"] == "candidate_extent_out_of_bounds"


def test_shared_budget_limit_propagates_into_one_shot_incomplete_issue(tmp_path: Path, monkeypatch) -> None:
    """部分復元をone-shotの静的復元完了へ誤昇格させない。"""

    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[2] / "analysis-framework"))
    from common.analyze_sample import _static_layer_issues

    path = _document(tmp_path / "profiles.json", [_profile()])
    report, _ = transforms.recover_profiled_transforms(b"abc", input_format="data", profiles_path=path, max_work_bytes=1)
    issues = _static_layer_issues({"steps": [{"report": {"profiled_transforms": report}}]})
    assert any("partial_shared_budget_limit" in item or "shared_budget_limit" in item for item in issues)


@pytest.mark.parametrize("input_format", ["elf", "pdf", "java-class", "apple-disk-image", "autoit-a3x", "ole", "macho"])
def test_all_static_detector_formats_can_be_matched_by_profile(tmp_path: Path, input_format: str) -> None:
    """既存detectorのcanonical形式をprofile設定でも拒否しない。"""

    profile = _profile()
    profile["input_formats"] = [input_format]
    path = _document(tmp_path / "profiles.json", [profile])
    report, artifacts = transforms.recover_profiled_transforms(b"MAGIC-content"[::-1], input_format=input_format, profiles_path=path)
    assert report["profile_evaluation_complete"] is True
    assert len(artifacts) == 1


def _zip_fixture(*, descriptor: bool = False) -> bytes:
    """通常ZIPまたはdata descriptor付きの無害なZIPを合成する。"""

    class NonSeekable(io.BytesIO):
        def seekable(self) -> bool:
            return False

        def seek(self, *_args):
            raise io.UnsupportedOperation("合成descriptor用stream")

    stream = NonSeekable() if descriptor else io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("fixture.txt", b"ordinary fixture data")
    return stream.getvalue()


@pytest.mark.parametrize("descriptor", [False, True])
def test_zip_validator_checks_headers_without_reading_content(monkeypatch, descriptor: bool) -> None:
    data = _zip_fixture(descriptor=descriptor)
    monkeypatch.setattr(zipfile, "ZipFile", lambda *_args, **_kwargs: pytest.fail("ZIP parserや本文読込は使用しない"))
    matched, evidence = transforms.validate_output(data, {"type": "zip"})
    assert matched is True
    assert evidence["member_count"] == 1
    assert evidence["member_content_read"] is False
    assert evidence["content_crc_verified"] is False


@pytest.mark.parametrize("corruption", ["count", "offset", "local_size", "name", "over_limit", "zip64", "central_magic", "trailing"])
def test_zip_validator_rejects_inconsistent_declared_structure(corruption: str) -> None:
    data = bytearray(_zip_fixture())
    central = data.index(b"PK\x01\x02")
    eocd = data.index(b"PK\x05\x06")
    if corruption == "count":
        struct.pack_into("<HH", data, eocd + 8, 2, 2)
    elif corruption == "offset":
        struct.pack_into("<I", data, central + 42, central)
    elif corruption == "local_size":
        struct.pack_into("<I", data, 18, 0)
    elif corruption == "name":
        data[30] ^= 1
    elif corruption == "over_limit":
        struct.pack_into("<HH", data, eocd + 8, 4097, 4097)
    elif corruption == "zip64":
        struct.pack_into("<I", data, eocd + 12, 0xFFFFFFFF)
    elif corruption == "central_magic":
        data[central] = 0
    else:
        data.extend(b"undeclared trailing data")
    matched, evidence = transforms.validate_output(bytes(data), {"type": "zip"})
    assert matched is False
    assert evidence["parse_status"] == "structural_bounds_rejected"


def test_static_unpacker_passes_smaller_parent_retention_budget(monkeypatch) -> None:
    """宣言型変換の保持量をcallerの総容量上限以下へ制限する。"""

    from unpackers import static_unpacker

    captured = {}

    def recover(_data, **kwargs):
        captured.update(kwargs)
        return {"attempts": [], "status": "no_profile_recovered_artifact"}, []

    monkeypatch.setattr(static_unpacker, "recover_profiled_transforms", recover)
    static_unpacker.unpack_bytes(b"ordinary binary fixture", max_archive_total_size=100)
    assert captured["max_artifact_bytes"] == 100


def test_recursive_pe_summary_omits_private_token_graph(monkeypatch) -> None:
    """private参照graphを再帰PE summaryへ複製しない。"""

    from unpackers import static_unpacker

    data = bytearray(_pe_fixture())
    struct.pack_into("<II", data, 0x98 + 96 + 14 * 8, 0x1100, 72)
    monkeypatch.setattr(static_unpacker, "analyze_managed_pe", lambda _data: {
        "types": [{"private": "type"}], "methods": [{"private": "method"}],
        "static_references": [{"private": "token-graph"}],
        "static_reference_count": 1,
    })
    monkeypatch.setattr(static_unpacker, "analyze_managed_protector", lambda _data: {"status": "fixture"})
    report, _artifacts = static_unpacker.pe_summary(bytes(data))
    managed = report["managed_il_triage"]
    assert managed == {"static_reference_count": 1}


@pytest.mark.parametrize("carrier_kind", ["elf", "pe"])
def test_declared_non_data_profile_reaches_automatic_static_route(monkeypatch, carrier_kind: str) -> None:
    """通常pipelineでdata以外のレビュー済み宣言を子layerへ接続する。"""

    from unpackers import static_unpacker

    prefix = b"\x7fELF" + bytes(12) if carrier_kind == "elf" else _pe_fixture()
    child = _pe_fixture()
    profile = {
        "id": "fixture-carrier-slice", "artifact_kind": "fixture-static-pe",
        "input_formats": [carrier_kind],
        "operations": [{"operation": "slice", "offset": len(prefix)}, {"operation": "xor_byte", "key": 0x5A}],
        "validator": {"type": "pe"},
    }
    monkeypatch.setattr(transforms, "load_profiles", lambda _path: (transforms.validate_profile(profile),))
    encoded_child = bytes(byte ^ 0x5A for byte in child)
    report, artifacts = static_unpacker.unpack_bytes(prefix + encoded_child, "fixture." + carrier_kind)
    assert ("fixture-static-pe", child) in artifacts
    assert report["profiled_transforms"]["status"] == "validated_artifacts_recovered"
    assert report["executed"] is False and report["network_contacted"] is False


def test_non_matching_declared_format_is_not_recovered_from_other_carrier(monkeypatch) -> None:
    """対象形式が違う宣言を全入力へ拡張しない。"""

    from unpackers import static_unpacker

    profile = _profile()
    profile["input_formats"] = ["pe"]
    monkeypatch.setattr(transforms, "load_profiles", lambda _path: (transforms.validate_profile(profile),))
    report, artifacts = static_unpacker.unpack_bytes(b"MAGIC-content"[::-1], "fixture.dat")
    assert artifacts == []
    assert report["profiled_transforms"]["attempts"][0]["status"] == "skipped_input_format"


@pytest.mark.parametrize("entry", ["single", "multiple"])
def test_validator_elapsed_time_is_not_reported_as_complete(monkeypatch, entry: str) -> None:
    """validator終了後に期限へ達した結果を成功mapや成果物へ出さない。"""

    clock = [0.0]
    monkeypatch.setattr(transforms.time, "monotonic", lambda: clock[0])
    profile = _profile()
    monkeypatch.setattr(transforms, "load_profiles", lambda _path: (transforms.validate_profile(profile),))

    def delayed_validator(_data, _validator, *, _budget):
        assert isinstance(_budget, transforms._TransformBudget)
        clock[0] = 20.0
        return True, {"type": "magic"}

    monkeypatch.setattr(transforms, "validate_output", delayed_validator)
    if entry == "single":
        report, artifacts = transforms.recover_transform_profile(b"CIGAM", profile)
    else:
        report, artifacts = transforms.recover_profiled_transforms(b"CIGAM", input_format="data")
    assert artifacts == []
    assert report["status"] == "partial_shared_budget_limit"
    assert report["profile_evaluation_complete"] is False
    assert report["limit_reasons"] == ["elapsed_time_limit"]
    assert report["budget"]["retained_artifact_bytes"] == 0


def test_single_profile_checks_time_after_report_hashing(monkeypatch) -> None:
    """hashや診断projectionの後にも、成果物を保持する前の期限を確認する。"""

    clock = [0.0]
    monkeypatch.setattr(transforms.time, "monotonic", lambda: clock[0])
    original = transforms.sha256_bytes

    def delayed_hash(data):
        clock[0] = 20.0
        return original(data)

    monkeypatch.setattr(transforms, "sha256_bytes", delayed_hash)
    report, artifacts = transforms.recover_transform_profile(b"CIGAM", _profile())
    assert artifacts == []
    assert report["limit_reasons"] == ["elapsed_time_limit"]
    assert report["budget"]["retained_artifact_bytes"] == 0


@pytest.mark.parametrize("options,reason", [
    ({"max_work_bytes": 4}, "operation_bytes_limit"),
    ({"max_artifact_bytes": 4}, "retained_artifact_bytes_limit"),
])
def test_single_profile_work_and_retention_limits_are_partial(options: dict, reason: str) -> None:
    report, artifacts = transforms.recover_transform_profile(b"CIGAM", _profile(), **options)
    assert artifacts == []
    assert report["status"] == "partial_shared_budget_limit"
    assert report["profile_evaluation_complete"] is False
    assert report["limit_reasons"] == [reason]
    assert report["budget"]["retained_artifact_bytes"] == 0
    assert report["budget"]["total_work_bytes"] <= report["budget"]["maximum_work_bytes"]


@pytest.mark.parametrize("options", [
    {"max_work_bytes": True}, {"max_work_bytes": 0},
    {"max_work_bytes": transforms.MAX_TRANSFORM_WORK_BYTES + 1},
    {"max_artifact_bytes": False}, {"max_artifact_bytes": 0},
    {"max_artifact_bytes": transforms.MAX_RETAINED_ARTIFACT_BYTES + 1},
    {"max_elapsed_seconds": True}, {"max_elapsed_seconds": float("nan")},
    {"max_elapsed_seconds": float("inf")}, {"max_elapsed_seconds": 0},
    {"max_elapsed_seconds": transforms.MAX_TRANSFORM_ELAPSED_SECONDS + 1},
    {"max_elapsed_seconds": 10**1000},
])
def test_single_profile_budget_is_down_only(options: dict) -> None:
    with pytest.raises(transforms.TransformProfileError):
        transforms.recover_transform_profile(b"CIGAM", _profile(), **options)


@pytest.mark.parametrize("operation", [
    {"operation": "xor_byte", "key": 0x5A},
    {"operation": "xor_repeating", "key_hex": "fefdfcfbfaf9f8"},
])
def test_public_operations_exclude_private_xor_values(operation: dict) -> None:
    """直接APIのJSONにも鍵本体を複製せず、既存の内部設定を保持する。"""

    profile = _profile()
    profile["operations"] = [operation]
    normalized = transforms.validate_profile(profile)
    encoded = transforms.apply_operations(b"MAGIC", normalized["operations"])
    report, artifacts = transforms.recover_transform_profile(encoded, profile)
    assert artifacts == [("fixture-output", b"MAGIC")]
    public = report["operations"][0]
    private = normalized["operations"][0]["key"]
    key_bytes = bytes([private]) if isinstance(private, int) else private
    assert "key" not in public and "key_hex" not in public
    assert public["key_size"] == len(key_bytes)
    assert public["key_sha256"] == transforms.sha256_bytes(key_bytes)
    assert public["key_published"] is False
    assert report["transform_key_values_published"] is False
    assert normalized["operations"][0]["key"] == private
    assert operation.get("key_hex", "not-present") not in json.dumps(report)


def _donut_headers(count: int, *, prefix_gap: int = 0) -> bytes:
    """複数E8宣言が同じ既知prologueを指す小さなヘッダー外形を作る。"""

    code = max(16, count * 8)
    data = bytearray(code + prefix_gap + 5)
    for index in range(count):
        offset = index * 8
        data[offset] = 0xE8
        struct.pack_into("<I", data, offset + 1, code - offset - 5)
    data[code + prefix_gap:] = b"YU\x48\x89\xe5"
    return bytes(data)


def _donut_profile() -> dict:
    profile = _profile("header-observation")
    profile["operations"] = [{"operation": "rotate_left", "amount": 0}]
    profile["validator"] = {"type": "donut_shellcode", "strides": [1]}
    return profile


def test_donut_headers_do_not_materialize_overlapping_payloads(monkeypatch) -> None:
    """同一prologueへ重なるE8宣言でcandidate本体の増幅を起こさない。"""

    from unpackers import donut_unpacker

    monkeypatch.setattr(donut_unpacker, "find_donut_shellcodes", lambda *_a, **_k: pytest.fail("body回収器を呼んではいけない"))
    monkeypatch.setattr(donut_unpacker, "is_donut_shellcode", lambda *_a, **_k: pytest.fail("body判定器を呼んではいけない"))
    class CopyBoundedBytes(bytes):
        def __getitem__(self, key):
            if isinstance(key, slice):
                start, stop, step = key.indices(len(self))
                assert len(range(start, stop, step)) <= 42, "header窓より大きい本文コピーは禁止"
            return super().__getitem__(key)

    data = CopyBoundedBytes(_donut_headers(32))
    report, artifacts = transforms.recover_transform_profile(data, _donut_profile())
    assert artifacts == [("fixture-output", data)]
    evidence = report["validation"]
    assert evidence["candidate_count"] == 32
    assert evidence["candidate_count_scope"] == "header_observation_positions_not_unique_payloads"
    assert evidence["candidate_bytes_materialized"] is False
    assert evidence["instance_decrypted"] is False
    assert evidence["runtime_code_executed"] is False
    assert evidence["scan_complete"] is True
    assert evidence["candidate_count_is_lower_bound"] is False
    assert evidence["candidate_offsets_returned"] == transforms.MAX_DONUT_HEADER_OFFSETS
    assert evidence["candidate_offsets_truncated"] is True
    assert report["budget"]["total_work_bytes"] <= 2 * len(data) + 32 * 47


@pytest.mark.parametrize("limit,reason", [
    ("MAX_DONUT_HEADER_PROBES", "donut_header_probe_limit"),
    ("MAX_DONUT_HEADER_CANDIDATES", "donut_header_candidate_limit"),
])
def test_donut_observation_limit_propagates_partial(monkeypatch, limit: str, reason: str) -> None:
    monkeypatch.setattr(transforms, limit, 2)
    data = _donut_headers(3)
    report, artifacts = transforms.recover_transform_profile(data, _donut_profile())
    assert artifacts == [("fixture-output", data)]
    assert report["status"] == "partial_shared_budget_limit"
    assert report["profile_evaluation_complete"] is False
    assert report["limit_reasons"] == [reason]
    evidence = report["validation"]
    assert evidence["candidate_count"] == 2
    assert evidence["scan_complete"] is False
    assert evidence["candidate_count_is_lower_bound"] is True
    assert evidence["limit_reasons"] == [reason]
    assert report["budget"]["retained_artifact_bytes"] == len(data)


def test_donut_probe_limit_bounds_negative_noise(monkeypatch) -> None:
    """候補なしのE8過多も陰性完了と誤認せずprobe数で打ち切る。"""

    monkeypatch.setattr(transforms, "MAX_DONUT_HEADER_PROBES", 2)
    report, artifacts = transforms.recover_transform_profile(b"\xe8\0\0\0\0" * 3, _donut_profile())
    assert artifacts == []
    assert report["limit_reasons"] == ["donut_header_probe_limit"]
    assert report["validation"]["header_probes"] == 2
    assert report["validation"]["candidate_count"] == 0
    assert report["validation"]["scan_complete"] is False


@pytest.mark.parametrize("extra_work", [0, 4, 5])
def test_donut_validator_work_is_reserved_before_probe_or_window(extra_work: int) -> None:
    data = _donut_headers(1)
    limit = 2 * len(data) + extra_work
    report, artifacts = transforms.recover_transform_profile(data, _donut_profile(), max_work_bytes=limit)
    assert artifacts == []
    assert report["limit_reasons"] == ["validator_work_bytes_limit"]
    assert report["validation"]["scan_complete"] is False
    assert report["budget"]["total_work_bytes"] <= limit
    assert report["budget"]["retained_artifact_bytes"] == 0
    assert report["budget"]["operation_input_bytes"] == len(data)


@pytest.mark.parametrize("gap,matched", [(0, True), (32, True), (33, False)])
def test_donut_known_prologue_window_is_bounded(gap: int, matched: bool) -> None:
    result, evidence = transforms.validate_output(_donut_headers(1, prefix_gap=gap), {"type": "donut_shellcode", "strides": [1]})
    assert result is matched
    assert evidence["scan_complete"] is True


def test_donut_strided_header_keeps_original_offset_without_lane_copy() -> None:
    lane = _donut_headers(1)
    sparse = bytearray(2 + len(lane) * 4)
    sparse[2::4] = lane
    matched, evidence = transforms.validate_output(bytes(sparse), {"type": "donut_shellcode", "strides": [4]})
    assert matched is True
    assert evidence["candidate_offsets"] == [2]
    assert evidence["header_probes"] == 1
    assert evidence["candidate_bytes_materialized"] is False


@pytest.mark.parametrize("data", [b"ordinary", b"\xe8", b"\xe8\0\0\0\0YU\x48\x89\xe5", b"\xe8\xff\xff\xff\xffYU\x48\x89\xe5"])
def test_donut_malformed_headers_are_complete_negative(data: bytes) -> None:
    report, artifacts = transforms.recover_transform_profile(data, _donut_profile())
    assert artifacts == []
    assert report["status"] == "validation_failed"
    assert report["profile_evaluation_complete"] is True
    assert report["validation"]["scan_complete"] is True
    assert report["validation"]["candidate_count"] == 0


def test_shared_donut_limit_keeps_prior_non_donut_candidate(monkeypatch) -> None:
    """Donut観測だけが未完了でも、先行する別候補を消去しない。"""

    data = _donut_headers(3)
    first = _profile("first")
    first["operations"] = [{"operation": "rotate_left", "amount": 0}]
    first["validator"] = {"type": "magic", "magic_hex": data[:1].hex()}
    monkeypatch.setattr(transforms, "MAX_DONUT_HEADER_CANDIDATES", 2)
    monkeypatch.setattr(transforms, "load_profiles", lambda _path: tuple(transforms.validate_profile(p) for p in [first, _donut_profile(), _profile("last")]))
    report, artifacts = transforms.recover_profiled_transforms(data, input_format="data")
    assert artifacts == [("fixture-output", data), ("fixture-output", data)]
    assert report["status"] == "partial_shared_budget_limit"
    assert report["attempts"][1]["validation"]["scan_complete"] is False
    assert report["attempts"][2]["status"] == "skipped_shared_budget_limit"
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[2] / "analysis-framework"))
    from common.analyze_sample import _static_layer_issues

    issues = _static_layer_issues({"steps": [{"report": {"profiled_transforms": report}}]})
    assert any("partial_shared_budget_limit" in issue for issue in issues)


def test_legacy_wrapper_preserves_success_shape_and_partial_status(monkeypatch) -> None:
    """従来tuple・成果物・成功名を保持し、header上限を成功へ置換しない。"""

    from unpackers.rotated_xor_donut import recover_rotated_xor_donut

    clear = _donut_headers(3)
    report, artifacts = recover_rotated_xor_donut(clear, rotation=0, xor_key=0)
    assert artifacts == [("rotated-xor-donut-shellcode", clear)]
    assert report["status"] == "donut_shellcode_recovered"
    assert report["candidate_count"] == 3
    assert report["candidate_offsets"] == [0, 8, 16]
    monkeypatch.setattr(transforms, "MAX_DONUT_HEADER_CANDIDATES", 2)
    report, artifacts = recover_rotated_xor_donut(clear, rotation=0, xor_key=0)
    assert artifacts == [("rotated-xor-donut-shellcode", clear)]
    assert report["status"] == "partial_shared_budget_limit"


def _donut_header_with_invalid_e8_inventory() -> bytes:
    """先頭に検証済みspanを置き、instance内へ無効E8を多数配置する。"""

    instance = b"\xe8\0\0\0\0" * 8
    return b"\xe8" + struct.pack("<I", len(instance)) + instance + b"YU\x48\x89\xe5"


def test_valid_span_survives_only_inventory_probe_limit(monkeypatch) -> None:
    """検証済み先頭spanとinstance内のnoise件数を混同しない。"""

    data = _donut_header_with_invalid_e8_inventory()
    normal, normal_artifacts = transforms.recover_transform_profile(data, _donut_profile())
    assert normal["profile_evaluation_complete"] is True
    assert normal["validation"]["candidate_count"] == 1
    assert normal["validation"]["header_probes"] == 9
    assert normal_artifacts == [("fixture-output", data)]
    monkeypatch.setattr(transforms, "MAX_DONUT_HEADER_PROBES", 3)
    partial, artifacts = transforms.recover_transform_profile(data, _donut_profile())
    assert artifacts == [("fixture-output", data)]
    assert partial["status"] == "partial_shared_budget_limit"
    assert partial["profile_evaluation_complete"] is False
    assert partial["validation"]["candidate_count"] == 1
    assert partial["validation"]["header_probes"] == 3
    assert partial["validation"]["candidate_count_is_lower_bound"] is True
    assert partial["validation"]["scan_complete"] is False


@pytest.mark.parametrize("hard_limit", ["work", "time", "retention"])
def test_inventory_partial_never_overrides_hard_budget(monkeypatch, hard_limit: str) -> None:
    """観測済みheaderがあっても硬い予算を超えた成果物は返さない。"""

    data = _donut_header_with_invalid_e8_inventory()
    monkeypatch.setattr(transforms, "MAX_DONUT_HEADER_PROBES", 3)
    clock = [0.0]
    monkeypatch.setattr(transforms.time, "monotonic", lambda: clock[0])
    options = {}
    if hard_limit == "work":
        # 先頭候補の窓まで予約した後、最初のnoise probeで上限へ達する。
        options["max_work_bytes"] = 2 * len(data) + 10
        reason = "validator_work_bytes_limit"
    elif hard_limit == "retention":
        options["max_artifact_bytes"] = len(data) - 1
        reason = "retained_artifact_bytes_limit"
    else:
        original = transforms.validate_output

        def delayed_validation(*args, **kwargs):
            result = original(*args, **kwargs)
            clock[0] = 20.0
            return result

        monkeypatch.setattr(transforms, "validate_output", delayed_validation)
        reason = "elapsed_time_limit"
    report, artifacts = transforms.recover_transform_profile(data, _donut_profile(), **options)
    assert artifacts == []
    assert report["status"] == "partial_shared_budget_limit"
    assert report["limit_reasons"] == [reason]
    assert report["budget"]["retained_artifact_bytes"] == 0
    if hard_limit == "work":
        assert report["validation"]["candidate_count"] == 1
        assert report["validation"]["limit_reasons"] == [reason]


def test_inventory_stop_checks_deadline_before_partial_return(monkeypatch) -> None:
    """probe数と時間の上限が同時に成立しても硬い期限を優先する。"""

    clock = [0.0]
    monkeypatch.setattr(transforms.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(transforms, "MAX_DONUT_HEADER_PROBES", 1)

    class DeadlineBytes(bytes):
        def find(self, value, start=0, end=None):
            result = super().find(value, start) if end is None else super().find(value, start, end)
            if start > 0:
                clock[0] = 20.0
            return result

    data = DeadlineBytes(_donut_header_with_invalid_e8_inventory())
    report, artifacts = transforms.recover_transform_profile(data, _donut_profile())
    assert artifacts == []
    assert report["limit_reasons"] == ["elapsed_time_limit"]
    assert report["validation"]["candidate_count"] == 1
    assert report["validation"]["scan_complete"] is False
    assert report["validation"]["limit_reasons"] == ["elapsed_time_limit"]
