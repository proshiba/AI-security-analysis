""".NET resource loaderのresource総量上限とmetadata相関を合成入力で検証する。"""

from __future__ import annotations

import hashlib
import json
import logging
from pathlib import Path
from types import SimpleNamespace
import sys

import pytest


FRAMEWORK_ROOT = Path(__file__).resolve().parents[1]
COMMON_ROOT = FRAMEWORK_ROOT / "common"
REPOSITORY_ROOT = FRAMEWORK_ROOT.parent
for trusted in (REPOSITORY_ROOT, FRAMEWORK_ROOT, COMMON_ROOT):
    value = str(trusted)
    if value not in sys.path:
        sys.path.insert(0, value)

import dotnet_resource_loader_evidence as evidence  # noqa: E402
import extract_dotnet_resources as resources  # noqa: E402
from handler_catalog import discover_handlers, load_handler  # noqa: E402


def _managed_marker_fixture() -> bytes:
    """実行不能な疑似managed PEへBitmap/reflection文字列を付加する。"""

    data = bytearray(0x200)
    data[:2] = b"MZ"
    data[0x3C:0x40] = (0x80).to_bytes(4, "little")
    data[0x80:0x84] = b"PE\0\0"
    coff = 0x84
    data[coff : coff + 2] = (0x14C).to_bytes(2, "little")
    data[coff + 16 : coff + 18] = (0xE0).to_bytes(2, "little")
    optional = 0x98
    data[optional : optional + 2] = (0x10B).to_bytes(2, "little")
    data[optional + 92 : optional + 96] = (16).to_bytes(4, "little")
    clr = optional + 96 + 14 * 8
    data[clr : clr + 4] = (0x1100).to_bytes(4, "little")
    data[clr + 4 : clr + 8] = (0x48).to_bytes(4, "little")
    return bytes(data) + (b"System.Drawing.Bitmap GetPixel GetExportedTypes InvokeMember get_R get_G get_B")


def test_resource_blobs_rejects_input_before_dnfile(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """入力byte上限超過ではdnfile parser自体を呼び出さない。"""

    monkeypatch.setattr(resources, "MAX_RESOURCE_INPUT_BYTES", 3)
    monkeypatch.setattr(
        resources.dnfile,
        "dnPE",
        lambda **_kwargs: pytest.fail("dnfileを呼んではならない"),
    )
    blobs, warnings = resources.resource_blobs(b"1234")
    assert blobs == []
    assert warnings[0].startswith(resources.BUDGET_WARNING_PREFIX)


def test_resource_blobs_contains_dnfile_diagnostics_and_restores_logger(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """ResourceSet parse中だけdnfile warningを抑止し、logger設定を復元する。"""

    logger = logging.getLogger("dnfile.synthetic-resource-test")
    handler = logging.StreamHandler()
    logger.addHandler(handler)
    logger.setLevel(logging.WARNING)
    logger.propagate = False

    def noisy_parse(**_kwargs):
        logger.warning("dnfile-resource-secret")
        return SimpleNamespace(net=None)

    monkeypatch.setattr(resources.dnfile, "dnPE", noisy_parse)
    try:
        blobs, warnings = resources.resource_blobs(b"MZ")
        assert blobs == []
        assert warnings == ["CLRヘッダーがないため.NETリソースを解析できません。"]
        assert "dnfile-resource-secret" not in capsys.readouterr().err

        logger.warning("dnfile-resource-restored")
        assert "dnfile-resource-restored" in capsys.readouterr().err
    finally:
        logger.removeHandler(handler)
        handler.close()


def test_resource_blobs_rejects_resource_and_entry_counts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """manifest resource数とResourceSet entry総数を個別に制限する。"""

    monkeypatch.setattr(resources, "MAX_RESOURCE_COUNT", 1)
    too_many_resources = SimpleNamespace(
        net=SimpleNamespace(
            resources=[
                SimpleNamespace(name="one", data=b"1"),
                SimpleNamespace(name="two", data=b"2"),
            ]
        )
    )
    monkeypatch.setattr(
        resources.dnfile,
        "dnPE",
        lambda **_kwargs: too_many_resources,
    )
    blobs, warnings = resources.resource_blobs(b"MZ")
    assert blobs == []
    assert warnings[0].startswith(resources.BUDGET_WARNING_PREFIX)

    monkeypatch.setattr(resources, "MAX_RESOURCE_COUNT", 2)
    monkeypatch.setattr(resources, "MAX_RESOURCE_ENTRY_COUNT", 1)
    entry = lambda name: SimpleNamespace(  # noqa: E731
        name=name,
        value=b"x",
        type_name="System.Stream",
    )
    too_many_entries = SimpleNamespace(
        net=SimpleNamespace(
            resources=[
                SimpleNamespace(
                    name="Synthetic.resources",
                    data=SimpleNamespace(entries=[entry("one"), entry("two")]),
                )
            ]
        )
    )
    monkeypatch.setattr(
        resources.dnfile,
        "dnPE",
        lambda **_kwargs: too_many_entries,
    )
    blobs, warnings = resources.resource_blobs(b"MZ")
    assert blobs == []
    assert warnings[0].startswith(resources.BUDGET_WARNING_PREFIX)


def test_resource_blobs_rejects_total_value_bytes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """複数resourceの合計byte数が上限を超えたら部分結果を返さない。"""

    monkeypatch.setattr(resources, "MAX_RESOURCE_TOTAL_BYTES", 5)
    image = SimpleNamespace(
        net=SimpleNamespace(
            resources=[
                SimpleNamespace(name="one", data=b"123"),
                SimpleNamespace(name="two", data=b"456"),
            ]
        )
    )
    monkeypatch.setattr(resources.dnfile, "dnPE", lambda **_kwargs: image)
    blobs, warnings = resources.resource_blobs(b"MZ")
    assert blobs == []
    assert warnings[0].startswith(resources.BUDGET_WARNING_PREFIX)


@pytest.mark.parametrize("status", ["parse_failed", "no_manifest_resources"])
def test_marker_only_pseudo_clr_is_not_strong_reflection(
    monkeypatch: pytest.MonkeyPatch,
    status: str,
) -> None:
    """疑似CLR headerと7文字列だけでは実Bitmap loaderへ昇格しない。"""

    monkeypatch.setattr(
        evidence,
        "_recover_budgeted_bitmap_pes",
        lambda _data: (
            {
                "status": status,
                "inventory": [],
                "diagnostics": ["合成resource不在"],
                "counters": {},
            },
            [],
        ),
    )
    result = evidence.bitmap_loader_evidence(_managed_marker_fixture())
    assert result["matched"] is False
    assert result["variant"] is None
    assert result["strong_reflection_correlation"] is False


def test_handler_maps_resource_budget_warning_to_parser_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """解析上限超過を非適用ではなく明示的なValueErrorとして扱う。"""

    spec = next(item for item in discover_handlers() if item.family == "dotnet_resource_loader" and item.automatic)
    handler, _invocation = load_handler(spec)
    monkeypatch.setitem(
        handler.__globals__,
        "resource_blobs",
        lambda _data: (
            [],
            [f"{resources.BUDGET_WARNING_PREFIX} 入力サイズ"],
        ),
    )
    monkeypatch.setitem(
        handler.__globals__,
        "bitmap_loader_evidence",
        lambda _data: {
            "matched": False,
            "variant": None,
            "managed_pe": {"is_managed_pe": False},
            "marker_hits": [],
            "strong_reflection_correlation": False,
            "resource_status": "not_scanned",
            "resource_diagnostics": [],
            "resource_counters": {},
            "bitmap_inventory": [],
            "recovered_children": [],
        },
    )
    with pytest.raises(ValueError):
        handler(b"MZ-budget")

def _embedded_bitmap(*, width: int = 2, height: int = 2) -> bytes:
    """埋め込み走査用の最小24-bit BI_RGBを作る。"""

    bits = 24
    stride = ((width * bits + 31) // 32) * 4
    declared_size = 54 + stride * height
    bitmap = bytearray(declared_size)
    bitmap[:2] = b"BM"
    bitmap[2:6] = declared_size.to_bytes(4, "little")
    bitmap[10:14] = (54).to_bytes(4, "little")
    bitmap[14:18] = (40).to_bytes(4, "little")
    bitmap[18:22] = width.to_bytes(4, "little", signed=True)
    bitmap[22:26] = height.to_bytes(4, "little", signed=True)
    bitmap[26:28] = (1).to_bytes(2, "little")
    bitmap[28:30] = bits.to_bytes(2, "little")
    return bytes(bitmap)


def _parsed_resource_image(resource_offset: int, resource_size: int, *, valid: bool = True):
    """実table行とresource directory境界を持つdnfile結果を合成する。"""

    tables = SimpleNamespace(
        struct=SimpleNamespace(Offset=32, Size=64),
        Module=SimpleNamespace(num_rows=1),
        TypeDef=SimpleNamespace(num_rows=1),
        MethodDef=SimpleNamespace(num_rows=1),
        ManifestResource=SimpleNamespace(num_rows=1),
    )
    metadata = (
        SimpleNamespace(
            struct=SimpleNamespace(Signature=0x424A5342),
            streams={b"#~": tables},
        )
        if valid
        else None
    )
    net = SimpleNamespace(
        struct=SimpleNamespace(
            cb=0x48,
            MetaDataRva=0x1200,
            MetaDataSize=128,
            ResourcesRva=0x2000,
            ResourcesSize=resource_size,
        ),
        metadata=metadata,
        mdtables=tables if valid else None,
        resources=[],
    )
    offsets = {0x1100: 256, 0x1200: 128, 0x2000: resource_offset}
    return SimpleNamespace(
        net=net,
        get_offset_from_rva=lambda rva: offsets[rva],
    )


def test_embedded_bitmap_fallback_requires_parsed_metadata(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """manifestが空でも実metadataと境界検証済みBMPが揃う場合だけ相関させる。"""

    outer = _managed_marker_fixture()
    bitmap = _embedded_bitmap()
    data = outer + bitmap
    parsed = _parsed_resource_image(len(outer), len(bitmap))
    monkeypatch.setattr(evidence, "valid_pe_extent", lambda _data, _offset: len(_data))
    monkeypatch.setattr(evidence.dnfile, "dnPE", lambda **_kwargs: parsed)
    result = evidence.bitmap_loader_evidence(data)
    assert result["matched"] is True
    assert result["variant"] == "bitmap_getpixel_reflection"
    assert result["resource_status"] == "embedded_bitmap_validated"
    assert result["managed_metadata_valid"] is True
    assert result["embedded_bitmap_headers"][0]["width"] == 2
    assert result["embedded_bitmap_headers"][0]["height"] == 2

    pseudo = _parsed_resource_image(len(outer), len(bitmap), valid=False)
    monkeypatch.setattr(evidence.dnfile, "dnPE", lambda **_kwargs: pseudo)
    rejected = evidence.bitmap_loader_evidence(data)
    assert rejected["matched"] is False
    assert rejected["resource_status"] == "no_manifest_resources"
    assert rejected["managed_metadata_valid"] is False
    assert rejected["embedded_bitmap_headers"] == []


def test_embedded_bitmap_candidate_budget_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """大量の偽BM候補を全走査せず、診断付きで一致を無効化する。"""

    monkeypatch.setattr(evidence, "MAX_EMBEDDED_BITMAP_CANDIDATES", 2)
    outer = _managed_marker_fixture()
    candidates = b"BMxBMxBM"
    data = outer + candidates
    parsed = _parsed_resource_image(len(outer), len(candidates))
    monkeypatch.setattr(evidence, "valid_pe_extent", lambda _data, _offset: len(_data))
    monkeypatch.setattr(evidence.dnfile, "dnPE", lambda **_kwargs: parsed)
    result = evidence.bitmap_loader_evidence(data)
    assert result["matched"] is False
    assert result["resource_status"] == "budget_exceeded"
    assert result["embedded_bitmap_headers"] == []
    assert result["resource_counters"]["embedded_bitmap_candidates"] == 3
    assert any("候補数" in value for value in result["resource_diagnostics"])

@pytest.mark.parametrize(
    "name",
    ["CON", "con.txt", "AUX.dll", "COM1.bin", "LPT9", "manifest.json", "MANIFEST.JSON"],
)
def test_safe_name_prefixes_windows_and_manifest_reserved_names(name: str) -> None:
    """Windows device名とCLI manifest名をresource出力へそのまま使わない。"""

    normalized = resources.safe_name(name, 7)
    assert normalized.casefold() != "manifest.json"
    assert normalized.split(".", 1)[0].upper() not in resources.WINDOWS_RESERVED_NAMES
    assert normalized.startswith("resource-0007-")


def _cli_resource(name: str, payload: bytes = b"payload") -> dict[str, object]:
    return {
        "index": 1,
        "original_name": name,
        "resource_container": "Synthetic.resources",
        "resource_type": "System.Stream",
        "value_encoding": "binary",
        "serialization_validated": False,
        "output_name": resources.safe_name(name, 1),
        "size": len(payload),
        "sha256": hashlib.sha256(payload).hexdigest(),
        "data": payload,
    }


def test_resource_cli_keeps_manifest_separate_from_resource(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """manifest.jsonというresourceを改名し、manifestによる内容上書きを防ぐ。"""

    sample_data = b"MZ-safe-resource-cli"
    sample = tmp_path / "sample.bin"
    sample.write_bytes(sample_data)
    output = tmp_path / "out"
    monkeypatch.setattr(
        resources,
        "resource_blobs",
        lambda _data: ([_cli_resource("manifest.json")], []),
    )
    result = resources.extract(sample, output, hashlib.sha256(sample_data).hexdigest())
    resource_name = str(result["resources"][0]["output_name"])
    assert resource_name.casefold() != "manifest.json"
    assert (output / resource_name).read_bytes() == b"payload"
    manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["resources"][0]["sha256"] == hashlib.sha256(b"payload").hexdigest()


@pytest.mark.parametrize("existing_name", ["payload.bin", "manifest.json"])
def test_resource_cli_rejects_existing_outputs_before_writing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    existing_name: str,
) -> None:
    """既存resourceまたはmanifestを上書きせず、他の出力も開始しない。"""

    sample_data = b"MZ-exclusive-resource-cli"
    sample = tmp_path / "sample.bin"
    sample.write_bytes(sample_data)
    output = tmp_path / "out"
    output.mkdir()
    existing = output / existing_name
    existing.write_bytes(b"keep")
    monkeypatch.setattr(
        resources,
        "resource_blobs",
        lambda _data: ([_cli_resource("payload.bin")], []),
    )
    with pytest.raises(FileExistsError):
        resources.extract(sample, output, hashlib.sha256(sample_data).hexdigest())
    assert existing.read_bytes() == b"keep"
    if existing_name == "manifest.json":
        assert not (output / "payload.bin").exists()


def test_resource_cli_rejects_existing_reparse_output_component(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """出力先にsymlink/junction相当があれば書き込み前に拒否する。"""

    sample_data = b"MZ-reparse-resource-cli"
    sample = tmp_path / "sample.bin"
    sample.write_bytes(sample_data)
    output = tmp_path / "reparse-output"
    output.mkdir()
    original = resources._is_reparse_point

    def fake_is_reparse(path: Path) -> bool:
        return path.absolute() == output.absolute() or original(path)

    monkeypatch.setattr(resources, "_is_reparse_point", fake_is_reparse)
    monkeypatch.setattr(
        resources,
        "resource_blobs",
        lambda _data: ([_cli_resource("payload.bin")], []),
    )
    with pytest.raises(ValueError, match="reparse point"):
        resources.extract(sample, output, hashlib.sha256(sample_data).hexdigest())
    assert not (output / "payload.bin").exists()
    assert not (output / "manifest.json").exists()

def _resource_set_image(raw: bytes, entries: list[object], *, base: int = 1):
    resource_set = SimpleNamespace(
        entries=entries,
        _data=raw,
        struct=SimpleNamespace(DataSectionOffset=base),
    )
    return SimpleNamespace(
        net=SimpleNamespace(
            resources=[SimpleNamespace(name="Synthetic.resources", data=resource_set)],
        )
    )


def test_resource_blobs_rejects_duplicate_serialized_offsets(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """同じSystem.String sliceを多数回materializeできるDataOffset重複を拒否する。"""

    monkeypatch.setattr(resources, "MAX_RESOURCE_TOTAL_BYTES", 100)
    raw = b"\0\x01\x50" + b"A" * 80
    entries = [
        SimpleNamespace(
            name=f"duplicate-{index}",
            type_name="System.String",
            value=b"A" * 80,
            struct=SimpleNamespace(DataOffset=0),
        )
        for index in range(3)
    ]
    monkeypatch.setattr(
        resources.dnfile,
        "dnPE",
        lambda **_kwargs: _resource_set_image(raw, entries),
    )
    blobs, warnings = resources.resource_blobs(b"MZ")
    assert blobs == []
    assert any("DataOffsetが重複" in warning for warning in warnings)


def test_resource_blobs_rejects_overlapping_serialized_strings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """文字列payloadが次entryの開始位置へ重なるResourceSetをfail-closedにする。"""

    raw = b"\0\x01\x0a" + b"A" * 10 + b"\x01\x01Z"
    entries = [
        SimpleNamespace(
            name="overlap",
            type_name="System.String",
            value=b"A" * 10,
            struct=SimpleNamespace(DataOffset=0),
        ),
        SimpleNamespace(
            name="next",
            type_name="System.String",
            value=b"Z",
            struct=SimpleNamespace(DataOffset=5),
        ),
    ]
    monkeypatch.setattr(
        resources.dnfile,
        "dnPE",
        lambda **_kwargs: _resource_set_image(raw, entries),
    )
    blobs, warnings = resources.resource_blobs(b"MZ")
    assert blobs == []
    assert any("次entryへ重なっています" in warning for warning in warnings)


def test_resource_blobs_limits_materialized_fallback_output_total(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """raw総量とは別に、fallback entry.valueの結果総量も制限する。"""

    monkeypatch.setattr(resources, "MAX_RESOURCE_TOTAL_BYTES", 100)
    raw = b"\0" * 20
    entries = [
        SimpleNamespace(
            name=f"fallback-{index}",
            type_name="System.Stream",
            value=bytes([65 + index]) * 60,
            struct=SimpleNamespace(DataOffset=index * 5),
        )
        for index in range(3)
    ]
    monkeypatch.setattr(
        resources.dnfile,
        "dnPE",
        lambda **_kwargs: _resource_set_image(raw, entries),
    )
    blobs, warnings = resources.resource_blobs(b"MZ")
    assert blobs == []
    assert warnings[0].startswith(resources.BUDGET_WARNING_PREFIX)
    assert "結果resource entry value総byte数" in warnings[0]
