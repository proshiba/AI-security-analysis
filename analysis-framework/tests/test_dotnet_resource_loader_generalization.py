""".NET resource loaderの証拠gate、誤検知抑制、解析上限を合成入力で検証する。"""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import sys
import zlib

import pytest


FRAMEWORK_ROOT = Path(__file__).resolve().parents[1]
COMMON_ROOT = FRAMEWORK_ROOT / "common"
REPOSITORY_ROOT = FRAMEWORK_ROOT.parent
for trusted in (REPOSITORY_ROOT, FRAMEWORK_ROOT, COMMON_ROOT):
    value = str(trusted)
    if value not in sys.path:
        sys.path.insert(0, value)

import dotnet_resource_loader_evidence as evidence  # noqa: E402
import extract_dotnet_resources as resource_reader  # noqa: E402
from analysis_contract import handler_result_quality  # noqa: E402
from handler_catalog import (  # noqa: E402
    HandlerNoEvidenceError,
    discover_handlers,
    load_handler,
)


def _load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _minimal_pe(*, managed: bool, markers: bytes = b"") -> bytes:
    """実行不能な最小PEヘッダへ任意の静的markerを付加する。"""

    data = bytearray(0x200)
    data[:2] = b"MZ"
    pe_offset = 0x80
    data[0x3C:0x40] = pe_offset.to_bytes(4, "little")
    data[pe_offset : pe_offset + 4] = b"PE\0\0"
    coff = pe_offset + 4
    data[coff : coff + 2] = (0x14C).to_bytes(2, "little")
    data[coff + 16 : coff + 18] = (0xE0).to_bytes(2, "little")
    optional = pe_offset + 24
    data[optional : optional + 2] = (0x10B).to_bytes(2, "little")
    data[optional + 92 : optional + 96] = (16).to_bytes(4, "little")
    if managed:
        clr = optional + 96 + 14 * 8
        data[clr : clr + 4] = (0x1100).to_bytes(4, "little")
        data[clr + 4 : clr + 8] = (0x48).to_bytes(4, "little")
    return bytes(data) + markers


def _pseudo_managed_pe_with_extent() -> bytes:
    """section境界だけが整合し、metadataを持たない疑似managed PEを返す。"""

    data = bytearray(0x400)
    data[:2] = b"MZ"
    pe_offset = 0x80
    data[0x3C:0x40] = pe_offset.to_bytes(4, "little")
    data[pe_offset : pe_offset + 4] = b"PE\0\0"
    coff = pe_offset + 4
    data[coff : coff + 2] = (0x14C).to_bytes(2, "little")
    data[coff + 2 : coff + 4] = (1).to_bytes(2, "little")
    data[coff + 16 : coff + 18] = (0xE0).to_bytes(2, "little")
    data[coff + 18 : coff + 20] = (0x2102).to_bytes(2, "little")
    optional = pe_offset + 24
    data[optional : optional + 2] = (0x10B).to_bytes(2, "little")
    data[optional + 28 : optional + 32] = (0x400000).to_bytes(4, "little")
    data[optional + 32 : optional + 36] = (0x1000).to_bytes(4, "little")
    data[optional + 36 : optional + 40] = (0x200).to_bytes(4, "little")
    data[optional + 56 : optional + 60] = (0x2000).to_bytes(4, "little")
    data[optional + 60 : optional + 64] = (0x200).to_bytes(4, "little")
    data[optional + 68 : optional + 70] = (3).to_bytes(2, "little")
    data[optional + 92 : optional + 96] = (16).to_bytes(4, "little")
    clr = optional + 96 + 14 * 8
    data[clr : clr + 4] = (0x1100).to_bytes(4, "little")
    data[clr + 4 : clr + 8] = (0x48).to_bytes(4, "little")
    section = optional + 0xE0
    data[section : section + 8] = b".text\0\0\0"
    data[section + 8 : section + 12] = (0x200).to_bytes(4, "little")
    data[section + 12 : section + 16] = (0x1000).to_bytes(4, "little")
    data[section + 16 : section + 20] = (0x200).to_bytes(4, "little")
    data[section + 20 : section + 24] = (0x200).to_bytes(4, "little")
    data[section + 36 : section + 40] = (0x60000020).to_bytes(4, "little")
    return bytes(data)


_MANAGED_FIXTURE_ZLIB_B64 = (
    "eNrtVd9rXEUU/u7dbdkmNka0oX2pN90UROplJYtUKZpsNk1Tk27IbqOosLl7d7q55e6dy9y5cSMi9aGIbz75Xij4otIHwVrsX6AF"
    "/4T8AYKvImg8M3P3R35gofjWnmTOzJz5zpnvnJk7u/rBV8gByFPb2wPuw8gcHi+3qE28/GACP5x4NH3fWnk03dgKEicWvCO8ruN7"
    "UcSl02KOSCMniJxqre50eZu5J0+OzWQx1haBFSuHbx+2bvbj7sKeHrfGDanjxna2SMoZEJvUY9tAgGGvSdlmmMPcbQVV/8N+0Gn5"
    "7Rzwbj/h3BFJbgLP4QmE+BVGpgWaXxmZu5L1JPUzuSyv/JD3SIhNVyTCR8ZtDvtqguFZzbmChdzPuG5mscYO4SqHeBZNd0W7HEOD"
    "Nv2UfC08mYzZr6JSv1qxsgiKz3bZLbmzpdnX31SWYwhJ/6q2/gy4SLDf1bguRRB1EoWYsU3titfruGCb8youXV+uUn/JNmUoVkLe"
    "yvZUdJdOASfU5K/zs5gy/HNZGays2QfmqkCmP44GVkl/gQ7p70hjgFGZfG5N4jW8QdzVbE2dF77Gh5m/BQ8v4Bs8jzOkX4KLcZwm"
    "/SKmkb91sEK/jN5W7V3tDy+t8nYasrfR5jJisilYwlPhs2bIvTYTzRtBT6aCue0wxHKbRTKQO6hLTwb+ZbOEbuJzEQYt1HcSybqo"
    "tW4yX2I+jsMdbHthyrIVdz0l/y5zF3g3DkIm6kxsBz5LYAwUlEfrLPR6epTMSzqgVioZXF9ygcxdgQnQCkLiMsT8dwL6Pusi4u87"
    "b927XVu6+tOdn6cenPq+gsKPn3y0caa8+2UeVqGQdyyrQFCrYGWf01l1Ag176j3hxdd4tNjzWawINrYE/zix/jw3rOxE/804Sor9"
    "QXOBi2oYrnpBZKrHTIGV7J0n/0k8NWLpZE+bV3SfXd3z0hH2/tvxPn2Ud0fer7t2mfQG6miSXsQ6jZZRwzWaL5O+TGMlD/N//HPU"
    "a/POyLt+4FnU34tFUT0IihPQe8IoZoQb4Hp9Rns1aNUja0LrHiThOM2M3Mvn9RtXJ7uglYi++MORdi2FKQ3+ymipGuACMbIG+Cq1"
    "BL6OE+/bx9E1K4xgN6gJQg8xJXonhg3YootpaQ5SYyPiHlK9PHShvps2eUqyMtJNWld7c6Q08mncJCwnbFv7NimPAD1Cphrpkj2E"
    "udmv6BxWyNrROyyQX4wdnUWHWMiMf6z51DJ7kPHp5xP977zKul5rZOdkTclbHqrawZpd1D7zhEgI2aVTCikT57F+z8QcsvqNdmaf"
    "leJplH8BB7klug=="
)


def _valid_managed_pe() -> bytes:
    """COR20、BSJB、metadata tableを持つ無害な最小managed DLLを返す。"""

    return zlib.decompress(base64.b64decode(_MANAGED_FIXTURE_ZLIB_B64))


def _stuff_markers() -> bytes:
    return (
        b"stuff FromBase64String Assembly Load GetString chapter "
        + "Dope.Version".encode("utf-16le")
        + b" "
        + "Step".encode("utf-16le")
    )


def _encode_chapter_payload(clear: bytes) -> bytes:
    """chapter変換後がclearとなる入力を合成する。"""

    def int32(value: int) -> int:
        value &= 0xFFFFFFFF
        return value - 0x100000000 if value & 0x80000000 else value

    output = bytearray()
    a = 17937
    b = 50497
    for index, desired in enumerate(clear):
        b = int32((b ^ index) * 31)
        a = int32((a + b) ^ 13)
        temporary = ((desired ^ 45) + b) & 0xFF
        output.append(temporary ^ (a & 0xFF))
        b = int32(b + desired)
    return bytes(output)


def _stuff_resource(value: bytes, *, validated: bool = True) -> dict[str, object]:
    return {
        "original_name": "stuff",
        "container_name": "Synthetic.resources",
        "resource_type": "System.String",
        "value_encoding": "utf-8",
        "serialization_validated": validated,
        "size": len(value),
        "data": value,
    }


def _no_bitmap(_data: bytes) -> dict[str, object]:
    return {
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
    }


def _automatic_spec():
    return next(item for item in discover_handlers() if item.family == "dotnet_resource_loader" and item.automatic)


def _handler_with_resource(
    monkeypatch: pytest.MonkeyPatch,
    resource: dict[str, object],
):
    handler, _invocation = load_handler(_automatic_spec())
    monkeypatch.setitem(
        handler.__globals__,
        "resource_blobs",
        lambda _data: ([resource], []),
    )
    monkeypatch.setitem(
        handler.__globals__,
        "bitmap_loader_evidence",
        _no_bitmap,
    )
    return handler


def test_managed_pe_shape_requires_nonzero_clr_directory() -> None:
    """MZ/PEだけでなく、範囲内のCLR data directoryを必須にする。"""

    assert evidence.managed_pe_shape(_minimal_pe(managed=True))["is_managed_pe"] is True
    assert evidence.managed_pe_shape(_minimal_pe(managed=False))["is_managed_pe"] is False
    assert evidence.managed_pe_shape(b"MZ-not-a-pe")["is_managed_pe"] is False
    assert evidence.validated_managed_pe_shape(_valid_managed_pe())["boundary_validated"] is True


def test_pseudo_managed_extent_is_not_metadata_validated() -> None:
    """sectionとCLR directoryだけの疑似PEをmanaged子として確定しない。"""

    result = evidence.validated_managed_pe_shape(_pseudo_managed_pe_with_extent())
    assert result["is_managed_pe"] is True
    assert result["validated_extent"] is not None
    assert result["metadata_validated"] is False
    assert result["boundary_validated"] is False


def test_serialized_system_string_uses_full_7bit_length() -> None:
    """dnfileのvalue表示に依存せず、entry境界内の長い文字列を復号する。"""

    value = b"A" * 4096
    length = bytearray()
    remaining = len(value)
    while remaining >= 0x80:
        length.append((remaining & 0x7F) | 0x80)
        remaining >>= 7
    length.append(remaining)
    base = 32
    raw = b"\0" * base + b"\x01" + bytes(length) + value
    entry = SimpleNamespace(
        name="stuff",
        type_name="System.String",
        struct=SimpleNamespace(DataOffset=0),
    )
    resource_set = SimpleNamespace(
        entries=[entry],
        _data=raw,
        struct=SimpleNamespace(DataSectionOffset=base),
    )
    assert resource_reader._serialized_resource_string(resource_set, entry, 0) == value


def test_detector_rejects_native_pe_with_bundled_dotnet_runtime_strings() -> None:
    """native PE内のAssembly等の文字列だけではloader扱いしない。"""

    detector = _load_module(
        FRAMEWORK_ROOT / "malware" / "dotnet_resource_loader" / "detect.py",
        "test_dotnet_resource_loader_detector",
    )
    native = _minimal_pe(
        managed=False,
        markers=(_stuff_markers() + b" System.Drawing.Bitmap GetPixel GetExportedTypes InvokeMember get_R get_G get_B"),
    )
    result = detector.detect(native)
    assert result["matched"] is False
    assert result["confidence"] == "none"
    assert result["observations"]["managed_pe"]["is_managed_pe"] is False


def test_detector_accepts_managed_getpixel_reflection_correlation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CLR構造とRGB読出し、reflectionの全相関がある場合だけ強く検出する。"""

    detector = _load_module(
        FRAMEWORK_ROOT / "malware" / "dotnet_resource_loader" / "detect.py",
        "test_dotnet_resource_loader_detector_positive",
    )
    monkeypatch.setattr(
        evidence,
        "_recover_budgeted_bitmap_pes",
        lambda _data: (
            {
                "status": "bitmap_entries_processed",
                "inventory": [
                    {
                        "name": "Synthetic.resources",
                        "bitmap_payloads": {
                            "status": "bitmap_entries_processed",
                            "entries": [{"name": "payload", "status": "rgb_recovered_no_pe"}],
                        },
                    }
                ],
                "diagnostics": [],
                "counters": {},
                "managed_metadata_valid": True,
                "managed_metadata_evidence": {"metadata_signature": "BSJB"},
                "managed_resource_range": None,
            },
            [],
        ),
    )
    managed = _valid_managed_pe() + (
        b"System.Drawing.Bitmap GetPixel GetExportedTypes InvokeMember get_R get_G get_B"
    )
    result = detector.detect(managed)
    assert result["matched"] is True
    assert result["confidence"] == "strong_structural_correlation"
    assert result["observations"]["bitmap_loader"]["strong_reflection_correlation"] is True


def test_bitmap_recovery_reuses_generic_decoder_without_returning_payload(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """上限付き走査結果をhashとsizeへ縮約し、子byte列を戻り値に含めない。"""

    child = _valid_managed_pe()
    monkeypatch.setattr(
        evidence,
        "_recover_budgeted_bitmap_pes",
        lambda _data: (
            {
                "status": "bitmap_pe_recovered",
                "inventory": [],
                "diagnostics": [],
                "counters": {"output_bytes": len(child)},
                "managed_metadata_valid": True,
                "managed_metadata_evidence": {"metadata_signature": "BSJB"},
                "managed_resource_range": None,
            },
            [
                ("dotnet-bitmap-rgb-pe", child),
                ("unrelated-transform", b"ignored"),
            ],
        ),
    )
    managed = _valid_managed_pe() + b"System.Drawing.Bitmap GetExportedTypes"
    result = evidence.bitmap_loader_evidence(managed)
    assert result["matched"] is True
    assert result["variant"] == "bitmap_rgb_recovered_pe"
    recovered = result["recovered_children"]
    assert len(recovered) == 1
    assert recovered[0]["sha256"] == hashlib.sha256(child).hexdigest()
    assert recovered[0]["size"] == len(child)
    assert recovered[0]["retained"] is False
    assert recovered[0]["executed"] is False
    assert "payload" not in recovered[0]
    assert child.hex() not in json.dumps(result)


def test_handler_accepts_only_correlated_stuff_with_valid_managed_child(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """固有markerと厳密Base64、境界検証済みmanaged子をすべて要求する。"""

    child = _valid_managed_pe()
    encoded = base64.b64encode(_encode_chapter_payload(child))
    handler = _handler_with_resource(
        monkeypatch,
        _stuff_resource(encoded),
    )
    result = handler(_valid_managed_pe() + _stuff_markers())
    assert result["variant"] == "system_string_stuff_chapter"
    assert result["classification_confidence"] == "confirmed_static_managed_child"
    assert result["recovered_child"]["sha256"] == hashlib.sha256(child).hexdigest()
    assert result["recovered_child"]["status"] == "structurally_complete_unexecuted"
    quality = handler_result_quality(result, minimum_score=20_000)
    assert quality["sufficient"] is True


@pytest.mark.parametrize(
    ("outer", "resource"),
    [
        (
            _valid_managed_pe(),
            _stuff_resource(base64.b64encode(_encode_chapter_payload(_valid_managed_pe()))),
        ),
        (
            _valid_managed_pe() + _stuff_markers(),
            _stuff_resource(b"invalid@base64" * 16),
        ),
        (
            _minimal_pe(managed=False, markers=_stuff_markers()),
            _stuff_resource(base64.b64encode(_encode_chapter_payload(_valid_managed_pe()))),
        ),
        (
            _valid_managed_pe() + _stuff_markers(),
            _stuff_resource(base64.b64encode(_encode_chapter_payload(b"MZ-cut-child"))),
        ),
        (
            _valid_managed_pe() + _stuff_markers(),
            _stuff_resource(
                base64.b64encode(_encode_chapter_payload(_valid_managed_pe())),
                validated=False,
            ),
        ),
    ],
    ids=[
        "arbitrary-stuff",
        "invalid-base64",
        "native-outer",
        "cut-child",
        "unvalidated-resource-boundary",
    ],
)
def test_handler_rejects_weak_or_malformed_stuff(
    monkeypatch: pytest.MonkeyPatch,
    outer: bytes,
    resource: dict[str, object],
) -> None:
    """stuff名だけ、無効Base64、native、切断子を証拠へ昇格しない。"""

    handler = _handler_with_resource(monkeypatch, resource)
    with pytest.raises(HandlerNoEvidenceError):
        handler(outer)


def test_handler_contract_and_bitmap_evidence_quality(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """PE限定契約とtier 2以上のBitmap構造証拠を保証する。"""

    spec = _automatic_spec()
    assert spec.input_formats == ("pe",)
    assert spec.minimum_evidence_score == 20_000
    handler, _invocation = load_handler(spec)
    monkeypatch.setitem(handler.__globals__, "resource_blobs", lambda _data: ([], []))
    monkeypatch.setitem(
        handler.__globals__,
        "bitmap_loader_evidence",
        lambda _data: {
            "matched": True,
            "variant": "bitmap_getpixel_reflection",
            "managed_pe": {"is_managed_pe": True},
            "marker_hits": [
                "System.Drawing.Bitmap",
                "GetPixel",
                "GetExportedTypes",
                "InvokeMember",
                "get_R",
                "get_G",
                "get_B",
            ],
            "strong_reflection_correlation": True,
            "resource_status": "synthetic",
            "resource_diagnostics": [],
            "resource_counters": {},
            "bitmap_inventory": [],
            "recovered_children": [],
        },
    )
    result = handler(_minimal_pe(managed=True))
    quality = handler_result_quality(
        result,
        minimum_score=spec.minimum_evidence_score,
    )
    assert result["variant"] == "bitmap_getpixel_reflection"
    assert quality["tier_name"] == "structural_corroboration"
    assert quality["sufficient"] is True
    assert result["safety"]["sample_executed"] is False
    assert result["safety"]["network_contacted"] is False


def _bitmap_resource(*, width: int = 1, height: int = 1):
    bits = 24
    stride = ((width * bits + 31) // 32) * 4
    declared_size = 54 + stride * max(1, abs(height))
    bitmap = bytearray(declared_size)
    bitmap[:2] = b"BM"
    bitmap[2:6] = declared_size.to_bytes(4, "little")
    bitmap[10:14] = (54).to_bytes(4, "little")
    bitmap[14:18] = (40).to_bytes(4, "little")
    bitmap[18:22] = width.to_bytes(4, "little", signed=True)
    bitmap[22:26] = height.to_bytes(4, "little", signed=True)
    bitmap[26:28] = (1).to_bytes(2, "little")
    bitmap[28:30] = bits.to_bytes(2, "little")
    base = 16
    raw = b"\0" * base + bytes(bitmap)
    entry = SimpleNamespace(
        name="payload",
        type_name="System.Drawing.Bitmap",
        struct=SimpleNamespace(DataOffset=0),
    )
    resource_set = SimpleNamespace(
        entries=[entry],
        _data=raw,
        struct=SimpleNamespace(DataSectionOffset=base),
    )
    return SimpleNamespace(name="Synthetic.resources", data=resource_set)


def test_bitmap_dimension_budget_blocks_match(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """巨大dimensionをRGB loopへ渡さずbudget診断で停止する。"""

    image = SimpleNamespace(
        net=SimpleNamespace(
            resources=[
                _bitmap_resource(
                    width=evidence.MAX_BITMAP_DIMENSION + 1,
                    height=1,
                )
            ]
        )
    )
    monkeypatch.setattr(evidence.dnfile, "dnPE", lambda **_kwargs: image)
    report, artifacts = evidence._recover_budgeted_bitmap_pes(b"MZ")
    assert report["status"] == "budget_exceeded"
    assert artifacts == []
    assert any("dimensions" in value for value in report["diagnostics"])


def test_bitmap_resource_and_total_size_budgets(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """多数resourceとraw data総量の両方をfail closedで拒否する。"""

    too_many = SimpleNamespace(
        net=SimpleNamespace(resources=[SimpleNamespace()] * (evidence.MAX_BITMAP_RESOURCE_COUNT + 1))
    )
    monkeypatch.setattr(evidence.dnfile, "dnPE", lambda **_kwargs: too_many)
    report, artifacts = evidence._recover_budgeted_bitmap_pes(b"MZ")
    assert report["status"] == "budget_exceeded"
    assert artifacts == []

    monkeypatch.setattr(evidence, "MAX_BITMAP_RESOURCE_BYTES", 100)
    resource_set = lambda: SimpleNamespace(  # noqa: E731
        entries=[],
        _data=b"x" * 60,
        struct=SimpleNamespace(DataSectionOffset=1),
    )
    total = SimpleNamespace(
        net=SimpleNamespace(
            resources=[
                SimpleNamespace(name="one", data=resource_set()),
                SimpleNamespace(name="two", data=resource_set()),
            ]
        )
    )
    monkeypatch.setattr(evidence.dnfile, "dnPE", lambda **_kwargs: total)
    report, artifacts = evidence._recover_budgeted_bitmap_pes(b"MZ")
    assert report["status"] == "budget_exceeded"
    assert artifacts == []
    assert any("raw data総量" in value for value in report["diagnostics"])


def test_bitmap_budget_exceeded_disables_strong_string_match(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """budget超過時は完全なGetPixel文字列相関があっても一致させない。"""

    monkeypatch.setattr(
        evidence,
        "_recover_budgeted_bitmap_pes",
        lambda _data: (
            {
                "status": "budget_exceeded",
                "inventory": [],
                "diagnostics": ["合成上限超過"],
                "counters": {"resource_count": 65},
            },
            [],
        ),
    )
    managed = _minimal_pe(
        managed=True,
        markers=(b"System.Drawing.Bitmap GetPixel GetExportedTypes InvokeMember get_R get_G get_B"),
    )
    result = evidence.bitmap_loader_evidence(managed)
    assert result["matched"] is False
    assert result["variant"] is None
    assert result["resource_status"] == "budget_exceeded"
    assert result["resource_diagnostics"] == ["合成上限超過"]
