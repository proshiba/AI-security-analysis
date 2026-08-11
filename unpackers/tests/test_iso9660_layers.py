"""7z内ISO9660をone-shot静的レイヤーへ昇格する回帰テスト。"""

from __future__ import annotations

import hashlib
from pathlib import Path
from types import SimpleNamespace

import pytest
from static_layer_pipeline import (
    InputUnit,
    StaticLayerPolicy,
    recover_static_layers,
)

from unpackers import static_unpacker as unpacker


def _iso_record(name: bytes, extent: int, size: int, flags: int = 0) -> bytes:
    length = 33 + len(name) + (1 if len(name) % 2 == 0 else 0)
    record = bytearray(length)
    record[0] = length
    record[2:6] = extent.to_bytes(4, "little")
    record[10:14] = size.to_bytes(4, "little")
    record[25] = flags
    record[32] = len(name)
    record[33 : 33 + len(name)] = name
    return bytes(record)


def _iso_image(*, corrupt_member_extent: bool = False) -> bytes:
    image = bytearray(25 * 2048)
    pvd = 16 * 2048
    image[pvd] = 1
    image[pvd + 1 : pvd + 6] = b"CD001"
    image[pvd + 6] = 1
    image[pvd + 40 : pvd + 48] = b"TEST-ISO"
    root = _iso_record(b"\x00", 20, 2048, flags=2)
    image[pvd + 156 : pvd + 156 + len(root)] = root

    payloads = [
        (b"HOST.EXE;1", 21, b"MZHOST"),
        (
            b"NVML.DLL;1",
            99 if corrupt_member_extent else 22,
            b"MZDLL!",
        ),
        (b"NVML.DAT;1", 23, b"NVML-DAT"),
    ]
    cursor = 20 * 2048
    for name, extent, payload in payloads:
        record = _iso_record(name, extent, len(payload))
        image[cursor : cursor + len(record)] = record
        cursor += len(record)
        if extent < 25:
            start = extent * 2048
            image[start : start + len(payload)] = payload
    return bytes(image)


def _mock_7z_extraction(
    monkeypatch: pytest.MonkeyPatch,
    image: bytes,
    *,
    member_name: str = "Tax_Notice.img",
) -> None:
    def fake_inventory(_data: bytes, _executable: Path, _password: str = ""):
        return {
            "status": "listed",
            "archive_types": ["7z"],
            "members": [member_name],
            "total_members": 1,
            "declared_total_size": len(image),
            "archive_unlock_attempted": False,
        }

    def fake_run(command, **_kwargs):
        output_arg = next(item for item in command if item.startswith("-o"))
        output = Path(output_arg[2:])
        output.mkdir(parents=True)
        (output / member_name).write_bytes(image)
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(unpacker, "sevenzip_inventory", fake_inventory)
    monkeypatch.setattr(unpacker, "_run_static_tool_process", fake_run)


def test_one_shot_recurses_from_7z_img_into_iso_members(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """7z→IMG→host／DLL／DATをそれぞれ認証済み子レイヤーにする。"""
    image = _iso_image()
    _mock_7z_extraction(monkeypatch, image)
    outer = b"7z\xbc\xaf'\x1cfixture"
    unit = InputUnit(
        source_name="sample.7z",
        data=outer,
        input_kind="raw",
        outer_sha256=hashlib.sha256(outer).hexdigest(),
        outer_size=len(outer),
    )

    layers, report = recover_static_layers(
        unit,
        unpacker=unpacker.unpack_bytes,
        sevenzip=tmp_path / "7z.exe",
        policy=StaticLayerPolicy(
            max_layers=8,
            max_depth=4,
            max_layer_size=1024 * 1024,
            max_total_size=2 * 1024 * 1024,
            max_archive_members=8,
        ),
    )

    assert report["limit_events"] == []
    assert {layer.transform for layer in layers} >= {
        "7z-iso9660",
        "iso9660-pe-exe",
        "iso9660-pe-dll",
        "iso9660-data-dat",
    }
    iso_step = next(
        step
        for step in report["steps"]
        if step["input_layer"]["transform"] == "7z-iso9660"
    )
    assert iso_step["report"]["iso9660"]["status"] == "artifacts_recovered"
    assert iso_step["report"]["iso9660"]["member_count"] == 3


def test_corrupt_iso_extent_is_not_recovered(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """PVD magicだけ一致しても境界外extentを持つIMGは成果物化しない。"""
    image = _iso_image(corrupt_member_extent=True)
    report, artifacts = unpacker.unpack_bytes(
        image,
        "broken.img",
    )

    assert report["iso9660"]["status"] == "invalid_iso9660"
    assert report["unpack_status"] == "invalid_container"
    assert artifacts == []
    _mock_7z_extraction(monkeypatch, image)
    archive_report, archive_artifacts = unpacker.sevenzip_extract(
        b"7zfixture",
        tmp_path / "7z.exe",
        max_members=8,
        max_member_size=1024 * 1024,
        max_total_size=2 * 1024 * 1024,
    )
    assert archive_report["inventory"][0]["iso9660_validation"]["status"] == (
        "invalid_iso9660"
    )
    assert archive_report["retained_members"] == 0
    assert archive_artifacts == []


def test_iso_member_limit_is_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ISO内部件数が上限を超えた場合は部分的なPE回収も行わない。"""
    image = _iso_image()
    report, artifacts = unpacker.unpack_bytes(
        image,
        "limited.img",
        max_archive_members=2,
    )

    assert report["iso9660"]["status"] == "member_limit_blocked"
    assert report["unpack_status"] == "bounded_limit"
    assert artifacts == []
    _mock_7z_extraction(monkeypatch, image)
    archive_report, archive_artifacts = unpacker.sevenzip_extract(
        b"7zfixture",
        tmp_path / "7z.exe",
        max_members=2,
        max_member_size=1024 * 1024,
        max_total_size=2 * 1024 * 1024,
    )
    assert archive_report["inventory"][0]["iso9660_validation"]["status"] == (
        "member_limit_blocked"
    )
    assert archive_report["retained_members"] == 0
    assert archive_artifacts == []


def test_unknown_img_member_is_inventory_only(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """拡張子だけがIMGの一般dataをISOとして誤展開しない。"""
    _mock_7z_extraction(monkeypatch, b"ordinary data")

    report, artifacts = unpacker.sevenzip_extract(
        b"7zfixture",
        tmp_path / "7z.exe",
        max_members=4,
        max_member_size=1024,
        max_total_size=4096,
    )

    assert report["inventory"][0]["iso9660_validation"] == {
        "status": "signature_mismatch"
    }
    assert report["retained_members"] == 0
    assert artifacts == []
