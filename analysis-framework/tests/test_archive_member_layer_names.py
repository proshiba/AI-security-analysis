"""archive member名を静的レイヤーへ安全に伝播する回帰テスト。"""

from __future__ import annotations

import hashlib
import struct
from pathlib import Path
from types import SimpleNamespace

import pytest
from unpackers import static_unpacker as unpacker

from common.static_layer_pipeline import InputUnit, StaticLayerPolicy, recover_static_layers


def _unit(data: bytes = b"root") -> InputUnit:
    digest = hashlib.sha256(data).hexdigest()
    return InputUnit(
        source_name="sample.bin",
        data=data,
        input_kind="raw",
        outer_sha256=digest,
        outer_size=len(data),
    )


def _minimal_pe() -> bytes:
    """queue優先度検証用の構造的に妥当な小型PE32を返す。"""

    image = bytearray(0x400)
    image[:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, 0x80)
    image[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", image, 0x84, 0x14C, 1, 0, 0, 0, 0xE0, 0x0102)
    optional = 0x98
    struct.pack_into("<H", image, optional, 0x10B)
    struct.pack_into("<I", image, optional + 4, 0x200)
    struct.pack_into("<I", image, optional + 16, 0x1000)
    struct.pack_into("<I", image, optional + 20, 0x1000)
    struct.pack_into("<I", image, optional + 24, 0x2000)
    struct.pack_into("<I", image, optional + 28, 0x400000)
    struct.pack_into("<II", image, optional + 32, 0x1000, 0x200)
    struct.pack_into("<I", image, optional + 56, 0x2000)
    struct.pack_into("<I", image, optional + 60, 0x200)
    struct.pack_into("<I", image, optional + 92, 16)
    section = optional + 0xE0
    image[section : section + 8] = b".text\0\0\0"
    struct.pack_into("<IIII", image, section + 8, 0x200, 0x1000, 0x200, 0x200)
    struct.pack_into("<I", image, section + 36, 0x60000020)
    image[0x200] = 0xC3
    return bytes(image)


@pytest.mark.parametrize(
    "member_name",
    [
        "../payload.vbs",
        "/absolute/payload.vbs",
        r"C:\payload.vbs",
        "．．/payload.vbs",
    ],
)
def test_archive_member_basename_rejects_traversal(member_name: str) -> None:
    """正規化前後の相対・絶対・drive pathをbasenameへ落とさない。"""

    with pytest.raises(ValueError, match="unsafe_archive_member_path"):
        unpacker.normalize_archive_member_basename(member_name)


def test_archive_member_basename_is_normalized_bounded_and_keeps_suffix() -> None:
    """制御文字と禁止文字を除去・置換し、UTF-8上限内で拡張子を保持する。"""

    member_name = "folder/" + "検" * 200 + "\u202e<name>\x00.vbs"
    basename = unpacker.normalize_archive_member_basename(member_name)

    assert basename.endswith(".vbs")
    assert "\u202e" not in basename
    assert "\x00" not in basename
    assert "<" not in basename
    assert ">" not in basename
    assert "/" not in basename
    assert "\\" not in basename
    assert len(basename) <= unpacker.MAX_ARCHIVE_LAYER_BASENAME_CHARS
    assert len(basename.encode("utf-8")) <= unpacker.MAX_ARCHIVE_LAYER_BASENAME_UTF8_BYTES


def test_sevenzip_hints_preserve_artifact_api_and_disambiguate_basenames(
    short_tmp: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """同名memberを決定的に識別しつつ既存artifact tupleを変えない。"""

    records = [
        {"name": "a/payload.vbs", "size": 10, "attributes": "A"},
        {"name": "b/PAYLOAD.vbs", "size": 10, "attributes": "A"},
    ]

    def fake_inventory(_data: bytes, _executable: Path, _password: str = ""):
        return {
            "status": "listed",
            "archive_types": ["7z"],
            "members": [item["name"] for item in records],
            "total_members": len(records),
            "declared_total_size": 20,
            "archive_unlock_attempted": False,
            "_member_records": records,
        }

    def fake_run(command, **_kwargs):
        output_arg = next(item for item in command if item.startswith("-o"))
        output = Path(output_arg[2:])
        (output / "a").mkdir(parents=True)
        (output / "b").mkdir(parents=True)
        (output / "a" / "payload.vbs").write_bytes(b"first text")
        (output / "b" / "PAYLOAD.vbs").write_bytes(b"second txt")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(unpacker, "sevenzip_inventory", fake_inventory)
    monkeypatch.setattr(unpacker, "_run_static_tool_process", fake_run)

    report, artifacts = unpacker.sevenzip_extract(
        b"7zfixture",
        short_tmp / "7z.exe",
        max_members=8,
        max_member_size=1024,
        max_total_size=1024,
    )

    assert artifacts == [
        ("7z-script", b"first text"),
        ("7z-script", b"second txt"),
    ]
    envelope = report["artifact_name_hints"]
    assert envelope["schema_version"] == 1
    assert envelope["complete"] is True
    hints = envelope["items"]
    basenames = [item["member_basename"] for item in hints]
    assert len({name.casefold() for name in basenames}) == 2
    assert all(name.endswith(".vbs") for name in basenames)
    assert all("/" not in name and "\\" not in name for name in basenames)
    assert [item["artifact_index"] for item in hints] == [0, 1]
    assert [item["artifact_kind"] for item in hints] == ["7z-script", "7z-script"]
    assert [item["sha256"] for item in hints] == [hashlib.sha256(blob).hexdigest() for _kind, blob in artifacts]


@pytest.mark.parametrize(
    "records",
    [
        [{"name": "payload.exe:stream", "size": 1}],
        [{"name": "CON.txt", "size": 1}],
        [{"name": "CONIN$", "size": 1}],
        [{"name": "bad?.exe", "size": 1}],
        [{"name": "payload.exe. ", "size": 1}],
        [{"name": "A/payload.exe", "size": 1}, {"name": "a/PAYLOAD.EXE", "size": 1}],
        [{"name": "folder", "size": 1}, {"name": "FOLDER/child.exe", "size": 1}],
    ],
)
def test_sevenzip_member_validation_rejects_windows_equivalent_paths(
    records: list[dict[str, object]],
) -> None:
    """ADS、予約名、末尾dot/space、case同値、file/dir衝突を抽出前に拒否する。"""

    validated, blocked, record_limit_exceeded = unpacker._validated_sevenzip_member_records(
        {"members": [item["name"] for item in records]},
        records,
    )

    assert blocked >= 1
    assert record_limit_exceeded is False
    assert len(validated) < len(records)


def test_sevenzip_member_validation_allows_explicit_directory_parent() -> None:
    """directory recordとその配下fileはWindows衝突として誤拒否しない。"""

    records = [
        {"name": "folder", "size": 0, "attributes": "D"},
        {"name": "folder/payload.exe", "size": 1, "attributes": "A"},
    ]

    validated, blocked, record_limit_exceeded = unpacker._validated_sevenzip_member_records(
        {"members": [item["name"] for item in records]},
        records,
    )

    assert blocked == 0
    assert record_limit_exceeded is False
    assert validated == records


def test_unpack_bytes_promotes_nested_sevenzip_hints(
    short_tmp: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """7-Zip report配下のindexをunpack_bytes全体のartifact indexへ伝播する。"""

    child = b"opaque fixture bytes"
    digest = hashlib.sha256(child).hexdigest()

    def fake_extract(*_args, **_kwargs):
        return {
            "status": "extracted",
            "artifact_name_hints": {
                "schema_version": 1,
                "complete": True,
                "items": [
                    {
                        "artifact_index": 0,
                        "artifact_kind": "7z-script",
                        "sha256": digest,
                        "member_basename": "invoice.vbs",
                    }
                ],
            },
        }, [("7z-script", child)]

    monkeypatch.setattr(unpacker, "sevenzip_extract", fake_extract)

    report, artifacts = unpacker.unpack_bytes(
        b"7z\xbc\xaf'\x1cfixture",
        "fixture.7z",
        sevenzip=short_tmp / "7z.exe",
    )

    assert artifacts == [("7z-script", child)]
    assert report["artifact_name_hints"] == {
        "schema_version": 1,
        "complete": True,
        "items": [
            {
                "artifact_index": 0,
                "artifact_kind": "7z-script",
                "sha256": digest,
                "member_basename": "invoice.vbs",
            }
        ],
    }


def test_nested_hint_index_is_rebased_after_existing_artifact() -> None:
    """PE/CAB等で先行artifactがあってもnested indexを誤対応させない。"""

    child = b"opaque fixture bytes"
    digest = hashlib.sha256(child).hexdigest()
    parent_report: dict[str, object] = {}
    artifacts = [("existing", b"first")]
    source_report: dict[str, object] = {
        "artifact_name_hints": {
            "schema_version": 1,
            "complete": True,
            "items": [
                {
                    "artifact_index": 0,
                    "artifact_kind": "7z-script",
                    "sha256": digest,
                    "member_basename": "invoice.vbs",
                }
            ],
        }
    }

    unpacker._extend_artifacts_with_name_hints(
        parent_report,
        artifacts,
        source_report,
        [("7z-script", child)],
    )

    assert artifacts == [("existing", b"first"), ("7z-script", child)]
    envelope = parent_report["artifact_name_hints"]
    assert isinstance(envelope, dict)
    items = envelope["items"]
    assert isinstance(items, list)
    assert items[0]["artifact_index"] == 1


def test_verified_archive_hint_routes_opaque_vbs_as_script() -> None:
    """検証済み拡張子を次層format判定へ渡し、transform契約は維持する。"""

    child = b"opaque fixture bytes"
    child_digest = hashlib.sha256(child).hexdigest()
    observed_names: list[str] = []

    def custom_unpacker(data: bytes, name: str, **_kwargs):
        observed_names.append(name)
        if data != b"root":
            return {"status": "terminal"}, []
        return {
            "status": "fixture",
            "artifact_name_hints": {
                "schema_version": 1,
                "complete": True,
                "items": [
                    {
                        "artifact_index": 0,
                        "artifact_kind": "7z-script",
                        "sha256": child_digest,
                        "member_basename": "invoice.vbs",
                    }
                ],
            },
        }, [("7z-script", child)]

    layers, _report = recover_static_layers(_unit(), unpacker=custom_unpacker)

    assert len(layers) == 2
    assert layers[1].name == "sample.bin::7z-script::invoice.vbs"
    assert layers[1].transform == "7z-script"
    assert layers[1].public()["format"] == "script"
    assert observed_names == ["sample.bin", "sample.bin::7z-script::invoice.vbs"]


def test_archive_name_decoys_cannot_outrank_content_validated_pe() -> None:
    """多数の偽script拡張子より、内容で検証したPEを優先して保持する。"""

    decoys = [b"MZ" + f"opaque-{index}".encode() for index in range(12)]
    terminal = _minimal_pe()
    artifacts = [("7z-data", blob) for blob in decoys] + [("7z-pe", terminal)]

    def custom_unpacker(data: bytes, _name: str, **_kwargs):
        if data != b"root":
            return {"status": "terminal"}, []
        return {
            "status": "fixture",
            "artifact_name_hints": {
                "schema_version": 1,
                "complete": True,
                "items": [
                    {
                        "artifact_index": index,
                        "artifact_kind": kind,
                        "sha256": hashlib.sha256(blob).hexdigest(),
                        "member_basename": f"decoy-{index}.vbs" if index < len(decoys) else "payload.exe",
                    }
                    for index, (kind, blob) in enumerate(artifacts)
                ],
            },
        }, artifacts

    layers, report = recover_static_layers(
        _unit(),
        unpacker=custom_unpacker,
        policy=StaticLayerPolicy(
            max_layers=2,
            max_depth=2,
            max_layer_size=1024,
            max_total_size=2048,
        ),
    )

    assert [layer.data for layer in layers] == [b"root", terminal]
    assert report["counts"]["recovered_layers"] == 1


@pytest.mark.parametrize("invalid_hint", ["../invoice.vbs", "invoice.vbs"])
def test_unverified_archive_hint_preserves_legacy_layer_name(invalid_hint: str) -> None:
    """危険pathまたはhash不一致のhintは無視し、従来名へfail closedする。"""

    child = b"opaque fixture bytes"
    digest = hashlib.sha256(child).hexdigest()
    hinted_digest = digest if invalid_hint.startswith("..") else "f" * 64

    def custom_unpacker(data: bytes, _name: str, **_kwargs):
        if data != b"root":
            return {"status": "terminal"}, []
        return {
            "status": "fixture",
            "artifact_name_hints": {
                "schema_version": 1,
                "complete": True,
                "items": [
                    {
                        "artifact_index": 0,
                        "artifact_kind": "7z-script",
                        "sha256": hinted_digest,
                        "member_basename": invalid_hint,
                    }
                ],
            },
        }, [("7z-script", child)]

    layers, _report = recover_static_layers(_unit(), unpacker=custom_unpacker)

    assert layers[1].name == "sample.bin::7z-script"
    assert layers[1].transform == "7z-script"
    assert layers[1].public()["format"] == "data"
