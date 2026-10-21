"""ZIP内PE import/export pairの候補優先化を合成fixtureで検証する。"""

from __future__ import annotations

import hashlib
import json
import struct

import pytest

from common.static_layer_pipeline import (
    InputUnit,
    StaticLayerPolicy,
    recover_static_layers,
)
from common.zip_sideload_pair import analyze_zip_sideload_pairs


def _pe32_headers(*, machine: int, dll: bool) -> bytearray:
    data = bytearray(0x800)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    characteristics = 0x0102 | (0x2000 if dll else 0)
    struct.pack_into("<HHIIIHH", data, 0x84, machine, 1, 0, 0, 0, 0xE0, characteristics)
    optional = 0x98
    struct.pack_into("<H", data, optional, 0x10B)
    struct.pack_into("<I", data, optional + 4, 0x200)
    struct.pack_into("<I", data, optional + 8, 0x600)
    struct.pack_into("<I", data, optional + 16, 0x1000)
    struct.pack_into("<I", data, optional + 20, 0x1000)
    struct.pack_into("<I", data, optional + 24, 0x1000)
    struct.pack_into("<I", data, optional + 28, 0x400000)
    struct.pack_into("<I", data, optional + 32, 0x1000)
    struct.pack_into("<I", data, optional + 36, 0x200)
    struct.pack_into("<HH", data, optional + 40, 6, 0)
    struct.pack_into("<HH", data, optional + 48, 6, 0)
    struct.pack_into("<I", data, optional + 56, 0x2000)
    struct.pack_into("<I", data, optional + 60, 0x200)
    struct.pack_into("<H", data, optional + 68, 3)
    struct.pack_into(
        "<IIIIII",
        data,
        optional + 72,
        0x100000,
        0x1000,
        0x100000,
        0x1000,
        0,
        16,
    )
    section = 0x178
    data[section : section + 8] = b".rdata\0\0"
    struct.pack_into("<IIIIII", data, section + 8, 0x600, 0x1000, 0x600, 0x200, 0, 0)
    struct.pack_into("<I", data, section + 36, 0x60000020)
    data[0x200] = 0xC3
    return data


def _host_pe(
    library: str = "helper.dll",
    symbol: str = "Launch",
    *,
    machine: int = 0x14C,
    ordinal: int | None = None,
) -> bytes:
    data = _pe32_headers(machine=machine, dll=False)
    optional = 0x98
    struct.pack_into("<II", data, optional + 96 + 8, 0x1100, 0x28)
    struct.pack_into("<IIIII", data, 0x300, 0x1140, 0, 0, 0x1180, 0x1160)
    if ordinal is None:
        thunk = 0x11A0
        struct.pack_into("<H", data, 0x3A0, 0)
        encoded_symbol = symbol.encode("ascii") + b"\0"
        data[0x3A2 : 0x3A2 + len(encoded_symbol)] = encoded_symbol
    else:
        thunk = 0x80000000 | ordinal
    struct.pack_into("<II", data, 0x340, thunk, 0)
    struct.pack_into("<II", data, 0x360, thunk, 0)
    encoded_library = library.encode("ascii") + b"\0"
    data[0x380 : 0x380 + len(encoded_library)] = encoded_library
    return bytes(data)


def _dll_pe(
    symbol: str = "Launch",
    *,
    machine: int = 0x14C,
    ordinal: int = 1,
    named: bool = True,
) -> bytes:
    data = _pe32_headers(machine=machine, dll=True)
    optional = 0x98
    struct.pack_into("<II", data, optional + 96, 0x1100, 0x120)
    struct.pack_into(
        "<IIHHIIIIIII",
        data,
        0x300,
        0,
        0,
        0,
        0,
        0x1180,
        ordinal,
        1,
        1 if named else 0,
        0x1140,
        0x1150,
        0x1160,
    )
    struct.pack_into("<I", data, 0x340, 0x1200)
    if named:
        struct.pack_into("<I", data, 0x350, 0x11A0)
        struct.pack_into("<H", data, 0x360, 0)
        encoded_symbol = symbol.encode("ascii") + b"\0"
        data[0x3A0 : 0x3A0 + len(encoded_symbol)] = encoded_symbol
    data[0x380:0x38B] = b"helper.dll\0"
    data[0x400] = 0xC3
    return bytes(data)


def _pair_analysis(
    host: bytes,
    dll: bytes,
    *,
    host_path: str = "bundle/host.exe",
    dll_path: str = "bundle/helper.dll",
):
    artifacts = [("zip-pe-host.exe", host), ("zip-pe-helper.dll", dll)]
    return analyze_zip_sideload_pairs(artifacts, {0: host_path, 1: dll_path})


def test_named_import_export_pair_is_prioritization_only() -> None:
    analysis = _pair_analysis(_host_pe(), _dll_pe())

    assert analysis.status == "strict_pairs_prioritized"
    assert analysis.pair_count == 1
    assert {index: role.role for index, role in analysis.roles} == {
        0: "host",
        1: "dll",
    }
    public = analysis.public()
    assert public["named_symbol_match_pair_count"] == 1
    assert public["evidence_boundary"] == {
        "queue_prioritization_only": True,
        "execution_confirmed": False,
        "maliciousness_confirmed": False,
        "family_confirmation": False,
        "c2_confirmation": False,
    }
    serialized = json.dumps(public, sort_keys=True)
    assert "bundle/host.exe" not in serialized
    assert "helper.dll" not in serialized
    assert "Launch" not in serialized


def test_ordinal_import_export_pair_is_supported() -> None:
    analysis = _pair_analysis(_host_pe(ordinal=7), _dll_pe(ordinal=7, named=False))

    assert analysis.status == "strict_pairs_prioritized"
    assert analysis.public()["ordinal_match_pair_count"] == 1


@pytest.mark.parametrize(
    ("host", "dll", "host_path", "dll_path"),
    [
        (_host_pe(symbol="Launch"), _dll_pe(symbol="Other"), "bundle/host.exe", "bundle/helper.dll"),
        (_host_pe(), _dll_pe(), "bundle/host.exe", "other/helper.dll"),
        (_host_pe(), _dll_pe(machine=0x8664), "bundle/host.exe", "bundle/helper.dll"),
    ],
    ids=("symbol-mismatch", "different-directory", "machine-mismatch"),
)
def test_incomplete_pair_evidence_never_prioritizes(
    host: bytes,
    dll: bytes,
    host_path: str,
    dll_path: str,
) -> None:
    analysis = _pair_analysis(host, dll, host_path=host_path, dll_path=dll_path)

    assert analysis.status == "no_strict_pair"
    assert analysis.roles == ()
    assert analysis.public()["prioritized_artifact_count"] == 0


@pytest.mark.parametrize(
    "invalid_path",
    (
        "bundle\\host.exe",
        "C:/bundle/host.exe",
        "bundle/cafe\u0301/host.exe",
        "bundle/control\x01/host.exe",
    ),
    ids=("backslash", "drive", "non-nfc", "control"),
)
def test_direct_api_rejects_noncanonical_windows_member_path(
    invalid_path: str,
) -> None:
    analysis = _pair_analysis(
        _host_pe(),
        _dll_pe(),
        host_path=invalid_path,
        dll_path="bundle/helper.dll",
    )

    assert analysis.status == "invalid_input"
    assert analysis.blocker == "canonical_path_invalid"
    assert analysis.roles == ()


def _unit(data: bytes = b"synthetic zip root") -> InputUnit:
    return InputUnit(
        source_name="fixture.zip",
        data=data,
        input_kind="raw",
        outer_sha256=hashlib.sha256(data).hexdigest(),
        outer_size=len(data),
    )


def _zip_report(
    values: list[tuple[str, bytes]],
    paths: list[str],
) -> dict[str, object]:
    inventory: list[dict[str, object]] = []
    for (kind, blob), path in zip(values, paths, strict=True):
        artifact_format = kind.split("-", 2)[1]
        inventory.append(
            {
                "name": path,
                "size": len(blob),
                "sha256": hashlib.sha256(blob).hexdigest(),
                "format": artifact_format,
            }
        )
    return {"format": "zip", "zip": inventory}


def test_pipeline_keeps_both_pair_members_before_other_pe() -> None:
    root = b"synthetic zip root"
    other_pe = _host_pe(library="other.dll", symbol="Unused")
    host = _host_pe()
    dll = _dll_pe()
    values = [
        ("zip-pe-other.exe", other_pe),
        ("zip-pe-host.exe", host),
        ("zip-pe-helper.dll", dll),
    ]
    paths = ["bundle/other.exe", "bundle/host.exe", "bundle/helper.dll"]

    def unpacker(data: bytes, _name: str, **_kwargs):
        if data != root:
            return {"format": "pe"}, []
        return _zip_report(values, paths), values

    layers, report = recover_static_layers(
        _unit(root),
        unpacker=unpacker,
        policy=StaticLayerPolicy(
            max_layers=3,
            max_depth=1,
            max_layer_size=4096,
            max_total_size=8192,
            max_archive_members=8,
        ),
    )

    assert [layer.data for layer in layers] == [root, host, dll]
    assert [layer.container_candidate_role for layer in layers[1:]] == ["host", "dll"]
    public_roles = [layer["container_priority_candidate"]["role"] for layer in report["layers"][1:]]
    assert public_roles == ["host", "dll"]
    summary = report["steps"][0]["report"]["zip_sideload_pair_prioritization"]
    assert summary["status"] == "strict_pairs_prioritized"
    assert summary["pair_count"] == 1
    assert summary["evidence_boundary"]["family_confirmation"] is False


@pytest.mark.parametrize(
    "tamper",
    ("sha256", "size-bool", "kind", "path", "missing-row"),
)
def test_pipeline_rejects_unbound_or_noncanonical_zip_inventory(tamper: str) -> None:
    root = b"synthetic zip root"
    other_pe = _host_pe(library="other.dll", symbol="Unused")
    host = _host_pe()
    dll = _dll_pe()
    values = [
        ("zip-pe-other.exe", other_pe),
        ("zip-pe-host.exe", host),
        ("zip-pe-helper.dll", dll),
    ]
    paths = ["bundle/other.exe", "bundle/host.exe", "bundle/helper.dll"]
    root_report = _zip_report(values, paths)
    inventory = root_report["zip"]
    assert isinstance(inventory, list)
    if tamper == "sha256":
        inventory[1]["sha256"] = "0" * 64
    elif tamper == "size-bool":
        inventory[1]["size"] = True
    elif tamper == "kind":
        inventory[1]["format"] = "elf"
    elif tamper == "path":
        inventory[1]["name"] = "../host.exe"
    else:
        inventory.pop()

    def unpacker(data: bytes, _name: str, **_kwargs):
        if data != root:
            return {"format": "pe"}, []
        return root_report, values

    layers, report = recover_static_layers(
        _unit(root),
        unpacker=unpacker,
        policy=StaticLayerPolicy(
            max_layers=2,
            max_depth=1,
            max_layer_size=4096,
            max_total_size=4096,
            max_archive_members=8,
        ),
    )

    assert [layer.data for layer in layers] == [root, other_pe]
    assert layers[1].container_candidate_kind is None
    summary = report["steps"][0]["report"]["zip_sideload_pair_prioritization"]
    assert summary["status"] == "provenance_unavailable"
    assert summary["prioritized_artifact_count"] == 0
