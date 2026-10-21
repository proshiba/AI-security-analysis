"""検証済みPyInstaller CArchive roleの静的レイヤー優先度テスト。"""

from __future__ import annotations

import hashlib
import re
import struct
from typing import Any

from common.static_layer_pipeline import (
    InputUnit,
    StaticLayerPolicy,
    recover_static_layers,
)


def _unit(data: bytes = b"root") -> InputUnit:
    """hashとsizeをraw入力へ束縛した小さな解析単位を返す。"""

    return InputUnit(
        source_name="sample.bin",
        data=data,
        input_kind="raw",
        outer_sha256=hashlib.sha256(data).hexdigest(),
        outer_size=len(data),
    )


def _minimal_pe() -> bytes:
    """本番と同じ構造検証へ通す1 sectionの合成PE32を返す。"""

    data = bytearray(0x400)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", data, 0x84, 0x14C, 1, 0, 0, 0, 0xE0, 0x0102)
    optional = 0x98
    struct.pack_into("<H", data, optional, 0x10B)
    struct.pack_into("<I", data, optional + 4, 0x200)
    struct.pack_into("<I", data, optional + 16, 0x1000)
    struct.pack_into("<I", data, optional + 20, 0x1000)
    struct.pack_into("<I", data, optional + 24, 0x2000)
    struct.pack_into("<I", data, optional + 28, 0x400000)
    struct.pack_into("<II", data, optional + 32, 0x1000, 0x200)
    struct.pack_into("<I", data, optional + 56, 0x2000)
    struct.pack_into("<I", data, optional + 60, 0x200)
    struct.pack_into("<I", data, optional + 92, 16)
    section = optional + 0xE0
    data[section : section + 8] = b".text\0\0\0"
    struct.pack_into("<IIII", data, section + 8, 0x200, 0x1000, 0x200, 0x200)
    struct.pack_into("<I", data, section + 36, 0x60000020)
    data[0x200] = 0xC3
    return bytes(data)


def _artifact_label(category: str, index: int, name: str) -> str:
    """CArchive復元器と同じASCII labelを合成する。"""

    basename = name.rsplit("/", 1)[-1]
    label = re.sub(r"[^A-Za-z0-9._-]+", "_", basename).strip("._")
    return f"pyinstaller-{category}-{index:03d}-{(label or 'entry')[:48]}"


def _report(
    parent: bytes,
    entries: list[tuple[str, str, str, str, bytes]],
) -> dict[str, Any]:
    """実レポートの親・選択entry・safety束縛を再現する。"""

    selected_entries = []
    for category, name, typecode, payload_format, payload in entries:
        selected_entries.append(
            {
                "name": name,
                "normalized_path": name,
                "typecode": typecode,
                "category": category,
                "payload_format": payload_format,
                "uncompressed_size": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
            }
        )
    return {
        "pyinstaller": {
            "schema_version": 1,
            "status": "artifacts_recovered",
            "sample": {
                "sha256": hashlib.sha256(parent).hexdigest(),
                "size": len(parent),
            },
            "archive": {"format": "PyInstaller CArchive"},
            "selection": {
                "strategy": "bounded_priority_v1",
                "retained_count": len(entries),
                "selected_entries": selected_entries,
            },
            "retained_artifact_count": len(entries),
            "safety": {
                "sample_executed": False,
                "external_process_started": False,
                "network_contacted": False,
                "file_written": False,
                "bytes_only": True,
                "all_toc_records_bounds_validated": True,
                "all_payload_ranges_overlap_validated": True,
                "all_paths_collision_validated": True,
                "retained_declared_and_actual_sizes_validated": True,
                "retained_zlib_eof_validated": True,
            },
        }
    }


def test_verified_roles_keep_entry_modules_pyz_and_pe_before_stdlib_fanout() -> None:
    """stdlib ZIPを後回しにし、実行候補と非標準moduleの解析枠を確保する。"""

    root = b"root"
    entry = b"marshal-entry-script"
    application_module = b"marshal-business-logic"
    pyz = b"PYZ\0application-modules"
    pe_child = _minimal_pe()
    runtime_script = b"marshal-pyinstaller-bootstrap"
    runtime_module = b"marshal-pyinstaller-import-hook"
    base_library = b"PK\x05\x06" + b"\0" * 18
    records = [
        ("python_script", "Program", "s", "pyinstaller_python_script_entry", entry),
        (
            "python_module",
            "business_logic",
            "m",
            "pyinstaller_python_module_entry",
            application_module,
        ),
        ("pyz_archive", "PYZ.pyz", "z", "pyinstaller_pyz", pyz),
        ("pe_name_candidate", "runtime.dll", "b", "portable_executable", pe_child),
        (
            "python_script",
            "pyiboot01_bootstrap",
            "s",
            "pyinstaller_python_script_entry",
            runtime_script,
        ),
        (
            "python_module",
            "pyimod01_archive",
            "m",
            "pyinstaller_python_module_entry",
            runtime_module,
        ),
        ("nested_archive", "base_library.zip", "Z", "zip", base_library),
    ]
    artifacts = [
        (_artifact_label(records[index][0], index, records[index][1]), records[index][4])
        for index in (6, 4, 5, 3, 1, 2, 0)
    ]
    stdlib = [(f"zip-data-stdlib-{index:03d}.pyc", b"stdlib-" + index.to_bytes(2, "little")) for index in range(80)]
    calls: list[bytes] = []

    def unpacker(data: bytes, _name: str, **_kwargs):
        calls.append(data)
        if data == root:
            return _report(root, records), artifacts
        if data == base_library:
            return {}, stdlib
        return {}, []

    layers, report = recover_static_layers(
        _unit(root),
        unpacker=unpacker,
        policy=StaticLayerPolicy(
            max_layers=8,
            max_depth=3,
            max_layer_size=4096,
            max_total_size=1024 * 1024,
        ),
    )

    expected = [
        root,
        entry,
        application_module,
        pyz,
        pe_child,
        runtime_script,
        runtime_module,
        base_library,
    ]
    assert [layer.data for layer in layers] == expected
    assert calls == expected
    assert {event["reason"] for event in report["limit_events"]} == {"layer_count_limit"}
    assert all(event["kind"].startswith("zip-data-stdlib-") for event in report["limit_events"])


def test_tampered_selected_entry_identity_disables_all_role_promotion() -> None:
    """選択entryが1件でもartifactへ束縛できなければrole全体をfail closedにする。"""

    root = b"root"
    entry = b"marshal-entry-script"
    base_library = b"PK\x05\x06" + b"\0" * 18
    records = [
        ("python_script", "Program", "s", "pyinstaller_python_script_entry", entry),
        ("nested_archive", "base_library.zip", "Z", "zip", base_library),
    ]
    artifacts = [
        (_artifact_label(records[0][0], 0, records[0][1]), entry),
        (_artifact_label(records[1][0], 1, records[1][1]), base_library),
    ]
    tampered = _report(root, records)
    tampered["pyinstaller"]["selection"]["selected_entries"][0]["sha256"] = "0" * 64

    def unpacker(data: bytes, _name: str, **_kwargs):
        return (tampered, artifacts) if data == root else ({}, [])

    layers, report = recover_static_layers(
        _unit(root),
        unpacker=unpacker,
        policy=StaticLayerPolicy(
            max_layers=2,
            max_depth=2,
            max_layer_size=4096,
            max_total_size=8192,
        ),
    )

    assert [layer.data for layer in layers] == [root, base_library]
    assert report["limit_events"] == [
        {
            "parent_sha256": hashlib.sha256(root).hexdigest(),
            "kind": _artifact_label(records[0][0], 0, records[0][1]),
            "sha256": hashlib.sha256(entry).hexdigest(),
            "size": len(entry),
            "reason": "layer_count_limit",
        }
    ]
