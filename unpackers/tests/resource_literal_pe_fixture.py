"""人工の PE/metadata/literal だけから作る triage 専用 fixture。

全入力 byte は定数・struct.pack・immutable bytes の連結から生成する。
検体、OS binary、外部 data、compiler、network は入力にしない。PE/CLR
entrypoint は 0、section は非実行。method の識別 byte は静的 reader stub
へのテスト入力にすぎず、CIL/CPU/CLR の実行・emulation は行わない。
resource MR44/emptyPE golden とは独立した builder である。
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import importlib
from pathlib import Path
import struct
import sys
from types import ModuleType

import dnfile


def resource_literal_source_root() -> Path:
    """通常配置と私有 overlay の ancestor から通常 source root を選ぶ。"""
    for ancestor in Path(__file__).resolve().parents:
        if ((ancestor / "unpackers" / "managed_resource_snapshot.py").is_file()
                and (ancestor / "analysis-framework").is_dir()):
            return ancestor
    raise RuntimeError("source-bound triage の通常ソース ancestor がありません")


RESOURCE_LITERAL_ROOT = resource_literal_source_root()
# checkout label は module 衝突回避だけに使い、監査や proof の cache key ではない。
_RESOURCE_LITERAL_NAMESPACE = "_resource_literal_triage_" + hashlib.sha256(
    str(RESOURCE_LITERAL_ROOT).encode("utf-8")).hexdigest()[:16]
_resource_literal_package = ModuleType(_RESOURCE_LITERAL_NAMESPACE)
_resource_literal_package.__path__ = [str(RESOURCE_LITERAL_ROOT / "unpackers")]
sys.modules[_RESOURCE_LITERAL_NAMESPACE] = _resource_literal_package
resource_literal_managed = importlib.import_module(
    _RESOURCE_LITERAL_NAMESPACE + ".managed_il_triage")

RESOURCE_LITERAL_METHOD_OFFSETS = (4500, 4550, 4600, 4650, 4700)
RESOURCE_LITERAL_BODY = bytes(range(256)) * 16
_RESOURCE_LITERAL_SECTION_RVA = 0x2000
_RESOURCE_LITERAL_SECTION_FILE = 0x200
_RESOURCE_LITERAL_SECTION_SIZE = 0x2600
_RESOURCE_LITERAL_METADATA_FILE = 0x300
_RESOURCE_LITERAL_RESOURCE_FILE = 0x1400


@dataclass(frozen=True)
class ResourceLiteralPE:
    """data だけを dnfile の静的 parser に渡す人工入力。"""
    data: bytes
    resource_body: bytes
    method_offsets: tuple[int, ...]


def _resource_literal_rva(offset: int) -> int:
    return _RESOURCE_LITERAL_SECTION_RVA + offset - _RESOURCE_LITERAL_SECTION_FILE


def _resource_literal_insert(data: bytes, offset: int, content: bytes) -> bytes:
    assert type(data) is bytes and type(content) is bytes
    assert 0 <= offset <= offset + len(content) <= len(data)
    return data[:offset] + content + data[offset + len(content):]


def _resource_literal_padding(data: bytes) -> bytes:
    return data + b"\x00" * (-len(data) % 4)


def resource_build_literal_pe() -> ResourceLiteralPE:
    """固定 metadata 宣言と静的 reader 識別本文を bytes だけで組み立てる。"""
    strings = b"\x00"
    names = {}
    for name in ("KoiVM", "Runtime", "Dispatch", "Proxy1", "Proxy2", "Proxy3",
                 "Broken", "Fixture", "payload.data", "Value", "CallOne", "CallTwo",
                 "SmartAssembly.Attributes", "KoiVM.Runtime"):
        names[name] = len(strings)
        strings += name.encode("ascii") + b"\x00"
    blobs = b"\x00"
    indices = {}
    for label, content in (
        ("method", b"\x10\x01\x00\x01"),
        ("member", b"\x00\x00\x01"),
        ("field", b"\x06\x08"),
        ("instantiation", b"\x0a\x01\x08"),
    ):
        indices[label] = len(blobs)
        assert len(content) < 0x80
        blobs += bytes((len(content),)) + content
    literal = "人工 fixture の非実行 literal".encode("utf-16le") + b"\x00"
    assert len(literal) < 0x80
    user_strings = b"\x00" + bytes((len(literal),)) + literal
    rows = {
        # TypeDef: Flags, Name, Namespace, Extends, FieldList, MethodList。
        2: (1, struct.pack("<IHHHHH", 0, names["Runtime"], names["KoiVM"], 0, 1, 1)),
        4: (1, struct.pack("<HHH", 0, names["Value"], indices["field"])),
        # MethodDef: Rva, ImplFlags, Flags, Name, Signature, ParamList。
        6: (5, b"".join(struct.pack("<IHHHHH", _resource_literal_rva(offset),
               0, 0x10, names[name], indices["method"], 1)
               for name, offset in zip(("Dispatch", "Proxy1", "Proxy2", "Proxy3", "Broken"),
                                      RESOURCE_LITERAL_METHOD_OFFSETS))),
        # MemberRefParent: TypeDef RID1、tag0。method 宣言のみで真正性は主張しない。
        10: (2, b"".join(struct.pack("<HHH", 8, names[name], indices["member"])
                         for name in ("CallOne", "CallTwo"))),
        17: (1, struct.pack("<H", indices["member"])),
        32: (1, struct.pack("<IHHHHIHHH", 0x8004, 1, 0, 0, 0, 0, 0,
                             names["Fixture"], 0)),
        40: (1, struct.pack("<IIHH", 0, 1, names["payload.data"], 0)),
        # MethodDefOrRef: MethodDef RID2、tag0。
        43: (1, struct.pack("<HH", 4, indices["instantiation"])),
    }
    numbers = tuple(sorted(rows))
    tables = struct.pack("<IBBBBQQ", 0, 2, 0, 0, 1,
                         sum(1 << number for number in numbers), 0)
    tables += b"".join(struct.pack("<I", rows[number][0]) for number in numbers)
    tables += b"".join(rows[number][1] for number in numbers)
    version = _resource_literal_padding(b"v4.0.30319\x00")
    root = struct.pack("<IHHII", 0x424A5342, 1, 1, 0, len(version))
    streams = ((b"#~", tables), (b"#Strings", strings), (b"#Blob", blobs),
               (b"#US", user_strings))
    root += version + struct.pack("<HH", 0, len(streams))
    names_raw = tuple(_resource_literal_padding(name + b"\x00") for name, _ in streams)
    offset = len(root) + sum(8 + len(name) for name in names_raw)
    headers, contents = b"", b""
    for (_, content), name in zip(streams, names_raw):
        headers += struct.pack("<II", offset, len(content)) + name
        contents += content
        offset += len(content)
    metadata = root + headers + contents
    assert _RESOURCE_LITERAL_METADATA_FILE + len(metadata) < RESOURCE_LITERAL_METHOD_OFFSETS[0]
    resource = struct.pack("<I", len(RESOURCE_LITERAL_BODY)) + RESOURCE_LITERAL_BODY
    clr = struct.pack("<IHH", 72, 2, 5)
    clr += b"".join(struct.pack("<I", value) for value in (
        _resource_literal_rva(_RESOURCE_LITERAL_METADATA_FILE), len(metadata), 1, 0,
        _resource_literal_rva(_RESOURCE_LITERAL_RESOURCE_FILE), len(resource), *([0] * 10)))
    assert len(clr) == 72
    optional = struct.pack("<HBB", 0x10B, 0, 0)
    optional += b"".join(struct.pack("<I", value) for value in (
        0, _RESOURCE_LITERAL_SECTION_SIZE, 0, 0, 0, _RESOURCE_LITERAL_SECTION_RVA,
        0x400000, 0x1000, 0x200))
    optional += struct.pack("<HHHHHH", 4, 0, 0, 0, 4, 0)
    optional += struct.pack("<IIIIHH", 0, 0x5000, 0x200, 0, 3, 0)
    optional += b"".join(struct.pack("<I", value) for value in (
        0x100000, 0x1000, 0x100000, 0x1000, 0, 16))
    assert len(optional) == 96
    optional += b"\x00" * (14 * 8)
    optional += struct.pack("<II", _resource_literal_rva(0x200), len(clr)) + b"\x00" * 8
    coff = struct.pack("<HHIIIHH", 0x14C, 1, 0, 0, 0, len(optional), 0x2102)
    section = struct.pack("<8sIIIIIIHHI", b".literal", _RESOURCE_LITERAL_SECTION_SIZE,
                          _RESOURCE_LITERAL_SECTION_RVA, _RESOURCE_LITERAL_SECTION_SIZE,
                          _RESOURCE_LITERAL_SECTION_FILE, 0, 0, 0, 0, 0x40000040)
    image = b"\x00" * (_RESOURCE_LITERAL_SECTION_FILE + _RESOURCE_LITERAL_SECTION_SIZE)
    for at, content in (
        (0, b"MZ"), (0x3C, struct.pack("<I", 0x80)),
        (0x80, b"PE\x00\x00" + coff + optional + section),
        (0x200, clr), (_RESOURCE_LITERAL_METADATA_FILE, metadata),
        (_RESOURCE_LITERAL_RESOURCE_FILE, resource),
    ):
        image = _resource_literal_insert(image, at, content)
    for identifier, at in enumerate(RESOURCE_LITERAL_METHOD_OFFSETS[:-1], 1):
        # tiny header と 10byte 識別領域。命令の解析は reader stub だけに限定。
        image = _resource_literal_insert(image, at, bytes(((10 << 2) | 2, identifier)) + b"\x00" * 9)
    image = _resource_literal_insert(image, RESOURCE_LITERAL_METHOD_OFFSETS[-1], b"\x00")
    return ResourceLiteralPE(image, RESOURCE_LITERAL_BODY, RESOURCE_LITERAL_METHOD_OFFSETS)


def resource_literal_parse(data: bytes):
    """名前付き file を使わず人工 immutable bytes を静的 dnfile に渡す。"""
    assert type(data) is bytes
    return dnfile.dnPE(data=data, clr_lazy_load=True)
