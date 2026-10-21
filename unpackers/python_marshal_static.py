#!/usr/bin/env python3
"""CPython 3.8--3.10互換marshal code layoutから定数候補を非実行で復元する。"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
import struct
from collections import Counter
from dataclasses import dataclass, field

MAX_INPUT_SIZE = 64 * 1024 * 1024
MAX_NODES = 200_000
MAX_DEPTH = 64
MAX_COLLECTION_ITEMS = 100_000
MAX_SCALAR_SIZE = 64 * 1024 * 1024
MAX_CANDIDATES = 64
MAX_CANDIDATE_SIZE = 64 * 1024 * 1024
MAX_CANDIDATE_TOTAL_SIZE = 64 * 1024 * 1024
MIN_ENCODED_CANDIDATE_SIZE = 64
MIN_OPAQUE_BYTES_CANDIDATE_SIZE = 4 * 1024

_FLAG_REF = 0x80
_PYINSTALLER_RAW_CODE_RE = re.compile(
    r"^pyinstaller-(?:python_script|python_module)-[0-9]{3}-"
    r"[A-Za-z0-9._-]{1,48}$",
    re.IGNORECASE,
)
_BASE64_RE = re.compile(rb"[A-Za-z0-9+/]*={0,2}")
_HEX_RE = re.compile(rb"[0-9A-Fa-f]+")
_FLOAT_TEXT_RE = re.compile(
    rb"[+-]?(?:(?:(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?)|"
    rb"(?:inf(?:inity)?|nan))",
    re.IGNORECASE,
)
_SCRIPT_PREFIXES = (
    b"#!",
    b"import ",
    b"from ",
    b"function ",
    b"var ",
    b"const ",
    b"let ",
    b"$",
    b"@echo ",
    b"<script",
    b"<?xml",
)
_KNOWN_MAGICS = (
    b"MZ",
    b"\x7fELF",
    b"PK\x03\x04",
    b"PK\x05\x06",
    b"MSCF",
    b"7z\xbc\xaf'\x1c",
    b"Rar!\x1a\x07",
    b"\x1f\x8b",
    b"BZh",
    b"\xfd7zXZ\x00",
    b"\x28\xb5\x2f\xfd",
    b"%PDF-",
    b"\x89PNG\r\n\x1a\n",
)
PROFILE = "cpython_3_8_to_3_10_marshal_v4_code_layout_candidate"


class MarshalStaticError(ValueError):
    """marshal構造が対象profile外または上限外であることを示す。"""

    def __init__(self, reason: str, offset: int) -> None:
        super().__init__(reason)
        self.reason = reason
        self.offset = offset


@dataclass(slots=True)
class _Node:
    """native Python objectを生成せずに保持するmarshal node。"""

    kind: str = "pending"
    offset: int = 0
    payload_offset: int | None = None
    payload_size: int = 0
    items: list[_Node] = field(default_factory=list)
    integer: int | None = None


@dataclass(frozen=True, slots=True)
class _Candidate:
    """公開reportと返却artifactを一対一に結ぶ定数候補。"""

    source_offset: int
    source_size: int
    source_kind: str
    source_path: str
    source_fragment_count: int
    source_fragments_sha256: str
    transform: str
    payload: bytes


@dataclass(frozen=True, slots=True)
class _ConstantRecord:
    """完全parse後に候補優先度を決める定数nodeとlineage。"""

    node: _Node
    path: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _CollectionRecord:
    """順序付き定数collectionの集約候補。"""

    node: _Node
    path: tuple[str, ...]


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _bounded_path(parts: tuple[str, ...]) -> str:
    path = ".".join(parts)
    return path if len(path) <= 512 else path[:509] + "..."


class _Parser:
    """CPython 3.8--3.10互換marshal v4 code layoutを有界に読み取る。"""

    def __init__(
        self,
        data: bytes,
        *,
        max_nodes: int,
        max_depth: int,
        max_collection_items: int,
        max_scalar_size: int,
        max_candidates: int,
        max_candidate_size: int,
        max_candidate_total_size: int,
    ) -> None:
        self.data = data
        self.view = memoryview(data)
        self.position = 0
        self.max_nodes = max_nodes
        self.max_depth_limit = max_depth
        self.max_collection_items = max_collection_items
        self.max_scalar_size = max_scalar_size
        self.max_candidates = max_candidates
        self.max_candidate_size = max_candidate_size
        self.max_candidate_total_size = max_candidate_total_size
        self.node_count = 0
        self.max_depth_seen = 0
        self.reference_reads = 0
        self.references: list[_Node] = []
        self.code_object_count = 0
        self.scalar_counts: Counter[str] = Counter()
        self.total_scalar_bytes = 0
        self.constant_scalar_count = 0
        self.candidates: list[_Candidate] = []
        self.candidate_digests: set[str] = set()
        self.constant_records: list[_ConstantRecord] = []
        self.constant_record_identities: set[tuple[int, int, str]] = set()
        self.collection_records: list[_CollectionRecord] = []
        self.candidate_total_size = 0
        self.rejection_counts: Counter[str] = Counter()
        self.limit_reasons: set[str] = set()

    def _fail(self, reason: str) -> MarshalStaticError:
        return MarshalStaticError(reason, self.position)

    def _read(self, size: int) -> memoryview:
        if size < 0 or size > len(self.data) - self.position:
            raise self._fail("truncated_input")
        start = self.position
        self.position += size
        return self.view[start : start + size]

    def _u8(self) -> int:
        return int(self._read(1)[0])

    def _i32(self) -> int:
        return struct.unpack("<i", self._read(4))[0]

    def _bounded_count(self, value: int, reason: str) -> int:
        if value < 0:
            raise self._fail(f"negative_{reason}")
        if value > self.max_collection_items:
            raise self._fail(f"{reason}_limit")
        return value

    def _reserve_reference(self, node: _Node, flagged: bool) -> None:
        if not flagged:
            return
        if len(self.references) >= self.max_nodes:
            raise self._fail("reference_limit")
        self.references.append(node)

    def _scalar(
        self,
        node: _Node,
        kind: str,
        size: int,
        *,
        ascii_only: bool = False,
        utf8: bool = False,
        in_constants: bool,
        path: tuple[str, ...],
    ) -> _Node:
        if size < 0:
            raise self._fail("negative_scalar_size")
        if size > self.max_scalar_size:
            raise self._fail("scalar_size_limit")
        start = self.position
        raw = self._read(size)
        if ascii_only:
            try:
                bytes(raw).decode("ascii", errors="strict")
            except UnicodeDecodeError as exc:
                raise self._fail("invalid_ascii_scalar") from exc
        elif utf8:
            try:
                # CPython marshalはUnicodeをsurrogatepassで直列化する。
                # ここでは文字列を生成・実行せず、正規wire表現だけを検証する。
                bytes(raw).decode("utf-8", errors="surrogatepass")
            except UnicodeDecodeError as exc:
                raise self._fail("invalid_utf8_scalar") from exc
        node.kind = kind
        node.payload_offset = start
        node.payload_size = size
        self.scalar_counts[kind] += 1
        self.total_scalar_bytes += size
        if in_constants:
            self._record_constant(node, path)
        return node

    def _scalar_bytes(self, node: _Node) -> bytes:
        if node.payload_offset is None:
            raise self._fail("scalar_payload_missing")
        start = node.payload_offset
        return bytes(self.view[start : start + node.payload_size])

    @staticmethod
    def _candidate_transforms(raw: bytes, source_kind: str) -> list[tuple[str, bytes]]:
        stripped = raw.strip()
        encoded_candidates: list[tuple[str, bytes]] = []
        if (
            len(stripped) >= MIN_ENCODED_CANDIDATE_SIZE
            and len(stripped) % 4 == 0
            and _BASE64_RE.fullmatch(stripped) is not None
        ):
            try:
                decoded = base64.b64decode(stripped, validate=True)
            except (binascii.Error, ValueError):
                decoded = b""
            if decoded and base64.b64encode(decoded) == stripped:
                encoded_candidates.append(("base64_decoded", decoded))
        if (
            len(stripped) >= MIN_ENCODED_CANDIDATE_SIZE * 2
            and len(stripped) % 2 == 0
            and _HEX_RE.fullmatch(stripped) is not None
        ):
            try:
                decoded = bytes.fromhex(stripped.decode("ascii"))
            except (UnicodeDecodeError, ValueError):
                decoded = b""
            if decoded and decoded.hex().encode("ascii") == stripped.lower():
                encoded_candidates.append(("hex_decoded", decoded))
        if len(encoded_candidates) > 1:
            structured = [
                item
                for item in encoded_candidates
                if any(item[1].startswith(magic) for magic in _KNOWN_MAGICS)
            ]
            # 一方だけが既知構造を持つ場合は決定的に採用する。どちらも同等なら
            # 一方を捨てず、個別候補として同じlineage/budgetの下で返す。
            if len(structured) == 1:
                return structured
        if encoded_candidates:
            return encoded_candidates
        if any(raw.startswith(magic) for magic in _KNOWN_MAGICS):
            return [("literal_structured_bytes", raw)]
        if source_kind == "bytes" and len(raw) >= MIN_OPAQUE_BYTES_CANDIDATE_SIZE:
            return [("literal_opaque_bytes", raw)]
        if source_kind == "text" and len(stripped) >= 128:
            lowered = stripped[:32].lower()
            if any(lowered.startswith(prefix) for prefix in _SCRIPT_PREFIXES):
                return [("literal_script_text", raw)]
        return []

    def _record_constant(self, node: _Node, path: tuple[str, ...]) -> None:
        if node.kind not in {"bytes", "text"} or node.payload_offset is None:
            return
        identity = (node.payload_offset, node.payload_size, node.kind)
        if identity in self.constant_record_identities:
            return
        self.constant_record_identities.add(identity)
        self.constant_scalar_count += 1
        self.constant_records.append(_ConstantRecord(node=node, path=path))

    @staticmethod
    def _fragment_commitment(nodes: list[_Node]) -> str:
        digest = hashlib.sha256()
        for node in nodes:
            if node.payload_offset is None:
                raise ValueError("定数fragmentのoffsetがありません")
            kind = node.kind.encode("ascii")
            digest.update(
                struct.pack("<QQI", node.payload_offset, node.payload_size, len(kind))
            )
            digest.update(kind)
        return digest.hexdigest()

    def _accept_candidate(
        self,
        *,
        nodes: list[_Node],
        path: tuple[str, ...],
        source_kind: str,
        transform: str,
        payload: bytes,
    ) -> bool:
        if not nodes or any(node.payload_offset is None for node in nodes):
            raise self._fail("candidate_lineage_missing")
        source_size = sum(node.payload_size for node in nodes)
        source_offset = min(
            int(node.payload_offset)
            for node in nodes
            if node.payload_offset is not None
        )
        if len(payload) > self.max_candidate_size:
            self.rejection_counts["candidate_size_limit"] += 1
            self.limit_reasons.add("candidate_size_limit")
            return False
        digest = _sha256(payload)
        if digest in self.candidate_digests:
            self.rejection_counts["duplicate_payload"] += 1
            return False
        if len(self.candidates) >= self.max_candidates:
            self.rejection_counts["candidate_count_limit"] += 1
            self.limit_reasons.add("candidate_count_limit")
            return False
        if len(payload) > self.max_candidate_total_size - self.candidate_total_size:
            self.rejection_counts["candidate_total_size_limit"] += 1
            self.limit_reasons.add("candidate_total_size_limit")
            return False
        self.candidate_digests.add(digest)
        self.candidate_total_size += len(payload)
        self.candidates.append(
            _Candidate(
                source_offset=source_offset,
                source_size=source_size,
                source_kind=source_kind,
                source_path=_bounded_path(path),
                source_fragment_count=len(nodes),
                source_fragments_sha256=self._fragment_commitment(nodes),
                transform=transform,
                payload=payload,
            )
        )
        return True

    def _consider_scalar_candidate(self, record: _ConstantRecord) -> None:
        node = record.node
        raw = self._scalar_bytes(node)
        transforms = self._candidate_transforms(raw, node.kind)
        if not transforms:
            self.rejection_counts["not_payload_shaped"] += 1
            return
        for transform, payload in transforms:
            self._accept_candidate(
                nodes=[node],
                path=record.path,
                source_kind=node.kind,
                transform=transform,
                payload=payload,
            )

    def _consider_collection_candidate(
        self, record: _CollectionRecord
    ) -> set[tuple[int, int, str]]:
        nodes = record.node.items
        if len(nodes) < 2 or any(
            node.kind not in {"bytes", "text"} or node.payload_offset is None
            for node in nodes
        ):
            return set()
        source_size = sum(node.payload_size for node in nodes)
        if source_size < MIN_ENCODED_CANDIDATE_SIZE:
            return set()
        # Base64（約4/3倍）とhex（2倍）の双方について、decoded上限を
        # 超えることが明白な巨大sequenceだけを連結前に拒否する。
        encoded_source_limit = max(
            (self.max_candidate_size * 4 // 3) + 4,
            self.max_candidate_size * 2,
        )
        if source_size > encoded_source_limit:
            self.rejection_counts["candidate_size_limit"] += 1
            self.limit_reasons.add("candidate_size_limit")
            return set()
        raw = b"".join(self._scalar_bytes(node) for node in nodes)
        transforms = self._candidate_transforms(raw, "text")
        transforms = [
            (transform, payload)
            for transform, payload in transforms
            if transform in {"base64_decoded", "hex_decoded"}
        ]
        if not transforms:
            return set()
        accepted_any = False
        for transform, payload in transforms:
            accepted_any = (
                self._accept_candidate(
                    nodes=nodes,
                    path=record.path,
                    source_kind="ordered_scalar_sequence",
                    transform=f"sequence_{transform}",
                    payload=payload,
                )
                or accepted_any
            )
        if not accepted_any:
            return set()
        return {
            (int(node.payload_offset), node.payload_size, node.kind)
            for node in nodes
            if node.payload_offset is not None
        }

    def finalize_candidates(self) -> None:
        """大きな順序付きaggregateを優先し、断片artifactの氾濫を防ぐ。"""

        consumed: set[tuple[int, int, str]] = set()
        collections = sorted(
            self.collection_records,
            key=lambda record: (
                -sum(node.payload_size for node in record.node.items),
                record.node.offset,
            ),
        )
        for record in collections:
            identities = {
                (int(node.payload_offset), node.payload_size, node.kind)
                for node in record.node.items
                if node.payload_offset is not None
            }
            if identities & consumed:
                continue
            consumed.update(self._consider_collection_candidate(record))
        for record in sorted(
            self.constant_records,
            key=lambda item: (-item.node.payload_size, item.node.offset),
        ):
            node = record.node
            if node.payload_offset is None:
                continue
            identity = (node.payload_offset, node.payload_size, node.kind)
            if identity in consumed:
                continue
            self._consider_scalar_candidate(record)

    @staticmethod
    def _tuple_of(node: _Node, accepted: set[str]) -> bool:
        return node.kind in {"tuple", "small_tuple"} and all(
            item.kind in accepted for item in node.items
        )

    @classmethod
    def _node_is_hashable(cls, node: _Node, active: set[int] | None = None) -> bool:
        """CPython container投入前に、構造だけで判定可能なhashabilityを検証する。"""

        if node.kind in {"pending", "null", "list", "dict", "set"}:
            return False
        if node.kind not in {"tuple", "small_tuple", "frozenset"}:
            return True
        current_active = set() if active is None else active
        identity = id(node)
        if identity in current_active:
            return False
        current_active.add(identity)
        try:
            return all(
                cls._node_is_hashable(item, current_active) for item in node.items
            )
        finally:
            current_active.remove(identity)

    def _validate_code(
        self,
        node: _Node,
        *,
        argcount: int,
        posonlyargcount: int,
        kwonlyargcount: int,
        nlocals: int,
        stacksize: int,
        flags: int,
        code: _Node,
        consts: _Node,
        names: _Node,
        varnames: _Node,
        freevars: _Node,
        cellvars: _Node,
        filename: _Node,
        name: _Node,
        firstlineno: int,
        lnotab: _Node,
    ) -> None:
        del node, flags
        if (
            min(
                argcount,
                posonlyargcount,
                kwonlyargcount,
                nlocals,
                stacksize,
                firstlineno,
            )
            < 0
        ):
            raise self._fail("negative_code_integer")
        if posonlyargcount > argcount:
            raise self._fail("invalid_posonlyargcount")
        if argcount + kwonlyargcount > nlocals:
            raise self._fail("invalid_nlocals")
        if stacksize > 1_000_000:
            raise self._fail("stacksize_limit")
        if code.kind != "bytes" or code.payload_size % 2 != 0:
            raise self._fail("invalid_wordcode")
        if consts.kind not in {"tuple", "small_tuple"}:
            raise self._fail("invalid_consts_tuple")
        for field_name, field_node in (
            ("names", names),
            ("varnames", varnames),
            ("freevars", freevars),
            ("cellvars", cellvars),
        ):
            if not self._tuple_of(field_node, {"text"}):
                raise self._fail(f"invalid_{field_name}_tuple")
        if len(varnames.items) != nlocals:
            raise self._fail("varnames_nlocals_mismatch")
        if filename.kind != "text" or name.kind != "text":
            raise self._fail("invalid_code_name")
        if filename.payload_size > 4096 or name.payload_size > 4096:
            raise self._fail("code_name_size_limit")
        if lnotab.kind != "bytes":
            raise self._fail("invalid_lnotab")

    def _code(
        self,
        node: _Node,
        *,
        depth: int,
        path: tuple[str, ...],
    ) -> _Node:
        self.code_object_count += 1
        argcount = self._i32()
        posonlyargcount = self._i32()
        kwonlyargcount = self._i32()
        nlocals = self._i32()
        stacksize = self._i32()
        flags = self._i32()
        code = self.read(depth + 1, path + ("code",), in_constants=False)
        consts = self.read(depth + 1, path + ("consts",), in_constants=True)
        names = self.read(depth + 1, path + ("names",), in_constants=False)
        varnames = self.read(depth + 1, path + ("varnames",), in_constants=False)
        freevars = self.read(depth + 1, path + ("freevars",), in_constants=False)
        cellvars = self.read(depth + 1, path + ("cellvars",), in_constants=False)
        filename = self.read(depth + 1, path + ("filename",), in_constants=False)
        name = self.read(depth + 1, path + ("name",), in_constants=False)
        firstlineno = self._i32()
        lnotab = self.read(depth + 1, path + ("lnotab",), in_constants=False)
        node.kind = "code"
        self._validate_code(
            node,
            argcount=argcount,
            posonlyargcount=posonlyargcount,
            kwonlyargcount=kwonlyargcount,
            nlocals=nlocals,
            stacksize=stacksize,
            flags=flags,
            code=code,
            consts=consts,
            names=names,
            varnames=varnames,
            freevars=freevars,
            cellvars=cellvars,
            filename=filename,
            name=name,
            firstlineno=firstlineno,
            lnotab=lnotab,
        )
        return node

    def read(
        self,
        depth: int,
        path: tuple[str, ...],
        *,
        in_constants: bool,
        allow_null_terminator: bool = False,
    ) -> _Node:
        if depth > self.max_depth_limit:
            raise self._fail("depth_limit")
        self.max_depth_seen = max(self.max_depth_seen, depth)
        self.node_count += 1
        if self.node_count > self.max_nodes:
            raise self._fail("node_limit")
        object_offset = self.position
        type_and_flag = self._u8()
        flagged = bool(type_and_flag & _FLAG_REF)
        typecode = type_and_flag & ~_FLAG_REF
        node = _Node(offset=object_offset)
        if typecode == ord("r"):
            if flagged:
                raise self._fail("flagged_reference")
            index = self._i32()
            if index < 0 or index >= len(self.references):
                raise self._fail("invalid_reference")
            referenced = self.references[index]
            if referenced.kind == "pending":
                raise self._fail("forward_or_recursive_reference")
            self.reference_reads += 1
            if in_constants:
                self._record_constant(referenced, path + ("ref",))
            return referenced
        if typecode == ord("0"):
            if not allow_null_terminator:
                raise self._fail("null_outside_dict_terminator")
            # CPython readerはdict終端のFLAG_REFを無視し、ref tableへ登録しない。
            node.kind = "null"
            return node
        simple_types = {
            ord("N"): "none",
            ord("F"): "false",
            ord("T"): "true",
            ord("S"): "stop_iteration",
            ord("."): "ellipsis",
        }
        if typecode in simple_types:
            node.kind = simple_types[typecode]
            return node
        if typecode == ord("i"):
            node.kind = "int"
            node.integer = self._i32()
            self._reserve_reference(node, flagged)
            return node
        if typecode == ord("I"):
            node.kind = "int64"
            self._read(8)
            self._reserve_reference(node, flagged)
            return node
        if typecode == ord("l"):
            node.kind = "long"
            digit_count = self._i32()
            absolute_count = abs(digit_count)
            if absolute_count > self.max_scalar_size // 2:
                raise self._fail("long_digit_limit")
            for index in range(absolute_count):
                digit = struct.unpack("<h", self._read(2))[0]
                if digit < 0 or digit > (1 << 15):
                    raise self._fail("long_digit_out_of_range")
                if index == absolute_count - 1 and digit == 0:
                    raise self._fail("unnormalized_long")
            self._reserve_reference(node, flagged)
            return node
        if typecode in {ord("f"), ord("x")}:
            node.kind = "float" if typecode == ord("f") else "complex"
            component_count = 1 if typecode == ord("f") else 2
            for _ in range(component_count):
                size = self._u8()
                try:
                    raw_float = bytes(self._read(size))
                    text_float = raw_float.decode("ascii", errors="strict")
                    if _FLOAT_TEXT_RE.fullmatch(raw_float) is None:
                        raise ValueError("numeric grammar mismatch")
                    float(text_float)
                except (UnicodeDecodeError, ValueError) as exc:
                    raise self._fail("invalid_float_text") from exc
            self._reserve_reference(node, flagged)
            return node
        if typecode in {ord("g"), ord("y")}:
            node.kind = "binary_float" if typecode == ord("g") else "binary_complex"
            self._read(8 if typecode == ord("g") else 16)
            self._reserve_reference(node, flagged)
            return node
        if typecode == ord("s"):
            result = self._scalar(
                node,
                "bytes",
                self._i32(),
                in_constants=in_constants,
                path=path,
            )
            self._reserve_reference(result, flagged)
            return result
        if typecode in {ord("t"), ord("u"), ord("a"), ord("A")}:
            result = self._scalar(
                node,
                "text",
                self._i32(),
                ascii_only=typecode in {ord("a"), ord("A")},
                utf8=typecode in {ord("t"), ord("u")},
                in_constants=in_constants,
                path=path,
            )
            self._reserve_reference(result, flagged)
            return result
        if typecode in {ord("z"), ord("Z")}:
            result = self._scalar(
                node,
                "text",
                self._u8(),
                ascii_only=True,
                in_constants=in_constants,
                path=path,
            )
            self._reserve_reference(result, flagged)
            return result
        if typecode in {ord("("), ord("["), ord("<"), ord(">"), ord(")")}:
            kinds = {
                ord("("): "tuple",
                ord("["): "list",
                ord("<"): "set",
                ord(">"): "frozenset",
                ord(")"): "small_tuple",
            }
            count = self._u8() if typecode == ord(")") else self._i32()
            count = self._bounded_count(count, "collection_count")
            delayed_reference = typecode == ord(">") and count > 0
            if not delayed_reference:
                node.kind = kinds[typecode]
            self._reserve_reference(node, flagged)
            for index in range(count):
                node.items.append(
                    self.read(
                        depth + 1,
                        path + (f"item[{index}]",),
                        in_constants=in_constants,
                    )
                )
            if delayed_reference:
                node.kind = kinds[typecode]
            if node.kind in {"set", "frozenset"} and any(
                not self._node_is_hashable(item) for item in node.items
            ):
                raise self._fail("unhashable_set_member")
            if in_constants and node.kind in {"tuple", "small_tuple", "list"}:
                self.collection_records.append(_CollectionRecord(node=node, path=path))
            return node
        if typecode == ord("{"):
            node.kind = "dict"
            self._reserve_reference(node, flagged)
            for index in range(self.max_collection_items + 1):
                key = self.read(
                    depth + 1,
                    path + (f"key[{index}]",),
                    in_constants=in_constants,
                    allow_null_terminator=True,
                )
                if key.kind == "null":
                    return node
                if index == self.max_collection_items:
                    raise self._fail("dict_item_limit")
                value = self.read(
                    depth + 1,
                    path + (f"value[{index}]",),
                    in_constants=in_constants,
                )
                if not self._node_is_hashable(key):
                    raise self._fail("unhashable_dict_key")
                node.items.extend((key, value))
            raise self._fail("dict_terminator_missing")
        if typecode == ord("c"):
            # code objectは全field検証後までpendingのままとし、自己参照を拒否する。
            self._reserve_reference(node, flagged)
            return self._code(node, depth=depth, path=path + ("code_object",))
        raise self._fail("unsupported_typecode")


def _bounded_positive_limit(value: int, name: str, hard_maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f"{name}は正の整数で指定してください")
    if value > hard_maximum:
        raise ValueError(f"{name}はhard maximum以下で指定してください")
    return value


def is_marshaled_code_entry_name(source_name: str) -> bool:
    """strictなPyInstaller raw script／module lineage名だけを受理する。"""

    if not isinstance(source_name, str) or not source_name:
        return False
    return (
        _PYINSTALLER_RAW_CODE_RE.fullmatch(source_name.rsplit("::", 1)[-1]) is not None
    )


def recover_marshaled_constants(
    data: bytes,
    source_name: str,
    *,
    max_input_size: int = MAX_INPUT_SIZE,
    max_nodes: int = MAX_NODES,
    max_depth: int = MAX_DEPTH,
    max_collection_items: int = MAX_COLLECTION_ITEMS,
    max_scalar_size: int = MAX_SCALAR_SIZE,
    max_candidates: int = MAX_CANDIDATES,
    max_candidate_size: int = MAX_CANDIDATE_SIZE,
    max_candidate_total_size: int = MAX_CANDIDATE_TOTAL_SIZE,
) -> tuple[dict[str, object], list[tuple[str, bytes]]]:
    """PyInstaller raw code候補だけをmarshal.loadsなしで検証・復元する。"""

    limits = {
        "max_input_size": _bounded_positive_limit(
            max_input_size, "max_input_size", MAX_INPUT_SIZE
        ),
        "max_nodes": _bounded_positive_limit(max_nodes, "max_nodes", MAX_NODES),
        "max_depth": _bounded_positive_limit(max_depth, "max_depth", MAX_DEPTH),
        "max_collection_items": _bounded_positive_limit(
            max_collection_items,
            "max_collection_items",
            MAX_COLLECTION_ITEMS,
        ),
        "max_scalar_size": _bounded_positive_limit(
            max_scalar_size, "max_scalar_size", MAX_SCALAR_SIZE
        ),
        "max_candidates": _bounded_positive_limit(
            max_candidates, "max_candidates", MAX_CANDIDATES
        ),
        "max_candidate_size": _bounded_positive_limit(
            max_candidate_size, "max_candidate_size", MAX_CANDIDATE_SIZE
        ),
        "max_candidate_total_size": _bounded_positive_limit(
            max_candidate_total_size,
            "max_candidate_total_size",
            MAX_CANDIDATE_TOTAL_SIZE,
        ),
    }
    if not isinstance(data, bytes):
        raise TypeError("dataはimmutable bytesで指定してください")
    if (
        not isinstance(source_name, str)
        or not source_name
        or len(source_name) > 4096
        or any(
            ord(character) < 32 or ord(character) == 127 for character in source_name
        )
    ):
        raise ValueError("source_nameは制御文字を含まない有界文字列で指定してください")
    if not is_marshaled_code_entry_name(source_name):
        return {
            "schema_version": 1,
            "status": "not_applicable",
            "profile": PROFILE,
            "applicability": "strict_pyinstaller_script_or_module_lineage_required",
            "candidate_set_complete": True,
            "candidate_count": 0,
            "candidates": [],
            "safety": {
                "sample_executed": False,
                "network_contacted": False,
                "marshal_loads_used": False,
                "python_bytecode_executed": False,
                "raw_constant_published": False,
            },
        }, []
    if len(data) > limits["max_input_size"]:
        return {
            "schema_version": 1,
            "status": "input_size_limit",
            "profile": PROFILE,
            "input": {"size": len(data), "sha256": _sha256(data)},
            "limits": limits,
            "candidate_set_complete": False,
            "candidate_count": 0,
            "candidates": [],
            "blockers": ["input_size_limit"],
            "safety": {
                "sample_executed": False,
                "network_contacted": False,
                "marshal_loads_used": False,
                "python_bytecode_executed": False,
                "raw_constant_published": False,
            },
        }, []
    parser = _Parser(
        data,
        max_nodes=limits["max_nodes"],
        max_depth=limits["max_depth"],
        max_collection_items=limits["max_collection_items"],
        max_scalar_size=limits["max_scalar_size"],
        max_candidates=limits["max_candidates"],
        max_candidate_size=limits["max_candidate_size"],
        max_candidate_total_size=limits["max_candidate_total_size"],
    )
    try:
        root = parser.read(0, ("root",), in_constants=False)
        if root.kind != "code":
            raise MarshalStaticError("root_is_not_code", parser.position)
        if parser.position != len(data):
            raise MarshalStaticError("trailing_bytes", parser.position)
    except MarshalStaticError as exc:
        return {
            "schema_version": 1,
            "status": "parse_failed",
            "profile": PROFILE,
            "input": {"size": len(data), "sha256": _sha256(data)},
            "failure": {"reason": exc.reason, "offset": exc.offset},
            "coverage": {
                "bytes_consumed": parser.position,
                "input_size": len(data),
                "full_consumption": False,
                "node_count": parser.node_count,
                "max_depth_seen": parser.max_depth_seen,
            },
            "candidate_set_complete": False,
            "candidate_count": 0,
            "candidates": [],
            "blockers": [exc.reason],
            "safety": {
                "sample_executed": False,
                "network_contacted": False,
                "marshal_loads_used": False,
                "python_bytecode_executed": False,
                "raw_constant_published": False,
            },
        }, []
    parser.finalize_candidates()
    artifacts: list[tuple[str, bytes]] = []
    public_candidates: list[dict[str, object]] = []
    for index, candidate in enumerate(parser.candidates):
        label = f"python-marshal-{candidate.transform.replace('_', '-')}-{index:03d}"
        digest = _sha256(candidate.payload)
        artifacts.append((label, candidate.payload))
        public_candidates.append(
            {
                "index": index,
                "artifact_kind": label,
                "source_offset": candidate.source_offset,
                "source_size": candidate.source_size,
                "source_kind": candidate.source_kind,
                "source_path": candidate.source_path,
                "source_fragment_count": candidate.source_fragment_count,
                "source_fragments_sha256": candidate.source_fragments_sha256,
                "transform": candidate.transform,
                "sha256": digest,
                "size": len(candidate.payload),
            }
        )
    complete = not parser.limit_reasons
    status = (
        "artifacts_recovered"
        if complete and artifacts
        else "validated_no_payload_candidate"
        if complete
        else "partial_artifacts_recovered"
        if artifacts
        else "bounded_limit"
    )
    return {
        "schema_version": 1,
        "status": status,
        "profile": PROFILE,
        "input": {"size": len(data), "sha256": _sha256(data)},
        "coverage": {
            "bytes_consumed": parser.position,
            "input_size": len(data),
            "full_consumption": parser.position == len(data),
            "node_count": parser.node_count,
            "max_depth_seen": parser.max_depth_seen,
            "code_object_count": parser.code_object_count,
            "reference_count": len(parser.references),
            "reference_read_count": parser.reference_reads,
            "scalar_counts": dict(sorted(parser.scalar_counts.items())),
            "total_scalar_bytes": parser.total_scalar_bytes,
            "constant_scalar_count": parser.constant_scalar_count,
        },
        "limits": limits,
        "candidate_set_complete": complete,
        "candidate_count": len(public_candidates),
        "candidate_total_size": sum(item["size"] for item in public_candidates),
        "candidates": public_candidates,
        "rejection_counts": dict(sorted(parser.rejection_counts.items())),
        "blockers": sorted(parser.limit_reasons),
        "evidence_boundary": {
            "runtime_python_version_confirmed": False,
            "marshal_wire_version_confirmed": False,
            "marshal_structure_confirms_family": False,
            "constant_candidate_confirms_payload": False,
            "constant_candidate_confirms_c2": False,
            "runtime_semantics_reconstructed": False,
        },
        "safety": {
            "sample_executed": False,
            "network_contacted": False,
            "marshal_loads_used": False,
            "python_bytecode_executed": False,
            "raw_constant_published": False,
        },
    }, artifacts


__all__ = [
    "MAX_CANDIDATES",
    "MAX_CANDIDATE_SIZE",
    "MAX_CANDIDATE_TOTAL_SIZE",
    "MAX_COLLECTION_ITEMS",
    "MAX_DEPTH",
    "MAX_INPUT_SIZE",
    "MAX_NODES",
    "MAX_SCALAR_SIZE",
    "PROFILE",
    "MarshalStaticError",
    "is_marshaled_code_entry_name",
    "recover_marshaled_constants",
]
