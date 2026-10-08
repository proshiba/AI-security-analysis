"""二段のmanaged Bitmap loaderを、CLRやBinaryFormatterを実行せず復元する。

対象recipeは次をすべて静的に確認した場合だけ受理する。

* outer CILが ``GetPixel(x, y)`` のR/G/Bをx-majorで連結し、明示長で切る。
* outerの同一methodが、field literalをdelimiterで分割して3引数constructorへ渡す。
* 第一段childがレビュー済みのBitmap crop／ARGB／XOR／``Assembly.Load`` CIL profileと一致する。
* root ResourceSetの対象Bitmapが、限定NRBF envelope内の単一 ``byte[]`` である。
* PNG、crop、length prefix、XOR後のmanaged PE境界が一意に成立する。

BinaryFormatter、CLR、CIL、復元PEは実行しない。NRBFは必要なrecord列だけを
byte-levelで読み、未知record、重複候補、上限超過を安全側へ拒否する。
復元成功はloader lineageの証拠であり、malware family、C2、終端到達の確証には
使わない。
"""

from __future__ import annotations

import hashlib
import logging
import re
import struct
import time
import warnings
import zlib
from collections import Counter
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass

import dnfile
from dncil.cil.body.reader import read_method_body_from_bytes
from dncil.cil.error import MethodBodyFormatError
from pefile import PEFormatError

from extractors.managed_pe import has_clr_metadata
from unpackers.bounded_pe_scan import inspect_structural_pe_extent
from unpackers.managed_constructor_guard import preflight_clr_declarations

MAX_INPUT_BYTES = 32 << 20
MAX_METHODS = 8_192
MAX_METHOD_BYTES = 256 << 10
MAX_SIGNATURE_BYTES = 512
MAX_TOTAL_METHOD_BYTES = 16 << 20
MAX_METHOD_INSTRUCTIONS = 20_000
MAX_TOTAL_INSTRUCTIONS = 250_000
MAX_RESOURCE_SETS = 256
MAX_RESOURCE_ENTRIES = 4_096
MAX_RESOURCE_BYTES = 32 << 20
MAX_BITMAP_BYTES = 16 << 20
MAX_IMAGE_DIMENSION = 4_096
MAX_IMAGE_PIXELS = 8_000_000
MAX_PNG_CHUNKS = 4_096
MAX_PNG_CHUNK_BYTES = 16 << 20
MAX_PNG_COMPRESSED_BYTES = 32 << 20
MAX_IMAGE_BYTES = 64 << 20
MAX_OUTPUT_BYTES = 64 << 20
MAX_OVERLAY_BYTES = 4_096
MAX_LITERAL_CHARACTERS = 8_192
MAX_ELAPSED_SECONDS = 10.0

PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
SYSTEM_DRAWING_IDENTITY = (
    "System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a"
)

# このprofileはroot hashやprovider labelではなく、第一段loader assemblyの
# exact method bodyを照合する。token参照先とdataflowは別途semantic検証する。
LOADER_PROFILE_ID = "managed-bitmap-argb-xor-v1"
LOADER_METHOD_BODY_SHA256 = {
    "entry": "46f04f13b35809eba53c7700fb2b08f2436c21cf5c25dd6ec2375ea586b7163e",
    "decode_resource_argument": "87009bdc4d5b0768af979ab95e6526520ec92324251a237ffa5506c711d23a65",
    "decode_key_argument": "e90a7443b487ed6732be1bfdef77ad99ddcfe52e1d901678e180020ae6945368",
    "resource_wrapper": "f9758f277394875f39e573b3ccde437101e46d598b40d7a54fcc74c78994eb28",
    "crop_and_argb": "d4eba862bb8ab8ea6a7ac99b5d1610ea77e141fd2d6696a8ec29db8d19b5edc0",
    "load_wrapper": "36e02581ab3519e7018072ef071e0325a080764623c6154cf968ae36e45f322c",
    "invoke_wrapper": "b7b4fef911545e31a7438fae843f70c2926cc337f6010264d0693e0cc83e75bb",
    "invoke_target": "67edb37b6ed6fe59ad50f7ab854a0b63916c62ea0f2b5ff1b91a3d7dff45a41e",
    "assembly_load": "c9ed8fddd1e44e27c722438a6911c09e2f5d15342f746826072d42904ba09105",
    "xor_wrapper": "9cefd66e7da0bb73c252d355e1cdec7e6aff9565b55922043f5079ba6a7595a8",
    "key_bytes": "8f7efbac0fcf94803d4c45718c5f3d8093ee31c8a21189c0e439fb785c02ef57",
    "mask": "590b914bd933c9e508a7c43bfa9b9134ac985dfbcac3fa3b0994148de96af617",
    "key_index": "6fd1b3d3dd4cd6a7da80c59d431dec0458f2d3734775336ca2c2af6060fe1014",
    "xor_loop": "05daddc5f06d88f0ffa5ac037ab563138ea142a906815ea00a252f33034ef05c",
    "drop_sentinel": "bec3d5af27f8199a83d3ab0c7d1d2a891fc1473c1bd153820998c8d93ecffb3c",
    "hex_text": "71f8cb4ac0882cde5005f9130249f2071480ceb3ef4bb4be92e95d9592626579",
    "resource_lookup": "b404ab4026ae97f15f1aa048c7e3f424b0f7ef38d62e3c702c12f897674bcfff",
    "argb_bytes": "9483b13252bf4737a9f51e0221e22364f1db84b7941c73092bf9826f4c44d617",
    "crop_bitmap": "e61720786a4280396c4ad2a93bed39011cc8555276c9e0c9194290f8ce5e0f28",
}


class RecoveryError(ValueError):
    """未知の形、曖昧性、上限超過をfail-closedで表す。"""


@dataclass(frozen=True)
class Instruction:
    """公開文字列を保持しない、有界CIL instruction model。"""

    offset: int
    opcode: str
    token: int | None
    resolved: str
    integer: int | None
    user_string: str | None
    local: int | None


@dataclass(frozen=True)
class MethodModel:
    """MethodDef bodyとtoken参照を結び付けた静的model。"""

    token: int
    owner: str
    name: str
    rva: int
    body_size: int
    body_sha256: str
    instructions: tuple[Instruction, ...]
    owner_token: int = 0
    owner_export_index: int | None = None
    signature: bytes = b""
    is_static: bool = False
    is_public: bool = False
    is_special_name: bool = False
    is_runtime_special_name: bool = False


@dataclass(frozen=True)
class RootRecipe:
    """outer CILから一意に得たconstructor引数と第一段変換。"""

    caller_token: int
    rgb_method_token: int
    bitmap_getter_token: int
    first_child_length: int
    first_bitmap_name: str
    resource_argument_hex: str
    key_argument_hex: str
    resource_namespace: str


@dataclass(frozen=True)
class LoaderRecipe:
    """レビュー済み第一段childから得た変換定数。"""

    crop_right: int
    crop_bottom: int
    mask_xor: int
    method_tokens: dict[str, int]
    constructor_token: int


@dataclass(frozen=True)
class ResourceEntry:
    """ResourceSet entryの境界検証済みraw bytes。"""

    resource_set_name: str
    entry_name: str
    type_name: str
    data: bytes


def _base_report(size: int) -> dict[str, object]:
    return {
        "schema_version": 1,
        "status": "not_candidate",
        "input_size": size,
        "profile_id": LOADER_PROFILE_ID,
        "sample_executed": False,
        "clr_loaded": False,
        "binaryformatter_deserialized": False,
        "instruction_emulation_performed": False,
        "network_contacted": False,
        "raw_resource_content_in_report": False,
        "raw_payload_content_in_report": False,
        "secret_material_in_report": False,
        "private_recursive_artifact_returned": False,
        "artifact_visibility": "private_recursive_analysis_only",
        "runtime_reachability_confirmed": False,
        "family_attribution_allowed": False,
        "c2_confirmation_allowed": False,
        "terminal_promotion_eligible": False,
    }


def _deadline(deadline: float, clock: Callable[[], float]) -> None:
    if clock() > deadline:
        raise RecoveryError("elapsed_time_limit")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _text(value: object, *, limit: int = 1_024) -> str:
    raw = getattr(value, "value", value)
    if not isinstance(raw, str) or len(raw) > limit:
        return ""
    return raw


def _type_name(row: object | None) -> str:
    if row is None:
        return ""
    namespace = _text(getattr(row, "TypeNamespace", None))
    name = _text(getattr(row, "TypeName", None))
    return f"{namespace}.{name}" if namespace and name else name


def _operand_value(operand: object) -> int | None:
    value = getattr(operand, "value", None)
    return value if type(value) is int else None


def _integer(opcode: str, operand: object) -> int | None:
    if opcode == "ldc.i4.m1":
        return -1
    match = re.fullmatch(r"ldc\.i4\.([0-8])", opcode)
    if match:
        return int(match.group(1))
    if opcode not in {"ldc.i4", "ldc.i4.s"}:
        return None
    value = _operand_value(operand)
    if value is not None:
        return value
    try:
        return int(str(operand), 0)
    except ValueError:
        return None


def _local(opcode: str, operand: object) -> int | None:
    match = re.fullmatch(r"(?:ld|st)loc\.([0-3])", opcode)
    if match:
        return int(match.group(1))
    if opcode not in {"ldloc", "ldloc.s", "stloc", "stloc.s", "ldloca", "ldloca.s"}:
        return None
    match = re.fullmatch(r"local\(0x([0-9a-fA-F]+)\)", str(operand))
    return int(match.group(1), 16) if match else None


def _row_tokens(
    tables: object,
    deadline: float,
    clock: Callable[[], float],
) -> dict[int, int]:
    result: dict[int, int] = {}
    total = 0
    for name, prefix in (
        ("TypeRef", 0x01000000),
        ("TypeDef", 0x02000000),
        ("Field", 0x04000000),
        ("MethodDef", 0x06000000),
        ("MemberRef", 0x0A000000),
        ("MethodSpec", 0x2B000000),
    ):
        table = getattr(tables, name, None)
        for index, row in enumerate(getattr(table, "rows", ()) or (), 1):
            total += 1
            if total & 0xFF == 0:
                _deadline(deadline, clock)
            result[id(row)] = prefix | index
    return result


def _metadata_names(
    pe: object,
    rows: dict[int, int],
    deadline: float,
    clock: Callable[[], float],
) -> tuple[dict[int, str], dict[int, str], dict[int, str]]:
    tables = pe.net.mdtables
    type_names: dict[int, str] = {}
    method_names: dict[int, str] = {}
    field_names: dict[int, str] = {}
    method_owners: dict[int, str] = {}
    field_owners: dict[int, str] = {}

    for table_name, prefix in (("TypeRef", 0x01000000), ("TypeDef", 0x02000000)):
        table = getattr(tables, table_name, None)
        for index, row in enumerate(getattr(table, "rows", ()) or (), 1):
            if index & 0xFF == 0:
                _deadline(deadline, clock)
            type_names[prefix | index] = _type_name(row)

    for index, row in enumerate(
        getattr(getattr(tables, "TypeDef", None), "rows", ()) or (), 1
    ):
        if index & 0xFF == 0:
            _deadline(deadline, clock)
        owner = _type_name(row)
        for reference in getattr(row, "MethodList", ()) or ():
            method_owners[int(reference.row_index)] = owner
        for reference in getattr(row, "FieldList", ()) or ():
            field_owners[int(reference.row_index)] = owner

    for index, row in enumerate(
        getattr(getattr(tables, "MethodDef", None), "rows", ()) or (), 1
    ):
        if index & 0xFF == 0:
            _deadline(deadline, clock)
        name = _text(getattr(row, "Name", None))
        owner = method_owners.get(index, "")
        method_names[0x06000000 | index] = f"{owner}::{name}" if owner else name
    for index, row in enumerate(
        getattr(getattr(tables, "Field", None), "rows", ()) or (), 1
    ):
        if index & 0xFF == 0:
            _deadline(deadline, clock)
        name = _text(getattr(row, "Name", None))
        owner = field_owners.get(index, "")
        field_names[0x04000000 | index] = f"{owner}::{name}" if owner else name
    for index, row in enumerate(
        getattr(getattr(tables, "MemberRef", None), "rows", ()) or (), 1
    ):
        if index & 0xFF == 0:
            _deadline(deadline, clock)
        parent = getattr(getattr(row, "Class", None), "row", None)
        parent_token = rows.get(id(parent), 0)
        owner = type_names.get(parent_token, method_names.get(parent_token, ""))
        name = _text(getattr(row, "Name", None))
        method_names[0x0A000000 | index] = f"{owner}::{name}" if owner else name
    for index, row in enumerate(
        getattr(getattr(tables, "MethodSpec", None), "rows", ()) or (), 1
    ):
        if index & 0xFF == 0:
            _deadline(deadline, clock)
        target = getattr(getattr(row, "Method", None), "row", None)
        target_token = rows.get(id(target), 0)
        method_names[0x2B000000 | index] = method_names.get(target_token, "")
    return type_names, method_names, field_names


def _method_raw_window(pe: object, data: bytes, rva: int) -> tuple[int, int]:
    matches: list[tuple[int, int]] = []
    for section in pe.sections:
        virtual = int(section.VirtualAddress)
        raw_size = int(section.SizeOfRawData)
        raw_offset = int(section.PointerToRawData)
        delta = rva - virtual
        if 0 <= delta < raw_size:
            start = raw_offset + delta
            available = min(MAX_METHOD_BYTES, raw_size - delta)
            if 0 <= start < start + available <= len(data):
                matches.append((start, start + available))
    if len(matches) != 1:
        raise RecoveryError("method_span_ambiguous_or_unbacked")
    return matches[0]


@contextmanager
def _contained_parser_diagnostics() -> Iterator[None]:
    logger = logging.getLogger("dnfile")
    previous = logger.level
    logger.setLevel(logging.CRITICAL)
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            yield
    finally:
        logger.setLevel(previous)


def _normalize_methods(
    pe: object,
    data: bytes,
    deadline: float,
    clock: Callable[[], float],
) -> list[MethodModel]:
    tables = pe.net.mdtables
    rows = list(getattr(getattr(tables, "MethodDef", None), "rows", ()) or ())
    if not rows or len(rows) > MAX_METHODS:
        raise RecoveryError("method_count_limit")
    metadata_rows = _row_tokens(tables, deadline, clock)
    type_names, method_names, field_names = _metadata_names(
        pe,
        metadata_rows,
        deadline,
        clock,
    )
    method_owner_tokens: dict[int, int] = {}
    exported_type_indices: dict[int, int] = {}
    exported_index = 0
    type_rows = list(getattr(getattr(tables, "TypeDef", None), "rows", ()) or ())
    for type_index, type_row in enumerate(type_rows, 1):
        type_token = 0x02000000 | type_index
        flags = getattr(type_row, "Flags", None)
        if bool(getattr(flags, "tdPublic", False)) or bool(
            getattr(flags, "tdNestedPublic", False)
        ):
            exported_type_indices[type_token] = exported_index
            exported_index += 1
        for reference in getattr(type_row, "MethodList", ()) or ():
            method_row = getattr(reference, "row", None)
            method_token = metadata_rows.get(id(method_row), 0)
            if method_token >> 24 == 6:
                if method_token in method_owner_tokens:
                    raise RecoveryError("method_owner_ambiguous")
                method_owner_tokens[method_token] = type_token
    models: list[MethodModel] = []
    total_bytes = 0
    total_instructions = 0
    for index, row in enumerate(rows, 1):
        _deadline(deadline, clock)
        rva = int(getattr(row, "Rva", 0) or 0)
        if not rva:
            continue
        start, end = _method_raw_window(pe, data, rva)
        try:
            body = read_method_body_from_bytes(data[start:end])
        except MethodBodyFormatError as exc:
            raise RecoveryError("method_body_parse_incomplete") from exc
        body_size = int(body.size)
        if not 0 < body_size <= end - start:
            raise RecoveryError("method_body_bounds")
        instructions = list(body.instructions)
        total_bytes += body_size
        total_instructions += len(instructions)
        if (
            body_size > MAX_METHOD_BYTES
            or total_bytes > MAX_TOTAL_METHOD_BYTES
            or len(instructions) > MAX_METHOD_INSTRUCTIONS
            or total_instructions > MAX_TOTAL_INSTRUCTIONS
        ):
            raise RecoveryError("method_body_budget")
        normalized: list[Instruction] = []
        for item in instructions:
            opcode = str(item.opcode.name)
            value = _operand_value(item.operand)
            token = (
                value
                if value is not None and value >> 24 in {1, 2, 4, 6, 10, 43}
                else None
            )
            user_string = None
            if opcode == "ldstr" and value is not None:
                try:
                    candidate = str(pe.net.user_strings.get(value & 0xFFFFFF))
                except Exception as exc:
                    raise RecoveryError("user_string_unavailable") from exc
                if len(candidate) > MAX_LITERAL_CHARACTERS:
                    raise RecoveryError("user_string_limit")
                user_string = candidate
            resolved = ""
            if token is not None:
                resolved = method_names.get(
                    token, field_names.get(token, type_names.get(token, ""))
                )
            normalized.append(
                Instruction(
                    offset=int(item.offset),
                    opcode=opcode,
                    token=token,
                    resolved=resolved,
                    integer=_integer(opcode, item.operand),
                    user_string=user_string,
                    local=_local(opcode, item.operand),
                )
            )
        token = 0x06000000 | index
        owner_token = method_owner_tokens.get(token, 0)
        if owner_token == 0:
            raise RecoveryError("method_owner_missing")
        raw_signature = getattr(getattr(row, "Signature", None), "value", None)
        if not isinstance(raw_signature, (bytes, bytearray)):
            raise RecoveryError("method_signature_unavailable")
        signature = bytes(raw_signature)
        if not 0 < len(signature) <= MAX_SIGNATURE_BYTES:
            raise RecoveryError("method_signature_bounds")
        flags = getattr(row, "Flags", None)
        owner, _, name = method_names.get(token, "").partition("::")
        models.append(
            MethodModel(
                token=token,
                owner=owner,
                name=name,
                rva=rva,
                body_size=body_size,
                body_sha256=_sha256(data[start : start + body_size]),
                instructions=tuple(normalized),
                owner_token=owner_token,
                owner_export_index=exported_type_indices.get(owner_token),
                signature=signature,
                is_static=bool(getattr(flags, "mdStatic", False)),
                is_public=bool(getattr(flags, "mdPublic", False)),
                is_special_name=bool(getattr(flags, "mdSpecialName", False)),
                is_runtime_special_name=bool(getattr(flags, "mdRTSpecialName", False)),
            )
        )
    return models


def _meaningful(method: MethodModel) -> list[Instruction]:
    return [item for item in method.instructions if item.opcode != "nop"]


def _calls(method: MethodModel) -> list[Instruction]:
    return [
        item
        for item in method.instructions
        if item.opcode in {"call", "callvirt", "newobj"}
    ]


def _call_suffix(method: MethodModel, suffix: str) -> bool:
    return any(item.resolved.endswith(suffix) for item in _calls(method))


def _method_tokens(method: MethodModel, opcode: str) -> list[int]:
    return [
        int(item.token)
        for item in method.instructions
        if item.opcode == opcode and item.token is not None and item.token >> 24 == 6
    ]


def _find_first_rgb_recipe(methods: list[MethodModel]) -> tuple[MethodModel, int]:
    rgb_candidates: list[MethodModel] = []
    for method in methods:
        il = _meaningful(method)
        if (
            [item.opcode for item in il]
            == [
                "ldc.i4.3",
                "newarr",
                "dup",
                "ldc.i4.0",
                "ldarga.s",
                "call",
                "stelem.i1",
                "dup",
                "ldc.i4.1",
                "ldarga.s",
                "call",
                "stelem.i1",
                "dup",
                "ldc.i4.2",
                "ldarga.s",
                "call",
                "stelem.i1",
                "ret",
            ]
            and il[1].resolved == "System.Byte"
            and [il[index].resolved for index in (5, 10, 15)]
            == [
                "System.Drawing.Color::get_R",
                "System.Drawing.Color::get_G",
                "System.Drawing.Color::get_B",
            ]
            and [item.integer for item in il if item.integer is not None]
            == [3, 0, 1, 2]
        ):
            rgb_candidates.append(method)
    if len(rgb_candidates) != 1:
        raise RecoveryError("outer_rgb_lambda_ambiguous")
    rgb = rgb_candidates[0]

    pixel_candidates: list[tuple[MethodModel, int]] = []
    height_candidates: list[tuple[MethodModel, int]] = []
    for method in methods:
        il = _meaningful(method)
        if (
            [item.opcode for item in il]
            == ["ldarg.0", "ldfld", "ldarg.1", "ldarg.2", "callvirt", "ret"]
            and il[1].token is not None
            and il[4].resolved == "System.Drawing.Bitmap::GetPixel"
        ):
            pixel_candidates.append((method, int(il[1].token)))
        if (
            [item.opcode for item in il]
            == ["ldc.i4.0", "ldarg.0", "ldfld", "callvirt", "call", "ret"]
            and il[2].token is not None
            and il[3].resolved == "System.Drawing.Image::get_Height"
            and il[4].resolved == "System.Linq.Enumerable::Range"
        ):
            height_candidates.append((method, int(il[2].token)))

    if len(pixel_candidates) != 1 or len(height_candidates) != 1:
        raise RecoveryError("outer_pixel_or_height_lambda_ambiguous")
    pixel, pixel_field = pixel_candidates[0]
    height, height_field = height_candidates[0]
    if pixel_field != height_field:
        raise RecoveryError("outer_bitmap_field_mismatch")

    main_candidates: list[tuple[MethodModel, int]] = []
    for method in methods:
        il = _meaningful(method)
        if [item.opcode for item in il] != [
            "newobj",
            "stloc.0",
            "ldloc.0",
            "ldarg.0",
            "stfld",
            "ldc.i4.0",
            "ldloc.0",
            "ldfld",
            "callvirt",
            "call",
            "ldloc.0",
            "ldftn",
            "newobj",
            "ldloc.0",
            "ldftn",
            "newobj",
            "call",
            "ldsfld",
            "dup",
            "brtrue.s",
            "pop",
            "ldsfld",
            "ldftn",
            "newobj",
            "dup",
            "stsfld",
            "call",
            "ldarg.1",
            "call",
            "call",
            "stloc.1",
            "br.s",
            "ldloc.1",
            "ret",
        ]:
            continue
        if not (
            il[4].token == il[7].token == pixel_field
            and il[11].token == height.token
            and il[14].token == pixel.token
            and il[22].token == rgb.token
            and il[17].token == il[25].token
            and il[8].resolved == "System.Drawing.Image::get_Width"
            and il[9].resolved == "System.Linq.Enumerable::Range"
            and il[16].resolved == "System.Linq.Enumerable::SelectMany"
            and il[26].resolved == "System.Linq.Enumerable::SelectMany"
            and il[28].resolved == "System.Linq.Enumerable::Take"
            and il[29].resolved
            in {
                "System.Linq.Enumerable::ToArray",
                "System.Linq.Enumerable::ToList",
            }
        ):
            continue
        main_candidates.append((method, pixel_field))
    unique = {(item.token, field): (item, field) for item, field in main_candidates}
    if len(unique) != 1:
        raise RecoveryError("outer_rgb_recipe_ambiguous")
    return next(iter(unique.values()))


def _match_split_arguments(
    method: MethodModel,
    assignments: dict[int, list[str]],
) -> tuple[str, str, str] | None:
    il = _meaningful(method)
    matches: list[tuple[str, str, str]] = []
    for start in range(max(0, len(il) - 31)):
        window = il[start : start + 32]
        if (
            len(window) != 32
            or window[0].opcode != "ldstr"
            or window[0].user_string is None
        ):
            continue
        delimiter = window[0].user_string
        delimiter_local = (
            window[1].local if window[1].opcode.startswith("stloc") else None
        )
        field_token = window[3].token
        split_local = (
            window[12].local if window[12].opcode.startswith("stloc") else None
        )
        args_local = window[31].local if window[31].opcode.startswith("stloc") else None
        if None in {delimiter_local, field_token, split_local, args_local}:
            continue
        checks = (
            window[2].opcode == "ldarg.0",
            window[3].opcode == "ldfld",
            window[4].integer == 1,
            window[5].opcode == "newarr" and window[5].resolved == "System.String",
            window[6].opcode == "dup",
            window[7].integer == 0,
            window[8].opcode.startswith("ldloc") and window[8].local == delimiter_local,
            window[9].opcode == "stelem.ref",
            window[10].integer == 0,
            window[11].opcode == "callvirt"
            and window[11].resolved == "System.String::Split",
            window[13].integer == 3,
            window[14].opcode == "newarr" and window[14].resolved == "System.String",
            window[15].opcode == "dup",
            window[16].integer == 0,
            window[17].opcode.startswith("ldloc") and window[17].local == split_local,
            window[18].integer == 1,
            window[19].opcode == "ldelem.ref",
            window[20].opcode == "stelem.ref",
            window[21].opcode == "dup",
            window[22].integer == 1,
            window[23].opcode.startswith("ldloc") and window[23].local == split_local,
            window[24].integer == 2,
            window[25].opcode == "ldelem.ref",
            window[26].opcode == "stelem.ref",
            window[27].opcode == "dup",
            window[28].integer == 2,
            window[29].opcode.startswith("ldloc")
            and window[29].local == delimiter_local,
            window[30].opcode == "stelem.ref",
        )
        if not all(checks):
            continue
        values = assignments.get(int(field_token), [])
        if len(values) != 1:
            continue
        combined = values[0]
        parts = combined.split(delimiter)
        if (
            not delimiter
            or parts[:1] != [""]
            or parts[3:] != ["", ""]
            or len(parts) != 5
        ):
            continue
        first, second = parts[1], parts[2]
        if not re.fullmatch(r"(?:[0-9A-Fa-f]{2}){1,128}", first) or not re.fullmatch(
            r"(?:[0-9A-Fa-f]{2}){1,128}", second
        ):
            continue
        if start == 0 or not il[start - 1].opcode.startswith("stloc"):
            continue
        exported_type_local = il[start - 1].local
        tail = il[start + 32 : start + 52]
        if len(tail) != 20:
            continue
        constructor_local = tail[14].local
        invoke_argument_local = tail[17].local
        if None in {exported_type_local, constructor_local, invoke_argument_local}:
            continue
        tail_checks = (
            tail[0].opcode.startswith("ldloc") and tail[0].local == exported_type_local,
            tail[1].opcode.startswith("ldloc") and tail[1].local == args_local,
            tail[2].opcode == "ldsfld" and tail[2].token is not None,
            tail[3].opcode == "dup",
            tail[4].opcode == "brtrue.s",
            tail[5].opcode == "pop",
            tail[6].opcode == "ldsfld",
            tail[7].opcode == "ldftn",
            tail[8].opcode == "newobj",
            tail[9].opcode == "dup",
            tail[10].opcode == "stsfld" and tail[10].token == tail[2].token,
            tail[11].opcode == "call"
            and tail[11].resolved == "System.Linq.Enumerable::Select",
            tail[12].opcode == "call"
            and tail[12].resolved == "System.Linq.Enumerable::ToArray",
            tail[13].opcode == "callvirt"
            and tail[13].resolved == "System.Type::GetConstructor",
            tail[14].opcode.startswith("stloc"),
            tail[15].opcode.startswith("ldloc") and tail[15].local == constructor_local,
            tail[16].opcode.startswith("ldloc") and tail[16].local == args_local,
            tail[17].opcode.startswith("stloc"),
            tail[18].opcode.startswith("ldloc")
            and tail[18].local == invoke_argument_local,
            tail[19].opcode == "callvirt"
            and tail[19].resolved == "System.Reflection.ConstructorInfo::Invoke",
        )
        if not all(tail_checks):
            continue
        matches.append((first, second, delimiter))
    return matches[0] if len(matches) == 1 else None


def _bitmap_getter(methods: list[MethodModel], token: int) -> str:
    matches = [method for method in methods if method.token == token]
    if len(matches) != 1:
        raise RecoveryError("outer_bitmap_getter_missing")
    method = matches[0]
    strings = [
        item.user_string for item in method.instructions if item.user_string is not None
    ]
    if len(strings) != 1 or not 0 < len(strings[0]) <= 256:
        raise RecoveryError("outer_bitmap_name_ambiguous")
    if not _call_suffix(
        method, "System.Resources.ResourceManager::GetObject"
    ) or not any(
        item.opcode == "castclass" and item.resolved == "System.Drawing.Bitmap"
        for item in method.instructions
    ):
        raise RecoveryError("outer_bitmap_getter_shape")
    return strings[0]


def _root_recipe(methods: list[MethodModel]) -> RootRecipe:
    rgb_method, _bitmap_field = _find_first_rgb_recipe(methods)

    def reaches_assembly_load(il: list[Instruction], index: int) -> bool:
        window = il[index : index + 21]
        if len(window) != 21:
            return False
        result_local = window[1].local
        assembly_local = window[16].local
        if result_local is None or assembly_local is None:
            return False
        return all(
            (
                window[0].opcode in {"call", "callvirt"}
                and window[0].token == rgb_method.token,
                window[1].opcode.startswith("stloc"),
                window[2].opcode == "call"
                and window[2].resolved == "System.Threading.Thread::GetDomain",
                window[3].opcode == "ldnull",
                window[4].opcode == "ldstr" and window[4].user_string == "Load",
                window[5].integer == 1,
                window[6].opcode == "newarr" and window[6].resolved == "System.Object",
                window[7].opcode == "dup",
                window[8].integer == 0,
                window[9].opcode.startswith("ldloc")
                and window[9].local == result_local,
                window[10].opcode == "call"
                and window[10].resolved == "System.Linq.Enumerable::ToArray",
                window[11].opcode == "stelem.ref",
                window[12].opcode == "ldnull",
                window[13].opcode == "ldnull",
                window[14].opcode == "call"
                and window[14].resolved
                == "Microsoft.VisualBasic.CompilerServices.LateBinding::LateGet",
                window[15].opcode == "castclass"
                and window[15].resolved == "System.Reflection.Assembly",
                window[16].opcode.startswith("stloc"),
                window[17].opcode.startswith("ldloc")
                and window[17].local == assembly_local,
                window[18].opcode == "callvirt"
                and window[18].resolved
                == "System.Reflection.Assembly::GetExportedTypes",
                window[19].integer == 0,
                window[20].opcode == "ldelem.ref",
            )
        )

    assignments: dict[int, list[str]] = {}
    for method in methods:
        if method.name != ".ctor":
            continue
        il = _meaningful(method)
        for index in range(len(il) - 2):
            first, literal, store = il[index : index + 3]
            if (
                first.opcode == "ldarg.0"
                and literal.opcode == "ldstr"
                and literal.user_string is not None
                and store.opcode == "stfld"
                and store.token is not None
            ):
                assignments.setdefault(store.token, []).append(literal.user_string)

    candidates: list[RootRecipe] = []
    for method in methods:
        if not any(
            item.opcode in {"call", "callvirt"} and item.token == rgb_method.token
            for item in method.instructions
        ):
            continue
        if not (
            _call_suffix(method, "System.Reflection.Assembly::GetExportedTypes")
            and _call_suffix(method, "System.Reflection.ConstructorInfo::Invoke")
            and any(item.user_string == "Load" for item in method.instructions)
        ):
            continue
        arguments = _match_split_arguments(method, assignments)
        if arguments is None:
            continue
        il = _meaningful(method)
        callsites: list[tuple[int, int]] = []
        for index, item in enumerate(il):
            if (
                item.opcode not in {"call", "callvirt"}
                or item.token != rgb_method.token
                or index < 2
            ):
                continue
            getter, length = il[index - 2], il[index - 1]
            if (
                getter.opcode == "call"
                and getter.token is not None
                and length.integer is not None
                and reaches_assembly_load(il, index)
            ):
                callsites.append((getter.token, length.integer))
        if len(callsites) != 1:
            continue
        getter_token, output_length = callsites[0]
        if not 0 < output_length <= MAX_OUTPUT_BYTES:
            continue
        bitmap_name = _bitmap_getter(methods, getter_token)
        first, second, namespace = arguments
        candidates.append(
            RootRecipe(
                caller_token=method.token,
                rgb_method_token=rgb_method.token,
                bitmap_getter_token=getter_token,
                first_child_length=output_length,
                first_bitmap_name=bitmap_name,
                resource_argument_hex=first,
                key_argument_hex=second,
                resource_namespace=namespace,
            )
        )
    if len(candidates) != 1:
        raise RecoveryError("outer_constructor_recipe_ambiguous")
    return candidates[0]


def _sequence(
    method: MethodModel, predicates: tuple[Callable[[Instruction], bool], ...]
) -> bool:
    il = _meaningful(method)
    for start in range(len(il) - len(predicates) + 1):
        if all(
            predicate(il[start + offset]) for offset, predicate in enumerate(predicates)
        ):
            return True
    return False


def _loader_recipe(methods: list[MethodModel]) -> LoaderRecipe:
    by_digest: dict[str, list[MethodModel]] = {}
    for method in methods:
        by_digest.setdefault(method.body_sha256, []).append(method)
    selected: dict[str, MethodModel] = {}
    for role, digest in LOADER_METHOD_BODY_SHA256.items():
        matches = by_digest.get(digest, [])
        if len(matches) != 1:
            raise RecoveryError("loader_method_profile_incomplete_or_ambiguous")
        selected[role] = matches[0]

    entry = selected["entry"]
    if (
        entry.owner_token == 0
        or entry.owner_export_index != 0
        or not entry.is_public
        or not entry.is_static
        or entry.signature != b"\x00\x03\x01\x0e\x0e\x0e"
        or any(
            method.owner_token != entry.owner_token or not method.is_static
            for method in selected.values()
        )
    ):
        raise RecoveryError("loader_entry_owner_or_signature_mismatch")
    constructors = [
        method
        for method in methods
        if method.owner_token == entry.owner_token
        and method.owner_export_index == 0
        and method.name == ".ctor"
        and method.is_public
        and not method.is_static
        and method.is_special_name
        and method.is_runtime_special_name
        and method.signature == b"\x20\x03\x01\x0e\x0e\x0e"
        and _sequence(
            method,
            (
                lambda item: item.opcode == "ldarg.1",
                lambda item: item.opcode == "ldarg.2",
                lambda item: item.opcode == "ldarg.3",
                lambda item: (
                    item.opcode in {"call", "callvirt"} and item.token == entry.token
                ),
            ),
        )
    ]
    if len(constructors) != 1:
        raise RecoveryError("loader_constructor_entry_link_ambiguous")

    required_calls = {
        "resource_lookup": (
            "System.Reflection.Assembly::GetEntryAssembly",
            "System.Resources.ResourceManager::.ctor",
            "System.Resources.ResourceManager::GetObject",
        ),
        "crop_bitmap": (
            "System.Drawing.Image::get_Width",
            "System.Drawing.Image::get_Height",
            "System.Drawing.Bitmap::GetPixel",
            "System.Drawing.Bitmap::SetPixel",
        ),
        "argb_bytes": (
            "System.Drawing.Bitmap::GetPixel",
            "System.Drawing.Color::ToArgb",
            "System.BitConverter::GetBytes",
            "System.BitConverter::ToInt32",
            "System.Array::Copy",
        ),
        "key_bytes": (
            "System.Text.Encoding::get_BigEndianUnicode",
            "System.Text.Encoding::GetBytes",
        ),
        "hex_text": (
            "System.String::Substring",
            "System.Convert::ToInt32",
            "System.Text.StringBuilder::Append",
        ),
        "assembly_load": ("System.Reflection.Assembly::Load",),
    }
    for role, suffixes in required_calls.items():
        if not all(_call_suffix(selected[role], suffix) for suffix in suffixes):
            raise RecoveryError("loader_framework_reference_mismatch")
    if [
        item.user_string
        for item in selected["resource_lookup"].instructions
        if item.user_string is not None
    ] != [".Properties.Resources"]:
        raise RecoveryError("loader_resource_suffix_mismatch")

    def calls_role(source: str, target: str) -> bool:
        token = selected[target].token
        return any(
            item.opcode in {"call", "callvirt"} and item.token == token
            for item in selected[source].instructions
        )

    edges = (
        ("entry", "decode_resource_argument"),
        ("entry", "decode_key_argument"),
        ("entry", "resource_wrapper"),
        ("entry", "crop_and_argb"),
        ("entry", "xor_wrapper"),
        ("entry", "load_wrapper"),
        ("entry", "invoke_wrapper"),
        ("decode_resource_argument", "hex_text"),
        ("decode_key_argument", "hex_text"),
        ("resource_wrapper", "resource_lookup"),
        ("crop_and_argb", "crop_bitmap"),
        ("crop_and_argb", "argb_bytes"),
        ("xor_wrapper", "key_bytes"),
        ("xor_wrapper", "mask"),
        ("xor_wrapper", "xor_loop"),
        ("xor_wrapper", "drop_sentinel"),
        ("xor_loop", "key_index"),
        ("load_wrapper", "assembly_load"),
        ("invoke_wrapper", "invoke_target"),
    )
    if not all(calls_role(source, target) for source, target in edges):
        raise RecoveryError("loader_call_graph_mismatch")
    if not _call_suffix(selected["xor_wrapper"], "System.String::get_Length"):
        raise RecoveryError("loader_key_period_dataflow_mismatch")
    if sum(item.opcode == "xor" for item in selected["xor_loop"].instructions) < 2:
        raise RecoveryError("loader_xor_shape_mismatch")

    crop_method = selected["crop_and_argb"]
    crop_matches: list[tuple[int, int]] = []
    il = _meaningful(crop_method)
    for index in range(len(il) - 4):
        window = il[index : index + 5]
        if (
            window[0].opcode == "ldarg.0"
            and window[1].integer is not None
            and window[2].integer is not None
            and window[3].opcode in {"call", "callvirt"}
            and window[3].token == selected["crop_bitmap"].token
            and window[4].opcode in {"call", "callvirt"}
            and window[4].token == selected["argb_bytes"].token
        ):
            crop_matches.append((window[1].integer, window[2].integer))
    if len(crop_matches) != 1:
        raise RecoveryError("loader_crop_constants_ambiguous")
    crop_right, crop_bottom = crop_matches[0]
    if (
        not 0 <= crop_right < MAX_IMAGE_DIMENSION
        or not 0 <= crop_bottom < MAX_IMAGE_DIMENSION
    ):
        raise RecoveryError("loader_crop_constants_bounds")

    mask_method = selected["mask"]
    mask_values = {
        item.integer
        for item in mask_method.instructions
        if item.integer is not None and 0 <= item.integer <= 255
    }
    if 112 not in mask_values or not _sequence(
        mask_method,
        (
            lambda item: item.opcode.startswith("ldloc"),
            lambda item: item.integer == 112,
            lambda item: item.opcode == "xor",
        ),
    ):
        raise RecoveryError("loader_mask_constant_mismatch")
    return LoaderRecipe(
        crop_right=crop_right,
        crop_bottom=crop_bottom,
        mask_xor=112,
        method_tokens={role: method.token for role, method in selected.items()},
        constructor_token=constructors[0].token,
    )


class _Reader:
    def __init__(self, data: bytes):
        self.data = data
        self.offset = 0

    def take(self, size: int) -> bytes:
        if size < 0 or self.offset > len(self.data) - size:
            raise RecoveryError("nrbf_truncated")
        value = self.data[self.offset : self.offset + size]
        self.offset += size
        return value

    def u8(self) -> int:
        return self.take(1)[0]

    def i32(self) -> int:
        return struct.unpack("<i", self.take(4))[0]

    def u7(self) -> int:
        value = 0
        for index, shift in enumerate(range(0, 35, 7)):
            byte = self.u8()
            if index == 4 and byte > 0x0F:
                raise RecoveryError("nrbf_7bit_integer_invalid")
            value |= (byte & 0x7F) << shift
            if not byte & 0x80:
                if index and value < 1 << (index * 7):
                    raise RecoveryError("nrbf_7bit_integer_noncanonical")
                return value
        raise RecoveryError("nrbf_7bit_integer_invalid")

    def string(self, *, maximum: int = 1_024) -> str:
        size = self.u7()
        if not 0 <= size <= maximum:
            raise RecoveryError("nrbf_string_limit")
        try:
            return self.take(size).decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise RecoveryError("nrbf_string_invalid_utf8") from exc


def _parse_bitmap_nrbf(data: bytes) -> bytes:
    """限定System.Drawing.Bitmap NRBFからbyte[]だけを完全走査して返す。"""

    if type(data) is not bytes or not 0 < len(data) <= MAX_RESOURCE_BYTES:
        raise RecoveryError("nrbf_input_bounds")
    reader = _Reader(data)
    resource_type_code = reader.u7()
    if resource_type_code < 64:
        raise RecoveryError("nrbf_resource_type_code")
    if reader.u8() != 0:
        raise RecoveryError("nrbf_stream_header_record")
    root_id = reader.i32()
    header_id = reader.i32()
    major = reader.i32()
    minor = reader.i32()
    if root_id <= 0 or header_id != -1 or (major, minor) != (1, 0):
        raise RecoveryError("nrbf_stream_header_values")
    if reader.u8() != 12:
        raise RecoveryError("nrbf_library_record")
    library_id = reader.i32()
    if (
        library_id <= 0
        or library_id == root_id
        or reader.string() != SYSTEM_DRAWING_IDENTITY
    ):
        raise RecoveryError("nrbf_library_identity")
    if reader.u8() != 5:
        raise RecoveryError("nrbf_class_record")
    object_id = reader.i32()
    if object_id != root_id or reader.string() != "System.Drawing.Bitmap":
        raise RecoveryError("nrbf_bitmap_class_identity")
    if reader.i32() != 1 or reader.string(maximum=64) != "Data":
        raise RecoveryError("nrbf_bitmap_member_shape")
    if reader.u8() != 7 or reader.u8() != 2 or reader.i32() != library_id:
        raise RecoveryError("nrbf_bitmap_member_type")
    if reader.u8() != 9:
        raise RecoveryError("nrbf_member_reference")
    array_reference = reader.i32()
    if array_reference <= 0 or array_reference in {object_id, library_id}:
        raise RecoveryError("nrbf_array_reference")
    if reader.u8() != 15:
        raise RecoveryError("nrbf_array_record")
    if reader.i32() != array_reference:
        raise RecoveryError("nrbf_array_object_id")
    size = reader.i32()
    if not 0 < size <= MAX_BITMAP_BYTES or reader.u8() != 2:
        raise RecoveryError("nrbf_byte_array_bounds_or_type")
    payload = reader.take(size)
    if reader.u8() != 11 or reader.offset != len(data):
        raise RecoveryError("nrbf_message_end_or_trailing")
    return payload


def _resource_entries(
    pe: object, deadline: float, clock: Callable[[], float]
) -> list[ResourceEntry]:
    resources = list(getattr(pe.net, "resources", ()) or ())
    if len(resources) > MAX_RESOURCE_SETS:
        raise RecoveryError("resource_set_count_limit")
    result: list[ResourceEntry] = []
    total_entries = 0
    total_bytes = 0
    for resource in resources:
        _deadline(deadline, clock)
        resource_set = getattr(resource, "data", None)
        entries = list(getattr(resource_set, "entries", ()) or ())
        raw_value = getattr(resource_set, "_data", None)
        if not entries:
            continue
        if not isinstance(raw_value, (bytes, bytearray)):
            raise RecoveryError("resource_set_raw_data_unavailable")
        raw = bytes(raw_value)
        total_entries += len(entries)
        total_bytes += len(raw)
        if total_entries > MAX_RESOURCE_ENTRIES or total_bytes > MAX_RESOURCE_BYTES:
            raise RecoveryError("resource_inventory_budget")
        header = getattr(resource_set, "struct", None)
        base = int(getattr(header, "DataSectionOffset", 0) or 0)
        offsets: list[int] = []
        for entry_index, entry in enumerate(entries):
            if entry_index & 0xFF == 0:
                _deadline(deadline, clock)
            value = int(getattr(getattr(entry, "struct", None), "DataOffset", -1))
            start = base + value
            if value < 0 or not 0 <= start < len(raw):
                raise RecoveryError("resource_entry_offset_bounds")
            offsets.append(start)
        if len(set(offsets)) != len(offsets):
            raise RecoveryError("resource_entry_offset_ambiguous")
        sorted_offsets = sorted(offsets)
        for entry_index, (entry, start) in enumerate(
            zip(entries, offsets, strict=True)
        ):
            if entry_index & 0xFF == 0:
                _deadline(deadline, clock)
            later = [offset for offset in sorted_offsets if offset > start]
            end = min(later) if later else len(raw)
            if not start < end <= len(raw):
                raise RecoveryError("resource_entry_bounds")
            name = _text(getattr(entry, "name", None))
            type_name = _text(getattr(entry, "type_name", None))
            resource_name = _text(getattr(resource, "name", None))
            if not name or not type_name or not resource_name:
                raise RecoveryError("resource_entry_identity_missing")
            result.append(ResourceEntry(resource_name, name, type_name, raw[start:end]))
    return result


def _find_bitmap_entry(
    entries: list[ResourceEntry],
    *,
    resource_set_name: str | None,
    entry_name: str,
) -> ResourceEntry:
    matches = [
        entry
        for entry in entries
        if entry.entry_name == entry_name
        and entry.type_name == "System.Drawing.Bitmap"
        and (resource_set_name is None or entry.resource_set_name == resource_set_name)
    ]
    if len(matches) != 1:
        raise RecoveryError("bitmap_resource_entry_ambiguous")
    return matches[0]


def _bmp_rgb_take(
    data: bytes,
    take: int,
    deadline: float,
    clock: Callable[[], float],
) -> tuple[bytes, dict[str, int | bool]]:
    if (
        type(data) is not bytes
        or not 54 <= len(data) <= MAX_BITMAP_BYTES
        or data[:2] != b"BM"
    ):
        raise RecoveryError("bmp_header_missing")
    declared_size = struct.unpack_from("<I", data, 2)[0]
    pixel_offset = struct.unpack_from("<I", data, 10)[0]
    dib_size = struct.unpack_from("<I", data, 14)[0]
    width, signed_height = struct.unpack_from("<ii", data, 18)
    planes, bits = struct.unpack_from("<HH", data, 26)
    compression = struct.unpack_from("<I", data, 30)[0]
    if (
        declared_size != len(data)
        or dib_size != 40
        or not 0 < width <= MAX_IMAGE_DIMENSION
        or signed_height == 0
        or abs(signed_height) > MAX_IMAGE_DIMENSION
        or planes != 1
        or bits not in {24, 32}
        or compression != 0
    ):
        raise RecoveryError("bmp_shape_unsupported")
    height = abs(signed_height)
    pixels = width * height
    if pixels > MAX_IMAGE_PIXELS:
        raise RecoveryError("bmp_pixel_limit")
    stride = ((width * bits + 31) // 32) * 4
    if pixel_offset < 54 or pixel_offset + stride * height != len(data):
        raise RecoveryError("bmp_pixel_extent")
    if not 0 < take <= pixels * 3 or take > MAX_OUTPUT_BYTES:
        raise RecoveryError("outer_rgb_take_bounds")
    bytes_per_pixel = bits // 8
    output = bytearray()
    for x in range(width):
        _deadline(deadline, clock)
        for y in range(height):
            file_y = height - 1 - y if signed_height > 0 else y
            offset = pixel_offset + file_y * stride + x * bytes_per_pixel
            blue, green, red = data[offset : offset + 3]
            output.extend((red, green, blue))
            if len(output) >= take:
                return bytes(output[:take]), {
                    "width": width,
                    "height": height,
                    "bits_per_pixel": bits,
                    "pixel_count": pixels,
                }
    raise RecoveryError("outer_rgb_take_incomplete")


def _paeth(left: int, above: int, upper_left: int) -> int:
    prediction = left + above - upper_left
    left_distance = abs(prediction - left)
    above_distance = abs(prediction - above)
    upper_left_distance = abs(prediction - upper_left)
    if left_distance <= above_distance and left_distance <= upper_left_distance:
        return left
    return above if above_distance <= upper_left_distance else upper_left


def _decode_rgba_png(
    data: bytes,
    deadline: float,
    clock: Callable[[], float],
) -> tuple[int, int, bytes, dict[str, object]]:
    if (
        type(data) is not bytes
        or not len(PNG_MAGIC) + 25 <= len(data) <= MAX_BITMAP_BYTES
    ):
        raise RecoveryError("png_input_bounds")
    if not data.startswith(PNG_MAGIC):
        raise RecoveryError("png_signature_missing")
    offset = len(PNG_MAGIC)
    chunk_count = 0
    saw_ihdr = False
    saw_idat = False
    idat_closed = False
    width = height = 0
    compressed = bytearray()
    while offset < len(data):
        _deadline(deadline, clock)
        if chunk_count >= MAX_PNG_CHUNKS or offset + 12 > len(data):
            raise RecoveryError("png_chunk_count_or_bounds")
        size = struct.unpack_from(">I", data, offset)[0]
        kind = data[offset + 4 : offset + 8]
        if size > MAX_PNG_CHUNK_BYTES or not all(
            65 <= value <= 90 or 97 <= value <= 122 for value in kind
        ):
            raise RecoveryError("png_chunk_shape")
        payload_start = offset + 8
        payload_end = payload_start + size
        crc_end = payload_end + 4
        if payload_end < payload_start or crc_end > len(data):
            raise RecoveryError("png_chunk_bounds")
        payload = data[payload_start:payload_end]
        expected_crc = struct.unpack_from(">I", data, payload_end)[0]
        if zlib.crc32(kind + payload) & 0xFFFFFFFF != expected_crc:
            raise RecoveryError("png_crc_mismatch")
        chunk_count += 1
        if chunk_count == 1 and kind != b"IHDR":
            raise RecoveryError("png_ihdr_not_first")
        if kind == b"IHDR":
            if saw_ihdr or size != 13:
                raise RecoveryError("png_ihdr_invalid")
            width, height, depth, color, compression, filtering, interlace = (
                struct.unpack(">IIBBBBB", payload)
            )
            if (
                not 0 < width <= MAX_IMAGE_DIMENSION
                or not 0 < height <= MAX_IMAGE_DIMENSION
                or width * height > MAX_IMAGE_PIXELS
                or (depth, color, compression, filtering, interlace) != (8, 6, 0, 0, 0)
            ):
                raise RecoveryError("png_rgba_shape_unsupported")
            saw_ihdr = True
        elif kind == b"IDAT":
            if not saw_ihdr or idat_closed:
                raise RecoveryError("png_idat_order")
            saw_idat = True
            if len(compressed) > MAX_PNG_COMPRESSED_BYTES - len(payload):
                raise RecoveryError("png_compressed_byte_limit")
            compressed.extend(payload)
        elif kind == b"IEND":
            if size != 0 or not saw_idat or crc_end != len(data):
                raise RecoveryError("png_iend_or_trailing")
            offset = crc_end
            break
        else:
            if saw_idat:
                idat_closed = True
            if kind[0] & 0x20 == 0:
                raise RecoveryError("png_unknown_critical_chunk")
        offset = crc_end
    if offset != len(data) or not saw_ihdr or not saw_idat or width <= 0 or height <= 0:
        raise RecoveryError("png_incomplete")

    row_bytes = width * 4
    expected_size = height * (row_bytes + 1)
    if expected_size > MAX_IMAGE_BYTES:
        raise RecoveryError("png_decompressed_byte_limit")
    inflater = zlib.decompressobj()
    filtered = inflater.decompress(bytes(compressed), expected_size + 1)
    if (
        len(filtered) != expected_size
        or not inflater.eof
        or inflater.unused_data
        or inflater.unconsumed_tail
    ):
        raise RecoveryError("png_zlib_size_or_eof")
    output = bytearray(width * height * 4)
    previous = bytearray(row_bytes)
    filter_counts: Counter[int] = Counter()
    source = 0
    destination = 0
    for _row in range(height):
        _deadline(deadline, clock)
        filter_type = filtered[source]
        source += 1
        if filter_type > 4:
            raise RecoveryError("png_filter_unsupported")
        filter_counts[filter_type] += 1
        encoded = filtered[source : source + row_bytes]
        source += row_bytes
        row = bytearray(row_bytes)
        for index, value in enumerate(encoded):
            left = row[index - 4] if index >= 4 else 0
            above = previous[index]
            upper_left = previous[index - 4] if index >= 4 else 0
            if filter_type == 0:
                predictor = 0
            elif filter_type == 1:
                predictor = left
            elif filter_type == 2:
                predictor = above
            elif filter_type == 3:
                predictor = (left + above) // 2
            else:
                predictor = _paeth(left, above, upper_left)
            row[index] = (value + predictor) & 0xFF
        output[destination : destination + row_bytes] = row
        destination += row_bytes
        previous = row
    return (
        width,
        height,
        bytes(output),
        {
            "chunk_count": chunk_count,
            "idat_size": len(compressed),
            "filtered_size": len(filtered),
            "filter_counts": {
                str(key): value for key, value in sorted(filter_counts.items())
            },
        },
    )


def _decode_hex_text(value: str) -> str:
    if not re.fullmatch(r"(?:[0-9A-Fa-f]{2}){1,128}", value):
        raise RecoveryError("constructor_hex_argument_invalid")
    decoded = bytes.fromhex(value)
    return "".join(chr(byte) for byte in decoded)


def _argb_xor_transform(
    rgba: bytes,
    width: int,
    height: int,
    *,
    crop_right: int,
    crop_bottom: int,
    key_text: str,
    mask_xor: int,
    deadline: float,
    clock: Callable[[], float],
) -> tuple[bytes, dict[str, int]]:
    if (
        type(rgba) is not bytes
        or len(rgba) != width * height * 4
        or not 0 <= crop_right < width
        or not 0 <= crop_bottom < height
        or not 0 < len(key_text) <= 128
        or not 0 <= mask_xor <= 255
    ):
        raise RecoveryError("argb_xor_model_bounds")
    cropped_width = width - crop_right
    cropped_height = height - crop_bottom
    if (
        cropped_width != cropped_height
        or cropped_width * cropped_height > MAX_IMAGE_PIXELS
    ):
        raise RecoveryError("argb_crop_not_square_or_too_large")
    stream_size = cropped_width * cropped_height * 4
    if stream_size > MAX_IMAGE_BYTES:
        raise RecoveryError("argb_stream_byte_limit")
    stream = bytearray(stream_size)
    position = 0
    for x in range(cropped_width):
        _deadline(deadline, clock)
        for y in range(cropped_height):
            source = (y * width + x) * 4
            red, green, blue, alpha = rgba[source : source + 4]
            stream[position : position + 4] = bytes((blue, green, red, alpha))
            position += 4
    if len(stream) < 5:
        raise RecoveryError("argb_stream_too_short")
    declared = struct.unpack_from("<i", stream)[0]
    if not 0 < declared <= MAX_OUTPUT_BYTES or declared > len(stream) - 4:
        raise RecoveryError("argb_declared_length_bounds")
    key_bytes = key_text.encode("utf-16-be", errors="strict")
    period = len(key_text)
    if period > len(key_bytes):
        raise RecoveryError("argb_key_period_bounds")
    encoded_start = 4
    encoded_end = encoded_start + declared
    mask = stream[encoded_end - 1] ^ mask_xor
    for index in range(declared):
        if index & 0xFFFF == 0:
            _deadline(deadline, clock)
        stream[encoded_start + index] ^= mask ^ key_bytes[index % period]
    decoded = bytes(stream[encoded_start:encoded_end])
    return decoded, {
        "cropped_width": cropped_width,
        "cropped_height": cropped_height,
        "argb_stream_size": len(stream),
        "declared_output_size": declared,
        "unused_argb_bytes": len(stream) - 4 - declared,
        "key_text_length": len(key_text),
        "key_byte_length": len(key_bytes),
        "key_period": period,
        "mask_constant_verified": True,
    }


def _parse_managed(
    data: bytes,
    deadline: float,
    clock: Callable[[], float],
) -> tuple[object, list[MethodModel], dict[str, object]]:
    preflight = preflight_clr_declarations(data, max_input_bytes=MAX_INPUT_BYTES)
    if preflight.get("accepted") is not True:
        raise RecoveryError("metadata_preflight_rejected")
    _deadline(deadline, clock)
    with _contained_parser_diagnostics():
        pe = dnfile.dnPE(data=data, clr_lazy_load=False)
    if getattr(pe, "net", None) is None or getattr(pe.net, "mdtables", None) is None:
        raise RecoveryError("managed_metadata_unavailable")
    return pe, _normalize_methods(pe, data, deadline, clock), preflight


def recover_managed_bitmap_argb_xor(
    data: bytes,
    *,
    clock: Callable[[], float] = time.monotonic,
) -> tuple[dict[str, object], list[tuple[str, bytes]]]:
    """outerから二段目 ``Assembly.Load`` 入力を有界な静的解析だけで復元する。"""

    report = _base_report(len(data) if type(data) is bytes else 0)
    if type(data) is not bytes or not 0 < len(data) <= MAX_INPUT_BYTES:
        report.update(status="rejected", reason="input_bounds")
        return report, []
    if not all(
        marker in data
        for marker in (b"System.Drawing.Bitmap", b"GetPixel", b"GetExportedTypes")
    ):
        report.update(reason="outer_marker_prefilter_not_matched")
        return report, []
    deadline = clock() + MAX_ELAPSED_SECONDS
    try:
        root_pe, root_methods, root_preflight = _parse_managed(data, deadline, clock)
        root_recipe = _root_recipe(root_methods)
        root_entries = _resource_entries(root_pe, deadline, clock)

        first_entry = _find_bitmap_entry(
            root_entries,
            resource_set_name=None,
            entry_name=root_recipe.first_bitmap_name,
        )
        first_bitmap = _parse_bitmap_nrbf(first_entry.data)
        first_child, first_bitmap_shape = _bmp_rgb_take(
            first_bitmap,
            root_recipe.first_child_length,
            deadline,
            clock,
        )
        first_extent = inspect_structural_pe_extent(
            first_child,
            max_extent=MAX_OUTPUT_BYTES,
        )
        if first_extent.extent != len(first_child) or not has_clr_metadata(first_child):
            raise RecoveryError("first_child_managed_pe_boundary")

        _first_pe, first_methods, first_preflight = _parse_managed(
            first_child,
            deadline,
            clock,
        )
        loader_recipe = _loader_recipe(first_methods)
        resource_name = _decode_hex_text(root_recipe.resource_argument_hex)
        key_text = _decode_hex_text(root_recipe.key_argument_hex)
        resource_set_name = (
            root_recipe.resource_namespace + ".Properties.Resources.resources"
        )
        nested_entry = _find_bitmap_entry(
            root_entries,
            resource_set_name=resource_set_name,
            entry_name=resource_name,
        )
        png = _parse_bitmap_nrbf(nested_entry.data)
        width, height, rgba, png_shape = _decode_rgba_png(
            png,
            deadline,
            clock,
        )
        load_input, transform = _argb_xor_transform(
            rgba,
            width,
            height,
            crop_right=loader_recipe.crop_right,
            crop_bottom=loader_recipe.crop_bottom,
            key_text=key_text,
            mask_xor=loader_recipe.mask_xor,
            deadline=deadline,
            clock=clock,
        )
        extent_result = inspect_structural_pe_extent(
            load_input,
            max_extent=MAX_OUTPUT_BYTES,
        )
        extent = extent_result.extent
        if extent is None or not 0 < extent <= len(load_input):
            raise RecoveryError("decoded_pe_extent_invalid")
        overlay = load_input[extent:]
        child = load_input[:extent]
        if len(overlay) > MAX_OVERLAY_BYTES or not has_clr_metadata(child):
            raise RecoveryError("decoded_managed_pe_or_overlay_invalid")
        child_preflight = preflight_clr_declarations(
            child, max_input_bytes=MAX_OUTPUT_BYTES
        )
        if child_preflight.get("accepted") is not True:
            raise RecoveryError("decoded_metadata_preflight_rejected")
        _deadline(deadline, clock)

        report.update(
            status="recovered_managed_pe",
            sample_sha256=_sha256(data),
            root_metadata_preflight=root_preflight,
            first_child_metadata_preflight=first_preflight,
            decoded_child_metadata_preflight=child_preflight,
            static_lineage={
                "outer_sha256": _sha256(data),
                "outer_size": len(data),
                "first_transform": "bitmap-rgb-x-major-take",
                "first_child_sha256": _sha256(first_child),
                "first_child_size": len(first_child),
                "second_transform": "bitmap-nrbf-png-crop-argb-xor",
                "assembly_load_input_sha256": _sha256(load_input),
                "assembly_load_input_size": len(load_input),
                "managed_pe_sha256": _sha256(child),
                "managed_pe_size": len(child),
                "overlay_size": len(overlay),
                "overlay_content_returned": False,
                "lineage_complete_to_assembly_load_input": True,
            },
            outer_recipe={
                "caller_token": f"0x{root_recipe.caller_token:08x}",
                "rgb_method_token": f"0x{root_recipe.rgb_method_token:08x}",
                "bitmap_getter_token": f"0x{root_recipe.bitmap_getter_token:08x}",
                "first_child_length": root_recipe.first_child_length,
                "constructor_argument_count": 3,
                "resource_argument_length": len(root_recipe.resource_argument_hex),
                "key_argument_length": len(root_recipe.key_argument_hex),
                "namespace_argument_length": len(root_recipe.resource_namespace),
                "raw_constructor_arguments_returned": False,
                "constructor_argument_hashes_returned": False,
            },
            loader_recipe={
                "profile_id": LOADER_PROFILE_ID,
                "method_body_sha256": dict(sorted(LOADER_METHOD_BODY_SHA256.items())),
                "method_tokens": {
                    role: f"0x{token:08x}"
                    for role, token in sorted(loader_recipe.method_tokens.items())
                },
                "constructor_token": f"0x{loader_recipe.constructor_token:08x}",
                "crop_right": loader_recipe.crop_right,
                "crop_bottom": loader_recipe.crop_bottom,
                "mask_constant_verified": True,
                "mask_constant_returned": False,
                "scan_order": "x-major-y-minor",
                "pixel_byte_order": "BGRA-from-Color.ToArgb-little-endian",
                "key_encoding": "UTF-16BE",
                "key_period_source": "decoded-key-string-length",
                "framework_references_verified": True,
                "call_graph_verified": True,
                "first_exported_type_constructor_verified": True,
            },
            resources={
                "first_resource_entry_sha256": _sha256(first_entry.data),
                "first_bitmap_sha256": _sha256(first_bitmap),
                "first_bitmap_size": len(first_bitmap),
                "first_bitmap_shape": first_bitmap_shape,
                "nested_resource_entry_sha256": _sha256(nested_entry.data),
                "png_sha256": _sha256(png),
                "png_size": len(png),
                "png_width": width,
                "png_height": height,
                "png_shape": png_shape,
                "nrbf_fully_consumed": True,
                "binaryformatter_runtime_used": False,
                "raw_names_returned": False,
                "name_hashes_returned": False,
            },
            transform=transform,
            assembly_load_input={
                "sha256": _sha256(load_input),
                "size": len(load_input),
                "content_in_report": False,
                "static_sink_verified": True,
                "retained_as_private_artifact": True,
            },
            structural_pe={
                "sha256": _sha256(child),
                "size": len(child),
                "format": "managed-pe",
                "pe_extent_reason": extent_result.reason,
                "content_returned_in_report": False,
                "retained_separately": False,
            },
            candidate_only=True,
            assembly_load_input_statically_reconstructed=True,
            private_recursive_artifact_returned=True,
            family_attribution_allowed=False,
            c2_confirmation_allowed=False,
            terminal_promotion_eligible=False,
        )
        return report, [("managed-bitmap-argb-xor-load-input", load_input)]
    except RecoveryError as exc:
        report.update(status="rejected", reason=str(exc))
        return report, []
    except (
        AttributeError,
        IndexError,
        KeyError,
        OverflowError,
        PEFormatError,
        struct.error,
        TypeError,
        ValueError,
        zlib.error,
    ):
        report.update(status="rejected", reason="invalid_static_recipe_structure")
        return report, []


__all__ = [
    "LOADER_METHOD_BODY_SHA256",
    "LOADER_PROFILE_ID",
    "MAX_ELAPSED_SECONDS",
    "RecoveryError",
    "recover_managed_bitmap_argb_xor",
]
