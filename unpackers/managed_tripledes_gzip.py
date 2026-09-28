"""明示CILのresource→TripleDES→長さ付きGZip→Assembly.Loadを静的復元する。

検体、CLR、CIL、復元PEを実行しない。CPU emulation、外部通信、file書込みも行わない。
literalとlocalの限定的な定義・使用をparseし、正常系CFG上の支配関係を確認する。
"""

from __future__ import annotations

import base64
import hashlib
import re
import struct
import time
import zlib
from collections import Counter
from itertools import pairwise

import dnfile
from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
from cryptography.hazmat.primitives.ciphers import Cipher, modes
from dncil.cil.body.reader import read_method_body_from_bytes
from dncil.cil.error import MethodBodyFormatError
from pefile import PEFormatError

from extractors.managed_pe import has_clr_metadata
from unpackers.bounded_pe_scan import inspect_structural_pe_extent
from unpackers.managed_metadata import MetadataResolver

MAX_INPUT = 32 << 20
MAX_RESOURCE = 4 << 20
MAX_OUTPUT = 8 << 20
MAX_METHODS = 4096
MAX_METHOD_BYTES = 256 << 10
MAX_METHOD_INSTRUCTIONS = 4096
MAX_TOTAL_METHOD_BYTES = 2 << 20
MAX_SECONDS = 10.0
MAX_REFERENCE_ROWS = 16384
MAX_API_SIGNATURE_BYTES = 1024
MAX_API_SIGNATURE_ITEMS = 64
MAX_API_SIGNATURE_DEPTH = 3

# framework APIの完全な呼出signatureだけを解釈する。sample内同名methodは対象外。
_API_SIGNATURES = {
    "System.Reflection.Assembly::GetManifestResourceStream": {
        (True, "System.IO.Stream", ("System.String",))
    },
    "System.IO.Stream::get_Length": {(True, "System.Int64", ())},
    "System.IO.Stream::Read": {
        (True, "System.Int32", ("System.Byte[]", "System.Int32", "System.Int32"))
    },
    "System.Convert::FromBase64String": {(False, "System.Byte[]", ("System.String",))},
    "System.Security.Cryptography.TripleDES::Create": {
        (False, "System.Security.Cryptography.TripleDES", ())
    },
    "System.Security.Cryptography.SymmetricAlgorithm::set_Key": {
        (True, "System.Void", ("System.Byte[]",))
    },
    "System.Security.Cryptography.SymmetricAlgorithm::set_IV": {
        (True, "System.Void", ("System.Byte[]",))
    },
    "System.Security.Cryptography.SymmetricAlgorithm::set_Mode": {
        (True, "System.Void", ("System.Security.Cryptography.CipherMode",))
    },
    "System.Security.Cryptography.SymmetricAlgorithm::set_Padding": {
        (True, "System.Void", ("System.Security.Cryptography.PaddingMode",))
    },
    "System.Security.Cryptography.SymmetricAlgorithm::CreateDecryptor": {
        (True, "System.Security.Cryptography.ICryptoTransform", ())
    },
    "System.Security.Cryptography.ICryptoTransform::TransformFinalBlock": {
        (True, "System.Byte[]", ("System.Byte[]", "System.Int32", "System.Int32"))
    },
    "System.IO.MemoryStream::.ctor": {
        (True, "System.Void", ()),
        (True, "System.Void", ("System.Byte[]",)),
        (True, "System.Void", ("System.Byte[]", "System.Int32", "System.Int32")),
    },
    "System.Security.Cryptography.CryptoStream::.ctor": {
        (
            True,
            "System.Void",
            (
                "System.IO.Stream",
                "System.Security.Cryptography.ICryptoTransform",
                "System.Security.Cryptography.CryptoStreamMode",
            ),
        )
    },
    "System.IO.Stream::CopyTo": {(True, "System.Void", ("System.IO.Stream",))},
    "System.IO.MemoryStream::ToArray": {(True, "System.Byte[]", ())},
    "System.IO.Compression.GZipStream::.ctor": {
        (
            True,
            "System.Void",
            ("System.IO.Stream", "System.IO.Compression.CompressionMode"),
        )
    },
    "System.IO.Stream::Write": {
        (True, "System.Void", ("System.Byte[]", "System.Int32", "System.Int32"))
    },
    "System.Reflection.Assembly::Load": {
        (False, "System.Reflection.Assembly", ("System.Byte[]",))
    },
    "System.IDisposable::Dispose": {(True, "System.Void", ())},
}

# classic .NETの型配置を限定する。modern facadeやtype forwardingは未レビュー。
_CLASSIC_ASSEMBLY_PAIRS = {
    ("mscorlib", bytes.fromhex("b77a5c561934e089")),
    ("System", bytes.fromhex("b77a5c561934e089")),
}
_CLASSIC_VERSIONS = {(2, 0, 0, 0), (4, 0, 0, 0)}
_SYSTEM_TYPES = {
    "System.IO.Compression.GZipStream", "System.IO.Compression.CompressionMode",
}
_VALUE_TYPES = {
    "System.Security.Cryptography.CipherMode", "System.Security.Cryptography.PaddingMode",
    "System.Security.Cryptography.CryptoStreamMode", "System.IO.Compression.CompressionMode",
}
_CLASSIC_TYPES = {
    "System.Byte", "System.Reflection.Assembly", "System.IO.Stream", "System.Convert",
    "System.Security.Cryptography.TripleDES", "System.Security.Cryptography.SymmetricAlgorithm",
    "System.Security.Cryptography.ICryptoTransform", "System.IO.MemoryStream",
    "System.Security.Cryptography.CryptoStream", "System.IDisposable",
    *_SYSTEM_TYPES, *_VALUE_TYPES,
}


class RecipeError(ValueError):
    """未知のdataflowや上限超過を安全側へ拒否する。"""


def _signature(blob, references, *, type_versions=None, expected_version=None):
    if not isinstance(blob, bytes) or not blob or len(blob) > MAX_API_SIGNATURE_BYTES or blob[0] not in {0, 0x20}:
        return None
    position = 1
    items = 0

    def integer():
        nonlocal position
        first = blob[position]
        count = 1 if first < 0x80 else (2 if first < 0xC0 else 4)
        if first >= 0xE0 or position + count > len(blob):
            raise ValueError("signature_integer")
        value = first & {1: 0x7F, 2: 0x3F, 4: 0x1F}[count]
        for item in blob[position + 1 : position + count]:
            value = value * 256 + item
        position += count
        if (count == 2 and value < 0x80) or (count == 4 and value < 0x4000):
            raise ValueError("signature_noncanonical_integer")
        return value

    def typename(depth=0):
        nonlocal position, items
        items += 1
        if depth >= MAX_API_SIGNATURE_DEPTH or items > MAX_API_SIGNATURE_ITEMS:
            raise ValueError("signature_depth")
        code = blob[position]
        position += 1
        simple = {
            1: "System.Void",
            2: "System.Boolean",
            5: "System.Byte",
            8: "System.Int32",
            10: "System.Int64",
            14: "System.String",
            24: "System.IntPtr",
            28: "System.Object",
        }
        if code in simple:
            return simple[code]
        if code == 0x1D:
            return typename(depth + 1) + "[]"
        if code in {0x11, 0x12}:
            value = integer()
            token = 0x01000000 | (value >> 2)
            name = references.get(token)
            if value & 3 != 1 or not value >> 2 or name not in _CLASSIC_TYPES:
                raise ValueError("signature_untrusted_type")
            if (code == 0x11) != (name in _VALUE_TYPES):
                raise ValueError("signature_type_kind")
            if type_versions is not None and type_versions.get(token) != expected_version:
                raise ValueError("signature_type_version")
            return name
        raise ValueError("signature_unknown_type")

    try:
        count = integer()
        if count > 16:
            return None
        result = (
            bool(blob[0] & 0x20),
            typename(),
            tuple(typename() for _ in range(count)),
        )
        return result if position == len(blob) else None
    except (ValueError, IndexError):
        return None


def _identity_text(value):
    value = getattr(value, "value", value)
    if (not isinstance(value, str) or len(value) > 512
            or any(ord(character) < 32 or ord(character) == 127 for character in value)):
        raise RecipeError("framework_identity_text_invalid")
    return value


def _classic_assembly(row):
    name = _identity_text(getattr(row, "Name", None))
    if _identity_text(getattr(row, "Culture", None)):
        raise RecipeError("framework_assembly_culture_not_neutral")
    flags = getattr(getattr(row, "struct", None), "Flags", None)
    if not isinstance(flags, int) or isinstance(flags, bool) or flags != 0:
        raise RecipeError("framework_assembly_flags_not_reviewed")
    key = getattr(getattr(row, "PublicKey", None), "value", None)
    if not isinstance(key, bytes) or len(key) != 8 or (name, key) not in _CLASSIC_ASSEMBLY_PAIRS:
        raise RecipeError("framework_assembly_identity_pair_not_reviewed")
    version = tuple(getattr(row, field, None) for field in
                    ("MajorVersion", "MinorVersion", "BuildNumber", "RevisionNumber"))
    if (any(not isinstance(value, int) or isinstance(value, bool) for value in version)
            or version not in _CLASSIC_VERSIONS):
        raise RecipeError("framework_assembly_version_not_reviewed")
    return name, key, version


def _framework_references(pe, deadline, clock):
    """型別classic identityと完全API宣言を照合し、実行時真正性は確認しない。"""
    resolver = MetadataResolver(pe, max_rows=MAX_REFERENCE_ROWS)
    coverage = resolver.coverage()
    if not coverage["complete"]:
        raise RecipeError("framework_metadata_incomplete_or_over_budget")
    if any(not resolver.tables[name]["present"] for name in ("TypeRef", "MemberRef", "AssemblyRef")):
        raise RecipeError("framework_metadata_table_missing")
    reasons = Counter()
    assemblies = {}
    for rid, row in enumerate(resolver.tables["AssemblyRef"]["rows"], 1):
        _check_time(deadline, clock)
        try:
            assemblies[0x23000000 | rid] = _classic_assembly(row)
        except RecipeError as failure:
            reasons[str(failure)] += 1
    references, type_versions = {}, {}
    for rid, row in enumerate(resolver.tables["TypeRef"]["rows"], 1):
        _check_time(deadline, clock)
        try:
            name = _identity_text(getattr(row, "TypeNamespace", None)) + "." + _identity_text(getattr(row, "TypeName", None))
            if name not in _CLASSIC_TYPES:
                raise RecipeError("framework_type_not_reviewed")
            try:
                # coded indexは同じPEの表・有効RIDに限定する。nested/forward scopeは対象外。
                scope = resolver._coded_token(getattr(row, "ResolutionScope", None), {"AssemblyRef"})
            except ValueError:
                raise RecipeError("framework_type_scope_not_reviewed") from None
            identity = assemblies.get(scope)
            expected_assembly = "System" if name in _SYSTEM_TYPES else "mscorlib"
            if identity is None or identity[0] != expected_assembly:
                raise RecipeError("framework_type_assembly_identity_mismatch")
            token = 0x01000000 | rid
            references[token], type_versions[token] = name, identity[2]
        except RecipeError as failure:
            reasons[str(failure)] += 1
    parameter_counts = {}
    matched = 0
    for rid, row in enumerate(resolver.tables["MemberRef"]["rows"], 1):
        _check_time(deadline, clock)
        try:
            try:
                owner = resolver._coded_token(getattr(row, "Class", None), {"TypeRef"})
            except ValueError:
                raise RecipeError("framework_member_owner_scope_not_reviewed") from None
            owner_name = references.get(owner)
            if owner_name is None:
                raise RecipeError("framework_member_owner_identity_not_reviewed")
            name = owner_name + "::" + _identity_text(getattr(row, "Name", None))
            if name not in _API_SIGNATURES:
                raise RecipeError("framework_member_not_reviewed")
            if name == "System.IO.Stream::CopyTo" and type_versions[owner] != (4, 0, 0, 0):
                raise RecipeError("framework_member_version_not_reviewed")
            token = 0x0A000000 | rid
            if resolver.resolve(token)["status"] != "resolved":
                raise RecipeError("framework_member_metadata_invalid")
            signature = getattr(getattr(row, "Signature", None), "value", None)
            parsed = _signature(signature, references, type_versions=type_versions, expected_version=type_versions[owner])
            if parsed not in _API_SIGNATURES[name]:
                raise RecipeError("framework_member_signature_not_reviewed")
            references[token], parameter_counts[token] = name, len(parsed[2])
            matched += 1
        except RecipeError as failure:
            reasons[str(failure)] += 1
    return references, parameter_counts, {
        "profile_id": "classic_dotnet_tripledes_gzip_v1", "matched_member_count": matched,
        "scope": "reviewed_metadata_declarations_only", "metadata_complete": True,
        "runtime_assembly_integrity_verified": False, "runtime_dispatch_verified": False,
        "side_effect_free_verified": False, "nonthrowing_verified": False,
        "unreviewed_reason_counts": dict(sorted(reasons.items())),
    }


def _check_time(deadline, clock):
    if clock() > deadline:
        raise RecipeError("elapsed_time_limit")


def _raw_span(pe, data, rva, size):
    matches = []
    if size < 0 or rva < 0:
        raise RecipeError("invalid_raw_span")
    for section in pe.sections:
        delta = rva - section.VirtualAddress
        offset = section.PointerToRawData + delta
        if (
            0 <= delta
            and delta + size <= section.SizeOfRawData
            and 0 <= offset
            and offset + size <= len(data)
        ):
            matches.append((offset, offset + size))
    if len(matches) != 1:
        raise RecipeError("ambiguous_or_unbacked_raw_span")
    return matches[0]


def _local(i: dict, action: str) -> int | None:
    opcode = i["opcode"]
    if opcode == action or opcode == action + ".s":
        match = re.fullmatch(r"local\(0x([0-9a-fA-F]+)\)", i["operand"])
        return int(match.group(1), 16) if match else None
    match = re.fullmatch(re.escape(action) + r"\.([0-3])", opcode)
    return int(match.group(1)) if match else None


def _integer(i: dict) -> int | None:
    op = i["opcode"]
    if op in {"ldc.i4", "ldc.i4.s"}:
        try:
            return int(i["operand"], 0)
        except ValueError:
            return None
    match = re.fullmatch(r"ldc\.i4\.([0-8])", op)
    return int(match.group(1)) if match else (-1 if op == "ldc.i4.m1" else None)


def _call(i: dict, suffix: str) -> bool:
    return (
        i["opcode"] in {"call", "callvirt", "newobj"}
        and i.get("resolved_token") == suffix
    )


def _loaded(i: dict, variable: int) -> bool:
    return _local(i, "ldloc") == variable


def _unique(items: list, reason: str):
    if len(items) != 1:
        raise RecipeError(reason)
    return items[0]


def _dominance(il: list[dict], required: list[int], sink: int, deadline, clock) -> None:
    """例外を実行せず、正常系CFGで全required定義がsinkを支配するか確認する。"""
    locations = {i["offset"]: n for n, i in enumerate(il)}
    if len(locations) != len(il):
        raise RecipeError("duplicate_instruction_offsets")
    edges = []
    for n, i in enumerate(il):
        op = i["opcode"]
        following = [n + 1] if n + 1 < len(il) else []
        if op in {"ret", "throw", "rethrow", "endfinally"}:
            following = []
        elif op == "switch":
            targets = [int(x) for x in re.findall(r"-?[0-9]+", i["operand"])]
            if len(targets) > 4096 or any(x not in locations for x in targets):
                raise RecipeError("invalid_switch_target")
            following += [locations[x] for x in targets]
        elif op.startswith(("br", "beq", "bne", "bge", "bgt", "ble", "blt", "leave")):
            try:
                target = int(i["operand"], 0)
            except ValueError as exc:
                raise RecipeError("invalid_branch_target") from exc
            if target not in locations:
                raise RecipeError("invalid_branch_target")
            following = [locations[target]] + (
                [] if op in {"br", "br.s", "leave", "leave.s"} else following
            )
        edges.append(following)

    def reachable(excluded):
        _check_time(deadline, clock)
        visited, pending = set(), [0]
        while pending:
            node = pending.pop()
            if node == excluded or node in visited:
                continue
            if node == sink:
                return True
            visited.add(node)
            pending.extend(edges[node])
        return False

    if not reachable(None) or any(reachable(node) for node in required):
        raise RecipeError("recipe_does_not_dominate_assembly_load")


def _recipe(method: dict, deadline, clock) -> dict:
    il = method["instructions"]
    if len(il) > MAX_METHOD_INSTRUCTIONS:
        raise RecipeError("method_instruction_limit")
    stores = Counter(v for i in il if (v := _local(i, "stloc")) is not None)
    critical = []
    reviewed = set()

    def span(start, end):
        reviewed.update(range(start, end + 1))

    literal_locals = {}
    for n in range(len(il) - 2):
        if (
            il[n]["opcode"] == "ldstr"
            and _call(il[n + 1], "System.Convert::FromBase64String")
            and (v := _local(il[n + 2], "stloc")) is not None
        ):
            text = il[n].get("string", "")
            if len(text) > 128:
                raise RecipeError("key_literal_size_limit")
            literal_locals[v] = (base64.b64decode(text, validate=True), n)
            span(n, n + 2)
    resources = []
    for n in range(len(il) - 2):
        if (
            il[n]["opcode"] == "ldstr"
            and _call(
                il[n + 1], "System.Reflection.Assembly::GetManifestResourceStream"
            )
            and (stream := _local(il[n + 2], "stloc")) is not None
        ):
            resources.append((il[n]["string"], stream, n + 1))
    resource_name, stream, resource_at = _unique(
        resources, "resource_binding_ambiguous"
    )
    span(resource_at - 1, resource_at + 1)
    array_candidates = []
    for n in range(len(il) - 4):
        if (
            _loaded(il[n], stream)
            and _call(il[n + 1], "System.IO.Stream::get_Length")
            and il[n + 2]["opcode"] == "conv.ovf.i"
            and il[n + 3]["opcode"] == "newarr"
            and il[n + 3].get("resolved_token") == "System.Byte"
            and (v := _local(il[n + 4], "stloc")) is not None
        ):
            array_candidates.append((v, n + 4))
    encrypted, encrypted_at = _unique(
        array_candidates, "resource_array_binding_ambiguous"
    )
    span(encrypted_at - 4, encrypted_at)
    reads = [
        n
        for n in range(6, len(il))
        if _call(il[n], "System.IO.Stream::Read")
        and _loaded(il[n - 6], stream)
        and _loaded(il[n - 5], encrypted)
        and _integer(il[n - 4]) == 0
        and _loaded(il[n - 3], encrypted)
        and il[n - 2]["opcode"] == "ldlen"
        and il[n - 1]["opcode"] == "conv.i4"
    ]
    read_at = _unique(reads, "resource_read_binding_ambiguous")
    span(read_at - 6, read_at)
    algorithms = [
        (v, n)
        for n in range(len(il) - 1)
        if _call(il[n], "System.Security.Cryptography.TripleDES::Create")
        and (v := _local(il[n + 1], "stloc")) is not None
    ]
    algorithm, algorithm_at = _unique(algorithms, "algorithm_binding_ambiguous")
    span(algorithm_at, algorithm_at + 1)
    setting_locals = {}
    for setting in ["Key", "IV", "Mode", "Padding"]:
        matches = [
            n
            for n in range(2, len(il))
            if _call(
                il[n], "System.Security.Cryptography.SymmetricAlgorithm::set_" + setting
            )
            and _loaded(il[n - 2], algorithm)
        ]
        at = _unique(matches, "algorithm_setting_binding_ambiguous")
        if setting in {"Key", "IV"}:
            local = _local(il[at - 1], "ldloc")
            if local not in literal_locals:
                raise RecipeError("key_or_iv_not_literal_bound")
            setting_locals[setting] = local
            critical.append(literal_locals[local][1])
        elif _integer(il[at - 1]) != {"Mode": 1, "Padding": 2}[setting]:
            raise RecipeError("unsupported_cipher_mode_or_padding")
        critical.append(at)
        span(at - 2, at)
    key, iv = [literal_locals[setting_locals[k]][0] for k in ["Key", "IV"]]
    if len(key) not in {16, 24} or len(iv) != 8:
        raise RecipeError("invalid_literal_key_or_iv_length")
    decryptors = [
        (v, n)
        for n in range(1, len(il) - 1)
        if _loaded(il[n - 1], algorithm)
        and _call(
            il[n], "System.Security.Cryptography.SymmetricAlgorithm::CreateDecryptor"
        )
        and (v := _local(il[n + 1], "stloc")) is not None
    ]
    decryptor, decryptor_at = _unique(decryptors, "decryptor_binding_ambiguous")
    span(decryptor_at - 1, decryptor_at + 1)
    transform = [
        (v, n)
        for n in range(6, len(il) - 1)
        if _call(
            il[n], "System.Security.Cryptography.ICryptoTransform::TransformFinalBlock"
        )
        and _loaded(il[n - 6], decryptor)
        and _loaded(il[n - 5], encrypted)
        and _integer(il[n - 4]) == 0
        and _loaded(il[n - 3], encrypted)
        and il[n - 2]["opcode"] == "ldlen"
        and il[n - 1]["opcode"] == "conv.i4"
        and (v := _local(il[n + 1], "stloc")) is not None
    ]
    crypto_bound = []
    transform_kind = "TransformFinalBlock"
    if transform:
        clear, transform_at = _unique(
            transform, "transform_final_block_binding_ambiguous"
        )
        span(transform_at - 6, transform_at + 1)
    else:
        input_streams = [
            (v, n)
            for n in range(1, len(il) - 1)
            if _loaded(il[n - 1], encrypted)
            and _call(il[n], "System.IO.MemoryStream::.ctor")
            and il[n].get("parameter_count") == 1
            and (v := _local(il[n + 1], "stloc")) is not None
        ]
        encrypted_stream, input_at = _unique(
            input_streams, "crypto_input_stream_binding_ambiguous"
        )
        crypto_streams = [
            (v, n)
            for n in range(3, len(il) - 1)
            if _loaded(il[n - 3], encrypted_stream)
            and _loaded(il[n - 2], decryptor)
            and _integer(il[n - 1]) == 0
            and _call(il[n], "System.Security.Cryptography.CryptoStream::.ctor")
            and il[n].get("parameter_count") == 3
            and (v := _local(il[n + 1], "stloc")) is not None
        ]
        crypto_stream, crypto_at = _unique(
            crypto_streams, "crypto_stream_binding_ambiguous"
        )
        copies = [
            (v, n)
            for n in range(2, len(il))
            if _loaded(il[n - 2], crypto_stream)
            and (v := _local(il[n - 1], "ldloc")) is not None
            and _call(il[n], "System.IO.Stream::CopyTo")
            and il[n].get("parameter_count") == 1
        ]
        clear_stream, copy_at = _unique(copies, "crypto_clear_stream_binding_ambiguous")
        constructors = [
            n
            for n in range(len(il) - 1)
            if _call(il[n], "System.IO.MemoryStream::.ctor")
            and il[n].get("parameter_count") == 0
            and _local(il[n + 1], "stloc") == clear_stream
        ]
        constructor_at = _unique(
            constructors, "crypto_clear_stream_constructor_ambiguous"
        )
        clear_arrays = [
            (v, n)
            for n in range(1, len(il) - 1)
            if _loaded(il[n - 1], clear_stream)
            and _call(il[n], "System.IO.MemoryStream::ToArray")
            and (v := _local(il[n + 1], "stloc")) is not None
        ]
        clear, transform_at = _unique(
            clear_arrays, "crypto_clear_array_binding_ambiguous"
        )
        crypto_bound = [encrypted_stream, crypto_stream, clear_stream]
        critical += [input_at, crypto_at, copy_at, constructor_at]
        span(input_at - 1, input_at + 1)
        span(crypto_at - 3, crypto_at + 1)
        span(copy_at - 2, copy_at)
        span(constructor_at, constructor_at + 1)
        span(transform_at - 1, transform_at + 1)
        transform_kind = "CryptoStream_Read_CopyTo"
    slices = [
        (v, n)
        for n in range(7, len(il) - 1)
        if _call(il[n], "System.IO.MemoryStream::.ctor")
        and _loaded(il[n - 7], clear)
        and _integer(il[n - 6]) == 4
        and _loaded(il[n - 5], clear)
        and il[n - 4]["opcode"] == "ldlen"
        and il[n - 3]["opcode"] == "conv.i4"
        and _integer(il[n - 2]) == 4
        and il[n - 1]["opcode"] == "sub"
        and (v := _local(il[n + 1], "stloc")) is not None
    ]
    compressed_stream, slice_at = _unique(slices, "gzip_prefix_slice_binding_ambiguous")
    if il[slice_at].get("parameter_count") != 3:
        raise RecipeError("unsupported_memory_stream_signature")
    span(slice_at - 7, slice_at + 1)
    gzip = [
        (v, n)
        for n in range(2, len(il) - 1)
        if _call(il[n], "System.IO.Compression.GZipStream::.ctor")
        and _loaded(il[n - 2], compressed_stream)
        and _integer(il[n - 1]) == 0
        and (v := _local(il[n + 1], "stloc")) is not None
    ]
    gzip_stream, gzip_at = _unique(gzip, "gzip_stream_binding_ambiguous")
    if il[gzip_at].get("parameter_count") != 2:
        raise RecipeError("unsupported_gzip_stream_signature")
    span(gzip_at - 2, gzip_at + 1)
    # 厳密なRead→positive count→Write loopのみを認める。
    loops = []
    for n in range(6, len(il) - 5):
        if not (
            _call(il[n], "System.IO.Stream::Read")
            and _loaded(il[n - 6], gzip_stream)
            and (buffer := _local(il[n - 5], "ldloc")) is not None
            and _integer(il[n - 4]) == 0
            and _loaded(il[n - 3], buffer)
            and il[n - 2]["opcode"] == "ldlen"
            and il[n - 1]["opcode"] == "conv.i4"
            and il[n + 1]["opcode"] == "dup"
            and (count := _local(il[n + 2], "stloc")) is not None
            and _integer(il[n + 3]) == 0
            and il[n + 4]["opcode"] in {"bgt", "bgt.s"}
        ):
            continue
        writes = [
            j
            for j in range(4, len(il))
            if _call(il[j], "System.IO.Stream::Write")
            and (output := _local(il[j - 4], "ldloc")) is not None
            and _loaded(il[j - 3], buffer)
            and _integer(il[j - 2]) == 0
            and _loaded(il[j - 1], count)
            and il[j - 4]["offset"] == int(il[n + 4]["operand"], 0)
            and j + 1 == n - 6
        ]
        if len(writes) == 1:
            output = _local(il[writes[0] - 4], "ldloc")
            loops.append((output, n, buffer, count))
            span(writes[0] - 4, writes[0])
    output_stream, gzip_read_at, buffer, count = _unique(
        loops, "gzip_read_write_loop_binding_ambiguous"
    )
    buffer_allocations = [
        n
        for n in range(1, len(il) - 1)
        if il[n]["opcode"] == "newarr"
        and il[n].get("resolved_token") == "System.Byte"
        and _local(il[n + 1], "stloc") == buffer
        and _integer(il[n - 1]) is not None
        and 0 < _integer(il[n - 1]) <= 65536
    ]
    buffer_at = _unique(buffer_allocations, "gzip_buffer_binding_ambiguous")
    span(buffer_at - 1, buffer_at + 1)
    span(gzip_read_at - 6, gzip_read_at + 4)
    output_constructors = [
        n
        for n in range(len(il) - 1)
        if _call(il[n], "System.IO.MemoryStream::.ctor")
        and _local(il[n + 1], "stloc") == output_stream
        and il[n]["opcode"] == "newobj"
        and il[n].get("parameter_count") == 0
    ]
    output_at = _unique(output_constructors, "output_stream_binding_ambiguous")
    span(output_at, output_at + 1)
    arrays = [
        (v, n)
        for n in range(1, len(il) - 1)
        if _loaded(il[n - 1], output_stream)
        and _call(il[n], "System.IO.MemoryStream::ToArray")
        and (v := _local(il[n + 1], "stloc")) is not None
    ]
    payload, payload_at = _unique(arrays, "payload_array_binding_ambiguous")
    span(payload_at - 1, payload_at + 1)
    sinks = [
        n
        for n in range(1, len(il))
        if _loaded(il[n - 1], payload)
        and _call(il[n], "System.Reflection.Assembly::Load")
    ]
    sink = _unique(sinks, "assembly_load_sink_binding_ambiguous")
    span(sink - 1, sink)
    bound_locals = [
        stream,
        encrypted,
        algorithm,
        decryptor,
        clear,
        compressed_stream,
        gzip_stream,
        output_stream,
        payload,
        buffer,
        count,
        *crypto_bound,
        *setting_locals.values(),
    ]
    if len(set(bound_locals)) != len(bound_locals) or any(
        stores[v] != 1 for v in bound_locals
    ):
        raise RecipeError("bound_local_alias_or_reassignment")
    if any(i["opcode"].startswith(("stelem", "stind", "cpblk", "initblk")) for i in il):
        raise RecipeError("unreviewed_array_mutation")
    for local in setting_locals.values():
        if sum(_loaded(i, local) for i in il) != 1:
            raise RecipeError("unreviewed_key_or_iv_alias")
    for n, instruction in enumerate(il[: sink + 1]):
        local = _local(instruction, "ldloc")
        if _local(instruction, "ldloca") in bound_locals:
            raise RecipeError("unreviewed_local_address_alias")
        if local in bound_locals and n not in reviewed:
            cleanup = n + 1 < len(il) and (
                _call(il[n + 1], "System.IDisposable::Dispose")
                or il[n + 1]["opcode"] in {"brfalse", "brfalse.s"}
            )
            if not cleanup or local in {
                encrypted,
                clear,
                payload,
                buffer,
                count,
                *setting_locals.values(),
            }:
                raise RecipeError("unreviewed_bound_local_use")
        if local in bound_locals and n in reviewed:
            definition = next(
                j for j, item in enumerate(il) if _local(item, "stloc") == local
            )
            _dominance(il, [definition], n, deadline, clock)
    critical += [
        resource_at,
        encrypted_at,
        read_at,
        algorithm_at,
        decryptor_at,
        transform_at,
        slice_at,
        gzip_at,
        output_at,
        buffer_at,
        gzip_read_at,
        payload_at,
    ]
    _dominance(il, critical, sink, deadline, clock)
    return {
        "resource_name": resource_name,
        "key": key,
        "iv": iv,
        "method_token": method["token"],
        "method_rva": method["rva"],
        "sink_offset": il[sink]["offset"],
        "transform_kind": transform_kind,
        "normal_cfg_dominance_verified": True,
        "critical_offsets": [il[n]["offset"] for n in sorted(set(critical))],
    }


def recover_model(
    data: bytes,
    methods: list[dict],
    resources: dict[str, bytes],
    *,
    clock=time.monotonic,
    deadline=None,
) -> tuple[dict, list[tuple[str, bytes]]]:
    """有界metadata/CIL modelの独立検証を行い、復元候補だけを返す。"""
    report = {
        "schema_version": 1,
        "status": "not_candidate",
        "sample_executed": False,
        "clr_loaded": False,
        "instruction_emulation_performed": False,
        "network_contacted": False,
        "raw_key_published": False,
        "family_attribution_allowed": False,
        "c2_confirmation_allowed": False,
        "terminal_promotion_eligible": False,
    }
    if deadline is None:
        deadline = clock() + MAX_SECONDS
    try:
        _check_time(deadline, clock)
        if len(data) > MAX_INPUT or len(methods) > MAX_METHODS:
            raise RecipeError("input_or_method_limit")
        recipes = []
        for method in methods:
            _check_time(deadline, clock)
            if any(
                _call(i, "System.Security.Cryptography.TripleDES::Create")
                for i in method["instructions"]
            ):
                recipes.append(_recipe(method, deadline, clock))
        if not recipes:
            return report, []
        recipe = _unique(recipes, "multiple_resource_recipes")
        encrypted = resources.get(recipe["resource_name"])
        if (
            not isinstance(encrypted, bytes)
            or not encrypted
            or len(encrypted) > MAX_RESOURCE
            or len(encrypted) % 8
        ):
            raise RecipeError("ciphertext_bounds")
        key, iv = recipe["key"], recipe["iv"]
        parity_free = [
            bytes(v & 0xFE for v in key[n : n + 8]) for n in range(0, len(key), 8)
        ]
        if any(a == b for a, b in pairwise(parity_free)):
            raise RecipeError("degenerate_tripledes_key")
        effective_key = key + key[:8] if len(key) == 16 else key
        _check_time(deadline, clock)
        decryptor = Cipher(TripleDES(effective_key), modes.CBC(iv)).decryptor()
        clear = decryptor.update(encrypted) + decryptor.finalize()
        padding = clear[-1]
        if not 1 <= padding <= 8 or clear[-padding:] != bytes([padding]) * padding:
            raise RecipeError("pkcs7_padding_invalid")
        clear = clear[:-padding]
        if len(clear) < 5:
            raise RecipeError("length_prefix_missing")
        expected = struct.unpack_from("<i", clear)[0]
        if not 0 < expected <= MAX_OUTPUT:
            raise RecipeError("declared_output_limit")
        inflate = zlib.decompressobj(zlib.MAX_WBITS + 16)
        payload = inflate.decompress(clear[4:], expected + 1)
        _check_time(deadline, clock)
        if (
            len(payload) != expected
            or not inflate.eof
            or inflate.unused_data
            or inflate.unconsumed_tail
        ):
            raise RecipeError("gzip_length_or_eof_invalid")
        extent = inspect_structural_pe_extent(payload, max_extent=MAX_OUTPUT)
        if extent.extent is None or not has_clr_metadata(payload):
            raise RecipeError("decoded_managed_pe_invalid")
        report.update(
            {
                "status": "recovered",
                "parent_sha256": hashlib.sha256(data).hexdigest(),
                "resource_sha256": hashlib.sha256(encrypted).hexdigest(),
                "resource_size": len(encrypted),
                "resource_name_sha256": hashlib.sha256(
                    recipe["resource_name"].encode()
                ).hexdigest(),
                "key_size": len(key),
                "iv_size": len(iv),
                "method_token": recipe["method_token"],
                "method_rva": recipe["method_rva"],
                "transform_kind": recipe["transform_kind"],
                "assembly_load_body_offset": recipe["sink_offset"],
                "critical_body_offsets": recipe["critical_offsets"],
                "normal_cfg_dominance_verified": True,
                "normal_cfg_def_use_verified": True,
                "exception_flow_semantics_complete": False,
                "runtime_declared_length_check_confirmed": False,
                "recovered_sha256": hashlib.sha256(payload).hexdigest(),
                "recovered_size": len(payload),
                "candidate_only": True,
            }
        )
        return report, [("managed-tripledes-gzip-pe", payload)]
    except (RecipeError, ValueError, zlib.error, struct.error) as exc:
        report.update(
            status="rejected",
            reason=str(exc)
            if isinstance(exc, RecipeError)
            else "invalid_static_recipe_structure",
        )
        return report, []


def recover_managed_tripledes_gzip(
    data: bytes, *, clock=time.monotonic
) -> tuple[dict, list[tuple[str, bytes]]]:
    """CLRをloadせず、明示CIL・resource・sinkからPE候補を静的回収する。"""
    if len(data) > MAX_INPUT:
        return recover_model(data, [], {})
    if not has_clr_metadata(data):
        return recover_model(b"", [], {})
    deadline = clock() + MAX_SECONDS
    declaration_validation = None
    try:
        pe = dnfile.dnPE(data=data, clr_lazy_load=True)
        tables = pe.net.mdtables
        if not tables or tables.MethodDef.num_rows > MAX_METHODS:
            raise RecipeError("method_count_limit")
        references, parameter_counts, declaration_validation = _framework_references(pe, deadline, clock)
        if not {
            "System.Security.Cryptography.TripleDES::Create",
            "System.IO.Compression.GZipStream::.ctor",
            "System.Reflection.Assembly::Load",
        }.issubset(references.values()):
            report, artifacts = recover_model(data, [], {}, clock=clock, deadline=deadline)
            report.update(reason="framework_api_declaration_not_reviewed", framework_declaration_validation=declaration_validation)
            return report, artifacts
        methods, total = [], 0
        for n, row in enumerate(tables.MethodDef.rows, 1):
            _check_time(deadline, clock)
            if not row.Rva:
                continue
            spans = [
                section
                for section in pe.sections
                if section.VirtualAddress
                <= row.Rva
                < section.VirtualAddress + section.SizeOfRawData
            ]
            if len(spans) != 1:
                raise RecipeError("method_not_file_backed")
            available = min(
                MAX_METHOD_BYTES,
                spans[0].VirtualAddress + spans[0].SizeOfRawData - row.Rva,
            )
            start, end = _raw_span(pe, data, row.Rva, available)
            body = read_method_body_from_bytes(data[start:end])
            total += body.size
            if (
                body.size > MAX_METHOD_BYTES
                or total > MAX_TOTAL_METHOD_BYTES
                or len(body.instructions) > MAX_METHOD_INSTRUCTIONS
            ):
                raise RecipeError("method_body_budget")
            instructions = []
            for i in body.instructions:
                value = getattr(i.operand, "value", None)
                record = {
                    "offset": i.offset,
                    "opcode": i.opcode.name,
                    "operand": str(i.operand),
                    "resolved_token": references.get(value),
                }
                record["parameter_count"] = parameter_counts.get(value)
                if i.opcode.name == "ldstr":
                    text = pe.net.user_strings.get(value & 0xFFFFFF)
                    if text is None or len(text.value) > 32768:
                        raise RecipeError("user_string_limit")
                    record["string"] = str(text)
                instructions.append(record)
            methods.append(
                {"token": 0x06000000 | n, "rva": row.Rva, "instructions": instructions}
            )
        if not any(
            _call(i, "System.Security.Cryptography.TripleDES::Create")
            for method in methods
            for i in method["instructions"]
        ):
            return recover_model(data, [], {}, clock=clock, deadline=deadline)
        resources = {}
        table = tables.ManifestResource
        if table and table.num_rows > 256:
            raise RecipeError("resource_count_limit")
        total_resource_bytes = 0
        resource_intervals = []
        for row in table.rows if table else []:
            _check_time(deadline, clock)
            if row.Implementation is not None and row.Implementation.row is not None:
                continue
            offset = int(row.Offset)
            if offset < 0 or offset + 4 > pe.net.struct.ResourcesSize:
                raise RecipeError("resource_offset_bounds")
            rva = pe.net.struct.ResourcesRva + offset
            begin, end = _raw_span(pe, data, rva, 4)
            size = struct.unpack("<I", data[begin:end])[0]
            if size > MAX_RESOURCE or offset + 4 + size > pe.net.struct.ResourcesSize:
                raise RecipeError("resource_size_bounds")
            total_resource_bytes += size
            if total_resource_bytes > MAX_INPUT:
                raise RecipeError("total_resource_bytes_limit")
            interval = (offset, offset + 4 + size)
            if any(
                interval[0] < end and interval[1] > start
                for start, end in resource_intervals
            ):
                raise RecipeError("overlapping_resource_ranges")
            resource_intervals.append(interval)
            name = str(row.Name)
            if name in resources or len(name) > 1024:
                raise RecipeError("resource_name_ambiguity")
            begin, end = _raw_span(pe, data, rva + 4, size)
            raw = data[begin:end]
            if len(raw) != size:
                raise RecipeError("resource_not_file_backed")
            resources[name] = raw
        _check_time(deadline, clock)
        report, artifacts = recover_model(data, methods, resources, clock=clock, deadline=deadline)
        report["framework_declaration_validation"] = declaration_validation
        return report, artifacts
    except (
        RecipeError,
        ValueError,
        AttributeError,
        IndexError,
        TypeError,
        struct.error,
        MethodBodyFormatError,
        PEFormatError,
    ) as exc:
        report, _ = recover_model(data, [], {})
        report.update(
            status="rejected",
            reason=str(exc)
            if isinstance(exc, RecipeError)
            else "invalid_managed_metadata",
        )
        if declaration_validation is not None:
            report["framework_declaration_validation"] = declaration_validation
        return report, []
