"""有界なCLR token／signature参照解決。CLRやCILを実行しない。

解決結果はmetadata上の宣言を示すだけで、実行時dispatch、到達性、framework
assemblyの真正性、protector帰属を証明しない。名前や生signatureは結果へ出さない。
"""

from __future__ import annotations

import hashlib
from itertools import islice
from typing import Any


DEFAULT_MAX_ROWS = 20_000
DEFAULT_MAX_TOTAL_ROWS = 80_000
MAX_SIGNATURE_BYTES = 16_384
MAX_SIGNATURE_ITEMS = 1_024
MAX_SIGNATURE_DEPTH = 32
MAX_FRAMEWORK_SCOPE_DEPTH = 8
MAX_IDENTITY_TEXT_LENGTH = 512
TABLES = {
    0x01: "TypeRef", 0x02: "TypeDef", 0x04: "Field", 0x06: "MethodDef",
    0x0A: "MemberRef", 0x11: "StandAloneSig", 0x1A: "ModuleRef",
    0x1B: "TypeSpec", 0x2B: "MethodSpec", 0x23: "AssemblyRef",
}
_TABLE_IDS = {name: identifier for identifier, name in TABLES.items()}

# 対応する宣言の組を固定し、assembly名集合とtoken集合の直積では判定しない。
# 先行profileは従来のmscorlib参照だけに限定する。別runtimeのidentityは未レビュー。
_FRAMEWORK_ASSEMBLY_IDENTITIES = {
    ("mscorlib", bytes.fromhex("b77a5c561934e089")): {(2, 0, 0, 0), (4, 0, 0, 0)},
}
_FRAMEWORK_MEMBER_PROFILES = {
    "system_text_encoding_get_ascii_v1": {
        "api_id": "system_text_encoding_ascii_getter",
        "owners": {("System.Text", "Encoding")},
        "member": "get_ASCII", "has_this": False, "generic_arity": 0,
        "return": ("class", "System.Text", "Encoding"), "parameters": (),
    },
    "system_text_encoding_get_bytes_string_v1": {
        "api_id": "system_text_encoding_getbytes_string",
        "owners": {("System.Text", "Encoding"), ("System.Text", "ASCIIEncoding")},
        "member": "GetBytes", "has_this": True, "generic_arity": 0,
        "return": ("array", ("primitive", 0x05)), "parameters": (("primitive", 0x0E),),
    },
}
_FRAMEWORK_DECLARING_TYPE_PROFILES = {
    ("System.Text", "Encoding"): "system_text_encoding",
    ("System.Text", "ASCIIEncoding"): "system_text_ascii_encoding",
}


class _MetadataError(ValueError):
    """公開可能な固定reasonだけを運ぶ内部例外。"""


def _exception_type(failure: Exception) -> str:
    name = type(failure).__name__
    if (not 1 <= len(name) <= 64 or not (name[0].isascii() and (name[0].isalpha() or name[0] == "_"))
            or any(not character.isascii() or not (character.isalnum() or character == "_") for character in name)):
        return "MetadataParseError"
    return name


def token_value(operand: Any) -> int | None:
    """dncil風operandをuint32 tokenへ限定し、不正値は未解決として返す。"""
    try:
        value = getattr(operand, "value", operand)
    except Exception:
        return None
    if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 0xFFFFFFFF:
        return value
    return None


def _blob(value: Any) -> bytes:
    value = getattr(value, "value", value)
    if not isinstance(value, bytes) or not 0 < len(value) <= MAX_SIGNATURE_BYTES:
        raise _MetadataError("signature_missing_or_oversized")
    return value


def _identity_text(value: Any) -> str:
    value = getattr(value, "value", value)
    if (not isinstance(value, str) or len(value) > MAX_IDENTITY_TEXT_LENGTH
            or any(ord(character) < 32 or ord(character) == 127 for character in value)):
        raise _MetadataError("framework_identity_text_invalid_or_oversized")
    return value


class _SignatureReader:
    def __init__(self, data: bytes, resolver: "MetadataResolver") -> None:
        self.data = data
        self.position = 0
        self.items = 0
        self.resolver = resolver

    def byte(self) -> int:
        if self.position >= len(self.data):
            raise _MetadataError("signature_truncated")
        value = self.data[self.position]
        self.position += 1
        return value

    def unsigned(self) -> int:
        first = self.byte()
        if first < 0x80:
            return first
        if first < 0xC0:
            value = ((first & 0x3F) << 8) | self.byte()
            if value >= 0x80:
                return value
        elif first < 0xE0:
            value = ((first & 0x1F) << 24) | (self.byte() << 16) | (self.byte() << 8) | self.byte()
            if value >= 0x4000:
                return value
        raise _MetadataError("signature_invalid_compressed_integer")

    def count(self, *, nonzero: bool = False) -> int:
        value = self.unsigned()
        if value > MAX_SIGNATURE_ITEMS or (nonzero and value == 0):
            raise _MetadataError("signature_item_budget_exceeded")
        return value

    def type_reference(self) -> None:
        coded = self.unsigned()
        table = {0: 0x02, 1: 0x01, 2: 0x1B}.get(coded & 3)
        if table is None or coded >> 2 == 0:
            raise _MetadataError("signature_invalid_type_reference")
        _, reason = self.resolver._row((table << 24) | (coded >> 2))
        if reason:
            raise _MetadataError("signature_type_reference_" + reason)

    def type(self, depth: int = 0, *, allow_void: bool = False) -> None:
        self.items += 1
        if depth >= MAX_SIGNATURE_DEPTH or self.items > MAX_SIGNATURE_ITEMS:
            raise _MetadataError("signature_type_budget_exceeded")
        element = self.byte()
        if element in {0x1F, 0x20}:  # cmod_reqd / cmod_opt
            self.type_reference()
            self.type(depth + 1, allow_void=allow_void)
        elif element == 0x01:
            if not allow_void:
                raise _MetadataError("signature_unexpected_void")
        elif element in {0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
                         0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x16, 0x18, 0x19, 0x1C}:
            pass
        elif element in {0x11, 0x12}:
            self.type_reference()
        elif element in {0x13, 0x1E}:
            self.count()
        elif element in {0x0F, 0x10, 0x1D}:
            self.type(depth + 1, allow_void=element == 0x0F)
        elif element == 0x14:  # 多次元array。boundは符号化構造だけを検証する。
            self.type(depth + 1)
            rank = self.count(nonzero=True)
            sizes = self.count()
            if sizes > rank:
                raise _MetadataError("signature_invalid_array_rank")
            for _ in range(sizes):
                self.unsigned()
            bounds = self.count()
            if bounds > rank:
                raise _MetadataError("signature_invalid_array_rank")
            for _ in range(bounds):
                # 符号付きboundは実数値へ解釈せず、符号化長だけを検証する。
                first = self.byte()
                additional = 0 if first < 0x80 else 1 if first < 0xC0 else 3 if first < 0xE0 else -1
                if additional < 0:
                    raise _MetadataError("signature_invalid_array_bound")
                for _ in range(additional):
                    self.byte()
        elif element == 0x15:
            if self.byte() not in {0x11, 0x12}:
                raise _MetadataError("signature_invalid_generic_type")
            self.type_reference()
            for _ in range(self.count(nonzero=True)):
                self.type(depth + 1)
        elif element == 0x1B:  # function pointer signatureであり、call edgeは確定しない。
            self.method(depth + 1)
        else:
            raise _MetadataError("signature_unsupported_element")

    def method(self, depth: int = 0) -> int:
        flags = self.byte()
        convention = flags & 0x0F
        if flags & 0x80 or convention not in {0, 1, 2, 3, 4, 5, 9} or (flags & 0x40 and not flags & 0x20):
            raise _MetadataError("signature_invalid_method_convention")
        generic_arity = self.count(nonzero=True) if flags & 0x10 else 0
        count = self.count()
        self.type(depth + 1, allow_void=True)
        sentinel = False
        for _ in range(count):
            if self.position < len(self.data) and self.data[self.position] == 0x41:
                if convention != 5 or sentinel:
                    raise _MetadataError("signature_invalid_sentinel")
                self.position += 1
                sentinel = True
            self.type(depth + 1)
        return generic_arity

    def finish(self) -> None:
        if self.position != len(self.data):
            raise _MetadataError("signature_trailing_bytes")


class MetadataResolver:
    """上限内のmetadata行をsnapshot化し、method／field tokenを保守的に解決する。"""

    def __init__(self, pe: Any, *, max_rows: int = DEFAULT_MAX_ROWS,
                 max_total_rows: int = DEFAULT_MAX_TOTAL_ROWS) -> None:
        if any(not isinstance(value, int) or isinstance(value, bool) or value <= 0
               for value in (max_rows, max_total_rows)) or max_rows > DEFAULT_MAX_ROWS or max_total_rows > DEFAULT_MAX_TOTAL_ROWS:
            raise ValueError("metadata上限は正の整数で、既定のhard上限以下にしてください")
        self.tables: dict[str, dict[str, Any]] = {}
        self._table_objects: dict[int, str] = {}
        self._cache: dict[tuple[int, str], dict[str, Any]] = {}
        source = getattr(getattr(pe, "net", None), "mdtables", None)
        total = 0
        for name in TABLES.values():
            table = getattr(source, name, None)
            if table is not None:
                self._table_objects[id(table)] = name
            error = None
            declared = None
            declared_status = "absent" if table is None else "missing"
            if table is not None:
                try:
                    value = getattr(table, "num_rows", None)
                    if value is None:
                        declared_status = "missing"
                    elif not isinstance(value, int) or isinstance(value, bool):
                        declared_status = "invalid_type"
                    elif value < 0:
                        declared_status = "negative"
                    else:
                        declared, declared_status = value, "valid"
                except Exception as failure:
                    declared_status = "parse_error"
                    error = _exception_type(failure)
            limit = min(max_rows, max(0, max_total_rows - total))
            rows: list[Any] = []
            try:
                iterator = iter(getattr(table, "rows", ()) or ())
                rows.extend(islice(iterator, limit + 1))
            except Exception as failure:
                error = _exception_type(failure)
            truncated = len(rows) > limit or (declared is not None and declared > limit)
            iteration_ended = len(rows) <= limit and not error
            mismatch = declared is not None and ((iteration_ended and len(rows) != declared) or len(rows) > declared)
            missing = declared is not None and iteration_ended and declared > len(rows)
            rows = rows[:limit]
            total += len(rows)
            self.tables[name] = {"rows": rows, "declared": declared, "declared_status": declared_status,
                                 "present": table is not None, "row_count_mismatch": mismatch,
                                 "truncated": truncated, "error": error,
                                 "missing_rows": missing}

    def coverage(self) -> dict[str, Any]:
        """参照表の保持件数と不完全理由を返し、生行や名前は公開しない。"""
        return {"scope": "lexical_metadata_declarations_not_runtime_reachability",
                "complete": all(not item["truncated"] and not item["error"] and not item["row_count_mismatch"]
                                and item["declared_status"] in {"absent", "valid"}
                                for item in self.tables.values()),
                "tables": {name: {"declared": item["declared"], "retained": len(item["rows"]),
                                  "present": item["present"], "declared_status": item["declared_status"],
                                  "row_count_mismatch": item["row_count_mismatch"],
                                  "truncated": item["truncated"], "parse_error": item["error"],
                                  "missing_rows": item["missing_rows"]}
                           for name, item in self.tables.items()}}

    def _row(self, token: int) -> tuple[Any, str | None]:
        name = TABLES.get(token >> 24)
        rid = token & 0xFFFFFF
        if name is None:
            return None, "unsupported_table"
        if rid == 0:
            return None, "zero_rid"
        item = self.tables[name]
        if not item["present"]:
            return None, "metadata_table_absent"
        if item["declared_status"] != "valid":
            return None, "metadata_declared_row_count_" + item["declared_status"]
        if rid > len(item["rows"]) and item["missing_rows"]:
            return None, "metadata_row_missing"
        if item["row_count_mismatch"]:
            return None, "metadata_row_count_mismatch"
        if rid > item["declared"] and item["error"]:
            return None, "table_parse_error"
        if rid > item["declared"] and item["truncated"]:
            return None, "metadata_row_budget_exceeded"
        if rid > item["declared"]:
            return None, "rid_out_of_range"
        if rid > len(item["rows"]):
            return None, ("table_parse_error" if item["error"] else "metadata_row_missing"
                          if item["missing_rows"] else "metadata_row_budget_exceeded")
        return item["rows"][rid - 1], None

    def _coded_token(self, reference: Any, allowed: set[str]) -> int:
        table = getattr(reference, "table", None)
        name = self._table_objects.get(id(table))
        rid = getattr(reference, "row_index", None)
        if name not in allowed or not isinstance(rid, int) or isinstance(rid, bool) or not 0 < rid <= 0xFFFFFF:
            raise _MetadataError("invalid_coded_reference")
        token = (_TABLE_IDS[name] << 24) | rid
        _, reason = self._row(token)
        if reason:
            raise _MetadataError(reason)
        return token

    def _signature(self, row: Any, kind: str) -> dict[str, Any]:
        data = _blob(getattr(row, "Signature", None))
        reader = _SignatureReader(data, self)
        if kind == "field":
            if reader.byte() != 0x06:
                raise _MetadataError("memberref_is_not_field")
            reader.type()
        else:
            if data[0] & 0x0F == 0x06:
                raise _MetadataError("memberref_is_field_not_method")
            generic_arity = reader.method()
        reader.finish()
        result = {"signature_sha256": hashlib.sha256(data).hexdigest(), "signature_size": len(data)}
        if kind != "field":
            result["generic_parameter_count"] = generic_arity
        return result

    def _framework_assembly_identity(self, token: int) -> tuple[str, bytes, tuple[int, ...]]:
        row, reason = self._row(token)
        if reason:
            raise _MetadataError("framework_assembly_" + reason)
        name = _identity_text(getattr(row, "Name", None))
        culture = _identity_text(getattr(row, "Culture", None))
        if culture:
            raise _MetadataError("framework_assembly_culture_not_neutral")
        raw_flags = getattr(getattr(row, "struct", None), "Flags", None)
        if not isinstance(raw_flags, int) or isinstance(raw_flags, bool) or raw_flags != 0:
            # full public key、retargetable、未レビューのarchitecture/JIT flagも対象外。
            raise _MetadataError("framework_assembly_flags_not_reviewed")
        public_key = _blob(getattr(row, "PublicKey", None))
        versions = _FRAMEWORK_ASSEMBLY_IDENTITIES.get((name, public_key))
        if versions is None:
            raise _MetadataError("framework_assembly_identity_pair_not_reviewed")
        version = tuple(getattr(row, field, None) for field in
                        ("MajorVersion", "MinorVersion", "BuildNumber", "RevisionNumber"))
        if any(not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= 0xFFFF for value in version):
            raise _MetadataError("framework_assembly_version_invalid")
        if version not in versions:
            raise _MetadataError("framework_assembly_version_not_reviewed")
        return name, public_key, version

    def _framework_type_identity(self, token: int) -> tuple[str, str, tuple[str, bytes, tuple[int, ...]]]:
        components = []
        seen = set()
        namespace = ""
        for _ in range(MAX_FRAMEWORK_SCOPE_DEPTH):
            if token in seen:
                raise _MetadataError("framework_typeref_scope_cycle")
            seen.add(token)
            if token >> 24 != 0x01:
                raise _MetadataError("framework_declaring_type_not_typeref")
            row, reason = self._row(token)
            if reason:
                raise _MetadataError("framework_type_" + reason)
            current_namespace = _identity_text(getattr(row, "TypeNamespace", None))
            name = _identity_text(getattr(row, "TypeName", None))
            if not name:
                raise _MetadataError("framework_typeref_name_empty")
            components.append(name)
            scope = self._coded_token(getattr(row, "ResolutionScope", None), {"TypeRef", "AssemblyRef"})
            if scope >> 24 == 0x23:
                namespace = current_namespace
                identity = self._framework_assembly_identity(scope)
                return namespace, "+".join(reversed(components)), identity
            if current_namespace:
                raise _MetadataError("framework_nested_typeref_namespace_not_empty")
            token = scope
        raise _MetadataError("framework_typeref_scope_depth_exceeded")

    def _framework_signature_type(self, reader: _SignatureReader, assembly: tuple,
                                  depth: int = 0) -> tuple:
        if depth >= MAX_SIGNATURE_DEPTH:
            raise _MetadataError("framework_signature_type_depth_exceeded")
        element = reader.byte()
        if element in {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
                       0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x16, 0x18, 0x19, 0x1C}:
            return "primitive", element
        if element == 0x1D:
            return "array", self._framework_signature_type(reader, assembly, depth + 1)
        if element == 0x12:
            coded = reader.unsigned()
            if coded & 3 != 1 or not coded >> 2:
                raise _MetadataError("framework_signature_class_not_typeref")
            namespace, name, identity = self._framework_type_identity(0x01000000 | (coded >> 2))
            if identity != assembly:
                raise _MetadataError("framework_signature_assembly_identity_mismatch")
            return "class", namespace, name
        raise _MetadataError("framework_signature_type_shape_not_reviewed")

    def match_framework_member(self, operand: Any, profile_id: str) -> dict[str, Any]:
        """限定framework APIの参照宣言を照合し、実行時真正性や無例外性は保証しない。

        AssemblyRefのexact name／public key token pair、neutral culture、flags、
        対応version、owner、member、has-this、generic数、戻値と全引数を確認する。
        生のowner名・member名・signature・keyは結果へ含めない。成功してもreceiverの
        producer、実行時dispatch、副作用の不在、nonthrowingは別の証明を要する。
        declaring_type_profileはレビュー済みownerの固定IDであり、receiver型の適合を
        自動確認しない。callerはproducer宣言・assembly versionとの整合を別途確認する。
        """
        token = token_value(operand)
        profile = (_FRAMEWORK_MEMBER_PROFILES.get(profile_id)
                   if isinstance(profile_id, str) and len(profile_id) <= 64 else None)
        result: dict[str, Any] = {
            "token": f"0x{token:08x}" if token is not None else None,
            "profile_id": profile_id if profile else None, "status": "unresolved",
            "resolution_scope": "reviewed_framework_metadata_declaration_only",
            "runtime_assembly_integrity_verified": False, "runtime_dispatch_verified": False,
            "receiver_dataflow_verified": False, "side_effect_free_verified": False,
            "nonthrowing_verified": False,
        }
        try:
            if profile is None:
                raise _MetadataError("framework_profile_unknown")
            if token is None:
                raise _MetadataError("invalid_token_operand")
            if token >> 24 != 0x0A:
                raise _MetadataError("framework_member_not_memberref")
            declaration = self.resolve(token)
            if declaration["status"] != "resolved":
                raise _MetadataError("framework_member_" + declaration["reason"])
            row, _ = self._row(token)
            parent = self._coded_token(getattr(row, "Class", None), {"TypeRef"})
            namespace, owner, assembly = self._framework_type_identity(parent)
            if (namespace, owner) not in profile["owners"]:
                raise _MetadataError("framework_member_owner_not_reviewed")
            if _identity_text(getattr(row, "Name", None)) != profile["member"]:
                raise _MetadataError("framework_member_name_mismatch")
            data = _blob(getattr(row, "Signature", None))
            if hashlib.sha256(data).hexdigest() != declaration["signature_sha256"]:
                raise _MetadataError("framework_signature_changed_since_resolution")
            reader = _SignatureReader(data, self)
            flags = reader.byte()
            if flags not in {0x00, 0x20}:
                raise _MetadataError("framework_signature_convention_or_generic_not_reviewed")
            if bool(flags & 0x20) != profile["has_this"] or declaration.get("generic_parameter_count") != profile["generic_arity"]:
                raise _MetadataError("framework_member_receiver_or_generic_mismatch")
            count = reader.count()
            if count != len(profile["parameters"]):
                raise _MetadataError("framework_member_parameter_count_mismatch")
            return_type = self._framework_signature_type(reader, assembly)
            parameters = tuple(self._framework_signature_type(reader, assembly) for _ in range(count))
            reader.finish()
            if return_type != profile["return"] or parameters != profile["parameters"]:
                raise _MetadataError("framework_member_signature_mismatch")
            result.update(status="matched_declaration", api_id=profile["api_id"],
                          declaring_type_profile=_FRAMEWORK_DECLARING_TYPE_PROFILES[(namespace, owner)],
                          signature_sha256=declaration["signature_sha256"],
                          assembly_identity_profile="mscorlib_b77a5c561934e089_v1",
                          assembly_version=list(assembly[2]))
        except _MetadataError as failure:
            result["reason"] = str(failure)
        except Exception as failure:
            result["reason"] = "framework_metadata_parse_error"
            result["parse_error"] = _exception_type(failure)
        return result

    def resolve(self, operand: Any, *, kind: str = "method") -> dict[str, Any]:
        """tokenを解決し、不正・未対応・上限を理由付きで保持する。"""
        if kind not in {"method", "field", "indirect_signature"}:
            raise ValueError("参照kindが対応する値ではありません")
        token = token_value(operand)
        result: dict[str, Any] = {"token": f"0x{token:08x}" if token is not None else None,
                                  "kind": kind, "status": "unresolved"}
        if token is None:
            return {**result, "reason": "invalid_token_operand"}
        key = (token, kind)
        if key in self._cache:
            return dict(self._cache[key])
        row, reason = self._row(token)
        name = TABLES.get(token >> 24)
        result["table"] = name
        try:
            if reason:
                raise _MetadataError(reason)
            if kind == "field":
                if name not in {"Field", "MemberRef"}:
                    raise _MetadataError("wrong_reference_table")
                result.update(self._signature(row, "field"))
            elif kind == "indirect_signature":
                if name != "StandAloneSig":
                    raise _MetadataError("wrong_reference_table")
                result.update(self._signature(row, "method"))
                raise _MetadataError("indirect_call_target_not_statically_known")
            elif name == "MethodSpec":
                target = self._coded_token(getattr(row, "Method", None), {"MethodDef", "MemberRef"})
                result["definition_token"] = f"0x{target:08x}"
                definition = self.resolve(target)
                if definition["status"] != "resolved":
                    raise _MetadataError("methodspec_definition_" + definition["reason"])
                data = _blob(getattr(row, "Instantiation", None))
                reader = _SignatureReader(data, self)
                if reader.byte() != 0x0A:
                    raise _MetadataError("methodspec_invalid_instantiation")
                count = reader.count(nonzero=True)
                if count != definition.get("generic_parameter_count"):
                    raise _MetadataError("methodspec_generic_arity_mismatch")
                for _ in range(count):
                    reader.type()
                reader.finish()
                result.update({"generic_argument_count": count,
                               "instantiation_sha256": hashlib.sha256(data).hexdigest(),
                               "definition_table": definition["table"]})
            elif name in {"MethodDef", "MemberRef"}:
                result.update(self._signature(row, "method"))
            else:
                raise _MetadataError("wrong_reference_table")
            if name == "MemberRef":
                parent = self._coded_token(getattr(row, "Class", None),
                                           {"TypeDef", "TypeRef", "TypeSpec", "ModuleRef", "MethodDef"})
                result["declaring_parent_token"] = f"0x{parent:08x}"
            result["status"] = "resolved"
            result["resolution_scope"] = "metadata_declaration_only"
        except _MetadataError as failure:
            result["reason"] = str(failure)
        except Exception as failure:
            result["reason"] = "metadata_row_parse_error"
            result["parse_error"] = _exception_type(failure)
        # cacheもsnapshot行数の定数倍以内へ限定する。
        if len(self._cache) < DEFAULT_MAX_TOTAL_ROWS:
            self._cache[key] = dict(result)
        return result
