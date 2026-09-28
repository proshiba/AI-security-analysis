#!/usr/bin/env python3
"""AsyncRAT／VenomRAT／DCRatのSettings静的初期化から公開可能な設定を復元する。"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import ipaddress
import json
import re
import struct
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import dnfile
from dncil.cil.body.reader import read_method_body_from_bytes
from dncil.cil.enums import OpCodeValue
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7


MAX_INPUT_BYTES = 32 * 1024 * 1024
MAX_METHOD_BODY_BYTES = 1024 * 1024
MAX_METADATA_ROWS = 20_000
MAX_INITIALIZER_INSTRUCTIONS = 65_536
MAX_SETTING_BYTES = 16 * 1024 * 1024
MAX_ENCODED_SETTING_CHARS = ((MAX_SETTING_BYTES + 2) // 3) * 4
MAX_MASTER_KEY_BYTES = 4096
MAX_ASSESSMENT_FIELDS = 4096
MAX_ASSESSMENT_ASSIGNMENTS = 4096
MAX_LITERAL_COUNT = 4096
MAX_LITERAL_UTF8_BYTES = MAX_INPUT_BYTES
_ASSESSMENT_OPCODE_NAMES = frozenset(
    {"Constrained": "constrained.", "Readonly": "readonly.", "Tailcall": "tail.",
     "Unaligned": "unaligned.", "Volatile": "volatile.", "No": "no."}.get(
        value.name, value.name.lower().replace("_", ".")
    )
    for value in OpCodeValue
    if not value.name.startswith(("UNKNOWN", "Prefix"))
)
PROFILES = {
    "asyncrat": {
        "settings_type": "Client.Settings",
        "salt": bytes.fromhex("bfeb1e56fbcd973bb219022430a57843003d5644d21e62b9d4f180e7e6c33941"),
        "fields": {
            "ports": "Ports",
            "hosts": "Hosts",
            "version": "Version",
            "install": "Install",
            "pastebin": "Pastebin",
            "anti": "Anti",
            "group": "Group",
            "certificate": "Certificate",
        },
    },
    "venomrat": {
        "settings_type": "Client.Settings",
        "salt": b"VenomRATByVenom",
        "fields": {
            "ports": "Por_ts",
            "hosts": "Hos_ts",
            "version": "Ver_sion",
            "install": "In_stall",
            "pastebin": "Paste_bin",
            "anti": "An_ti",
            "group": "Group",
            "certificate": "Certifi_cate",
        },
    },
    "dcrat": {
        "settings_type": "Client.Settings",
        "salt": None,
        "salt_initializer_type": "Client.Algorithm.Aes256",
        "fields": {
            "ports": "Por_ts",
            "hosts": "Hos_ts",
            "version": "Ver_sion",
            "install": "In_stall",
            "pastebin": "Paste_bin",
            "anti": "An_ti",
            "group": "Group",
            "certificate": "Certifi_cate",
        },
    },
}


class ConfigRecoveryError(ValueError):
    """設定metadata、暗号形式、または認証tagが期待形状と一致しない。"""


class _LiteralBudgetError(ConfigRecoveryError):
    """非公開literalの保持予算を超え、途中候補の公開も拒否する。"""


class SettingsLiteralAssessment:
    """候補値を非公開領域へ隔離した、Settings初期化の静的評価結果。

    公開には`settings_literal_diagnostics`を使う。repr、標準JSONの文字列表現、
    state projectionへliteral値やfield名を含めず、候補値は内部consumerだけが扱う。
    """

    __slots__ = ("_diagnostics", "_private_literals")

    def __init__(
        self, diagnostics: dict[str, Any], private_literals: dict[str, str]
    ) -> None:
        self._diagnostics = diagnostics
        self._private_literals = private_literals

    @property
    def status(self) -> str:
        """観測候補と通常成功を分離する評価状態を返す。"""
        return self._diagnostics["status"]

    def __repr__(self) -> str:
        return (
            f"SettingsLiteralAssessment(status={self.status!r}, "
            f"fields={self._diagnostics['counts']['fields']}, "
            f"effects_unresolved={self._diagnostics['effects_unresolved']!r})"
        )

    def __getstate__(self) -> dict[str, Any]:
        """汎用serializerへ候補値ではなく公開診断だけを渡す。"""
        return settings_literal_diagnostics(self)


def settings_literal_diagnostics(assessment: SettingsLiteralAssessment) -> dict[str, Any]:
    """候補literal、field名、例外本文を含まない独立した公開診断copyを返す。"""

    if not isinstance(assessment, SettingsLiteralAssessment):
        raise TypeError("SettingsLiteralAssessmentだけを公開診断へ変換できます")
    return json.loads(json.dumps(assessment._diagnostics, ensure_ascii=False))


def _bounded_method_body_data(data: bytes, pe: dnfile.dnPE, rva: int) -> bytes:
    """宣言されたCIL code範囲を検証し、有界なmethod bodyだけを返す。"""

    if not isinstance(rva, int) or isinstance(rva, bool) or rva <= 0:
        raise ConfigRecoveryError("CIL method RVAが不正です")
    try:
        offset = pe.get_offset_from_rva(rva)
    except Exception as exc:
        raise ConfigRecoveryError("CIL method RVAをfile offsetへ変換できません") from exc
    if (
        not isinstance(offset, int)
        or isinstance(offset, bool)
        or not 0 <= offset < len(data)
    ):
        raise ConfigRecoveryError("CIL method offsetが入力範囲外です")

    first = data[offset]
    header_kind = first & 0x03
    if header_kind == 0x02:  # ECMA-335 tiny format
        header_size = 1
        code_size = first >> 2
        more_sections = False
    elif header_kind == 0x03:  # ECMA-335 fat format
        if offset + 12 > len(data):
            raise ConfigRecoveryError("fat CIL method headerが入力範囲外です")
        flags_and_size = struct.unpack_from("<H", data, offset)[0]
        header_size = ((flags_and_size >> 12) & 0x0F) * 4
        if not 12 <= header_size <= 60 or offset + header_size > len(data):
            raise ConfigRecoveryError("fat CIL method header sizeが不正です")
        code_size = struct.unpack_from("<I", data, offset + 4)[0]
        more_sections = bool(flags_and_size & 0x08)
    else:
        raise ConfigRecoveryError("CIL method header形式が不正です")

    if code_size > MAX_METHOD_BODY_BYTES:
        raise ConfigRecoveryError("CIL method code sizeが上限を超えています")
    code_end = offset + header_size + code_size
    if code_end > len(data):
        raise ConfigRecoveryError("CIL method codeが入力範囲外です")
    if not more_sections:
        return data[offset:code_end]

    # 例外処理sectionはdncilに解析させるが、入力末尾全体は渡さない。
    bounded_end = min(len(data), offset + MAX_METHOD_BODY_BYTES)
    if bounded_end < code_end:
        raise ConfigRecoveryError("CIL method bodyが解析上限を超えています")
    return data[offset:bounded_end]


def read_bounded_method_body(data: bytes, pe: dnfile.dnPE, rva: int) -> object:
    """不正な巨大code sizeをdncilへ渡さずmethod bodyを解析する。"""

    try:
        return read_method_body_from_bytes(_bounded_method_body_data(data, pe, rva))
    except ConfigRecoveryError:
        raise
    except Exception as exc:
        raise ConfigRecoveryError("CIL method bodyを解析できません") from exc


_DOMAIN_LABEL = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\Z")
_BUILD_PLACEHOLDER = re.compile(r"(?:%[A-Za-z][A-Za-z0-9_]*%|<[A-Za-z0-9_]+>)\Z")
_CHACHA_CONSTANTS = (1634760805, 857760878, 2036477234, 1797285236)


def _field_owners(pe: dnfile.dnPE) -> dict[int, str]:
    owners: dict[int, str] = {}
    try:
        for row in pe.net.mdtables.TypeDef.rows:
            owner = ".".join(
                value for value in (str(row.TypeNamespace), str(row.TypeName)) if value
            )
            for field in row.FieldList:
                index = field.row_index
                if (
                    not isinstance(index, int)
                    or isinstance(index, bool)
                    or not 1 <= index <= len(pe.net.mdtables.Field.rows)
                    or index in owners
                ):
                    raise ConfigRecoveryError("FieldDef所有型が不正または競合しています")
                owners[index] = owner
    except ConfigRecoveryError:
        raise
    except Exception as exc:
        raise ConfigRecoveryError("FieldDef所有型を解析できません") from exc
    return owners


def _method_owners(pe: dnfile.dnPE) -> dict[int, str]:
    owners: dict[int, str] = {}
    try:
        for row in pe.net.mdtables.TypeDef.rows:
            owner = ".".join(
                value for value in (str(row.TypeNamespace), str(row.TypeName)) if value
            )
            for method in row.MethodList:
                index = method.row_index
                if (
                    not isinstance(index, int)
                    or isinstance(index, bool)
                    or not 1 <= index <= len(pe.net.mdtables.MethodDef.rows)
                    or index in owners
                ):
                    raise ConfigRecoveryError("MethodDef所有型が不正または競合しています")
                owners[index] = owner
    except ConfigRecoveryError:
        raise
    except Exception as exc:
        raise ConfigRecoveryError("MethodDef所有型を解析できません") from exc
    return owners


def _method_owner(pe: dnfile.dnPE, method_index: int) -> str | None:
    return _method_owners(pe).get(method_index)


def _require_unique_type(pe: dnfile.dnPE, qualified_name: str) -> None:
    matches = [
        row
        for row in pe.net.mdtables.TypeDef.rows
        if ".".join(value for value in (str(row.TypeNamespace), str(row.TypeName)) if value)
        == qualified_name
    ]
    if len(matches) != 1:
        raise ConfigRecoveryError("static initializerの所有型が欠落または競合しています")


def _managed_pe(data: bytes) -> dnfile.dnPE:
    """入力と必要metadata tableの上限を確認して静的parserへ渡す。"""

    if not isinstance(data, bytes) or not 1 <= len(data) <= MAX_INPUT_BYTES:
        raise ConfigRecoveryError("入力bytesが欠落または上限外です")
    try:
        pe = dnfile.dnPE(data=data)
        tables = pe.net.mdtables if pe.net is not None else None
        if tables is None:
            raise ConfigRecoveryError("CLR metadataがありません")
        for table in (tables.TypeDef, tables.Field, tables.MethodDef):
            if table is None or not 1 <= len(table.rows) <= MAX_METADATA_ROWS:
                raise ConfigRecoveryError("CLR tableが欠落または上限外です")
        return pe
    except ConfigRecoveryError:
        raise
    except Exception as exc:
        raise ConfigRecoveryError("PE／CLR metadataを解析できません") from exc


def _field_index(pe: dnfile.dnPE, operand: object) -> int:
    """FieldDef tokenだけを境界確認し、不正なrow参照を拒否する。"""

    if (
        not isinstance(operand, int)
        or isinstance(operand, bool)
        or operand >> 24 != 0x04
        or not 1 <= (operand & 0xFFFFFF) <= len(pe.net.mdtables.Field.rows)
    ):
        raise ConfigRecoveryError("static field tokenが不正です")
    return operand & 0xFFFFFF


def _user_string(pe: dnfile.dnPE, operand: object) -> str:
    """UserString tokenと値の型・長さを確認し、例外断片を公開しない。"""

    if (
        not isinstance(operand, int)
        or isinstance(operand, bool)
        or operand >> 24 != 0x70
        or not 1 <= (operand & 0xFFFFFF)
    ):
        raise ConfigRecoveryError("user string tokenが不正です")
    try:
        value = pe.net.user_strings.get(operand & 0xFFFFFF).value
    except Exception as exc:
        raise ConfigRecoveryError("user stringを解析できません") from exc
    if not isinstance(value, str) or len(value) > MAX_ENCODED_SETTING_CHARS:
        raise ConfigRecoveryError("user stringが文字列ではないか上限を超えています")
    return value


class _LiteralReader:
    """cctor内のimmutable文字列をtoken単位で一度だけ取得し、総保持量を限定する。"""

    __slots__ = ("_pe", "_cache", "_utf8_bytes")

    def __init__(self, pe: dnfile.dnPE) -> None:
        self._pe = pe
        self._cache: dict[int, str] = {}
        self._utf8_bytes = 0

    def read(self, token: object) -> str:
        """不正tokenと予算超過を拒否し、field-copyで文字列を複製しない。"""

        if (not isinstance(token, int) or isinstance(token, bool) or token >> 24 != 0x70
                or not 1 <= (token & 0xFFFFFF)):
            raise ConfigRecoveryError("user string tokenが不正です")
        if token in self._cache:
            return self._cache[token]
        if len(self._cache) >= MAX_LITERAL_COUNT:
            raise _LiteralBudgetError("user stringのdistinct件数が上限を超えています")
        value = _user_string(self._pe, token)
        size = 0
        try:
            for start in range(0, len(value), 8192):
                size += len(value[start:start + 8192].encode("utf-8"))
                if self._utf8_bytes + size > MAX_LITERAL_UTF8_BYTES:
                    raise _LiteralBudgetError("user stringのUTF-8総保持量が上限を超えています")
        except UnicodeEncodeError as exc:
            raise ConfigRecoveryError("user stringのUnicode形式が不正です") from exc
        self._cache[token] = value
        self._utf8_bytes += size
        return value


def _validate_string_field(pe: dnfile.dnPE, index: int) -> None:
    """静的なstring FieldDefだけへliteralを対応付ける。"""

    field = pe.net.mdtables.Field.rows[index - 1]
    try:
        if (
            field.Signature.value != b"\x06\x0e"
            or field.Flags.fdStatic is not True
            or field.Flags.fdLiteral
        ):
            raise ConfigRecoveryError("Settings fieldがstatic string宣言ではありません")
    except ConfigRecoveryError:
        raise
    except Exception as exc:
        raise ConfigRecoveryError("Settings field宣言を解析できません") from exc


def _straight_line_initializer(body: object) -> list:
    """分岐や例外経路を評価せず、直線の初期化構文だけを許可する。"""

    instructions = body.instructions
    if len(instructions) > MAX_INITIALIZER_INSTRUCTIONS:
        raise ConfigRecoveryError("static initializer命令数が上限を超えています")
    if body.exception_handlers:
        raise ConfigRecoveryError("static initializerに未対応の例外handlerがあります")
    if any(
        item.opcode.name.startswith(("br", "beq", "bne", "bge", "bgt", "ble", "blt", "leave"))
        or item.opcode.name in {"switch", "jmp", "throw", "rethrow", "endfinally", "endfilter"}
        for item in instructions
    ):
        raise ConfigRecoveryError("static initializerに未対応の制御フローがあります")
    meaningful = [item for item in instructions if item.opcode.name != "nop"]
    if not meaningful or meaningful[-1].opcode.name != "ret" or any(
        item.opcode.name == "ret" for item in meaningful[:-1]
    ):
        raise ConfigRecoveryError("static initializerのret位置が不正です")
    return instructions


def _validate_cctor(row: object) -> None:
    """default convention、引数なしvoid、static宣言のcctorだけを許可する。"""

    try:
        if row.Signature.value != b"\x00\x00\x01" or row.Flags.mdStatic is not True:
            raise ConfigRecoveryError("static cctor宣言のsignatureまたはflagsが不正です")
        flags = row.struct.Flags
        impl_flags = row.struct.ImplFlags
        if any(not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= 0xFFFF
               for value in (flags, impl_flags)):
            raise ConfigRecoveryError("static cctorのraw flagsがuint16ではありません")
        if not flags & 0x10 or flags & 0x2408 or flags & 0x07 == 0x07:
            raise ConfigRecoveryError("static cctorに未対応のmethod flagsがあります")
        # IL managed以外、ForwardRef/InternalCall、未レビューreservedbitを拒否する。
        # NoInlining/Synchronized/NoOptimization/PreserveSig/積極最適化bitは許容する。
        if impl_flags & 0x1017 or impl_flags & ~0x03E8:
            raise ConfigRecoveryError("static cctorに未対応のimplementation flagsがあります")
    except ConfigRecoveryError:
        raise
    except Exception as exc:
        raise ConfigRecoveryError("static cctor宣言を解析できません") from exc


def _settings_initializer(data: bytes, settings_type: str) -> tuple:
    """strict回収と候補評価に共通する一意なcctor宣言とbodyを得る。"""

    pe = _managed_pe(data)
    _require_unique_type(pe, settings_type)
    owners = _field_owners(pe)
    method_owners = _method_owners(pe)
    methods = [
        (index, row)
        for index, row in enumerate(pe.net.mdtables.MethodDef.rows, 1)
        if str(row.Name) == ".cctor" and method_owners.get(index) == settings_type
    ]
    if len(methods) != 1:
        raise ConfigRecoveryError("Settings cctorを一意に確認できません")
    index, row = methods[0]
    _validate_cctor(row)
    body = read_bounded_method_body(data, pe, row.Rva)
    return pe, owners, body, 0x06000000 | index, _LiteralReader(pe)


def _collect_settings_literals(pe: dnfile.dnPE, owners: dict[int, str], instructions: list,
                              settings_type: str, literal_reader: _LiteralReader) -> dict[str, str]:
    """従来のstrict隣接代入契約を維持し、実行せずliteralだけを対応付ける。"""

    constants: dict[int, str] = {}
    assigned: set[int] = set()
    values: dict[str, str] = {}
    pending: str | None = None
    terminated = False
    for instruction in instructions:
        opcode = instruction.opcode.name
        operand = getattr(instruction.operand, "value", instruction.operand)
        if opcode == "nop":
            continue
        if terminated:
            raise ConfigRecoveryError("Settings cctorのret後に未対応命令があります")
        if opcode == "ret":
            pending = None
            terminated = True
            continue
        if opcode == "ldstr":
            if pending is not None:
                raise ConfigRecoveryError("Settings literalの隣接代入形状が不正です")
            pending = literal_reader.read(operand)
            continue
        if opcode == "ldsfld":
            if pending is not None:
                raise ConfigRecoveryError("Settings field参照の隣接代入形状が不正です")
            row_index = _field_index(pe, operand)
            if owners.get(row_index) != settings_type or row_index not in constants:
                raise ConfigRecoveryError("Settings field参照が未解決です")
            pending = constants[row_index]
            continue
        if opcode == "stsfld":
            row_index = _field_index(pe, operand)
            if owners.get(row_index) != settings_type:
                raise ConfigRecoveryError("Settings cctorに別型のfield代入があります")
            if row_index in assigned:
                raise ConfigRecoveryError("Settings fieldへの重複代入があります")
            assigned.add(row_index)
            if pending is not None:
                _validate_string_field(pe, row_index)
                name = str(pe.net.mdtables.Field.rows[row_index - 1].Name)
                if name in values:
                    raise ConfigRecoveryError("Settings field名が競合しています")
                constants[row_index] = pending
                values[name] = pending
            pending = None
            continue
        if opcode in {"call", "callvirt", "calli", "newobj", "stsflda", "ldsflda"}:
            raise ConfigRecoveryError("Settings cctorに未対応callまたはfield addressがあります")
        pending = None
    if not terminated:
        raise ConfigRecoveryError("Settings cctorのretがありません")
    if not values:
        raise ConfigRecoveryError("Settings cctorのfield literalを復元できません")
    return values


def settings_literals(data: bytes, settings_type: str = "Client.Settings") -> dict[str, str]:
    """一意な直線cctorの隣接literal代入と既知field参照を構文的に回収する。

    stack、CLR、分岐を実行しない。参照は同じcctorで先に確定した同型のfieldに
    限定し、前方参照、重複代入、分岐、例外handlerはfail-closedで拒否する。
    partial評価の候補を、この成功mapへ渡すことはない。
    """

    pe, owners, body, _token, literal_reader = _settings_initializer(data, settings_type)
    return _collect_settings_literals(pe, owners, _straight_line_initializer(body), settings_type, literal_reader)


def _assessment_instructions(body: object) -> list:
    """instruction境界を検証する。分岐の到達性やEH経路は解釈しない。"""

    instructions = body.instructions
    if not isinstance(instructions, list) or not 1 <= len(instructions) <= MAX_INITIALIZER_INSTRUCTIONS:
        raise ConfigRecoveryError("assessment命令数が欠落または上限外です")
    start = body.offset + body.header_size
    end = start + body.code_size
    if (any(not isinstance(value, int) or isinstance(value, bool) for value in
            (body.offset, body.header_size, body.code_size)) or body.offset != 0
            or not 0 <= body.header_size <= 60 or not 1 <= body.code_size <= MAX_METHOD_BODY_BYTES):
        raise ConfigRecoveryError("assessment body境界が不正です")
    expected = start
    boundaries = set()
    for instruction in instructions:
        if (not isinstance(instruction.offset, int) or isinstance(instruction.offset, bool)
                or instruction.offset != expected or not isinstance(instruction.size, int)
                or isinstance(instruction.size, bool) or instruction.size <= 0
                or not isinstance(instruction.opcode.name, str)
                or instruction.opcode.name not in _ASSESSMENT_OPCODE_NAMES):
            raise ConfigRecoveryError("assessment instruction境界が不正です")
        boundaries.add(instruction.offset)
        expected += instruction.size
        if expected > end:
            raise ConfigRecoveryError("assessment instructionがcode範囲外です")
    if expected != end:
        raise ConfigRecoveryError("assessment code範囲が一致しません")
    for instruction in instructions:
        opcode = instruction.opcode.name
        operand = getattr(instruction.operand, "value", instruction.operand)
        if opcode != "break" and opcode.startswith(("br", "beq", "bne", "bge", "bgt", "ble", "blt", "leave")):
            targets = [operand]
        elif opcode == "switch":
            if not isinstance(operand, list) or len(operand) > MAX_INITIALIZER_INSTRUCTIONS:
                raise ConfigRecoveryError("assessment switch targetが不正です")
            targets = operand
        else:
            continue
        if any(not isinstance(target, int) or isinstance(target, bool)
               or target not in boundaries for target in targets):
            raise ConfigRecoveryError("assessment branch targetが不正です")
    handlers = body.exception_handlers
    if not isinstance(handlers, list) or len(handlers) > MAX_ASSESSMENT_ASSIGNMENTS:
        raise ConfigRecoveryError("assessment EH件数が上限外です")
    code_boundaries = {offset - start for offset in boundaries}
    for handler in handlers:
        positions = (handler.try_start, handler.try_end, handler.handler_start, handler.handler_end)
        if (any(not isinstance(value, int) or isinstance(value, bool) for value in positions)
                or handler.try_start not in code_boundaries
                or handler.handler_start not in code_boundaries
                or handler.try_end not in code_boundaries | {body.code_size}
                or handler.handler_end not in code_boundaries | {body.code_size}
                or handler.try_start >= handler.try_end or handler.handler_start >= handler.handler_end
                or not isinstance(handler.exception_type, int) or isinstance(handler.exception_type, bool)
                or handler.exception_type not in {0, 1, 2, 4}
                or (handler.exception_type == 1 and (not isinstance(handler.filter_start, int)
                    or isinstance(handler.filter_start, bool) or handler.filter_start not in code_boundaries))):
            raise ConfigRecoveryError("assessment EH境界が不正です")
    return instructions


def _assessment_type_token(resolver: object, operand: object) -> None:
    """型tokenのsnapshot境界だけを確認し、型やruntimeの意味を評価しない。"""

    if not isinstance(operand, int) or isinstance(operand, bool) or not 0 <= operand <= 0xFFFFFFFF:
        raise ConfigRecoveryError("assessment type tokenが不正です")
    name = {0x01: "TypeRef", 0x02: "TypeDef", 0x1B: "TypeSpec"}.get(operand >> 24)
    index = operand & 0xFFFFFF
    if name is None or not 1 <= index <= len(resolver.tables[name]["rows"]):
        raise ConfigRecoveryError("assessment type tokenが範囲外です")


def assess_settings_literals(data: bytes, settings_type: str = "Client.Settings") -> SettingsLiteralAssessment:
    """未解決効果を残しながら、fieldごとに隣接literal代入を静的観測する。

    completeは従来strict契約の成立、partialは実行時の最終値を証明しない観測、
    rejectedはmetadata／body／token／上限の不成立を表す。分岐やEHは解釈せず、
    call、newobj、address escapeの効果を未知のままにする。候補は非公開であり、
    公開には`settings_literal_diagnostics`だけを使用する。通常recoverは使わない。
    """

    diagnostics: dict[str, Any] = {
        "schema_version": 1, "status": "rejected", "method_token": None,
        "effects_unresolved": True, "effects": [], "fields": [], "reasons": [],
        "counts": {"fields": 0, "assignments": 0, "instructions": 0},
        "candidate_scope": "lexical_observation_not_final_runtime_value",
        "literal_values_published": False, "field_names_published": False,
        "executed": False, "emulated": False, "network_contacted": False,
    }
    failure_reason = "metadata_or_body_invalid"
    try:
        from unpackers.managed_metadata import MetadataResolver

        pe, owners, body, method_token, literal_reader = _settings_initializer(data, settings_type)
        diagnostics["method_token"] = f"0x{method_token:08x}"
        failure_reason = "body_or_instruction_boundary_invalid"
        if isinstance(body.instructions, list) and len(body.instructions) > MAX_INITIALIZER_INSTRUCTIONS:
            failure_reason = "assessment_limit_exceeded"
        instructions = _assessment_instructions(body)
        diagnostics["counts"]["instructions"] = len(instructions)
        failure_reason = "metadata_declaration_invalid"
        resolver = MetadataResolver(pe)
        if not resolver.coverage()["complete"] or resolver.resolve(method_token)["status"] != "resolved":
            raise ConfigRecoveryError("assessment metadata宣言が不完全です")
        for handler in body.exception_handlers:
            if handler.exception_type == 0:
                _assessment_type_token(resolver, getattr(handler.catch_type, "value", handler.catch_type))
        target_fields = [index for index, owner in owners.items() if owner == settings_type]
        if len(target_fields) > MAX_ASSESSMENT_FIELDS:
            failure_reason = "assessment_limit_exceeded"
            raise ConfigRecoveryError("assessment field件数が上限を超えています")
        names: dict[str, list[int]] = {}
        for index in target_fields:
            names.setdefault(str(pe.net.mdtables.Field.rows[index - 1].Name), []).append(index)
        collisions = {index for indices in names.values() if len(indices) > 1 for index in indices}
        records: dict[int, dict[str, Any]] = {}
        literals: dict[int, str] = {}
        dependencies: dict[int, set[int]] = {}
        effects: list[dict[str, Any]] = []
        previous = None
        assignments = 0
        prior_producer = None
        failure_reason = "metadata_token_or_signature_invalid"
        for instruction in instructions:
            opcode = instruction.opcode.name
            operand = getattr(instruction.operand, "value", instruction.operand)
            if opcode == "nop":
                continue
            if opcode == "ldstr":
                literal_reader.read(operand)
            if opcode in {"ldsfld", "stsfld", "ldsflda", "stfld", "ldfld", "ldflda"}:
                index = _field_index(pe, operand)
                if resolver.resolve(operand, kind="field")["status"] != "resolved":
                    raise ConfigRecoveryError("assessment FieldDef宣言が不正です")
                if opcode.startswith(("lds", "sts")):
                    field = pe.net.mdtables.Field.rows[index - 1]
                    if field.Flags.fdStatic is not True or field.Flags.fdLiteral:
                        raise ConfigRecoveryError("assessment static field宣言が不正です")
                if opcode.startswith(("lds", "sts")) and owners.get(index) != settings_type:
                    effects.append({"offset": instruction.offset, "reason": "cross_type_static_access_unresolved"})
            if opcode in {"box", "unbox", "unbox.any", "castclass", "isinst", "newarr", "ldelema",
                          "ldelem", "stelem", "cpobj", "ldobj", "stobj", "initobj", "sizeof",
                          "constrained.", "refanyval", "mkrefany"}:
                _assessment_type_token(resolver, operand)
            if opcode == "ldtoken":
                if isinstance(operand, int) and not isinstance(operand, bool) and operand >> 24 in {0x04, 0x06, 0x0A, 0x2B}:
                    reference = resolver.resolve(operand, kind="field" if operand >> 24 == 0x04 else "method")
                    if reference["status"] != "resolved":
                        raise ConfigRecoveryError("assessment handle tokenが不正です")
                else:
                    _assessment_type_token(resolver, operand)
                effects.append({"offset": instruction.offset, "reason": "token_handle_unresolved"})
            if opcode in {"call", "callvirt", "calli", "newobj", "jmp", "ldftn", "ldvirtftn"}:
                kind = "indirect_signature" if opcode == "calli" else "method"
                declaration = resolver.resolve(operand, kind=kind)
                if declaration["status"] != "resolved" and not (
                    opcode == "calli" and declaration.get("reason") == "indirect_call_target_not_statically_known"
                ):
                    raise ConfigRecoveryError("assessment call宣言が不正です")
                effects.append({"offset": instruction.offset, "reason": "call_effects_unresolved",
                                "reference_token": declaration["token"]})
            elif opcode in {"ldsflda", "ldflda", "stsflda", "ldloca", "ldloca.s", "ldarga", "ldarga.s"}:
                effects.append({"offset": instruction.offset, "reason": "address_escape_unresolved"})
            elif opcode.startswith("stind.") or opcode in {"stobj", "cpobj", "initobj", "cpblk", "initblk", "stfld"}:
                effects.append({"offset": instruction.offset, "reason": "indirect_write_unresolved"})
            elif (opcode.startswith(("br", "beq", "bne", "bge", "bgt", "ble", "blt", "leave"))
                  or opcode in {"switch", "throw", "rethrow", "endfinally", "endfilter"}):
                effects.append({"offset": instruction.offset, "reason": "control_flow_not_interpreted"})
            if len(effects) > MAX_ASSESSMENT_ASSIGNMENTS:
                failure_reason = "assessment_limit_exceeded"
                raise ConfigRecoveryError("assessment effect件数が上限を超えています")
            if opcode == "stsfld":
                assignments += 1
                if assignments > MAX_ASSESSMENT_ASSIGNMENTS:
                    failure_reason = "assessment_limit_exceeded"
                    raise ConfigRecoveryError("assessment代入件数が上限を超えています")
                record = records.setdefault(index, {"field_token": f"0x{operand:08x}",
                    "status": "unresolved_assignment", "assignments": [], "dependency_tokens": [], "reasons": []})
                reasons = record["reasons"]
                if record["assignments"]:
                    reasons.append("duplicate_assignment")
                if owners.get(index) != settings_type:
                    reasons.append("cross_type_assignment")
                if index in collisions:
                    reasons.append("field_name_collision")
                observation = {"assignment_offset": instruction.offset, "source_offset": None,
                               "kind": "unresolved", "dependency_token": None}
                if previous is not None and previous.opcode.name in {"ldstr", "ldsfld"}:
                    observation["source_offset"] = previous.offset
                    source = getattr(previous.operand, "value", previous.operand)
                    _validate_string_field(pe, index)
                    if prior_producer is not None and prior_producer.opcode.name in {"ldstr", "ldsfld"}:
                        reasons.append("multiple_lexical_producers")
                    if previous.opcode.name == "ldstr":
                        observation["kind"] = "adjacent_literal"
                        literals[index] = literal_reader.read(source)
                    else:
                        source_index = _field_index(pe, source)
                        token = f"0x{source:08x}"
                        observation.update(kind="prior_field_copy", dependency_token=token)
                        dependencies.setdefault(index, set()).add(source_index)
                        record["dependency_tokens"].append(token)
                        if owners.get(source_index) != settings_type:
                            reasons.append("cross_type_dependency")
                        elif source_index not in literals:
                            reasons.append("forward_or_unresolved_dependency")
                        else:
                            literals[index] = literals[source_index]
                else:
                    reasons.append("literal_rhs_not_lexically_proven")
                record["assignments"].append(observation)
                if len(records) > MAX_ASSESSMENT_FIELDS:
                    failure_reason = "assessment_limit_exceeded"
                    raise ConfigRecoveryError("assessment field件数が上限を超えています")
            prior_producer = previous
            previous = instruction
        if body.exception_handlers:
            effects.append({"offset": None, "reason": "exception_flow_not_interpreted"})
        meaningful = [instruction for instruction in instructions if instruction.opcode.name != "nop"]
        if not meaningful or meaningful[-1].opcode.name != "ret" or any(item.opcode.name == "ret" for item in meaningful[:-1]):
            effects.append({"offset": None, "reason": "termination_shape_not_proven"})
        if len(effects) > MAX_ASSESSMENT_ASSIGNMENTS:
            failure_reason = "assessment_limit_exceeded"
            raise ConfigRecoveryError("assessment effect件数が上限を超えています")
        invalid = {index for index, record in records.items() if record["reasons"]}
        # 到達経路や値を計算せず、構文依存先の不成立だけを推移的に伝播する。
        while True:
            affected = {index for index, sources in dependencies.items() if sources & invalid} - invalid
            if not affected:
                break
            for index in affected:
                records[index]["reasons"].append("dependency_invalidated")
            invalid.update(affected)
        try:
            _collect_settings_literals(pe, owners, _straight_line_initializer(body), settings_type, literal_reader)
            strict_complete = not effects and not invalid
        except ConfigRecoveryError:
            strict_complete = False
        diagnostics.update(status="complete" if strict_complete else "partial",
                           effects_unresolved=bool(effects), effects=effects)
        if not strict_complete:
            diagnostics["reasons"] = ["strict_contract_not_met"]
        for index, record in records.items():
            record["reasons"] = sorted(set(record["reasons"]))
            record["dependency_tokens"] = sorted(set(record["dependency_tokens"]))
            record["status"] = ("invalidated" if index in invalid else
                                "observed_literal" if effects else "proven_literal")
        diagnostics["fields"] = list(records.values())
        diagnostics["counts"].update(fields=len(records), assignments=assignments)
        private = {f"0x{index | 0x04000000:08x}": value for index, value in literals.items() if index not in invalid}
        return SettingsLiteralAssessment(diagnostics, private)
    except Exception as failure:
        if isinstance(failure, _LiteralBudgetError):
            failure_reason = "literal_retention_budget_exceeded"
        diagnostics.update(status="rejected", fields=[], effects=[], reasons=[failure_reason], effects_unresolved=True)
        diagnostics["counts"].update(fields=0, assignments=0)
        return SettingsLiteralAssessment(diagnostics, {})


def _member_name(pe: dnfile.dnPE, token: int, owners: dict[int, str]) -> str:
    """既存ChaCha形状比較用の限定名を返す。saltのAPI照合には使わない。"""

    table_id = (token >> 24) & 0xFF
    row_id = token & 0xFFFFFF
    if table_id == 0x06:
        table = pe.net.mdtables.MethodDef
        if table is not None and 1 <= row_id <= len(table.rows):
            return f"{owners.get(row_id, '')}.{table.rows[row_id - 1].Name}".strip(".")
    if table_id == 0x0A:
        table = pe.net.mdtables.MemberRef
        if table is not None and 1 <= row_id <= len(table.rows):
            return str(table.rows[row_id - 1].Name)
    return ""


def static_salt(data: bytes, initializer_type: str) -> bytes:
    """exact framework宣言と隣接receiver構文で限定ASCII saltだけを回収する。

    宣言一致はruntime assembly、dispatch、副作用、nonthrowingの証明ではない。
    getter→literal→GetBytes→Salt→ret以外の構文・未知callは一切評価しない。
    """

    from unpackers.managed_metadata import MetadataResolver

    pe, field_owners, body, cctor_token, literal_reader = _settings_initializer(data, initializer_type)
    _assessment_instructions(body)
    instructions = [item for item in _straight_line_initializer(body) if item.opcode.name != "nop"]
    if tuple(item.opcode.name for item in instructions) != ("call", "ldstr", "callvirt", "stsfld", "ret"):
        raise ConfigRecoveryError("saltの隣接ASCII receiver構文が一致しません")
    operands = [getattr(item.operand, "value", item.operand) for item in instructions]
    resolver = MetadataResolver(pe)
    getter = resolver.match_framework_member(operands[0], "system_text_encoding_get_ascii_v1")
    get_bytes = resolver.match_framework_member(operands[2], "system_text_encoding_get_bytes_string_v1")
    if (not resolver.coverage()["complete"] or resolver.resolve(cctor_token)["status"] != "resolved"
            or getter["status"] != "matched_declaration" or get_bytes["status"] != "matched_declaration"
            or getter.get("declaring_type_profile") != "system_text_encoding"
            or get_bytes.get("declaring_type_profile") != "system_text_encoding"
            or getter.get("assembly_identity_profile") is None or getter.get("assembly_version") is None
            or getter.get("assembly_identity_profile") != get_bytes.get("assembly_identity_profile")
            or getter.get("assembly_version") != get_bytes.get("assembly_version")):
        raise ConfigRecoveryError("saltのframework member宣言が一致しません")
    index = _field_index(pe, operands[3])
    field = pe.net.mdtables.Field.rows[index - 1]
    try:
        if (resolver.resolve(operands[3], kind="field")["status"] != "resolved"
                or field_owners.get(index) != initializer_type or str(field.Name) != "Salt"
                or field.Signature.value != b"\x06\x1d\x05" or field.Flags.fdStatic is not True
                or field.Flags.fdLiteral or sum(1 for rid, owner in field_owners.items()
                    if owner == initializer_type and str(pe.net.mdtables.Field.rows[rid - 1].Name) == "Salt") != 1):
            raise ConfigRecoveryError("salt field宣言が不正または競合しています")
    except ConfigRecoveryError:
        raise
    except Exception as exc:
        raise ConfigRecoveryError("salt field宣言を解析できません") from exc
    literal = literal_reader.read(operands[1])
    if not 8 <= len(literal) <= 128:
        raise ConfigRecoveryError("salt literalの長さが範囲外です")
    try:
        return literal.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ConfigRecoveryError("salt literalがASCIIではありません") from exc


def _derive(master_key: str, salt: bytes) -> tuple[bytes, bytes]:
    if not isinstance(master_key, str) or not isinstance(salt, bytes):
        raise ConfigRecoveryError("master keyまたはsaltの型が不正です")
    try:
        raw_key = master_key.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ConfigRecoveryError("master keyがUTF-8ではありません") from exc
    if not 1 <= len(raw_key) <= MAX_MASTER_KEY_BYTES or not 8 <= len(salt) <= 128:
        raise ConfigRecoveryError("master keyまたはsaltの長さが上限外です")
    material = hashlib.pbkdf2_hmac("sha1", raw_key, salt, 50_000, 96)
    return material[:32], material[32:]


def _decode_setting_bytes(ciphertext: str) -> bytes:
    if not isinstance(ciphertext, str) or len(ciphertext) > MAX_ENCODED_SETTING_CHARS:
        raise ConfigRecoveryError("暗号化設定値の型または長さが上限外です")
    try:
        raw = base64.b64decode(ciphertext, validate=True)
    except ValueError as exc:
        raise ConfigRecoveryError("設定値が正しいBase64ではありません") from exc
    if not 64 <= len(raw) <= MAX_SETTING_BYTES or (len(raw) - 48) % 16:
        raise ConfigRecoveryError("暗号化設定値の長さが不正です")
    return raw


def _decrypt_setting_with_keys(raw: bytes, keys: tuple[bytes, bytes]) -> str:
    encryption_key, authentication_key = keys
    observed_mac, iv, encrypted = raw[:32], raw[32:48], raw[48:]
    expected_mac = hmac.new(authentication_key, raw[32:], hashlib.sha256).digest()
    if not hmac.compare_digest(observed_mac, expected_mac):
        raise ConfigRecoveryError("設定値のHMACが一致しません")
    decryptor = Cipher(algorithms.AES(encryption_key), modes.CBC(iv)).decryptor()
    padded = decryptor.update(encrypted) + decryptor.finalize()
    unpadder = PKCS7(128).unpadder()
    try:
        plain = unpadder.update(padded) + unpadder.finalize()
        return plain.decode("utf-8")
    except (ValueError, UnicodeDecodeError) as exc:
        raise ConfigRecoveryError("設定値のpaddingまたはUTF-8が不正です") from exc


def decrypt_setting(ciphertext: str, master_key: str, salt: bytes) -> str:
    """AsyncRAT系の有界なHMAC-SHA256＋AES-256-CBC設定を認証後に復号する。"""

    raw = _decode_setting_bytes(ciphertext)
    return _decrypt_setting_with_keys(raw, _derive(master_key, salt))


def _rotate_left32(value: int, count: int) -> int:
    return ((value << count) & 0xFFFFFFFF) | (value >> (32 - count))


def _chacha_quarter_round(
    state: list[int], a: int, b: int, c: int, d: int
) -> None:
    state[a] = (state[a] + state[b]) & 0xFFFFFFFF
    state[d] = _rotate_left32(state[d] ^ state[a], 16)
    state[c] = (state[c] + state[d]) & 0xFFFFFFFF
    state[b] = _rotate_left32(state[b] ^ state[c], 12)
    state[a] = (state[a] + state[b]) & 0xFFFFFFFF
    state[d] = _rotate_left32(state[d] ^ state[a], 8)
    state[c] = (state[c] + state[d]) & 0xFFFFFFFF
    state[b] = _rotate_left32(state[b] ^ state[c], 7)


def _derive_obfuscated_chacha_key(master_key: str) -> bytes:
    """review済みv0.5.8系constructorと同じ32-byte鍵混合だけを再現する。"""

    raw = master_key.encode("utf-8")
    if not 1 <= len(raw) <= 4096:
        raise ConfigRecoveryError("ChaCha20 master key長が範囲外です")
    key = bytearray(32)
    for index, value in enumerate(raw):
        key[index % 32] ^= value
        target = (index + 7) % 32
        key[target] = (key[target] + value) & 0xFF
    return bytes(key)


def _chacha20_ietf_crypt(
    payload: bytes, key: bytes, nonce: bytes, *, counter: int = 1
) -> bytes:
    """CILで確認したIETF ChaCha20 block関数を有界に静的再現する。"""

    if len(key) != 32 or len(nonce) != 12 or not 0 <= counter <= 0xFFFFFFFF:
        raise ConfigRecoveryError("ChaCha20 key、nonce、counterが不正です")
    if len(payload) > MAX_INPUT_BYTES:
        raise ConfigRecoveryError("ChaCha20 payloadが上限を超えています")
    key_words = list(struct.unpack("<8I", key))
    nonce_words = list(struct.unpack("<3I", nonce))
    output = bytearray(len(payload))
    for offset in range(0, len(payload), 64):
        initial = [*_CHACHA_CONSTANTS, *key_words, counter, *nonce_words]
        state = initial.copy()
        for _ in range(10):
            _chacha_quarter_round(state, 0, 4, 8, 12)
            _chacha_quarter_round(state, 1, 5, 9, 13)
            _chacha_quarter_round(state, 2, 6, 10, 14)
            _chacha_quarter_round(state, 3, 7, 11, 15)
            _chacha_quarter_round(state, 0, 5, 10, 15)
            _chacha_quarter_round(state, 1, 6, 11, 12)
            _chacha_quarter_round(state, 2, 7, 8, 13)
            _chacha_quarter_round(state, 3, 4, 9, 14)
        stream = struct.pack(
            "<16I",
            *((state[index] + initial[index]) & 0xFFFFFFFF for index in range(16)),
        )
        chunk = payload[offset : offset + 64]
        for index, value in enumerate(chunk):
            output[offset + index] = value ^ stream[index]
        counter = (counter + 1) & 0xFFFFFFFF
    return bytes(output)


def decrypt_obfuscated_chacha_setting(ciphertext: str, master_key: str) -> str:
    """12-byte nonce前置のreview済みChaCha20設定を復号する。"""

    if not isinstance(ciphertext, str) or len(ciphertext) > MAX_ENCODED_SETTING_CHARS:
        raise ConfigRecoveryError("ChaCha20設定値の型または長さが上限外です")
    try:
        raw = base64.b64decode(ciphertext, validate=True)
    except ValueError as exc:
        raise ConfigRecoveryError("ChaCha20設定値が正しいBase64ではありません") from exc
    if not 13 <= len(raw) <= MAX_SETTING_BYTES:
        raise ConfigRecoveryError("ChaCha20設定値の長さが不正です")
    plain = _chacha20_ietf_crypt(
        raw[12:], _derive_obfuscated_chacha_key(master_key), raw[:12]
    )
    try:
        return plain.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ConfigRecoveryError("ChaCha20設定値がUTF-8ではありません") from exc


def _runtime_base64_text(value: str) -> str:
    try:
        return base64.b64decode(value, validate=True).decode("utf-8")
    except (ValueError, UnicodeDecodeError) as exc:
        raise ConfigRecoveryError("runtime Base64文字列を復元できません") from exc


def _method_token(index: int) -> str:
    return f"0x0600{index:04x}"


def _obfuscated_chacha_profile(
    data: bytes,
) -> tuple[list[tuple[str, str]], dict[str, object]]:
    """名前ではなくcctor、初期化、ChaCha20 CIL形状からv0.5.8系を選ぶ。"""

    pe = _managed_pe(data)
    method_rows = pe.net.mdtables.MethodDef.rows
    field_rows = pe.net.mdtables.Field.rows
    if not 1 <= len(method_rows) <= 20_000 or not field_rows:
        raise ConfigRecoveryError("CLR tableが欠落または上限外です")
    method_owners = {
        method.row_index: ".".join(
            value for value in (str(row.TypeNamespace), str(row.TypeName)) if value
        )
        for row in pe.net.mdtables.TypeDef.rows
        for method in row.MethodList
    }
    field_owners = _field_owners(pe)
    bodies: dict[int, object] = {}

    def body_for(index: int) -> object:
        if index not in bodies:
            row = method_rows[index - 1]
            if not row.Rva:
                raise ConfigRecoveryError("review対象methodにCIL bodyがありません")
            try:
                bodies[index] = read_bounded_method_body(data, pe, row.Rva)
            except Exception as exc:
                raise ConfigRecoveryError("review対象CILを解析できません") from exc
        return bodies[index]

    cctor_candidates: list[tuple[int, list[tuple[str, str]]]] = []
    for index, row in enumerate(method_rows, 1):
        if str(row.Name) != ".cctor" or not row.Rva:
            continue
        owner = method_owners.get(index, "")
        assignments: list[tuple[str, str]] = []
        pending: str | None = None
        decoded = False
        for instruction in body_for(index).instructions:
            opcode = instruction.opcode.name
            operand = getattr(instruction.operand, "value", instruction.operand)
            if opcode == "ldstr" and isinstance(operand, int):
                try:
                    pending = str(pe.net.user_strings.get(operand & 0xFFFFFF).value)
                except Exception as exc:
                    raise ConfigRecoveryError("cctor user stringを解析できません") from exc
                decoded = False
                continue
            if opcode in {"call", "callvirt"} and isinstance(operand, int):
                if (
                    pending is not None
                    and _member_name(pe, operand, method_owners)
                    == "<Module>.Decrypt_Base64"
                ):
                    pending = _runtime_base64_text(pending)
                    decoded = True
                    continue
                pending = None
                decoded = False
                continue
            if opcode == "stsfld" and isinstance(operand, int):
                table_id = (operand >> 24) & 0xFF
                field_index = operand & 0xFFFFFF
                if (
                    decoded
                    and pending is not None
                    and table_id == 0x04
                    and 1 <= field_index <= len(field_rows)
                    and field_owners.get(field_index) == owner
                ):
                    assignments.append((str(field_rows[field_index - 1].Name), pending))
                pending = None
                decoded = False
                continue
            if opcode != "nop":
                pending = None
                decoded = False
        if 18 <= len(assignments) <= 32:
            cctor_candidates.append((index, assignments))
    if len(cctor_candidates) != 1:
        raise ConfigRecoveryError("難読化Settings cctorを一意に特定できません")
    cctor_index, assignments = cctor_candidates[0]
    settings_owner = method_owners.get(cctor_index, "")

    crypto_candidates: list[tuple[str, int, int, int, int]] = []
    for core_index, row in enumerate(method_rows, 1):
        if not row.Rva:
            continue
        body = body_for(core_index)
        constants = {
            getattr(instruction.operand, "value", instruction.operand)
            for instruction in body.instructions
            if instruction.opcode.name == "ldc.i4"
        }
        if not set(_CHACHA_CONSTANTS) <= constants:
            continue
        crypto_owner = method_owners.get(core_index, "")
        owner_indices = [
            index
            for index in range(1, len(method_rows) + 1)
            if method_owners.get(index) == crypto_owner and method_rows[index - 1].Rva
        ]
        ctor = []
        string_decrypt = []
        byte_decrypt = []
        for index in owner_indices:
            candidate = body_for(index)
            opcodes = [item.opcode.name for item in candidate.instructions]
            calls = [
                _member_name(
                    pe,
                    getattr(item.operand, "value", item.operand),
                    method_owners,
                )
                for item in candidate.instructions
                if item.opcode.name in {"call", "callvirt", "newobj"}
                and isinstance(getattr(item.operand, "value", item.operand), int)
            ]
            call_leafs = {name.rsplit(".", 1)[-1] for name in calls}
            integer_values = {
                getattr(item.operand, "value", item.operand)
                for item in candidate.instructions
                if item.opcode.name in {"ldc.i4", "ldc.i4.s"}
            }
            for item in candidate.instructions:
                if item.opcode.name.startswith("ldc.i4."):
                    suffix = item.opcode.name.rsplit(".", 1)[-1]
                    if suffix == "m1":
                        integer_values.add(-1)
                    elif suffix.isdigit():
                        integer_values.add(int(suffix))
            if (
                str(method_rows[index - 1].Name) == ".ctor"
                and {"IsNullOrEmpty", "GetBytes"} <= call_leafs
                and {"xor", "add", "rem", "newarr"} <= set(opcodes)
                and {7, 32} <= integer_values
            ):
                ctor.append(index)
            if {"FromBase64String", "GetString"} <= call_leafs:
                string_decrypt.append(index)
            if calls.count("BlockCopy") >= 2 and 12 in integer_values:
                byte_decrypt.append(index)
        if len(string_decrypt) == 1:
            decrypt_calls = {
                getattr(item.operand, "value", item.operand)
                for item in body_for(string_decrypt[0]).instructions
                if item.opcode.name in {"call", "callvirt"}
            }
            byte_decrypt = [
                index
                for index in byte_decrypt
                if (0x06000000 | index) in decrypt_calls
            ]
        if len(ctor) == len(string_decrypt) == len(byte_decrypt) == 1:
            crypto_candidates.append(
                (crypto_owner, ctor[0], string_decrypt[0], byte_decrypt[0], core_index)
            )
    if len(crypto_candidates) != 1:
        raise ConfigRecoveryError("ChaCha20 CIL profileを一意に特定できません")
    crypto_owner, ctor_index, string_decrypt_index, byte_decrypt_index, core_index = (
        crypto_candidates[0]
    )

    initializer_candidates: list[int] = []
    ctor_token = 0x06000000 | ctor_index
    decrypt_token = 0x06000000 | string_decrypt_index
    for index, row in enumerate(method_rows, 1):
        if method_owners.get(index) != settings_owner or not row.Rva:
            continue
        instructions = body_for(index).instructions
        newobjs = [
            getattr(item.operand, "value", item.operand)
            for item in instructions
            if item.opcode.name == "newobj"
        ]
        decrypt_calls = [
            getattr(item.operand, "value", item.operand)
            for item in instructions
            if item.opcode.name == "callvirt"
        ]
        leaf_calls = {
            _member_name(
                pe,
                getattr(item.operand, "value", item.operand),
                method_owners,
            ).rsplit(".", 1)[-1]
            for item in instructions
            if item.opcode.name in {"call", "callvirt", "newobj"}
            and isinstance(getattr(item.operand, "value", item.operand), int)
        }
        if (
            ctor_token in newobjs
            and decrypt_calls.count(decrypt_token) >= 10
            and {"FromBase64String", "GetString"} <= leaf_calls
        ):
            initializer_candidates.append(index)
    if len(initializer_candidates) != 1:
        raise ConfigRecoveryError("難読化Settings initializerを一意に特定できません")

    return assignments, {
        "settings_owner_sha256": hashlib.sha256(settings_owner.encode()).hexdigest(),
        "settings_cctor_token": _method_token(cctor_index),
        "settings_initializer_token": _method_token(initializer_candidates[0]),
        "crypto_owner_sha256": hashlib.sha256(crypto_owner.encode()).hexdigest(),
        "crypto_constructor_token": _method_token(ctor_index),
        "string_decrypt_token": _method_token(string_decrypt_index),
        "byte_decrypt_token": _method_token(byte_decrypt_index),
        "chacha_core_token": _method_token(core_index),
        "literal_assignment_count": len(assignments),
    }


def _recover_obfuscated_chacha_asyncrat(data: bytes) -> dict[str, Any]:
    assignments, shape = _obfuscated_chacha_profile(data)
    values = [value for _field, value in assignments]
    try:
        master_key = base64.b64decode(values[5], validate=True).decode("utf-8")
    except (ValueError, UnicodeDecodeError, IndexError) as exc:
        raise ConfigRecoveryError("難読化Settings.Keyを復元できません") from exc
    if len(master_key) != 32 or any(not character.isprintable() for character in master_key):
        raise ConfigRecoveryError("難読化Settings.Keyの形状が一致しません")

    def decrypted(index: int) -> str:
        try:
            return decrypt_obfuscated_chacha_setting(values[index], master_key)
        except IndexError as exc:
            raise ConfigRecoveryError("難読化Settings field順が不足しています") from exc

    ports_text = decrypted(0)
    hosts_text = decrypted(1)
    version = decrypted(2).strip()
    install = decrypted(3).strip()
    mutex = decrypted(6)
    certificate_text = decrypted(7)
    signature_text = decrypted(8)
    anti = decrypted(9).strip()
    dynamic_url = decrypted(14).strip()
    group = decrypted(17).strip()
    endpoints = _validated_endpoints(hosts_text, ports_text)
    if not 1 <= len(version) <= 128 or len(group) > 512 or not 1 <= len(mutex) <= 512:
        raise ConfigRecoveryError("難読化Settingsのversion、group、mutexが不正です")
    if install.casefold() not in {"true", "false"} or anti.casefold() not in {
        "true",
        "false",
    }:
        raise ConfigRecoveryError("難読化Settingsのbooleanが不正です")
    try:
        certificate = base64.b64decode(certificate_text, validate=True)
        signature = base64.b64decode(signature_text, validate=True)
    except ValueError as exc:
        raise ConfigRecoveryError("難読化Settingsの証明書または署名が不正です") from exc
    if not 128 <= len(certificate) <= 16 * 1024 * 1024 or not 64 <= len(signature) <= 8192:
        raise ConfigRecoveryError("難読化Settingsの証明書または署名長が範囲外です")
    dynamic_url = _public_dynamic_url(dynamic_url)
    return {
        "schema_version": 1,
        "family": "asyncrat",
        "sha256": hashlib.sha256(data).hexdigest(),
        "terminal_managed_client": True,
        "static_config_recovered": True,
        "config_mode": "chacha20_obfuscated_v058",
        "version": version,
        "install": install,
        "group": group,
        "anti_analysis": anti,
        "config_endpoints": endpoints,
        "dynamic_config_url": dynamic_url,
        "dynamic_config_url_scope": "origin_only",
        "certificate": {
            "sha256": hashlib.sha256(certificate).hexdigest(),
            "size": len(certificate),
            "validation": "embedded_certificate_present",
            "certificate_mismatch_excludes_c2": False,
        },
        "secret_fields_published": False,
        "crypto_profile": {
            "settings_storage": "encrypted",
            "key_derivation": "reviewed_xor_add_32_byte_mixing",
            "authentication": "none_per_setting",
            "cipher": "ChaCha20-IETF",
            "nonce_size": 12,
            "initial_counter": 1,
            "salt_source": "not_applicable",
            "salt_published": False,
        },
        "static_shape_evidence": shape,
        "executed": False,
        "network_contacted": False,
        "limitations": [
            "各設定blob自体にはMACがなく、CIL形状、復号後の型、証明書、署名を相互検証しました。",
            "dynamic_config_urlの内容は別の時点付き取得で確認する必要があります。",
            "証明書不一致だけでは非C2と判定しません。",
        ],
    }


def _validated_endpoints(hosts_text: str, ports_text: str) -> list[dict[str, Any]]:
    """不正値を黙って落とさず、有限個の全host／portを検証する。"""

    if len(hosts_text) > 64 * 256 or len(ports_text) > 64 * 6:
        raise ConfigRecoveryError("Settings endpoint文字列が上限を超えています")
    hosts = sorted({item.strip() for item in hosts_text.split(",") if item.strip()})
    port_values = sorted({item.strip() for item in ports_text.split(",") if item.strip()})
    if not hosts or any(not _valid_host(host) for host in hosts):
        raise ConfigRecoveryError("Settingsのhostが不正です")
    if not port_values or any(re.fullmatch(r"[0-9]{1,5}", value) is None for value in port_values):
        raise ConfigRecoveryError("Settingsのportが不正です")
    ports = sorted({int(value) for value in port_values})
    if any(not 1 <= port <= 65_535 for port in ports) or len(hosts) * len(ports) > 64:
        raise ConfigRecoveryError("Settingsのendpoint数またはport範囲が上限外です")
    return [
        {"host": host.casefold().rstrip("."), "port": port}
        for host in hosts
        for port in ports
    ]


def _public_dynamic_url(value: str) -> str | None:
    """動的設定URLはoriginだけを残し、秘密を含み得るpathやuserinfoを公開しない。"""

    value = value.strip()
    if not value or value.casefold() == "null":
        return None
    if len(value) > 2048 or any(ord(character) < 0x20 for character in value):
        raise ConfigRecoveryError("動的設定URLの型または長さが不正です")
    try:
        parsed = urlsplit(value)
        host = parsed.hostname or ""
        port = parsed.port
    except ValueError as exc:
        raise ConfigRecoveryError("動的設定URLの形式が不正です") from exc
    if parsed.scheme.casefold() not in {"http", "https"} or not _valid_host(host):
        raise ConfigRecoveryError("動的設定URLが許可形式ではありません")
    if port is not None and not 1 <= port <= 65535:
        raise ConfigRecoveryError("動的設定URLのportが不正です")
    netloc = host.casefold().rstrip(".")
    if port is not None:
        netloc += f":{port}"
    return urlunsplit((parsed.scheme.casefold(), netloc, "/", "", ""))


def _valid_host(value: str) -> bool:
    """URL、placeholder、空labelを除外したIPまたはDNS名だけを受理する。"""

    host = value.strip().rstrip(".")
    if not host or len(host) > 253 or host != value.strip().rstrip("."):
        return False
    if any(character in host for character in "/:@%<>{}[] \t\r\n"):
        return False
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        labels = host.split(".")
        return len(labels) >= 2 and all(_DOMAIN_LABEL.fullmatch(label) for label in labels)


def _method_opcode_shape(
    data: bytes,
    pe: dnfile.dnPE,
    owner: str,
    name: str,
) -> tuple[str, ...]:
    """一意なmanaged methodのopcode列を限定取得する。"""

    candidates = []
    owners = _method_owners(pe)
    for index, row in enumerate(pe.net.mdtables.MethodDef.rows, 1):
        if str(row.Name) != name or owners.get(index) != owner or not row.Rva:
            continue
        try:
            body = read_bounded_method_body(data, pe, row.Rva)
        except Exception as exc:
            raise ConfigRecoveryError(f"{owner}.{name}のCILを解析できません") from exc
        candidates.append(
            tuple(
                instruction.opcode.name
                for instruction in body.instructions
                if instruction.opcode.name != "nop"
            )
        )
    if len(candidates) != 1:
        raise ConfigRecoveryError(f"{owner}.{name}を一意に確認できません")
    return candidates[0]


def _asyncrat_plaintext_profile(data: bytes, literals: dict[str, str]) -> dict[str, object]:
    """v0.5.7B系developer buildの平文Settings形状をfail-closedで確認する。"""

    pe = _managed_pe(data)
    _require_unique_type(pe, "Client.Settings")
    accepted_true_shapes = {
        ("ldc.i4.1", "ret"),
        ("ldc.i4.1", "stloc.0", "br.s", "ldloc.0", "ret"),
        ("ldc.i4.1", "stloc.0", "br", "ldloc.0", "ret"),
    }
    initialize_shape = _method_opcode_shape(
        data, pe, "Client.Settings", "InitializeSettings"
    )
    certificate_shape = _method_opcode_shape(
        data,
        pe,
        "Client.Connection.ClientSocket",
        "ValidateServerCertificate",
    )
    if initialize_shape not in accepted_true_shapes:
        raise ConfigRecoveryError("平文Settings初期化methodが既知のreturn true形状ではありません")
    if certificate_shape not in accepted_true_shapes:
        raise ConfigRecoveryError("TLS証明書callbackが既知のaccept-all形状ではありません")
    key = literals.get("Key")
    if (
        not isinstance(key, str)
        or not 8 <= len(key) <= 128
        or any(not 0x20 <= ord(character) <= 0x7E for character in key)
    ):
        raise ConfigRecoveryError("平文buildの非公開Key形状が一致しません")
    for field in ("Certificate", "Serversignature"):
        value = literals.get(field)
        if not isinstance(value, str) or _BUILD_PLACEHOLDER.fullmatch(value) is None:
            raise ConfigRecoveryError(f"平文build placeholderが一致しません: {field}")
    return {
        "settings_initializer": "trivial_return_true",
        "tls_certificate_validation": "accept_all",
        "placeholder_fields_validated": True,
    }


def _recover_plaintext_asyncrat(
    data: bytes,
    literals: dict[str, str],
    profile: dict[str, Any],
) -> dict[str, Any]:
    shape = _asyncrat_plaintext_profile(data, literals)
    fields = profile["fields"]
    plain = {
        public_name: literals.get(field_name, "")
        for public_name, field_name in fields.items()
        if public_name != "certificate"
    }
    endpoints = _validated_endpoints(plain.get("hosts", ""), plain.get("ports", ""))
    version = plain.get("version", "").strip()
    group = plain.get("group", "").strip()
    if not 1 <= len(version) <= 128 or len(group) > 512:
        raise ConfigRecoveryError("平文Settingsのversionまたはgroupが不正です")
    for field in ("install", "anti"):
        if plain.get(field, "").strip().casefold() not in {"true", "false"}:
            raise ConfigRecoveryError(f"平文Settingsのbooleanが不正です: {field}")
    dynamic_url = plain.get("pastebin", "").strip()
    dynamic_url = _public_dynamic_url(dynamic_url)
    return {
        "schema_version": 1,
        "family": "asyncrat",
        "sha256": hashlib.sha256(data).hexdigest(),
        "terminal_managed_client": True,
        "static_config_recovered": True,
        "config_mode": "plaintext_static_v057b",
        "version": version,
        "install": plain.get("install", "").strip(),
        "group": group,
        "anti_analysis": plain.get("anti", "").strip(),
        "config_endpoints": endpoints,
        "dynamic_config_url": dynamic_url,
        "dynamic_config_url_scope": "origin_only",
        "certificate": {
            "sha256": None,
            "size": None,
            "validation": "accept_all",
            "certificate_mismatch_excludes_c2": False,
        },
        "secret_fields_published": False,
        "crypto_profile": {
            "settings_storage": "plaintext",
            "key_derivation": "not_applicable",
            "authentication": "not_applicable",
            "cipher": "not_applicable",
            "salt_source": "not_applicable",
            "salt_published": False,
        },
        "static_shape_evidence": shape,
        "executed": False,
        "network_contacted": False,
        "limitations": [
            "dynamic_config_urlの内容は別の時点付き取得で確認する必要があります。",
            "このbuildはTLS server証明書をaccept-allで受理し、証明書pinを持ちません。",
        ],
    }


def recover(data: bytes, family: str) -> dict[str, Any]:
    """指定familyのreview済みfield mappingで公開可能な設定だけを返す。"""

    if not isinstance(data, bytes) or not 1 <= len(data) <= MAX_INPUT_BYTES:
        raise ConfigRecoveryError("入力bytesが欠落または上限外です")
    if not isinstance(family, str) or family not in PROFILES:
        raise ConfigRecoveryError("設定復元familyが未対応です")
    profile = PROFILES[family]
    try:
        literals = settings_literals(data, str(profile["settings_type"]))
    except ConfigRecoveryError:
        if family == "asyncrat":
            return _recover_obfuscated_chacha_asyncrat(data)
        raise
    encoded_key = literals.get("Key")
    if not encoded_key:
        if family == "asyncrat":
            return _recover_obfuscated_chacha_asyncrat(data)
        raise ConfigRecoveryError("Settings.Keyがありません")
    if not isinstance(encoded_key, str) or len(encoded_key) > ((MAX_MASTER_KEY_BYTES + 2) // 3) * 4:
        raise ConfigRecoveryError("Settings.Keyが型不正または上限外です")
    try:
        master_key = base64.b64decode(encoded_key, validate=True).decode("utf-8")
    except (ValueError, UnicodeDecodeError) as exc:
        if family == "asyncrat":
            return _recover_plaintext_asyncrat(data, literals, profile)
        raise ConfigRecoveryError("Settings.Keyを復元できません") from exc
    configured_salt = profile.get("salt")
    if isinstance(configured_salt, bytes):
        salt = configured_salt
        salt_source = "reviewed_family_profile"
    else:
        initializer_type = profile.get("salt_initializer_type")
        if not isinstance(initializer_type, str):
            raise ConfigRecoveryError("salt復元profileが不正です")
        salt = static_salt(data, initializer_type)
        salt_source = "reviewed_static_initializer"
    decrypted: dict[str, str] = {}
    if any(literals.get(field_name) is None for field_name in profile["fields"].values()):
        raise ConfigRecoveryError("Settingsの必須fieldが欠落しています")
    encoded_fields = {
        public_name: _decode_setting_bytes(literals[field_name])
        for public_name, field_name in profile["fields"].items()
    }
    keys = _derive(master_key, salt)
    for public_name in profile["fields"]:
        decrypted[public_name] = _decrypt_setting_with_keys(encoded_fields[public_name], keys)
    endpoints = _validated_endpoints(decrypted["hosts"], decrypted["ports"])
    version = decrypted["version"].strip()
    group = decrypted["group"].strip()
    if not 1 <= len(version) <= 128 or len(group) > 512:
        raise ConfigRecoveryError("Settingsのversionまたはgroupが不正です")
    for field in ("install", "anti"):
        if decrypted[field].strip().casefold() not in {"true", "false"}:
            raise ConfigRecoveryError("Settingsのbooleanが不正です")
    certificate_sha256 = None
    certificate_size = None
    if decrypted.get("certificate"):
        try:
            certificate = base64.b64decode(decrypted["certificate"], validate=True)
        except ValueError as exc:
            raise ConfigRecoveryError("復号証明書が正しいBase64ではありません") from exc
        if not 1 <= len(certificate) <= MAX_SETTING_BYTES:
            raise ConfigRecoveryError("復号証明書の長さが上限外です")
        certificate_sha256 = hashlib.sha256(certificate).hexdigest()
        certificate_size = len(certificate)
    else:
        raise ConfigRecoveryError("復号証明書が欠落しています")
    dynamic_url = _public_dynamic_url(decrypted["pastebin"])
    return {
        "schema_version": 1,
        "family": family,
        "sha256": hashlib.sha256(data).hexdigest(),
        "terminal_managed_client": True,
        "static_config_recovered": True,
        "config_mode": "hmac_encrypted",
        "version": version,
        "install": decrypted.get("install", "").strip() or None,
        "group": group,
        "anti_analysis": decrypted.get("anti", "").strip() or None,
        "config_endpoints": endpoints,
        "dynamic_config_url": dynamic_url,
        "dynamic_config_url_scope": "origin_only",
        "certificate": {
            "sha256": certificate_sha256,
            "size": certificate_size,
            "validation": "embedded_certificate_present",
            "certificate_mismatch_excludes_c2": False,
        },
        "secret_fields_published": False,
        "crypto_profile": {
            "key_derivation": "PBKDF2-HMAC-SHA1",
            "iterations": 50_000,
            "authentication": "HMAC-SHA256",
            "cipher": "AES-256-CBC-PKCS7",
            "salt_source": salt_source,
            "salt_published": False,
        },
        "executed": False,
        "network_contacted": False,
        "limitations": [
            "dynamic_config_urlの内容は別の時点付き取得で確認する必要があります。",
            "証明書不一致だけでは非C2と判定しません。",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--family", required=True, choices=sorted(PROFILES))
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if args.input.stat().st_size > MAX_INPUT_BYTES:
        parser.error("入力が32 MiB上限を超えています")
    try:
        result = recover(args.input.read_bytes(), args.family)
    except (OSError, ConfigRecoveryError) as exc:
        parser.error(str(exc))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"sha256": result["sha256"], "family": result["family"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
