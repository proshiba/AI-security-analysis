"""PureRAT terminal設定の宣言的protobuf schemaと既知profile。"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import Enum
from typing import Any


class TerminalFieldKind(str, Enum):
    """GClass3で確認済みのprotobuf member種別。"""

    STRING = "string"
    BOOL = "bool"
    INT32 = "int32"


@dataclass(frozen=True, slots=True)
class TerminalFieldRule:
    """GClass3の1 fieldに対するcodec・静的判定共通規則。"""

    number: int
    property_name: str
    kind: TerminalFieldKind
    semantic_name: str
    repeated: bool = False
    maximum_utf8_bytes: int | None = None
    allow_empty: bool = True


@dataclass(frozen=True, slots=True)
class TerminalSchemaProfile:
    """family確定へ利用できる、実検体で確認済みのwire inventory。"""

    name: str
    required_fields: frozenset[int]
    allowed_fields: frozenset[int]
    default_elided_fields: frozenset[int] = frozenset()


TERMINAL_SCHEMA_PROFILE_EXPLICIT_FIELDS_1_TO_9 = (
    "managed_purerat_explicit_fields_1_to_9"
)
TERMINAL_SCHEMA_PROFILE_V4_DEFAULT_ELIDED_FIELD_7 = (
    "managed_purerat_v4_default_elided_field_7"
)


# property_nameは4.4.1 terminalのCLR metadata、semantic_nameは既存codecの
# 公開契約に基づく。静的family確定では、この表にないfieldを受理しない。
TERMINAL_FIELD_RULES: tuple[TerminalFieldRule, ...] = (
    TerminalFieldRule(
        1,
        "List_0",
        TerminalFieldKind.STRING,
        "c2_hosts",
        repeated=True,
        maximum_utf8_bytes=253,
        allow_empty=False,
    ),
    TerminalFieldRule(
        2,
        "List_1",
        TerminalFieldKind.INT32,
        "c2_ports",
        repeated=True,
    ),
    TerminalFieldRule(
        3,
        "String_0",
        TerminalFieldKind.STRING,
        "certificate_pfx",
        allow_empty=False,
    ),
    TerminalFieldRule(
        4,
        "String_1",
        TerminalFieldKind.STRING,
        "campaign_id",
        maximum_utf8_bytes=128,
        allow_empty=False,
    ),
    TerminalFieldRule(5, "Boolean_0", TerminalFieldKind.BOOL, "persistence"),
    TerminalFieldRule(6, "Boolean_1", TerminalFieldKind.BOOL, "prevent_sleep"),
    TerminalFieldRule(
        7,
        "String_2",
        TerminalFieldKind.STRING,
        "scheduled_task",
        maximum_utf8_bytes=512,
    ),
    TerminalFieldRule(
        8,
        "String_3",
        TerminalFieldKind.STRING,
        "install_environment",
        maximum_utf8_bytes=512,
    ),
    TerminalFieldRule(
        9,
        "stadrmoOn1",
        TerminalFieldKind.STRING,
        "mutex",
        maximum_utf8_bytes=512,
    ),
    TerminalFieldRule(
        10,
        "Boolean_2",
        TerminalFieldKind.BOOL,
        "unresolved_bool",
    ),
)

TERMINAL_FIELD_RULES_BY_NUMBER: Mapping[int, TerminalFieldRule] = {
    rule.number: rule for rule in TERMINAL_FIELD_RULES
}

_KNOWN_FIELDS = frozenset(TERMINAL_FIELD_RULES_BY_NUMBER)
TERMINAL_SCHEMA_PROFILES: tuple[TerminalSchemaProfile, ...] = (
    TerminalSchemaProfile(
        name=TERMINAL_SCHEMA_PROFILE_EXPLICIT_FIELDS_1_TO_9,
        required_fields=frozenset(range(1, 10)),
        allowed_fields=_KNOWN_FIELDS,
    ),
    TerminalSchemaProfile(
        name=TERMINAL_SCHEMA_PROFILE_V4_DEFAULT_ELIDED_FIELD_7,
        required_fields=frozenset(range(1, 10)) - {7},
        allowed_fields=_KNOWN_FIELDS,
        default_elided_fields=frozenset({7}),
    ),
)

TERMINAL_SCHEMA_PROFILES_BY_NAME: Mapping[str, TerminalSchemaProfile] = {
    profile.name: profile for profile in TERMINAL_SCHEMA_PROFILES
}


def _valid_field_values(
    rule: TerminalFieldRule,
    values: object,
    wire_types: object,
) -> bool:
    """正規化済み値とwire typeが宣言上の型・個数・境界を満たすか返す。"""

    if not isinstance(values, Sequence) or isinstance(values, (str, bytes)):
        return False
    if not isinstance(wire_types, Sequence) or isinstance(
        wire_types,
        (str, bytes),
    ):
        return False
    if len(wire_types) != len(values) or any(
        not isinstance(wire_type, int) or isinstance(wire_type, bool)
        for wire_type in wire_types
    ):
        return False
    if not values or (not rule.repeated and len(values) != 1):
        return False
    for value, wire_type in zip(values, wire_types, strict=True):
        if rule.kind is TerminalFieldKind.STRING:
            if wire_type != 2 or not isinstance(value, bytes):
                return False
            if (
                rule.maximum_utf8_bytes is not None
                and len(value) > rule.maximum_utf8_bytes
            ):
                return False
            try:
                text = value.decode("utf-8")
            except UnicodeDecodeError:
                return False
            if not rule.allow_empty and not text:
                return False
            if any(ord(character) < 32 or ord(character) == 127 for character in text):
                return False
        elif rule.kind is TerminalFieldKind.BOOL:
            if (
                wire_type != 0
                or not isinstance(value, int)
                or isinstance(value, bool)
                or value not in {0, 1}
            ):
                return False
        elif rule.kind is TerminalFieldKind.INT32:
            if (
                wire_type not in {0, 2}
                or not isinstance(value, int)
                or isinstance(value, bool)
            ):
                return False
        else:  # pragma: no cover - Enum追加時に明示実装を要求する防御線
            return False
    return True


def terminal_schema_profile(
    fields: Mapping[int, list[Any]],
    wire_types: Mapping[int, list[int]] | None = None,
) -> str | None:
    """値と明示wire inventoryから既知GClass3 profile名を返す。"""

    field_numbers = frozenset(fields)
    if not field_numbers.issubset(_KNOWN_FIELDS):
        return None
    if not isinstance(wire_types, Mapping):
        return None
    if any(
        not _valid_field_values(
            TERMINAL_FIELD_RULES_BY_NUMBER[number],
            values,
            wire_types.get(number),
        )
        for number, values in fields.items()
    ):
        return None
    for profile in TERMINAL_SCHEMA_PROFILES:
        if (
            profile.required_fields.issubset(field_numbers)
            and field_numbers.issubset(profile.allowed_fields)
            and not (profile.default_elided_fields & field_numbers)
        ):
            return profile.name
    return None


def terminal_default_elided_fields(profile_name: str | None) -> tuple[int, ...]:
    """既知profileでwireから省略された既定値fieldを昇順で返す。"""

    profile = TERMINAL_SCHEMA_PROFILES_BY_NAME.get(profile_name or "")
    return tuple(sorted(profile.default_elided_fields)) if profile else ()


__all__ = [
    "TERMINAL_FIELD_RULES",
    "TERMINAL_FIELD_RULES_BY_NUMBER",
    "TERMINAL_SCHEMA_PROFILES",
    "TERMINAL_SCHEMA_PROFILES_BY_NAME",
    "TERMINAL_SCHEMA_PROFILE_EXPLICIT_FIELDS_1_TO_9",
    "TERMINAL_SCHEMA_PROFILE_V4_DEFAULT_ELIDED_FIELD_7",
    "TerminalFieldKind",
    "TerminalFieldRule",
    "TerminalSchemaProfile",
    "terminal_default_elided_fields",
    "terminal_schema_profile",
]
