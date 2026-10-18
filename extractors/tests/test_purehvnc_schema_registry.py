"""PureRAT terminal schema registryのcodec・extractor共通契約を検証する。"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from extractors.purehvnc import extractor
from extractors.purehvnc_schema import (
    TERMINAL_FIELD_RULES,
    TERMINAL_SCHEMA_PROFILE_EXPLICIT_FIELDS_1_TO_9,
    TERMINAL_SCHEMA_PROFILE_V4_DEFAULT_ELIDED_FIELD_7,
    TerminalFieldKind,
    terminal_default_elided_fields,
    terminal_schema_profile,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
FAMILY_DIR = REPOSITORY_ROOT / "analysis-framework" / "malware" / "purehvnc"
if str(FAMILY_DIR) not in sys.path:
    sys.path.insert(0, str(FAMILY_DIR))

import purerat_441_protocol as protocol


def _terminal_fields(*, include_field_7: bool = True) -> extractor.ParsedProtobufFields:
    fields: dict[int, list[object]] = {
        1: [b"c2.example.test"],
        2: [443, 56001],
        3: [b"Zml4dHVyZS1wZng="],
        4: [b"Default"],
        5: [1],
        6: [0],
        8: [b"APPDATA"],
        9: [b"fixture-mutex"],
        10: [1],
    }
    if include_field_7:
        fields[7] = [b""]
    wire_types = {
        number: [0 if number in {2, 5, 6, 10} else 2] * len(values)
        for number, values in fields.items()
    }
    return extractor.ParsedProtobufFields(fields, wire_types=wire_types)


def _schema_profile(fields: extractor.ParsedProtobufFields) -> str | None:
    """値とwire inventoryを明示して共有schemaを評価する。"""

    return terminal_schema_profile(fields, fields.wire_types)


def test_codec_gclass3_uses_the_shared_field_registry() -> None:
    """field番号・型・反復性・意味名が共有定義から乖離しない。"""

    codec_fields = protocol.MESSAGE_SCHEMAS["GClass3"].fields
    assert len(codec_fields) == len(TERMINAL_FIELD_RULES)
    kind_map = {
        TerminalFieldKind.STRING: protocol.FieldKind.STRING,
        TerminalFieldKind.BOOL: protocol.FieldKind.BOOL,
        TerminalFieldKind.INT32: protocol.FieldKind.INT32,
    }
    assert [
        (
            field.number,
            field.property_name,
            field.kind,
            field.repeated,
            field.semantic_name,
        )
        for field in codec_fields
    ] == [
        (
            rule.number,
            rule.property_name,
            kind_map[rule.kind],
            rule.repeated,
            rule.semantic_name,
        )
        for rule in TERMINAL_FIELD_RULES
    ]


def test_shared_profiles_preserve_explicit_and_field_7_elided_contracts() -> None:
    """旧profile名とfield 7既定値省略の公開意味を維持する。"""

    assert _schema_profile(_terminal_fields()) == (
        TERMINAL_SCHEMA_PROFILE_EXPLICIT_FIELDS_1_TO_9
    )
    elided = _terminal_fields(include_field_7=False)
    assert _schema_profile(elided) == (
        TERMINAL_SCHEMA_PROFILE_V4_DEFAULT_ELIDED_FIELD_7
    )
    assert terminal_default_elided_fields(_schema_profile(elided)) == (7,)
    assert extractor._terminal_schema_profile(elided) == (
        TERMINAL_SCHEMA_PROFILE_V4_DEFAULT_ELIDED_FIELD_7
    )


def test_unknown_field_and_other_required_field_loss_remain_fail_closed() -> None:
    """既知codecがraw保持できる未知fieldもfamily確定には利用しない。"""

    fields = _terminal_fields()
    fields[11] = [1]
    assert _schema_profile(fields) is None
    assert extractor._terminal_schema_profile(fields) is None

    fields = _terminal_fields(include_field_7=False)
    fields.pop(8)
    assert _schema_profile(fields) is None
    assert extractor._terminal_schema_profile(fields) is None


def test_optional_field_10_must_still_match_its_declared_type() -> None:
    """任意fieldは欠落のみ許容し、重複・型違い・不正boolを拒否する。"""

    fields = _terminal_fields()
    fields.pop(10)
    assert _schema_profile(fields) == (TERMINAL_SCHEMA_PROFILE_EXPLICIT_FIELDS_1_TO_9)

    for invalid_values in ([0, 1], [2], [b"1"]):
        fields[10] = invalid_values
        assert _schema_profile(fields) is None


def test_schema_profile_requires_preserved_wire_inventory() -> None:
    """値だけのplain mappingをwire schemaの確証へ昇格させない。"""

    assert terminal_schema_profile(dict(_terminal_fields())) is None


def test_protocol_import_from_family_directory_resolves_shared_registry(
    tmp_path: Path,
) -> None:
    """hyphenを含むanalysis-framework配下からの単独利用も維持する。"""

    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(FAMILY_DIR)
    completed = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "import purerat_441_protocol as p; "
                "assert [f.number for f in p.MESSAGE_SCHEMAS['GClass3'].fields] "
                "== list(range(1, 11))"
            ),
        ],
        cwd=tmp_path,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
