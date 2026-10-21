"""Polygon dead-drop抽出器のsource限定preflight例外を検証する。"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

import pytest

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
FRAMEWORK_COMMON = REPOSITORY_ROOT / "analysis-framework" / "common"
for import_root in (REPOSITORY_ROOT, FRAMEWORK_COMMON):
    if str(import_root) not in sys.path:
        sys.path.insert(0, str(import_root))

import handler_catalog as catalog  # noqa: E402

SOURCE_PATH = REPOSITORY_ROOT / "extractors" / "valleyrat" / "polygon_dead_drop.py"
SOURCE_KEY = "extractors/valleyrat/polygon_dead_drop.py"
SOURCE = SOURCE_PATH.read_text(encoding="utf-8")


def _shape_results(source: str, function: str, call_name: str) -> list[bool]:
    tree = ast.parse(source)
    scope = next(
        item
        for item in tree.body
        if isinstance(item, ast.FunctionDef) and item.name == function
    )
    calls = [
        item
        for item in ast.walk(scope)
        if isinstance(item, ast.Call)
        and catalog._ast_call_name(item.func) == call_name
    ]
    key = (SOURCE_KEY, f"reachable:{function}", call_name)
    return [
        catalog._reviewed_source_call_shape_allowed(
            call,
            call_name,
            tree,
            scope,
            catalog._import_aliases(tree),
            key=key,
        )
        for call in calls
    ]


def test_allowance_registry_is_limited_to_seven_polygon_call_sites() -> None:
    """module全体ではなくレビュー済み7 call-siteだけを登録する。"""

    keys = {
        key
        for key in catalog._REVIEWED_SOURCE_CALLS
        if key[0] == SOURCE_KEY
    }
    assert keys == {
        (SOURCE_KEY, "reachable:_canonical_register", "instruction.reg_name"),
        (SOURCE_KEY, "reachable:_disassemble", "decoder.disasm"),
        (SOURCE_KEY, "reachable:_load_pe", "image.close"),
        (SOURCE_KEY, "reachable:_valid_pe", "image.close"),
        (SOURCE_KEY, "reachable:_recover_outer", "image.close"),
        (SOURCE_KEY, "reachable:_terminal_profile", "image.close"),
        (
            SOURCE_KEY,
            "reachable:_terminal_profile",
            "provider_sources.setdefault",
        ),
    }


@pytest.mark.parametrize(
    ("function", "call_name"),
    (
        ("_canonical_register", "instruction.reg_name"),
        ("_disassemble", "decoder.disasm"),
        ("_load_pe", "image.close"),
        ("_valid_pe", "image.close"),
        ("_recover_outer", "image.close"),
        ("_terminal_profile", "image.close"),
        ("_terminal_profile", "provider_sources.setdefault"),
    ),
)
def test_current_polygon_call_shapes_are_accepted(
    function: str,
    call_name: str,
) -> None:
    """現在の有界静的処理だけをsource-shape監査が受理する。"""

    assert _shape_results(SOURCE, function, call_name) == [True]


@pytest.mark.parametrize(
    "mutation",
    (
        "    instruction.reg_name = _evil\n",
        "    alias = instruction\n",
        "    _evil(instruction)\n",
        "    return instruction.reg_name(register + 1)\n",
    ),
)
def test_register_name_allowance_rejects_rebinding_escape_and_argument_change(
    mutation: str,
) -> None:
    """Capstone instruction receiverの差替え・escape・引数変更を拒否する。"""

    source = (
        "def _canonical_register(instruction: object, register: int) -> str:\n"
        f"{mutation}"
        "    return instruction.reg_name(register)\n"
    )
    results = _shape_results(source, "_canonical_register", "instruction.reg_name")
    assert results
    assert all(result is False for result in results)


@pytest.mark.parametrize(
    ("before", "after"),
    (
        ("Cs(CS_ARCH_X86, CS_MODE_64)", "Cs(CS_ARCH_X86, CS_MODE_32)"),
        (
            "MAXIMUM_SECTION_SIZE = 32 * 1024 * 1024",
            "MAXIMUM_SECTION_SIZE = 64 * 1024 * 1024",
        ),
        (
            "instructions = tuple(decoder.disasm(raw, address))",
            "instructions = tuple(decoder.disasm(raw, address + 1))",
        ),
        ("if count > 250_000:", "if count > 500_000:"),
        (
            "decoder.detail = True\n",
            "decoder.detail = True\n    leaked = decoder\n",
        ),
    ),
)
def test_disassembly_allowance_rejects_mode_bounds_and_receiver_changes(
    before: str,
    after: str,
) -> None:
    """architecture、byte/命令上限、receiver不変性を固定する。"""

    mutated = SOURCE.replace(before, after, 1)
    assert mutated != SOURCE
    assert _shape_results(mutated, "_disassemble", "decoder.disasm") == [False]


@pytest.mark.parametrize(
    ("function", "before", "after"),
    (
        (
            "_load_pe",
            "pefile.PE(data=data, fast_load=False)",
            "pefile.PE(name=data, fast_load=False)",
        ),
        ("_valid_pe", "image = _load_pe(value)", "image = _evil(value)"),
        ("_recover_outer", "image = _load_pe(data)", "image = _evil(data)"),
        ("_terminal_profile", "image = _load_pe(data)", "image = _evil(data)"),
    ),
)
def test_image_cleanup_allowance_requires_reviewed_pe_provenance(
    function: str,
    before: str,
    after: str,
) -> None:
    """PE receiverが直接bytes parserまたは監査済みloader由来でなければ拒否する。"""

    mutated = SOURCE.replace(before, after)
    assert mutated != SOURCE
    assert _shape_results(mutated, function, "image.close") == [False]


@pytest.mark.parametrize(
    ("before", "after"),
    (
        (
            "provider_sources: dict[str, set[int]] = {}",
            "provider_sources = {}",
        ),
        (
            "provider_sources.setdefault(normalized, set())",
            "provider_sources.setdefault(host, set())",
        ),
        (
            "section_va + offset\n                            )",
            "section_va + offset + 1\n                            )",
        ),
    ),
)
def test_provider_aggregation_allowance_requires_exact_local_dict_chain(
    before: str,
    after: str,
) -> None:
    """空の型付き局所dict、正規化host、参照元addressの連鎖だけを許可する。"""

    mutated = SOURCE.replace(before, after, 1)
    assert mutated != SOURCE
    assert _shape_results(
        mutated,
        "_terminal_profile",
        "provider_sources.setdefault",
    ) == [False]


def test_polygon_allowance_is_not_reused_by_another_source_or_function() -> None:
    """同一call shapeでも別source/contextへ横展開しない。"""

    tree = ast.parse(
        "def other(instruction, register):\n"
        "    return instruction.reg_name(register)\n"
    )
    scope = tree.body[0]
    call = next(item for item in ast.walk(scope) if isinstance(item, ast.Call))
    aliases = catalog._import_aliases(tree)
    assert catalog._reviewed_source_call_shape_allowed(
        call,
        "instruction.reg_name",
        tree,
        scope,
        aliases,
        key=(SOURCE_KEY, "reachable:other", "instruction.reg_name"),
    ) is False
    assert (
        catalog._REVIEWED_SOURCE_CALLS.get(
            (
                "extractors/other.py",
                "reachable:_canonical_register",
                "instruction.reg_name",
            )
        )
        is None
    )
