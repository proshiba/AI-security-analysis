"""ZIP side-load終端handlerのAST監査境界を検証する。"""

from __future__ import annotations

import ast
import copy
import importlib
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
COMMON = ROOT / "analysis-framework" / "common"
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

catalog = importlib.import_module("handler_catalog")


SOURCE = ROOT / "extractors" / "valleyrat" / "zip_sideload_shellcode.py"
HANDLER_ID = (
    "valleyrat:analysis.framework.malware.valleyrat.campaigns.zip.sideload.shellcode.vvas.terminal.analyze.py:analyze"
)


def _guard_inputs() -> tuple[ast.Module, ast.FunctionDef, ast.Call]:
    tree = ast.parse(SOURCE.read_text(encoding="utf-8"))
    scope = next(
        item for item in tree.body if isinstance(item, ast.FunctionDef) and item.name == "_intraprocedural_cfg"
    )
    call = next(
        item
        for item in ast.walk(scope)
        if isinstance(item, ast.Call) and catalog._ast_call_name(item.func) == "disassembler.disasm"
    )
    return tree, scope, call


def _guard_accepts(tree: ast.Module, scope: ast.FunctionDef, call: ast.Call) -> bool:
    return catalog._approved_zip_sideload_cfg_decode(call, tree, scope)


def test_zip_sideload_cfg_decode_guard_accepts_exact_bounded_shape() -> None:
    """実装中の16 byte・1命令・有界CFGだけを受理する。"""

    tree, scope, call = _guard_inputs()

    assert _guard_accepts(tree, scope, call) is True


def test_zip_sideload_cfg_decode_guard_rejects_wider_decode() -> None:
    """decode窓または命令数を広げた実装を拒否する。"""

    tree, scope, call = _guard_inputs()
    wider_tree, wider_scope, wider_call = copy.deepcopy((tree, scope, call))
    bounded = wider_call.args[0]
    assert isinstance(bounded, ast.Subscript)
    assert isinstance(bounded.slice, ast.Slice)
    bounded.slice.upper = ast.BinOp(
        left=ast.Name(id="offset", ctx=ast.Load()),
        op=ast.Add(),
        right=ast.Constant(value=32),
    )
    assert _guard_accepts(wider_tree, wider_scope, wider_call) is False

    tree, scope, call = _guard_inputs()
    count_tree, count_scope, count_call = copy.deepcopy((tree, scope, call))
    count_call.keywords[0].value = ast.Constant(value=2)
    assert _guard_accepts(count_tree, count_scope, count_call) is False


def test_zip_sideload_cfg_decode_guard_rejects_receiver_rebinding_or_escape() -> None:
    """receiverの差替えと未証明のalias・container・helper escapeを拒否する。"""

    for statement in (
        "disassembler.disasm = other",
        "for disassembler.disasm in [other]:\n    pass",
        "alias = disassembler",
        "alias = chained = disassembler",
        "method = disassembler.disasm",
        "mutate(disassembler)",
        "receivers = [disassembler]",
        'receivers = {"disassembler": disassembler}',
        "holder.value = disassembler",
        "holder[0] = disassembler",
        "return disassembler",
        "yield disassembler",
        "global leaked\nleaked = disassembler",
        "leaked = None\ndef escape():\n    nonlocal leaked\n    leaked = disassembler",
        "leaked = lambda: disassembler",
    ):
        tree, scope, call = _guard_inputs()
        scope.body[2:2] = ast.parse(statement).body

        assert _guard_accepts(tree, scope, call) is False


def test_zip_sideload_cfg_decode_guard_rejects_weakened_limits() -> None:
    """CFG命令数または待機block上限の変更を暗黙に許可しない。"""

    for name in ("MAXIMUM_CFG_PENDING_BLOCKS", "MAXIMUM_CFG_INSTRUCTIONS"):
        tree, scope, call = _guard_inputs()
        assignment = next(
            item
            for item in tree.body
            if isinstance(item, ast.Assign)
            and any(isinstance(target, ast.Name) and target.id == name for target in item.targets)
        )
        assignment.value = ast.Constant(value=1_000_000)

        assert _guard_accepts(tree, scope, call) is False


def test_zip_sideload_terminal_handler_preflight_is_safe_and_automatic() -> None:
    """完全lineage用handlerが副作用なしのZIP自動handlerとして通過する。"""

    catalog.clear_handler_caches()
    try:
        spec = next(item for item in catalog.discover_handlers() if item.id == HANDLER_ID)
        preflight = catalog.preflight_handler_for_assessment(
            spec,
            actual_format="zip",
            input_size=1024 * 1024,
        )
    finally:
        catalog.clear_handler_caches()

    assert spec.automatic is True
    assert preflight["eligible"] is True
    assert preflight["blockers"] == []
    assert preflight["sample_execution_allowed"] is False
    assert preflight["network_allowed"] is False
    assert preflight["filesystem_write_allowed"] is False
