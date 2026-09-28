"""通常sourceの監査helperだけを使い、同一audit内の遅延cache契約を試験する。"""

from __future__ import annotations

import ast
import copy
import inspect
from pathlib import Path
import sys

import pytest

COMMON = Path(__file__).resolve().parents[1] / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))
import handler_catalog


def _cache_helpers():
    """信頼済み監査sourceの3helperだけを抽出する。検体やhandlerは実行しない。"""
    tree = ast.parse(inspect.getsource(handler_catalog._recursive_handler_side_effect_audit))
    audit, = tree.body
    assert isinstance(audit, ast.FunctionDef)
    helpers = [copy.deepcopy(node) for node in audit.body if isinstance(node, ast.FunctionDef)
               and node.name in {"bindings", "aliases", "definitions"}]
    assert {node.name for node in helpers} == {"bindings", "aliases", "definitions"}
    future = ast.ImportFrom(module="__future__", names=[ast.alias(name="annotations")], level=0)
    unit = ast.fix_missing_locations(ast.Module(body=[future, *helpers], type_ignores=[]))
    namespace = {"ast": ast, "binding_cache": {}, "alias_cache": {}, "definition_cache": {}}
    # 通常app sourceの固定helperだけ。検体本文や生成payloadをcompileしない。
    exec(compile(unit, "trusted_audit_cache_helpers_only", "exec"), namespace)
    return namespace


@pytest.mark.parametrize("helper,cache_name,factory_name", [
    ("bindings", "binding_cache", "_detailed_import_bindings"),
    ("aliases", "alias_cache", "_import_aliases"),
])
@pytest.mark.parametrize("empty_value", [False, True, None])
def test_same_ast_cache_hit_does_not_recompute_factory(helper, cache_name, factory_name, empty_value):
    namespace = _cache_helpers()
    # 同じsource文字列でも異なるAST objectは別keyとして扱う。
    keys = [ast.parse("def one(data): return data"), ast.parse("def one(data): return data")]
    calls = []

    def factory(key):
        calls.append(key)
        return None if empty_value is None else {} if empty_value else {"origin": key}

    namespace[factory_name] = factory
    first = namespace[helper](keys[0])
    assert namespace[helper](keys[0]) is first
    second = namespace[helper](keys[1])
    assert namespace[helper](keys[1]) is second
    assert calls == keys
    assert set(namespace[cache_name]) == set(keys)


@pytest.mark.parametrize("helper,cache_name,factory_name", [
    ("bindings", "binding_cache", "_detailed_import_bindings"),
    ("aliases", "alias_cache", "_import_aliases"),
])
def test_factory_exception_does_not_commit_partial_cache(helper, cache_name, factory_name):
    namespace = _cache_helpers()
    key = ast.parse("def one(data): return data")

    def raises(_key):
        raise ValueError("人工factoryの例外")

    namespace[factory_name] = raises
    with pytest.raises(ValueError, match="人工factory"):
        namespace[helper](key)
    assert namespace[cache_name] == {}
    retained = {"origin": key}
    namespace[factory_name] = lambda _key: retained
    assert namespace[helper](key) is retained


def test_definition_cache_keeps_object_identity_without_rewalking_body():
    """人工bodyの訪問数だけを計測し、cache hitで無駄な列挙を行わない。"""
    class CountingBody(list):
        def __init__(self, values, *, fail=False):
            super().__init__(values)
            self.visits = 0
            self.fail = fail

        def __iter__(self):
            self.visits += 1
            if self.fail:
                raise ValueError("人工body列挙の例外")
            return super().__iter__()

    namespace = _cache_helpers()
    tree = ast.parse("def one(data): return data")
    body = CountingBody(tree.body)
    tree.body = body
    first = namespace["definitions"](tree)
    assert namespace["definitions"](tree) is first
    assert first["one"] is body[0]
    assert body.visits == 1
    other = ast.parse("def one(data): return data")
    assert namespace["definitions"](other) is not first
    broken = ast.parse("def broken(data): return data")
    broken_body = CountingBody(broken.body, fail=True)
    broken.body = broken_body
    with pytest.raises(ValueError, match="人工body"):
        namespace["definitions"](broken)
    assert broken not in namespace["definition_cache"]
    broken_body.fail = False
    assert "broken" in namespace["definitions"](broken)


def test_cache_storage_is_local_to_one_audit_not_global_or_cross_source():
    tree = ast.parse(inspect.getsource(handler_catalog._recursive_handler_side_effect_audit))
    audit, = tree.body
    for name in ("binding_cache", "alias_cache", "definition_cache"):
        definitions = [node for node in audit.body if isinstance(node, ast.AnnAssign)
                       and isinstance(node.target, ast.Name) and node.target.id == name]
        assert len(definitions) == 1
        assert isinstance(definitions[0].value, ast.Dict)
        assert definitions[0].value.keys == definitions[0].value.values == []
