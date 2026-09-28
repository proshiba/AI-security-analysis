"""通常catalogを直importし、ordinary source／人工ASTだけでcache回帰を点検する。"""
from __future__ import annotations

import ast
import copy
import hashlib
import inspect
from pathlib import Path
import sys

import pytest

COMMON = Path(__file__).resolve().parents[1] / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))
import handler_catalog as target

ROOT = Path(target.__file__).resolve().parents[2]


@pytest.fixture(autouse=True)
def _clear_catalog_caches():
    target.clear_handler_caches()
    yield
    target.clear_handler_caches()


RELATIVE = "unpackers/managed_il_triage.py"
PROXY = "unpackers/managed_proxy_deobfuscator.py"




def _fixture():
    tree = ast.parse("def analyze_managed_pe(data):\n    return resource_scan.coverage()\n")
    scope = tree.body[0]
    return tree, scope, scope.body[0].value


def _new_audit_scope(contract, dispatch):
    audit = ast.parse(inspect.getsource(target._recursive_handler_side_effect_audit)).body[0]
    cache = next(node for node in audit.body if isinstance(node, ast.AnnAssign)
                 and isinstance(node.target, ast.Name) and node.target.id == "consumer_contract_cache")
    helper = next(node for node in audit.body if isinstance(node, ast.FunctionDef)
                  and node.name == "managed_consumer_call_shape")
    factory = ast.parse("def make_scope():\n    pass\n").body[0]
    factory.body = [copy.deepcopy(cache), copy.deepcopy(helper), ast.Return(value=ast.Name(id=helper.name, ctx=ast.Load()))]
    module = ast.fix_missing_locations(ast.Module(body=[factory], type_ignores=[]))
    namespace = {"ast": ast, "_managed_resource_consumer_contract": contract,
                 "_managed_resource_consumer_dispatch_shape": dispatch}
    exec(compile(module, "_artificial_audit_scope", "exec"), namespace)
    return namespace["make_scope"]()


def test_same_tree_and_relative_reuses_only_contract():
    contracts, dispatches = [], []
    def contract(tree, relative):
        contracts.append((tree, relative))
        return True
    def dispatch(*args):
        dispatches.append(args)
        return ("managed_resources", "coverage")
    tree, scope, call = _fixture()
    shape = _new_audit_scope(contract, dispatch)
    for _ in range(5):
        assert shape(call, tree, scope, RELATIVE, "reachable:analyze_managed_pe") == ("managed_resources", "coverage")
    assert len(contracts) == 1
    assert len(dispatches) == 5


def test_new_audit_does_not_reuse_prior_cache():
    contracts = []
    def contract(tree, relative):
        contracts.append((tree, relative))
        return True
    tree, scope, call = _fixture()
    for _ in range(2):
        shape = _new_audit_scope(contract, target._managed_resource_consumer_dispatch_shape)
        assert shape(call, tree, scope, RELATIVE, "reachable:analyze_managed_pe") is not None
    assert len(contracts) == 2


def test_same_relative_different_ast_object_rechecks_contract():
    contracts = []
    def contract(tree, relative):
        contracts.append((tree, relative))
        return True
    shape = _new_audit_scope(contract, target._managed_resource_consumer_dispatch_shape)
    for _ in range(2):
        tree, scope, call = _fixture()
        assert shape(call, tree, scope, RELATIVE, "reachable:analyze_managed_pe") is not None
    assert len(contracts) == 2
    assert contracts[0][0] is not contracts[1][0]


def test_contract_exception_is_not_saved_as_a_cache_result():
    contracts = []
    def contract(tree, relative):
        contracts.append((tree, relative))
        if len(contracts) == 1:
            raise ValueError("人工契約例外")
        return True
    tree, scope, call = _fixture()
    shape = _new_audit_scope(contract, target._managed_resource_consumer_dispatch_shape)
    with pytest.raises(ValueError, match="人工契約例外"):
        shape(call, tree, scope, RELATIVE, "reachable:analyze_managed_pe")
    assert shape(call, tree, scope, RELATIVE, "reachable:analyze_managed_pe") is not None
    assert shape(call, tree, scope, RELATIVE, "reachable:analyze_managed_pe") is not None
    assert len(contracts) == 2


def test_same_ast_different_relative_rechecks_contract():
    contracts = []
    def contract(tree, relative):
        contracts.append((tree, relative))
        return True
    tree, scope, call = _fixture()
    shape = _new_audit_scope(contract, target._managed_resource_consumer_dispatch_shape)
    shape(call, tree, scope, RELATIVE, "reachable:analyze_managed_pe")
    shape(call, tree, scope, PROXY, "reachable:analyze_managed_pe")
    assert [value[1] for value in contracts] == [RELATIVE, PROXY]


@pytest.mark.parametrize("relative", [RELATIVE, "unpackers/unreviewed.py"])
def test_false_result_is_cached_and_never_dispatches(relative):
    contracts = []
    def contract(tree, relative):
        contracts.append((tree, relative))
        return False
    def forbidden_dispatch(*args):
        raise AssertionError("契約拒否後にdispatchしてはいけない")
    tree, scope, call = _fixture()
    shape = _new_audit_scope(contract, forbidden_dispatch)
    for _ in range(5):
        assert shape(call, tree, scope, relative, "reachable:analyze_managed_pe") is None
    assert len(contracts) == 1


def test_unknown_relative_never_acquires_dispatch_authority():
    tree, scope, call = _fixture()
    shape = _new_audit_scope(target._managed_resource_consumer_contract,
                             target._managed_resource_consumer_dispatch_shape)
    assert shape(call, tree, scope, "unpackers/unreviewed.py", "reachable:analyze_managed_pe") is None
    assert target._managed_resource_consumer_dispatch_shape(call, tree, scope,
             "unpackers/unreviewed.py", "reachable:analyze_managed_pe") is None


def test_cached_true_rechecks_dispatch_receiver_arguments_and_context():
    contracts = []
    def contract(tree, relative):
        contracts.append((tree, relative))
        return True
    tree, scope, call = _fixture()
    shape = _new_audit_scope(contract, target._managed_resource_consumer_dispatch_shape)
    assert shape(call, tree, scope, RELATIVE, "reachable:analyze_managed_pe") is not None
    for expression, context in [("other.coverage()", "reachable:analyze_managed_pe"),
                                 ("resource_scan.coverage(data)", "reachable:analyze_managed_pe"),
                                 ("resource_scan.coverage()", "import_time")]:
        different_call = ast.parse(expression, mode="eval").body
        assert shape(different_call, tree, scope, RELATIVE, context) is None
    assert len(contracts) == 1


def test_global_wrapper_preserves_full_contract_on_every_call(monkeypatch):
    contracts = []
    def contract(tree, relative):
        contracts.append((tree, relative))
        return True
    tree, scope, call = _fixture()
    monkeypatch.setattr(target, "_managed_resource_consumer_contract", contract)
    for _ in range(5):
        assert target._managed_resource_consumer_call_shape(call, tree, scope, RELATIVE,
                                                           "reachable:analyze_managed_pe") is not None
    assert len(contracts) == 5


def test_global_wrapper_contract_rejection_does_not_dispatch(monkeypatch):
    monkeypatch.setattr(target, "_managed_resource_consumer_contract", lambda *args: False)
    def forbidden_dispatch(*args):
        raise AssertionError("global入口でも契約拒否後にdispatch不可")
    monkeypatch.setattr(target, "_managed_resource_consumer_dispatch_shape", forbidden_dispatch)
    tree, scope, call = _fixture()
    assert target._managed_resource_consumer_call_shape(call, tree, scope, RELATIVE,
                                                      "reachable:analyze_managed_pe") is None




def _artificial_repository(tmp_path, monkeypatch, *, unsafe_callee=False):
    folder = tmp_path / "unpackers"
    folder.mkdir()
    source = folder / "managed_il_triage.py"
    statement = target._MANAGED_RESOURCE_CONSUMER_ASSIGNMENTS[RELATIVE][3][1]
    text = "def analyze_managed_pe(data, max_resources, max_resource_bytes, max_methods, max_types, max_references):\n"
    text += "    " + statement + "\n    " + statement + "\n"
    source.write_text(text, encoding="utf-8")
    callee = folder / "managed_resource_snapshot.py"
    callee.write_text(("import os\n" if unsafe_callee else "") +
        "def prepare_resource_snapshot(data, pe, **limits):\n" +
        ("    os.system('人工AST専用・実行禁止')\n" if unsafe_callee else "    return None\n"), encoding="utf-8")
    monkeypatch.setattr(target, "REPOSITORY_ROOT", tmp_path)
    monkeypatch.setattr(target, "FRAMEWORK_ROOT", tmp_path / "analysis-framework")
    monkeypatch.setattr(target, "MALWARE_ROOT", tmp_path / "analysis-framework/malware")
    monkeypatch.setattr(target, "EXTRACTORS_ROOT", tmp_path / "extractors")
    monkeypatch.setattr(target, "_MANAGED_RESOURCE_CONSUMER_COMMITMENTS", {RELATIVE: hashlib.sha256(source.read_bytes()).hexdigest()})
    monkeypatch.setattr(target, "_MANAGED_RESOURCE_SOURCE_COMMITMENTS", {"unpackers/managed_resource_snapshot.py": hashlib.sha256(callee.read_bytes()).hexdigest()})
    monkeypatch.setattr(target, "_managed_constructor_consumer_contract", lambda *args: True)
    contracts = []
    def contract(tree, relative):
        contracts.append((tree, relative))
        return True
    monkeypatch.setattr(target, "_managed_resource_consumer_contract", contract)
    target.clear_handler_caches()
    return source, contracts


def test_cached_true_does_not_skip_callee_side_effect_audit(tmp_path, monkeypatch):
    source, contracts = _artificial_repository(tmp_path, monkeypatch, unsafe_callee=True)
    result = target._recursive_handler_side_effect_audit(source, "analyze_managed_pe")
    assert len(contracts) == 1
    assert any("system" in issue for issue in result["issues"]), result
    assert any(item["path"] == "unpackers/managed_resource_snapshot.py" for item in result["files"])


def test_cached_true_does_not_skip_depth_cap(tmp_path, monkeypatch):
    source, contracts = _artificial_repository(tmp_path, monkeypatch)
    monkeypatch.setattr(target, "MAX_ASSESSMENT_IMPORT_DEPTH", 0)
    result = target._recursive_handler_side_effect_audit(source, "analyze_managed_pe")
    assert len(contracts) == 1
    assert any("import_depth_limit:unpackers/managed_resource_snapshot.py" in issue for issue in result["issues"]), result


def test_cached_true_does_not_skip_consumer_source_pin(tmp_path, monkeypatch):
    source, contracts = _artificial_repository(tmp_path, monkeypatch)
    monkeypatch.setattr(target, "_MANAGED_RESOURCE_CONSUMER_COMMITMENTS", {RELATIVE: "0" * 64})
    result = target._recursive_handler_side_effect_audit(source, "analyze_managed_pe")
    assert len(contracts) == 1
    assert any("managed_resource_consumer_origin_or_commitment_rejected:prepare_resource_snapshot" in issue
               for issue in result["issues"]), result


@pytest.mark.parametrize("exception", [OSError, ValueError, RuntimeError])
def test_exception_then_false_is_retried_once_and_never_dispatches(exception):
    count = [0]
    def contract(tree, relative):
        count[0] += 1
        if count[0] == 1:
            raise exception("人工契約の失敗")
        return False
    def forbidden(*args):
        raise AssertionError("Falseまたは例外からdispatch不可")
    shape = _new_audit_scope(contract, forbidden)
    tree, scope, call = _fixture()
    with pytest.raises(exception):
        shape(call, tree, scope, RELATIVE, "reachable:analyze_managed_pe")
    for _ in range(3):
        assert shape(call, tree, scope, RELATIVE, "reachable:analyze_managed_pe") is None
    assert count == [2]


def test_dispatch_failure_does_not_cache_a_dispatch_result():
    contracts, dispatches = [0], [0]
    def contract(tree, relative):
        contracts[0] += 1
        return True
    def dispatch(*args):
        dispatches[0] += 1
        if dispatches[0] == 1:
            raise ValueError("人工dispatchの失敗")
        return None
    shape = _new_audit_scope(contract, dispatch)
    tree, scope, call = _fixture()
    with pytest.raises(ValueError):
        shape(call, tree, scope, RELATIVE, "reachable:analyze_managed_pe")
    assert shape(call, tree, scope, RELATIVE, "reachable:analyze_managed_pe") is None
    assert contracts == [1] and dispatches == [2]


def test_new_audit_rechecks_a_changed_contract_even_with_same_ast_object():
    state, count = [True], [0]
    def contract(tree, relative):
        count[0] += 1
        return state[0]
    tree, scope, call = _fixture()
    first = _new_audit_scope(contract, target._managed_resource_consumer_dispatch_shape)
    assert first(call, tree, scope, RELATIVE, "reachable:analyze_managed_pe") is not None
    state[0] = False
    second = _new_audit_scope(contract, target._managed_resource_consumer_dispatch_shape)
    assert second(call, tree, scope, RELATIVE, "reachable:analyze_managed_pe") is None
    assert count == [2]


@pytest.mark.parametrize("relative", (RELATIVE, PROXY))
def test_global_wrapper_rechecks_an_actual_consumer_tree_after_mutation(relative):
    # global互換APIでは同じASTを外部が変更してもfullcontractを再計算する。
    # audit内ASTは不変というlocal cacheの前提を、global APIへ拡張しない。
    source = ROOT / relative
    tree = ast.parse(source.read_text(encoding="utf-8-sig"))
    entry = target._MANAGED_RESOURCE_CONSUMER_ASSIGNMENTS[relative][0]
    scope = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == entry)
    call = next(node for node in ast.walk(scope) if isinstance(node, ast.Call)
                and target._ast_call_name(node.func) == "preflight_clr_declarations")
    context = "reachable:" + entry
    assert target._managed_resource_consumer_call_shape(call, tree, scope, relative, context) is not None
    tree.body.append(ast.parse("def " + entry + "(data):\n    return None\n").body[0])
    assert target._managed_resource_consumer_call_shape(call, tree, scope, relative, context) is None


def test_cached_true_does_not_authorize_a_wrong_scope_or_nonfunction_scope():
    shape = _new_audit_scope(lambda *args: True, target._managed_resource_consumer_dispatch_shape)
    tree, scope, call = _fixture()
    assert shape(call, tree, scope, RELATIVE, "reachable:analyze_managed_pe") is not None
    wrong = ast.parse("def unrelated(data):\n    return None\n").body[0]
    assert shape(call, tree, wrong, RELATIVE, "reachable:unrelated") is None
    assert shape(call, tree, tree, RELATIVE, "reachable:analyze_managed_pe") is None
