"""固定raw source pinの包装条件を検査し、対象moduleを実行しない。"""

from __future__ import annotations

import ast
import hashlib
from pathlib import Path

import pytest


REPOSITORY = Path(__file__).resolve().parents[2]
PINNED_PATHS = (
    "unpackers/managed_resources.py",
    "unpackers/dnfile_resource_adapter.py",
    "unpackers/clr_input_binding.py",
    "unpackers/managed_resource_snapshot.py",
    "unpackers/managed_constructor_guard.py",
    "unpackers/managed_il_triage.py",
    "unpackers/managed_proxy_deobfuscator.py",
    "analysis-framework/common/dotnet_rat_config.py",
    "unpackers/managed_metadata.py",
)
PIN_TABLES = {
    "_MANAGED_RESOURCE_SOURCE_COMMITMENTS",
    "_MANAGED_RESOURCE_CONSUMER_COMMITMENTS",
    "_MANAGED_READER_SOURCE_COMMITMENTS",
}


def _literal_pins() -> dict[str, str]:
    """通常catalogのliteralだけを読み、calleeやmoduleをimportしない。"""
    raw = (REPOSITORY / "analysis-framework/common/handler_catalog.py").read_bytes()
    tree = ast.parse(raw)
    pins: dict[str, str] = {}
    found = set()
    for node in tree.body:
        if not isinstance(node, ast.Assign) or len(node.targets) != 1:
            continue
        target = node.targets[0]
        if not isinstance(target, ast.Name) or target.id not in PIN_TABLES:
            continue
        assert target.id not in found
        found.add(target.id)
        assert isinstance(node.value, ast.Dict)
        for key, value in zip(node.value.keys, node.value.values, strict=True):
            assert isinstance(key, ast.Constant) and type(key.value) is str
            assert isinstance(value, ast.Constant) and type(value.value) is str
            assert key.value not in pins
            assert len(value.value) == 64 and all(char in "0123456789abcdef" for char in value.value)
            pins[key.value] = value.value
    assert found == PIN_TABLES
    return pins


def test_all_declared_raw_pins_are_in_explicit_packaging_scope() -> None:
    """pin追加時に属性・検証scopeの見直しを要求する。"""
    assert set(_literal_pins()) == set(PINNED_PATHS)


@pytest.mark.parametrize("relative", PINNED_PATHS)
def test_pinned_source_has_exact_rule_and_current_raw_sha(relative: str) -> None:
    """現在byteとexact ruleだけを検証し、公開blob照合は代用しない。"""
    attributes = (REPOSITORY / ".gitattributes").read_text(encoding="utf-8-sig")
    rules = [line.split() for line in attributes.splitlines() if line.strip() and not line.lstrip().startswith("#")]
    matching = [rule for rule in rules if rule[0] == relative]
    assert matching == [[relative, "-text", "diff", "whitespace=blank-at-eol,blank-at-eof,space-before-tab,cr-at-eol"]]
    assert hashlib.sha256((REPOSITORY / relative).read_bytes()).hexdigest() == _literal_pins()[relative]
