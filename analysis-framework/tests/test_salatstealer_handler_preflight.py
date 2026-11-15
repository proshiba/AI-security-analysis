"""Salatの安全な純メモリhandlerをsource限定ASTだけで許可する。"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

COMMON = Path(__file__).resolve().parents[1] / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

import handler_catalog as catalog  # noqa: E402


def test_salat_preflight_uses_exact_reviewed_source_calls_only():
    catalog.clear_handler_caches()
    spec = next(
        item for item in catalog.discover_handlers()
        if item.family == "salatstealer" and item.relative_path.endswith("salatstealer/extract_config.py")
    )
    preflight = catalog.preflight_handler_for_assessment(spec, actual_format="pe", input_size=1024)
    assert preflight["eligible"] is True, preflight["blockers"]
    assert preflight["dependency_audit"]["allowance_counts"]["reviewed_source_scoped_call"] == 18
    assert "pow" not in catalog._APPROVED_EXTERNAL_CALLS
    assert "bit_length" not in catalog._APPROVED_SAFE_METHOD_NAMES
    assert "reg_name" not in catalog._APPROVED_SAFE_METHOD_NAMES
    assert "cryptography.hazmat.primitives.ciphers.aead.AESGCM" not in catalog._APPROVED_EXTERNAL_CALLS
    for key, expressions in catalog._SALAT_STATIC_REVIEWED_CALL_EXPRESSIONS.items():
        assert key in catalog._REVIEWED_SOURCE_CALLS
        assert ("unpackers/other.py", key[1], key[2]) not in catalog._REVIEWED_SOURCE_CALLS
        tree = ast.parse("")
        for expression in expressions:
            call = ast.parse(expression, mode="eval").body
            assert catalog._reviewed_source_call_shape_allowed(call, key[2], tree, tree, {}, key=key)
            call.keywords.append(ast.keyword(arg="unreviewed_argument", value=ast.Constant(True)))
            assert not catalog._reviewed_source_call_shape_allowed(call, key[2], tree, tree, {}, key=key)


def test_salat_does_not_accept_other_formats():
    spec = next(
        item for item in catalog.discover_handlers()
        if item.family == "salatstealer" and item.relative_path.endswith("salatstealer/extract_config.py")
    )
    preflight = catalog.preflight_handler_for_assessment(spec, actual_format="elf", input_size=1024)
    assert preflight["eligible"] is False
