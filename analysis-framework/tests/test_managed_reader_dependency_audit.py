"""固定managed readerの起点・callee実装監査を非実行sourceコピーで検証する。"""

from __future__ import annotations

import ast
import hashlib
import sys
from pathlib import Path

import pytest

COMMON = Path(__file__).resolve().parents[1] / "common"
REPOSITORY = COMMON.parents[1]
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))
import handler_catalog as catalog  # noqa: E402

CONFIG = "analysis-framework/common/dotnet_rat_config.py"
METADATA = "unpackers/managed_metadata.py"


@pytest.fixture
def copied_sources(tmp_path, monkeypatch):
    """通常sourceだけをコピーし、変更版をimport／実行することはない。"""
    root = tmp_path / "repository"
    for relative in (CONFIG, METADATA):
        destination = root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes((REPOSITORY / relative).read_bytes())
    (root / "unpackers" / "__init__.py").write_text("", encoding="utf-8")
    monkeypatch.setattr(catalog, "REPOSITORY_ROOT", root)
    monkeypatch.setattr(catalog, "MALWARE_ROOT", root / "analysis-framework" / "malware")
    monkeypatch.setattr(catalog, "EXTRACTORS_ROOT", root / "extractors")
    catalog.clear_handler_caches()
    yield root
    catalog.clear_handler_caches()


def _audit(root, symbol="static_salt"):
    return catalog._recursive_handler_side_effect_audit(root / CONFIG, symbol)


def _replace(root, relative, before, after, monkeypatch, *, renew_commitment=True):
    """意図的な新レビューSHAでもcallee内危険callを見逃さないことを試験する。"""
    path = root / relative
    source = path.read_text(encoding="utf-8")
    assert before in source
    source = source.replace(before, after, 1)
    path.write_text(source, encoding="utf-8")
    if renew_commitment:
        monkeypatch.setitem(catalog._MANAGED_READER_SOURCE_COMMITMENTS, relative,
                            hashlib.sha256(path.read_bytes()).hexdigest())


@pytest.mark.parametrize("symbol", ["settings_literals", "static_salt"])
def test_normal_fixed_managed_reader_closure_is_audited(copied_sources, symbol):
    result = _audit(copied_sources, symbol)
    assert result["issues"] == [], result["issues"]
    assert result["allowance_counts"]["reviewed_managed_reader_source_call"] >= 1
    paths = {item["path"] for item in result["files"]}
    assert CONFIG in paths
    if symbol == "static_salt":
        assert METADATA in paths
        assert result["allowance_counts"]["reviewed_managed_reader_internal_call"] >= 1


@pytest.mark.parametrize("mutation", ["factory", "tuple", "reader_rebind", "reader_attribute", "profile", "resolver_origin", "import", "parameter", "namespace", "pe_parameter"])
def test_fixed_origin_call_and_namespace_mutations_fail_closed(copied_sources, monkeypatch, mutation):
    changes = {
        "factory": ("_LiteralReader(pe)\n", "UntrustedReader(pe)\n"),
        "tuple": ("pe, field_owners, body, cctor_token, literal_reader =", "pe, field_owners, body, literal_reader, cctor_token ="),
        "reader_rebind": ("literal = literal_reader.read(operands[1])", "literal_reader = object()\n    literal = literal_reader.read(operands[1])"),
        "reader_attribute": ("literal = literal_reader.read(operands[1])", "literal_reader.read = lambda value: value\n    literal = literal_reader.read(operands[1])"),
        "profile": ('"system_text_encoding_get_ascii_v1")', '"unreviewed_profile")'),
        "resolver_origin": ("resolver = MetadataResolver(pe)\n    getter", "resolver = object()\n    getter"),
        "import": ("from unpackers.managed_metadata import MetadataResolver\n\n    pe, field_owners", "from untrusted import MetadataResolver\n\n    pe, field_owners"),
        "parameter": ("pending = literal_reader.read(operand)", "literal_reader = object()\n            pending = literal_reader.read(operand)"),
        "namespace": ("pe, field_owners, body, cctor_token, literal_reader =", "_settings_initializer = lambda *args: args\n    pe, field_owners, body, cctor_token, literal_reader ="),
        "pe_parameter": ("pending = literal_reader.read(operand)", "pe = object()\n            pending = literal_reader.read(operand)"),
    }
    before, after = changes[mutation]
    _replace(copied_sources, CONFIG, before, after, monkeypatch)
    symbol = "settings_literals" if mutation in {"parameter", "pe_parameter"} else "static_salt"
    result = _audit(copied_sources, symbol)
    assert result["issues"], mutation
    assert any("managed_reader" in issue or "unresolved" in issue or "unapproved" in issue for issue in result["issues"])


@pytest.mark.parametrize("relative", [CONFIG, METADATA])
def test_source_commitment_change_is_rejected(copied_sources, monkeypatch, relative):
    _replace(copied_sources, relative, 'from __future__ import annotations',
             'from __future__ import annotations\n# 新しい未レビュー版', monkeypatch, renew_commitment=False)
    assert any("managed_reader_source_commitment_mismatch" in value for value in _audit(copied_sources)["issues"])


@pytest.mark.parametrize("capability", [
    'open("C:/private/synthetic.bin", "rb")',
    '__import__("socket").socket()',
    '__import__("subprocess").run(["synthetic-only"])',
    '__import__("clr").AddReference("synthetic-only")',
    'eval("synthetic-only")',
])
@pytest.mark.parametrize("callee", ["literal_direct", "literal_indirect", "metadata_direct", "metadata_indirect", "constructor"])
def test_callee_body_and_internal_self_calls_reject_capabilities(copied_sources, monkeypatch, capability, callee):
    if callee.startswith("literal") or callee == "constructor":
        relative = CONFIG
        if callee == "constructor":
            before, after = "self._pe = pe", f'{capability}\n        self._pe = pe'
        elif callee == "literal_direct":
            before, after = "value = _user_string(self._pe, token)", f'{capability}\n        value = _user_string(self._pe, token)'
        else:
            before = "value = _user_string(self._pe, token)"
            after = "self._synthetic_unsafe()\n        " + before
            _replace(copied_sources, relative, "    def read(self, token: object) -> str:",
                     f"    def _synthetic_unsafe(self):\n        {capability}\n\n    def read(self, token: object) -> str:", monkeypatch)
    else:
        relative = METADATA
        before = "token = token_value(operand)\n        profile ="
        if callee == "metadata_direct":
            after = f"{capability}\n        token = token_value(operand)\n        profile ="
        else:
            after = "self._synthetic_unsafe()\n        " + before
            _replace(copied_sources, relative, "    def match_framework_member(self, operand: Any, profile_id: str) -> dict[str, Any]:",
                     f"    def _synthetic_unsafe(self):\n        {capability}\n\n    def match_framework_member(self, operand: Any, profile_id: str) -> dict[str, Any]:", monkeypatch)
    _replace(copied_sources, relative, before, after, monkeypatch)
    result = _audit(copied_sources)
    assert result["issues"], (callee, capability)
    assert any("forbidden" in value or "unapproved" in value or "unresolved" in value for value in result["issues"])


def test_both_parameter_callers_are_exact_and_assessment_is_not_globally_allowed(copied_sources, monkeypatch):
    path = copied_sources / CONFIG
    tree = ast.parse(path.read_text(encoding="utf-8"))
    collector = next(item for item in tree.body if isinstance(item, ast.FunctionDef) and item.name == "_collect_settings_literals")
    assert catalog._managed_reader_parameter_origin(tree, collector)
    assert (CONFIG, "reachable:assess_settings_literals", "literal_reader.read") not in catalog._MANAGED_READER_SOURCE_CALLS
    _replace(copied_sources, CONFIG, "            _collect_settings_literals(pe, owners, _straight_line_initializer(body), settings_type, literal_reader)",
             "            _collect_settings_literals(pe, owners, _straight_line_initializer(body), settings_type, object())", monkeypatch)
    assert _audit(copied_sources, "settings_literals")["issues"]


@pytest.mark.parametrize("relative,class_name", [(CONFIG, "_LiteralReader"), (METADATA, "MetadataResolver")])
@pytest.mark.parametrize("hook", ["property", "getattribute"])
def test_class_attribute_hooks_cannot_hide_callee_side_effects(copied_sources, monkeypatch, relative, class_name, hook):
    body = ('    @property\n    def _synthetic_property(self):\n        open("synthetic-only", "rb")\n'
            if hook == "property" else
            '    def __getattribute__(self, name):\n        open("synthetic-only", "rb")\n')
    before = f"class {class_name}:\n"
    _replace(copied_sources, relative, before, before + body, monkeypatch)
    assert any("managed_reader_class_shape_rejected" in value for value in _audit(copied_sources)["issues"])


def test_normal_venom_handler_preflight_integrates_fixed_class_audit():
    spec = next(item for item in catalog.discover_handlers() if item.id == "venomrat:extractors.venomrat.integrated.py:extract")
    result = catalog.preflight_handler_for_assessment(spec, actual_format="pe", input_size=1)
    assert result["eligible"] is True, result["blockers"]
    assert result["sample_execution_allowed"] is False
    assert result["network_allowed"] is False
    assert result["filesystem_write_allowed"] is False
