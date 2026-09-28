"""managed handlerのtransactionと動的設定origin契約を無害な合成metadataだけで検証する。"""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

COMMON = Path(__file__).resolve().parents[1] / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

import handler_catalog
from extractors.asyncrat import integrated as asyncrat
from extractors.dcrat import integrated as dcrat
from extractors.venomrat import integrated as venomrat

SYNTHETIC = b"SYNTHETIC-CONTRACT-NOT-A-SAMPLE"
FAMILIES = {"asyncrat": asyncrat, "dcrat": dcrat, "venomrat": venomrat}


def _common_recovery(family: str) -> dict:
    """検体・payloadを持たない共通recoverの合成成功recordを構成する。"""

    return {"schema_version": 1, "family": family, "sha256": hashlib.sha256(SYNTHETIC).hexdigest(),
        "terminal_managed_client": True, "static_config_recovered": True,
        "secret_fields_published": False, "executed": False, "network_contacted": False,
        "config_mode": "hmac_encrypted", "config_endpoints": [{"host": "fixture.example.test", "port": 4444}],
        "version": "fixture", "group": "fixture", "install": "false", "anti_analysis": "false",
        "dynamic_config_url": "https://Resolver.Example.Test:8443/", "dynamic_config_url_scope": "origin_only",
        "certificate": {"sha256": "a" * 64, "size": 128, "validation": "embedded_certificate_present",
            "certificate_mismatch_excludes_c2": False},
        "crypto_profile": {"salt_source": "reviewed_static_initializer" if family == "dcrat"
            else "reviewed_family_profile", "salt_published": False}}


def _bind_common(monkeypatch: pytest.MonkeyPatch, family: str, value: dict) -> None:
    module = FAMILIES[family]
    fake = SimpleNamespace(recover=lambda *_args: copy.deepcopy(value))
    if family == "venomrat":
        monkeypatch.setattr(module, "_load_dotnet_rat_config", lambda: fake)
    else:
        monkeypatch.setattr(module, "_load_common_module", lambda _name: fake)


@pytest.mark.parametrize("family", FAMILIES)
def test_valid_origin_is_scoped_but_never_a_complete_locator(monkeypatch, family: str) -> None:
    value = _common_recovery(family)
    _bind_common(monkeypatch, family, value)
    projection = FAMILIES[family]._validated_recovery(SYNTHETIC)
    assert projection["dynamic_config_url_scope"] == "origin_only"
    assert projection["dynamic_config_locator_complete"] is False
    if family == "asyncrat":
        assert projection["dynamic_config_present"] is True
        assert "dynamic_config_url" not in projection
    else:
        assert projection["dynamic_config_url"] == "https://resolver.example.test:8443/"


@pytest.mark.parametrize("family", FAMILIES)
@pytest.mark.parametrize("omitted", [False, True])
def test_null_url_keeps_legacy_fixture_compatibility(monkeypatch, family: str, omitted: bool) -> None:
    value = _common_recovery(family)
    value.pop("dynamic_config_url_scope")
    if omitted:
        value.pop("dynamic_config_url")
    else:
        value["dynamic_config_url"] = None
    _bind_common(monkeypatch, family, value)
    projection = FAMILIES[family]._validated_recovery(SYNTHETIC)
    assert projection["dynamic_config_url_scope"] is None
    assert projection["dynamic_config_locator_complete"] is False


@pytest.mark.parametrize("family", FAMILIES)
@pytest.mark.parametrize("scope", [None, False, True, "full_url", "origin_only "])
def test_nonnull_origin_requires_exact_explicit_scope(monkeypatch, family: str, scope) -> None:
    value = _common_recovery(family)
    value["dynamic_config_url_scope"] = scope
    _bind_common(monkeypatch, family, value)
    with pytest.raises(ValueError, match="動的設定origin"):
        FAMILIES[family]._validated_recovery(SYNTHETIC)


@pytest.mark.parametrize("family", FAMILIES)
@pytest.mark.parametrize("url", [
    "https://resolver.example.test/SECRET-PATH", "https://resolver.example.test/?token=SECRET",
    "https://resolver.example.test/#SECRET", "https://SECRET@resolver.example.test/",
    "https://resolver.example.test/?", "https://resolver.example.test/#",
    "https://resolver.example.test/\n", "https://resolver.example.test:0/",
    "https://resolver.example.test:65536/", "file://resolver.example.test/",
    {"value": "SECRET"}, False,
])
def test_nonorigin_shapes_and_secret_context_are_rejected(monkeypatch, family: str, url) -> None:
    value = _common_recovery(family)
    value["dynamic_config_url"] = url
    _bind_common(monkeypatch, family, value)
    with pytest.raises(ValueError, match="動的設定origin") as error:
        FAMILIES[family]._validated_recovery(SYNTHETIC)
    assert "SECRET" not in str(error.value)


@pytest.mark.parametrize("family", FAMILIES)
@pytest.mark.parametrize("key,value", [("schema_version", True), ("terminal_managed_client", False),
    ("static_config_recovered", False), ("secret_fields_published", True),
    ("executed", True), ("network_contacted", True)])
def test_invalid_safety_metadata_is_never_recovered(monkeypatch, family: str, key: str, value) -> None:
    recovered = _common_recovery(family)
    recovered[key] = value
    _bind_common(monkeypatch, family, recovered)
    with pytest.raises(ValueError):
        FAMILIES[family]._validated_recovery(SYNTHETIC)


@pytest.mark.parametrize("failure", [ValueError, OSError, ImportError])
def test_dcrat_protocol_failure_rolls_back_all_recovery(monkeypatch, failure) -> None:
    _bind_common(monkeypatch, "dcrat", _common_recovery("dcrat"))
    monkeypatch.setattr(dcrat, "structural_evidence", lambda _data: {"matched": True})
    def reject(*_args):
        raise failure("SECRET-PROTOCOL-ERROR")
    monkeypatch.setattr(dcrat, "_validated_protocol", reject)
    result = dcrat.extract(SYNTHETIC)
    assert result["config"]["recovery_status"] == "rejected_or_not_recovered"
    assert result["config"]["static_config_recovered"] is False
    assert result["config"]["terminal_managed_client"] is False
    assert result["config"]["c2_protocol_recovered"] is False
    assert result["static_config_recovered"] is False
    assert result["config_endpoints"] == result["findings"] == []
    assert result["protocol_evidence"] is None and result["static_protocol"] is None
    assert result["config"]["dynamic_config_url"] is None
    assert result["config"]["dynamic_config_url_scope"] is None
    assert "resolver.example" not in json.dumps(result) and "SECRET" not in json.dumps(result)


@pytest.mark.parametrize("family", ["dcrat", "venomrat"])
def test_publication_retains_origin_scope_without_terminal_c2_role(monkeypatch, family: str) -> None:
    module = FAMILIES[family]
    _bind_common(monkeypatch, family, _common_recovery(family))
    monkeypatch.setattr(module, "structural_evidence", lambda _data: {"matched": True})
    if family == "dcrat":
        monkeypatch.setattr(module, "_validated_protocol", lambda *_args: {"analysis_status": "complete"})
    result = module.extract(SYNTHETIC)
    assert result["config"]["static_config_recovered"] is True
    assert result["config"]["dynamic_config_url_scope"] == "origin_only"
    assert result["config"]["dynamic_config_locator_complete"] is False
    origin = next(item for item in result["findings"] if item["role"] == "dynamic_config_resolver")
    assert origin["value_scope"] == "origin_only"
    assert origin["retrieval_locator_complete"] is False and origin["terminal_c2_endpoint"] is False
    assert origin["value"] == "https://resolver.example.test:8443/"
    assert result["executed"] is False and result["network_contacted"] is False


@pytest.mark.parametrize("family", ["dcrat", "venomrat"])
@pytest.mark.parametrize("legacy", ["missing_scope", "full_path", "contradictory_scope"])
def test_publication_rechecks_projection_contract(monkeypatch, family: str, legacy: str) -> None:
    module = FAMILIES[family]
    value = {"endpoints": [{"host": "fixture.example.test", "port": 4444}],
        "certificate": {"sha256": "a" * 64, "size": 128},
        "dynamic_config_url": "https://resolver.example.test/", "dynamic_config_url_scope": "origin_only"}
    if legacy == "missing_scope":
        value.pop("dynamic_config_url_scope")
    elif legacy == "full_path":
        value["dynamic_config_url"] += "SECRET-PATH"
    else:
        value["dynamic_config_url_scope"] = "full_url"
    monkeypatch.setattr(module, "structural_evidence", lambda _data: {"matched": True})
    monkeypatch.setattr(module, "_validated_recovery", lambda _data: copy.deepcopy(value))
    if family == "dcrat":
        monkeypatch.setattr(module, "_validated_protocol", lambda *_args: pytest.fail("URL契約拒否後にprotocolへ進めません"))
    result = module.extract(SYNTHETIC)
    assert result["config"]["static_config_recovered"] is False
    assert result["findings"] == []
    assert "SECRET" not in json.dumps(result)


def test_asyncrat_publication_keeps_presence_and_scope_without_url_value(monkeypatch) -> None:
    _bind_common(monkeypatch, "asyncrat", _common_recovery("asyncrat"))
    monkeypatch.setattr(asyncrat, "structural_evidence", lambda _data: {"matched": True, "managed_pe": True})
    monkeypatch.setattr(asyncrat, "_validated_protocol", lambda *_args: {"analysis_status": "complete"})
    monkeypatch.setattr(asyncrat, "_managed_inventory", lambda *_args: [])
    monkeypatch.setattr(asyncrat, "_reviewed_functions", lambda *_args, **_kwargs: [])
    result = asyncrat.extract(SYNTHETIC)
    assert result["config"]["dynamic_config_present"] is True
    assert result["config"]["dynamic_config_url_scope"] == "origin_only"
    assert result["config"]["dynamic_config_locator_complete"] is False
    assert "dynamic_config_url" not in result["config"]
    assert "resolver.example" not in json.dumps(result)


@pytest.mark.parametrize("family", FAMILIES)
def test_normal_handler_preflight_remains_nonexecuting_and_nonnetworked(family: str) -> None:
    spec = next(item for item in handler_catalog.discover_handlers()
        if item.family == family and item.relative_path == f"extractors/{family}/extractor.py")
    result = handler_catalog.preflight_handler_for_assessment(spec, actual_format="pe", input_size=1024)
    assert result["eligible"] is True and result["blockers"] == []
    assert result["sample_execution_allowed"] is False
    assert result["network_allowed"] is False and result["filesystem_write_allowed"] is False
