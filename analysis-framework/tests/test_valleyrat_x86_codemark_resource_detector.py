"""x86 codemark resourceのdetector帰属と公開境界を検証する。"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

MODULE_PATH = (
    Path(__file__).resolve().parents[1] / "malware" / "valleyrat" / "detect.py"
)
SPEC = importlib.util.spec_from_file_location(
    "valleyrat_x86_codemark_resource_detect",
    MODULE_PATH,
)
assert SPEC and SPEC.loader
DETECT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DETECT)


def _empty_probe() -> dict[str, object]:
    return {
        "matched": False,
        "supports_family_attribution": False,
        "static_config_recovered": False,
        "evidence": {},
        "config": {},
    }


def _x86_outer_probe() -> dict[str, object]:
    return {
        "matched": True,
        "family": None,
        "variant": "x86_codemark_resource_terminal",
        "supports_family_attribution": False,
        "attribution_scope": "component_handler_route",
        "terminal_family_confirmed": False,
        "static_config_recovered": True,
        "evidence": {
            "status": "validated_x86_codemark_resource_config",
            "resource_occurrence_count": 2,
            "unique_stage_count": 1,
            "raw_resource_included": False,
            "raw_code_included": False,
            "raw_key_included": False,
        },
        "config": {
            "endpoint_count": 2,
            "raw_config_included": False,
            "raw_network_values_included": False,
        },
        "sample_executed": False,
        "network_contacted": False,
    }


def test_validated_outer_resource_is_route_only_without_publishing_config(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        DETECT,
        "probe_codemark_terminal_config",
        lambda *_args, **_kwargs: _empty_probe(),
    )
    monkeypatch.setattr(
        DETECT,
        "probe_x86_codemark_resource_config",
        lambda _data: _x86_outer_probe(),
    )
    monkeypatch.setattr(
        DETECT,
        "probe_n520_config",
        lambda _data: pytest.fail("x86 resource一致後に別probeを呼んではならない"),
    )

    result = DETECT.detect(b"MZ validated outer", Path("unknown.exe"))
    serialized = json.dumps(result, sort_keys=True)

    assert result["matched"] is True
    assert result["supports_family_attribution"] is False
    campaign = result["campaigns"][0]
    assert campaign["campaign_type"] == "x86_codemark_resource_terminal"
    assert campaign["confidence"] == "medium"
    assert campaign["supports_family_attribution"] is False
    assert campaign["attribution_scope"] == "component_handler_route"
    assert campaign["terminal_family_confirmed"] is False
    assert "198.51.100.24" not in serialized
    assert "backup.example" not in serialized


def test_raw_x86_stage_remains_route_only_and_does_not_reparse_network_values(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw_probe = {
        "matched": True,
        "family": None,
        "variant": "winos_codemark_recovered_stage",
        "supports_family_attribution": False,
        "attribution_scope": "component_handler_route",
        "terminal_family_confirmed": False,
        "static_config_recovered": True,
        "evidence": {
            "raw_x86_shellcode": {"instruction_coverage": 1.0},
            "codemark_config": {"slot_count": 2},
        },
        "config": {
            "endpoint_count": 2,
            "raw_config_included": False,
            "raw_network_values_included": False,
        },
        "sample_executed": False,
        "network_contacted": False,
    }
    monkeypatch.setattr(
        DETECT,
        "probe_codemark_terminal_config",
        lambda *_args, **_kwargs: raw_probe,
    )
    assert not hasattr(DETECT, "parse_codemark_config")

    result = DETECT.detect(b"raw x86 stage", Path("stage.bin"))
    serialized = json.dumps(result, sort_keys=True)

    assert result["matched"] is True
    assert result["supports_family_attribution"] is False
    campaign = result["campaigns"][0]
    assert campaign["confidence"] == "medium"
    assert campaign["attribution_scope"] == "component_handler_route"
    assert campaign["terminal_family_confirmed"] is False
    observation = result["observations"]["codemark_stage"]
    assert observation["config"]["endpoint_count"] == 2
    assert "endpoints" not in observation["config"]
    assert "198.51.100.24" not in serialized
