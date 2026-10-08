from __future__ import annotations

import sys
from pathlib import Path

import pytest

COMMON = Path(__file__).parents[1] / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

import audit_c2_active_integration as audit_module


def _script(root: Path, name: str = "fixture-c2.nse") -> str:
    scripts = root / "scripts"
    scripts.mkdir(parents=True, exist_ok=True)
    path = scripts / name
    path.write_text(
        'categories = {"intrusive", "malware"}\n'
        "action = function()\n"
        '  local mode = stdnse.get_script_args("fixture.mode")\n'
        '  if mode ~= "fixture" then return nil end\n'
        "  return {c2_confirmed=false}\n"
        "end\n",
        encoding="utf-8",
    )
    return f"scripts/{name}"


def _state(tmp_path: Path) -> dict:
    script = _script(tmp_path)
    return {
        "profile_methods": {"fixture_handler": ("fixture_protocol", "fixture_method")},
        "loaded_profiles": {
            "fixture-profile": {
                "handler": "fixture_handler",
                "protocol": "fixture_protocol",
                "method": "fixture_method",
                "family": "fixturefamily",
                "sample_sha256s": ["a" * 64],
            }
        },
        "allowed_methods": {"fixture_method"},
        "active_methods": {"fixture_method"},
        "method_ceilings": {"fixture_method": 0.95},
        "method_labels": {"fixture_method": "fixture malware固有probe"},
        "nmap_mapping": {
            "schema_version": 2,
            "canonical_families": [
                {
                    "family": "fixturefamily",
                    "aliases": [],
                    "script": script,
                    "modes": ["fixture"],
                }
            ],
            "execution_backend": "nmap_nse_only",
            "network_method_count": 1,
            "method_bindings": [
                {
                    "method": "fixture_method",
                    "script": script,
                    "mode": "fixture",
                    "confirmation_allowed": True,
                }
            ],
        },
        "nmap_root": tmp_path,
    }


def test_repository_active_integration_has_no_cross_layer_drift() -> None:
    report = audit_module.audit_repository()
    assert report["network_contacted"] is False
    assert report["status"] == "pass", report["errors"]
    assert report["summary"]["handler_count"] >= 10
    assert report["summary"]["reviewed_profile_count"] >= 15
    assert report["summary"]["nmap_method_binding_count"] == len(audit_module.monitor_module.ALLOWED_METHODS)


@pytest.mark.parametrize(
    ("method", "expected_ceiling"),
    [
        ("purelogs_https_ping", 0.70),
        ("purerat_tls_prelude", 0.60),
    ],
)
def test_pure_probable_only_binding_and_ceiling_fail_closed(
    tmp_path: Path,
    method: str,
    expected_ceiling: float,
) -> None:
    state = _state(tmp_path)
    state["profile_methods"] = {"fixture_handler": ("fixture_protocol", method)}
    state["loaded_profiles"]["fixture-profile"]["method"] = method
    state["allowed_methods"] = {method}
    state["active_methods"] = {method}
    state["method_ceilings"] = {method: expected_ceiling}
    state["method_labels"] = {method: "Pure probable限定probe"}
    state["nmap_mapping"]["method_bindings"][0]["method"] = method
    state["nmap_mapping"]["method_bindings"][0]["confirmation_allowed"] = False
    if method == "purelogs_https_ping":
        script = tmp_path / state["nmap_mapping"]["method_bindings"][0]["script"]
        script.write_text(
            script.read_text(encoding="utf-8")
            + '\nvariant="http_aes_v5"\n'
            + 'generation_evidence_scope="family_level_public_research"\n'
            + "sample_version_confirmed=false\n"
            + 'excluded_variant="legacy_socket_3des"\n'
            + "legacy_codec_implemented=false\n",
            encoding="utf-8",
        )

    report = audit_module.audit_integration_state(**state)
    assert report["status"] == "pass", report["errors"]

    state["method_ceilings"][method] = 0.95
    state["nmap_mapping"]["method_bindings"][0]["confirmation_allowed"] = True
    report = audit_module.audit_integration_state(**state)
    codes = {error["code"] for error in report["errors"]}
    assert "pure_probable_only_ceiling_mismatch" in codes
    assert "pure_probable_only_confirmation_enabled" in codes


def test_pure_probable_only_script_must_not_assign_confirmation_true(
    tmp_path: Path,
) -> None:
    state = _state(tmp_path)
    method = "purerat_tls_prelude"
    state["profile_methods"] = {"fixture_handler": ("fixture_protocol", method)}
    state["loaded_profiles"]["fixture-profile"]["method"] = method
    state["allowed_methods"] = {method}
    state["active_methods"] = {method}
    state["method_ceilings"] = {method: 0.60}
    state["method_labels"] = {method: "Pure probable限定probe"}
    state["nmap_mapping"]["method_bindings"][0]["method"] = method
    state["nmap_mapping"]["method_bindings"][0]["confirmation_allowed"] = False
    script = tmp_path / state["nmap_mapping"]["method_bindings"][0]["script"]
    script.write_text(
        script.read_text(encoding="utf-8").replace("c2_confirmed=false", "c2_confirmed=true"),
        encoding="utf-8",
    )

    report = audit_module.audit_integration_state(**state)
    assert any(error["code"] == "pure_probable_only_script_can_confirm" for error in report["errors"])


def test_purelogs_nse_requires_family_level_generation_boundary_markers(
    tmp_path: Path,
) -> None:
    state = _state(tmp_path)
    method = "purelogs_https_ping"
    state["profile_methods"] = {"fixture_handler": ("fixture_protocol", method)}
    state["loaded_profiles"]["fixture-profile"]["method"] = method
    state["allowed_methods"] = {method}
    state["active_methods"] = {method}
    state["method_ceilings"] = {method: 0.70}
    state["method_labels"] = {method: "PureLogs probable限定probe"}
    state["nmap_mapping"]["method_bindings"][0]["method"] = method
    state["nmap_mapping"]["method_bindings"][0]["confirmation_allowed"] = False

    report = audit_module.audit_integration_state(**state)
    assert any(error["code"] == "purelogs_generation_boundary_marker_missing" for error in report["errors"])


def test_capability_without_reviewed_endpoint_is_warning_not_activation(
    tmp_path: Path,
) -> None:
    state = _state(tmp_path)
    state["loaded_profiles"] = {}
    report = audit_module.audit_integration_state(
        **state,
        required_contracts=[
            {
                "handler": "fixture_handler",
                "protocol": "fixture_protocol",
                "method": "fixture_method",
                "nmap_family": "fixturefamily",
            }
        ],
    )
    assert report["status"] == "pass"
    assert report["warnings"] == [
        {
            "code": "capability_has_no_reviewed_endpoint_profile",
            "detail": "fixture_handler: 実endpointへの送信はfail-closedのままです",
        }
    ]


def test_passive_only_capability_must_not_be_monitor_or_nmap_enabled(
    tmp_path: Path,
) -> None:
    state = _state(tmp_path)
    state["loaded_profiles"] = {}
    state["allowed_methods"] = {"transport_method"}
    state["active_methods"] = set()
    state["nmap_mapping"]["passive_only_application_methods"] = ["fixture_method"]
    state["nmap_mapping"]["method_bindings"][0]["method"] = "transport_method"
    report = audit_module.audit_integration_state(**state)
    assert report["status"] == "pass", report["errors"]
    assert report["handlers"][0]["passive_only"] is True

    state["allowed_methods"].add("fixture_method")
    state["active_methods"].add("fixture_method")
    state["nmap_mapping"]["method_bindings"][0]["method"] = "fixture_method"
    report = audit_module.audit_integration_state(**state)
    codes = {error["code"] for error in report["errors"]}
    assert "passive_only_method_enabled" in codes
    assert "passive_only_method_bound_to_nmap" in codes


@pytest.mark.parametrize(
    ("field", "expected_detail"),
    [
        ("allowed_methods", "allowed_methods"),
        ("active_methods", "active_methods"),
        ("method_ceilings", "method_ceilings"),
        ("method_labels", "method_labels"),
    ],
)
def test_missing_monitor_layer_fails_closed(
    tmp_path: Path,
    field: str,
    expected_detail: str,
) -> None:
    state = _state(tmp_path)
    state[field] = {} if isinstance(state[field], dict) else set()
    report = audit_module.audit_integration_state(**state)
    assert report["status"] == "fail"
    assert any(
        error["code"] == "monitor_method_missing" and expected_detail in error["detail"] for error in report["errors"]
    )


def test_reviewed_family_without_nmap_registration_is_error(tmp_path: Path) -> None:
    state = _state(tmp_path)
    state["nmap_mapping"]["canonical_families"][0]["family"] = "otherfamily"
    report = audit_module.audit_integration_state(**state)
    assert report["status"] == "fail"
    assert {
        "code": "reviewed_family_missing_from_nmap",
        "detail": "fixturefamily",
    } in report["errors"]


@pytest.mark.parametrize("script", ["../escape.nse", "C:/escape.nse"])
def test_nmap_script_path_escape_is_rejected(tmp_path: Path, script: str) -> None:
    state = _state(tmp_path)
    state["nmap_mapping"]["canonical_families"][0]["script"] = script
    report = audit_module.audit_integration_state(**state)
    assert report["status"] == "fail"
    assert any(error["code"] == "nmap_script_path_unsafe" for error in report["errors"])


@pytest.mark.parametrize("modes", [None, [], ["fixture", "fixture"], ["bad mode"]])
def test_nmap_modes_must_be_present_unique_and_canonical(
    tmp_path: Path,
    modes: object,
) -> None:
    state = _state(tmp_path)
    state["nmap_mapping"]["canonical_families"][0]["modes"] = modes
    report = audit_module.audit_integration_state(**state)
    assert report["status"] == "fail"
    assert any(error["code"] == "nmap_modes_invalid" for error in report["errors"])


def test_nmap_declared_mode_must_match_script_dispatch(tmp_path: Path) -> None:
    state = _state(tmp_path)
    state["nmap_mapping"]["canonical_families"][0]["modes"] = ["missing"]
    state["nmap_mapping"]["method_bindings"][0]["mode"] = "missing"
    report = audit_module.audit_integration_state(**state)
    codes = {error["code"] for error in report["errors"]}
    assert report["status"] == "fail"
    assert "nmap_mode_not_dispatched" in codes
    assert "nmap_dispatch_not_registered" in codes


def test_schema_two_requires_every_monitor_method_binding(tmp_path: Path) -> None:
    state = _state(tmp_path)
    state["nmap_mapping"]["method_bindings"] = []
    state["nmap_mapping"]["network_method_count"] = 0
    report = audit_module.audit_integration_state(**state)
    codes = {error["code"] for error in report["errors"]}
    assert report["status"] == "fail"
    assert "nmap_method_bindings_invalid" in codes
    assert "monitor_method_missing_from_nmap" in codes


def test_required_contract_detects_handler_and_nmap_drift(tmp_path: Path) -> None:
    state = _state(tmp_path)
    report = audit_module.audit_integration_state(
        **state,
        required_contracts=[
            {
                "handler": "missing_handler",
                "protocol": "expected_protocol",
                "method": "expected_method",
                "nmap_family": "missingfamily",
            }
        ],
    )
    codes = {error["code"] for error in report["errors"]}
    assert report["status"] == "fail"
    assert "required_handler_missing_or_mismatched" in codes
    assert "required_nmap_family_missing" in codes


def test_duplicate_required_handler_is_rejected(tmp_path: Path) -> None:
    state = _state(tmp_path)
    contract = {
        "handler": "fixture_handler",
        "protocol": "fixture_protocol",
        "method": "fixture_method",
        "nmap_family": "fixturefamily",
    }
    with pytest.raises(audit_module.IntegrationAuditError):
        audit_module.audit_integration_state(
            **state,
            required_contracts=[contract, contract],
        )
