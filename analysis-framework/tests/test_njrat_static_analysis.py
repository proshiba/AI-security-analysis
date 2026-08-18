from __future__ import annotations

import importlib
import sys
from pathlib import Path

import pytest


REPOSITORY = Path(__file__).resolve().parents[2]
COMMON = REPOSITORY / "analysis-framework" / "common"
for candidate in (REPOSITORY, COMMON):
    if str(candidate) not in sys.path:
        sys.path.insert(0, str(candidate))

integrated = importlib.import_module("extractors.njrat.integrated")
handler_evidence = importlib.import_module("handler_evidence")

REVIEWED_SHA256 = "520afe474c0d141f0efb5ab826e581fb4d0e87a30cf6e34fd509af71d3829f26"


def _record(
    name: str,
    *,
    strings: set[str] | None = None,
    calls: set[str] | None = None,
    fields: set[str] | None = None,
    instructions: tuple[tuple[str, object], ...] = (),
) -> integrated.MethodRecord:
    return integrated.MethodRecord(
        token="0x06000001",
        owner="j.OK",
        name=name,
        instructions=instructions,
        strings=frozenset(strings or set()),
        calls=frozenset(calls or set()),
        fields=frozenset(fields or set()),
    )


def _review() -> integrated.ManagedReview:
    methods = {
        ".cctor": _record(".cctor"),
        "Sendb": _record(
            "Sendb",
            strings={"\x00"},
            calls={"ToString", "Concat", "Write", "Send"},
            instructions=(("callvirt", "Write"), ("callvirt", "Write"), ("callvirt", "Send")),
        ),
        "RC": _record("RC", calls={"ReadByte", "ToLong", "Receive", "j.OK.connect"}),
        "connect": _record(
            "connect",
            strings={"inf", ":", "\r\n"},
            calls={"Connect", "j.OK.inf", "j.OK.ENB", "j.OK.Send"},
            fields={"H", "P", "Y"},
        ),
        "Ind": _record(
            "Ind",
            strings=set(integrated._COMMAND_MARKERS),
            calls={"j.OK.BS", "Split"},
            fields={"Y"},
        ),
        "inf": _record("inf"),
        "INS": _record("INS"),
    }
    return integrated.ManagedReview(
        owner="j.OK",
        fields=integrated._REQUIRED_FIELDS,
        methods=methods,
        cctor_values={
            "H": "c2.example.test",
            "P": "13152",
            "VN": "VmljdGlt",
            "VR": "<- NjRAT 0.7d Horror Edition ->",
            "Y": "fixture-delimiter",
            "DR": "TEMP",
            "EXE": "dllhost.exe",
            "RG": "fixture-mutex",
            "PASTEE": "Disabled",
            "PASTEBIN": "https://example.test/raw/???",
        },
        type_count=22,
        method_count=122,
        methods_with_body=76,
        methods_without_body=46,
        malformed_method_bodies=0,
    )


def test_config_recovers_fixed_endpoint_without_placeholder_overpromotion() -> None:
    config = integrated._config(_review())

    assert config["version"] == "0.7d Horror Edition"
    assert config["host"] == "c2.example.test"
    assert config["port"] == 13152
    assert config["campaign_label"] == "Victim"
    assert config["dynamic_config_enabled"] is False
    assert config["dynamic_config_url"] is None
    assert config["delimiter_published"] is False


@pytest.mark.parametrize(
    ("field", "value"),
    [("H", "not a host"), ("P", "0"), ("P", "65536"), ("VN", "%%%"), ("Y", "x")],
)
def test_config_rejects_invalid_critical_fields(field: str, value: str) -> None:
    review = _review()
    review.cctor_values[field] = value

    with pytest.raises(integrated.NjratStaticError):
        integrated._config(review)


def test_protocol_requires_bidirectional_frame_and_dispatcher_structure() -> None:
    protocol = integrated._protocol_summary(_review())

    assert protocol["framing"] == "ascii_decimal_length_nul_delimiter"
    assert protocol["registration"]["prefix"] == "inf"
    assert protocol["dispatcher"]["command_marker_count"] == 9
    assert protocol["safety"]["sample_executed"] is False
    assert protocol["safety"]["network_contacted"] is False


def test_protocol_rejects_missing_dispatch_marker() -> None:
    review = _review()
    review.methods["Ind"] = _record(
        "Ind",
        strings=set(integrated._COMMAND_MARKERS - {"prof"}),
        calls={"j.OK.BS", "Split"},
        fields={"Y"},
    )

    with pytest.raises(integrated.NjratStaticError):
        integrated._protocol_summary(review)


def test_extract_publishes_confirmed_static_not_live(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(integrated, "_inspect", lambda _data: _review())

    result = integrated.extract(b"MZ\0BSJB\0fixture", "fixture.exe")

    assert result["static_config_recovered"] is True
    assert result["config_endpoints"] == [
        {
            "host": "c2.example.test",
            "port": 13152,
            "transport": "tcp",
            "role": "configured_c2",
            "confidence": "confirmed_static_configuration",
            "evidence": {
                "kind": "managed_cctor_and_connect_correlation",
                "all_expected_fields_validated": True,
            },
        }
    ]
    assert result["static_protocol"]["live_verified"] is False
    assert result["executed"] is False
    assert result["network_contacted"] is False


def test_nonheartbeat_protocol_is_confirmed_without_live_overpromotion(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(integrated, "_inspect", lambda _data: _review())
    result = integrated.extract(b"MZ\0BSJB\0fixture", "fixture.exe")
    execution = {
        "handler_id": "njrat:extractors.njrat.extractor.py:extract",
        "status": "succeeded",
        "selected_evidence": {"sufficient": True},
    }
    artifact = {
        "handler": {"id": execution["handler_id"]},
        "result": result,
        "selected_evidence": {"sufficient": True},
        "executed_sample": False,
        "network_contacted": False,
    }

    protocols = handler_evidence.confirmed_static_protocol_evidence([(execution, artifact)])

    assert protocols == [
        {
            "family": "njrat",
            "sample_sha256": result["sample_sha256"],
            "method": "managed_cil_ascii_length_nul_delimited_tcp",
            "transport": "tcp",
            "framing": "ascii_decimal_length_nul_delimiter",
            "serialization": "utf8_delimiter_commands",
            "confidence": "high",
            "registration_method": "j.OK.connect",
            "dispatcher_method": "j.OK.Ind",
            "heartbeat_required": False,
            "heartbeat_method": "",
            "command_markers": sorted(integrated._COMMAND_MARKERS),
            "transfer_markers": [],
            "heartbeat_response_markers": [],
            "live_operation_fake_result_allowed": False,
            "live_verified": False,
        }
    ]


def test_exact_review_has_meaningful_functions_and_program_inventory() -> None:
    functions = integrated._reviewed_functions(REVIEWED_SHA256)
    programs = integrated._program_evidence(_review(), REVIEWED_SHA256)

    assert len(functions) == 10
    assert {item["role"] for item in functions} >= {
        "command_control",
        "command_dispatcher",
        "config_decoder",
        "credential_collection",
        "destructive_capability",
        "persistence",
    }
    assert all(item["summary_ja"] and item["logic_steps_ja"] for item in functions)
    assert programs[0]["managed_method_count"] == 122
    assert programs[0]["retrieval_coverage"]["managed_methods_with_body"] == 76


def test_structural_evidence_fails_closed_on_non_managed_bytes() -> None:
    result = integrated.structural_evidence(b"MZ but not managed")

    assert result["matched"] is False
    assert result["sample_executed"] is False
    assert result["network_contacted"] is False
