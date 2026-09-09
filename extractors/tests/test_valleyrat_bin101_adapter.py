"""ValleyRAT共通extractorのBIN/101 adapterを合成結果で検証する。"""

from __future__ import annotations

import hashlib
from types import SimpleNamespace

import pytest

from extractors.valleyrat import extractor

OUTER = b"MZ" + b"\0" * 126
PAYLOAD = b"synthetic validated codemark terminal payload"
ENDPOINTS = ["45.194.37.221:449", "fshsjlk.cc:8856"]


def _recovery() -> SimpleNamespace:
    """実payloadを含まず、BIN/101 recoveryの公開契約だけを再現する。"""

    return SimpleNamespace(
        payload=PAYLOAD,
        input_sha256=hashlib.sha256(OUTER).hexdigest(),
        payload_sha256=hashlib.sha256(PAYLOAD).hexdigest(),
        metadata=lambda: {
            "schema_version": 1,
            "status": "shellcode_recovered",
            "component": "bin101_nibble_rc4_loader",
            "payload_size": len(PAYLOAD),
            "payload_sha256": hashlib.sha256(PAYLOAD).hexdigest(),
            "raw_payload_included": False,
            "executed": False,
            "network_contacted": False,
        },
    )


def _probe(*, endpoint_count: int = 2) -> dict[str, object]:
    """trusted static recovery後に要求するcodemark終端probe契約を返す。"""

    return {
        "matched": True,
        "family": "valleyrat",
        "variant": "winos_codemark_recovered_stage",
        "supports_family_attribution": True,
        "attribution_scope": "validated_terminal_component_structure",
        "terminal_family_confirmed": True,
        "static_config_recovered": True,
        "evidence": {"trusted_static_recovery": True},
        "config": {
            "endpoint_count": endpoint_count,
            "raw_config_included": False,
            "raw_network_values_included": False,
        },
        "sample_executed": False,
        "network_contacted": False,
    }


def _parsed_config() -> dict[str, object]:
    """実parserが返す公開slot schemaに沿った一意な設定を返す。"""

    slots = [
        {
            "index": 1,
            "host": "45.194.37.221",
            "port": 449,
            "active": True,
            "enabled": True,
            "header_enabled": True,
            "transport_selector": 1,
            "transport": "tcp",
        },
        {
            "index": 2,
            "host": "fshsjlk.cc",
            "port": 8856,
            "active": True,
            "enabled": True,
            "header_enabled": True,
            "transport_selector": 1,
            "transport": "tcp",
        },
    ]
    return {
        "marker": "codemark",
        "endpoints": list(ENDPOINTS),
        "slots": slots,
        "raw_config_included": False,
    }


def _isolate_bin101_dispatch(monkeypatch: pytest.MonkeyPatch) -> None:
    """BIN/101以外の先行・後続adapterを決定論的に不一致へ固定する。"""

    monkeypatch.setattr(extractor, "looks_like_bin101_profile", lambda _data: True)
    for name in (
        "_reviewed_pdfcore8_result",
        "_extract_ca01_sideload",
        "_extract_onyx_terminal",
        "_extract_x86_codemark_resource",
        "_extract_codemark_stage",
        "_extract_n520",
        "_extract_xor_b1_downloader",
    ):
        monkeypatch.setattr(extractor, name, lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        extractor,
        "probe_run_dll_native_core_config",
        lambda _data: {"matched": False},
    )
    monkeypatch.setattr(extractor, "looks_like_nvml_dat", lambda _data: False)
    monkeypatch.setattr(
        extractor,
        "_bounded_strings",
        lambda _data: (
            [],
            {
                "truncated": False,
                "ascii_count": 0,
                "wide_count": 0,
                "unique_count": 0,
                "character_count": 0,
            },
        ),
    )


def _assert_unresolved(result: dict[str, object]) -> None:
    """adapter相関失敗が部分的なfamily/configへ昇格しないことを確認する。"""

    config = result["config"]
    assert isinstance(config, dict)
    assert config["variant"] == "unresolved_variant"
    assert config["static_config_recovered"] is False
    assert config["candidate_config_recovered"] is False
    assert config["terminal_family_confirmed"] is False
    assert config["endpoints"] == []
    assert result["findings"] == []
    assert "terminal_payload" not in result


def test_bin101_adapter_correlates_recovery_probe_and_config(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """同一payloadの復元・trusted probe・parseが一致した場合だけ終端へ昇格する。"""

    _isolate_bin101_dispatch(monkeypatch)
    calls: list[tuple[object, ...]] = []

    def recover(data: bytes) -> SimpleNamespace:
        calls.append(("recover", data))
        return _recovery()

    def probe(
        data: bytes,
        *,
        trusted_static_recovery: bool = False,
    ) -> dict[str, object]:
        calls.append(("probe", data, trusted_static_recovery))
        return _probe()

    def parse(data: bytes) -> dict[str, object]:
        calls.append(("parse", data))
        return _parsed_config()

    monkeypatch.setattr(extractor, "recover_bin101_payload", recover)
    monkeypatch.setattr(
        extractor,
        "public_bin101_recovery_summary",
        lambda recovery: recovery.metadata(),
    )
    monkeypatch.setattr(extractor, "probe_codemark_terminal_config", probe)
    monkeypatch.setattr(extractor, "parse_codemark_config", parse)

    result = extractor.extract(OUTER, r"C:\private\sample.exe")

    assert calls == [
        ("recover", OUTER),
        ("probe", PAYLOAD, True),
        ("parse", PAYLOAD),
    ]
    config = result["config"]
    assert config["variant"] == "bin101_nibble_rc4_loader_terminal"
    assert config["decoded_config_recovered"] is True
    assert config["static_config_recovered"] is True
    assert config["candidate_config_recovered"] is False
    assert config["terminal_family_confirmed"] is True
    assert config["attribution_scope"] == "validated_terminal_component_structure"
    assert config["endpoints"] == ENDPOINTS
    assert config["ipv4"] == ["45.194.37.221"]
    assert config["source_name"] == "sample.exe"
    assert [item["value"] for item in result["findings"]] == ENDPOINTS
    assert all(item["kind"] == "network.endpoint" for item in result["findings"])
    assert all(item["role"] == "static_config_c2" for item in result["findings"])
    assert all(
        item["confidence"] == "confirmed_static_config"
        for item in result["findings"]
    )
    assert result["executed"] is False
    assert result["network_contacted"] is False
    assert result["terminal_payload"] == {
        "role": "terminal_payload",
        "name": f"{hashlib.sha256(PAYLOAD).hexdigest()}.bin",
        "data": PAYLOAD,
    }


def test_bin101_adapter_recovery_none_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """外層復元失敗時はcodemark probe／parserを呼ばない。"""

    _isolate_bin101_dispatch(monkeypatch)
    monkeypatch.setattr(extractor, "recover_bin101_payload", lambda _data: None)
    monkeypatch.setattr(
        extractor,
        "probe_codemark_terminal_config",
        lambda *_args, **_kwargs: pytest.fail("復元失敗後にprobeしてはならない"),
    )
    monkeypatch.setattr(
        extractor,
        "parse_codemark_config",
        lambda _data: pytest.fail("復元失敗後にparseしてはならない"),
    )

    _assert_unresolved(extractor.extract(OUTER))


@pytest.mark.parametrize("digest_attribute", ["input_sha256", "payload_sha256"])
def test_bin101_adapter_recovery_sha_mismatch_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
    digest_attribute: str,
) -> None:
    """外層または復元payloadのrecovery SHA不一致を終端へ昇格しない。"""

    _isolate_bin101_dispatch(monkeypatch)
    recovery = _recovery()
    setattr(recovery, digest_attribute, "0" * 64)
    monkeypatch.setattr(extractor, "recover_bin101_payload", lambda _data: recovery)
    monkeypatch.setattr(
        extractor,
        "probe_codemark_terminal_config",
        lambda *_args, **_kwargs: pytest.fail("SHA不一致後にprobeしてはならない"),
    )
    monkeypatch.setattr(
        extractor,
        "parse_codemark_config",
        lambda _data: pytest.fail("SHA不一致後にparseしてはならない"),
    )

    _assert_unresolved(extractor.extract(OUTER))


def test_bin101_adapter_probe_contract_mismatch_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """route-only probeをtrusted終端結果として採用せず、parserも呼ばない。"""

    _isolate_bin101_dispatch(monkeypatch)
    mismatch = _probe()
    mismatch.update(
        {
            "family": None,
            "supports_family_attribution": False,
            "attribution_scope": "component_handler_route",
            "terminal_family_confirmed": False,
        }
    )
    monkeypatch.setattr(extractor, "recover_bin101_payload", lambda _data: _recovery())
    monkeypatch.setattr(
        extractor,
        "probe_codemark_terminal_config",
        lambda _data, *, trusted_static_recovery: mismatch,
    )
    monkeypatch.setattr(
        extractor,
        "parse_codemark_config",
        lambda _data: pytest.fail("probe契約不一致後にparseしてはならない"),
    )

    _assert_unresolved(extractor.extract(OUTER))


def test_bin101_adapter_endpoint_count_mismatch_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """probe要約とparserのendpoint件数がずれた場合は設定を一切返さない。"""

    _isolate_bin101_dispatch(monkeypatch)
    monkeypatch.setattr(extractor, "recover_bin101_payload", lambda _data: _recovery())
    monkeypatch.setattr(
        extractor,
        "probe_codemark_terminal_config",
        lambda _data, *, trusted_static_recovery: _probe(endpoint_count=3),
    )
    monkeypatch.setattr(extractor, "parse_codemark_config", lambda _data: _parsed_config())

    _assert_unresolved(extractor.extract(OUTER))


def test_bin101_adapter_parse_error_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """probe後の独立parseが失敗した場合もpayloadや部分設定を公開しない。"""

    _isolate_bin101_dispatch(monkeypatch)
    monkeypatch.setattr(extractor, "recover_bin101_payload", lambda _data: _recovery())
    monkeypatch.setattr(
        extractor,
        "probe_codemark_terminal_config",
        lambda _data, *, trusted_static_recovery: _probe(),
    )

    def reject(_data: bytes) -> dict[str, object]:
        raise extractor.NvmlDatError("合成parse失敗")

    monkeypatch.setattr(extractor, "parse_codemark_config", reject)

    _assert_unresolved(extractor.extract(OUTER))
