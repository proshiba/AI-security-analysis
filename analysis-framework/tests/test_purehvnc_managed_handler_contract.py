"""厳密なmanaged復元だけを両Pure handlerの標準設定契約へ投影する境界を検証する。"""
from __future__ import annotations

import base64
import gzip
import hashlib
import importlib.util
import sys
from pathlib import Path

import pytest
from extractors.purehvnc import extractor

ROOT = Path(__file__).resolve().parents[2]
COMMON = ROOT / "analysis-framework" / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

handler_result_quality = importlib.import_module("analysis_contract").handler_result_quality
_handler_evidence = importlib.import_module("handler_evidence")
confirmed_static_handler_iocs = _handler_evidence.confirmed_static_handler_iocs
static_config_recovered = _handler_evidence.static_config_recovered
summarize_handler_outputs = importlib.import_module("orchestration_outcome").summarize_handler_outputs

SPEC = importlib.util.spec_from_file_location(
    "purehvnc_managed_contract_handler",
    ROOT / "analysis-framework" / "malware" / "purehvnc" / "extract_config.py",
)
assert SPEC and SPEC.loader
HANDLER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HANDLER)
DATA = b"MZ harmless managed configuration contract fixture"
SHA256 = hashlib.sha256(DATA).hexdigest()
HOST = "contract.example.test"
PORTS = [56001, 56002, 56003]


def _varint(value: int) -> bytes:
    """fixture用protobuf integerを符号化する。"""
    result = bytearray()
    while value > 127:
        result.append((value & 127) | 128)
        value >>= 7
    result.append(value)
    return bytes(result)


def _field(number: int, value: bytes) -> bytes:
    """fixture用length-delimited fieldを符号化する。"""
    return _varint(number << 3 | 2) + _varint(len(value)) + value


def _encoded(host: str = HOST, ports: list[int] | None = None) -> str:
    """実行能力を持たないBase64／GZip／protobuf設定を生成する。"""
    message = _field(1, host.encode()) + _field(4, b"fixture-campaign") + _field(3, b"fixture-certificate")
    for port in PORTS if ports is None else ports:
        message += _varint(2 << 3) + _varint(port)
    return base64.b64encode(gzip.compress(message, mtime=0)).decode()


@pytest.fixture
def managed_strings(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """metadata取得だけを置換し、既存の厳密decoderと公開証明書shapeを検証する。"""
    values = [_encoded(), "4.4.1"]
    monkeypatch.setattr(extractor, "iter_dotnet_user_strings", lambda _data: iter(values))
    monkeypatch.setattr(extractor, "has_clr_metadata", lambda _data: False)
    monkeypatch.setattr(
        extractor,
        "certificate_metadata",
        lambda _value: {
            "pfx_sha256": "a" * 64,
            "certificate_sha256": "b" * 64,
            "subject": "CN=PureRAT Agent",
            "issuer": "CN=PureRAT Agent",
            "serial_number": 1,
            "not_before": "2026-01-01T00:00:00+00:00",
            "not_after": "2027-01-01T00:00:00+00:00",
        },
    )
    monkeypatch.setattr(
        HANDLER,
        "structural_summary",
        lambda _data: {"required_exports": [], "injection_imports": [], "xor55_pdf_resources": []},
    )
    return values


def _call(kind: str, data: bytes = DATA) -> dict:
    """両標準handlerへ同じ静的fixtureを渡す。"""
    return HANDLER.extract_config(data) if kind == "family" else extractor.extract(data, "fixture")


def _record(result: dict, *, corroborated: bool = True) -> dict:
    """独立detector由来の受理／拒否を持つnormalizer用recordを作る。"""
    return {
        "family": "purehvnc",
        "handler_id": "purehvnc:fixture:extract",
        "status": "corroborated",
        "source": "candidate_verification",
        "selected_layer_sha256": SHA256,
        "handler_evidence": handler_result_quality(result),
        "detector_corroboration": {
            "corroborated": corroborated,
            "basis": "detector_structural_evidence",
            "layer_sha256": SHA256,
            "lineage_distance": 0,
        },
        "result": {"result": result},
    }


@pytest.mark.parametrize("kind", ["family", "integrated"])
def test_strict_managed_recovery_has_standard_flags_and_correlated_endpoints(kind: str, managed_strings) -> None:
    """既存decoder成功を標準flagと同じhost／portの証跡へ欠落なく投影する。"""
    result = _call(kind)
    assert result["config"]["static_config_recovered"] is True
    assert result["config"]["decoded_config_recovered"] is True
    assert result["config"]["endpoints"] == [f"{HOST}:{port}" for port in PORTS]
    assert [item["value"] for item in result["findings"]] == result["config"]["endpoints"]
    assert all(item["role"] == "configured_c2" and item["source"] == "static_config" for item in result["findings"])
    assert {(item["host"], item["port"]) for item in result["c2"]} == {(HOST, port) for port in PORTS}
    assert all(item["confidence"] == "confirmed_static_configuration" for item in result["c2"])
    assert result["network_contacted"] is False
    assert result.get("executed", result.get("sample_executed")) is False
    summary = summarize_handler_outputs([_record(result)])
    assert summary["config_recovered"] is True
    assert {(item["host"], item["port"]) for item in summary["qualified_network_endpoints"]} == {(HOST, port) for port in PORTS}


@pytest.mark.parametrize("kind", ["family", "integrated"])
def test_publisher_recovers_three_static_c2_records_without_claiming_liveness(kind: str, managed_strings) -> None:
    """publisherの標準c2契約も同じ3endpointを採用し、稼働は確認済みにしない。"""
    result = _call(kind)
    evidence = handler_result_quality(result)
    handler_id = "purehvnc:fixture:extract"
    execution = {"handler_id": handler_id, "status": "succeeded", "selected_evidence": evidence, "selected_layer_sha256": SHA256}
    artifact = {
        "handler": {"id": handler_id, "family": "purehvnc"}, "result": result,
        "executed_sample": False, "network_contacted": False, "selected_evidence": evidence,
        "selected_layer": {"sha256": SHA256},
    }
    iocs = confirmed_static_handler_iocs([(execution, artifact)], family="purehvnc")
    assert {(item["host"], item["port"]) for item in iocs} == {(HOST, port) for port in PORTS}
    assert static_config_recovered([(execution, artifact)], iocs, family="purehvnc") is True
    assert all(item.get("liveness_confirmed") is not True and item.get("contacted") is not True for item in iocs)
    assert confirmed_static_handler_iocs([(execution, artifact)], family="other") == []
    assert static_config_recovered([(execution, artifact)], iocs, family="other") is False


@pytest.mark.parametrize("kind", ["family", "integrated"])
def test_managed_config_success_does_not_replace_independent_detector(kind: str, managed_strings) -> None:
    """標準flagとendpointだけでは独立detector拒否を迂回できない。"""
    result = _call(kind)
    summary = summarize_handler_outputs([_record(result, corroborated=False)])
    assert summary["config_recovered"] is False
    assert summary["qualified_network_endpoints"] == []
    assert HANDLER._DETECT_MODULE._managed_terminal_evidence(DATA)["matched"] is True
    result["config"]["certificate"]["subject"] = "CN=Generic Application"
    # 証明書anchorを別に検証する既存detectorの契約は変更しない。
    original = HANDLER._DETECT_MODULE.extract_managed_config
    try:
        HANDLER._DETECT_MODULE.extract_managed_config = lambda _data: result["config"]
        assert HANDLER._DETECT_MODULE._managed_terminal_evidence(DATA)["matched"] is False
    finally:
        HANDLER._DETECT_MODULE.extract_managed_config = original


@pytest.mark.parametrize("kind", ["family", "integrated"])
@pytest.mark.parametrize("failure", ["invalid_host", "duplicate_port", "conflict", "missing"])
def test_rejected_managed_config_never_sets_standard_recovery_flags(kind: str, failure: str, managed_strings) -> None:
    """未知・破損・相反設定を標準managed復元やC2へ昇格させない。"""
    if failure == "invalid_host":
        managed_strings[:] = [_encoded("single-label")]
    elif failure == "duplicate_port":
        managed_strings[:] = [_encoded(ports=[443, 443])]
    elif failure == "conflict":
        managed_strings[:] = [_encoded(), _encoded("other.example.test")]
    else:
        managed_strings[:] = []
    result = _call(kind)
    assert result["config"]["static_config_recovered"] is False
    assert result["config"]["decoded_config_recovered"] is False
    assert result["findings"] == []
    assert result["c2"] == []
    assert summarize_handler_outputs([_record(result)])["config_recovered"] is False


def test_native_candidate_does_not_gain_managed_config_confirmation(managed_strings) -> None:
    """native候補の既存findingは保持するが、今回の標準managed契約には採用しない。"""
    managed_strings[:] = []
    result = extractor.extract(b"10FX\0START_SCREEN\0" + b"192.0.2.10:443\0", "native-fixture")
    assert result["config"]["variant"] == "native_10fx"
    assert result["findings"]
    assert result["config"]["static_config_recovered"] is False
    assert result["config"]["decoded_config_recovered"] is False
    assert result["c2"] == []
