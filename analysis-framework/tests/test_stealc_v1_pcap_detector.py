"""StealC v1 PCAP offline detectorの証拠bindingとflow境界を検証する。"""

from __future__ import annotations

import hashlib
import importlib.util
import io
import subprocess
import sys
from pathlib import Path

import pytest

COMMON_PATH = Path(__file__).parents[1] / "common"
if str(COMMON_PATH) not in sys.path:
    sys.path.insert(0, str(COMMON_PATH))

from immutable_snapshot import SnapshotIdentity

MODULE_PATH = Path(__file__).parents[1] / "malware" / "stealc" / "v1_pcap_detector.py"
SPEC = importlib.util.spec_from_file_location("stealc_v1_pcap_detector", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


ROOT = "a" * 64
PCAP_SHA = "b" * 64
MANIFEST_SHA = "c" * 64
CONFIG_SHA = "d" * 64
TERMINAL_SHA = "e" * 64
REVIEW_ID = "stealc-v1-fixture"
REGISTRY_SOURCE = "analysis-framework/malware/stealc/v1_pcap_review_registry.json"
REGISTRY_SHA = "f" * 64


def row(**values: str) -> str:
    return "\t".join(values.get(field, "") for field in MODULE.TSHARK_FIELDS)


def request_row(
    *,
    frame: str = "10",
    stream: str = "7",
    source_ip: str = "10.0.0.2",
    source_port: str = "49152",
    destination_ip: str = "192.0.2.10",
    destination_port: str = "80",
    host: str = "192.0.2.10",
    path: str = "/gate.php",
    response_in: str = "",
) -> str:
    return row(
        **{
            "frame.number": frame,
            "tcp.stream": stream,
            "ip.src": source_ip,
            "tcp.srcport": source_port,
            "ip.dst": destination_ip,
            "tcp.dstport": destination_port,
            "http.request.method": "POST",
            "http.host": host,
            "http.request.uri": path,
            "http.content_type": "multipart/form-data; boundary=x",
            "http.content_length": "211",
            "mime_multipart.header.content-disposition": ('form-data; name="hwid"|form-data; name="build"'),
            "http.response_in": response_in,
        }
    )


def response_row(
    *,
    frame: str = "11",
    stream: str = "7",
    source_ip: str = "192.0.2.10",
    source_port: str = "80",
    destination_ip: str = "10.0.0.2",
    destination_port: str = "49152",
    request_in: str = "10",
    body_hex: str = b"YmxvY2s=".hex(),
    content_length: str = "8",
    response_code: str = "200",
) -> str:
    return row(
        **{
            "frame.number": frame,
            "tcp.stream": stream,
            "ip.src": source_ip,
            "tcp.srcport": source_port,
            "ip.dst": destination_ip,
            "tcp.dstport": destination_port,
            "http.content_type": "text/html; charset=UTF-8",
            "http.response.code": response_code,
            "http.content_length": content_length,
            "http.file_data": body_hex,
            "http.request_in": request_in,
        }
    )


def review(**overrides: str) -> object:
    values = {
        "review_id": REVIEW_ID,
        "root_sample_sha256": ROOT,
        "static_config_sha256": CONFIG_SHA,
        "terminal_payload_sha256": TERMINAL_SHA,
        "endpoint": "http://192.0.2.10/gate.php",
        "evidence_manifest_sha256": MANIFEST_SHA,
        "pcap_sha256": PCAP_SHA,
        "triage_sample_id": "241015-fixture",
        "triage_task_id": "behavioral1",
        "capture_started_at_utc": "2024-10-15T06:47:12Z",
        "pcap_file_name": "fixture.pcapng",
    }
    values.update(overrides)
    return MODULE.StealCPCAPReview(**values)


def binding() -> object:
    return MODULE.EvidenceBinding(
        root_sample_sha256=ROOT,
        triage_sample_id="241015-fixture",
        triage_task_id="behavioral1",
        pcap_sha256=PCAP_SHA,
        pcap_file_name="fixture.pcapng",
        capture_started_at_utc="2024-10-15T06:47:12Z",
        manifest_sha256=MANIFEST_SHA,
        static_config_sha256=CONFIG_SHA,
        terminal_payload_sha256=TERMINAL_SHA,
        review_id=REVIEW_ID,
        review_registry_source=REGISTRY_SOURCE,
        review_registry_sha256=REGISTRY_SHA,
    )


def snapshot(tmp_path: Path) -> object:
    path = tmp_path / "immutable.pcapng"
    data = b"pcap-fixture"
    path.write_bytes(data)
    identity = SnapshotIdentity(
        size=len(data),
        sha256=hashlib.sha256(data).hexdigest(),
        device=1,
        inode=2,
        modified_ns=3,
        link_count=1,
    )
    return MODULE.FileSnapshot(path=path, identity=identity)


def report_for(tmp_path: Path, text: str, endpoint: str = "http://192.0.2.10/gate.php") -> dict:
    requests, responses = MODULE.parse_tshark_rows(text)
    return MODULE.build_report(
        snapshot(tmp_path),
        requests,
        responses,
        endpoint=MODULE.canonicalize_expected_endpoint(endpoint),
        binding=binding(),
    )


def manifest() -> dict:
    return {
        "schema_version": 1,
        "root_sample_sha256": ROOT,
        "captures": [
            {
                "sample_id": "241015-fixture",
                "task_id": "behavioral1",
                "pcap": {
                    "sha256": PCAP_SHA,
                    "file_name": "fixture.pcapng",
                    "capture_started_at_utc": "2024-10-15T06:47:12Z",
                },
            }
        ],
    }


def test_exact_flow_and_block_are_historical_high_not_live_confirmed(tmp_path: Path) -> None:
    result = report_for(tmp_path, request_row() + "\n" + response_row())
    assert result["assessment"]["state"] == "historical_high_confidence_protocol_match"
    assert result["assessment"]["confidence"] == "high"
    assert result["assessment"]["current_liveness_verified"] is False
    assert result["assessment"]["active_probe_status"] == "protocol_profile_required"
    assert result["evidence_binding"]["root_sample_sha256"] == ROOT


def test_ip_literal_requires_destination_ip_not_host_only(tmp_path: Path) -> None:
    text = request_row(destination_ip="198.51.100.9", host="192.0.2.10") + "\n" + response_row(source_ip="198.51.100.9")
    result = report_for(tmp_path, text)
    assert result["assessment"]["state"] == "historical_protocol_compatible"
    assert result["matches"][0]["expected_endpoint_match"] is False


def test_ip_literal_requires_matching_host_header(tmp_path: Path) -> None:
    result = report_for(
        tmp_path,
        request_row(host="198.51.100.9") + "\n" + response_row(),
    )
    assert result["assessment"]["state"] == "historical_protocol_compatible"
    assert result["matches"][0]["expected_endpoint_match"] is False


def test_separate_tcp_stream_cannot_pair(tmp_path: Path) -> None:
    result = report_for(tmp_path, request_row() + "\n" + response_row(stream="8"))
    assert result["assessment"]["state"] == "no_stealc_v1_protocol_match"


def test_wrong_reverse_four_tuple_cannot_pair(tmp_path: Path) -> None:
    result = report_for(
        tmp_path,
        request_row() + "\n" + response_row(destination_port="49153"),
    )
    assert result["matches"] == []


def test_two_requests_one_response_is_not_reused(tmp_path: Path) -> None:
    text = "\n".join(
        [
            request_row(frame="10"),
            request_row(frame="11"),
            response_row(frame="12", request_in="11"),
        ]
    )
    result = report_for(tmp_path, text)
    assert len(result["matches"]) == 1
    assert result["matches"][0]["request"]["frame"] == 11
    assert result["matches"][0]["response_reused"] is False


def test_pipelining_interleave_with_conflicting_response_in_is_rejected(tmp_path: Path) -> None:
    text = "\n".join(
        [
            request_row(frame="10", response_in="13"),
            request_row(frame="11", response_in="12"),
            response_row(frame="12", request_in="10"),
            response_row(frame="13", request_in="11"),
        ]
    )
    result = report_for(tmp_path, text)
    assert result["matches"] == []


def test_body_validation_failures_never_classify_control(tmp_path: Path) -> None:
    cases = [
        response_row(body_hex="zz", content_length="1"),
        response_row(body_hex="abc", content_length="2"),
        response_row(body_hex="41" * 257, content_length="257"),
        response_row(body_hex=b"YmxvY2s=".hex(), content_length="7"),
        response_row(body_hex=b"YmxvY2s=".hex() + "|" + b"YmxvY2s=".hex()),
        response_row(response_code="200|200"),
    ]
    for index, response in enumerate(cases):
        case_dir = tmp_path / str(index)
        case_dir.mkdir()
        result = report_for(case_dir, request_row() + "\n" + response)
        assert result["assessment"]["confidence"] != "high"
        assert not any(item["known_control_response"] for item in result["matches"])


def test_ipv6_endpoint_requires_exact_destination_literal(tmp_path: Path) -> None:
    request = request_row().split("\t")
    request[MODULE.FIELD_INDEX["ip.dst"]] = ""
    request[MODULE.FIELD_INDEX["ipv6.dst"]] = "2001:db8::10"
    request[MODULE.FIELD_INDEX["http.host"]] = "[2001:db8::10]"
    response = response_row().split("\t")
    response[MODULE.FIELD_INDEX["ip.src"]] = ""
    response[MODULE.FIELD_INDEX["ipv6.src"]] = "2001:db8::10"
    result = report_for(
        tmp_path,
        "\t".join(request) + "\n" + "\t".join(response),
        "http://[2001:db8::10]/gate.php",
    )
    assert result["assessment"]["confidence"] == "high"


def test_manifest_binding_requires_exact_root_sample_task_and_pcap() -> None:
    result = MODULE.load_evidence_binding(
        manifest(),
        manifest_sha256=MANIFEST_SHA,
        review=review(),
        review_registry_source=REGISTRY_SOURCE,
        review_registry_sha256=REGISTRY_SHA,
    )
    assert result.pcap_sha256 == PCAP_SHA
    assert result.review_id == REVIEW_ID
    assert result.review_registry_sha256 == REGISTRY_SHA


def test_manifest_binding_rejects_review_mismatch_and_fabrication() -> None:
    with pytest.raises(ValueError, match="review pin"):
        MODULE.load_evidence_binding(
            manifest(),
            manifest_sha256=MANIFEST_SHA,
            review=review(evidence_manifest_sha256="0" * 64),
            review_registry_source=REGISTRY_SOURCE,
            review_registry_sha256=REGISTRY_SHA,
        )
    fabricated = manifest()
    fabricated["root_sample_sha256"] = "1" * 64
    fabricated["captures"][0]["pcap"]["sha256"] = "2" * 64
    with pytest.raises(ValueError, match="review sample"):
        MODULE.load_evidence_binding(
            fabricated,
            manifest_sha256=MANIFEST_SHA,
            review=review(),
            review_registry_source=REGISTRY_SOURCE,
            review_registry_sha256=REGISTRY_SHA,
        )


def test_manifest_capture_identity_must_match_review() -> None:
    payload = manifest()
    payload["captures"][0]["pcap"]["capture_started_at_utc"] = "2024-10-16T00:00:00Z"
    with pytest.raises(ValueError, match="capture identity"):
        MODULE.load_evidence_binding(
            payload,
            manifest_sha256=MANIFEST_SHA,
            review=review(),
            review_registry_source=REGISTRY_SOURCE,
            review_registry_sha256=REGISTRY_SHA,
        )


def test_expected_endpoint_rejects_ambiguous_components() -> None:
    for value in (
        "http://user:pass@192.0.2.10/gate.php",
        "http://192.0.2.10/gate.php?x=1",
        "http://192.0.2.10/gate.php#x",
    ):
        with pytest.raises(ValueError):
            MODULE.canonicalize_expected_endpoint(value)


class FakeProcess:
    """run_tsharkのbounded process制御を再現する最小fake。"""

    def __init__(self, stdout: bytes, stderr: bytes, outcome: int | Exception):
        self.stdout = io.BytesIO(stdout)
        self.stderr = io.BytesIO(stderr)
        self.outcome = outcome
        self.killed = False

    def wait(self, timeout: int | None = None) -> int:
        del timeout
        if self.killed:
            return -9
        if isinstance(self.outcome, Exception):
            raise self.outcome
        return self.outcome

    def kill(self) -> None:
        self.killed = True


def test_tshark_nonzero_exit_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeProcess(b"", b"decoder failed", 2)
    monkeypatch.setattr(MODULE.subprocess, "Popen", lambda *args, **kwargs: fake)
    with pytest.raises(RuntimeError, match="途中終了"):
        MODULE.run_tshark(Path("snapshot.pcapng"), Path("tshark"))


def test_tshark_timeout_kills_process(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeProcess(
        b"",
        b"",
        subprocess.TimeoutExpired(cmd="tshark", timeout=120),
    )
    monkeypatch.setattr(MODULE.subprocess, "Popen", lambda *args, **kwargs: fake)
    with pytest.raises(TimeoutError, match="timeout"):
        MODULE.run_tshark(Path("snapshot.pcapng"), Path("tshark"))
    assert fake.killed is True


def test_tshark_streaming_cap_kills_process(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeProcess(b"12345", b"", 0)
    monkeypatch.setattr(MODULE, "MAX_TSHARK_OUTPUT", 4)
    monkeypatch.setattr(MODULE.subprocess, "Popen", lambda *args, **kwargs: fake)
    with pytest.raises(ValueError, match="上限"):
        MODULE.run_tshark(Path("snapshot.pcapng"), Path("tshark"))
    assert fake.killed is True


def test_report_removes_victim_network_identifiers(tmp_path: Path) -> None:
    result = report_for(tmp_path, request_row() + "\n" + response_row())
    match = result["matches"][0]
    assert "source_ip" not in match["request"]
    assert "source_port" not in match["request"]
    assert "destination_ip" not in match["response"]
    assert "destination_port" not in match["response"]
    assert result["privacy"]["victim_network_identifiers_retained"] is False
    assert "10.0.0.2" not in str(result)
    assert "49152" not in str(result)


def test_domain_host_header_only_never_reaches_high_confidence(tmp_path: Path) -> None:
    result = report_for(
        tmp_path,
        request_row(host="c2.example") + "\n" + response_row(),
        "http://c2.example/gate.php",
    )
    assert result["matches"][0]["expected_endpoint_match"] is True
    assert result["assessment"]["confidence"] == "medium"


@pytest.mark.parametrize("bad_port", ["0", "65536", "999999"])
def test_invalid_transport_ports_are_fail_closed(tmp_path: Path, bad_port: str) -> None:
    result = report_for(
        tmp_path,
        request_row(destination_port=bad_port) + "\n" + response_row(source_port=bad_port),
    )
    assert result["matches"] == []


def test_static_config_binds_root_terminal_and_endpoint() -> None:
    payload = {
        "schema_version": 2,
        "family": "stealc",
        "sample_sha256": ROOT,
        "config": {
            "terminal_payload_sha256": TERMINAL_SHA,
            "profile": {"c2_url": "http://192.0.2.10/gate.php"},
        },
    }
    endpoint, terminal = MODULE.load_static_config_binding(
        payload,
        config_sha256=CONFIG_SHA,
        review=review(),
    )
    assert endpoint.canonical_url == "http://192.0.2.10/gate.php"
    assert terminal == TERMINAL_SHA
    payload["sample_sha256"] = "f" * 64
    with pytest.raises(ValueError, match="sample"):
        MODULE.load_static_config_binding(
            payload,
            config_sha256=CONFIG_SHA,
            review=review(),
        )


def test_expected_endpoint_rejects_port_zero() -> None:
    with pytest.raises(ValueError):
        MODULE.canonicalize_expected_endpoint("http://192.0.2.10:0/gate.php")


def test_production_cli_accepts_review_id_not_self_attested_pins() -> None:
    parser = MODULE.build_argument_parser()
    option_names = {option for action in parser._actions for option in action.option_strings}
    assert "--review-id" in option_names
    for forbidden in (
        "--sample-sha256",
        "--expected-pcap-sha256",
        "--expected-manifest-sha256",
        "--expected-config-sha256",
        "--triage-sample-id",
        "--triage-task-id",
        "--registry",
        "--registry-sha256",
    ):
        assert forbidden not in option_names


def test_static_config_cannot_self_attest_fabricated_evidence() -> None:
    payload = {
        "schema_version": 2,
        "family": "stealc",
        "sample_sha256": "1" * 64,
        "config": {
            "terminal_payload_sha256": "2" * 64,
            "profile": {"c2_url": "http://198.51.100.9/fake.php"},
        },
    }
    with pytest.raises(ValueError, match="review pin"):
        MODULE.load_static_config_binding(
            payload,
            config_sha256="3" * 64,
            review=review(),
        )
