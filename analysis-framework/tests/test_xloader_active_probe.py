from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
MODULE_DIR = ROOT / "analysis-framework" / "malware" / "formbook_loader"


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


_load("native_xloader", MODULE_DIR / "native_xloader.py")
C2 = _load("xloader_c2", MODULE_DIR / "xloader_c2.py")
PROBE = _load("xloader_active_probe", MODULE_DIR / "xloader_active_probe.py")
EMULATOR = _load("xloader_emulator", MODULE_DIR / "xloader_emulator.py")


SELECTORS = (39, 50, 43, 47, 33, 40, 13, 59, 57, 28, 29, 54, 49, 4, 24, 15)
PATHS = (
    "/r79d/", "/sy4v/", "/yim2/", "/lieg/", "/s50d/", "/bvy8/",
    "/iir6/", "/70hw/", "/ue3i/", "/rjwn/", "/ievt/", "/tb8q/",
    "/ximu/", "/s3gf/", "/lsg7/", "/zqgn/",
)


def _fixture():
    host = "example.com"
    path = "/ximu/"
    inner_plaintext = (
        b"XLNG:00000000:8.9:Windows 10 x64:U1lOVEhFVElDXFVTRVI="
    )
    inner_plaintext_sha256 = hashlib.sha256(inner_plaintext).hexdigest()
    table = [
        {
            "slot": slot,
            "selector": selector,
            "path": item_path,
            "effective_host": host if slot == 12 else f"host{slot}.example.com",
        }
        for slot, (selector, item_path) in enumerate(zip(SELECTORS, PATHS))
    ]
    data = {
        "schema_version": 1,
        "sample_sha256": "a" * 64,
        "fully_recovered_image_sha256": "b" * 64,
        "candidate_index": 12,
        "selector": 49,
        "host": host,
        "http_path": path,
        "record_sha1": C2.derive_record_sha1(host, path).hex(),
        "selector_path_table": table,
        "identity_kind": "synthetic",
        "contains_real_victim_data": False,
        "synthetic_template_id": PROBE.SYNTHETIC_TEMPLATE_ID,
        "pkt2_inner_plaintext_sha256": inner_plaintext_sha256,
        "pkt2_wire_mode": "fixed_key_cancelled",
        "first_pkt2_rc4_key_base64": base64.b64encode(bytes(range(20))).decode(),
        "url_seed_base64": base64.b64encode(bytes(range(20, 40))).decode(),
        "pkt2_inner_plaintext_base64": base64.b64encode(inner_plaintext).decode(),
    }
    raw = json.dumps(
        data, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode()
    material = PROBE.PrivateMaterialEnvelope(data, hashlib.sha256(raw).hexdigest())
    pkt2 = C2.build_pkt2_packet(inner_plaintext, bytes(range(20)))
    encrypted = C2.encrypt_get_payload(
        pkt2,
        bytes.fromhex(data["record_sha1"]),
        bytes(range(20, 40)),
    ).decode("ascii")
    target = path + "?cd34=fixture&ab12=" + encrypted
    independent_wire = (
        "GET "
        + target
        + " HTTP/1.1\r\n"
        + "Host: example.com\r\n"
        + "User-Agent: Mozilla/5.0 XLoader local fixture\r\n"
        + "Accept: */*\r\n"
        + "Accept-Encoding: gzip, deflate, br\r\n"
        + "Connection: close\r\n\r\n"
    ).encode("ascii")
    request_sha256 = hashlib.sha256(independent_wire).hexdigest()
    profile = {
        "schema_version": 1,
        "profile_id": "xloader-fixture-reviewed-1",
        "handler": PROBE.HANDLER,
        "protocol": PROBE.PROTOCOL,
        "method": PROBE.METHOD,
        "reviewed": True,
        "review_id": "review-xloader-fixture-1",
        "candidate_classification": "reviewed_real_c2",
        "response_contract_evidence": "cross_version_v8_7_primary_research",
        "synthetic_template_id": data["synthetic_template_id"],
        "pkt2_inner_plaintext_sha256": inner_plaintext_sha256,
        "request_sha256": request_sha256,
        "sample_sha256": data["sample_sha256"],
        "fully_recovered_image_sha256": data["fully_recovered_image_sha256"],
        "private_material_sha256": material.sha256,
        "selector_path_table_sha256": PROBE.selector_path_table_sha256(table),
        "candidate_index": 12,
        "selector": 49,
        "host": host,
        "scheme": "http",
        "port": 80,
        "http_path": path,
        "record_sha1": data["record_sha1"],
        "transport": "raw_socket",
        "pinned_ips": ["93.184.216.34"],
        "maximum_request_count": 1,
        "maximum_request_bytes": PROBE.MAXIMUM_REQUEST_BYTES,
        "maximum_response_bytes": PROBE.MAXIMUM_RESPONSE_BYTES,
        "timeout_seconds": 2.0,
        "data_parameter_name": "ab12",
        "junk_parameter_name": "cd34",
        "junk_value": "fixture",
        "data_parameter_position": "last",
        "user_agent": "Mozilla/5.0 XLoader local fixture",
    }
    pins = {
        "expected_profile_sha256": PROBE.canonical_profile_sha256(profile),
        "expected_profile_registry_sha256": "c" * 64,
        "expected_private_material_sha256": material.sha256,
        "expected_selector_path_table_sha256": profile[
            "selector_path_table_sha256"
        ],
        "expected_synthetic_template_id": profile["synthetic_template_id"],
        "expected_pkt2_inner_plaintext_sha256": profile[
            "pkt2_inner_plaintext_sha256"
        ],
        "expected_request_sha256": profile["request_sha256"],
        "expected_review_id": profile["review_id"],
        "expected_profile_id": profile["profile_id"],
    }
    return profile, material, pins


def _approve(monkeypatch, profile):
    monkeypatch.setattr(
        PROBE,
        "_resolve_registry_profile",
        lambda profile_id, host, port, digest: dict(profile),
    )


def test_loopback_contract_uses_one_request_and_never_executes_task(monkeypatch) -> None:
    profile, material, pins = _fixture()
    _approve(monkeypatch, profile)
    emulator = EMULATOR.XLoaderLoopbackEmulator(material)
    result = PROBE.probe_reviewed_xloader_registration(
        profile,
        private_material=material,
        allow_network=True,
        allow_xloader_registration=True,
        sender=emulator,
        **pins,
    )
    assert emulator.request_count == 1
    assert emulator.last_request_evidence["accepted"] is True
    assert result["protocol_evidence"]["command_id"] == 9
    assert result["task_available"] is False
    assert result["task_executed"] is False
    assert result["payload_download_attempted"] is False
    assert result["request_count"] == 1
    assert result["network_contacted"] is False
    assert result["exact_binding"]["synthetic_template_id"] == (
        PROBE.SYNTHETIC_TEMPLATE_ID
    )
    assert result["exact_binding"]["pkt2_inner_plaintext_sha256"] == (
        "629e93de60e88a81a45bdf3f15107faad8bbd01ed58d610d69647a995e1e9353"
    )
    assert "XLNG:00000000" not in json.dumps(result)
    assert "U1lOVEhFVElDXFVTRVI=" not in json.dumps(result)


def test_both_gates_are_required() -> None:
    profile, material, pins = _fixture()
    emulator = EMULATOR.XLoaderLoopbackEmulator(material)
    assert PROBE.probe_reviewed_xloader_registration(
        profile, private_material=material, sender=emulator, **pins
    )["status"] == "network_disabled"
    assert PROBE.probe_reviewed_xloader_registration(
        profile,
        private_material=material,
        allow_network=True,
        sender=emulator,
        **pins,
    )["status"] == "xloader_registration_disabled"
    assert emulator.request_count == 0


def test_synthetic_wire_vector_is_frozen_independently() -> None:
    profile, material, pins = _fixture()
    first_key, url_seed, inner = PROBE._validate_profile(
        profile,
        material,
        expected_profile_sha256=pins["expected_profile_sha256"],
        expected_private_material_sha256=pins[
            "expected_private_material_sha256"
        ],
        expected_selector_path_table_sha256=pins[
            "expected_selector_path_table_sha256"
        ],
        expected_synthetic_template_id=pins[
            "expected_synthetic_template_id"
        ],
        expected_pkt2_inner_plaintext_sha256=pins[
            "expected_pkt2_inner_plaintext_sha256"
        ],
        expected_request_sha256=pins["expected_request_sha256"],
        expected_review_id=pins["expected_review_id"],
        expected_profile_id=pins["expected_profile_id"],
    )
    request = PROBE._build_request(profile, first_key, url_seed, inner)
    response = C2.encrypt_command_response(
        b"XLNG9",
        bytes.fromhex(profile["record_sha1"]),
        url_seed,
    )
    assert request.request_bytes == 280
    assert request.request_sha256 == (
        "e62e799ab52bfac7a066d2d3f512a61e7dd0e3494e97a1b73dccbcfbde39252b"
    )
    assert request.request_sha256 == profile["request_sha256"]
    assert material.data["pkt2_inner_plaintext_sha256"] == (
        "629e93de60e88a81a45bdf3f15107faad8bbd01ed58d610d69647a995e1e9353"
    )
    assert request.encrypted_payload_length == 104
    assert request.encrypted_payload_sha256 == (
        "da405f346f7757720468af1908bce1f3253c40468631898e53dbdbf29143d113"
    )
    assert request.target.startswith("/ximu/?cd34=fixture&ab12=")
    assert request.target.count("&") == 1
    assert len(response) == 8
    assert hashlib.sha256(response).hexdigest() == (
        "a2cf81c78b0a9306a8732041936edbe13ddd01f8fce936982a0032b6160a4cb5"
    )
    assert response == b"d791xus="


def test_request_hash_mismatch_is_rejected_before_sender(monkeypatch) -> None:
    profile, material, pins = _fixture()
    profile["request_sha256"] = "f" * 64
    pins["expected_request_sha256"] = profile["request_sha256"]
    pins["expected_profile_sha256"] = PROBE.canonical_profile_sha256(profile)
    _approve(monkeypatch, profile)

    def must_not_send(_profile, _request):
        pytest.fail("canonical GET hash mismatch must be rejected before sender")

    with pytest.raises(PROBE.XLoaderProbeError, match="GET request hash pin"):
        PROBE.probe_reviewed_xloader_registration(
            profile,
            private_material=material,
            allow_network=True,
            allow_xloader_registration=True,
            sender=must_not_send,
            **pins,
        )


def test_self_declared_non_synthetic_identity_is_rejected_before_sender(
    monkeypatch,
) -> None:
    profile, material, pins = _fixture()
    bad_inner = b"XLNG:00000000:8.9:Windows 10 x64:UkVBTFxVU0VS"
    bad_data = dict(material.data)
    bad_data["pkt2_inner_plaintext_base64"] = base64.b64encode(bad_inner).decode()
    bad_data["pkt2_inner_plaintext_sha256"] = hashlib.sha256(bad_inner).hexdigest()
    raw = json.dumps(
        bad_data,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    bad_material = PROBE.PrivateMaterialEnvelope(
        bad_data,
        hashlib.sha256(raw).hexdigest(),
    )
    profile["pkt2_inner_plaintext_sha256"] = bad_data[
        "pkt2_inner_plaintext_sha256"
    ]
    profile["private_material_sha256"] = bad_material.sha256
    pins["expected_private_material_sha256"] = bad_material.sha256
    pins["expected_pkt2_inner_plaintext_sha256"] = bad_data[
        "pkt2_inner_plaintext_sha256"
    ]
    pins["expected_profile_sha256"] = PROBE.canonical_profile_sha256(profile)
    _approve(monkeypatch, profile)

    def must_not_send(_profile, _request):
        pytest.fail("non-synthetic identity must be rejected before sender")

    with pytest.raises(PROBE.XLoaderProbeError, match="sentinel"):
        PROBE.probe_reviewed_xloader_registration(
            profile,
            private_material=bad_material,
            allow_network=True,
            allow_xloader_registration=True,
            sender=must_not_send,
            **pins,
        )


def test_bootstrap_candidate_needs_extra_gate_and_never_falls_back(
    monkeypatch,
) -> None:
    profile, material, pins = _fixture()
    profile["candidate_classification"] = "reviewed_initial_bootstrap_candidate"
    pins["expected_profile_sha256"] = PROBE.canonical_profile_sha256(profile)
    emulator = EMULATOR.XLoaderLoopbackEmulator(material)
    disabled = PROBE.probe_reviewed_xloader_registration(
        profile,
        private_material=material,
        allow_network=True,
        allow_xloader_registration=True,
        sender=emulator,
        **pins,
    )
    assert disabled["status"] == "xloader_candidate_check_disabled"
    assert disabled["request_count"] == 0
    assert emulator.request_count == 0
    _approve(monkeypatch, profile)
    result = PROBE.probe_reviewed_xloader_registration(
        profile,
        private_material=material,
        allow_network=True,
        allow_xloader_registration=True,
        allow_xloader_candidate_check=True,
        sender=emulator,
        **pins,
    )
    assert result["request_count"] == 1
    assert emulator.request_count == 1
    assert result["exact_binding"]["candidate_classification"] == (
        "reviewed_initial_bootstrap_candidate"
    )


def test_unresolved_real_decoy_state_is_rejected_before_sender(monkeypatch) -> None:
    profile, material, pins = _fixture()
    profile["candidate_classification"] = "real_c2_decoy_unresolved"
    pins["expected_profile_sha256"] = PROBE.canonical_profile_sha256(profile)
    _approve(monkeypatch, profile)
    emulator = EMULATOR.XLoaderLoopbackEmulator(material)
    with pytest.raises(PROBE.XLoaderProbeError):
        PROBE.probe_reviewed_xloader_registration(
            profile,
            private_material=material,
            allow_network=True,
            allow_xloader_registration=True,
            sender=emulator,
            **pins,
        )
    assert emulator.request_count == 0


def test_sender_cannot_bypass_ip_pin(monkeypatch) -> None:
    profile, material, pins = _fixture()
    _approve(monkeypatch, profile)

    def wrong_pin(_profile, _request):
        return PROBE.BoundedHttpResponse(
            200, "text/plain", b"", False, ("1.1.1.1",), "1.1.1.1"
        )

    with pytest.raises(PROBE.XLoaderProbeError, match="IP pin"):
        PROBE.probe_reviewed_xloader_registration(
            profile,
            private_material=material,
            allow_network=True,
            allow_xloader_registration=True,
            sender=wrong_pin,
            **pins,
        )


def test_sender_network_error_is_sanitized(monkeypatch) -> None:
    profile, material, pins = _fixture()
    _approve(monkeypatch, profile)

    def timeout(_profile, _request):
        raise TimeoutError("private detail")

    result = PROBE.probe_reviewed_xloader_registration(
        profile,
        private_material=material,
        allow_network=True,
        allow_xloader_registration=True,
        sender=timeout,
        **pins,
    )
    assert result["status"] == "xloader_v8_network_error"
    assert result["target_contact_attempted"] is True
    assert result["application_data_sent"] is False
    assert result["request_send_attempted"] is False
    assert result["request_count"] == 0
    assert result["transport_phase"] == "injected_sender_unknown"
    assert result["transport_state_known"] is False
    assert result["error_type"] == "TimeoutError"
    assert "private detail" not in json.dumps(result)


def test_connect_timeout_records_no_connection_or_request(monkeypatch) -> None:
    profile, material, pins = _fixture()
    _approve(monkeypatch, profile)
    monkeypatch.setattr(
        PROBE,
        "_resolve_and_pin",
        lambda *_args, **_kwargs: (("93.184.216.34",), "93.184.216.34"),
    )

    class ConnectTimeout:
        def __init__(self, _host, _port, *, timeout):
            assert timeout == profile["timeout_seconds"]

        def connect(self):
            raise TimeoutError("connect private detail")

        def close(self):
            return None

    monkeypatch.setattr(PROBE.http.client, "HTTPConnection", ConnectTimeout)
    result = PROBE.probe_reviewed_xloader_registration(
        profile,
        private_material=material,
        allow_network=True,
        allow_xloader_registration=True,
        **pins,
    )
    assert result["status"] == "xloader_v8_network_error"
    assert result["transport_phase"] == "connect"
    assert result["target_connection_established"] is False
    assert result["request_send_attempted"] is False
    assert result["application_data_sent"] is False
    assert result["request_attempt_count"] == 0
    assert result["request_count"] == 0
    assert result["partial_send_possible"] is False
    assert result["connected_ip"] is None
    assert result["error_type"] == "TimeoutError"
    assert "connect private detail" not in json.dumps(result)


def test_timeout_after_request_send_records_one_request(monkeypatch) -> None:
    profile, material, pins = _fixture()
    _approve(monkeypatch, profile)
    monkeypatch.setattr(
        PROBE,
        "_resolve_and_pin",
        lambda *_args, **_kwargs: (("93.184.216.34",), "93.184.216.34"),
    )

    class ResponseTimeout:
        def __init__(self, _host, _port, *, timeout):
            assert timeout == profile["timeout_seconds"]

        def connect(self):
            return None

        def putrequest(self, *_args, **_kwargs):
            return None

        def putheader(self, *_args, **_kwargs):
            return None

        def endheaders(self):
            return None

        def getresponse(self):
            raise TimeoutError("response private detail")

        def close(self):
            return None

    monkeypatch.setattr(PROBE.http.client, "HTTPConnection", ResponseTimeout)
    result = PROBE.probe_reviewed_xloader_registration(
        profile,
        private_material=material,
        allow_network=True,
        allow_xloader_registration=True,
        **pins,
    )
    assert result["status"] == "xloader_v8_network_error"
    assert result["transport_phase"] == "receive_response_headers"
    assert result["target_connection_established"] is True
    assert result["request_send_attempted"] is True
    assert result["application_data_sent"] is True
    assert result["synthetic_identity_sent"] is True
    assert result["request_attempt_count"] == 1
    assert result["request_count"] == 1
    assert result["partial_send_possible"] is False
    assert result["connected_ip"] == "93.184.216.34"
    assert result["error_type"] == "TimeoutError"
    assert "response private detail" not in json.dumps(result)


def test_timeout_during_endheaders_marks_partial_send_possible(monkeypatch) -> None:
    profile, material, pins = _fixture()
    _approve(monkeypatch, profile)
    monkeypatch.setattr(
        PROBE,
        "_resolve_and_pin",
        lambda *_args, **_kwargs: (("93.184.216.34",), "93.184.216.34"),
    )

    class SendTimeout:
        def __init__(self, _host, _port, *, timeout):
            assert timeout == profile["timeout_seconds"]

        def connect(self):
            return None

        def putrequest(self, *_args, **_kwargs):
            return None

        def putheader(self, *_args, **_kwargs):
            return None

        def endheaders(self):
            raise TimeoutError("send private detail")

        def close(self):
            return None

    monkeypatch.setattr(PROBE.http.client, "HTTPConnection", SendTimeout)
    result = PROBE.probe_reviewed_xloader_registration(
        profile,
        private_material=material,
        allow_network=True,
        allow_xloader_registration=True,
        **pins,
    )
    assert result["transport_phase"] == "send_request"
    assert result["target_connection_established"] is True
    assert result["request_send_attempted"] is True
    assert result["application_data_sent"] is False
    assert result["request_attempt_count"] == 1
    assert result["request_count"] == 0
    assert result["partial_send_possible"] is True
    assert "send private detail" not in json.dumps(result)


def test_profile_id_acknowledgement_is_required(monkeypatch) -> None:
    profile, material, pins = _fixture()
    _approve(monkeypatch, profile)
    pins["expected_profile_id"] = "xloader-different-profile"
    with pytest.raises(PROBE.XLoaderProbeError, match="profile ID"):
        PROBE.probe_reviewed_xloader_registration(
            profile,
            private_material=material,
            allow_network=True,
            allow_xloader_registration=True,
            sender=EMULATOR.XLoaderLoopbackEmulator(material),
            **pins,
        )
