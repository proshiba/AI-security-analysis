from __future__ import annotations

import importlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

FRAMEWORK = Path(__file__).resolve().parents[1]
if str(FRAMEWORK) not in sys.path:
    sys.path.insert(0, str(FRAMEWORK))

detector = importlib.import_module("nmap.nmap_c2_detector")


def _xml(script: str, fields: dict[str, object], *, port_state: str = "open") -> bytes:
    elements = "".join(
        f'<elem key="{key}">{str(value).lower() if isinstance(value, bool) else value}</elem>'
        for key, value in fields.items()
    )
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<nmaprun scanner="nmap" version="7.99">'
        '<host><address addr="127.0.0.1" addrtype="ipv4"/>'
        f'<ports><port protocol="tcp" portid="1"><state state="{port_state}"/>'
        f'<script id="{Path(script).stem}" output="fixture"><table>{elements}</table></script>'
        "</port></ports></host></nmaprun>"
    ).encode()


def _target(method: str, profile_id: str | None = None) -> dict[str, object]:
    value: dict[str, object] = {
        "target_id": "loopback",
        "family": "unknown",
        "host": "127.0.0.1",
        "port": 4444,
        "protocol": "tcp",
        "method": method,
        "timeout_seconds": 1.0,
        "maximum_response_bytes": 256,
        "transport": "direct",
    }
    if profile_id:
        value["protocol_profile_id"] = profile_id
    return value


def test_method_coverage_matches_machine_readable_registry() -> None:
    profile_map = json.loads((FRAMEWORK / "nmap" / "profiles.json").read_text(encoding="utf-8"))
    declared = {entry["method"]: entry for entry in profile_map["method_bindings"]}
    runtime = detector.nmap_method_coverage()
    assert runtime["execution_backend"] == "nmap_nse_only"
    assert runtime["method_count"] == 20
    assert set(runtime["methods"]) == set(declared)
    assert set(runtime["passive_only_application_methods"]) == {
        "formbook_reviewed_route_head",
        "xloader_v8_get_registration",
    }
    assert not set(runtime["passive_only_application_methods"]) & set(runtime["methods"])
    for method, binding in runtime["methods"].items():
        assert f"scripts/{binding['script']}" == declared[method]["script"]
        assert (FRAMEWORK / "nmap" / declared[method]["script"]).is_file()


def test_args_file_quotes_values_and_rejects_control_characters() -> None:
    rendered = detector.render_script_args({"agenttesla.user": "analyst@example.test", "agenttesla.pass": 'a"b\\c'})
    assert 'agenttesla.pass="a\\"b\\\\c"' in rendered
    assert "\n" not in rendered.rstrip("\n")
    with pytest.raises(detector.NmapC2Error):
        detector.render_script_args({"agenttesla.user": "bad\r\nvalue"})


def test_network_gate_returns_without_resolving_nmap() -> None:
    called = False

    def forbidden(*_args, **_kwargs):
        nonlocal called
        called = True
        raise AssertionError("executor must not run")

    result = detector.probe_target_with_nmap(
        _target("tcp_connect"),
        allow_network=False,
        executor=forbidden,
    )
    assert result["status"] == "network_disabled"
    assert result["execution_engine"] == "nmap_nse"
    assert result["target_contact_attempted"] is False
    assert called is False


@pytest.mark.parametrize(
    ("method", "family"),
    [
        ("formbook_reviewed_route_head", "unknown"),
        ("xloader_v8_get_registration", "unknown"),
        ("http_get", "formbook"),
        ("http_get", "formbook-stealer"),
        ("http_get", "xloader"),
        ("http_get", "guloader-xloader-payload"),
    ],
)
def test_passive_only_application_probes_ignore_all_enabling_gates(
    method: str,
    family: str,
) -> None:
    called = False

    def forbidden(*_args, **_kwargs):
        nonlocal called
        called = True
        raise AssertionError("executor must not run")

    target = _target(method)
    target["family"] = family
    if method == "http_get":
        target.update(
            {
                "protocol": "https",
                "http_host": "example.invalid",
                "http_path": "/known-route/",
            }
        )
    result = detector.probe_target_with_nmap(
        target,
        allow_network=True,
        allow_application_probes=True,
        allow_authentication=True,
        allow_malware_registration=True,
        allow_reviewed_checkconnect=True,
        allow_xloader_registration=True,
        executor=forbidden,
    )
    assert result["status"] == "passive_only_application_probe_blocked"
    assert result["passive_only_policy_enforced"] is True
    assert result["blocked_method"] == method
    assert result["target_contact_attempted"] is False
    assert result["application_data_sent"] is False
    assert result["request_count"] == 0
    assert result["sent_bytes"] == 0
    assert result["c2_confirmed"] is False
    assert result["probable_c2"] is False
    assert result["c2_confirmation_independent_evidence_required"] == 4
    assert result["c2_confirmation_independent_evidence_observed"] == 0
    assert len(result["c2_confirmation_missing_evidence_classes"]) == 4
    assert called is False


@pytest.mark.parametrize(
    ("family", "method", "protocol", "status"),
    [
        ("formbook", "tcp_connect", "tcp", "tcp_open_only"),
        ("xloader", "tls_handshake", "tls", "tls_handshake_observed"),
        ("formbook", "passive_banner", "tcp", "server_first_banner_observed"),
    ],
)
def test_passive_only_transport_and_receive_only_methods_remain_available(
    family: str,
    method: str,
    protocol: str,
    status: str,
) -> None:
    called = False

    def fake_executor(command, **_kwargs):
        nonlocal called
        called = True
        return subprocess.CompletedProcess(
            command,
            0,
            _xml(
                "c2-transport-observe.nse",
                {
                    "family": "unclassified",
                    "status": status,
                    "target_connection_established": True,
                    "application_data_sent": False,
                    "sent_bytes": 0,
                    "received_bytes": 8 if method == "passive_banner" else 0,
                },
            ),
            b"",
        )

    target = _target(method)
    target.update({"family": family, "protocol": protocol})
    result = detector.probe_target_with_nmap(
        target,
        allow_network=True,
        nmap_executable=sys.executable,
        executor=fake_executor,
    )
    assert called is True
    assert result["target_contact_attempted"] is True
    assert result["target_connection_established"] is True
    assert result["application_data_sent"] is False
    assert result["sent_bytes"] == 0
    assert result["c2_confirmed"] is False
    assert result["probable_c2"] is False
    assert result["open_port_is_c2_confirmation"] is False
    assert result["c2_confirmation_independent_evidence_required"] == 4
    assert result["c2_confirmation_independent_evidence_observed"] == 0


def test_generic_tls_observation_preserves_valid_sha1_and_sha256() -> None:
    sha1 = "7f1ed4a13d8a2ba6e690ecaf66a9dfa42dd8d9d1"
    sha256 = "a" * 64

    def fake_executor(command, **_kwargs):
        return subprocess.CompletedProcess(
            command,
            0,
            _xml(
                "c2-transport-observe.nse",
                {
                    "family": "unclassified",
                    "protocol": "tls_transport_only",
                    "status": "tls_handshake_observed",
                    "certificate_sha1": sha1.upper(),
                    "certificate_sha256": sha256.upper(),
                    "target_connection_established": True,
                    "application_data_sent": False,
                },
            ),
            b"",
        )

    result = detector.probe_target_with_nmap(
        _target("tls_handshake"),
        allow_network=True,
        nmap_executable=sys.executable,
        executor=fake_executor,
    )
    assert result["tls"]["certificate"]["observed_sha1"] == sha1
    assert result["tls"]["certificate"]["observed_sha256"] == sha256
    assert result["application_data_sent"] is False
    assert result["c2_confirmed"] is False


def test_generic_tls_can_passively_validate_n520_without_application_data() -> None:
    captured: dict[str, object] = {}

    def fake_executor(command, **_kwargs):
        captured["command"] = command
        args_path = Path(command[command.index("--script-args-file") + 1])
        captured["args"] = args_path.read_text(encoding="utf-8")
        return subprocess.CompletedProcess(
            command,
            0,
            _xml(
                "c2-transport-observe.nse",
                {
                    "family": "valleyrat",
                    "protocol": "tls_transport_only",
                    "status": "n520_server_first_handshake_match",
                    "probable_c2": True,
                    "c2_confirmed": False,
                    "confidence": "0.90",
                    "received_bytes": 44,
                    "sent_bytes": 0,
                    "request_count": 0,
                    "magic_matches": True,
                    "crc_matches": True,
                    "response_printable_ascii": False,
                    "response_sha256": "b" * 64,
                    "application_data_sent": False,
                },
            ),
            b"",
        )

    legacy = {
        "host": "127.0.0.1",
        "port": 443,
        "protocol": "tls",
        "family": "valleyrat",
        "observe_n520_server_first": True,
        "timeout_seconds": 1.0,
    }
    target = detector.normalize_legacy_target(legacy)
    result = detector.probe_target_with_nmap(
        target,
        allow_network=True,
        nmap_executable=sys.executable,
        executor=fake_executor,
    )
    assert 'c2-transport.observe-n520-server-first="true"' in str(captured["args"])
    assert result["status"] == "n520_server_first_handshake_match"
    assert result["probable_c2"] is True
    assert result["c2_confirmed"] is False
    assert result["application_data_sent"] is False
    assert result["sent_bytes"] == 0
    assert result["request_count"] == 0
    assert result["response_sha256"] == "b" * 64


def test_n520_server_first_generic_observation_rejects_non_tls() -> None:
    with pytest.raises(detector.NmapC2Error):
        detector.normalize_legacy_target(
            {
                "host": "127.0.0.1",
                "port": 80,
                "protocol": "tcp",
                "observe_n520_server_first": True,
            }
        )


def test_invalid_response_sha256_is_not_published() -> None:
    def fake_executor(command, **_kwargs):
        return subprocess.CompletedProcess(
            command,
            0,
            _xml(
                "c2-transport-observe.nse",
                {
                    "status": "tls_server_first_timeout_marker",
                    "response_sha256": "not-a-sha256",
                    "received_bytes": 7,
                    "application_data_sent": False,
                },
            ),
            b"",
        )

    result = detector.probe_target_with_nmap(
        _target("tls_handshake"),
        allow_network=True,
        nmap_executable=sys.executable,
        executor=fake_executor,
    )
    assert "response_sha256" not in result


def test_generic_tls_observation_drops_invalid_certificate_digests() -> None:
    def fake_executor(command, **_kwargs):
        return subprocess.CompletedProcess(
            command,
            0,
            _xml(
                "c2-transport-observe.nse",
                {
                    "family": "unclassified",
                    "status": "tls_handshake_observed",
                    "certificate_sha1": "not-a-sha1",
                    "certificate_sha256": "not-a-sha256",
                },
            ),
            b"",
        )

    result = detector.probe_target_with_nmap(
        _target("tls_handshake"),
        allow_network=True,
        nmap_executable=sys.executable,
        executor=fake_executor,
    )
    assert "certificate_sha1" not in result
    assert "certificate_sha256" not in result
    assert "tls" not in result


def test_executor_receives_only_args_file_path_not_ftp_secret(tmp_path: Path) -> None:
    profile_id = "agenttesla-ftp-auth-3f091457-vilimorin"
    target = {
        **_target("ftp_authenticated", profile_id),
        "family": "agenttesla",
        "host": "ftp.vilimorin.com",
        "port": 21,
        "protocol": "ftp",
    }
    vault = tmp_path / "vault.json"
    vault.write_text(
        json.dumps(
            {
                "classification": "sensitive_local_only",
                "records": [
                    {
                        "credential_id": "agenttesla:987bed1a8e0a44a6a34d3193cbb1f782c45d51419a317e55f086d8de0748d018:ftp:0",
                        "protocol": "ftp",
                        "endpoint": "ftp.vilimorin.com:21",
                        "username": "private-user",
                        "password": "private-pass",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    captured: dict[str, object] = {}

    def fake_executor(command, **_kwargs):
        captured["command"] = command
        args_path = Path(command[command.index("--script-args-file") + 1])
        captured["args"] = args_path.read_text(encoding="utf-8")
        return subprocess.CompletedProcess(
            command,
            0,
            _xml(
                "agenttesla-ftp-c2.nse",
                {
                    "family": "agenttesla",
                    "protocol": "ftp",
                    "status": "sample_credential_ftp_login_succeeded",
                    "c2_confirmed": True,
                    "confidence": "0.95",
                    "authentication_attempted": True,
                    "file_operation_attempted": False,
                },
            ),
            b"",
        )

    result = detector.probe_target_with_nmap(
        target,
        allow_network=True,
        allow_authentication=True,
        private_credential_vault=vault,
        nmap_executable=sys.executable,
        executor=fake_executor,
    )
    command_text = " ".join(str(part) for part in captured["command"])
    assert "private-user" not in command_text
    assert "private-pass" not in command_text
    assert "private-user" in str(captured["args"])
    assert "private-pass" in str(captured["args"])
    assert result["c2_confirmed"] is True
    assert result["authentication_attempted"] is True
    assert result["raw_request_published"] is False


def test_purerat_certificate_match_stays_unconfirmed_without_exact_tls_version() -> None:
    target = {
        **_target(
            "purerat_direct_tls_certificate_pin",
            "purerat-441-d025a296-45-192-211-77-56001-direct-tls10",
        ),
        "family": "purehvnc",
        "host": "45.192.211.77",
        "port": 56001,
        "protocol": "purerat_direct_tls",
    }

    def fake_executor(command, **_kwargs):
        return subprocess.CompletedProcess(
            command,
            0,
            _xml(
                "purerat-direct-tls.nse",
                {
                    "family": "purehvnc",
                    "profile_id": ("purerat-441-d025a296-45-192-211-77-56001-direct-tls10"),
                    "status": ("purerat_direct_tls_certificate_match_tls_version_unverified"),
                    "c2_confirmed": False,
                    "probable_c2": True,
                    "confidence": "0.75",
                    "target_endpoint_exact_match": True,
                    "certificate_sha256": ("b3ae061b0b14a89d5134c279775b8f77a42214323c6bddab07f4d81ca2fc5c57"),
                    "certificate_exact_match": True,
                    "tls_version_enforced_by_nse": False,
                    "application_data_sent": False,
                    "plaintext_prelude_sent": False,
                    "request_count": 0,
                    "sent_bytes": 0,
                },
            ),
            b"",
        )

    result = detector.probe_target_with_nmap(
        target,
        allow_network=True,
        allow_purerat_legacy_tls=True,
        nmap_executable=sys.executable,
        executor=fake_executor,
    )
    assert result["status"] == "purerat_nse_certificate_match_tls_version_unverified"
    assert result["c2_confirmed"] is False
    assert result["probable_c2"] is True
    assert result["confidence"] == 0.75
    assert result["nse_reported_match"] is True
    assert result["exact_profile_match"] is False
    assert result["certificate_profile_match"] is True
    assert result["tls_version_enforced_by_nse"] is False
    assert result["sent_bytes"] == 0


def test_purerat_nse_certificate_match_without_profile_provenance_is_not_probable() -> None:
    """証明書一致だけを返すNSE出力をprofile一致へ昇格しない。"""
    target = {
        **_target(
            "purerat_direct_tls_certificate_pin",
            "purerat-441-d025a296-45-192-211-77-56001-direct-tls10",
        ),
        "family": "purehvnc",
        "host": "45.192.211.77",
        "port": 56001,
        "protocol": "purerat_direct_tls",
    }

    def fake_executor(command, **_kwargs):
        return subprocess.CompletedProcess(
            command,
            0,
            _xml(
                "purerat-direct-tls.nse",
                {
                    "family": "purehvnc",
                    "probable_c2": True,
                    "target_endpoint_exact_match": True,
                    "certificate_sha256": ("b3ae061b0b14a89d5134c279775b8f77a42214323c6bddab07f4d81ca2fc5c57"),
                    "certificate_exact_match": True,
                    "application_data_sent": False,
                    "plaintext_prelude_sent": False,
                    "request_count": 0,
                    "sent_bytes": 0,
                },
            ),
            b"",
        )

    result = detector.probe_target_with_nmap(
        target,
        allow_network=True,
        allow_purerat_legacy_tls=True,
        nmap_executable=sys.executable,
        executor=fake_executor,
    )

    assert result["c2_confirmed"] is False
    assert result["probable_c2"] is False
    assert result["confidence"] == 0.0
    assert result["certificate_profile_match"] is False


def test_purelogs_ping_requires_exact_ack_and_remains_probable_only() -> None:
    profile_id = "purelogs-0f2abaab-logs-uvexio-8443-ping-v1"
    target = {
        **_target("purelogs_https_ping", profile_id),
        "family": "purelogs",
        "host": "logs.uvexio.com",
        "port": 8443,
        "protocol": "https",
        "maximum_response_bytes": 1024,
    }
    captured: dict[str, object] = {}

    def fake_executor(command, **_kwargs):
        args_path = Path(command[command.index("--script-args-file") + 1])
        captured["args"] = args_path.read_text(encoding="utf-8")
        captured["command"] = command
        return subprocess.CompletedProcess(
            command,
            0,
            _xml(
                "purelogs-c2.nse",
                {
                    "family": "purelogs",
                    "profile_id": profile_id,
                    "status": "purelogs_ping_probable_match",
                    "variant": "http_aes_v5",
                    "generation_evidence_scope": "family_level_public_research",
                    "sample_version_confirmed": False,
                    "excluded_variant": "legacy_socket_3des",
                    "legacy_codec_implemented": False,
                    "c2_confirmed": True,
                    "probable_c2": True,
                    "confidence": "0.99",
                    "profile_acknowledged": True,
                    "target_endpoint_exact_match": True,
                    "certificate_sha256": ("9e254cab8c68944cea18a3ac5523fe491eb14f9447b352dca33729b64eaeeac3"),
                    "certificate_exact_match": True,
                    "http_status": 200,
                    "body_exact_match": True,
                    "response_sha256": ("565339bc4d33d72817b583024112eb7f5cdf3e5eef0252d6ec1b9c9a94e12bb3"),
                    "response_hash_scope": "http_body",
                    "response_size": 128,
                    "received_bytes": 128,
                    "request_count": 1,
                    "sent_bytes": 143,
                    "application_data_sent": True,
                    "request_body_sent": False,
                    "redirect_followed": False,
                    "response_body_published": False,
                    "raw_response_published": False,
                    "tls_version_enforced_by_nse": True,
                },
            ),
            b"",
        )

    result = detector.probe_target_with_nmap(
        target,
        allow_network=True,
        allow_application_probes=True,
        acknowledged_active_profiles=frozenset({profile_id}),
        nmap_executable=sys.executable,
        executor=fake_executor,
    )

    assert "193.26.115.118" == captured["command"][-1]
    args = str(captured["args"])
    assert f'purelogs.profile-id="{profile_id}"' in args
    assert f'purelogs.acknowledge-profile="{profile_id}"' in args
    assert 'purelogs.expected-host="logs.uvexio.com"' in args
    assert 'purelogs.expected-ip="193.26.115.118"' in args
    assert result["status"] == "purelogs_ping_probable_match_tls_version_unverified"
    assert result["probable_c2"] is True
    assert result["c2_confirmed"] is False
    assert result["confidence"] == 0.70
    assert result["variant"] == "http_aes_v5"
    assert result["generation_evidence_scope"] == "family_level_public_research"
    assert result["sample_version_confirmed"] is False
    assert result["excluded_variant"] == "legacy_socket_3des"
    assert result["legacy_codec_implemented"] is False
    assert result["tls_version_enforced_by_nse"] is False
    assert result["redirect_followed"] is False
    assert result["response_body_published"] is False
    assert result["open_port_is_c2_confirmation"] is False


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("response_hash_scope", "full_http_response"),
        ("response_size", 127),
        ("sent_bytes", 257),
        ("request_body_sent", True),
        ("raw_response_published", True),
    ],
)
def test_purelogs_ping_rejects_ambiguous_or_out_of_bounds_nse_evidence(
    field: str,
    value: object,
) -> None:
    """hash範囲、byte数、body送信、raw公開が曖昧な出力をprobableにしない。"""
    profile_id = "purelogs-0f2abaab-logs-uvexio-8443-ping-v1"
    target = {
        **_target("purelogs_https_ping", profile_id),
        "family": "purelogs",
        "host": "logs.uvexio.com",
        "port": 8443,
        "protocol": "https",
        "maximum_response_bytes": 1024,
    }
    fields: dict[str, object] = {
        "family": "purelogs",
        "profile_id": profile_id,
        "status": "purelogs_ping_probable_match",
        "variant": "http_aes_v5",
        "generation_evidence_scope": "family_level_public_research",
        "sample_version_confirmed": False,
        "excluded_variant": "legacy_socket_3des",
        "legacy_codec_implemented": False,
        "probable_c2": True,
        "profile_acknowledged": True,
        "target_endpoint_exact_match": True,
        "certificate_sha256": ("9e254cab8c68944cea18a3ac5523fe491eb14f9447b352dca33729b64eaeeac3"),
        "certificate_exact_match": True,
        "http_status": 200,
        "body_exact_match": True,
        "response_sha256": ("565339bc4d33d72817b583024112eb7f5cdf3e5eef0252d6ec1b9c9a94e12bb3"),
        "response_hash_scope": "http_body",
        "response_size": 128,
        "received_bytes": 128,
        "request_count": 1,
        "sent_bytes": 143,
        "application_data_sent": True,
        "request_body_sent": False,
        "redirect_followed": False,
        "response_body_published": False,
        "raw_response_published": False,
    }
    fields[field] = value

    def fake_executor(command, **_kwargs):
        return subprocess.CompletedProcess(
            command,
            0,
            _xml("purelogs-c2.nse", fields),
            b"",
        )

    result = detector.probe_target_with_nmap(
        target,
        allow_network=True,
        allow_application_probes=True,
        acknowledged_active_profiles=frozenset({profile_id}),
        nmap_executable=sys.executable,
        executor=fake_executor,
    )

    assert result["c2_confirmed"] is False
    assert result["probable_c2"] is False
    assert result["confidence"] == 0.0


@pytest.mark.parametrize(
    ("allow_application_probes", "acknowledgements", "expected_status"),
    [
        (False, frozenset(), "reviewed_application_probe_disabled"),
        (True, frozenset(), "profile_acknowledgement_missing_or_mismatch"),
        (True, frozenset({"wrong-profile"}), "profile_acknowledgement_missing_or_mismatch"),
    ],
)
def test_purelogs_ping_gates_before_nmap(
    allow_application_probes: bool,
    acknowledgements: frozenset[str],
    expected_status: str,
) -> None:
    called = False

    def forbidden(*_args, **_kwargs):
        nonlocal called
        called = True
        raise AssertionError("executor must not run")

    profile_id = "purelogs-0f2abaab-logs-uvexio-8443-ping-v1"
    result = detector.probe_target_with_nmap(
        {
            **_target("purelogs_https_ping", profile_id),
            "family": "purelogs",
            "host": "logs.uvexio.com",
            "port": 8443,
            "protocol": "https",
        },
        allow_network=True,
        allow_application_probes=allow_application_probes,
        acknowledged_active_profiles=acknowledgements,
        executor=forbidden,
    )

    assert result["status"] == expected_status
    assert result["target_contact_attempted"] is False
    assert result["c2_confirmed"] is False
    assert result["probable_c2"] is False
    assert called is False


def test_purelogs_ping_certificate_mismatch_cannot_be_probable() -> None:
    profile_id = "purelogs-0f2abaab-logs-uvexio-8443-ping-v1"
    target = {
        **_target("purelogs_https_ping", profile_id),
        "family": "purelogs",
        "host": "logs.uvexio.com",
        "port": 8443,
        "protocol": "https",
    }

    def fake_executor(command, **_kwargs):
        return subprocess.CompletedProcess(
            command,
            0,
            _xml(
                "purelogs-c2.nse",
                {
                    "family": "purelogs",
                    "profile_id": profile_id,
                    "status": "purelogs_ping_probable_match",
                    "variant": "http_aes_v5",
                    "generation_evidence_scope": "family_level_public_research",
                    "sample_version_confirmed": False,
                    "excluded_variant": "legacy_socket_3des",
                    "legacy_codec_implemented": False,
                    "probable_c2": True,
                    "profile_acknowledged": True,
                    "target_endpoint_exact_match": True,
                    "certificate_sha256": "0" * 64,
                    "certificate_exact_match": True,
                    "http_status": 200,
                    "body_exact_match": True,
                    "response_sha256": ("565339bc4d33d72817b583024112eb7f5cdf3e5eef0252d6ec1b9c9a94e12bb3"),
                    "received_bytes": 128,
                    "request_count": 1,
                    "sent_bytes": 143,
                    "application_data_sent": True,
                    "redirect_followed": False,
                },
            ),
            b"",
        )

    result = detector.probe_target_with_nmap(
        target,
        allow_network=True,
        allow_application_probes=True,
        acknowledged_active_profiles=frozenset({profile_id}),
        nmap_executable=sys.executable,
        executor=fake_executor,
    )

    assert result["certificate_exact_match"] is False
    assert result["probable_c2"] is False
    assert result["c2_confirmed"] is False
    assert result["confidence"] == 0.0


def test_purerat_legacy_prelude_is_acknowledged_hypothesis_only() -> None:
    profile_id = "purerat-441-e5541255-tirakian-56001"
    target = {
        **_target("purerat_tls_prelude", profile_id),
        "family": "purehvnc",
        "host": "tirakian.com",
        "port": 56001,
        "protocol": "purehvnc",
    }
    captured: dict[str, str] = {}

    def fake_executor(command, **_kwargs):
        args_path = Path(command[command.index("--script-args-file") + 1])
        captured["args"] = args_path.read_text(encoding="utf-8")
        return subprocess.CompletedProcess(
            command,
            0,
            _xml(
                "purerat-c2.nse",
                {
                    "family": "purehvnc",
                    "profile_id": profile_id,
                    "status": "purerat_prelude_tls_certificate_match",
                    "c2_confirmed": True,
                    "probable_c2": True,
                    "confidence": "0.95",
                    "profile_acknowledged": True,
                    "target_endpoint_exact_match": True,
                    "compatibility_hypothesis": True,
                    "certificate_sha256": ("67260a713ab105197098882f6d126f89fe4f48df8013f8bba1d2c9307b17410b"),
                    "certificate_exact_match": True,
                    "application_data_sent": True,
                    "plaintext_prelude_sent": True,
                    "sent_bytes": 4,
                    "request_count": 1,
                    "tls_version_enforced_by_nse": True,
                },
            ),
            b"",
        )

    result = detector.probe_target_with_nmap(
        target,
        allow_network=True,
        allow_purerat_legacy_tls=True,
        acknowledged_active_profiles=frozenset({profile_id}),
        nmap_executable=sys.executable,
        executor=fake_executor,
    )

    args = captured["args"]
    assert f'purerat.profile-id="{profile_id}"' in args
    assert f'purerat.acknowledge-profile="{profile_id}"' in args
    assert 'purerat.expected-host="tirakian.com"' in args
    assert "purerat.ports" not in args
    assert result["status"] == ("purerat_legacy_prelude_hypothesis_certificate_match_tls_version_unverified")
    assert result["compatibility_hypothesis"] is True
    assert result["probable_c2"] is True
    assert result["c2_confirmed"] is False
    assert result["confidence"] == 0.60
    assert result["tls_version_enforced_by_nse"] is False
    assert result["sent_bytes"] == 4


def test_purerat_legacy_prelude_requires_exact_ack_before_nmap() -> None:
    called = False

    def forbidden(*_args, **_kwargs):
        nonlocal called
        called = True
        raise AssertionError("executor must not run")

    profile_id = "purerat-441-e5541255-tirakian-56001"
    result = detector.probe_target_with_nmap(
        {
            **_target("purerat_tls_prelude", profile_id),
            "family": "purehvnc",
            "host": "tirakian.com",
            "port": 56001,
            "protocol": "purehvnc",
        },
        allow_network=True,
        allow_purerat_legacy_tls=True,
        acknowledged_active_profiles=frozenset(),
        executor=forbidden,
    )

    assert result["status"] == "profile_acknowledgement_missing_or_mismatch"
    assert result["target_contact_attempted"] is False
    assert result["c2_confirmed"] is False
    assert result["probable_c2"] is False
    assert called is False


def test_unexpected_family_and_raw_fields_fail_closed() -> None:
    target = _target("tcp_connect")

    def fake_executor(command, **_kwargs):
        return subprocess.CompletedProcess(
            command,
            0,
            _xml(
                "c2-transport-observe.nse",
                {
                    "family": "unexpected-family",
                    "status": "tcp_open_only",
                    "c2_confirmed": True,
                    "raw_response": "SECRET",
                },
            ),
            b"",
        )

    result = detector.probe_target_with_nmap(
        target,
        allow_network=True,
        nmap_executable=sys.executable,
        executor=fake_executor,
    )
    assert result["status"] == "nmap_script_family_mismatch"
    assert result["c2_confirmed"] is False
    assert "raw_response" not in result
    assert "SECRET" not in json.dumps(result)


def test_duplicate_script_results_are_rejected() -> None:
    payload = _xml("c2-transport-observe.nse", {"status": "tcp_open_only"})
    duplicated = payload.replace(
        b"</port></ports>", payload[payload.index(b"<script") : payload.index(b"</script>") + 9] + b"</port></ports>"
    )
    with pytest.raises(detector.NmapC2Error, match="複数"):
        detector.parse_nmap_xml(duplicated, "c2-transport-observe.nse")


def test_legacy_target_prefers_exact_reviewed_profile() -> None:
    target = detector.normalize_legacy_target(
        {
            "host": "202.95.8.27",
            "port": 6666,
            "protocol": "vvas",
            "send_hex": "333200",
            "expected_stage_size": 307214,
        },
        sample_sha256="8bf54a76924ad62e3b5562826f0e491c4c498f166276b071c177b694762199f6",
    )
    assert target["method"] == "vvas_checkin"
    assert target["protocol_profile_id"] == "valleyrat-vvas-8bf54-6666"
    assert target["selection_basis"] == "中央registryのreview済みNmap NSE profile完全一致"
    assert "send_hex" not in target
    assert "expected_stage_size" not in target


def test_legacy_generic_https_is_transport_only() -> None:
    target = detector.normalize_legacy_target(
        {
            "host": "www.tq8j.com",
            "port": 443,
            "protocol": "https",
            "http_host": "www.tq8j.com",
        },
        sample_sha256="b433ecdf855beaaf91d57522eebe9c9e1c3fc756f711bd79ac1b3ecf6c75016c",
    )
    assert target["method"] == "http_get"
    assert target["family"] == "unknown"
    assert target["selection_basis"] == "汎用Nmap NSEによる到達性観測のみ"
    assert "protocol_profile_id" not in target


@pytest.mark.parametrize("protocol", ["udp", "mxgo", "vvas", "n520"])
def test_unreviewed_private_protocol_is_rejected(protocol: str) -> None:
    with pytest.raises(detector.NmapC2Error, match="未対応"):
        detector.normalize_legacy_target({"host": "example.test", "port": 443, "protocol": protocol})


def test_unreviewed_send_bytes_are_rejected() -> None:
    with pytest.raises(detector.NmapC2Error, match="未レビューの送信値"):
        detector.normalize_legacy_target(
            {
                "host": "example.test",
                "port": 443,
                "protocol": "tcp",
                "send_hex": "00",
            }
        )


def test_cli_defaults_to_nmap_offline_gate(tmp_path: Path) -> None:
    output = tmp_path / "result.json"
    completed = subprocess.run(
        [
            sys.executable,
            str(FRAMEWORK / "nmap" / "nmap_c2_detector.py"),
            "203.0.113.10",
            "443",
            "--protocol",
            "https",
            "--output",
            str(output),
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )
    assert completed.returncode == 1
    result = json.loads(output.read_text(encoding="utf-8"))
    assert result["status"] == "network_disabled"
    assert result["execution_engine"] == "nmap_nse"
    assert result["target_contact_attempted"] is False
