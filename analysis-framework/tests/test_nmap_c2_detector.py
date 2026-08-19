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
    assert runtime["method_count"] == 21
    assert set(runtime["methods"]) == set(declared)
    for method, binding in runtime["methods"].items():
        assert f"scripts/{binding['script']}" == declared[method]["script"]
        assert (FRAMEWORK / "nmap" / declared[method]["script"]).is_file()


def test_args_file_quotes_values_and_rejects_control_characters() -> None:
    rendered = detector.render_script_args(
        {"agenttesla.user": "analyst@example.test", "agenttesla.pass": 'a"b\\c'}
    )
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


def test_formbook_reviewed_route_requires_application_probe_gate() -> None:
    called = False

    def forbidden(*_args, **_kwargs):
        nonlocal called
        called = True
        raise AssertionError("executor must not run")

    result = detector.probe_target_with_nmap(
        _target("formbook_reviewed_route_head"),
        allow_network=True,
        allow_application_probes=False,
        executor=forbidden,
    )
    assert result["status"] == "tls_handshake_only_application_probe_disabled"
    assert result["target_contact_attempted"] is False
    assert result["application_data_sent"] is False
    assert called is False


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
                    "status": "purerat_direct_tls_certificate_match",
                    "c2_confirmed": True,
                    "confidence": "0.92",
                    "certificate_sha256": (
                        "b3ae061b0b14a89d5134c279775b8f77a42214323c6bddab07f4d81ca2fc5c57"
                    ),
                    "certificate_exact_match": True,
                    "application_data_sent": False,
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
    assert result["nse_reported_match"] is True
    assert result["tls_version_enforced_by_nse"] is False
    assert result["sent_bytes"] == 0


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
    duplicated = payload.replace(b"</port></ports>", payload[payload.index(b"<script") : payload.index(b"</script>") + 9] + b"</port></ports>")
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
        detector.normalize_legacy_target(
            {"host": "example.test", "port": 443, "protocol": protocol}
        )


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
