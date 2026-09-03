"""第13バッチの解析資材、デュアルユース判定、安全境界、公開成果物を回帰検証する。"""

from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

FRAMEWORK = Path(__file__).parents[1]
REPOSITORY = FRAMEWORK.parent
BATCH13 = REPOSITORY / "analysis-results/research/malwarebazaar/batches/batch-0013"
SCREENCONNECT_SHA256 = "16d76fb73e844e7ae13081b614f4b7449d4f020246189bfd6d77585d33a55a71"
JACK_ARM_SHA256 = "02e960e5278a686f38a356e5e7842def5797e07ec0b06b8fe5f34d0b28fde0b2"
JACK_AARCH64_SHA256 = "875257991745c0557dd2fb00cd40934de6281ded379289c26d900bca2628f25f"
SIGNED_ARMV7_SHA256 = "fd5a48693a99cbb7c49f5f4245f3090ffeec58ce3f9d9bcf7f6c7eade62769f1"
GEND_MIPS_SHA256 = "e7889354c0d2cce6cc0c6a34ec13afd79bf361388e76ed2b3b987e0613d9c6a6"


def load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def family_module(family: str, filename: str = "extract_config.py"):
    return load_module(FRAMEWORK / "malware" / family / filename, f"batch13_{family}_{filename}")


def test_jackskid_arm_and_aarch64_exact_profiles_cover_same_generation() -> None:
    extractor = family_module("jackskid")
    arm = extractor.HASH_PROFILES[JACK_ARM_SHA256]
    aarch64 = extractor.HASH_PROFILES[JACK_AARCH64_SHA256]
    assert arm["architecture"] == "armv5"
    assert aarch64["architecture"] == "aarch64"
    assert arm["key_address"] == 0x24804
    assert aarch64["key_bytes"] == extractor.KEY_BYTES
    assert arm["ghidra_main"] == "0x0000f544"
    assert aarch64["ghidra_main"] == "0x00100d8c"
    assert len(arm["entries"]) == len(aarch64["entries"]) == 53
    assert arm["controller_ports"] == aarch64["controller_ports"]
    assert len(arm["controller_ports"]) == 101
    assert arm["controller_ports"][0] == 64409
    assert arm["observed_controller_ips"] == ["172.233.124.230", "45.154.98.115"]


def test_jackskid_new_port_requires_protocol_correlation() -> None:
    detector = family_module("jackskid", "network_detector.py")
    endpoint_only = detector.detect_flow({"host": "172.233.124.230", "port": 64409, "events": []})
    assert endpoint_only["matched"] is False
    flow = {
        "host": "172.233.124.230",
        "port": 64409,
        "events": [
            {"direction": "out", "size": 32},
            {"direction": "in", "size": 32},
            {"direction": "out", "size": 16},
            {"direction": "out", "size": 64},
        ],
    }
    assert detector.detect_flow(flow)["matched"] is True
    flow["host"] = "ethereum.publicnode.com"
    assert detector.detect_flow(flow)["matched"] is False


def test_signed_dht_armv7_repair_profile_is_fixed_and_nonexecuting() -> None:
    extractor = family_module("signed_dht_bot")
    profile = extractor.PROFILES[SIGNED_ARMV7_SHA256]
    assert profile["architecture"] == "armv7"
    assert profile["packaging"] == "tampered_upx"
    assert profile["inserted_trailer_bytes"] == 10
    assert profile["repaired_packed_sha256"] == "0ca62676007dbfdbc1a68719dda27bd7e52507b294032282a98c8faf5f32cac5"
    assert profile["recovered_sha256"] == "3f09fcfdcc84cf8e478def482cbf8d5b953b13de3fb096fb3c5ebd1577039e2e"
    assert profile["ghidra_main"] == "0x00008db8"
    assert profile["table_cipher_key"] == "0x25e27a77"
    assert profile["attack_handler_count"] == 19


def test_genddos_batch13_mips_profile_is_exact() -> None:
    extractor = family_module("genddos_bot")
    profile = extractor.HASH_PROFILES[GEND_MIPS_SHA256]
    assert profile["architecture"] == "mips"
    assert profile["key_address"] == 0x0046188C
    assert profile["domain_address"] == 0x0041F030
    assert profile["port_address"] == 0x0041F03C
    assert profile["ghidra"]["main_address"] == "0x0040da78"


def test_screenconnect_extractor_redacts_synthetic_tenant_key() -> None:
    extractor = family_module("screenconnect_rmm")
    key = "synthetic-test-key-0123456789-abcdefghijklmnop"
    query = f"?h=tenant-lab-relay.screenconnect.com&p=443&k={key}"
    data = b"MZ" + b"ScreenConnect.WindowsInstaller\x00ClientSetup\x00" + query.encode() + b"\x00"
    result = extractor.extract_config(data)
    assert result["classification"] == "commercial_rmm_dual_use"
    assert result["classification_confidence"] == "structural_only"
    assert result["malware_by_itself"] is False
    assert result["version"] is None
    assert result["relay"]["tenant_key_sha256"] == hashlib.sha256(key.encode()).hexdigest()
    assert result["relay"]["tenant_key_length"] == len(key)
    assert key not in json.dumps(result, ensure_ascii=False)
    assert result["relay"]["redacted_query"].endswith("&k=<redacted>")
    assert result["config"]["static_config_recovered"] is True
    assert result["config"]["static_evidence"] == {
        "all_expected_fields_validated": True,
        "source": "screenconnect_embedded_management_configuration",
        "dual_use_endpoint": True,
    }
    assert result["config"]["config_endpoints"] == [
        {
            "host": "tenant-lab-relay.screenconnect.com",
            "port": 443,
            "transport": "tcp_tls",
            "role": "remote_management_relay",
            "confidence": "confirmed_static_configuration",
            "evidence": {
                "kind": "screenconnect_embedded_management_endpoint",
                "c2_classification": "dual_use_not_c2_by_itself",
                "malicious_use_confirmed": False,
            },
        }
    ]
    assert "tenant_key" not in json.dumps(
        result["config"], ensure_ascii=False
    ).casefold()


def test_screenconnect_file_detector_requires_extractor_compatible_query() -> None:
    detector = family_module("screenconnect_rmm", "detect.py")
    key = "synthetic-test-key-0123456789-abcdefghijklmnop"
    data = (
        b"MZScreenConnect.WindowsInstaller\x00"
        + f"?h=tenant-lab-relay.screenconnect.com&p=443&k={key}".encode()
    )

    result = detector.detect(data, Path("synthetic-screenconnect.exe"))

    assert result["matched"] is True
    assert result["observations"]["reviewed_hash"] is False
    assert result["observations"]["extractor_compatible_query"] is True
    assert result["campaigns"][0]["confidence"] == "medium"
    assert result["campaigns"][0]["reasons"] == [
        "screenconnect_product",
        "installer_marker",
        "direct_or_tenant_relay_host",
        "extractor_compatible_query",
    ]


def test_screenconnect_direct_ip_relay_query_is_shared_and_redacted() -> None:
    detector = family_module("screenconnect_rmm", "detect.py")
    extractor = family_module("screenconnect_rmm")
    key = "synthetic-direct-ip-key-0123456789-abcdefghijklmnop"
    data = (
        b"MZScreenConnect.WindowsInstaller\x00ClientSetup\x00"
        + f"?h=102.220.160.93&p=8041&k={key}".encode("ascii")
    )

    detected = detector.detect(data, Path("synthetic-direct-ip.exe"))
    extracted = extractor.extract_config(data)

    assert detected["matched"] is True
    assert detected["observations"]["relay_suffix"] is False
    assert detected["observations"]["extractor_compatible_query"] is True
    assert detected["campaigns"][0]["reasons"] == [
        "screenconnect_product",
        "installer_marker",
        "direct_or_tenant_relay_host",
        "extractor_compatible_query",
    ]
    assert extracted["relay"]["host"] == "102.220.160.93"
    assert extracted["relay"]["port"] == 8041
    assert extracted["relay"]["tenant_key_sha256"] == hashlib.sha256(
        key.encode("ascii")
    ).hexdigest()
    assert key not in json.dumps(extracted, ensure_ascii=False)


@pytest.mark.parametrize(
    "query",
    [
        "?h=-invalid.example&p=443&k=" + "a" * 40,
        "?h=relay.example&p=65536&k=" + "b" * 40,
        "?h=999.999.999.999&p=443&k=" + "c" * 40,
    ],
    ids=["invalid_host", "invalid_port", "invalid_numeric_ip"],
)
def test_screenconnect_shared_relay_parser_rejects_invalid_endpoint(query: str) -> None:
    detector = family_module("screenconnect_rmm", "detect.py")
    extractor = family_module("screenconnect_rmm")
    data = b"MZScreenConnect.WindowsInstaller\x00ClientSetup\x00" + query.encode("ascii")

    assert detector.detect(data, Path("invalid.exe"))["matched"] is False
    with pytest.raises(ValueError, match="埋め込みリレー照会"):
        extractor.extract_config(data)


def test_screenconnect_shared_relay_parser_rejects_ambiguous_queries() -> None:
    detector = family_module("screenconnect_rmm", "detect.py")
    extractor = family_module("screenconnect_rmm")
    first = "?h=192.0.2.10&p=443&k=" + "a" * 40
    second = "?h=192.0.2.11&p=8443&k=" + "b" * 40
    data = (
        b"MZScreenConnect.WindowsInstaller\x00ClientSetup\x00"
        + first.encode("ascii")
        + b"\x00"
        + second.encode("ascii")
    )

    assert detector.detect(data, Path("ambiguous.exe"))["matched"] is False
    with pytest.raises(ValueError, match="複数の異なるリレー照会"):
        extractor.extract_config(data)


@pytest.mark.parametrize(
    ("key_length", "accepted"),
    [(31, False), (32, True), (2048, True), (2049, False)],
)
def test_screenconnect_relay_key_length_has_exact_token_boundary(
    key_length: int,
    accepted: bool,
) -> None:
    detector = family_module("screenconnect_rmm", "detect.py")
    extractor = family_module("screenconnect_rmm")
    key = "a" * key_length
    data = (
        b"MZScreenConnect.WindowsInstaller\x00ClientSetup\x00"
        + f"?h=192.0.2.10&p=443&k={key}".encode("ascii")
    )

    detected = detector.detect(data, Path("key-boundary.exe"))
    assert detected["matched"] is accepted
    if accepted:
        result = extractor.extract_config(data)
        assert result["relay"]["tenant_key_length"] == key_length
    else:
        with pytest.raises(ValueError, match="埋め込みリレー照会"):
            extractor.extract_config(data)


def test_screenconnect_auxiliary_malformed_url_is_skipped_without_leak() -> None:
    extractor = family_module("screenconnect_rmm")
    key = "a" * 40
    sentinel = "sensitive-sentinel"
    data = (
        b"MZScreenConnect.WindowsInstaller\x00ClientSetup\x00"
        + f"?h=192.0.2.10&p=443&k={key}".encode("ascii")
        + b"\x00http://["
        + sentinel.encode("ascii")
    )

    result = extractor.extract_config(data)

    assert result["relay"]["host"] == "192.0.2.10"
    assert sentinel not in json.dumps(result, ensure_ascii=False)


@pytest.mark.parametrize(
    "relay_host",
    ["attacker.example", "localhost", "999.999.999.999"],
)
def test_screenconnect_relay_query_rejects_nonvendor_dns_and_invalid_numeric_host(
    relay_host: str,
) -> None:
    detector = family_module("screenconnect_rmm", "detect.py")
    extractor = family_module("screenconnect_rmm")
    data = (
        b"MZScreenConnect.WindowsInstaller\x00ClientSetup\x00"
        + f"?h={relay_host}&p=443&k=".encode("ascii")
        + b"a" * 40
    )

    assert detector.detect(data, Path("invalid-relay-host.exe"))["matched"] is False
    with pytest.raises(ValueError, match="埋め込みリレー照会"):
        extractor.extract_config(data)


def test_screenconnect_detector_rejects_unique_relay_with_ambiguous_applications() -> None:
    detector = family_module("screenconnect_rmm", "detect.py")
    extractor = family_module("screenconnect_rmm")
    data = (
        b"MZScreenConnect.WindowsInstaller\x00ClientSetup\x00"
        b"ScreenConnect.Client.application\x00"
        b"?h=192.0.2.10&p=443&k=" + b"a" * 40
        + b"\x00https://192.0.2.20/Bin/ScreenConnect.Client.application"
        + b"\x00https://192.0.2.21/Bin/ScreenConnect.Client.application"
    )

    assert detector.detect(data, Path("ambiguous-applications.exe"))["matched"] is False
    with pytest.raises(ValueError, match="複数の異なるScreenConnect application URL"):
        extractor.extract_config(data)


def test_screenconnect_detector_rejects_ambiguous_relays_with_unique_application() -> None:
    detector = family_module("screenconnect_rmm", "detect.py")
    extractor = family_module("screenconnect_rmm")
    data = (
        b"MZScreenConnect.WindowsInstaller\x00ClientSetup\x00"
        b"ScreenConnect.Client.application\x00"
        b"?h=192.0.2.10&p=443&k=" + b"a" * 40
        + b"\x00?h=192.0.2.11&p=8443&k=" + b"b" * 40
        + b"\x00https://192.0.2.20/Bin/ScreenConnect.Client.application"
    )

    assert detector.detect(data, Path("ambiguous-relays.exe"))["matched"] is False
    with pytest.raises(ValueError, match="複数の異なるリレー照会"):
        extractor.extract_config(data)


def test_screenconnect_odd_offset_utf16_markers_share_detector_contract() -> None:
    detector = family_module("screenconnect_rmm", "detect.py")
    extractor = family_module("screenconnect_rmm")
    data = (
        b"MZX"
        + "ScreenConnect.WindowsInstaller".encode("utf-16le")
        + b"\x00?h=192.0.2.10&p=443&k="
        + b"a" * 40
    )

    detected = detector.detect(data, Path("odd-offset-wide.exe"))
    extracted = extractor.extract_config(data)

    assert detected["matched"] is True
    assert extracted["artifact_role"] == "access_agent_installer"
    assert extracted["relay"]["host"] == "192.0.2.10"


def test_screenconnect_relay_without_installer_marker_is_rejected_by_both() -> None:
    detector = family_module("screenconnect_rmm", "detect.py")
    extractor = family_module("screenconnect_rmm")
    data = (
        b"MZScreenConnect\x00?h=192.0.2.10&p=443&k="
        + b"a" * 40
    )

    assert detector.detect(data, Path("markerless-relay.exe"))["matched"] is False
    with pytest.raises(ValueError, match="installer marker"):
        extractor.extract_config(data)


def test_screenconnect_unique_application_does_not_mask_markerless_relay() -> None:
    detector = family_module("screenconnect_rmm", "detect.py")
    extractor = family_module("screenconnect_rmm")
    data = (
        b"MZScreenConnect.Client.application\x00"
        b"?h=192.0.2.10&p=443&k=" + b"a" * 40
        + b"\x00https://192.0.2.20/Bin/ScreenConnect.Client.application"
    )

    assert detector.detect(data, Path("mixed-markerless-relay.exe"))["matched"] is False
    with pytest.raises(ValueError, match="installer marker"):
        extractor.extract_config(data)


@pytest.mark.parametrize(
    "query",
    [
        "?e=Access&y=Guest&h=tenant-lab-relay.screenconnect.com&p=443&k=" + "a" * 40,
        "?h=tenant-lab-relay.screenconnect.com&amp;p=443&amp;k=" + "b" * 40,
    ],
    ids=["guest_launch", "xml_escaped"],
)
def test_screenconnect_file_detector_rejects_nonextractable_query(query: str) -> None:
    detector = family_module("screenconnect_rmm", "detect.py")
    extractor = family_module("screenconnect_rmm")
    data = b"MZScreenConnect.WindowsInstaller\x00" + query.encode("ascii")

    result = detector.detect(data, Path("synthetic-screenconnect.exe"))

    assert result["matched"] is False
    assert result["observations"] == {
        "reviewed_hash": False,
        "pe": True,
        "screenconnect_product": True,
        "installer_marker": True,
        "relay_suffix": True,
        "extractor_compatible_query": False,
        "application_marker": False,
        "extractor_compatible_application_url": False,
    }
    assert result["campaigns"] == []
    with pytest.raises(ValueError, match="埋め込みリレー照会"):
        extractor.extract_config(data)


def test_screenconnect_file_detector_preserves_exact_reviewed_hash(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    detector = family_module("screenconnect_rmm", "detect.py")
    data = b"MZreviewed-without-structural-query"
    monkeypatch.setattr(detector, "REVIEWED", {hashlib.sha256(data).hexdigest()})

    result = detector.detect(data, Path("reviewed-screenconnect.exe"))

    assert result["matched"] is True
    assert result["observations"]["reviewed_hash"] is True
    assert result["observations"]["extractor_compatible_query"] is False
    assert result["campaigns"][0]["confidence"] == "high"
    assert result["campaigns"][0]["reasons"] == ["reviewed_sha256"]


def test_screenconnect_support_client_application_profile_is_deterministic() -> None:
    extractor = family_module("screenconnect_rmm")
    application_url = (
        "http://31.42.176.91:5001/Bin/ScreenConnect.Client.application"
    )
    certificate_url = "http://cacerts.digicert.com/DigiCertAssuredIDRootCA.crt"
    data = (
        b"MZScreenConnect.Client.application\x00ClickOnceRunner\x00"
        + application_url.encode("ascii")
        + b"\x00ScreenConnect.ClientService.dll25.2.4.92290"
        + b"ScreenConnect.Client.dll\x00"
        + certificate_url.encode("ascii")
        + b"\x001.3.6.1\x00"
    )

    result = extractor.extract_config(data)

    assert result["classification"] == "commercial_rmm_dual_use"
    assert result["artifact_role"] == "clickonce_bootstrap_client"
    assert result["version"] == "25.2.4.92290"
    assert result["build"] == {
        "status": "recovered",
        "value": "25.2.4.92290",
        "source": "screenconnect_adjacent_version_string",
    }
    assert "relay" not in result
    assert result["application"] == {
        "url": application_url,
        "scheme": "http",
        "host": "31.42.176.91",
        "port": 5001,
        "path": "/Bin/ScreenConnect.Client.application",
        "transport": "tcp",
        "role": "screenconnect_clickonce_bootstrap",
        "contacted": False,
        "c2_classification": "dual_use_management_endpoint_not_c2_by_itself",
    }
    assert result["network_contacted"] is False
    assert result["sample_executed"] is False
    assert result["malicious_use_context"] == {
        "assessment": "requires_incident_context",
        "malicious_use_confirmed": False,
        "unauthorized_installation_observed": False,
        "embedded_management_endpoint_observed": True,
        "requires_authorization_and_delivery_context": True,
        "rationale_ja": (
            "ScreenConnectはデュアルユース製品であり、埋め込み管理先だけでは"
            "不正導入またはC2利用を確定できない"
        ),
    }
    assert result["indicator_filter"]["authenticode_certificate_url_count"] >= 1
    assert result["indicator_filter"]["asn1_oid_count"] >= 1
    assert result["indicator_filter"]["excluded_values_published"] is False
    assert result["hunt_guidance"]["shodan_queries"] == [
        "ip:31.42.176.91 port:5001"
    ]
    serialized = json.dumps(result, ensure_ascii=False)
    assert certificate_url not in serialized
    assert "1.3.6.1" not in serialized


@pytest.mark.parametrize(
    ("application_url", "expected_host", "expected_port", "expected_transport"),
    [
        (
            "http://31.42.176.91:5001/Bin/ScreenConnect.Client.application",
            "31.42.176.91", 5001, "tcp",
        ),
        (
            "http://23.146.240.17/Bin/ScreenConnect.Client.application",
            "23.146.240.17", 80, "tcp",
        ),
        (
            "http://23.148.146.148/Bin/ScreenConnect.Client.application",
            "23.148.146.148", 80, "tcp",
        ),
        (
            "https://102.220.160.93/Bin/ScreenConnect.Client.application",
            "102.220.160.93", 443, "tcp_tls",
        ),
        (
            "http://23.146.242.101/Bin/ScreenConnect.Client.application",
            "23.146.242.101", 80, "tcp",
        ),
        (
            "https://102.220.160.223/Bin/ScreenConnect.Client.application",
            "102.220.160.223", 443, "tcp_tls",
        ),
        (
            "https://93.152.221.193/Bin/ScreenConnect.Client.application",
            "93.152.221.193", 443, "tcp_tls",
        ),
    ],
    ids=[
        "0142e425", "249e01fa", "824b7cfe", "8a08133e",
        "ab60f3ec", "eb528aa8", "f0885b53",
    ],
)
def test_screenconnect_support_client_detector_requires_exact_application_url(
    application_url: str,
    expected_host: str,
    expected_port: int,
    expected_transport: str,
) -> None:
    detector = family_module("screenconnect_rmm", "detect.py")
    extractor = family_module("screenconnect_rmm")
    data = b"MZScreenConnect.Client.application\x00" + application_url.encode("ascii")

    result = detector.detect(data, Path("support.client.exe"))
    config = extractor.extract_config(data)

    assert result["matched"] is True
    assert result["classification"] == "commercial_rmm_dual_use"
    assert result["malware_by_itself"] is False
    assert result["requires_incident_context"] is True
    assert result["observations"]["extractor_compatible_query"] is False
    assert result["observations"]["application_marker"] is True
    assert result["observations"]["extractor_compatible_application_url"] is True
    assert result["campaigns"][0]["reasons"] == [
        "screenconnect_product",
        "application_marker",
        "extractor_compatible_application_url",
    ]
    assert config["application"]["url"] == application_url
    assert config["application"]["host"] == expected_host
    assert config["application"]["port"] == expected_port
    assert config["application"]["transport"] == expected_transport
    assert config["network_contacted"] is False
    assert config["sample_executed"] is False


def test_screenconnect_support_client_rejects_multiple_application_urls() -> None:
    extractor = family_module("screenconnect_rmm")
    data = (
        b"MZScreenConnect.Client.application\x00"
        b"http://31.42.176.91:5001/Bin/ScreenConnect.Client.application\x00"
        b"http://23.146.240.17/Bin/ScreenConnect.Client.application\x00"
    )

    with pytest.raises(ValueError, match="複数の異なるScreenConnect application URL"):
        extractor.extract_config(data)


@pytest.mark.parametrize(
    "application_url",
    [
        "https://example.com/Bin/ScreenConnect.Client.application.evil",
        "https://example.com/Bin/ScreenConnect.Client.application?tenant=1",
        "https://example.com/Bin/ScreenConnect.Client.application#fragment",
        "https://example.com/bin/other.application",
        "https://bad..example/Bin/ScreenConnect.Client.application",
        "https://user@example.com/Bin/ScreenConnect.Client.application",
        "https://example.com:/Bin/ScreenConnect.Client.application",
        "https://example.com:0/Bin/ScreenConnect.Client.application",
        "https://example.com:65536/Bin/ScreenConnect.Client.application",
        "https://example.com/Bin/ScreenConnect%2EClient%2Eapplication",
    ],
)
def test_screenconnect_application_parser_rejects_prefix_spoof_and_invalid_url(
    application_url: str,
) -> None:
    detector = family_module("screenconnect_rmm", "detect.py")
    extractor = family_module("screenconnect_rmm")
    data = (
        b"MZScreenConnect.Client.application\x00"
        + application_url.encode("ascii")
        + b"\x00"
    )

    detection = detector.detect(data, Path("spoofed-support-client.exe"))

    assert detection["matched"] is False
    assert (
        detection["observations"]["extractor_compatible_application_url"]
        is False
    )
    with pytest.raises(
        ValueError,
        match="埋め込みリレー照会またはapplication URL",
    ):
        extractor.extract_config(data)


def test_screenconnect_detector_requires_product_and_authorization_context() -> None:
    detector = family_module("screenconnect_rmm", "network_detector.py")
    hostname_only = detector.detect_flow({
        "host": "tenant-lab-relay.screenconnect.com", "port": 443,
    })
    assert hostname_only["matched"] is False
    authorized_or_unknown = detector.detect_flow({
        "host": "tenant-lab-relay.screenconnect.com", "port": 443,
        "product": "ScreenConnect Client", "signer": "ConnectWise, LLC",
    })
    assert authorized_or_unknown["matched"] is True
    assert authorized_or_unknown["classification"] == "authorized_or_unknown_dual_use_rmm"
    assert authorized_or_unknown["malicious"] is False
    suspected = detector.detect_flow({
        "host": "tenant-lab-relay.screenconnect.com", "port": 443,
        "product": "ScreenConnect Client", "signer": "ConnectWise, LLC",
        "unauthorized_installation": True,
    })
    assert suspected["classification"] == "suspected_rmm_abuse"
    assert suspected["malicious"] is False
    assert suspected["requires_incident_context"] is True


def test_screenconnect_emulator_is_offline_and_redacts() -> None:
    emulator = family_module("screenconnect_rmm", "emulator.py")
    key = "synthetic-screenconnect-tenant-key"
    result = emulator.inspect_query(
        f"?h=tenant-lab-relay.screenconnect.com&p=443&k={key}"
    )
    assert result["network_contacted"] is False
    assert result["malware_protocol_compatible"] is False
    assert key not in json.dumps(result, ensure_ascii=False)
    assert "ネットワーク接続" in result["not_implemented"]


def test_batch13_yara_rules_compile() -> None:
    yara = pytest.importorskip("yara")
    for family in (
        "screenconnect_rmm", "jackskid", "signed_dht_bot", "genddos_bot",
        "efimer", "freepbx_k_php", "condi",
    ):
        for rule in (FRAMEWORK / "malware" / family / "rules").glob("*.yar"):
            yara.compile(filepath=str(rule))


def test_batch13_publication_has_ten_unique_fixed_depth_cases() -> None:
    classification = json.loads((BATCH13 / "classification.json").read_text(encoding="utf-8"))
    samples = classification["samples"]
    assert len(samples) == 10
    assert len({sample["sha256"] for sample in samples}) == 10
    for sample in samples:
        version = sample["version"] or "unknown"
        case = REPOSITORY / "analysis-results/malware" / sample["family"] / "versions" / version / "cases" / sample["sha256"]
        metadata = json.loads((case / "metadata.json").read_text(encoding="utf-8"))
        assert metadata["sha256"] == sample["sha256"]
        assert metadata["malware_version"]["normalized_key"] == version
        assert "refresh" not in case.parts
        for filename in ("README.md", "metadata.json", "config.json", "iocs.json", "IOC-LIST.md"):
            assert (case / filename).is_file()


def test_batch13_connection_validation_preserves_safety_boundaries() -> None:
    validation = json.loads((BATCH13 / "c2-validation.json").read_text(encoding="utf-8"))
    assert validation["sample_count"] == 10
    assert validation["unique_probe_count"] == 12
    assert validation["policy"]["timeout_seconds"] == 3.0
    assert validation["policy"]["port_scanning"] is False
    assert validation["policy"]["tor_started"] is False
    candidates = [item for sample in validation["samples"] for item in sample["candidate_results"]]
    assert all(item["application_data_sent"] is False for item in candidates)
    assert all(item["banner_read"] is False for item in candidates)
    assert all(item["c2_confirmed"] is False for item in candidates)
    screen = next(item for item in validation["samples"] if item["family"] == "screenconnect-rmm")
    assert screen["candidate_results"][0]["role"] == "remote_management_relay_not_c2"
    jack = next(item for item in validation["samples"] if item["family"] == "jackskid")
    assert {item["port"] for item in jack["candidate_results"]} == {64409, 9018}


def test_batch13_shodan_results_are_passive_and_nonattributing() -> None:
    shodan = json.loads((BATCH13 / "shodan-hunt.json").read_text(encoding="utf-8"))
    assert len(shodan["queries"]) == 9
    assert len(shodan["internetdb_results"]) == 9
    statuses = [item["status"] for item in shodan["internetdb_results"]]
    assert statuses.count("ok") == 8
    assert statuses.count("http_404_not_found") == 1
    assert all(item["vulnerability_list_omitted"] is True for item in shodan["internetdb_results"])
    assert "悪性" in shodan["policy_note"]


def test_screenconnect_public_config_contains_only_redacted_key_evidence() -> None:
    path = (
        REPOSITORY / "analysis-results/malware/screenconnect-rmm/versions/v26.4.3.9662/cases"
        / SCREENCONNECT_SHA256 / "config.json"
    )
    config = json.loads(path.read_text(encoding="utf-8"))
    relay = config["relay"]
    assert config["malware_by_itself"] is False
    assert relay["tenant_key_length"] == 448
    assert relay["tenant_key_sha256"] == "8de7b8af2393dd81fbbdeb78790555bd417b01036f1130833ff19715a5490589"
    assert set(relay) == {
        "host", "port", "transport", "role", "c2_classification",
        "tenant_key_sha256", "tenant_key_length", "redacted_query",
    }


def test_registry_contains_all_new_reviewed_hashes() -> None:
    registry = json.loads((FRAMEWORK / "registry/malware_types.json").read_text(encoding="utf-8"))["malware_types"]
    assert registry["screenconnect_rmm"]["known_sample_sha256"] == [SCREENCONNECT_SHA256]
    assert registry["screenconnect_rmm"]["classification"] == "commercial_rmm_dual_use"
    assert JACK_ARM_SHA256 in registry["jackskid"]["known_sample_sha256"]
    assert JACK_AARCH64_SHA256 in registry["jackskid"]["known_sample_sha256"]
    assert SIGNED_ARMV7_SHA256 in registry["signed_dht_bot"]["known_sample_sha256"]


def test_screenconnect_osint_knowledge_is_registered_as_commercial_dual_use() -> None:
    knowledge = json.loads(
        (FRAMEWORK / "knowledge/malware_families/n_z.json").read_text(encoding="utf-8")
    )["families"]
    screen = next(item for item in knowledge if item["id"] == "screenconnect-rmm")
    assert screen["developer"]["assessment_ja"].startswith("製品の開発・提供主体はConnectWise")
    assert screen["commodity"]["classification"] == "commercial_service"
    assert screen["versioning"]["local_confirmed_case_count"] == 1
    actors = {item["name"] for item in screen["actors"]}
    assert {"MuddyWater", "ALPHV／BlackCat関係者", "Interlockランサムウェア運用者"} <= actors
