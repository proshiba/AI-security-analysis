from __future__ import annotations

import hashlib
import importlib.util
import json
import shutil
import subprocess
from pathlib import Path

import pytest

FRAMEWORK = Path(__file__).resolve().parents[1]
NMAP_ROOT = FRAMEWORK / "nmap"
CENTRAL_PROFILES = FRAMEWORK / "common" / "c2_protocol_probe_profiles.json"


def _load_validator():
    path = NMAP_ROOT / "verify_nse.py"
    spec = importlib.util.spec_from_file_location("nmap_verify_nse", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _nmap_executable() -> str | None:
    local = Path(r"C:\Users\Administrator\Tools\Nmap\nmap.exe")
    if local.is_file():
        return str(local)
    return shutil.which("nmap")


def test_profiles_cover_reviewed_active_families() -> None:
    mapping = json.loads((NMAP_ROOT / "profiles.json").read_text(encoding="utf-8"))
    central = json.loads(CENTRAL_PROFILES.read_text(encoding="utf-8"))
    mapped = {entry["family"] for entry in mapping["canonical_families"]}
    reviewed = {entry["family"] for entry in central["profiles"]}
    assert reviewed <= mapped
    assert "purehvnc" in mapped
    assert "darkcomet" in mapped
    assert "redlinestealer" in mapped
    assert "xloader" in mapped
    assert {"formbook", "vidar", "amosstealer"} <= mapped
    assert len(mapped) == 15

    passive = {entry["family"]: entry for entry in mapping["passive_only_families"]}
    assert set(passive) == {"formbook", "xloader"}
    assert all(entry["offline_detector"].endswith("stealer_protocol_evidence.py") for entry in passive.values())
    assert all(entry["application_layer_requests_allowed"] is False for entry in passive.values())
    assert all(
        set(entry["allowed_external_methods"])
        == {
            "dns_resolve",
            "tcp_connect",
            "passive_banner",
            "tls_handshake",
            "protocol_profile_required",
        }
        for entry in passive.values()
    )
    probable = {entry["family"]: entry for entry in mapping["profile_limited_probable_families"]}
    assert set(probable) == {"vidar", "amosstealer"}
    assert probable["vidar"]["maximum_request_count"] == 2
    assert probable["amosstealer"]["maximum_request_count"] == 3
    assert all(entry["request_method"] == "HEAD" for entry in probable.values())
    assert all(entry["request_body_sent"] is False for entry in probable.values())
    assert all(entry["confirmation_allowed"] is False for entry in probable.values())

    assert mapping["schema_version"] == 2
    assert mapping["execution_backend"] == "nmap_nse_only"
    methods = {entry["method"] for entry in mapping["method_bindings"]}
    assert len(methods) == mapping["network_method_count"] == 20
    blocked = set(mapping["passive_only_application_methods"])
    assert blocked == {
        "formbook_reviewed_route_head",
        "xloader_v8_get_registration",
    }
    assert not blocked & methods


def test_pure_catalog_separates_protocol_generations_and_evidence_scope() -> None:
    """PureLogs世代とPureRAT family/sample証拠を機械可読に分離する。"""

    mapping = json.loads((NMAP_ROOT / "profiles.json").read_text(encoding="utf-8"))
    families = {entry["family"]: entry for entry in mapping["canonical_families"]}

    purelogs = families["purelogs"]
    variants = {entry["variant"]: entry for entry in purelogs["protocol_variants"]}
    assert set(variants) == {"legacy_socket_3des", "http_aes_v5"}
    assert variants["legacy_socket_3des"] == {
        "variant": "legacy_socket_3des",
        "transport": "raw_socket",
        "cryptography": "TripleDES",
        "evidence_scope": "family_level_public_research",
        "evidence_sources": [
            "https://any.run/cybersecurity-blog/pure-malware-family-analysis/",
            ("https://www.fortinet.com/uk/blog/threat-research/purelogs-delivery-via-pawsrunner-steganography"),
        ],
        "nmap_probe_available": False,
        "codec_implemented": False,
        "reason": "公開資料だけでは全field、鍵導出、方向別変換を確定できない",
    }
    assert variants["http_aes_v5"]["sample_version_confirmed"] is False
    assert variants["http_aes_v5"]["nmap_probe_scope"] == "reviewed_https_ping_only"

    purerat = families["purehvnc"]["protocol_variants"]
    assert len(purerat) == 1
    legacy = purerat[0]
    assert legacy["family_evidence_version"] == "4.1.9"
    assert legacy["family_evidence_status"] == "family_level_public_research_confirmed"
    assert legacy["profile_sample_version"] == "4.4.1"
    assert legacy["profile_sample_sha256"] == ("e55412555b4699c6d3ce2ac60df81eb1ee0d5aa412a303555c8f64037d5633d0")
    assert legacy["profile_sample_wire_binding_status"] == "unverified"


def test_nmap_readme_keeps_pure_generation_evidence_boundaries() -> None:
    text = (NMAP_ROOT / "README.md").read_text(encoding="utf-8")
    for marker in (
        "`legacy_socket_3des`",
        "`http_aes_v5`",
        "v4.1.9のfamily-level",
        "e554 v4.4.1個別検体",
        "旧世代codecを実装しません",
    ):
        assert marker in text


def test_all_declared_scripts_exist_and_are_utf8() -> None:
    mapping = json.loads((NMAP_ROOT / "profiles.json").read_text(encoding="utf-8"))
    scripts = {entry["script"] for entry in mapping["canonical_families"]}
    scripts.update(entry["script"] for entry in mapping["method_bindings"])
    assert len(scripts) == 13
    for relative in scripts:
        path = NMAP_ROOT / relative
        assert path.is_file()
        text = path.read_text(encoding="utf-8")
        assert "categories" in text
        assert "c2_confirmed" in text

    valleyrat = (NMAP_ROOT / "scripts" / "valleyrat-c2.nse").read_text(encoding="utf-8")
    assert "response:sub(1, #frame) == frame" in valleyrat
    assert 'status="winos_request_reflected"' in valleyrat
    assert "request_reflected=true" in valleyrat

    darkcomet = (NMAP_ROOT / "scripts" / "darkcomet-c2.nse").read_text(encoding="utf-8")
    assert "socket:send" not in darkcomet
    assert "quiet" not in darkcomet
    assert "receive_buf(match.numbytes(1), true)" in darkcomet
    assert 'plain == "IDTYPE"' in darkcomet
    assert 'deadline_scope="post_dns_connect_receive"' in darkcomet

    redline = (NMAP_ROOT / "scripts" / "redline-c2.nse").read_text(encoding="utf-8")
    assert redline.count("socket:send(request)") == 1
    assert "192.144.32.84" in redline
    assert "MAX_RESPONSE_BYTES = 4096" in redline
    assert "PRODUCTION_REQUEST_SIZE = 357" in redline
    assert "dd8c02ce792cd8d4e9ce3e05c32ff19c8d1633d24312203b9ec5018645e45f33" in redline
    assert "redline.acknowledge-profile" in redline
    assert 'require "http"' not in redline
    assert "redirect_followed=false" in redline
    assert "task_executed=false" in redline
    assert "sample_executed=false" in redline
    assert "application_data_sent=true" in redline
    assert "c2_confirmed=matched" in redline
    assert "checkconnect_result=result_text" in redline
    assert "result and 0.98 or 0.95" in redline

    stealer = (NMAP_ROOT / "scripts" / "stealer-http-c2.nse").read_text(encoding="utf-8")
    assert "redirect_ok=false" in stealer
    assert "max_body_size=65536" in stealer
    assert stealer.count("request_count=1") == 3
    assert stealer.count("response_body_published=false") == 3
    assert stealer.count("redirect_followed=false") == 3
    assert "#response.body >= 41 and #response.body <= 8192" in stealer
    assert 'content_type:match("application/octet%-stream")' in stealer

    xloader = (NMAP_ROOT / "scripts" / "xloader-c2.nse").read_text(encoding="utf-8")
    assert 'require "nmap"' not in xloader
    assert "c2_confirmed=false" in xloader
    assert "application_data_sent=false" in xloader
    assert "candidate_spray_attempted=false" in xloader
    assert "registration_attempted=false" in xloader
    assert "network_contacted_by_nmap_scan=true" in xloader
    assert 'stdnse.get_script_args("xloader.variant")' in xloader
    assert "formbook_terminal_profile_required_tcp_open_only" in xloader

    route = (NMAP_ROOT / "scripts" / "stealer-route-c2.nse").read_text(encoding="utf-8")
    assert 'mode ~= "formbook" and mode ~= "vidar" and mode ~= "amos"' in route
    assert 'stdnse.get_script_args("stealer-route.profile-id")' in route
    assert 'stdnse.get_script_args("stealer-route.acknowledge-profile")' in route
    assert 'stdnse.get_script_args("stealer-route.expected-ip")' in route
    assert '"HEAD " .. path .. " HTTP/1.1\\r\\n"' in route
    assert "MAX_HEADER_BYTES = 4096" in route
    assert "MAX_REQUEST_BYTES = 512" in route
    assert "3bb64d86bed8337443f4b6f6c981914dd7d94b6fa7b61709015f9698e13bc67c" in route
    assert "3f79dba83a2059c77f593c3247acf8f3d2b4c3e8a60f9ba1a656d0c04e600948" in route
    assert "6f33360d3a3dc60454a64d74e1ac586f6a184b3886df46471b10e520c5fe0644" in route
    assert "8809d3421c09669f88330adf3007b933abec13bf6ed105a785a97c7df2625301" in route
    assert "47cd98c6ae435a1a6aa518e29f9e407ca42c82c9f4b86ceee93cc85d7feeae98" in route
    assert route.count("socket:send(request)") == 1
    assert 'profile.tls and "ssl" or "tcp"' in route
    assert "vidar_reviewed_route_pair_match" in route
    assert "formbook_reviewed_route_pair_match" in route
    assert "amos_reviewed_ledger_pair_match" in route
    assert "confidence=0.60" in route
    assert "confidence=0.65" in route
    assert "c2_confirmed=false" in route
    assert "request_body_sent=false" in route
    assert "victim_metadata_sent=false" in route
    assert "redirect_followed=false" in route
    assert "registration_attempted=false" in route
    assert "task_executed=false" in route
    assert "payload_download_attempted=false" in route

    purerat_direct = (NMAP_ROOT / "scripts" / "purerat-direct-tls.nse").read_text(encoding="utf-8")
    assert 'socket:connect(host.ip, port.number, "ssl")' in purerat_direct
    assert "socket:send" not in purerat_direct
    assert "reconnect_ssl" not in purerat_direct
    assert "get_ssl_certificate" in purerat_direct
    assert "45.192.211.77" in purerat_direct
    assert "d025a29613e300d7755f878eb1d23d8a8a042cb2d3eb9005d66664ab9b97c677" in purerat_direct
    assert "df0359edefe34a970af39227978dbe7f1caa09caf98a2c6db53f49187ec25dd7" in purerat_direct
    assert "b3ae061b0b14a89d5134c279775b8f77a42214323c6bddab07f4d81ca2fc5c57" in purerat_direct
    assert "tls_version_enforced_by_nse=false" in purerat_direct
    assert "plaintext_prelude_sent=false" in purerat_direct
    assert "application_data_sent=false" in purerat_direct
    assert "certificate_mismatch_excludes_c2=false" in purerat_direct
    assert "certificate_mismatch_excludes_exact_build_endpoint=true" in purerat_direct
    assert "certificate_mismatch_excludes_family_c2=false" in purerat_direct
    assert "purerat_direct_tls_certificate_mismatch_inconclusive" in purerat_direct
    assert "result.confidence = exact and 0.75 or 0.0" in purerat_direct
    assert "result.c2_confirmed = false" in purerat_direct
    assert "result.probable_c2 = exact" in purerat_direct
    assert "result.exact_profile_match = false" in purerat_direct
    assert "result.certificate_profile_match = exact" in purerat_direct
    assert "result.family_c2_candidate = false" not in purerat_direct

    purelogs = (NMAP_ROOT / "scripts" / "purelogs-c2.nse").read_text(encoding="utf-8")
    assert "purelogs-0f2abaab-logs-uvexio-8443-ping-v1" in purelogs
    assert 'variant="http_aes_v5"' in purelogs
    assert 'generation_evidence_scope="family_level_public_research"' in purelogs
    assert "sample_version_confirmed=false" in purelogs
    assert 'excluded_variant="legacy_socket_3des"' in purelogs
    assert "legacy_codec_implemented=false" in purelogs
    assert "logs.uvexio.com" in purelogs
    assert "193.26.115.118" in purelogs
    assert "8443" in purelogs
    assert "9e254cab8c68944cea18a3ac5523fe491eb14f9447b352dca33729b64eaeeac3" in purelogs
    assert 'stdnse.get_script_args("purelogs.profile-id")' in purelogs
    assert 'stdnse.get_script_args("purelogs.acknowledge-profile")' in purelogs
    assert 'stdnse.get_script_args("purelogs.expected-host")' in purelogs
    assert 'stdnse.get_script_args("purelogs.expected-ip")' in purelogs
    assert 'stdnse.get_script_args("purelogs.expected-cert")' in purelogs
    assert '"GET /ping HTTP/1.1\\r\\nHost: " .. REVIEWED_HOST' in purelogs
    assert "MAX_RESPONSE_BYTES = 1024" in purelogs
    assert 'match.pattern_limit("\\r\\n\\r\\n", MAX_HEADER_BYTES)' in purelogs
    assert "socket:receive_bytes(2)" in purelogs
    assert purelogs.count("socket:send(request)") == 1
    assert 'require "http"' not in purelogs
    assert "redirect_followed=false" in purelogs
    assert "response_body_published=false" in purelogs
    assert 'response_hash_scope="http_body"' in purelogs
    assert "request_body_sent=false" in purelogs
    assert "tls_version_enforced_by_nse=false" in purelogs
    assert "result.c2_confirmed = false" in purelogs
    assert "result.probable_c2 = matched" in purelogs
    assert "matched and 0.70 or 0.0" in purelogs

    purerat_legacy = (NMAP_ROOT / "scripts" / "purerat-c2.nse").read_text(encoding="utf-8")
    assert 'stdnse.get_script_args("purerat.profile-id")' in purerat_legacy
    assert 'stdnse.get_script_args("purerat.acknowledge-profile")' in purerat_legacy
    assert 'stdnse.get_script_args("purerat.expected-host")' in purerat_legacy
    assert 'stdnse.get_script_args("purerat.expected-cert")' in purerat_legacy
    assert "purerat.ports" not in purerat_legacy
    assert "port.number == 56001 or port.number == 56002 or port.number == 56003" in purerat_legacy
    assert "tirakian.com" in purerat_legacy
    assert "67260a713ab105197098882f6d126f89fe4f48df8013f8bba1d2c9307b17410b" in purerat_legacy
    assert "compatibility_hypothesis=true" in purerat_legacy
    assert "tls_version_enforced_by_nse=false" in purerat_legacy
    assert "result.c2_confirmed = false" in purerat_legacy
    assert "result.probable_c2 = exact" in purerat_legacy
    assert "exact and 0.60 or 0.0" in purerat_legacy
    assert purerat_legacy.count("socket:send(string.char(4, 0, 0, 0))") == 1


def test_purerat_direct_tls_nse_script_help_parses_offline() -> None:
    executable = _nmap_executable()
    if not executable:
        pytest.skip("Nmap executableがないためNSE offline構文検証を省略します")
    script = NMAP_ROOT / "scripts" / "purerat-direct-tls.nse"
    completed = subprocess.run(
        [executable, "--script-help", str(script)],
        capture_output=True,
        timeout=20,
        check=False,
    )
    output = (completed.stdout + completed.stderr).decode("utf-8", errors="replace")
    assert completed.returncode == 0, output
    assert "purerat-direct-tls" in output


@pytest.mark.parametrize("script_name", ["purelogs-c2.nse", "purerat-c2.nse"])
def test_pure_family_nse_script_help_parses_offline(script_name: str) -> None:
    executable = _nmap_executable()
    if not executable:
        pytest.skip("Nmap executableがないためNSE offline構文検証を省略します")
    script = NMAP_ROOT / "scripts" / script_name
    completed = subprocess.run(
        [executable, "--script-help", str(script)],
        capture_output=True,
        timeout=20,
        check=False,
    )
    output = (completed.stdout + completed.stderr).decode("utf-8", errors="replace")
    assert completed.returncode == 0, output
    assert script.stem in output


def test_redline_production_request_vector_is_exact() -> None:
    body = (
        b'<?xml version="1.0" encoding="utf-8"?>'
        b'<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">'
        b'<s:Body><CheckConnect xmlns="http://tempuri.org/" /></s:Body></s:Envelope>'
    )
    request = (
        b"POST / HTTP/1.1\r\nHost: 192.144.32.84:16383\r\n"
        b"Content-Type: text/xml; charset=utf-8\r\n"
        b'SOAPAction: "http://tempuri.org/Endpoint/CheckConnect"\r\n'
        + f"Content-Length: {len(body)}\r\n".encode("ascii")
        + b"Connection: close\r\n\r\n"
        + body
    )
    assert len(request) == 357
    assert hashlib.sha256(request).hexdigest() == ("dd8c02ce792cd8d4e9ce3e05c32ff19c8d1633d24312203b9ec5018645e45f33")


def test_nmap_loopback_protocol_validation() -> None:
    executable = _nmap_executable()
    if not executable:
        pytest.skip("Nmap executableがないためloopback統合試験を省略します")
    report = _load_validator().verify_all(executable)
    assert report["external_network_used"] is False
    assert report["case_count"] == 40
    assert report["passed_count"] == 40
