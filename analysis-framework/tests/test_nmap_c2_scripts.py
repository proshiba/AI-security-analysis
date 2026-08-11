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
    assert len(mapped) == 11


def test_all_declared_scripts_exist_and_are_utf8() -> None:
    mapping = json.loads((NMAP_ROOT / "profiles.json").read_text(encoding="utf-8"))
    scripts = {entry["script"] for entry in mapping["canonical_families"]}
    assert len(scripts) == 8
    for relative in scripts:
        path = NMAP_ROOT / relative
        assert path.is_file()
        text = path.read_text(encoding="utf-8")
        assert "categories" in text
        assert "c2_confirmed" in text

    darkcomet = (NMAP_ROOT / "scripts" / "darkcomet-c2.nse").read_text(encoding="utf-8")
    assert "socket:send" not in darkcomet
    assert "quiet" not in darkcomet
    assert "receive_buf(match.numbytes(1), true)" in darkcomet
    assert "plain == \"IDTYPE\"" in darkcomet
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
    assert 'checkconnect_result=result_text' in redline
    assert "result and 0.98 or 0.95" in redline

    xloader = (NMAP_ROOT / "scripts" / "xloader-c2.nse").read_text(encoding="utf-8")
    assert 'require "nmap"' not in xloader
    assert "c2_confirmed=false" in xloader
    assert "application_data_sent=false" in xloader
    assert "candidate_spray_attempted=false" in xloader
    assert "registration_attempted=false" in xloader
    assert "network_contacted_by_nmap_scan=true" in xloader

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
    assert "result.confidence = exact and 0.92 or 0.35" in purerat_direct
    assert "result.c2_confirmed = exact" in purerat_direct
    assert "result.exact_profile_match = exact" in purerat_direct
    assert "result.family_c2_candidate = false" not in purerat_direct


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
    assert hashlib.sha256(request).hexdigest() == (
        "dd8c02ce792cd8d4e9ce3e05c32ff19c8d1633d24312203b9ec5018645e45f33"
    )


def test_nmap_loopback_protocol_validation() -> None:
    executable = _nmap_executable()
    if not executable:
        pytest.skip("Nmap executableがないためloopback統合試験を省略します")
    report = _load_validator().verify_all(executable)
    assert report["external_network_used"] is False
    assert report["case_count"] == 25
    assert report["passed_count"] == 25
