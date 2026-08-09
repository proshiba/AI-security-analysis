from __future__ import annotations

import hashlib
import importlib.util
import json
import shutil
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
