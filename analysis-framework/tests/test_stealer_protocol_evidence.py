from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path


MODULE_PATH = (
    Path(__file__).parents[1] / "common" / "stealer_protocol_evidence.py"
)
SPEC = importlib.util.spec_from_file_location("stealer_protocol_evidence", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def _row(
    frame: int,
    *,
    ip: str = "192.0.2.10",
    port: int = 8080,
    host: str = "example.test",
    method: str = "POST",
    uri: str = "/?token=secret",
    content_type: str = "application/x-www-form-urlencoded",
    length: int = 64,
    keys: str = "",
    disposition: str = "",
) -> str:
    return "\t".join(
        (
            str(frame),
            ip,
            str(port),
            host,
            method,
            uri,
            content_type,
            str(length),
            keys,
            disposition,
        )
    )


def test_parser_keeps_names_but_discards_query_and_values() -> None:
    rows = _row(
        7,
        uri="/gate?access_token=secret#fragment",
        keys="access_token;step;bad value",
        disposition='form-data;name="file";filename="private.zip"',
    )
    request = MODULE.parse_tshark_rows(rows)[0]
    assert request.uri_path == "/gate"
    assert request.form_keys == ("access_token", "step")
    assert request.multipart_names == ("file",)
    serialized = json.dumps(request.__dict__)
    assert "secret" not in serialized
    assert "private.zip" not in serialized


def test_remus_sequence_requires_registration_task_and_upload() -> None:
    rows = "\n".join(
        (
            _row(1, keys="tag;exp;hwid"),
            _row(2, keys="access_token;debug"),
            _row(3, keys="access_token;step"),
            _row(
                4,
                content_type="multipart/form-data; boundary=x",
                keys="",
                disposition=(
                    'form-data;name="access_token";'
                    'form-data;name="type";'
                    'form-data;name="file";filename="data"'
                ),
            ),
        )
    )
    result = MODULE.classify_protocol(
        MODULE.parse_tshark_rows(rows), "remusstealer"
    )
    assert result["profile"] == "remus_http_token_task_file"
    assert result["confidence"] == "high"
    assert result["active_probe_policy"] == "guarded_active_reviewed_profile_only"


def test_lumma_v6_compatible_sequence_and_optional_browser_agent() -> None:
    rows = "\n".join(
        (
            _row(1, keys="uid;cid"),
            _row(2, method="GET", uri="/api/set_agent?id=x&token=y"),
            _row(
                3,
                content_type="multipart/form-data; boundary=x",
                keys="",
                disposition=(
                    'form-data;name="uid";form-data;name="pid";'
                    'form-data;name="hwid";form-data;name="file";filename="data"'
                ),
            ),
        )
    )
    result = MODULE.classify_protocol(
        MODULE.parse_tshark_rows(rows), "lummastealer"
    )
    assert result["profile"] == "lumma_v6_compatible_uid_cid"
    assert result["evidence"]["browser_agent_path"] is True
    assert result["active_probe_policy"] == "guarded_active_reviewed_profile_only"


def test_build_report_separates_socket_domain_from_http_host(tmp_path: Path) -> None:
    pcap = tmp_path / "fixture.pcapng"
    pcap.write_bytes(b"pcap-fixture")
    triage = tmp_path / "report.json"
    triage.write_text(
        json.dumps(
            {
                "sample": {"id": "fixture", "sha256": "a" * 64},
                "network": {
                    "flows": [
                        {
                            "dst": "192.0.2.10:2535",
                            "domain": "actual.example",
                        }
                    ]
                },
            }
        ),
        encoding="utf-8",
    )
    request = MODULE.parse_tshark_rows(
        _row(1, ip="192.0.2.10", port=2535, host="microsoft.com")
    )
    result = MODULE.build_report(
        pcap, request, family_hint="remusstealer", triage_report=triage
    )
    endpoint = result["endpoints"][0]
    assert endpoint["resolved_domains"] == ["actual.example"]
    assert endpoint["http_host"] == "microsoft.com"
    assert endpoint["host_misdirection"] is True
    assert result["privacy"]["body_values_retained"] is False
