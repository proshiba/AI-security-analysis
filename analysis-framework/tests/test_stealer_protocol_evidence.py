from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import sys

MODULE_PATH = Path(__file__).parents[1] / "common" / "stealer_protocol_evidence.py"
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
    user_agent: str = "",
) -> str:
    return "\t".join(
        (
            str(frame), ip, str(port), host, method, uri, content_type,
            str(length), keys, disposition, user_agent,
        )
    )


def test_parser_keeps_names_and_hash_but_discards_values() -> None:
    rows = _row(
        7,
        uri="/gate?access_token=secret&step=1#fragment",
        keys="access_token;step;bad value",
        disposition='form-data;name="file";filename="private.zip"',
        user_agent="Reviewed-Agent/1.0",
    )
    request = MODULE.parse_tshark_rows(rows)[0]
    assert request.uri_path == "/gate"
    assert request.query_keys == ("access_token", "step")
    assert request.form_keys == ("access_token", "step")
    assert request.multipart_names == ("file",)
    assert request.user_agent_sha256 == hashlib.sha256(b"Reviewed-Agent/1.0").hexdigest()
    serialized = json.dumps(request.__dict__)
    assert "secret" not in serialized
    assert "private.zip" not in serialized
    assert "Reviewed-Agent" not in serialized


def _remus_rows(*, split_endpoint: bool = False, reverse: bool = False) -> str:
    registration_frame = 3 if reverse else 1
    step_frame = 1 if reverse else 3
    records = [
        _row(registration_frame, keys="tag;exp;hwid"),
        _row(2, keys="access_token;debug", host="other.test" if split_endpoint else "example.test"),
        _row(step_frame, keys="access_token;step"),
        _row(
            4,
            content_type="multipart/form-data; boundary=x",
            disposition=(
                'form-data;name="access_token";form-data;name="type";'
                'form-data;name="file";filename="data"'
            ),
        ),
    ]
    return "\n".join(records)


def test_remus_requires_ordered_sequence_on_one_endpoint() -> None:
    result = MODULE.classify_protocol(MODULE.parse_tshark_rows(_remus_rows()), "remusstealer")
    assert result["profile"] == "remus_http_token_task_file"
    assert result["confidence"] == "high"
    assert result["evidence"]["ordered_frames"] == [1, 2, 3, 4]
    assert result["active_probe_policy"] == "guarded_active_reviewed_profile_only"


def test_remus_rejects_cross_endpoint_and_reversed_false_positives() -> None:
    for rows in (_remus_rows(split_endpoint=True), _remus_rows(reverse=True)):
        result = MODULE.classify_protocol(MODULE.parse_tshark_rows(rows), "remusstealer")
        assert result["profile"] == "unclassified_http_sequence"
        assert result["confidence"] == "low"


def test_lumma_requires_ordered_registration_and_upload() -> None:
    rows = "\n".join(
        (
            _row(1, keys="uid;cid"),
            _row(2, method="GET", uri="/api/set_agent?id=x&token=y"),
            _row(
                3,
                content_type="multipart/form-data; boundary=x",
                disposition=(
                    'form-data;name="uid";form-data;name="pid";'
                    'form-data;name="hwid";form-data;name="file";filename="data"'
                ),
            ),
        )
    )
    result = MODULE.classify_protocol(MODULE.parse_tshark_rows(rows), "lummastealer")
    assert result["profile"] == "lumma_v6_compatible_uid_cid"
    assert result["evidence"]["browser_agent_path_between_steps"] is True


def test_stealc_needs_two_json_posts_on_same_endpoint_and_path() -> None:
    rows = "\n".join(
        (
            _row(1, content_type="application/json", uri="/gate"),
            _row(2, content_type="application/json", uri="/gate"),
        )
    )
    result = MODULE.classify_protocol(MODULE.parse_tshark_rows(rows), "stealc")
    assert result["profile"] == "stealc_v2_json_transport_compatible"
    cross_path = rows.replace("/gate", "/other", 1)
    assert MODULE.classify_protocol(
        MODULE.parse_tshark_rows(cross_path), "stealc"
    )["profile"] == "unclassified_http_sequence"


def test_amos_requires_matching_campaign_pair_on_one_endpoint() -> None:
    campaign = "a" * 64
    rows = "\n".join(
        (
            _row(1, uri=f"/ledger/{campaign}", content_type="application/octet-stream"),
            _row(2, uri=f"/ledger/live/{campaign}", content_type="application/octet-stream"),
        )
    )
    result = MODULE.classify_protocol(MODULE.parse_tshark_rows(rows), "amosstealer")
    assert result["profile"] == "amos_ledger_campaign_pair"
    assert result["confidence"] == "high"
    assert result["evidence"]["campaign_identifier_published"] is False
    mismatch = rows.replace("a" * 64, "b" * 64, 1)
    assert MODULE.classify_protocol(
        MODULE.parse_tshark_rows(mismatch), "amosstealer"
    )["profile"] == "unclassified_http_sequence"


def test_vidar_matches_only_exact_static_profile_and_user_agent_hash() -> None:
    user_agent = "Vidar-Reviewed-Agent/1.5"
    request = MODULE.parse_tshark_rows(
        _row(5, host="vidar.test", port=443, uri="/gate", user_agent=user_agent)
    )
    profile = {
        "family": "vidar",
        "profile": "vidar_repeated_xor_v1_5_plus",
        "version": "1.5",
        "build_id": "fixture",
        "records": [{"url": "https://vidar.test/gate", "tag": "x", "user_agent": user_agent}],
    }
    result = MODULE.classify_protocol(request, "vidar", profile)
    assert result["profile"] == "vidar_static_profile_endpoint_match"
    assert result["evidence"]["endpoint_value_published"] is False
    profile["records"][0]["user_agent"] = "different"
    assert MODULE.classify_protocol(request, "vidar", profile)["profile"] == "unclassified_http_sequence"


def test_formbook_remains_passive_without_terminal_wire_signature() -> None:
    result = MODULE.classify_protocol(MODULE.parse_tshark_rows(_row(1)), "formbook")
    assert result["profile"] == "formbook_xloader_terminal_protocol_not_observed"
    assert result["active_probe_policy"] == "passive_only"
    assert result["evidence"]["terminal_wire_signature_matched"] is False


def test_build_report_separates_socket_domain_and_keeps_privacy(tmp_path: Path) -> None:
    pcap = tmp_path / "fixture.pcapng"
    pcap.write_bytes(b"pcap-fixture")
    triage = tmp_path / "report.json"
    triage.write_text(
        json.dumps(
            {
                "sample": {"id": "fixture", "sha256": "a" * 64},
                "network": {"flows": [{"dst": "192.0.2.10:2535", "domain": "actual.example"}]},
            }
        ),
        encoding="utf-8",
    )
    request = MODULE.parse_tshark_rows(
        _row(1, ip="192.0.2.10", port=2535, host="microsoft.com", user_agent="secret-agent")
    )
    result = MODULE.build_report(pcap, request, family_hint="remusstealer", triage_report=triage)
    endpoint = result["endpoints"][0]
    assert endpoint["resolved_domains"] == ["actual.example"]
    assert endpoint["host_misdirection"] is True
    assert result["privacy"]["body_values_retained"] is False
    assert result["privacy"]["user_agent_values_retained"] is False
    assert "secret-agent" not in json.dumps(result)
