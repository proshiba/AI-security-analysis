"""StealC公開unpack証拠parserのbindingとfail-closed検証。"""

from __future__ import annotations

import copy
import hashlib
import json

import pytest

from extractors.stealc.public_unpack import (
    PublicUnpackEvidenceError,
    extract_public_unpack_evidence,
)

PARENT = "a" * 64
TERMINAL = "b" * 64
PROVIDER_ID = "fixture-result"


def fixture() -> dict:
    """親と一意の終端StealC configを持つ最小provider結果。"""
    return {
        "id": PROVIDER_ID,
        "status": "complete",
        "sha256": PARENT,
        "results": [
            {
                "hashes": {"sha256": PARENT},
                "analysis": {"metadata": {"Size": 100}},
            },
            {
                "hashes": {"sha256": TERMINAL},
                "analysis": {"metadata": {"Size": 6914048}},
                "config": {
                    "extractor_name": "static_stealc",
                    "sha256": TERMINAL,
                    "rule_name": "stealc",
                    "config": {
                        "c2s": [
                            {"type": "ip", "value": "192.0.2.10"},
                            {"type": "url", "value": "http://192.0.2.10/gate.php"},
                        ],
                        "settings": [
                            {"name": "server_url", "value": "http://192.0.2.10"},
                            {"name": "landing_path", "value": "/gate.php"},
                            {"name": "lib_path", "value": "/deps/"},
                            {"name": "botnet_id", "value": "fixture"},
                        ],
                        "decrypted_strings": [
                            {"offset": 2, "value": "hwid"},
                            {"offset": 1, "value": "POST"},
                        ],
                    },
                },
            },
        ],
    }


def raw_sha(payload: dict) -> str:
    return hashlib.sha256(
        json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def extract(payload: dict | None = None, **overrides: str) -> dict:
    document = payload or fixture()
    actual = raw_sha(document)
    return extract_public_unpack_evidence(
        document,
        overrides.get("parent", PARENT),
        expected_provider_result_id=overrides.get("provider_id", PROVIDER_ID),
        expected_provider_json_sha256=overrides.get("expected_json_sha", actual),
        actual_provider_json_sha256=overrides.get("actual_json_sha", actual),
    )


def test_extracts_bound_terminal_config_and_normalized_string_digest() -> None:
    result = extract()
    terminal = result["terminal_payload"]
    assert terminal["sha256"] == TERMINAL
    assert terminal["bytes_available"] is False
    assert terminal["config"]["c2_url"] == "http://192.0.2.10/gate.php"
    assert terminal["config"]["decrypted_string_count"] == 2
    assert len(terminal["config"]["decrypted_strings_normalized_sha256"]) == 64
    assert result["evidence_binding"]["provider_result_id"] == PROVIDER_ID
    assert result["trust_boundary"]["terminal_bytes_independently_verified"] is False
    assert result["c2_assessment"]["active_probe_status"] == "protocol_profile_required"


def test_normalized_string_digest_is_order_independent() -> None:
    first = fixture()
    second = fixture()
    second["results"][1]["config"]["config"]["decrypted_strings"].reverse()
    assert (
        extract(first)["terminal_payload"]["config"][
            "decrypted_strings_normalized_sha256"
        ]
        == extract(second)["terminal_payload"]["config"][
            "decrypted_strings_normalized_sha256"
        ]
    )


def test_rejects_parent_provider_id_and_raw_json_mismatch() -> None:
    with pytest.raises(PublicUnpackEvidenceError, match="対象親"):
        extract(parent="c" * 64)
    with pytest.raises(PublicUnpackEvidenceError, match="result ID"):
        extract(provider_id="different-result")
    with pytest.raises(PublicUnpackEvidenceError, match="JSON SHA-256"):
        extract(expected_json_sha="c" * 64)


def test_rejects_config_hash_mismatch() -> None:
    payload = fixture()
    payload["results"][1]["config"]["sha256"] = "c" * 64
    with pytest.raises(PublicUnpackEvidenceError, match="一致しません"):
        extract(payload)


def test_rejects_conflicting_terminal_configs() -> None:
    payload = fixture()
    second = copy.deepcopy(payload["results"][1])
    second["hashes"]["sha256"] = "c" * 64
    second["config"]["sha256"] = "c" * 64
    payload["results"].append(second)
    with pytest.raises(PublicUnpackEvidenceError, match="一意"):
        extract(payload)


@pytest.mark.parametrize(
    "bad_row, expected",
    [
        ({"offset": 1, "value": None}, "value"),
        ({"offset": 1, "value": ""}, "value"),
        ({"offset": "1", "value": "x"}, "offset"),
        ({"offset": -1, "value": "x"}, "offset"),
    ],
)
def test_rejects_invalid_decrypted_string_elements(
    bad_row: dict, expected: str
) -> None:
    payload = fixture()
    payload["results"][1]["config"]["config"]["decrypted_strings"] = [bad_row]
    with pytest.raises(PublicUnpackEvidenceError, match=expected):
        extract(payload)


def test_rejects_duplicate_offsets_and_count_overflow() -> None:
    payload = fixture()
    payload["results"][1]["config"]["config"]["decrypted_strings"] = [
        {"offset": 1, "value": "a"},
        {"offset": 1, "value": "b"},
    ]
    with pytest.raises(PublicUnpackEvidenceError, match="重複"):
        extract(payload)
    payload = fixture()
    payload["results"][1]["config"]["config"]["decrypted_strings"] = [
        {"offset": index, "value": "x"} for index in range(4097)
    ]
    with pytest.raises(PublicUnpackEvidenceError, match="上限"):
        extract(payload)


def test_rejects_credentials_in_server_url() -> None:
    payload = fixture()
    payload["results"][1]["config"]["config"]["settings"][0]["value"] = (
        "http://user:pass@192.0.2.10"
    )
    with pytest.raises(PublicUnpackEvidenceError, match="許可範囲外"):
        extract(payload)


def test_rejects_coerced_provider_and_config_scalar_types() -> None:
    payload = fixture()
    payload["id"] = 123
    with pytest.raises(PublicUnpackEvidenceError, match="文字列"):
        extract(payload)

    payload = fixture()
    payload["results"][1]["analysis"]["metadata"]["Size"] = True
    with pytest.raises(PublicUnpackEvidenceError, match="整数"):
        extract(payload)

    payload = fixture()
    payload["results"][1]["config"]["config"]["settings"][3]["value"] = 123
    with pytest.raises(PublicUnpackEvidenceError, match="文字列"):
        extract(payload)

    payload = fixture()
    payload["results"][1]["config"]["config"]["c2s"][0]["value"] = 123
    with pytest.raises(PublicUnpackEvidenceError, match="文字列"):
        extract(payload)


def test_rejects_server_url_port_zero() -> None:
    payload = fixture()
    payload["results"][1]["config"]["config"]["settings"][0]["value"] = (
        "http://192.0.2.10:0"
    )
    with pytest.raises(PublicUnpackEvidenceError, match="許可範囲外"):
        extract(payload)
