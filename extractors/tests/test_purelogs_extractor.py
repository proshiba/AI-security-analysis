"""PureLogs静的extractorの回帰テスト。"""

from __future__ import annotations

import json

from extractors.purelogs import extract
from extractors.purelogs.extractor import endpoint_candidates


def test_extracts_corroborated_http_profile() -> None:
    """複数の固有pathで裏付けたC2だけを採用する。"""
    data = (
        b"https://logs.example.test:8443/ping\n"
        b"/plugin\n/userinfo\n/browser\n/filesearch/req\n/finish\n"
        b"protobuf-net\n"
    )
    result = extract(data, "decrypted-http.txt")
    assert result["config"]["variant"] == "purelogs_http_api"
    assert result["config"]["endpoints"] == ["logs.example.test:8443"]
    assert result["findings"][0]["confidence"] == "confirmed"
    assert result["network_contacted"] is False


def test_rejects_generic_browser_url() -> None:
    """一般的なbrowser文字列や単独URLをPureLogs C2に昇格させない。"""
    result = extract(b"https://example.test/browser", "generic.txt")
    assert result["config"]["variant"] == "unrecognized"
    assert result["config"]["endpoints"] == []
    assert result["findings"] == []


def test_endpoint_candidates_validate_ports() -> None:
    """不正portを除外し、URLの既定HTTPS portを補う。"""
    assert endpoint_candidates(
        "https://one.example/path two.example:56001 bad.example:70000"
    ) == ["one.example:443", "two.example:56001"]


def test_structured_evidence_excludes_secondary_purerat_channel() -> None:
    """???????PureRAT???PureLogs C2????????"""
    payload = {
        "channels": [
            {
                "role": "PureLogs HTTP API over TLS",
                "endpoint": "logs.example.test:8443",
            },
            {
                "role": "PureRAT/PureHVNC candidate binary channel over TLS",
                "endpoint": "rat.example.test:56001",
            },
        ],
        "observed_requests": ["/plugin", "/userinfo", "/filesearch/req", "/finish"],
    }
    result = extract(json.dumps(payload).encode(), "network-validation.json")
    assert result["config"]["variant"] == "purelogs_http_api"
    assert result["config"]["endpoints"] == ["logs.example.test:8443"]
    assert [item["value"] for item in result["findings"]] == ["logs.example.test:8443"]
