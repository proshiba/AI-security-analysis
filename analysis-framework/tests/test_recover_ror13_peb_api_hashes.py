"""ROR13 PEB APIハッシュと接続先候補の静的復元テスト。"""

from __future__ import annotations

import importlib.util
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "common" / "recover_ror13_peb_api_hashes.py"
SPEC = importlib.util.spec_from_file_location("recover_ror13_peb_api_hashes", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
REVIEW = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(REVIEW)


def test_known_export_hashes() -> None:
    assert REVIEW.api_hash("kernel32.dll", "LoadLibraryA") == 0x0726774C
    assert REVIEW.api_hash("ws2_32.dll", "WSAStartup") == 0x006B8029
    assert REVIEW.api_hash("ws2_32.dll", "connect") == 0x6174A599


def test_endpoint_remains_candidate_with_provenance() -> None:
    fragments = [{"text": text} for text in ("149.", "104.", "28.2", "04", "8.0")]
    ports = [{"port": 8084, "address": "0x1000"}]
    matches = [
        {"exports": [name]}
        for name in (
            "ws2_32.dll!connect",
            "ws2_32.dll!inet_addr",
            "user32.dll!wsprintfA",
        )
    ]
    result = REVIEW.endpoint_candidate(fragments, ports, matches)
    assert result is not None
    assert result["host"] == "149.104.28.204"
    assert result["port"] == 8084
    assert result["confidence"] == "static_candidate_dataflow_review_required"
    assert result["evidence"]["stack_fragments"] == ["149.", "104.", "28.2", "04"]
    assert REVIEW.endpoint_candidate(fragments, ports + [{"port": 443}], matches) is None
    assert REVIEW.endpoint_candidate(fragments, ports, matches[:2]) is None
