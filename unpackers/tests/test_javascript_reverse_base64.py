"""反転・区切り文字・Base64型JavaScript復元器のテスト。"""

from __future__ import annotations

import base64

import pytest

from unpackers import javascript_reverse_base64 as dropper


def _encode(payload: bytes, separator: str = "?") -> str:
    encoded = base64.b64encode(payload).decode()
    separated = separator.join(encoded)
    return separated[::-1]


def test_recovers_lua_layer_without_executing_javascript() -> None:
    payload = (
        b'local X="|0abc"\n'
        b'local F=require("\\102\\102\\105")\n'
        b"function PolyRot(E) return E end\n"
        b"NtAllocateVirtualMemory();RtlMoveMemory();"
        + b"A" * 5000
    )
    script = f"var layer='{_encode(payload)}';".encode()
    report, artifacts = dropper.recover_reverse_base64(script)
    assert report["status"] == "artifacts_recovered"
    assert report["executed"] is False
    assert artifacts == [("javascript-reverse-base64-lua", payload)]


def test_rejects_decoded_data_without_strict_artifact_shape() -> None:
    payload = b"ordinary data" * 1000
    script = f"var layer='{_encode(payload, '~')}';".encode()
    report, artifacts = dropper.recover_reverse_base64(script)
    assert report["status"] == "pattern_not_found"
    assert artifacts == []


def test_javascript_escape_decoder_is_bounded() -> None:
    assert dropper._decode_javascript_string(r"A\x42\u0043") == "ABC"
    with pytest.raises(ValueError):
        dropper._decode_javascript_string("\\x")
