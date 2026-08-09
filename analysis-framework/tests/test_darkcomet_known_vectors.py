from __future__ import annotations

import sys
from pathlib import Path

COMMON = Path(__file__).parents[1] / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

from darkcomet_server_first_probe import (
    decode_server_first_response,
    rc4_crypt,
)


def test_static_reviewed_idtype_vector() -> None:
    key = b"#KCMDDC5#-"
    raw = bytes.fromhex("9A4EA882ADFD")
    assert rc4_crypt(b"IDTYPE", key) == raw
    assert rc4_crypt(raw, key) == b"IDTYPE"
    assert decode_server_first_response(raw, key)["matched"] is True
    assert decode_server_first_response(b"9A4EA882ADFD", key)["matched"] is True
    assert decode_server_first_response(b"9a4ea882adfd", key)["matched"] is True


def test_static_reviewed_non_idtype_vectors_do_not_confirm() -> None:
    key = b"#KCMDDC5#-"
    assert rc4_crypt(bytes.fromhex("804FAE8DB8EA"), key) == b"SERVER"
    assert rc4_crypt(bytes.fromhex("F041B99EADF99494F0BB98"), key) == b"#KEEPALIVE#"
    assert decode_server_first_response(bytes.fromhex("804FAE8DB8EA"), key)["matched"] is False
    assert decode_server_first_response(b"804FAE8DB8EA", key)["matched"] is False
    assert decode_server_first_response(bytes.fromhex("F041B99EADF99494F0BB98"), key)["matched"] is False
