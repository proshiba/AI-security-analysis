"""clipboard文字列復元式の境界と非実行性を確認する。"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "common"))
from recover_clipboard_xor_strings import decode_blob


def test_two_series_xor_recovers_ascii_without_executing_sample() -> None:
    value = b"bc1qg73sq2pz05hrcfdxul4kemq5kuew0wtekgzxxp"
    key = b"ABCD"
    blob = bytearray(key)
    blob.extend(byte ^ key[index % 4] for index, byte in enumerate(value))
    blob.extend(b"\0" * 16)
    assert decode_blob(bytes(blob), len(value)) == value.decode("ascii")


def test_decode_bounds_fail_closed() -> None:
    with pytest.raises(ValueError, match="上限外"):
        decode_blob(b"", 121)
    with pytest.raises(ValueError, match="PE領域外"):
        decode_blob(b"ABCD", 30)
