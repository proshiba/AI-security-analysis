"""Tests for bounded JavaScript/PowerShell dropper reconstruction."""

from __future__ import annotations

import gzip

from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad
import pytest

from unpackers import javascript_dropper_unpacker as dropper


def _numbers(values: bytes) -> str:
    return ",".join(str(value) for value in values)


def test_xor_concat_environment_payload(monkeypatch: pytest.MonkeyPatch) -> None:
    """Recover a direct Unicode environment-variable PE recipe."""
    payload = b"MZ" + b"P" * 126
    encoded_payload = "".join(chr(19968 + value) for value in payload)
    powershell = "$x=($env:a+$env:b);[Reflection.Assembly]::Load($x)"
    key = 7
    encoded_script = bytes(value ^ key for value in powershell.encode())
    split = len(encoded_script) // 2
    script = f'''var O={{}};
O["first"]=[{_numbers(encoded_script[:split])}];
O["second"]=[{_numbers(encoded_script[split:])}];
var A=O["first"].concat(O["second"]);
var K="{chr(19968 + key)}";
var V=A[i] ^ (K.charCodeAt(i % K.length) - 19968);
var E={{}};
E["one"]=["a","{encoded_payload[:64]}"];
E["two"]=["b","{encoded_payload[64:]}"];
'''.encode("utf-16")
    monkeypatch.setattr(dropper, "_is_valid_pe", lambda _: True)
    report, artifacts = dropper.recover_javascript_dropper(script)
    assert report["status"] == "pe_recovered"
    assert report["payload"]["chunks"] == 2
    assert artifacts[-1][1] == payload


def test_subtract_aes_gzip_payload(monkeypatch: pytest.MonkeyPatch) -> None:
    """Recover the bounded Unicode, AES-CBC, and GZip transform chain."""
    payload = b"MZ" + b"Q" * 126
    key, iv = bytes(range(16)), bytes(range(16, 32))
    ciphertext = AES.new(key, AES.MODE_CBC, iv).encrypt(
        pad(gzip.compress(payload), AES.block_size)
    )
    encoded_payload = "".join(chr(19968 + value) for value in ciphertext)
    powershell = (
        "$x=($env:a+$env:b);$c=New-Object AesManaged;"
        f"$c.Key=[byte[]]@({_numbers(key)});"
        f"$c.IV=[byte[]]@({_numbers(iv)});"
        "GZipStream;" + " " * 1200
    )
    delta = 3
    encoded_script = bytes((value + delta) & 0xFF for value in powershell.encode())
    script = f'''var A=[{_numbers(encoded_script)}];
var K="{chr(19968 + delta)}";
var V=(A[i] - (K.charCodeAt(i % K.length) - 19968) + 256) & 255;
X("a") = "{encoded_payload[: len(encoded_payload) // 2]}";
X("b") = "{encoded_payload[len(encoded_payload) // 2 :]}";
'''.encode()
    monkeypatch.setattr(dropper, "_is_valid_pe", lambda _: True)
    report, artifacts = dropper.recover_javascript_dropper(script)
    assert report["status"] == "pe_recovered"
    assert report["payload"]["transforms"] == [
        "unicode_minus_19968",
        "aes_cbc_pkcs7",
        "gzip",
    ]
    assert artifacts[-1][1] == payload


def test_invalid_aes_parameters_are_reported() -> None:
    """Reject malformed embedded AES parameters without aborting analysis."""
    powershell = (
        "$x=($env:a);$c=New-Object AesManaged;"
        "$c.Key=[byte[]]@(1,2);$c.IV=[byte[]]@(1,2);" + " " * 1200
    )
    delta = 5
    encoded_script = bytes((value + delta) & 0xFF for value in powershell.encode())
    script = f"""var A=[{_numbers(encoded_script)}];
var K="{chr(19968 + delta)}";
var V=(A[i] - (K.charCodeAt(i % K.length) - 19968) + 256) & 255;
X("a") = "{chr(19968)}";
""".encode()
    report, artifacts = dropper.recover_javascript_dropper(script)
    assert report["status"] == "powershell_recovered"
    assert report["payload"]["status"] == "aes_parameters_invalid"
    assert len(artifacts) == 1


def test_large_unterminated_arrays_are_rejected_without_backtracking() -> None:
    """Keep malformed large JavaScript arrays on a linear-time no-match path."""
    script = (
        'O["first"]=[' + '1,' * 100_000 + "\n" +
        'O["second"]=[' + '2,' * 100_000
    ).encode()
    report, artifacts = dropper.recover_javascript_dropper(script)
    assert report == {"status": "pattern_not_found", "executed": False}
    assert artifacts == []
