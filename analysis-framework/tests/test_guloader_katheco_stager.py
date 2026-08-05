"""GuLoader Katheco型ステージャーの静的復号テスト。"""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
import sys


GULOADER = Path(__file__).parents[1] / "malware" / "guloader"
COMMON = Path(__file__).parents[1] / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

if str(GULOADER) not in sys.path:
    sys.path.insert(0, str(GULOADER))

import katheco_stager as stager  # noqa: E402
import detect as guloader_detect  # noqa: E402


def numeric_encode(text: str, key: bytes) -> str:
    values = [ord(character) + key[index % len(key)] for index, character in enumerate(text)]
    return ",".join(str(value) for value in values)


def literal_encode(data: bytes, key: bytes) -> str:
    encrypted = bytes(value ^ key[index % len(key)] for index, value in enumerate(data))
    return base64.b64encode(encrypted).decode()


def synthetic_parent(key: bytes, shellcode_size: int, suffix_size: int) -> str:
    semantic = [
        "[Convert]::FromBase64String($value)",
        "$left-bxor($right)",
        "-join [char[]]$bytes",
        "IEX",
    ]
    arrays = ";".join(f"prelab(@({numeric_encode(value, key)}))" for value in semantic)
    encoded_key = ",".join(str(value) for value in key)
    sample_literal = literal_encode(b"A", key)
    return (
        "function prelab($value){$value};"
        "function Katheco($value,$execute=0){$value};"
        f"$key=@({encoded_key});"
        f"{arrays};"
        f"$item=Katheco '{sample_literal}';"
        f"$shell={shellcode_size};$suffix={suffix_size};"
    )


def test_identify_decoder_and_render_short_literal() -> None:
    key = b"Key1"
    parent = synthetic_parent(key, 64, 32)
    decoder = stager.identify_decoder(parent)
    assert decoder.name == "Katheco"
    assert decoder.key == key
    calls = stager.decode_calls(parent, decoder)
    assert calls[0]["assigned_variable"] == "item"
    assert calls[0]["text"] == "A"
    rendered = stager.render_deobfuscated(parent, decoder)
    assert "$item='A'" in rendered


def test_strict_carrier_decode_and_semantic_split() -> None:
    key = b"Key1"
    shellcode = bytes(range(256))
    suffix_literal = literal_encode(b"$global:test=$true", key)
    suffix = f"function Stage {{ Katheco '{suffix_literal}' 1 }}".encode() + b"#" * 100
    parent = synthetic_parent(key, len(shellcode), len(suffix))
    decoder = stager.identify_decoder(parent)
    decoded = stager.decode_whole_file_base64(base64.b64encode(shellcode + suffix))
    recovered_shellcode, recovered_suffix, split = stager.split_carrier(
        decoded, parent, decoder.name
    )
    assert recovered_shellcode == shellcode
    assert recovered_suffix == suffix
    assert split["shellcode_offset"] == len(shellcode)
    assert split["script_length"] == len(suffix)
    rendered = stager.render_deobfuscated(suffix.decode(), decoder)
    assert "$global:test=$true" in rendered


def test_detector_matches_katheco_parent_structure() -> None:
    script = (
        b"function Katheco($value){$value};function prelab($value){$value};"
        b"$overpol=151775;$daug=15261;$path='Ovenly.Foa';"
        + (b"Katheco 'QQ==' 1;" * 10)
    )
    result = guloader_detect.detect(script, Path("sample.bat"))
    assert result["matched"] is True
    assert result["observations"]["structural_profile"] == "katheco_parent_script"
    assert result["observations"]["profile_structural_correlation"] is True
    assert result["observations"]["profile_literal_correlation"] is False


def test_detector_matches_whole_file_base64_carrier() -> None:
    suffix = (
        b"function hubb{};function hesperideo{};"
        b"Katheco 'QQ==' 1;VirtualAlloc;" + (b"#" * 20_000)
    )
    carrier = base64.b64encode((b"\x90" * 100_000) + suffix)
    result = guloader_detect.detect(carrier, Path("Ikatath.xtp"))
    assert result["matched"] is True
    assert result["observations"]["structural_profile"] == (
        "katheco_whole_file_base64_carrier"
    )


def test_detector_rejects_unrelated_base64() -> None:
    unrelated = base64.b64encode(b"A" * 120_000)
    result = guloader_detect.detect(unrelated, Path("unrelated.txt"))
    assert result["matched"] is False


def test_cli_preserves_embedded_powershell_bytes(tmp_path, monkeypatch) -> None:
    key = b"Key1"
    shellcode = bytes(range(256))
    literal = literal_encode(b"$global:test=$true", key)
    suffix = (
        f"function Stage {{ Katheco '{literal}' 1 }}\r\n"
        "# preserve-crlf\r\n" + ("#" * 100)
    ).encode()
    parent = synthetic_parent(key, len(shellcode), len(suffix))
    parent_path = tmp_path / "parent.bat"
    carrier_path = tmp_path / "carrier.txt"
    output = tmp_path / "output"
    parent_path.write_text(parent, encoding="utf-8", newline="\n")
    carrier_path.write_bytes(base64.b64encode(shellcode + suffix))
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "katheco_stager.py",
            "--parent-script", str(parent_path),
            "--carrier", str(carrier_path),
            "--output-directory", str(output),
        ],
    )
    assert stager.main() == 0
    assert (output / "embedded-powershell.txt").read_bytes() == suffix
    report = json.loads((output / "katheco-decoded.json").read_text(encoding="utf-8"))
    assert report["embedded_powershell"]["sha256"] == hashlib.sha256(suffix).hexdigest()
