from __future__ import annotations

import base64
import importlib.util
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]


def load(relative: str, name: str):
    path = ROOT / relative
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_repeated_separator_and_dual_xor_are_reconstructed_without_execution() -> None:
    module = load(
        "analysis-framework/malware/windows_script_stager/javascript_dual_xor_stager.py",
        "b19_js_dual_xor",
    )
    text = 'var payload = "PoSEPwer";\npayload += "ShSEPell";'
    restored, count = module.reconstruct_concat_variable(text, "payload", "SEP")
    assert restored == "PowerShell"
    assert count == 2

    key = "Key1"
    first = b"alpha;"
    second = b"beta"
    key_a = [ord(char) ^ 0xAA for char in key]
    hexadecimal = "".join(
        f"{value ^ key_a[index % len(key_a)]:02x}" for index, value in enumerate(first)
    )
    key_b = [ord(char) ^ 0x55 for char in key]
    encoded = base64.b64encode(
        bytes(value ^ key_b[index % len(key_b)] for index, value in enumerate(second))
    ).decode()
    powershell = f"$hdCfJ2='{key}';$xhYHgP='{hexadecimal}';$gKCTQ0FI='{encoded}'"
    assert module.decode_embedded_command(powershell) == "alpha;beta"


def test_dual_xor_extractor_fails_closed_for_unreviewed_hash() -> None:
    module = load(
        "analysis-framework/malware/windows_script_stager/javascript_dual_xor_stager.py",
        "b19_js_dual_xor_unknown",
    )
    with pytest.raises(ValueError, match="SHA-256"):
        module.extract_config(b'var payload = "synthetic";')
