"""Tests for static JavaScript string-array deobfuscation."""

from __future__ import annotations

import base64

from unpackers.javascript_obfuscator import decode_script_text, deobfuscate_string_array


def _custom_base64(value: str) -> str:
    standard = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
    custom = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/="
    return (
        base64.b64encode(value.encode())
        .decode()
        .translate(str.maketrans(standard, custom))
        .rstrip("=")
    )


def test_deobfuscate_rotated_custom_base64_array() -> None:
    """Solve rotation and substitute aliases without JavaScript execution."""
    first, second = _custom_base64("456"), _custom_base64("123")
    script = f"""var a0_0xaaa=a0_0xdef;
(function(_array,_target){{while(!![]){{try{{var _value=parseInt(a0_0xdef(0x1));if(_value===_target)break;else _items.push(_items.shift());}}catch(_error){{_items.push(_items.shift());}}}}}}(a0_0xabc,123));
var result=a0_0xaaa(0x1)+'x';
function a0_0xabc(){{var _items=['{first}','{second}'];a0_0xabc=function(){{return _items;}};return a0_0xabc();}}
function a0_0xdef(_index,_unused){{_index=_index-(0x1);var _items=a0_0xabc();var _value=_items[_index];var _alphabet='abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/=';return _value;}}
""".encode()
    report, output = deobfuscate_string_array(script)
    assert report["status"] == "deobfuscated"
    assert report["rotation"] == 1
    assert report["executed"] is False
    assert output is not None and b'var result="123x"' in output


def test_deobfuscate_pattern_not_found() -> None:
    """Leave ordinary JavaScript unchanged."""
    report, output = deobfuscate_string_array(b"var x = 1;")
    assert report["status"] == "pattern_not_found" and output is None


def test_decode_script_text_encodings() -> None:
    """Normalize BOM-tagged and heuristic UTF-16 scripts without execution."""
    source = "var payload = 'ok';"
    assert decode_script_text(source.encode("utf-16")) == source
    assert decode_script_text(source.encode("utf-16-le")) == source
    assert decode_script_text(source.encode()) == source
