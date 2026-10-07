"""JavaScript文字列配列を実行せず静的復号する処理のテスト。"""

from __future__ import annotations

import base64

from unpackers import javascript_obfuscator
from unpackers.javascript_obfuscator import (
    decode_script_text,
    deobfuscate_plain_string_array,
    deobfuscate_rc4_string_array,
    deobfuscate_string_array,
)


def _custom_base64(value: str) -> str:
    standard = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
    custom = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/="
    return (
        base64.b64encode(value.encode())
        .decode()
        .translate(str.maketrans(standard, custom))
        .rstrip("=")
    )


def _rc4_text(value: str, key: str) -> str:
    state = list(range(256))
    cursor = 0
    for index in range(256):
        cursor = (cursor + state[index] + ord(key[index % len(key)])) & 0xFF
        state[index], state[cursor] = state[cursor], state[index]
    left = right = 0
    output = []
    for character in value:
        left = (left + 1) & 0xFF
        right = (right + state[left]) & 0xFF
        state[left], state[right] = state[right], state[left]
        output.append(chr(ord(character) ^ state[(state[left] + state[right]) & 0xFF]))
    return "".join(output)


def _custom_base64_rc4(value: str, key: str) -> str:
    return _custom_base64(_rc4_text(value, key))


def _rc4_decoder_source(
    array_values: list[str],
    body: str,
    offset: int = 0x88,
    *,
    decoder_before_array: bool = False,
) -> bytes:
    values = ",".join(repr(value) for value in array_values)
    array_source = f"""function _0xarr(){{var _items=[{values}];_0xarr=function(){{return _items;}};return _0xarr();}}"""
    decoder_source = f"""function _0xdec(_index,_key){{_index=_index-{hex(offset)};var _items=_0xarr();var _value=_items[_index];
var _alphabet='abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/=';
for(var _i=0x0;_i<0x100;_i++){{_key.charCodeAt(_i%_key.length);}}
return String.fromCharCode(_value.charCodeAt(0));}}"""
    ordered = (
        decoder_source + "\n" + array_source
        if decoder_before_array
        else array_source + "\n" + decoder_source
    )
    return f"{ordered}\nvar _alias=_0xdec;{body}\n".encode()


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


def test_deobfuscate_custom_base64_rc4_array_without_javascript_execution() -> None:
    key = "k3y!"
    script = _rc4_decoder_source(
        [_custom_base64_rc4("https://example.invalid/gate/", key)],
        "var endpoint=_alias(0x88,'k3y!');",
    )
    report, output = deobfuscate_rc4_string_array(script)
    assert report["status"] == "deobfuscated"
    assert report["variant"] == "custom_base64_rc4_string_array"
    assert report["substitutions"] == 1
    assert report["decoders"][0]["alias_count"] == 1
    assert report["decoders"][0]["alias_max_depth"] == 1
    assert report["urls"] == ["https://example.invalid/gate/"]
    assert report["executed"] is False
    assert output is not None and b'var endpoint="https://example.invalid/gate/"' in output


def test_rc4_decoder_resolves_bounded_transitive_aliases() -> None:
    """匿名化fixtureの3段aliasを推移的に解決する。"""
    key = "chain"
    script = _rc4_decoder_source(
        [_custom_base64_rc4("https://chain.invalid/stage.ps1", key)],
        "var endpoint=_alias(0x88,'chain');",
    ).replace(
        b"var _alias=_0xdec;",
        b"var _direct=_0xdec;var _middle=_direct;var _alias=_middle;",
    )
    report, output = deobfuscate_rc4_string_array(script)
    assert report["status"] == "deobfuscated"
    assert report["decoders"][0]["alias_count"] == 3
    assert report["decoders"][0]["alias_max_depth"] == 3
    assert output is not None
    assert b'var endpoint="https://chain.invalid/stage.ps1"' in output


def test_rc4_decoder_alias_ambiguity_fails_closed() -> None:
    """同じaliasの別sourceへの再代入は復号しない。"""
    script = _rc4_decoder_source(
        [_custom_base64_rc4("ignored", "ambiguous")],
        "var value=_alias(0x88,'ambiguous');",
    ).replace(
        b"var _alias=_0xdec;",
        b"var _alias=_0xdec;_alias=_other;",
    )
    report, output = deobfuscate_rc4_string_array(script)
    assert report["status"] == "decoder_alias_ambiguous"
    assert report["executed"] is False
    assert output is None


def test_rc4_decoder_alias_cycle_fails_closed() -> None:
    """decoderへ連なるalias cycleを明示的に拒否する。"""
    script = _rc4_decoder_source(
        [_custom_base64_rc4("ignored", "cycle")],
        "var value=_alias(0x88,'cycle');",
    ).replace(
        b"var _alias=_0xdec;",
        b"var _direct=_0xdec;var _alias=_direct;_direct=_alias;",
    )
    report, output = deobfuscate_rc4_string_array(script)
    assert report["status"] == "decoder_alias_cycle"
    assert report["executed"] is False
    assert output is None


def test_rc4_decoder_alias_count_is_bounded() -> None:
    """decoderへ直結するalias数が上限を超えた場合は拒否する。"""
    declarations = ";".join(f"var _alias_{index}=_0xdec" for index in range(257))
    script = _rc4_decoder_source(
        [_custom_base64_rc4("ignored", "count")],
        "var value=_alias(0x88,'count');",
    ).replace(
        b"var _alias=_0xdec;",
        (declarations + ";var _alias=_0xdec;").encode(),
    )
    report, output = deobfuscate_rc4_string_array(script)
    assert report["status"] == "decoder_alias_count_exceeded"
    assert report["executed"] is False
    assert output is None


def test_rc4_decoder_alias_depth_is_bounded() -> None:
    """深すぎるalias chainは復号しない。"""
    declarations = ["var _alias_0=_0xdec"]
    declarations.extend(
        f"var _alias_{index}=_alias_{index - 1}" for index in range(1, 17)
    )
    declarations.append("var _alias=_alias_16")
    script = _rc4_decoder_source(
        [_custom_base64_rc4("ignored", "depth")],
        "var value=_alias(0x88,'depth');",
    ).replace(
        b"var _alias=_0xdec;",
        (";".join(declarations) + ";").encode(),
    )
    report, output = deobfuscate_rc4_string_array(script)
    assert report["status"] == "decoder_alias_depth_exceeded"
    assert report["executed"] is False
    assert output is None


def test_rc4_decoder_alias_resolution_has_elapsed_time_limit(monkeypatch) -> None:
    """alias走査が経過時間上限を超えた場合はfail-closedにする。"""
    ticks = iter((10.0, 13.0))
    monkeypatch.setattr(
        javascript_obfuscator.time,
        "monotonic",
        lambda: next(ticks),
    )
    script = _rc4_decoder_source(
        [_custom_base64_rc4("ignored", "time")],
        "var value=_alias(0x88,'time');",
    )
    report, output = deobfuscate_rc4_string_array(script)
    assert report["status"] == "decoder_alias_time_exceeded"
    assert report["executed"] is False
    assert output is None


def test_rc4_decoder_may_precede_the_string_array() -> None:
    """decoderが配列より前にある亜種もJavaScript非実行で復号する。"""
    key = "front"
    script = _rc4_decoder_source(
        [_custom_base64_rc4("https://front.invalid/gate/", key)],
        "var endpoint=_alias(0x88,'front');",
        decoder_before_array=True,
    )
    report, output = deobfuscate_rc4_string_array(script)
    assert report["status"] == "deobfuscated"
    assert report["substitutions"] == 1
    assert report["urls"] == ["https://front.invalid/gate/"]
    assert report["executed"] is False
    assert output is not None and b'var endpoint="https://front.invalid/gate/"' in output


def test_rc4_decoder_selects_its_own_array_after_a_plain_decoy() -> None:
    """先行する別配列ではなくRC4 decoderが直接参照する配列を選ぶ。"""
    key = "paired"
    decoy = b"""function _plain(){var _values=['not-the-target'];return _values;}
function _plainDecoder(_index,_unused){_index=_index-0;var _values=_plain();return _values[_index];}
"""
    script = decoy + _rc4_decoder_source(
        [_custom_base64_rc4("https://paired.invalid/gate/", key)],
        "var endpoint=_alias(0x88,'paired');",
    )
    report, output = deobfuscate_rc4_string_array(script)
    assert report["status"] == "deobfuscated"
    assert report["decoder_count"] == 1
    assert report["decoders"][0]["array_function"] == "_0xarr"
    assert report["substitutions"] == 1
    assert output is not None and b'https://paired.invalid/gate/' in output


def test_rc4_array_rotation_is_solved_from_numeric_sentinel() -> None:
    key = "rotate"
    script = _rc4_decoder_source(
        [
            _custom_base64_rc4("456", key),
            _custom_base64_rc4("123", key),
        ],
        "var selected=_alias(0x88,'rotate');",
    ).decode()
    rotation = """(function(_array,_target){while(!![]){try{var _value=parseInt(_alias(0x88,'rotate'));if(_value===_target)break;else _items.push(_items.shift());}catch(_error){_items.push(_items.shift());}}}(_0xarr,123));\n"""
    script = script.replace("function _0xdec", rotation + "function _0xdec").encode()
    report, output = deobfuscate_rc4_string_array(script)
    assert report["status"] == "deobfuscated"
    assert report["rotation"] == 1
    assert report["rotation_source"] == "sentinel"
    assert output is not None and b'var selected="123"' in output


def test_plain_decoder_accepts_formatted_second_array_and_bounded_aliases() -> None:
    """先行RC4風decoyを除外し、整形済み第2配列のaliasを解決する。"""
    script = b"""
function _rc4array() { var _enc = ['ignored']; return _enc; }
function _rc4dec(_index, _key) {
  _index = _index - 0x0; var _enc = _rc4array(); var _value = _enc[_index];
  var _alphabet = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/=';
  for (var _i = 0; _i < 0x100; _i++) { _key.charCodeAt(_i % _key.length); }
  return String.fromCharCode(_value.charCodeAt(0));
}
function _plain(_index, _unused) {
  _index = _index - 0x0;
  var _values = _strings(), _value = _values[_index];
  return _value;
}
function _strings() {
  var _unused = 1, _values = [
    'MSXML2.XMLHTTP', 'open', 'https://stage.invalid/a.ps1'
  ];
  _strings = function () { return _values; };
  return _strings();
}
var _direct = _plain, _middle = _direct, _alias = _middle;
var objectName = _alias(0x0), methodName = _alias(0x1), endpoint = _alias(0x2);
"""
    report, output = deobfuscate_plain_string_array(script)
    assert report["status"] == "deobfuscated"
    assert report["decoder_count"] == 1
    assert report["decoders"][0]["array_function"] == "_strings"
    assert report["decoders"][0]["alias_count"] == 3
    assert report["decoders"][0]["alias_max_depth"] == 3
    assert report["substitutions"] == 3
    assert report["urls"] == ["https://stage.invalid/a.ps1"]
    assert report["executed"] is False
    assert report["network_contacted"] is False
    assert output is not None
    assert b'objectName = "MSXML2.XMLHTTP"' in output


def test_plain_decoder_accepts_minified_script_above_legacy_two_mib_limit() -> None:
    """総上限内の大きなscriptを旧2 MiB境界だけで拒否しない。"""

    padding = b"/*" + (b"A" * (2 * 1024 * 1024)) + b"*/\n"
    script = padding + b"""
function _plain(_index) {
  _index = _index - 0;
  var _values = _strings();
  return _values[_index];
}
function _strings() {
  var _values = ['open'];
  return _values;
}
var value = _plain(0);
"""

    report, output = deobfuscate_plain_string_array(script)

    assert report["status"] == "deobfuscated"
    assert report["executed"] is False
    assert output is not None and b'var value = "open"' in output


def test_plain_decoder_still_rejects_input_above_bounded_limit(monkeypatch) -> None:
    """調整後も明示した総script上限をfail-closedで維持する。"""

    monkeypatch.setattr(
        javascript_obfuscator,
        "_PLAIN_STRING_ARRAY_SCRIPT_SIZE_LIMIT",
        16,
    )

    report, output = deobfuscate_plain_string_array(b"A" * 17)

    assert report == {"status": "script_size_blocked", "executed": False}
    assert output is None


def test_plain_decoder_alias_ambiguity_fails_closed() -> None:
    """平文decoder aliasの異なるsourceへの再代入を拒否する。"""
    script = b"""
function _strings() { var _values = ['open']; return _values; }
function _plain(_index) {
  _index = _index - 0; var _values = _strings(); return _values[_index];
}
var _alias = _plain; _alias = _other; var value = _alias(0);
"""
    report, output = deobfuscate_plain_string_array(script)
    assert report["status"] == "decoder_alias_ambiguous"
    assert report["executed"] is False
    assert output is None


def test_decode_script_text_encodings() -> None:
    """Normalize BOM-tagged and heuristic UTF-16 scripts without execution."""
    source = "var payload = 'ok';"
    assert decode_script_text(source.encode("utf-16")) == source
    assert decode_script_text(source.encode("utf-16-le")) == source
    assert decode_script_text(source.encode()) == source
