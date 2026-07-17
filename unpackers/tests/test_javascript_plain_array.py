"""Tests for plain JavaScript string-array deobfuscation."""

from unpackers.javascript_obfuscator import deobfuscate_plain_string_array


def test_deobfuscates_plain_rotated_array_without_execution() -> None:
    """Resolve the plain array/index-offset shape used by Electron loaders."""
    script = b"""
function D(a,b){a=a-0x10;const z=A();let q=z[a];return q;}
(function(a,b){const P=D,z=a();while(!![]){try{const q=parseInt(P(0x10))+parseInt(P(0x11));if(q===b)break;else z.push(z.shift());}catch(e){z.push(z.shift());}}}(A,30));
const endpoint=D(0x12)+D(0x13);
function A(){const x=['10a','20b','https://example.test','/gate'];A=function(){return x;};return A();}
"""
    report, transformed = deobfuscate_plain_string_array(script)
    assert report["status"] == "deobfuscated"
    assert report["rotation"] == 0
    assert report["executed"] is False
    assert transformed is not None
    assert b"https://example.test/gate" in transformed
    assert "https://example.test/gate" in report["urls"]


def test_plain_array_pattern_not_found() -> None:
    """Leave ordinary JavaScript unresolved and never execute it."""
    report, transformed = deobfuscate_plain_string_array(b"const answer = 42;")
    assert report == {"status": "pattern_not_found", "executed": False}
    assert transformed is None
