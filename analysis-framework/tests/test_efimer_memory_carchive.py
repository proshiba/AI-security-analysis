"""Efimerのメモリ内PyInstaller復元と誤検出防止を検証する。"""

from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path
import struct
import sys
import zlib

import pytest


FRAMEWORK = Path(__file__).parents[1]
COMMON = FRAMEWORK / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

from analysis_contract import handler_result_quality  # noqa: E402
import extract_pyinstaller_archive as pyinstaller_archive  # noqa: E402
from extract_pyinstaller_archive import (  # noqa: E402
    MemoryCArchiveError,
    extract_selected_entries_from_bytes,
)
from handler_catalog import HandlerNoEvidenceError  # noqa: E402


COOKIE_MAGIC = b"MEI\x0c\x0b\x0a\x0b\x0e"
COOKIE_FORMAT = "!8sIIII64s"
TOC_FORMAT = "!IIIIBc"
TOC_HEADER_SIZE = struct.calcsize(TOC_FORMAT)


def load(relative: str, name: str):
    spec = importlib.util.spec_from_file_location(name, FRAMEWORK / relative)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def build_carchive(entries: dict[str, bytes]) -> bytes:
    """必要最小限のPyInstaller CArchiveをメモリ上だけで合成する。"""

    data_region = bytearray()
    toc = bytearray()
    for name, payload in entries.items():
        stored = zlib.compress(payload)
        offset = len(data_region)
        data_region.extend(stored)
        encoded_name = name.encode("utf-8") + b"\0"
        padded_length = ((len(encoded_name) + 15) // 16) * 16
        encoded_name = encoded_name.ljust(padded_length, b"\0")
        entry_length = TOC_HEADER_SIZE + len(encoded_name)
        toc.extend(
            struct.pack(
                TOC_FORMAT,
                entry_length,
                offset,
                len(stored),
                len(payload),
                1,
                b"x",
            )
        )
        toc.extend(encoded_name)
    toc_offset = len(data_region)
    cookie_length = struct.calcsize(COOKIE_FORMAT)
    archive_length = len(data_region) + len(toc) + cookie_length
    cookie = struct.pack(
        COOKIE_FORMAT,
        COOKIE_MAGIC,
        archive_length,
        toc_offset,
        len(toc),
        313,
        b"python313.dll".ljust(64, b"\0"),
    )
    return b"MZ" + b"\0" * 126 + bytes(data_region) + bytes(toc) + cookie


def encrypted_efimer_entries(module) -> dict[str, bytes]:
    phase = b"c2MIdLA5PdAD"
    xml = (
        '\ufeff<?xml version="1.0" encoding="UTF-16"?>'
        '<Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">'
        "<Triggers><TimeTrigger><Repetition><Interval>PT1M</Interval></Repetition>"
        "</TimeTrigger></Triggers><Actions><Exec><Command>wscript.exe</Command>"
        "</Exec></Actions></Task>"
    ).encode("utf-16-le")
    host_a = "a" * 56
    host_b = "b" * 56
    host_c = "c" * 56
    bjs = (
        f"var PING_URL='http://{host_a}.onion/route.php';"
        "var TOR_ARGS='--socks5-hostname 127.0.0.1:9050';var TOR_EXE='uusd.exe';"
    ).encode()
    njs = (
        f"var PING_URL='http://{host_a}.onion/route.php';"
        f"var FILE_URL='http://{host_b}.onion/route.php';"
        f"var STUB_URL='http://{host_c}.onion/core/repla.php';"
    ).encode()
    plaintext = {
        "data_p002\\002.xml": xml,
        "data_p002\\002_b.js": bjs,
        "data_p002\\002_n.js": njs,
        "data_p002\\pack.js": b"var PACK=true;",
        "data_p002\\uusd.exe": b"MZ-synthetic-tor-placeholder",
    }
    entries = {name: module.xor_repeating(payload, phase) for name, payload in plaintext.items()}
    entries["pyarmor_runtime_000000\\pyarmor_runtime.pyd"] = b"synthetic-pyarmor-runtime"
    return entries


def test_efimer_embedded_config_is_decoded_without_disk_or_network() -> None:
    module = load("malware/efimer/extract_config.py", "efimer_memory_positive")
    sample = build_carchive(encrypted_efimer_entries(module))

    result = module.extract_config(sample)

    assert result["family"] == "Efimer"
    assert result["classification_confidence"] == "confirmed_decoded_configuration"
    assert result["decoded_config_recovered"] is True
    assert result["static_config_recovered"] is True
    assert result["carchive"]["saved_to_disk"] is False
    assert result["executed_sample"] is False
    assert result["network_contacted"] is False
    assert result["endpoint_summary"]["unique_url_count"] == 3
    assert {item["role"] for item in result["c2"]} == {
        "beacon_or_tasking",
        "file_exfiltration",
        "wallet_replacement_configuration",
    }
    assert all(item["reachability"] == "not_tested" for item in result["c2"])
    assert all(item["evidence"]["kind"].startswith("deobfuscated_static") for item in result["c2"])
    assert result["capabilities"] == []
    assert result["capability_evidence"] == []
    assert result["embedded_executable"]["classification"] == "bundled_tor_candidate"
    assert "bundled_tor_candidate_sha256" in result
    assert handler_result_quality(result)["tier_name"] == "decoded_configuration"


def test_generic_pyinstaller_pyarmor_is_not_labeled_efimer() -> None:
    module = load("malware/efimer/extract_config.py", "efimer_memory_negative")
    detector = load("malware/efimer/detect.py", "efimer_detector_negative")
    sample = build_carchive(
        {
            "pyarmor_runtime_000000\\pyarmor_runtime.pyd": b"runtime",
            "python313.dll": b"python",
            "pyi-runtime-tmpdir": b"option-like-string",
            "installer.py": b"installer",
            "campus.py": b"campus",
        }
    )

    with pytest.raises(HandlerNoEvidenceError, match="data_p002"):
        module.extract_config(sample)
    assert detector.detect(sample)["matched"] is False


def test_corrupt_carchive_bounds_are_rejected_as_no_evidence() -> None:
    module = load("malware/efimer/extract_config.py", "efimer_memory_corrupt")
    sample = bytearray(build_carchive(encrypted_efimer_entries(module)))
    cookie_offset = sample.rfind(COOKIE_MAGIC)
    struct.pack_into("!I", sample, cookie_offset + 8, len(sample) + 1)

    with pytest.raises(HandlerNoEvidenceError, match="CArchive"):
        module.extract_config(bytes(sample))


def test_memory_reader_rejects_unsafe_selected_entry_path() -> None:
    sample = build_carchive({"../data_p002/002.xml": b"synthetic"})

    with pytest.raises((MemoryCArchiveError, ValueError), match="相対移動"):
        extract_selected_entries_from_bytes(sample, prefixes=("data_p002/",))


def _rotation_source(values: list[str], calls: int = 2) -> str:
    rendered = repr(values)
    call_run = "+".join(f"_0xdef({0x10 + (index % max(1, len(values))):#x})" for index in range(calls))
    return (
        f"var _0xabc={rendered};"
        "function _0xdef(_0xaaa){_0xaaa=_0xaaa-0x10;return _0xabc[_0xaaa];}"
        f"var PING_URL={call_run};"
    )


def test_rotation_probe_selects_expected_rotation_and_rewrites_full_text_once() -> None:
    module = load("malware/efimer/extract_config.py", "efimer_rotation_positive")
    host = "a" * 56 + ".onion/route.php"
    source = _rotation_source(["junk", "http://", host])

    expanded, profile = module.expand_rotated_string_array(source)

    assert profile["rotation"] == 1
    assert profile["call_count"] == 2
    assert profile["probe_bytes"] < 1024
    assert f"http://{host}" in expanded


def test_array_preflight_rejects_2049_before_literal_eval_and_handles_recursion(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = load("malware/efimer/extract_config.py", "efimer_array_preflight")
    parsed = module._parse_bounded_string_array("['comma,inside', 'quote\\'inside']")
    assert parsed is not None
    assert parsed[0] == ["comma,inside", "quote'inside"]

    called = False

    def fail_if_called(_token: str):
        nonlocal called
        called = True
        raise AssertionError("要素上限確認前にliteral_evalを呼んではならない")

    monkeypatch.setattr(module.ast, "literal_eval", fail_if_called)
    oversized_values = ["x"] * (module.MAX_STRING_ARRAY_ITEMS + 1)
    with pytest.raises(ValueError, match="要素数"):
        module.expand_rotated_string_array(_rotation_source(oversized_values))
    assert called is False

    def recurse(_token: str):
        raise RecursionError("synthetic")

    monkeypatch.setattr(module.ast, "literal_eval", recurse)
    with pytest.raises(ValueError, match="再帰上限"):
        module._parse_bounded_string_array("['x']")


def test_literal_eval_recursion_is_mapped_to_handler_no_evidence(monkeypatch: pytest.MonkeyPatch) -> None:
    module = load("malware/efimer/extract_config.py", "efimer_array_recursion_handler")
    entries = encrypted_efimer_entries(module)
    phase = b"c2MIdLA5PdAD"
    host = "a" * 56 + ".onion/route.php"
    entries["data_p002\\002_b.js"] = module.xor_repeating(
        _rotation_source(["http://", host]).encode(),
        phase,
    )

    def recurse(_token: str):
        raise RecursionError("synthetic")

    monkeypatch.setattr(module.ast, "literal_eval", recurse)
    with pytest.raises(HandlerNoEvidenceError, match="静的検証"):
        module.extract_config(build_carchive(entries))


def test_concat_run_rejects_bytes_before_eval_and_limits_literal_count(monkeypatch: pytest.MonkeyPatch) -> None:
    module = load("malware/efimer/extract_config.py", "efimer_concat_limits")
    original_literal_eval = module.ast.literal_eval
    called = False

    def fail_if_called(_token: str):
        nonlocal called
        called = True
        raise AssertionError("run byte上限確認前にliteral_evalを呼んではならない")

    monkeypatch.setattr(module, "MAX_CONCAT_RUN_BYTES", 64)
    monkeypatch.setattr(module.ast, "literal_eval", fail_if_called)
    with pytest.raises(ValueError, match="runの入力サイズ"):
        module.collapse_string_concatenations("+".join("'abcd'" for _ in range(64)))
    assert called is False

    monkeypatch.setattr(module.ast, "literal_eval", original_literal_eval)
    monkeypatch.setattr(module, "MAX_CONCAT_RUN_BYTES", 4096)
    monkeypatch.setattr(module, "MAX_CONCAT_LITERALS", 3)
    with pytest.raises(ValueError, match="literal数"):
        module.collapse_string_concatenations("'a'+'b'+'c'+'d'")


def test_rotation_limits_reject_large_array_and_many_calls() -> None:
    module = load("malware/efimer/extract_config.py", "efimer_rotation_limits")
    host = "a" * 56 + ".onion/route.php"
    with pytest.raises(ValueError, match="要素数"):
        module.expand_rotated_string_array(_rotation_source(["x"] * (module.MAX_ROTATION_COUNT + 1)))
    with pytest.raises(ValueError, match="呼出し数"):
        module.expand_rotated_string_array(_rotation_source(["http://", host], calls=module.MAX_DECODER_CALLS + 1))


def test_rotation_limits_reject_array_bytes_and_rotation_call_product(monkeypatch: pytest.MonkeyPatch) -> None:
    module = load("malware/efimer/extract_config.py", "efimer_rotation_work_limits")
    host = "a" * 56 + ".onion/route.php"
    monkeypatch.setattr(module, "MAX_STRING_ARRAY_BYTES", 8)
    with pytest.raises(ValueError, match="総サイズ"):
        module.expand_rotated_string_array(_rotation_source(["http://", host]))

    module = load("malware/efimer/extract_config.py", "efimer_rotation_product_limit")
    monkeypatch.setattr(module, "MAX_ROTATION_CALL_WORK", 3)
    with pytest.raises(ValueError, match="積"):
        module.expand_rotated_string_array(_rotation_source(["http://", host], calls=2))


def test_rotation_overflow_is_mapped_to_handler_no_evidence() -> None:
    module = load("malware/efimer/extract_config.py", "efimer_rotation_handler_boundary")
    entries = encrypted_efimer_entries(module)
    phase = b"c2MIdLA5PdAD"
    hostile_javascript = _rotation_source(["x"] * (module.MAX_ROTATION_COUNT + 1)).encode()
    entries["data_p002\\002_n.js"] = module.xor_repeating(hostile_javascript, phase)

    with pytest.raises(HandlerNoEvidenceError, match="静的検証"):
        module.extract_config(build_carchive(entries))


def test_capabilities_are_emitted_only_with_definition_call_and_markers() -> None:
    module = load("malware/efimer/extract_config.py", "efimer_capability_evidence")
    source = (
        "function GetClipboard(){}function SetClipboard(){}function MakeREPL(){}"
        "var btc_1_addrs=[];var REPL_PATH='002a.txt';"
        "var x=GetClipboard();x=MakeREPL(x);SetClipboard(x);"
    )

    capabilities, evidence = module._observed_capabilities({"002_n.js": source, "002_b.js": ""})

    assert capabilities == ["暗号資産アドレスのクリップボード置換"]
    assert len(evidence) == 1
    assert evidence[0]["confidence"] == "confirmed_deobfuscated_static_logic"
    assert {item["function"] for item in evidence[0]["function_call_correlations"]} == {
        "GetClipboard",
        "SetClipboard",
        "MakeREPL",
    }


def test_capability_ignores_comment_string_and_regex_decoys() -> None:
    module = load("malware/efimer/extract_config.py", "efimer_capability_lexical_negative")
    source = (
        "// function GetClipboard(){} GetClipboard(); btc_1_addrs REPL_PATH\n"
        "var text='function SetClipboard(){} SetClipboard(); function MakeREPL(){} MakeREPL();';"
        "var one=/function GetClipboard\\(\\)/;var two=/GetClipboard\\(\\)/;"
        "var three=/function SetClipboard\\(\\)/;var four=/SetClipboard\\(\\)/;"
        "var five=/function MakeREPL\\(\\)/;var six=/MakeREPL\\(\\)/;"
        "var markers=/btc_1_addrs REPL_PATH/;"
    )

    code_view, _tokens = module._javascript_code_and_strings(source)
    capabilities, evidence = module._observed_capabilities({"002_n.js": source, "002_b.js": ""})

    assert len(code_view) == len(source)
    assert "function GetClipboard" not in code_view
    assert capabilities == []
    assert evidence == []


def test_capability_requires_markers_in_their_expected_lexical_location() -> None:
    module = load("malware/efimer/extract_config.py", "efimer_capability_marker_location")
    source = (
        "function GetClipboard(){}function SetClipboard(){}function MakeREPL(){}"
        "var REPL_PATH='002a.txt';var decoy='btc_1_addrs';"
        "var x=GetClipboard();x=MakeREPL(x);SetClipboard(x);"
    )

    capabilities, evidence = module._observed_capabilities({"002_n.js": source, "002_b.js": ""})

    assert capabilities == []
    assert evidence == []


def test_uusd_requires_pe_and_tor_specific_markers_for_confirmation() -> None:
    module = load("malware/efimer/extract_config.py", "efimer_tor_artifact")
    assert module._classify_bundled_uusd(b"MZ-placeholder")["classification"] == "bundled_tor_candidate"

    payload = bytearray(1024)
    payload[:2] = b"MZ"
    struct.pack_into("<I", payload, 0x3C, 0x80)
    payload[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<H", payload, 0x86, 1)
    struct.pack_into("<H", payload, 0x94, 0xE0)
    struct.pack_into("<H", payload, 0x98, 0x10B)
    optional_start = 0x98
    section_start = optional_start + 0xE0
    struct.pack_into("<I", payload, optional_start + 60, 0x200)
    struct.pack_into("<I", payload, section_start + 16, 0x100)
    struct.pack_into("<I", payload, section_start + 20, 0x200)
    payload.extend(b"ControlPort GeoIPFile ntor SOCKS libevent OpenSSL")

    result = module._classify_bundled_uusd(bytes(payload))
    assert result["classification"] == "bundled_tor"
    assert result["pe_structure_valid"] is True
    assert result["validated_pe_extent"] == 0x300


def test_endpoint_scan_stops_at_bound(monkeypatch: pytest.MonkeyPatch) -> None:
    module = load("malware/efimer/extract_config.py", "efimer_endpoint_bound")
    monkeypatch.setattr(module, "MAX_ENDPOINT_OBSERVATIONS", 2)
    host_a = "a" * 56
    host_b = "b" * 56
    host_c = "c" * 56
    source = (
        f"var PING_URL='http://{host_a}.onion/route.php';"
        f"var FILE_URL='http://{host_b}.onion/route.php';"
        f"var STUB_URL='http://{host_c}.onion/route.php';"
    )

    with pytest.raises(ValueError, match="走査数"):
        module._endpoint_observations(
            {"002_n.js": source},
            bundled_tor_classification="bundled_tor_candidate",
        )


def test_endpoint_ignores_urls_inside_comments_and_regex_literals() -> None:
    module = load("malware/efimer/extract_config.py", "efimer_endpoint_lexical_negative")
    host_a = "a" * 56
    host_b = "b" * 56
    source = (
        f"// var PING_URL='http://{host_a}.onion/route.php';\n"
        f"/* var FILE_URL='http://{host_b}.onion/route.php'; */"
        f"var old=/http:\\/\\/{host_a}\\.onion\\/route\\.php/;"
    )

    assert (
        module._endpoint_observations(
            {"002_n.js": source},
            bundled_tor_classification="bundled_tor_candidate",
        )
        == []
    )


def test_memory_reader_rejects_windows_unsafe_names_and_casefold_collision() -> None:
    for value in (
        "data/file:ads",
        "data/file. ",
        "data/file.",
        "data/CON",
        "data/con.txt",
        "data/COM1.bin",
        "data/lpt9",
        "data/CONIN$",
        "data/conout$.txt",
        "data/CLOCK$.log",
        "data/COM¹",
        "data/com².bin",
        "data/LPT³.log",
        "data/control\x1f.bin",
    ):
        with pytest.raises(ValueError):
            pyinstaller_archive.safe_relative_path(value)

    sample = build_carchive({"Data/File.bin": b"a", "data/file.BIN": b"b"})
    with pytest.raises(MemoryCArchiveError, match="正規化後に衝突"):
        extract_selected_entries_from_bytes(sample, prefixes=("data/",))


def test_memory_reader_rejects_overlapping_ranges_and_compressed_total() -> None:
    sample = bytearray(build_carchive({"data/a.bin": b"A" * 100, "data/b.bin": b"B" * 100}))
    cookie_offset = sample.rfind(COOKIE_MAGIC)
    _magic, archive_length, toc_offset, _toc_length, _python, _library = struct.unpack_from(
        COOKIE_FORMAT, sample, cookie_offset
    )
    archive_start = cookie_offset + struct.calcsize(COOKIE_FORMAT) - archive_length
    toc_start = archive_start + toc_offset
    first_entry_length = struct.unpack_from("!I", sample, toc_start)[0]
    second_entry = toc_start + first_entry_length
    struct.pack_into("!I", sample, second_entry + 4, 0)

    with pytest.raises(MemoryCArchiveError, match="range"):
        extract_selected_entries_from_bytes(bytes(sample), prefixes=("data/",))

    normal = build_carchive({"data/a.bin": b"A" * 100})
    with pytest.raises(MemoryCArchiveError, match="圧縮入力総量"):
        extract_selected_entries_from_bytes(normal, prefixes=("data/",), max_compressed_total_size=1)


def test_cli_analyze_uses_bounded_memory_reader_and_writes_safe_path(tmp_path: Path) -> None:
    sample_bytes = build_carchive({"data/a.bin": b"payload"})
    sample = tmp_path / "sample.exe"
    sample.write_bytes(sample_bytes)
    output = tmp_path / "out"

    result = pyinstaller_archive.analyze(
        sample,
        hashlib.sha256(sample_bytes).hexdigest(),
        output,
        prefixes=("data/",),
    )

    assert result["archive"]["reader"] == "bounded_memory_carchive"
    assert result["safety"]["bounded_memory_reader"] is True
    assert result["safety"]["exclusive_output_create"] is True
    assert result["safety"]["post_write_identity_verified"] is True
    assert result["extraction"]["written_count"] == 1
    assert (output / "data" / "a.bin").read_bytes() == b"payload"


def test_cli_does_not_overwrite_existing_output(tmp_path: Path) -> None:
    sample_bytes = build_carchive({"data/a.bin": b"payload"})
    sample = tmp_path / "sample.exe"
    sample.write_bytes(sample_bytes)
    output = tmp_path / "out"
    target = output / "data" / "a.bin"
    target.parent.mkdir(parents=True)
    target.write_bytes(b"existing")

    with pytest.raises(FileExistsError, match="上書きしません"):
        pyinstaller_archive.analyze(
            sample,
            hashlib.sha256(sample_bytes).hexdigest(),
            output,
            prefixes=("data/",),
        )
    assert target.read_bytes() == b"existing"


def test_cli_exclusive_create_rejects_file_created_after_planning(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sample_bytes = build_carchive({"data/a.bin": b"payload"})
    sample = tmp_path / "sample.exe"
    sample.write_bytes(sample_bytes)
    output = tmp_path / "out"
    original_write = pyinstaller_archive._write_reserved_file

    def create_racer(destination: Path, payload: bytes) -> None:
        destination.write_bytes(b"racer")
        original_write(destination, payload)

    monkeypatch.setattr(pyinstaller_archive, "_write_reserved_file", create_racer)
    with pytest.raises(FileExistsError, match="上書きしません"):
        pyinstaller_archive.analyze(
            sample,
            hashlib.sha256(sample_bytes).hexdigest(),
            output,
            prefixes=("data/",),
        )
    assert (output / "data" / "a.bin").read_bytes() == b"racer"


def test_reserved_output_identity_is_checked_before_payload_write(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = tmp_path / "reserved.bin"
    calls = 0

    def reject_identity(_handle, _destination: Path) -> None:
        nonlocal calls
        calls += 1
        raise ValueError("synthetic identity race")

    monkeypatch.setattr(pyinstaller_archive, "_verify_reserved_output_identity", reject_identity)
    with pytest.raises(ValueError, match="identity race"):
        pyinstaller_archive._write_reserved_file(destination, b"payload")
    assert calls == 1
    assert destination.read_bytes() == b""


def test_reserved_output_rejects_handle_path_identity_mismatch(tmp_path: Path) -> None:
    first = tmp_path / "first.bin"
    second = tmp_path / "second.bin"
    first.write_bytes(b"first")
    second.write_bytes(b"second")

    with first.open("rb") as handle, pytest.raises(ValueError, match="identity"):
        pyinstaller_archive._verify_reserved_output_identity(handle, second)


def test_cli_rejects_existing_reparse_output_component(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sample_bytes = build_carchive({"data/a.bin": b"payload"})
    sample = tmp_path / "sample.exe"
    sample.write_bytes(sample_bytes)
    output = tmp_path / "reparse-output"
    output.mkdir()
    original = pyinstaller_archive._is_reparse_point

    def fake_is_reparse(path: Path) -> bool:
        return path.absolute() == output.absolute() or original(path)

    monkeypatch.setattr(pyinstaller_archive, "_is_reparse_point", fake_is_reparse)
    with pytest.raises(ValueError, match="reparse point"):
        pyinstaller_archive.analyze(
            sample,
            hashlib.sha256(sample_bytes).hexdigest(),
            output,
            prefixes=("data/",),
        )
    assert not (output / "data" / "a.bin").exists()
