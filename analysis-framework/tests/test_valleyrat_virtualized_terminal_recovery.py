from __future__ import annotations

import hashlib
import io
import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = (
    ROOT
    / "malware"
    / "valleyrat"
    / "common"
    / "virtualized_terminal_recovery.py"
)
SPEC = importlib.util.spec_from_file_location(
    "valleyrat_virtualized_terminal_recovery",
    MODULE_PATH,
)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def _align(value: int, alignment: int = 0x200) -> int:
    return (value + alignment - 1) & ~(alignment - 1)


def _minimal_pe(section_name: bytes, payload: bytes) -> bytes:
    raw_size = _align(len(payload))
    image = bytearray(0x200 + raw_size)
    image[:2] = b"MZ"
    image[0x3C:0x40] = (0x80).to_bytes(4, "little")
    image[0x80:0x84] = b"PE\0\0"
    image[0x84:0x86] = (0x14C).to_bytes(2, "little")
    image[0x86:0x88] = (1).to_bytes(2, "little")
    image[0x94:0x96] = (0xE0).to_bytes(2, "little")
    image[0x96:0x98] = (0x210E).to_bytes(2, "little")

    optional = 0x98
    image[optional : optional + 2] = (0x10B).to_bytes(2, "little")
    image[optional + 16 : optional + 20] = (0x1000).to_bytes(4, "little")
    image[optional + 28 : optional + 32] = (0x400000).to_bytes(4, "little")
    image[optional + 32 : optional + 36] = (0x1000).to_bytes(4, "little")
    image[optional + 36 : optional + 40] = (0x200).to_bytes(4, "little")
    image[optional + 56 : optional + 60] = (0x2000).to_bytes(4, "little")
    image[optional + 60 : optional + 64] = (0x200).to_bytes(4, "little")
    image[optional + 92 : optional + 96] = (16).to_bytes(4, "little")

    section = optional + 0xE0
    image[section : section + 8] = section_name.ljust(8, b"\0")[:8]
    image[section + 8 : section + 12] = len(payload).to_bytes(4, "little")
    image[section + 12 : section + 16] = (0x1000).to_bytes(4, "little")
    image[section + 16 : section + 20] = raw_size.to_bytes(4, "little")
    image[section + 20 : section + 24] = (0x200).to_bytes(4, "little")
    image[section + 36 : section + 40] = (0x60000020).to_bytes(4, "little")
    image[0x200 : 0x200 + len(payload)] = payload
    return bytes(image)


def _terminal(fill: int = 0x90) -> bytes:
    return _minimal_pe(b".text", bytes([fill]) * 0x200)


def _noise() -> bytes:
    return bytes(range(256)) * 32


def test_unique_xor8_terminal_is_recovered() -> None:
    terminal = _terminal()
    protected = bytes(value ^ 0xA5 for value in terminal) + _noise()
    root = _minimal_pe(b".msedge0", protected)

    report, recovered = MODULE.recover_virtualized_terminal(root)

    assert recovered == terminal
    assert report["result"]["status"] == "recovered"
    assert report["result"]["blockers"] == []
    assert report["scan"]["unique_structurally_valid_pe_count"] == 1
    assert report["scan"]["candidates"][0]["transform"] == {
        "kind": "xor8",
        "key": 0xA5,
    }
    assert report["safety"] == {
        "sample_executed": False,
        "cpu_or_clr_emulation_used": False,
        "external_network_contacted": False,
        "stage_fetched": False,
    }


def test_unique_zlib_terminal_is_recovered() -> None:
    import zlib

    terminal = _terminal(0xCC)
    root = _minimal_pe(b".msedge0", zlib.compress(terminal) + _noise())

    report, recovered = MODULE.recover_virtualized_terminal(root)

    assert recovered == terminal
    assert report["result"]["status"] == "recovered"
    assert report["scan"]["candidates"][0]["transform"]["kind"] == "zlib"


def test_multiple_valid_terminals_fail_closed() -> None:
    first = _terminal(0x90)
    second = _terminal(0xCC)
    protected = first + second + _noise()
    root = _minimal_pe(b".msedge0", protected)

    report, recovered = MODULE.recover_virtualized_terminal(root)

    assert recovered is None
    assert report["result"]["status"] == "ambiguous"
    assert report["result"]["reason"] == "multiple_structurally_valid_static_terminal_pes"
    assert report["scan"]["unique_structurally_valid_pe_count"] == 2


def test_false_mz_and_pe_tokens_are_not_promoted() -> None:
    protected = bytearray(bytes(range(256)) * 24)
    protected[0x100:0x102] = b"MZ"
    protected[0x13C:0x140] = (0x80).to_bytes(4, "little")
    protected[0x180:0x184] = b"PE\0\0"
    root = _minimal_pe(b".msedge0", bytes(protected))

    report, recovered = MODULE.recover_virtualized_terminal(root)

    assert recovered is None
    assert report["result"] == {
        "status": "not_recovered",
        "reason": "no_structurally_valid_static_terminal_pe",
        "blockers": ["virtualized_terminal_payload_not_recovered"],
        "terminal_payload": None,
    }


def test_non_executable_section_is_not_applicable() -> None:
    root = bytearray(_minimal_pe(b".msedge0", bytes(range(256)) * 24))
    section = 0x98 + 0xE0
    root[section + 36 : section + 40] = (0x40000040).to_bytes(4, "little")

    report, recovered = MODULE.recover_virtualized_terminal(bytes(root))

    assert recovered is None
    assert report["result"]["status"] == "not_applicable"
    assert report["result"]["reason"] == "protected_section_contract_mismatch"


def test_decompression_over_output_limit_fails_closed() -> None:
    import zlib

    protected = zlib.compress(b"A" * 4096) + _noise()
    root = _minimal_pe(b".msedge0", protected)

    report, recovered = MODULE.recover_virtualized_terminal(
        root,
        max_output_size=1024,
    )

    assert recovered is None
    assert report["result"]["status"] == "not_recovered"
    assert report["scan"]["compressed_stream_attempts"]["zlib"] >= 1


def test_overlapping_root_sections_are_rejected() -> None:
    root = bytearray(_minimal_pe(b".msedge0", bytes(range(256)) * 24))
    root[0x86:0x88] = (2).to_bytes(2, "little")
    first = 0x98 + 0xE0
    second = first + 40
    root[second : second + 40] = root[first : first + 40]

    with pytest.raises(MODULE.RecoveryError, match="重複"):
        MODULE.recover_virtualized_terminal(bytes(root))


def test_artifact_output_must_be_outside_repository() -> None:
    with pytest.raises(MODULE.RecoveryError, match="repository外"):
        MODULE._outside_repository(ROOT / "malware")


def test_cli_bounded_reader_requests_only_limit_plus_one() -> None:
    requested: list[int] = []

    class RecordingBytesIO(io.BytesIO):
        def read(self, size: int = -1) -> bytes:
            requested.append(size)
            return super().read(size)

    handle = RecordingBytesIO(b"A" * 32)
    assert MODULE._bounded_read(handle, 8) == b"A" * 9
    assert requested == [9]


def test_cli_input_rejects_non_regular_file(tmp_path: Path) -> None:
    with pytest.raises(MODULE.RecoveryError, match="通常file"):
        MODULE._read_cli_input(tmp_path, maximum=1024)


def test_cli_input_rejects_symlink_when_supported(tmp_path: Path) -> None:
    target = tmp_path / "target.bin"
    target.write_bytes(b"fixture")
    alias = tmp_path / "alias.bin"
    try:
        alias.symlink_to(target)
    except OSError:
        pytest.skip("この環境ではfile symlinkを作成できません")

    with pytest.raises(MODULE.RecoveryError, match="symlink|reparse"):
        MODULE._read_cli_input(alias, maximum=1024)


def test_cli_input_revalidates_identity_after_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"stable fixture")
    original = MODULE._same_file_identity
    calls = 0

    def changed_after_open(first, second) -> bool:
        nonlocal calls
        calls += 1
        return original(first, second) if calls == 1 else False

    monkeypatch.setattr(MODULE, "_same_file_identity", changed_after_open)
    with pytest.raises(MODULE.RecoveryError, match="identity|変更"):
        MODULE._read_cli_input(sample, maximum=1024)


def test_cli_does_not_use_path_read_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(_minimal_pe(b".text", b"A" * 0x200))

    def forbidden_read_bytes(_path: Path) -> bytes:
        raise AssertionError("Path.read_bytes must not be used")

    monkeypatch.setattr(Path, "read_bytes", forbidden_read_bytes)
    monkeypatch.setattr(sys, "argv", [str(MODULE_PATH), str(sample)])
    assert MODULE.main() == 2


@pytest.mark.parametrize("existing_kind", ["report", "payload"])
def test_cli_rejects_existing_outputs_before_writing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    existing_kind: str,
) -> None:
    terminal = _terminal()
    protected = bytes(value ^ 0xA5 for value in terminal) + _noise()
    sample = tmp_path / "sample.bin"
    sample.write_bytes(_minimal_pe(b".msedge0", protected))
    report = tmp_path / "report.json"
    output_dir = tmp_path / "payloads"
    output_dir.mkdir()
    payload_path = output_dir / f"{hashlib.sha256(terminal).hexdigest()}.bin"
    existing = report if existing_kind == "report" else payload_path
    existing.write_bytes(b"keep")

    monkeypatch.setattr(
        sys,
        "argv",
        [
            str(MODULE_PATH),
            str(sample),
            "--report",
            str(report),
            "--output-dir",
            str(output_dir),
        ],
    )
    with pytest.raises(MODULE.RecoveryError, match="上書き"):
        MODULE.main()

    assert existing.read_bytes() == b"keep"
    if existing_kind == "report":
        assert not payload_path.exists()
    else:
        assert not report.exists()


def test_output_symlink_resolving_inside_repository_is_rejected(
    tmp_path: Path,
) -> None:
    alias = tmp_path / "repository-alias"
    try:
        alias.symlink_to(MODULE._repository_root(), target_is_directory=True)
    except OSError:
        pytest.skip("この環境ではdirectory symlinkを作成できません")

    with pytest.raises(MODULE.RecoveryError, match="repository外"):
        MODULE._outside_repository(alias / "blocked.json")


def test_exclusive_output_writer_creates_once(tmp_path: Path) -> None:
    target = tmp_path / "new" / "artifact.bin"

    MODULE._write_new_file(target, b"payload")

    assert target.read_bytes() == b"payload"
    with pytest.raises(MODULE.RecoveryError, match="上書き"):
        MODULE._write_new_file(target, b"replacement")
    assert target.read_bytes() == b"payload"
