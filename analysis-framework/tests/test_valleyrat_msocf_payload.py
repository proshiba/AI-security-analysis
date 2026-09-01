"""ValleyRAT MSOCFプロキシの静的復元回帰テスト。"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import sys
from pathlib import Path

import pytest

MODULE_PATH = Path(__file__).resolve().parents[1] / "malware/valleyrat/campaigns/signed_proxy_sideload/msocf_payload.py"
SPEC = importlib.util.spec_from_file_location("valleyrat_msocf_payload", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def _index_setup(index: int) -> bytes:
    prefix = b"\x33\xc0\x40"
    if index == 1:
        return prefix + b"\xc1\xe0\x00"
    if index > 0 and index & (index - 1) == 0:
        return prefix + b"\xc1\xe0" + (index.bit_length() - 1).to_bytes(1, "little")
    if index <= 0x7F:
        return prefix + b"\x6b\xc0" + index.to_bytes(1, "little")
    return prefix + b"\x69\xc0" + index.to_bytes(4, "little")


def _key_builder(key: bytes) -> bytes:
    result = bytearray(b"\x55\x8b\xec")
    for index, value in enumerate(key + b"\x00"):
        result.extend(_index_setup(index))
        result.extend(b"\x8b\x4d\x08\xc6\x04\x01")
        result.append(value)
    return bytes(result)


def _valid_sample() -> tuple[bytes, bytes, bytes]:
    key = (b"Ab9" * 80)[:200]
    payload = bytearray(b"\x55\x8b\xec" + b"\x90" * 1_197)
    payload[128:136] = b"codemark"
    payload[256:270] = b"203.0.113.77\0"
    encrypted = MODULE.rc4(bytes(value ^ 0xFF for value in payload), key)
    sample = _key_builder(key) + b"\x00not-hex\x00" + encrypted.hex().encode() + b"\x00"
    return sample, bytes(payload), key


def test_sequential_key_builder_and_payload_are_recovered_without_execution() -> None:
    sample, payload, key = _valid_sample()

    recovery = MODULE.recover_msocf_payload(sample)
    summary = MODULE.public_recovery_summary(recovery)

    assert recovery.key == key
    assert recovery.payload == payload
    assert recovery.public_summary() == summary
    assert set(summary) == {
        "status",
        "algorithm",
        "encrypted_size",
        "encrypted_sha256",
        "key_size",
        "key_sha256",
        "payload_size",
        "payload_sha256",
        "hex_file_offset",
        "key_builder_file_offset",
        "markers",
        "endpoints",
        "executed",
        "network_contacted",
    }
    assert summary["algorithm"] == ["ascii_hex_decode", "rc4", "xor_each_byte_0xff"]
    assert summary["endpoints"] == ["203.0.113.77"]
    assert summary["markers"] == ["codemark"]
    assert summary["executed"] is False
    assert summary["network_contacted"] is False
    assert "payload" not in summary
    assert "key" not in summary


def test_msocf_material_absent_fails_closed() -> None:
    """MSOCF構造がない入力を復元済みへ昇格しない。"""

    for sample in (b"ordinary file", b"a" * 4096, _key_builder(b"A" * 200)):
        with pytest.raises(MODULE.MsocfPayloadError):
            MODULE.recover_msocf_payload(sample)


@pytest.mark.parametrize(
    "hex_text",
    [
        b"0" * 2047,
        b"0" * 2049,
        b"g" + b"0" * 2048,
    ],
)
def test_hex_length_and_alphabet_boundaries_fail_closed(hex_text: bytes) -> None:
    """最小長未満、奇数長、非hex混入を復元候補として受理しない。"""

    with pytest.raises(MODULE.MsocfPayloadError):
        MODULE.recover_msocf_payload(_key_builder(b"A" * 200) + b"\x00" + hex_text + b"\x00")


def test_ambiguous_valid_recoveries_fail_closed() -> None:
    """検証済みの組が複数ある入力を一意なpayloadとして返さない。"""

    key = (b"Ab9" * 80)[:200]
    payload = bytearray(b"\x90" * 1_200)
    payload[128:136] = b"codemark"
    payload[256:270] = b"203.0.113.77\0"
    encrypted = MODULE.rc4(bytes(value ^ 0xFF for value in payload), key)
    hex_blob = encrypted.hex().encode()
    sample = _key_builder(key) + b"\x00" + hex_blob + b"\x00" + hex_blob + b"\x00"

    with pytest.raises(MODULE.MsocfPayloadError, match="count must be one"):
        MODULE.recover_msocf_payload(sample)


def test_truncated_key_instruction_fails_closed() -> None:
    assert MODULE.find_built_keys(b"prefix\x33\xc0\x40\x6b\xc0") == []


def test_payload_output_must_be_outside_repository() -> None:
    with pytest.raises(MODULE.MsocfPayloadError, match="repository外"):
        MODULE.outside_repository(MODULE.REPOSITORY_ROOT / "analysis-results")


def test_direct_input_reader_enforces_cap_and_single_link(tmp_path: Path) -> None:
    """CLI入力は上限ちょうどだけを受理し、超過とhardlinkを拒否する。"""

    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"ABCD")
    assert MODULE.read_input_capped(sample, maximum=4) == b"ABCD"
    with pytest.raises(MODULE.MsocfPayloadError, match="size上限"):
        MODULE.read_input_capped(sample, maximum=3)

    alias = tmp_path / "sample-hardlink.bin"
    try:
        os.link(sample, alias)
    except OSError as exc:
        pytest.skip(f"このfilesystemではhardlinkを作成できません: {exc}")
    with pytest.raises(MODULE.MsocfPayloadError, match="単一link"):
        MODULE.read_input_capped(sample, maximum=4)


def test_direct_input_reader_rejects_symlink_or_reparse(tmp_path: Path) -> None:
    """CLI入力はsymlink／reparse pointをfollowしない。"""

    source = tmp_path / "source.bin"
    source.write_bytes(b"ABCD")
    link = tmp_path / "source-link.bin"
    try:
        link.symlink_to(source)
    except OSError as exc:
        pytest.skip(f"この環境ではsymlinkを作成できません: {exc}")
    with pytest.raises(MODULE.MsocfPayloadError, match="単一link"):
        MODULE.read_input_capped(link, maximum=4)

    real_parent = tmp_path / "real-parent"
    real_parent.mkdir()
    (real_parent / "nested.bin").write_bytes(b"ABCD")
    linked_parent = tmp_path / "linked-parent"
    try:
        linked_parent.symlink_to(real_parent, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"この環境ではdirectory symlinkを作成できません: {exc}")
    with pytest.raises(MODULE.MsocfPayloadError, match="symlink|reparse"):
        MODULE.read_input_capped(linked_parent / "nested.bin", maximum=4)


def test_prepare_output_root_rejects_parent_escape_and_reparse(tmp_path: Path) -> None:
    """出力rootは親component境界内のrepository外通常directoryに限定する。"""

    output = MODULE.prepare_output_root(tmp_path / "new-output")
    assert output.is_dir()
    with pytest.raises(MODULE.MsocfPayloadError, match=r"\.\."):
        MODULE.prepare_output_root(tmp_path / "child" / ".." / "escape")

    target = tmp_path / "real-output"
    target.mkdir()
    link = tmp_path / "output-link"
    try:
        link.symlink_to(target, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"この環境ではdirectory symlinkを作成できません: {exc}")
    with pytest.raises(MODULE.MsocfPayloadError, match="symlink|reparse"):
        MODULE.prepare_output_root(link)


def test_payload_write_is_exclusive_and_revalidates_hash(tmp_path: Path) -> None:
    """payloadは新規fileへ一度だけ書き、open descriptorからhashを再検証する。"""

    root = MODULE.prepare_output_root(tmp_path / "output")
    payload = b"defensive-static-payload"
    digest = hashlib.sha256(payload).hexdigest()
    destination = MODULE.write_payload_exclusive(
        root,
        payload,
        expected_sha256=digest,
    )
    assert destination.read_bytes() == payload
    assert destination.stat().st_nlink == 1
    with pytest.raises(MODULE.MsocfPayloadError, match="既に存在"):
        MODULE.write_payload_exclusive(root, b"replacement", expected_sha256=digest)
    assert destination.read_bytes() == payload

    wrong_digest = hashlib.sha256(b"different").hexdigest()
    with pytest.raises(MODULE.MsocfPayloadError, match="hash再検証"):
        MODULE.write_payload_exclusive(root, payload, expected_sha256=wrong_digest)


@pytest.mark.parametrize("entry_kind", ["file", "hardlink", "symlink"])
def test_payload_write_never_overwrites_existing_entry(
    tmp_path: Path,
    entry_kind: str,
) -> None:
    """既存file／hardlink／symlinkをfollowまたは上書きしない。"""

    root = MODULE.prepare_output_root(tmp_path / "output")
    payload = b"new-payload"
    digest = hashlib.sha256(payload).hexdigest()
    destination = root / f"{digest}.bin"
    protected = tmp_path / "protected.bin"
    protected.write_bytes(b"protected")
    try:
        if entry_kind == "file":
            destination.write_bytes(b"existing")
        elif entry_kind == "hardlink":
            os.link(protected, destination)
        else:
            destination.symlink_to(protected)
    except OSError as exc:
        pytest.skip(f"このfilesystemでは{entry_kind}を作成できません: {exc}")

    with pytest.raises(MODULE.MsocfPayloadError, match="既に存在"):
        MODULE.write_payload_exclusive(root, payload, expected_sha256=digest)
    assert protected.read_bytes() == b"protected"
    if entry_kind == "file":
        assert destination.read_bytes() == b"existing"


def test_payload_write_rejects_hardlink_added_after_open(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """open後に追加されたhardlinkをfstat／lstatのlink countで拒否する。"""

    root = MODULE.prepare_output_root(tmp_path / "output")
    payload = b"payload"
    digest = hashlib.sha256(payload).hexdigest()
    destination = root / f"{digest}.bin"
    alias = tmp_path / "late-hardlink.bin"
    original_fsync = MODULE.os.fsync

    def add_hardlink(descriptor: int) -> None:
        original_fsync(descriptor)
        try:
            os.link(destination, alias)
        except OSError as exc:
            pytest.skip(f"このfilesystemではhardlinkを作成できません: {exc}")

    monkeypatch.setattr(MODULE.os, "fsync", add_hardlink)
    with pytest.raises(MODULE.MsocfPayloadError, match="identity／link／size"):
        MODULE.write_payload_exclusive(root, payload, expected_sha256=digest)
    assert alias.read_bytes() == payload


def test_candidate_and_decode_work_limits_fail_before_rc4(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """blob・key・総byte・直積workの上限超過をRC4前に拒否する。"""

    two_blobs = b"0" * 2048 + b" " + b"1" * 2048
    with pytest.raises(MODULE.MsocfPayloadError, match="blob数"):
        MODULE.find_hex_blobs(two_blobs, maximum_blobs=1)
    with pytest.raises(MODULE.MsocfPayloadError, match="復号総byte数"):
        MODULE.find_hex_blobs(b"0" * 2048, maximum_decoded_bytes=1023)

    two_keys = _key_builder(b"A" * 128) + _key_builder(b"B" * 128)
    with pytest.raises(MODULE.MsocfPayloadError, match="key候補数"):
        MODULE.find_built_keys(two_keys, maximum_candidates=1)

    sample, _payload, _key = _valid_sample()
    monkeypatch.setattr(MODULE, "MAX_PAIR_DECODE_BYTES", 1)
    monkeypatch.setattr(MODULE, "rc4", lambda *_args: pytest.fail("RC4へ到達してはなりません"))
    with pytest.raises(MODULE.MsocfPayloadError, match="復号予定byte数"):
        MODULE.recover_msocf_payload(sample)


def test_input_size_limit_fails_before_candidate_scan(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """入力上限超過はhex／key探索より前に停止する。"""

    monkeypatch.setattr(MODULE, "MAX_INPUT_BYTES", 4)
    monkeypatch.setattr(
        MODULE,
        "find_hex_blobs",
        lambda *_args, **_kwargs: pytest.fail("hex探索へ到達してはなりません"),
    )
    with pytest.raises(MODULE.MsocfPayloadError, match="入力data"):
        MODULE.recover_msocf_payload(b"12345")


def test_direct_cli_routes_sample_through_capped_reader(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """direct CLIがPath.read_bytesへ戻らず、capped readerを必ず通す。"""

    sample, payload, _key = _valid_sample()
    input_path = tmp_path / "synthetic.bin"
    calls: list[Path] = []

    def capped(path: Path, *, maximum: int = MODULE.MAX_INPUT_BYTES) -> bytes:
        assert maximum == MODULE.MAX_INPUT_BYTES
        calls.append(path)
        return sample

    monkeypatch.setattr(MODULE, "read_input_capped", capped)
    monkeypatch.setattr(sys, "argv", ["msocf_payload.py", str(input_path)])

    assert MODULE.main() == 0
    assert calls == [input_path]
    summary = json.loads(capsys.readouterr().out)
    assert summary["payload_sha256"] == hashlib.sha256(payload).hexdigest()
    assert summary["executed"] is False
    assert summary["network_contacted"] is False
