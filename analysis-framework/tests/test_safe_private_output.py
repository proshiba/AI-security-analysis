from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path
import sys

import pytest


ROOT = Path(__file__).resolve().parents[2]
COMMON = ROOT / "analysis-framework" / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

import safe_private_output  # noqa: E402


def load(relative: str, name: str):
    path = ROOT / relative
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def test_write_private_output_is_exclusive_and_hash_verified(
    tmp_path: Path,
) -> None:
    payload = b"synthetic private child"
    destination = tmp_path / "child.bin"

    observed = safe_private_output.write_private_output(
        destination,
        payload,
        sha256(payload),
    )

    assert observed == sha256(payload)
    assert destination.read_bytes() == payload
    with pytest.raises(FileExistsError, match="上書きしません"):
        safe_private_output.write_private_output(
            destination,
            b"replacement",
            sha256(b"replacement"),
        )
    assert destination.read_bytes() == payload


def test_write_private_outputs_rejects_allowed_root_escape(
    tmp_path: Path,
) -> None:
    root = tmp_path / "private"
    root.mkdir()
    destination = root / ".." / "escaped.bin"
    payload = b"escape"

    with pytest.raises(ValueError, match="許可rootの外側"):
        safe_private_output.write_private_outputs(
            [(destination, payload, sha256(payload))],
            allowed_root=root,
        )

    assert not (tmp_path / "escaped.bin").exists()


def test_write_private_outputs_rejects_reparse_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "private"
    root.mkdir()
    original = safe_private_output._is_reparse_point

    def fake_is_reparse(path: Path) -> bool:
        return safe_private_output._lexical_absolute(path) == root or original(path)

    monkeypatch.setattr(
        safe_private_output,
        "_is_reparse_point",
        fake_is_reparse,
    )
    payload = b"reparse"
    with pytest.raises(ValueError, match="reparse point"):
        safe_private_output.write_private_outputs(
            [(root / "child.bin", payload, sha256(payload))],
            allowed_root=root,
        )


def test_handle_and_path_identity_mismatch_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = tmp_path / "child.bin"
    with destination.open("xb+") as handle:
        monkeypatch.setattr(
            safe_private_output.os.path,
            "samestat",
            lambda _left, _right: False,
        )
        with pytest.raises(ValueError, match="identity"):
            safe_private_output._verify_reserved_output_identity(
                handle,
                destination,
                tmp_path,
            )


def test_final_path_mismatch_removes_only_new_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = tmp_path / "child.bin"
    payload = b"final-path"
    monkeypatch.setattr(
        safe_private_output,
        "_windows_final_path_from_fd",
        lambda _descriptor: str(tmp_path / "different.bin"),
    )

    with pytest.raises(ValueError, match="final path"):
        safe_private_output.write_private_output(
            destination,
            payload,
            sha256(payload),
        )

    assert not destination.exists()


def test_post_write_hash_mismatch_removes_only_new_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = tmp_path / "child.bin"
    payload = b"post-write-hash"
    monkeypatch.setattr(
        safe_private_output,
        "_sha256_from_handle",
        lambda _handle: "0" * 64,
    )

    with pytest.raises(ValueError, match="書込み後SHA-256"):
        safe_private_output.write_private_output(
            destination,
            payload,
            sha256(payload),
        )

    assert not destination.exists()


def test_batch_failure_rolls_back_created_file_and_preserves_racer(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "private"
    root.mkdir()
    first = root / "first.bin"
    second = root / "second.bin"
    first_payload = b"first"
    second_payload = b"second"
    original_write = safe_private_output._write_reserved_file

    def race_second(
        destination: Path,
        payload: bytes,
        expected_sha256: str,
        allowed_root: Path,
    ):
        if destination == second:
            destination.write_bytes(b"racer-owned")
            raise FileExistsError("simulated race")
        return original_write(
            destination,
            payload,
            expected_sha256,
            allowed_root,
        )

    monkeypatch.setattr(
        safe_private_output,
        "_write_reserved_file",
        race_second,
    )
    with pytest.raises(FileExistsError, match="simulated race"):
        safe_private_output.write_private_outputs(
            [
                (first, first_payload, sha256(first_payload)),
                (second, second_payload, sha256(second_payload)),
            ],
            allowed_root=root,
        )

    assert not first.exists()
    assert second.read_bytes() == b"racer-owned"


def test_cleanup_refuses_reparse_without_masking_cleanup_result(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = tmp_path / "child.bin"
    destination.write_bytes(b"new output")
    metadata = destination.stat(follow_symlinks=False)
    original = safe_private_output._is_reparse_point

    def fake_is_reparse(path: Path) -> bool:
        return path == destination or original(path)

    monkeypatch.setattr(
        safe_private_output,
        "_is_reparse_point",
        fake_is_reparse,
    )
    assert not safe_private_output._remove_if_same_file(destination, metadata)
    assert destination.read_bytes() == b"new output"


@pytest.mark.parametrize(
    ("relative", "argument_name", "child_constant"),
    [
        (
            "analysis-framework/malware/dotnet_resource_loader/bitmap_stego_loader.py",
            "--child-output",
            "CHILD_SHA256",
        ),
        (
            "analysis-framework/malware/dotnet_resource_loader/bitmap_column_loader.py",
            "--private-child-output",
            "CHILD_SHA256",
        ),
    ],
)
def test_single_child_loader_cli_uses_safe_writer(
    relative: str,
    argument_name: str,
    child_constant: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = load(relative, f"safe_private_{Path(relative).stem}")
    payload = b"synthetic child for CLI"
    destination = tmp_path / f"{Path(relative).stem}.bin"
    sample = tmp_path / f"{Path(relative).stem}.sample"
    sample.write_bytes(b"synthetic parent")
    monkeypatch.setattr(module, child_constant, sha256(payload))
    monkeypatch.setattr(module, "extract_child", lambda _data: (payload, {}))
    if Path(relative).stem == "bitmap_stego_loader":
        result = {
            "safety": {"child_written": False},
            "recovered_child": {"retained": False},
        }
    else:
        result = {"safety": {"child_written": False}}
    monkeypatch.setattr(module, "extract_config", lambda _data: result)
    monkeypatch.setattr(
        sys,
        "argv",
        [Path(relative).name, str(sample), argument_name, str(destination)],
    )

    assert module.main() == 0
    assert destination.read_bytes() == payload
    with pytest.raises(FileExistsError, match="上書きしません"):
        module.main()
    assert destination.read_bytes() == payload


def test_chunk_loader_cli_rolls_back_as_one_private_batch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = load(
        "analysis-framework/malware/dotnet_resource_loader/bitmap_chunk_loader.py",
        "safe_private_bitmap_chunk_loader",
    )
    children = {"r": b"first child", "traslp": b"second child"}
    module.SERIES = {prefix: {"child_sha256": sha256(payload)} for prefix, payload in children.items()}
    monkeypatch.setattr(
        module,
        "extract_children",
        lambda _data: (children, {}),
    )
    monkeypatch.setattr(
        module,
        "extract_config",
        lambda _data: {"safety": {"child_written": False}},
    )
    sample = tmp_path / "chunk.sample"
    sample.write_bytes(b"synthetic parent")
    output_root = tmp_path / "private"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "bitmap_chunk_loader.py",
            str(sample),
            "--private-output-dir",
            str(output_root),
        ],
    )

    assert module.main() == 0
    written = sorted(output_root.iterdir())
    assert len(written) == 2
    before = {path.name: path.read_bytes() for path in written}
    with pytest.raises(FileExistsError, match="上書きしません"):
        module.main()
    assert {path.name: path.read_bytes() for path in written} == before
