from __future__ import annotations

import json
import sys
import urllib.error
from io import BytesIO
from pathlib import Path

import pytest
import pyzipper

ROOT = Path(__file__).resolve().parents[1]
COMMON = ROOT / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

import triage_artifact_retrieval as retrieval  # noqa: E402

SHA256 = "a" * 64


def overview() -> dict:
    return {
        "sample": {"sha256": SHA256},
        "extracted": [
            {
                "tasks": ["behavioral1"],
                "resource": "behavioral1/memory/proc-memory.dmp",
                "dumped_file": "memory/proc-memory.dmp",
            },
            {
                "tasks": ["behavioral1"],
                "dumped_file": "extracted/next-stage.exe",
            },
        ],
    }


def test_extract_candidates_keeps_reviewed_task_boundaries() -> None:
    candidates = retrieval.extract_artifact_candidates(
        overview(),
        expected_sha256=SHA256,
        sample_id="260802-abcdefghij",
        include_memory=True,
    )
    assert {item["kind"] for item in candidates} == {"memory_image", "dumped_file"}
    assert any(item["endpoint_path"].endswith("/files/next-stage.exe") for item in candidates)
    assert all(".." not in item["endpoint_path"] for item in candidates)


def test_extract_candidates_can_exclude_memory() -> None:
    candidates = retrieval.extract_artifact_candidates(
        overview(),
        expected_sha256=SHA256,
        sample_id="260802-abcdefghij",
        include_memory=False,
    )
    assert [item["kind"] for item in candidates] == ["dumped_file"]


def test_extract_candidates_rejects_hash_mismatch() -> None:
    with pytest.raises(ValueError, match="一致"):
        retrieval.extract_artifact_candidates(
            overview(),
            expected_sha256="b" * 64,
            sample_id="260802-abcdefghij",
            include_memory=True,
        )


def test_encrypted_zip_never_requires_plaintext_disk() -> None:
    payload = b"MZ" + b"payload" * 20
    archive_data = retrieval.encrypted_zip_bytes(payload, "next-stage.exe", "infected")
    with pyzipper.AESZipFile(BytesIO(archive_data)) as archive:
        archive.setpassword(b"infected")
        assert archive.read("next-stage.exe") == payload


def test_existing_zero_byte_archive_is_not_reported_as_downloaded(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """中断で残った0 byte archiveを成功済みとして再利用しない。"""

    payload = b"MZ" + b"terminal" * 32
    digest = __import__("hashlib").sha256(payload).hexdigest()
    sample_id = "260802-abcdefghij"
    candidate = {
        "parent_sha256": SHA256,
        "sample_id": sample_id,
        "task_id": "behavioral1",
        "kind": "memory_image",
        "name": "1700-22-memory.dmp",
        "endpoint_path": f"/samples/{sample_id}/behavioral1/memory/1700-22-memory.dmp",
    }

    monkeypatch.setenv("TRIAGE_API_KEY", "test-key")
    monkeypatch.setattr(
        retrieval,
        "discover_candidates",
        lambda *args, **kwargs: ([candidate], []),
    )
    monkeypatch.setattr(
        retrieval,
        "fetch_bounded",
        lambda *args, **kwargs: (payload, {"http_status": 200}),
    )
    output_root = tmp_path / "triage"
    archive_path = output_root / SHA256 / sample_id / f"artifact-{digest[:16]}.zip"
    archive_path.parent.mkdir(parents=True)
    archive_path.write_bytes(b"")

    assert retrieval.main(
        [
            "--allow-network",
            "--download",
            "--hash",
            SHA256,
            "--output-root",
            str(output_root),
        ]
    ) == 0
    manifest = json.loads((output_root / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["downloaded_count"] == 0
    assert manifest["downloads"] == []
    assert manifest["errors"][0]["reason"] == (
        "既存の暗号化archive sizeが許可範囲外です"
    )
    assert archive_path.stat().st_size == 0


def test_valid_existing_archive_is_verified_and_reused(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """既存archiveはAES、member、size、平文hash一致時だけ再利用する。"""

    payload = b"MZ" + b"terminal" * 32
    digest = __import__("hashlib").sha256(payload).hexdigest()
    sample_id = "260802-abcdefghij"
    member_name = "1700-22-memory.dmp"
    candidate = {
        "parent_sha256": SHA256,
        "sample_id": sample_id,
        "task_id": "behavioral1",
        "kind": "memory_image",
        "name": member_name,
        "endpoint_path": f"/samples/{sample_id}/behavioral1/memory/{member_name}",
    }

    monkeypatch.setenv("TRIAGE_API_KEY", "test-key")
    monkeypatch.setattr(
        retrieval,
        "discover_candidates",
        lambda *args, **kwargs: ([candidate], []),
    )
    monkeypatch.setattr(
        retrieval,
        "fetch_bounded",
        lambda *args, **kwargs: (payload, {"http_status": 200}),
    )
    output_root = tmp_path / "triage"
    archive_path = output_root / SHA256 / sample_id / f"artifact-{digest[:16]}.zip"
    archive_path.parent.mkdir(parents=True)
    existing = retrieval.encrypted_zip_bytes(payload, member_name, "infected")
    archive_path.write_bytes(existing)

    assert retrieval.main(
        [
            "--allow-network",
            "--download",
            "--hash",
            SHA256,
            "--output-root",
            str(output_root),
        ]
    ) == 0
    manifest = json.loads((output_root / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["downloaded_count"] == 1
    assert manifest["errors"] == []
    assert manifest["downloads"][0]["archive_reused"] is True
    assert manifest["downloads"][0]["archive_sha256"] == (
        __import__("hashlib").sha256(existing).hexdigest()
    )
    assert archive_path.read_bytes() == existing


def test_corrupt_or_plaintext_mismatched_existing_archive_is_rejected(
    tmp_path: Path,
) -> None:
    """破損ZIPと異なる平文を持つAES ZIPのどちらも再利用しない。"""

    expected = b"A" * 128
    digest = __import__("hashlib").sha256(expected).hexdigest()
    generated = retrieval.encrypted_zip_bytes(expected, "payload.bin", "infected")

    corrupt_path = tmp_path / "corrupt.zip"
    corrupt_path.write_bytes(b"not-a-zip")
    with pytest.raises(ValueError, match="安全に検証"):
        retrieval.persist_encrypted_archive(
            corrupt_path,
            generated,
            member_name="payload.bin",
            password="infected",
            expected_size=len(expected),
            expected_sha256=digest,
        )

    mismatch_path = tmp_path / "mismatch.zip"
    mismatched = retrieval.encrypted_zip_bytes(
        b"B" * len(expected), "payload.bin", "infected"
    )
    mismatch_path.write_bytes(mismatched)
    with pytest.raises(ValueError, match="平文SHA-256"):
        retrieval.persist_encrypted_archive(
            mismatch_path,
            generated,
            member_name="payload.bin",
            password="infected",
            expected_size=len(expected),
            expected_sha256=digest,
        )
    assert corrupt_path.read_bytes() == b"not-a-zip"
    assert mismatch_path.read_bytes() == mismatched


def test_load_reviewed_candidates_builds_memory_endpoint(tmp_path: Path) -> None:
    manifest = tmp_path / "reviewed.json"
    manifest.write_text(
        json.dumps(
            {
                "candidates": [
                    {
                        "parent_sha256": SHA256,
                        "sample_id": "260802-abcdefghij",
                        "task_id": "behavioral2",
                        "name": "memory/proc-memory.dmp",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    candidates = retrieval.load_reviewed_candidates(manifest)
    assert candidates[0]["kind"] == "memory_image"
    assert candidates[0]["selection"] == "reviewed_report_memory"
    assert candidates[0]["endpoint_path"].endswith(
        "/behavioral2/memory/proc-memory.dmp"
    )


@pytest.mark.parametrize(
    "name",
    ["../memory.dmp", "memory/../memory.dmp", "files/proc-memory.dmp", "memory/not-a-dump"],
)
def test_load_reviewed_candidates_rejects_unsafe_scope(
    tmp_path: Path, name: str
) -> None:
    manifest = tmp_path / "reviewed.json"
    manifest.write_text(
        json.dumps(
            [
                {
                    "parent_sha256": SHA256,
                    "sample_id": "260802-abcdefghij",
                    "task_id": "behavioral1",
                    "name": name,
                }
            ]
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError):
        retrieval.load_reviewed_candidates(manifest)

class RecordingOpener:
    def __init__(self) -> None:
        self.urls: list[str] = []

    def open(self, request, timeout):  # noqa: ANN001, ANN201, ARG002
        self.urls.append(request.full_url)
        return object()


class PublicPageResponse:
    status = 200

    def __enter__(self):  # noqa: ANN204
        return self

    def __exit__(self, *args):  # noqa: ANN002, ANN204
        return False

    def read(self, limit: int) -> bytes:  # noqa: ARG002
        return b"public analysis 260802-abcdefghij"


class PublicPageOpener:
    def open(self, request, timeout):  # noqa: ANN001, ANN201, ARG002
        assert request.get_header("Authorization") is None
        return PublicPageResponse()


def test_verify_public_page_is_unauthenticated_and_id_bound() -> None:
    opener = PublicPageOpener()
    assert retrieval.verify_public_page(
        "260802-abcdefghij", opener=opener, timeout=1
    )
    assert not retrieval.verify_public_page(
        "260802-jq6svser5s", opener=opener, timeout=1
    )


def test_safe_error_record_keeps_only_http_status() -> None:
    error = urllib.error.HTTPError("https://tria.ge/api/v0/x", 403, "denied", {}, None)
    assert retrieval.safe_error_record(error) == {
        "error": "HTTPError",
        "http_status": 403,
    }

def test_request_allows_query_only_for_exact_hash_search() -> None:
    opener = RecordingOpener()
    retrieval._request(
        "/search?query=sha256%3A" + SHA256,
        "secret",
        accept="application/json",
        opener=opener,
        timeout=1,
    )
    assert opener.urls == [retrieval.TRIAGE_API + "/search?query=sha256%3A" + SHA256]
    with pytest.raises(ValueError, match="許可"):
        retrieval._request(
            "/samples/260802-abcdefghij?unexpected=1",
            "secret",
            accept="application/json",
            opener=opener,
            timeout=1,
        )
