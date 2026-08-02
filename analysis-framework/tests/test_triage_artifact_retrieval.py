from __future__ import annotations

from io import BytesIO
from pathlib import Path
import sys
import urllib.error

import pyzipper
import pytest


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
