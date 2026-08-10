"""Triage root sampleの明示取得と失敗分離を検証する。"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from pytest import MonkeyPatch

ROOT = Path(__file__).resolve().parents[1]
COMMON = ROOT / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

import triage_artifact_retrieval as retrieval  # noqa: E402

SHA256_A = "a" * 64
SHA256_B = "b" * 64
SAMPLE_A = "260810-abcdefghij"
SAMPLE_B = "260810-klmnopqrst"


def root_candidate(digest: str, sample_id: str) -> dict[str, Any]:
    """test用の完全hash一致root sample候補を返す。"""

    return {
        "parent_sha256": digest,
        "expected_sha256": digest,
        "sample_id": sample_id,
        "kind": "root_sample",
        "selection": "exact_sha256_public_triage_analysis",
        "endpoint_path": f"/samples/{sample_id}/sample",
        "metadata_sha256_verified": True,
    }


class RecordingClient:
    """外部通信を行わず、fetch_sample呼出しだけを記録する。"""

    def __init__(self, *, fail_for: set[str] | None = None) -> None:
        self.fail_for = fail_for or set()
        self.calls: list[dict[str, Any]] = []

    def fetch_sample(
        self,
        sample_id: str,
        output_path: Path,
        *,
        expected_sha256: str,
        password: str,
        member_name: str,
        max_bytes: int,
    ) -> dict[str, Any]:
        """固定応答を返し、指定したIDだけ既存file相当の失敗にする。"""

        self.calls.append(
            {
                "sample_id": sample_id,
                "output_path": output_path,
                "expected_sha256": expected_sha256,
                "password": password,
                "member_name": member_name,
                "max_bytes": max_bytes,
            }
        )
        if sample_id in self.fail_for:
            raise FileExistsError("秘密pathを含む想定のtest error")
        return {
            "source": "hatching_triage",
            "sample_id": sample_id,
            "archive_path": str(output_path),
            "archive_sha256": "c" * 64,
            "archive_size": 1234,
            "archive_encrypted": True,
            "archive_encryption": "WinZip AES-256",
            "archive_member_name": member_name,
            "archive_extracted": False,
            "server_response_encrypted_zip": False,
            "source_sha256": expected_sha256,
            "source_size": 1200,
            "plaintext_written": False,
            "sample_executed_locally": False,
        }


def test_parser_keeps_root_sample_download_disabled_by_default(tmp_path: Path) -> None:
    """root sample取得は既定で無効にする。"""

    args = retrieval.build_parser().parse_args(["--output-root", str(tmp_path)])
    assert args.include_root_sample is False
    assert args.max_root_sample_bytes == retrieval.DEFAULT_MAX_SAMPLE_BYTES
    assert args.max_root_total_bytes == retrieval.DEFAULT_MAX_ROOT_TOTAL_BYTES


def test_root_sample_download_is_exact_hash_bound_and_fail_isolated(
    tmp_path: Path,
) -> None:
    """1件の既存file拒否後も、次の完全hash一致検体を取得する。"""

    client = RecordingClient(fail_for={SAMPLE_A})
    downloads, errors, budget = retrieval._retrieve_root_samples(
        [root_candidate(SHA256_A, SAMPLE_A), root_candidate(SHA256_B, SAMPLE_B)],
        output_root=tmp_path,
        password="infected",
        client=client,
        max_samples=20,
        max_sample_bytes=4096,
        max_total_bytes=8192,
    )

    assert len(client.calls) == 2
    assert [call["max_bytes"] for call in client.calls] == [4096, 4096]
    assert all(call["expected_sha256"] in {SHA256_A, SHA256_B} for call in client.calls)
    assert client.calls[1]["member_name"] == f"{SHA256_B}.bin"
    assert client.calls[1]["output_path"] == (
        tmp_path / SHA256_B / SAMPLE_B / "root-sample.zip"
    )
    assert len(downloads) == 1
    assert downloads[0]["source"] == "hatching_triage"
    assert downloads[0]["source_sha256"] == SHA256_B
    assert downloads[0]["source_size"] == 1200
    assert downloads[0]["archive_sha256"] == "c" * 64
    assert downloads[0]["archive_size"] == 1234
    assert downloads[0]["archive_encryption"] == "WinZip AES-256"
    assert downloads[0]["plaintext_written"] is False
    assert downloads[0]["payload_sha256_verified"] is True
    assert errors == [
        {
            "parent_sha256": SHA256_A,
            "expected_sha256": SHA256_A,
            "sample_id": SAMPLE_A,
            "stage": "root_sample_download",
            "error": "FileExistsError",
        }
    ]
    assert "秘密path" not in json.dumps(errors, ensure_ascii=False)
    assert budget["status"] == "partial"
    assert budget["archive_total_bytes"] == 1234
    assert budget["budget_exhausted"] is False


def test_missing_expected_sha256_never_calls_helper(tmp_path: Path) -> None:
    """完全SHA-256がない候補ではhelperを呼ばない。"""

    client = RecordingClient()
    candidate = root_candidate(SHA256_A, SAMPLE_A)
    candidate.pop("expected_sha256")
    downloads, errors, budget = retrieval._retrieve_root_samples(
        [candidate],
        output_root=tmp_path,
        password="infected",
        client=client,
        max_samples=20,
        max_sample_bytes=4096,
        max_total_bytes=8192,
    )

    assert downloads == []
    assert client.calls == []
    assert errors[0]["stage"] == "root_sample_download"
    assert errors[0]["error"] == "ValueError"
    assert budget["status"] == "partial"


def test_aggregate_budget_passes_remaining_and_records_exhaustion(
    tmp_path: Path,
) -> None:
    """2件目へ残量だけを渡し、超過をpartialとして記録する。"""

    class BudgetClient(RecordingClient):
        def fetch_sample(self, *args, max_bytes: int, **kwargs):  # noqa: ANN002, ANN003, ANN202
            self.calls.append({"max_bytes": max_bytes})
            if len(self.calls) == 1:
                return {
                    "archive_encrypted": True,
                    "archive_size": 80,
                    "plaintext_written": False,
                    "server_response_encrypted_zip": False,
                }
            raise retrieval.ExternalServiceError(
                "archive size limit",
                code="archive_size_limit_exceeded",
            )

    client = BudgetClient()
    downloads, errors, budget = retrieval._retrieve_root_samples(
        [root_candidate(SHA256_A, SAMPLE_A), root_candidate(SHA256_B, SAMPLE_B)],
        output_root=tmp_path,
        password="infected",
        client=client,
        max_samples=20,
        max_sample_bytes=90,
        max_total_bytes=100,
    )

    assert [call["max_bytes"] for call in client.calls] == [90, 20]
    assert len(downloads) == 1
    assert errors[0]["reason"] == "archive_size_limit_exceeded"
    assert budget["status"] == "partial"
    assert budget["archive_total_bytes"] == 80
    assert budget["remaining_bytes"] == 20
    assert budget["budget_exhausted"] is True
    assert budget["exhausted_reasons"] == [
        "root_sample_aggregate_byte_budget_exhausted"
    ]


def test_root_sample_candidates_are_deduplicated_by_expected_hash() -> None:
    """同一検体の複数公開解析からroot sampleを重複取得しない。"""

    candidates = retrieval._deduplicate_root_sample_candidates(
        [root_candidate(SHA256_A, SAMPLE_A), root_candidate(SHA256_A, SAMPLE_B)]
    )
    assert candidates == [root_candidate(SHA256_A, SAMPLE_A)]


def test_main_without_opt_in_does_not_construct_download_client(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
) -> None:
    """既定経路は候補列挙後もroot sample clientを生成しない。"""

    def fake_discover(*args, root_sample_candidates=None, **kwargs):  # noqa: ANN002, ANN003, ANN202
        assert root_sample_candidates is None
        return [], []

    def forbidden_client():  # noqa: ANN202
        raise AssertionError("root sample client must not be constructed")

    monkeypatch.setenv("TRIAGE_API_KEY", "test-key")
    monkeypatch.setattr(retrieval, "discover_candidates", fake_discover)
    monkeypatch.setattr(retrieval, "TriageClient", forbidden_client)
    output_root = tmp_path / "triage"

    assert (
        retrieval.main(
            [
                "--allow-network",
                "--hash",
                SHA256_A,
                "--output-root",
                str(output_root),
            ]
        )
        == 0
    )
    manifest = json.loads((output_root / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["root_sample_opt_in"] is False
    assert manifest["root_sample_download_attempted"] is False
    assert manifest["root_sample_downloads"] == []


def test_main_opt_in_records_structured_root_sample_manifest(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
) -> None:
    """明示取得時だけroot sampleの安全情報をmanifestへ構造化する。"""

    client = RecordingClient()

    def fake_discover(*args, root_sample_candidates=None, **kwargs):  # noqa: ANN002, ANN003, ANN202
        assert root_sample_candidates is not None
        root_sample_candidates.append(root_candidate(SHA256_A, SAMPLE_A))
        return [], []

    monkeypatch.setenv("TRIAGE_API_KEY", "test-key")
    monkeypatch.setattr(retrieval, "discover_candidates", fake_discover)
    monkeypatch.setattr(retrieval, "HttpClient", lambda **kwargs: object())
    monkeypatch.setattr(retrieval, "TriageClient", lambda *, http: client)
    output_root = tmp_path / "triage"

    assert (
        retrieval.main(
            [
                "--allow-network",
                "--download",
                "--include-root-sample",
                "--hash",
                SHA256_A,
                "--output-root",
                str(output_root),
            ]
        )
        == 0
    )
    manifest = json.loads((output_root / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["root_sample_opt_in"] is True
    assert manifest["root_sample_download_attempted"] is True
    assert manifest["root_sample_downloaded_count"] == 1
    assert manifest["root_sample_archive_total_bytes"] == 1234
    assert manifest["root_sample_download_status"] == "complete"
    assert manifest["root_sample_budget"]["archive_total_bytes"] == 1234
    assert manifest["root_sample_errors"] == []
    assert manifest["root_sample_downloads"][0]["plaintext_written"] is False
    assert manifest["root_sample_downloads"][0]["expected_sha256"] == SHA256_A
    assert manifest["safety"]["sample_executed_locally"] is False
