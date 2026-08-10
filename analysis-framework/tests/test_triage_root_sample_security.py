"""Triage root sample取得のredirect拒否と件数上限を検証する。"""

from __future__ import annotations

import json
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

import pytest
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


def candidate(digest: str, sample_id: str) -> dict[str, Any]:
    """test用のroot sample候補を返す。"""

    return {
        "parent_sha256": digest,
        "expected_sha256": digest,
        "sample_id": sample_id,
        "kind": "root_sample",
        "selection": "exact_sha256_public_triage_analysis",
        "endpoint_path": f"/samples/{sample_id}/sample",
        "metadata_sha256_verified": True,
    }


@pytest.mark.parametrize(
    "redirect_url",
    [
        "https://tria.ge/api/v0/samples/260810-abcdefghij/sample2",
        "https://example.invalid/credential-capture",
    ],
)
def test_no_redirect_rejects_same_and_cross_host_redirects(redirect_url: str) -> None:
    """Bearer header付きrequestはsame-host／cross-hostともredirectしない。"""

    handler = retrieval.NoRedirect()
    request = urllib.request.Request(
        "https://tria.ge/api/v0/samples/260810-abcdefghij/sample",
        headers={"Authorization": "Bearer test-secret"},
    )
    with pytest.raises(urllib.error.HTTPError, match="redirect refused"):
        handler.redirect_request(request, None, 302, "Found", {}, redirect_url)


def test_parser_limits_root_sample_download_to_one_by_default(tmp_path: Path) -> None:
    """root sampleの既定上限は1件に固定する。"""

    args = retrieval.build_parser().parse_args(["--output-root", str(tmp_path)])
    assert args.max_root_samples == 1
    assert args.max_root_sample_bytes == retrieval.DEFAULT_MAX_SAMPLE_BYTES
    assert args.max_root_total_bytes == retrieval.DEFAULT_MAX_ROOT_TOTAL_BYTES


def test_non_positive_root_sample_limit_is_rejected(tmp_path: Path) -> None:
    """0件以下のroot sample上限をnetwork準備前に拒否する。"""

    with pytest.raises(ValueError, match="max_root_samples"):
        retrieval.main(
            [
                "--allow-network",
                "--hash",
                SHA256_A,
                "--output-root",
                str(tmp_path / "triage"),
                "--max-root-samples",
                "0",
            ]
        )


@pytest.mark.parametrize(
    ("argument", "value", "message"),
    [
        ("--max-root-sample-bytes", "0", "max_root_sample_bytes"),
        (
            "--max-root-sample-bytes",
            str(retrieval.DEFAULT_MAX_SAMPLE_BYTES + 1),
            "max_root_sample_bytes",
        ),
        ("--max-root-total-bytes", "0", "max_root_total_bytes"),
        (
            "--max-root-total-bytes",
            str(retrieval.MAX_ROOT_TOTAL_BYTES + 1),
            "max_root_total_bytes",
        ),
    ],
)
def test_invalid_root_byte_limits_are_rejected_before_network(
    tmp_path: Path,
    argument: str,
    value: str,
    message: str,
) -> None:
    """root sample byte上限の範囲外をnetwork準備前に拒否する。"""

    with pytest.raises(ValueError, match=message):
        retrieval.main(
            [
                "--allow-network",
                "--hash",
                SHA256_A,
                "--output-root",
                str(tmp_path / "triage"),
                argument,
                value,
            ]
        )


def test_main_injects_no_redirect_http_client_and_applies_root_limit(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
) -> None:
    """root取得clientへNoRedirectを渡し、既定1件だけを取得する。"""

    captured: dict[str, Any] = {"calls": []}
    http_sentinel = object()

    def fake_discover(*args, root_sample_candidates=None, **kwargs):  # noqa: ANN002, ANN003, ANN202
        assert root_sample_candidates is not None
        root_sample_candidates.extend(
            [candidate(SHA256_A, SAMPLE_A), candidate(SHA256_B, SAMPLE_B)]
        )
        return [], []

    def fake_http_client(**kwargs):  # noqa: ANN003, ANN202
        captured["http_kwargs"] = kwargs
        return http_sentinel

    class FakeTriageClient:
        """注入されたHTTP clientと取得件数を記録する。"""

        def __init__(self, *, http: object) -> None:
            assert http is http_sentinel

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
            captured["calls"].append(
                (sample_id, expected_sha256, password, max_bytes)
            )
            return {
                "source": "hatching_triage",
                "sample_id": sample_id,
                "archive_path": str(output_path),
                "archive_sha256": "c" * 64,
                "archive_size": 100,
                "archive_encrypted": True,
                "archive_encryption": "WinZip AES-256",
                "archive_member_name": member_name,
                "archive_extracted": False,
                "server_response_encrypted_zip": False,
                "source_sha256": expected_sha256,
                "source_size": 90,
                "plaintext_written": False,
                "sample_executed_locally": False,
            }

    monkeypatch.setenv("TRIAGE_API_KEY", "test-key")
    monkeypatch.setattr(retrieval, "discover_candidates", fake_discover)
    monkeypatch.setattr(retrieval, "HttpClient", fake_http_client)
    monkeypatch.setattr(retrieval, "TriageClient", FakeTriageClient)
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

    http_kwargs = captured["http_kwargs"]
    assert http_kwargs["attempts"] == 1
    assert any(
        isinstance(handler, retrieval.NoRedirect)
        for handler in http_kwargs["opener"].handlers
    )
    assert captured["calls"] == [
        (SAMPLE_A, SHA256_A, "infected", retrieval.DEFAULT_MAX_SAMPLE_BYTES)
    ]
    manifest = json.loads((output_root / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["root_sample_limit"] == 1
    assert manifest["root_sample_downloaded_count"] == 1
    assert manifest["root_sample_download_status"] == "complete"
    assert manifest["root_sample_budget"]["archive_total_bytes"] == 100
