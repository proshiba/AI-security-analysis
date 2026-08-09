"""StealC v1固定review registryのtrust boundaryを検証する。"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest

COMMON_PATH = Path(__file__).parents[1] / "common"
if str(COMMON_PATH) not in sys.path:
    sys.path.insert(0, str(COMMON_PATH))

import stealc_v1_pcap_review as REVIEW


def review_row(review_id: str, seed: str) -> dict[str, object]:
    """有効なreview fixtureを返す。"""
    seed_value = int(seed, 16)

    def digest(offset: int) -> str:
        return format((seed_value + offset) % 16, "x") * 64

    return {
        "review_id": review_id,
        "status": "approved",
        "root_sample_sha256": digest(0),
        "static_config_sha256": digest(1),
        "terminal_payload_sha256": digest(2),
        "endpoint": f"http://192.0.2.{int(seed, 16) + 1}/gate.php",
        "evidence_manifest_sha256": digest(3),
        "pcap_sha256": digest(4),
        "triage_sample_id": f"fixture-{review_id}",
        "triage_task_id": "behavioral1",
        "capture_started_at_utc": "2024-10-15T06:47:12Z",
        "pcap_file_name": f"{review_id}.pcapng",
    }


def write_registry(
    root: Path,
    rows: list[dict[str, object]],
    monkeypatch: pytest.MonkeyPatch,
    newline: str = "lf",
) -> str:
    """固定相対pathへregistryを書き、test用compile-time digestをpinする。"""
    path = root.joinpath(*REVIEW.REGISTRY_RELATIVE_PATH.parts)
    path.parent.mkdir(parents=True)
    document = {
        "schema_version": 1,
        "registry_type": REVIEW.REGISTRY_TYPE,
        "reviews": rows,
    }
    raw_lf = (json.dumps(document, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    if newline not in {"lf", "crlf"}:
        raise AssertionError("test fixtureの改行指定が不正です")
    raw = raw_lf if newline == "lf" else raw_lf.replace(b"\n", b"\r\n")
    path.write_bytes(raw)
    digest = hashlib.sha256(raw_lf).hexdigest()
    monkeypatch.setattr(REVIEW, "REGISTRY_SHA256", digest)
    return digest


def test_repository_registry_loads_current_review() -> None:
    review, source, digest = REVIEW.load_stealc_v1_review("stealc-v1-09034743-241015-hj7k5szgrf-behavioral1")
    assert review.root_sample_sha256 == ("09034743ead73365c3077a85036d69c4ef0b0c19bba669db7cd53814b9308889")
    assert review.endpoint == "http://185.215.113.37/e2b1563c6670f193.php"
    assert source == REVIEW.REGISTRY_RELATIVE_PATH.as_posix()
    assert digest == REVIEW.REGISTRY_SHA256


def test_unreviewed_id_is_fail_closed() -> None:
    with pytest.raises(REVIEW.StealCReviewRegistryError, match="registryにありません"):
        REVIEW.load_stealc_v1_review("unreviewed-fabricated")


def test_registry_digest_is_stable_across_lf_and_crlf(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    digest = write_registry(
        tmp_path,
        [review_row("review-one", "1")],
        monkeypatch,
        newline="crlf",
    )
    review, _, observed_digest = REVIEW.load_stealc_v1_review(
        "review-one", repository_root=tmp_path
    )
    assert review.review_id == "review-one"
    assert observed_digest == digest


def test_registry_rejects_lone_carriage_return(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    write_registry(tmp_path, [review_row("review-one", "1")], monkeypatch, newline="crlf")
    path = tmp_path.joinpath(*REVIEW.REGISTRY_RELATIVE_PATH.parts)
    path.write_bytes(path.read_bytes().replace(b"\r\n", b"\r", 1))
    with pytest.raises(REVIEW.StealCReviewRegistryError, match="改行"):
        REVIEW.load_stealc_v1_review_registry(repository_root=tmp_path)


def test_tampered_registry_digest_is_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    write_registry(tmp_path, [review_row("review-one", "1")], monkeypatch)
    monkeypatch.setattr(REVIEW, "REGISTRY_SHA256", "f" * 64)
    with pytest.raises(REVIEW.StealCReviewRegistryError, match="SHA-256 pin"):
        REVIEW.load_stealc_v1_review_registry(repository_root=tmp_path)


def test_review_id_mismatch_does_not_fall_back(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    write_registry(tmp_path, [review_row("review-one", "1")], monkeypatch)
    with pytest.raises(REVIEW.StealCReviewRegistryError, match="registryにありません"):
        REVIEW.load_stealc_v1_review("review-two", repository_root=tmp_path)


def test_future_distinct_reviewed_entry_is_supported(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    first = review_row("review-one", "1")
    second = review_row("review-two", "6")
    digest = write_registry(tmp_path, [first, second], monkeypatch)
    review, source, observed_digest = REVIEW.load_stealc_v1_review("review-two", repository_root=tmp_path)
    assert review.review_id == "review-two"
    assert review.root_sample_sha256 == "6" * 64
    assert review.endpoint == "http://192.0.2.7/gate.php"
    assert source == REVIEW.REGISTRY_RELATIVE_PATH.as_posix()
    assert observed_digest == digest


def test_all_evidence_fabrication_cannot_modify_fixed_review(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    production_review, _, _ = REVIEW.load_stealc_v1_review("stealc-v1-09034743-241015-hj7k5szgrf-behavioral1")
    fabricated = review_row("fabricated", "1")
    write_registry(tmp_path, [fabricated], monkeypatch)
    fabricated_review, _, _ = REVIEW.load_stealc_v1_review("fabricated", repository_root=tmp_path)
    assert production_review.root_sample_sha256 != fabricated_review.root_sample_sha256
    assert production_review.pcap_sha256 != fabricated_review.pcap_sha256
