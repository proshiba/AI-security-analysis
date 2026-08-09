#!/usr/bin/env python3
"""StealC v1履歴PCAP判定の固定review registryを検証する。"""

from __future__ import annotations

import hashlib
import ipaddress
import os
import re
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path, PurePosixPath
from urllib.parse import urlsplit, urlunsplit

from immutable_snapshot import decode_strict_json, read_bounded_snapshot
from safe_private_output import reject_existing_reparse_components

REGISTRY_RELATIVE_PATH = PurePosixPath("analysis-framework/malware/stealc/v1_pcap_review_registry.json")
REGISTRY_TYPE = "stealc_v1_pcap_review_registry"
REGISTRY_SHA256 = "b791acae6d172636b47320e650741d5a3e33ce1a2bbb01ad052376df7f26a79b"
MAX_REGISTRY_BYTES = 64 * 1024
MAX_REVIEWS = 256
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
SAFE_ID = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")
REVIEW_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
UTC_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$")
REVIEW_KEYS = {
    "review_id",
    "status",
    "root_sample_sha256",
    "static_config_sha256",
    "terminal_payload_sha256",
    "endpoint",
    "evidence_manifest_sha256",
    "pcap_sha256",
    "triage_sample_id",
    "triage_task_id",
    "capture_started_at_utc",
    "pcap_file_name",
}


class StealCReviewRegistryError(ValueError):
    """固定review registryのschema・digest・pinが不正な場合のエラー。"""


@dataclass(frozen=True)
class StealCPCAPReview:
    """review済みStealC v1 captureの固定値。"""

    review_id: str
    root_sample_sha256: str
    static_config_sha256: str
    terminal_payload_sha256: str
    endpoint: str
    evidence_manifest_sha256: str
    pcap_sha256: str
    triage_sample_id: str
    triage_task_id: str
    capture_started_at_utc: str
    pcap_file_name: str

    def public_dict(self) -> dict[str, str]:
        """機械可読なreview pinを返す。"""
        return asdict(self)


def default_repository_root() -> Path:
    """このmoduleが属するrepository rootを返す。"""
    return Path(__file__).resolve().parents[2]


def _canonical_registry_sha256(data: bytes) -> str:
    """GitのCRLF checkout差を除いた固定registry digestを返す。"""
    canonical = data.replace(b"\r\n", b"\n")
    if b"\r" in canonical:
        raise StealCReviewRegistryError("固定StealC review registryの改行が不正です")
    return hashlib.sha256(canonical).hexdigest()


def _sha256(value: object, label: str) -> str:
    if not isinstance(value, str):
        raise StealCReviewRegistryError(f"{label}は文字列ではありません")
    normalized = value.lower()
    if SHA256_RE.fullmatch(normalized) is None:
        raise StealCReviewRegistryError(f"{label}が正しいSHA-256ではありません")
    return normalized


def _safe_id(value: object, label: str) -> str:
    if not isinstance(value, str) or SAFE_ID.fullmatch(value) is None:
        raise StealCReviewRegistryError(f"{label}が不正です")
    return value


def _review_id(value: object) -> str:
    if not isinstance(value, str) or REVIEW_ID_RE.fullmatch(value) is None:
        raise StealCReviewRegistryError("review_idが不正です")
    return value


def _capture_time(value: object) -> str:
    if not isinstance(value, str) or UTC_RE.fullmatch(value) is None:
        raise StealCReviewRegistryError("capture_started_at_utcが不正です")
    try:
        datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError as error:
        raise StealCReviewRegistryError("capture_started_at_utcが不正です") from error
    return value


def _file_name(value: object) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= 255
        or value in {".", ".."}
        or "/" in value
        or "\\" in value
        or ":" in value
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
    ):
        raise StealCReviewRegistryError("pcap_file_nameが不正です")
    return value


def _endpoint(value: object) -> str:
    if not isinstance(value, str):
        raise StealCReviewRegistryError("endpointは文字列ではありません")
    try:
        parsed = urlsplit(value)
        explicit_port = parsed.port
    except ValueError as error:
        raise StealCReviewRegistryError("endpointを解析できません") from error
    scheme = parsed.scheme.lower()
    port = explicit_port or (443 if scheme == "https" else 80)
    if (
        scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or not parsed.path.startswith("/")
        or parsed.path == "/"
        or len(parsed.path) > 2048
        or explicit_port == 0
    ):
        raise StealCReviewRegistryError("endpointが許可された完全URLではありません")
    host = parsed.hostname.lower().rstrip(".")
    try:
        host = str(ipaddress.ip_address(host))
    except ValueError:
        if (
            not host.isascii()
            or any(ord(character) < 0x21 for character in host)
            or any(not label or len(label) > 63 for label in host.split("."))
        ):
            raise StealCReviewRegistryError("endpoint hostが不正です")
    authority = f"[{host}]" if ":" in host else host
    if port != (443 if scheme == "https" else 80):
        authority = f"{authority}:{port}"
    return urlunsplit((scheme, authority, parsed.path, "", ""))


def _repository_registry_path(repository_root: Path) -> tuple[Path, Path]:
    root = Path(os.path.abspath(os.fspath(repository_root)))
    registry = root.joinpath(*REGISTRY_RELATIVE_PATH.parts)
    try:
        reject_existing_reparse_components(root)
        reject_existing_reparse_components(registry)
        resolved_root = root.resolve(strict=True)
        resolved_registry = registry.resolve(strict=True)
        resolved_registry.relative_to(resolved_root)
    except (OSError, RuntimeError, ValueError) as error:
        raise StealCReviewRegistryError("固定StealC review registryを安全に解決できません") from error
    return resolved_root, resolved_registry


def load_stealc_v1_review_registry(*, repository_root: Path | None = None) -> dict[str, object]:
    """固定path・compile-time digestのreview registryを読み込む。"""
    root, registry_path = _repository_registry_path(repository_root or default_repository_root())
    del root
    snapshot = read_bounded_snapshot(registry_path, MAX_REGISTRY_BYTES)
    registry_sha256 = _canonical_registry_sha256(snapshot.data)
    if registry_sha256 != REGISTRY_SHA256:
        raise StealCReviewRegistryError("固定StealC review registryのSHA-256 pinが一致しません")
    payload = decode_strict_json(snapshot.data)
    if not isinstance(payload, dict) or set(payload) != {
        "schema_version",
        "registry_type",
        "reviews",
    }:
        raise StealCReviewRegistryError("StealC review registry root schemaが不正です")
    if payload.get("schema_version") != 1 or payload.get("registry_type") != REGISTRY_TYPE:
        raise StealCReviewRegistryError("StealC review registry typeが不正です")
    rows = payload.get("reviews")
    if not isinstance(rows, list) or not 1 <= len(rows) <= MAX_REVIEWS:
        raise StealCReviewRegistryError("StealC review registry reviewsが不正です")

    reviews: dict[str, StealCPCAPReview] = {}
    for index, value in enumerate(rows):
        if not isinstance(value, dict) or set(value) != REVIEW_KEYS:
            raise StealCReviewRegistryError(f"reviews[{index}] schemaが不正です")
        if value.get("status") != "approved":
            raise StealCReviewRegistryError(f"reviews[{index}]はapprovedではありません")
        record = StealCPCAPReview(
            review_id=_review_id(value.get("review_id")),
            root_sample_sha256=_sha256(value.get("root_sample_sha256"), "root sample SHA-256"),
            static_config_sha256=_sha256(value.get("static_config_sha256"), "static config SHA-256"),
            terminal_payload_sha256=_sha256(value.get("terminal_payload_sha256"), "terminal payload SHA-256"),
            endpoint=_endpoint(value.get("endpoint")),
            evidence_manifest_sha256=_sha256(
                value.get("evidence_manifest_sha256"),
                "evidence manifest SHA-256",
            ),
            pcap_sha256=_sha256(value.get("pcap_sha256"), "PCAP SHA-256"),
            triage_sample_id=_safe_id(value.get("triage_sample_id"), "Triage sample ID"),
            triage_task_id=_safe_id(value.get("triage_task_id"), "Triage task ID"),
            capture_started_at_utc=_capture_time(value.get("capture_started_at_utc")),
            pcap_file_name=_file_name(value.get("pcap_file_name")),
        )
        if record.review_id in reviews:
            raise StealCReviewRegistryError("review_idが重複しています")
        reviews[record.review_id] = record
    return {
        "source": REGISTRY_RELATIVE_PATH.as_posix(),
        "sha256": registry_sha256,
        "reviews": reviews,
    }


def load_stealc_v1_review(
    review_id: object, *, repository_root: Path | None = None
) -> tuple[StealCPCAPReview, str, str]:
    """allowlist済みreview IDとregistry source/digestを返す。"""
    normalized = _review_id(review_id)
    registry = load_stealc_v1_review_registry(repository_root=repository_root)
    reviews = registry["reviews"]
    assert isinstance(reviews, dict)
    review = reviews.get(normalized)
    if not isinstance(review, StealCPCAPReview):
        raise StealCReviewRegistryError("review_idが固定registryにありません")
    return review, str(registry["source"]), str(registry["sha256"])


__all__ = [
    "REGISTRY_RELATIVE_PATH",
    "REGISTRY_SHA256",
    "StealCPCAPReview",
    "StealCReviewRegistryError",
    "load_stealc_v1_review",
    "load_stealc_v1_review_registry",
]
