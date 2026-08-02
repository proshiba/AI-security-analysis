#!/usr/bin/env python3
"""Triageの完全ハッシュ一致解析から次段・メモリ成果物を限定取得する。"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
from io import BytesIO
import json
import os
from pathlib import Path
import re
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

import pyzipper


REPOSITORY = Path(__file__).resolve().parents[2]
TRIAGE_API = "https://tria.ge/api/v0"
USER_AGENT = "AI-security-analysis Triage artifact retrieval/1.0"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
SAMPLE_ID_RE = re.compile(r"^\d{6}-[a-z0-9]{10}$")
TASK_ID_RE = re.compile(r"^behavioral\d+$")
MEMORY_RESOURCE_RE = re.compile(r"^(behavioral\d+)/memory/([^/]+)$")
DEFAULT_MAX_BYTES = 64 * 1024 * 1024
DEFAULT_MAX_TOTAL_BYTES = 256 * 1024 * 1024
MAX_JSON_BYTES = 25 * 1024 * 1024


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """レビュー済みAPI pathから別scopeへ移るredirectを拒否する。"""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001, ANN201
        raise urllib.error.HTTPError(req.full_url, code, "redirect refused", headers, fp)


def utc_now() -> str:
    """現在時刻をUTCのISO 8601形式で返す。"""

    return datetime.now(timezone.utc).isoformat()


def safe_error_record(error: Exception) -> dict[str, Any]:
    """秘密情報を含めず、再試行判断に必要な失敗分類だけを残す。"""

    record: dict[str, Any] = {"error": type(error).__name__}
    if isinstance(error, urllib.error.HTTPError):
        record["http_status"] = int(error.code)
    elif isinstance(error, ValueError):
        record["reason"] = str(error)
    return record

def normalize_sha256(value: Any) -> str:
    """SHA-256を小文字へ正規化し、不正値を拒否する。"""

    digest = str(value or "").strip().lower()
    if not SHA256_RE.fullmatch(digest):
        raise ValueError("有効なSHA-256が必要です")
    return digest


def safe_basename(value: Any) -> str:
    """成果物名をbasenameへ限定し、危険な名前を拒否する。"""

    text = str(value or "").replace("\\", "/").rstrip("/")
    name = text.rsplit("/", 1)[-1]
    if (
        not name
        or name in {".", ".."}
        or any(ord(character) < 32 for character in name)
        or len(name) > 240
    ):
        raise ValueError("安全でないTriage成果物名です")
    return name


def _overview_sha256(overview: dict[str, Any]) -> str:
    sample = overview.get("sample")
    if not isinstance(sample, dict):
        raise ValueError("Triage overviewにsample情報がありません")
    return normalize_sha256(sample.get("sha256"))


def extract_artifact_candidates(
    overview: dict[str, Any],
    *,
    expected_sha256: str,
    sample_id: str,
    include_memory: bool,
) -> list[dict[str, Any]]:
    """overviewから、task境界を検証できる成果物API pathだけを作る。"""

    digest = normalize_sha256(expected_sha256)
    if _overview_sha256(overview) != digest:
        raise ValueError("Triage overviewのSHA-256が要求値と一致しません")
    if not SAMPLE_ID_RE.fullmatch(sample_id):
        raise ValueError("Triage sample IDの形式が不正です")

    candidates: list[dict[str, Any]] = []
    seen: set[str] = set()
    for extracted in overview.get("extracted") or []:
        if not isinstance(extracted, dict):
            continue
        tasks = [
            str(task)
            for task in extracted.get("tasks") or []
            if TASK_ID_RE.fullmatch(str(task))
        ]
        task = tasks[0] if tasks else None

        resource = extracted.get("resource")
        if include_memory and isinstance(resource, str):
            match = MEMORY_RESOURCE_RE.fullmatch(resource.replace("\\", "/"))
            if match:
                resource_task, name = match.groups()
                safe_name = safe_basename(name)
                endpoint = (
                    f"/samples/{sample_id}/{resource_task}/memory/"
                    f"{urllib.parse.quote(safe_name, safe='')}"
                )
                if endpoint not in seen:
                    seen.add(endpoint)
                    candidates.append(
                        {
                            "parent_sha256": digest,
                            "sample_id": sample_id,
                            "task_id": resource_task,
                            "kind": "memory_image",
                            "name": safe_name,
                            "endpoint_path": endpoint,
                            "reference_sha256": hashlib.sha256(resource.encode()).hexdigest(),
                        }
                    )

        dumped = extracted.get("dumped_file")
        if not isinstance(dumped, str) or not task:
            continue
        normalized = dumped.replace("\\", "/")
        safe_name = safe_basename(normalized)
        is_memory = normalized.startswith("memory/") or safe_name.lower().endswith("memory.dmp")
        if is_memory and not include_memory:
            continue
        kind = "memory_image" if is_memory else "dumped_file"
        endpoint_kind = "memory" if is_memory else "files"
        endpoint = (
            f"/samples/{sample_id}/{task}/{endpoint_kind}/"
            f"{urllib.parse.quote(safe_name, safe='')}"
        )
        if endpoint in seen:
            continue
        seen.add(endpoint)
        candidates.append(
            {
                "parent_sha256": digest,
                "sample_id": sample_id,
                "task_id": task,
                "kind": kind,
                "name": safe_name,
                "endpoint_path": endpoint,
                "reference_sha256": hashlib.sha256(dumped.encode()).hexdigest(),
            }
        )
    return candidates


def _request(
    path: str,
    api_key: str,
    *,
    accept: str,
    opener: Any,
    timeout: float,
):
    parsed = urllib.parse.urlsplit(path)
    if (
        parsed.scheme
        or parsed.netloc
        or parsed.fragment
        or not parsed.path.startswith("/")
        or ".." in parsed.path
        or (parsed.query and parsed.path != "/search")
    ):
        raise ValueError("許可されていないTriage API pathです")
    request = urllib.request.Request(
        TRIAGE_API + path,
        headers={
            "Authorization": f"Bearer {api_key}",
            "Accept": accept,
            "User-Agent": USER_AGENT,
        },
    )
    return opener.open(request, timeout=timeout)


def verify_public_page(sample_id: str, *, opener: Any, timeout: float) -> bool:
    """認証情報なしでTriage解析ページが公開されていることを確認する。"""

    if not SAMPLE_ID_RE.fullmatch(sample_id):
        return False
    request = urllib.request.Request(
        f"https://tria.ge/{sample_id}",
        headers={"User-Agent": USER_AGENT, "Accept": "text/html"},
    )
    try:
        with opener.open(request, timeout=timeout) as response:
            status = int(getattr(response, "status", 200))
            body = response.read(256 * 1024)
    except (OSError, urllib.error.URLError, urllib.error.HTTPError):
        return False
    return status == 200 and sample_id.encode("ascii") in body

def api_json(path: str, api_key: str, *, opener: Any, timeout: float) -> Any:
    """許可済みTriage API pathから上限付きJSONを取得する。"""

    with _request(
        path,
        api_key,
        accept="application/json",
        opener=opener,
        timeout=timeout,
    ) as response:
        data = response.read(MAX_JSON_BYTES + 1)
        if len(data) > MAX_JSON_BYTES:
            raise ValueError("Triage JSON応答が上限を超えました")
        return json.loads(data.decode("utf-8"))


def fetch_bounded(
    endpoint_path: str,
    api_key: str,
    *,
    opener: Any,
    timeout: float,
    max_bytes: int,
) -> tuple[bytes, dict[str, Any]]:
    """成果物を指定byte上限内で取得し、HTTP証跡を返す。"""

    if not 1 <= max_bytes <= DEFAULT_MAX_BYTES:
        raise ValueError("max_bytesは1から64MiBの範囲が必要です")
    with _request(
        endpoint_path,
        api_key,
        accept="application/octet-stream",
        opener=opener,
        timeout=timeout,
    ) as response:
        status = int(getattr(response, "status", 200))
        if not 200 <= status < 300:
            raise ValueError("Triage成果物取得が成功statusではありません")
        content_length = response.headers.get("Content-Length")
        if content_length is not None and int(content_length) > max_bytes:
            raise ValueError("Triage成果物のContent-Lengthが上限を超えました")
        data = response.read(max_bytes + 1)
        if len(data) > max_bytes:
            raise ValueError("Triage成果物本文が上限を超えました")
        return data, {
            "http_status": status,
            "content_type": response.headers.get("Content-Type"),
            "content_length_header": content_length,
            "redirects_followed": False,
        }


def encrypted_zip_bytes(data: bytes, member_name: str, password: str) -> bytes:
    """平文をdiskへ書かず、AES-256 ZIPをmemory上で作る。"""

    safe_name = safe_basename(member_name)
    buffer = BytesIO()
    with pyzipper.AESZipFile(
        buffer,
        "w",
        compression=pyzipper.ZIP_DEFLATED,
        encryption=pyzipper.WZ_AES,
    ) as archive:
        archive.setpassword(password.encode("utf-8"))
        archive.setencryption(pyzipper.WZ_AES, nbits=256)
        archive.writestr(safe_name, data)
    return buffer.getvalue()


def _manifest_hashes(path: Path) -> list[str]:
    document = json.loads(path.read_text(encoding="utf-8-sig"))
    values = document.get("selected_hashes") or []
    return [normalize_sha256(value) for value in values]


def _atomic_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(value, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)


def _outside_repository(path: Path) -> Path:
    resolved = path.resolve()
    try:
        resolved.relative_to(REPOSITORY)
    except ValueError:
        return resolved
    raise ValueError("Triage成果物の保存先はリポジトリ外である必要があります")


def discover_candidates(
    hashes: list[str],
    api_key: str,
    *,
    opener: Any,
    timeout: float,
    include_memory: bool,
) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    """完全hash一致の公開解析から取得候補と失敗分類を列挙する。"""

    candidates: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    for digest in sorted({normalize_sha256(value) for value in hashes}):
        try:
            query = urllib.parse.urlencode({"query": f"sha256:{digest}"})
            search = api_json(f"/search?{query}", api_key, opener=opener, timeout=timeout)
        except Exception as error:  # network/API parserは異種例外を返す
            errors.append({"parent_sha256": digest, "stage": "search", **safe_error_record(error)})
            continue
        for row in (search.get("data") or [])[:3]:
            sample_id = str((row or {}).get("id") or "")
            if not SAMPLE_ID_RE.fullmatch(sample_id):
                continue
            try:
                metadata = api_json(
                    f"/samples/{sample_id}", api_key, opener=opener, timeout=timeout
                )
                if normalize_sha256(metadata.get("sha256")) != digest:
                    raise ValueError("Triage metadataのSHA-256が一致しません")
                if metadata.get("private") is True or metadata.get("owner"):
                    raise ValueError("公開解析ではないため成果物取得を拒否しました")
                if metadata.get("private") is not False and not verify_public_page(
                    sample_id, opener=opener, timeout=timeout
                ):
                    raise ValueError("公開解析ではないため成果物取得を拒否しました")
                overview = api_json(
                    f"/samples/{sample_id}/overview.json",
                    api_key,
                    opener=opener,
                    timeout=timeout,
                )
                candidates.extend(
                    extract_artifact_candidates(
                        overview,
                        expected_sha256=digest,
                        sample_id=sample_id,
                        include_memory=include_memory,
                    )
                )
            except Exception as error:  # network/API parserは異種例外を返す
                errors.append(
                    {
                        "parent_sha256": digest,
                        "sample_id": sample_id,
                        "stage": "overview",
                        **safe_error_record(error),
                    }
                )
    unique = {item["endpoint_path"]: item for item in candidates}
    return list(unique.values()), errors


def build_parser() -> argparse.ArgumentParser:
    """限定取得CLIの引数parserを構築する。"""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hash", action="append", default=[])
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--output-root", required=True, type=Path)
    parser.add_argument("--allow-network", action="store_true")
    parser.add_argument("--download", action="store_true")
    parser.add_argument("--include-memory", action="store_true")
    parser.add_argument("--max-artifacts", type=int, default=20)
    parser.add_argument("--max-bytes", type=int, default=DEFAULT_MAX_BYTES)
    parser.add_argument("--max-total-bytes", type=int, default=DEFAULT_MAX_TOTAL_BYTES)
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument("--password", default="infected")
    return parser


def main(argv: list[str] | None = None) -> int:
    """候補列挙と任意の暗号化取得を実行する。"""

    args = build_parser().parse_args(argv)
    if not args.allow_network:
        raise SystemExit("--allow-networkなしではTriage APIへ接続しません")
    if not 1 <= args.max_artifacts <= 100:
        raise ValueError("max_artifactsは1から100の範囲が必要です")
    if not 1 <= args.max_total_bytes <= 1024 * 1024 * 1024:
        raise ValueError("max_total_bytesは1から1GiBの範囲が必要です")
    api_key = os.environ.get("TRIAGE_API_KEY", "")
    if not api_key:
        raise SystemExit("TRIAGE_API_KEYが必要です")
    hashes = list(args.hash)
    if args.manifest:
        hashes.extend(_manifest_hashes(args.manifest.resolve()))
    if not hashes:
        raise ValueError("--hashまたは--manifestでSHA-256を指定してください")

    output_root = _outside_repository(args.output_root)
    output_root.mkdir(parents=True, exist_ok=True)
    opener = urllib.request.build_opener(NoRedirect())
    candidates, errors = discover_candidates(
        hashes,
        api_key,
        opener=opener,
        timeout=args.timeout,
        include_memory=args.include_memory,
    )
    downloads: list[dict[str, Any]] = []
    total_bytes = 0
    if args.download:
        for candidate in candidates[: args.max_artifacts]:
            try:
                remaining = args.max_total_bytes - total_bytes
                if remaining <= 0:
                    raise ValueError("総取得量上限に到達しました")
                data, response = fetch_bounded(
                    candidate["endpoint_path"],
                    api_key,
                    opener=opener,
                    timeout=args.timeout,
                    max_bytes=min(args.max_bytes, remaining),
                )
                digest = hashlib.sha256(data).hexdigest()
                archive_bytes = encrypted_zip_bytes(data, candidate["name"], args.password)
                case_root = output_root / candidate["parent_sha256"] / candidate["sample_id"]
                case_root.mkdir(parents=True, exist_ok=True)
                archive_path = case_root / f"artifact-{digest[:16]}.zip"
                if not archive_path.exists():
                    archive_path.write_bytes(archive_bytes)
                total_bytes += len(data)
                downloads.append(
                    {
                        **candidate,
                        **response,
                        "artifact_sha256": digest,
                        "size": len(data),
                        "archive_path": str(archive_path),
                        "archive_sha256": hashlib.sha256(archive_bytes).hexdigest(),
                        "archive_encryption": "AES-256",
                        "duplicate_of_parent": digest == candidate["parent_sha256"],
                        "executed": False,
                    }
                )
            except Exception as error:  # network/API parserは異種例外を返す
                errors.append(
                    {
                        "parent_sha256": candidate["parent_sha256"],
                        "sample_id": candidate["sample_id"],
                        "stage": "download",
                        **safe_error_record(error),
                    }
                )

    result = {
        "schema_version": 1,
        "created_at_utc": utc_now(),
        "query_type": "exact_sha256_public_triage_analysis",
        "requested_hashes": len(set(hashes)),
        "candidate_count": len(candidates),
        "download_attempted": bool(args.download),
        "downloaded_count": len(downloads),
        "downloaded_total_bytes": total_bytes,
        "candidates": candidates,
        "downloads": downloads,
        "errors": errors,
        "safety": {
            "sample_submitted": False,
            "sample_executed_locally": False,
            "artifact_executed": False,
            "network_contacted": True,
            "network_scope": "Triage API exact-hash search and bounded artifact GET only",
            "redirects_followed": False,
            "ambiguous_visibility_requires_unauthenticated_public_page": True,
            "plaintext_artifact_written": False,
            "artifacts_encrypted_at_rest": bool(downloads),
            "api_key_published": False,
        },
    }
    _atomic_json(output_root / "manifest.json", result)
    print(
        json.dumps(
            {
                "requested_hashes": result["requested_hashes"],
                "candidate_count": len(candidates),
                "downloaded_count": len(downloads),
                "errors": len(errors),
                "output": str(output_root / "manifest.json"),
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
