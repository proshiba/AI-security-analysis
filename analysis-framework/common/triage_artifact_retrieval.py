#!/usr/bin/env python3
"""Triageの完全ハッシュ一致解析から次段・メモリ成果物を限定取得する。"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import tempfile
import urllib.error
import urllib.parse
import urllib.request

from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path
from typing import Any

import pyzipper
from external_api_helpers import (
    DEFAULT_MAX_SAMPLE_BYTES,
    ExternalServiceError,
    HttpClient,
    NoRedirectHandler,
    TriageClient,
)

REPOSITORY = Path(__file__).resolve().parents[2]
TRIAGE_API = "https://tria.ge/api/v0"
USER_AGENT = "AI-security-analysis Triage artifact retrieval/1.0"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
SAMPLE_ID_RE = re.compile(r"^\d{6}-[a-z0-9]{10}$")
TASK_ID_RE = re.compile(r"^behavioral\d+$")
MEMORY_RESOURCE_RE = re.compile(r"^(behavioral\d+)/memory/([^/]+)$")
REPORT_MEMORY_NAME_RE = re.compile(
    r"^memory/(?P<pid>[1-9]\d{0,9})-(?P<procid>\d{1,10})-"
    r"0x(?P<start>[0-9a-fA-F]{8,16})-0x(?P<end>[0-9a-fA-F]{8,16})-"
    r"memory\.dmp$"
)
DEFAULT_MAX_BYTES = 64 * 1024 * 1024
DEFAULT_MAX_TOTAL_BYTES = 256 * 1024 * 1024
DEFAULT_MAX_REPORT_TASKS = 2
# discovery上限は、実際に取得する件数（--max-artifacts）から独立させる。
# 公開PureRAT解析では2 task合計72 regionがあり、既定の取得上限20を
# discoveryへ流用するとsample全体が拒否されるためである。
DEFAULT_MAX_REPORT_MEMORY_CANDIDATES = 100
DEFAULT_MAX_ROOT_TOTAL_BYTES = DEFAULT_MAX_SAMPLE_BYTES
MAX_ROOT_TOTAL_BYTES = 1024 * 1024 * 1024
MAX_JSON_BYTES = 25 * 1024 * 1024


NoRedirect = NoRedirectHandler


def utc_now() -> str:
    """現在時刻をUTCのISO 8601形式で返す。"""

    return datetime.now(timezone.utc).isoformat()


def safe_error_record(error: Exception) -> dict[str, Any]:
    """秘密情報を含めず、再試行判断に必要な失敗分類だけを残す。"""

    record: dict[str, Any] = {"error": type(error).__name__}
    if isinstance(error, urllib.error.HTTPError):
        record["http_status"] = int(error.code)
    elif isinstance(error, ExternalServiceError) and error.code:
        record["reason"] = error.code
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


def reported_behavioral_tasks(
    overview: dict[str, Any],
    *,
    sample_id: str,
    max_tasks: int = DEFAULT_MAX_REPORT_TASKS,
) -> list[str]:
    """overviewからreported状態のbehavioral taskを最大件数まで列挙する。"""

    if not SAMPLE_ID_RE.fullmatch(sample_id):
        raise ValueError("Triage sample IDの形式が不正です")
    if not 1 <= max_tasks <= DEFAULT_MAX_REPORT_TASKS:
        raise ValueError("report task上限は1件または2件である必要があります")
    sample = overview.get("sample")
    if not isinstance(sample, dict):
        raise ValueError("Triage overviewにsample情報がありません")
    overview_sample_id = str(sample.get("id") or "")
    if overview_sample_id and overview_sample_id != sample_id:
        raise ValueError("Triage overviewのsample IDが要求値と一致しません")

    tasks = overview.get("tasks")
    if not isinstance(tasks, dict):
        return []
    reported: list[str] = []
    for raw_task_id, task in tasks.items():
        task_id = str(raw_task_id)
        prefix = sample_id + "-"
        if task_id.startswith(prefix):
            task_id = task_id[len(prefix) :]
        if (
            not TASK_ID_RE.fullmatch(task_id)
            or not isinstance(task, dict)
            or task.get("kind") != "behavioral"
            or task.get("status") != "reported"
            or task_id in reported
        ):
            continue
        reported.append(task_id)
        if len(reported) == max_tasks:
            break
    return reported


def _strict_positive_int(value: Any, *, field: str, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= maximum:
        raise ValueError(f"Triage reportの{field}が許可範囲外です")
    return value


def extract_report_memory_candidates(
    report: dict[str, Any],
    *,
    expected_sha256: str,
    sample_id: str,
    task_id: str,
    max_candidates: int = DEFAULT_MAX_REPORT_MEMORY_CANDIDATES,
    max_bytes: int = DEFAULT_MAX_BYTES,
    max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES,
) -> list[dict[str, Any]]:
    """task reportのregion dumpを、長さを検証したmemory取得候補へ変換する。"""

    digest = normalize_sha256(expected_sha256)
    if not SAMPLE_ID_RE.fullmatch(sample_id):
        raise ValueError("Triage sample IDの形式が不正です")
    if not TASK_ID_RE.fullmatch(task_id):
        raise ValueError("Triage task IDの形式が不正です")
    if not 1 <= max_candidates <= 100:
        raise ValueError("report memory候補上限は1件から100件の範囲が必要です")
    if not 1 <= max_bytes <= DEFAULT_MAX_BYTES:
        raise ValueError("report memory単体上限は1 byteから64 MiBの範囲が必要です")
    if not 1 <= max_total_bytes <= 1024 * 1024 * 1024:
        raise ValueError("report memory合計上限は1 byteから1 GiBの範囲が必要です")

    sample = report.get("sample")
    if not isinstance(sample, dict):
        raise ValueError("Triage task reportにsample情報がありません")
    if str(sample.get("id") or "") != sample_id:
        raise ValueError("Triage task reportのsample IDが要求値と一致しません")
    if normalize_sha256(sample.get("sha256")) != digest:
        raise ValueError("Triage task reportのSHA-256が要求値と一致しません")

    task = report.get("task")
    if not isinstance(task, dict):
        raise ValueError("Triage task reportにtask情報がありません")
    if normalize_sha256(task.get("sha256")) != digest:
        raise ValueError("Triage task reportのtask SHA-256が要求値と一致しません")
    report_task_id = str(task.get("id") or "")
    if report_task_id:
        if report_task_id.startswith(sample_id + "-"):
            report_task_id = report_task_id[len(sample_id) + 1 :]
        if report_task_id != task_id:
            raise ValueError("Triage task reportのtask IDが要求値と一致しません")

    dumped = report.get("dumped")
    if dumped is None:
        return []
    if not isinstance(dumped, list):
        raise ValueError("Triage task reportのdumpedは配列である必要があります")

    candidates: list[dict[str, Any]] = []
    total_bytes = 0
    seen: set[str] = set()
    for entry in dumped:
        if not isinstance(entry, dict) or entry.get("kind") != "region":
            continue
        raw_name = entry.get("name")
        if not isinstance(raw_name, str):
            raise ValueError("Triage region dumpにnameがありません")
        normalized_name = raw_name.replace("\\", "/")
        match = REPORT_MEMORY_NAME_RE.fullmatch(normalized_name)
        if match is None:
            raise ValueError("Triage region dumpのmemory pathが不正です")
        safe_name = safe_basename(normalized_name)
        pid = _strict_positive_int(entry.get("pid"), field="pid", maximum=0xFFFFFFFF)
        length = _strict_positive_int(
            entry.get("length"), field="length", maximum=max_bytes
        )
        name_pid = int(match.group("pid"))
        region_index = int(match.group("procid"))
        start = int(match.group("start"), 16)
        end = int(match.group("end"), 16)
        if name_pid != pid:
            raise ValueError("Triage region dumpのpidがmemory名と一致しません")
        if end <= start or end - start != length:
            raise ValueError("Triage region dumpのlengthがmemory範囲と一致しません")
        entry_procid = _strict_positive_int(
            entry.get("procid"), field="procid", maximum=0x7FFFFFFF
        )
        entry_address = entry.get("addr")
        if entry_address is not None and (
            isinstance(entry_address, bool)
            or not isinstance(entry_address, int)
            or entry_address != start
        ):
            raise ValueError("Triage region dumpのaddrがmemory名と一致しません")
        total_bytes += length
        if total_bytes > max_total_bytes:
            raise ValueError("Triage region dumpの合計lengthが上限を超えています")
        endpoint = (
            f"/samples/{sample_id}/{task_id}/memory/"
            f"{urllib.parse.quote(safe_name, safe='')}"
        )
        if endpoint in seen:
            continue
        seen.add(endpoint)
        candidates.append(
            {
                "parent_sha256": digest,
                "sample_id": sample_id,
                "task_id": task_id,
                "kind": "memory_image",
                "name": safe_name,
                "endpoint_path": endpoint,
                "reference_sha256": hashlib.sha256(
                    normalized_name.encode("utf-8")
                ).hexdigest(),
                "selection": "reported_region_memory",
                "reported_pid": pid,
                "reported_procid": entry_procid,
                "reported_region_index": region_index,
                "reported_address": start,
                "reported_length": length,
            }
        )
        if len(candidates) > max_candidates:
            raise ValueError("Triage region dumpの候補件数が上限を超えています")
    return candidates


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


def verify_encrypted_archive_bytes(
    archive_data: bytes,
    *,
    member_name: str,
    password: str,
    expected_size: int,
    expected_sha256: str,
) -> str:
    """AES-256 ZIPの単一member、長さ、平文hashをmemory上で検証する。"""

    safe_name = safe_basename(member_name)
    digest = normalize_sha256(expected_sha256)
    if (
        isinstance(expected_size, bool)
        or not isinstance(expected_size, int)
        or not 0 <= expected_size <= DEFAULT_MAX_BYTES
    ):
        raise ValueError("暗号化archiveの期待平文sizeが不正です")
    if not archive_data:
        raise ValueError("暗号化archiveが空です")
    try:
        with pyzipper.AESZipFile(BytesIO(archive_data), "r") as archive:
            infos = archive.infolist()
            if len(infos) != 1 or infos[0].filename != safe_name:
                raise ValueError("暗号化archiveのmemberが期待値と一致しません")
            info = infos[0]
            if info.is_dir() or info.file_size != expected_size:
                raise ValueError("暗号化archiveの平文sizeが期待値と一致しません")
            if not info.flag_bits & 0x1 or getattr(info, "wz_aes_strength", None) != 3:
                raise ValueError("暗号化archiveがWinZip AES-256ではありません")
            archive.setpassword(password.encode("utf-8"))
            with archive.open(info, "r") as member:
                plaintext = member.read(expected_size + 1)
                if member.read(1):
                    raise ValueError("暗号化archiveの平文が期待上限を超えています")
    except (
        pyzipper.zipfile.BadZipFile,
        EOFError,
        OSError,
        RuntimeError,
        NotImplementedError,
    ) as error:
        raise ValueError("暗号化archiveを安全に検証できません") from error
    if len(plaintext) != expected_size:
        raise ValueError("暗号化archiveの平文sizeが期待値と一致しません")
    if hashlib.sha256(plaintext).hexdigest() != digest:
        raise ValueError("暗号化archiveの平文SHA-256が期待値と一致しません")
    return hashlib.sha256(archive_data).hexdigest()


def persist_encrypted_archive(
    archive_path: Path,
    archive_data: bytes,
    *,
    member_name: str,
    password: str,
    expected_size: int,
    expected_sha256: str,
) -> dict[str, Any]:
    """既存archiveを厳密検証し、新規archiveは同一directoryからatomic replaceする。"""

    generated_sha256 = verify_encrypted_archive_bytes(
        archive_data,
        member_name=member_name,
        password=password,
        expected_size=expected_size,
        expected_sha256=expected_sha256,
    )
    archive_path.parent.mkdir(parents=True, exist_ok=True)
    if archive_path.exists() or archive_path.is_symlink():
        if archive_path.is_symlink() or not archive_path.is_file():
            raise ValueError("既存の暗号化archiveが通常fileではありません")
        maximum_existing_size = len(archive_data) + 1024 * 1024
        size = archive_path.stat().st_size
        if not 1 <= size <= maximum_existing_size:
            raise ValueError("既存の暗号化archive sizeが許可範囲外です")
        existing_data = archive_path.read_bytes()
        existing_sha256 = verify_encrypted_archive_bytes(
            existing_data,
            member_name=member_name,
            password=password,
            expected_size=expected_size,
            expected_sha256=expected_sha256,
        )
        return {
            "archive_sha256": existing_sha256,
            "archive_reused": True,
        }

    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{archive_path.name}.",
        suffix=".tmp",
        dir=archive_path.parent,
    )
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(archive_data)
            stream.flush()
            os.fsync(stream.fileno())
        temporary_data = temporary_path.read_bytes()
        if hashlib.sha256(temporary_data).hexdigest() != generated_sha256:
            raise ValueError("一時暗号化archiveの内容が生成値と一致しません")
        verify_encrypted_archive_bytes(
            temporary_data,
            member_name=member_name,
            password=password,
            expected_size=expected_size,
            expected_sha256=expected_sha256,
        )
        os.replace(temporary_path, archive_path)
    finally:
        temporary_path.unlink(missing_ok=True)

    persisted_data = archive_path.read_bytes()
    persisted_sha256 = verify_encrypted_archive_bytes(
        persisted_data,
        member_name=member_name,
        password=password,
        expected_size=expected_size,
        expected_sha256=expected_sha256,
    )
    if persisted_sha256 != generated_sha256:
        raise ValueError("保存済み暗号化archiveが生成値と一致しません")
    return {
        "archive_sha256": persisted_sha256,
        "archive_reused": False,
    }


def _manifest_hashes(path: Path) -> list[str]:
    document = json.loads(path.read_text(encoding="utf-8-sig"))
    values = document.get("selected_hashes") or []
    return [normalize_sha256(value) for value in values]


def load_reviewed_candidates(path: Path) -> list[dict[str, Any]]:
    """人手で確認した公開解析のmemory名を、安全なAPI候補へ変換する。"""

    document = json.loads(path.read_text(encoding="utf-8-sig"))
    rows = document.get("candidates") if isinstance(document, dict) else document
    if not isinstance(rows, list):
        raise TypeError("reviewed candidatesは配列である必要があります")
    candidates: list[dict[str, Any]] = []
    seen: set[str] = set()
    for row in rows:
        if not isinstance(row, dict):
            raise TypeError("reviewed candidateの各要素はobjectが必要です")
        digest = normalize_sha256(row.get("parent_sha256"))
        sample_id = str(row.get("sample_id") or "")
        task_id = str(row.get("task_id") or "")
        resource = str(row.get("name") or "").replace("\\", "/")
        if not SAMPLE_ID_RE.fullmatch(sample_id):
            raise ValueError("reviewed candidateのsample ID形式が不正です")
        if not TASK_ID_RE.fullmatch(task_id):
            raise ValueError("reviewed candidateのtask ID形式が不正です")
        if not resource.startswith("memory/") or resource.count("/") != 1:
            raise ValueError("reviewed candidateはmemory直下の成果物に限定されます")
        safe_name = safe_basename(resource)
        if not safe_name.lower().endswith("memory.dmp"):
            raise ValueError("reviewed candidateはmemory.dmpに限定されます")
        endpoint = (
            f"/samples/{sample_id}/{task_id}/memory/"
            f"{urllib.parse.quote(safe_name, safe='')}"
        )
        if endpoint in seen:
            continue
        seen.add(endpoint)
        candidates.append(
            {
                "parent_sha256": digest,
                "sample_id": sample_id,
                "task_id": task_id,
                "kind": "memory_image",
                "name": safe_name,
                "endpoint_path": endpoint,
                "reference_sha256": hashlib.sha256(resource.encode()).hexdigest(),
                "selection": "reviewed_report_memory",
            }
        )
    return candidates


def verify_reviewed_candidates(
    candidates: list[dict[str, Any]],
    api_key: str,
    *,
    opener: Any,
    timeout: float,
) -> None:
    """review済み候補も、完全hash一致かつ公開解析であることを再検証する。"""

    scopes = {
        (item["parent_sha256"], item["sample_id"])
        for item in candidates
    }
    for digest, sample_id in sorted(scopes):
        metadata = api_json(
            f"/samples/{sample_id}", api_key, opener=opener, timeout=timeout
        )
        if normalize_sha256(metadata.get("sha256")) != digest:
            raise ValueError("reviewed candidateのTriage SHA-256が一致しません")
        if metadata.get("private") is True or metadata.get("owner"):
            raise ValueError("公開解析ではないためreviewed candidateを拒否しました")
        if metadata.get("private") is not False and not verify_public_page(
            sample_id, opener=opener, timeout=timeout
        ):
            raise ValueError("公開解析ではないためreviewed candidateを拒否しました")


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
    root_sample_candidates: list[dict[str, Any]] | None = None,
    report_memory_max_candidates: int = DEFAULT_MAX_REPORT_MEMORY_CANDIDATES,
    report_memory_max_bytes: int = DEFAULT_MAX_BYTES,
    report_memory_max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
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
                if root_sample_candidates is not None:
                    root_sample_candidates.append(
                        {
                            "parent_sha256": digest,
                            "expected_sha256": digest,
                            "sample_id": sample_id,
                            "kind": "root_sample",
                            "selection": "exact_sha256_public_triage_analysis",
                            "endpoint_path": f"/samples/{sample_id}/sample",
                            "metadata_sha256_verified": True,
                        }
                    )
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
                if include_memory:
                    report_candidates: list[dict[str, Any]] = []
                    for task_id in reported_behavioral_tasks(
                        overview,
                        sample_id=sample_id,
                    ):
                        report = api_json(
                            f"/samples/{sample_id}/{task_id}/report_triage.json",
                            api_key,
                            opener=opener,
                            timeout=timeout,
                        )
                        report_candidates.extend(
                            extract_report_memory_candidates(
                                report,
                                expected_sha256=digest,
                                sample_id=sample_id,
                                task_id=task_id,
                                max_candidates=report_memory_max_candidates,
                                max_bytes=report_memory_max_bytes,
                                max_total_bytes=report_memory_max_total_bytes,
                            )
                        )
                    if len(report_candidates) > report_memory_max_candidates:
                        raise ValueError(
                            "Triage region dumpの候補件数がsample上限を超えています"
                        )
                    if (
                        sum(item["reported_length"] for item in report_candidates)
                        > report_memory_max_total_bytes
                    ):
                        raise ValueError(
                            "Triage region dumpの合計lengthがsample上限を超えています"
                        )
                    candidates.extend(report_candidates)
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


def _deduplicate_root_sample_candidates(
    candidates: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """同一hashのroot sampleを、最初に検証できた公開解析1件へ限定する。"""

    unique: dict[str, dict[str, Any]] = {}
    for candidate in candidates:
        digest = normalize_sha256(candidate.get("expected_sha256"))
        if normalize_sha256(candidate.get("parent_sha256")) != digest:
            raise ValueError("root sample候補の親SHA-256が要求値と一致しません")
        sample_id = str(candidate.get("sample_id") or "")
        if not SAMPLE_ID_RE.fullmatch(sample_id):
            raise ValueError("root sample候補のsample ID形式が不正です")
        unique.setdefault(digest, candidate)
    return list(unique.values())


def _retrieve_root_samples(
    candidates: list[dict[str, Any]],
    *,
    output_root: Path,
    password: str,
    client: TriageClient,
    max_samples: int,
    max_sample_bytes: int,
    max_total_bytes: int,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    """root sampleを応答・合計上限内で取得し、失敗を構造化して返す。"""

    if not 1 <= max_samples <= 100:
        raise ValueError("max_samplesは1から100の範囲が必要です")
    if (
        isinstance(max_sample_bytes, bool)
        or not isinstance(max_sample_bytes, int)
        or not 1 <= max_sample_bytes <= DEFAULT_MAX_SAMPLE_BYTES
    ):
        raise ValueError("root sample応答上限は1 byteから512 MiBの範囲が必要です")
    if (
        isinstance(max_total_bytes, bool)
        or not isinstance(max_total_bytes, int)
        or not 1 <= max_total_bytes <= MAX_ROOT_TOTAL_BYTES
    ):
        raise ValueError("root sample合計上限は1 byteから1 GiBの範囲が必要です")

    downloads: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    exhausted_reasons: list[str] = []
    archive_total_bytes = 0
    attempted_count = 0
    for candidate in candidates[:max_samples]:
        expected_sha256 = candidate.get("expected_sha256")
        sample_id = str(candidate.get("sample_id") or "")
        remaining = max_total_bytes - archive_total_bytes
        if remaining <= 0:
            reason = "root_sample_aggregate_byte_budget_exhausted"
            exhausted_reasons.append(reason)
            errors.append(
                {
                    "parent_sha256": str(candidate.get("parent_sha256") or ""),
                    "expected_sha256": str(expected_sha256 or ""),
                    "sample_id": sample_id,
                    "stage": "root_sample_download",
                    "error": "RootSampleBudgetExceeded",
                    "reason": reason,
                }
            )
            break
        effective_max_bytes = min(max_sample_bytes, remaining)
        attempted_count += 1
        try:
            digest = normalize_sha256(expected_sha256)
            if normalize_sha256(candidate.get("parent_sha256")) != digest:
                raise ValueError("root sample候補の親SHA-256が要求値と一致しません")
            if not SAMPLE_ID_RE.fullmatch(sample_id):
                raise ValueError("root sample候補のsample ID形式が不正です")
            destination = output_root / digest / sample_id / "root-sample.zip"
            result = client.fetch_sample(
                sample_id,
                output_path=destination,
                expected_sha256=digest,
                password=password,
                member_name=f"{digest}.bin",
                max_bytes=effective_max_bytes,
            )
            if result.get("archive_encrypted") is not True:
                raise ValueError("root sample archiveが暗号化済みではありません")
            if result.get("plaintext_written") is not False:
                raise ValueError("root sample取得で平文がdiskへ書き込まれました")
            archive_size = result.get("archive_size")
            if (
                isinstance(archive_size, bool)
                or not isinstance(archive_size, int)
                or not 1 <= archive_size <= effective_max_bytes
            ):
                raise ValueError("root sample archive sizeが取得上限と整合しません")
            archive_total_bytes += archive_size
            downloads.append(
                {
                    **candidate,
                    **result,
                    "expected_sha256": digest,
                    "effective_max_bytes": effective_max_bytes,
                    "payload_sha256_verified": not bool(
                        result.get("server_response_encrypted_zip")
                    ),
                    "metadata_sha256_verified": True,
                }
            )
        except Exception as error:  # helper/network/filesystemは異種例外を返す
            error_record = safe_error_record(error)
            errors.append(
                {
                    "parent_sha256": str(candidate.get("parent_sha256") or ""),
                    "expected_sha256": str(expected_sha256 or ""),
                    "sample_id": sample_id,
                    "stage": "root_sample_download",
                    **error_record,
                }
            )
            if (
                error_record.get("reason")
                in {
                    "archive_size_limit_exceeded",
                    "response_size_limit_exceeded",
                }
                and effective_max_bytes < max_sample_bytes
            ):
                exhausted_reasons.append(
                    "root_sample_aggregate_byte_budget_exhausted"
                )
                break

    exhausted_reasons = list(dict.fromkeys(exhausted_reasons))
    budget = {
        "status": "partial" if errors else "complete",
        "configured_per_response_bytes": max_sample_bytes,
        "configured_aggregate_bytes": max_total_bytes,
        "attempted_count": attempted_count,
        "archive_total_bytes": archive_total_bytes,
        "remaining_bytes": max_total_bytes - archive_total_bytes,
        "budget_exhausted": bool(exhausted_reasons),
        "exhausted_reasons": exhausted_reasons,
    }
    return downloads, errors, budget


def build_parser() -> argparse.ArgumentParser:
    """限定取得CLIの引数parserを構築する。"""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hash", action="append", default=[])
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--reviewed-candidates", type=Path)
    parser.add_argument("--output-root", required=True, type=Path)
    parser.add_argument("--allow-network", action="store_true")
    parser.add_argument("--download", action="store_true")
    parser.add_argument("--include-memory", action="store_true")
    parser.add_argument(
        "--include-root-sample",
        action="store_true",
        help="--download時に、完全SHA-256一致を確認した公開解析のroot sampleも取得する",
    )
    parser.add_argument("--max-artifacts", type=int, default=20)
    parser.add_argument("--max-root-samples", type=int, default=1)
    parser.add_argument(
        "--max-root-sample-bytes",
        type=int,
        default=DEFAULT_MAX_SAMPLE_BYTES,
    )
    parser.add_argument(
        "--max-root-total-bytes",
        type=int,
        default=DEFAULT_MAX_ROOT_TOTAL_BYTES,
    )
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
    if not 1 <= args.max_bytes <= DEFAULT_MAX_BYTES:
        raise ValueError("max_bytesは1 byteから64 MiBの範囲が必要です")
    if not 1 <= args.max_total_bytes <= 1024 * 1024 * 1024:
        raise ValueError("max_total_bytesは1から1GiBの範囲が必要です")
    if not 1 <= args.max_root_samples <= 100:
        raise ValueError("max_root_samplesは1から100の範囲が必要です")
    if not 1 <= args.max_root_sample_bytes <= DEFAULT_MAX_SAMPLE_BYTES:
        raise ValueError("max_root_sample_bytesは1 byteから512 MiBの範囲が必要です")
    if not 1 <= args.max_root_total_bytes <= MAX_ROOT_TOTAL_BYTES:
        raise ValueError("max_root_total_bytesは1 byteから1 GiBの範囲が必要です")
    api_key = os.environ.get("TRIAGE_API_KEY", "")
    if not api_key:
        raise SystemExit("TRIAGE_API_KEYが必要です")
    hashes = list(args.hash)
    if args.manifest:
        hashes.extend(_manifest_hashes(args.manifest.resolve()))
    reviewed_candidates: list[dict[str, Any]] = []
    if args.reviewed_candidates:
        reviewed_candidates = load_reviewed_candidates(args.reviewed_candidates.resolve())
        hashes.extend(item["parent_sha256"] for item in reviewed_candidates)
    if not hashes:
        raise ValueError("--hashまたは--manifestでSHA-256を指定してください")

    output_root = _outside_repository(args.output_root)
    output_root.mkdir(parents=True, exist_ok=True)
    opener = urllib.request.build_opener(NoRedirect())
    root_sample_candidates: list[dict[str, Any]] = []
    candidates, errors = discover_candidates(
        hashes,
        api_key,
        opener=opener,
        timeout=args.timeout,
        include_memory=args.include_memory,
        root_sample_candidates=(
            root_sample_candidates if args.include_root_sample else None
        ),
        report_memory_max_bytes=args.max_bytes,
        report_memory_max_total_bytes=args.max_total_bytes,
    )
    if reviewed_candidates:
        verify_reviewed_candidates(
            reviewed_candidates,
            api_key,
            opener=opener,
            timeout=args.timeout,
        )
        merged = {
            item["endpoint_path"]: item
            for item in [*candidates, *reviewed_candidates]
        }
        candidates = list(merged.values())
        if args.include_root_sample:
            root_sample_candidates.extend(
                {
                    "parent_sha256": item["parent_sha256"],
                    "expected_sha256": item["parent_sha256"],
                    "sample_id": item["sample_id"],
                    "kind": "root_sample",
                    "selection": "reviewed_exact_sha256_public_triage_analysis",
                    "endpoint_path": f"/samples/{item['sample_id']}/sample",
                    "metadata_sha256_verified": True,
                }
                for item in reviewed_candidates
            )
    root_sample_candidates = _deduplicate_root_sample_candidates(
        root_sample_candidates
    )
    downloads: list[dict[str, Any]] = []
    root_sample_downloads: list[dict[str, Any]] = []
    root_sample_errors: list[dict[str, Any]] = []
    root_sample_budget: dict[str, Any] = {
        "status": "not_requested" if not args.include_root_sample else "not_started",
        "configured_per_response_bytes": args.max_root_sample_bytes,
        "configured_aggregate_bytes": args.max_root_total_bytes,
        "attempted_count": 0,
        "archive_total_bytes": 0,
        "remaining_bytes": args.max_root_total_bytes,
        "budget_exhausted": False,
        "exhausted_reasons": [],
    }
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
                    max_bytes=min(
                        args.max_bytes,
                        remaining,
                        int(candidate.get("reported_length") or args.max_bytes),
                    ),
                )
                reported_length = candidate.get("reported_length")
                if reported_length is not None and len(data) != reported_length:
                    raise ValueError(
                        "Triage region dumpの応答長がreportのlengthと一致しません"
                    )
                digest = hashlib.sha256(data).hexdigest()
                archive_bytes = encrypted_zip_bytes(data, candidate["name"], args.password)
                case_root = output_root / candidate["parent_sha256"] / candidate["sample_id"]
                case_root.mkdir(parents=True, exist_ok=True)
                archive_path = case_root / f"artifact-{digest[:16]}.zip"
                archive_result = persist_encrypted_archive(
                    archive_path,
                    archive_bytes,
                    member_name=candidate["name"],
                    password=args.password,
                    expected_size=len(data),
                    expected_sha256=digest,
                )
                total_bytes += len(data)
                downloads.append(
                    {
                        **candidate,
                        **response,
                        "artifact_sha256": digest,
                        "size": len(data),
                        "archive_path": str(archive_path),
                        "archive_sha256": archive_result["archive_sha256"],
                        "archive_reused": archive_result["archive_reused"],
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

        if args.include_root_sample:
            (
                root_sample_downloads,
                root_sample_errors,
                root_sample_budget,
            ) = _retrieve_root_samples(
                root_sample_candidates,
                output_root=output_root,
                password=args.password,
                client=TriageClient(
                    http=HttpClient(
                        timeout=args.timeout,
                        attempts=1,
                        opener=opener,
                    )
                ),
                max_samples=args.max_root_samples,
                max_sample_bytes=args.max_root_sample_bytes,
                max_total_bytes=args.max_root_total_bytes,
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
        "root_sample_opt_in": bool(args.include_root_sample),
        "root_sample_candidates": root_sample_candidates,
        "root_sample_limit": args.max_root_samples,
        "root_sample_download_attempted": bool(
            args.download and args.include_root_sample
        ),
        "root_sample_downloaded_count": len(root_sample_downloads),
        "root_sample_download_status": root_sample_budget["status"],
        "root_sample_budget": root_sample_budget,
        "root_sample_archive_total_bytes": root_sample_budget["archive_total_bytes"],
        "root_sample_downloads": root_sample_downloads,
        "root_sample_errors": root_sample_errors,
        "errors": errors,
        "safety": {
            "sample_submitted": False,
            "sample_executed_locally": False,
            "artifact_executed": False,
            "network_contacted": True,
            "network_scope": (
                "Triage API exact-hash search, bounded artifact GET, and opted-in "
                "exact-hash root sample GET"
                if args.download and args.include_root_sample
                else "Triage API exact-hash search and bounded artifact GET only"
            ),
            "redirects_followed": False,
            "ambiguous_visibility_requires_unauthenticated_public_page": True,
            "plaintext_artifact_written": False,
            "artifacts_encrypted_at_rest": bool(downloads or root_sample_downloads),
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
                "root_sample_downloaded_count": len(root_sample_downloads),
                "root_sample_errors": len(root_sample_errors),
                "output": str(output_root / "manifest.json"),
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
