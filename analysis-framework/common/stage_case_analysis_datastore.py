#!/usr/bin/env python3
"""日次解析の非公開成果物を検体単位のdatastore入力へ安全に分離する。"""

from __future__ import annotations

import argparse
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from functools import cache
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import sys
import uuid
from typing import Any

import archive_analysis_datastore


SCHEMA_VERSION = "analysis-datastore-case-staging/v1"
RELATIONSHIP_SCHEMA_VERSION = "analysis-datastore-case-input-relationships/v1"
VALIDATION_SCHEMA_VERSION = "analysis-datastore-case-private-validation/v1"
ACQUISITION_SCHEMA_VERSION = "analysis-datastore-case-acquisition/v1"
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
COLLECTION_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,127}\Z")
MAX_CASES = 1000
MAX_RELATIONSHIPS = 250_000
MAX_FILES = 500_000
MAX_JSON_BYTES = 256 * 1024 * 1024
MINIMUM_FREE_RESERVE_BYTES = 512 * 1024 * 1024
COPY_CHUNK_BYTES = 1024 * 1024
SCAN_OVERLAP_BYTES = 1024
FILE_ATTRIBUTE_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
STAGING_MANIFEST_NAME = "_case_staging_manifest.json"

FORBIDDEN_SENSITIVE_NAMES = frozenset(
    {
        ".aws",
        ".env",
        ".ssh",
        "aws-credentials",
        "aws_credentials",
        "credentials",
        "credentials.json",
        "creds.txt",
        "datastore-upload.json",
        "github-token.txt",
        "github_token.txt",
        "id_ed25519",
        "id_rsa",
        "secrets.json",
        "token.txt",
    }
)
FORBIDDEN_SENSITIVE_SUFFIXES = (".key", ".p12", ".pfx")
STATIC_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[bytes]], ...] = (
    (
        "github_fine_grained_pat",
        re.compile(rb"github_pat_[A-Za-z0-9_]{20,255}"),
    ),
    (
        "github_classic_token",
        re.compile(rb"gh[pousr]_[A-Za-z0-9]{20,255}"),
    ),
    (
        "aws_access_key_id",
        re.compile(rb"(?:AKIA|ASIA)[A-Z0-9]{16}"),
    ),
    (
        "aws_access_key_assignment",
        re.compile(rb"(?i)aws_access_key_id\s*[:=]\s*[A-Z0-9]{16,}"),
    ),
    (
        "aws_secret_key_assignment",
        re.compile(rb"(?i)aws_secret_access_key\s*[:=]\s*[A-Za-z0-9/+=]{32,}"),
    ),
    (
        "private_key_material",
        re.compile(rb"-----BEGIN (?:OPENSSH |RSA |EC |DSA )?PRIVATE KEY-----"),
    ),
)
CASE_SHA256_FIELD_RE = re.compile(rb'"case_sha256"\s*:\s*"([0-9a-fA-F]{64})"')
REPORT_CASE_IDENTITY_KEYS = frozenset(
    {
        "case_sha256",
        "root_sample_sha256",
        "sample_sha256",
        "submitted_sample_sha256",
    }
)


class CaseStagingError(RuntimeError):
    """caseを安全に分離できず、保管を中止すべき場合の例外。"""


@dataclass(frozen=True)
class CopiedFile:
    """物理copy後に照合したstaging file。"""

    path: Path
    relative: str
    size: int
    sha256: str
    role: str


@dataclass(frozen=True)
class SourceCommitment:
    """preflightで固定し、copy時に再照合する入力fileの契約。"""

    path: Path
    size: int
    sha256: str
    identity: os.stat_result


@dataclass(frozen=True)
class CaseInputs:
    """1 caseへ帰属が固定された入力集合。"""

    case_sha256: str
    source_directory: Path
    one_shot_directory: Path
    relationships: tuple[dict[str, Any], ...]
    pe_sha256s: tuple[str, ...]


@dataclass(frozen=True)
class ValidatedInputs:
    """全case共通manifestを検証後に保持するread-only入力。"""

    repository: Path
    collection_id: str
    source_root: Path
    one_shot_root: Path
    ghidra_root: Path
    output_root: Path
    source_manifest: dict[str, Any]
    source_manifest_sha256: str
    relationships_manifest: dict[str, Any]
    relationships_manifest_sha256: str
    validation_manifest: dict[str, Any]
    validation_manifest_sha256: str
    validation_programs: Mapping[str, dict[str, Any]]
    program_results: Mapping[str, dict[str, Any]]
    cases: Mapping[str, CaseInputs]


def _absolute(path: Path) -> Path:
    return Path(os.path.abspath(os.fspath(path)))


def _is_within(path: Path, root: Path) -> bool:
    return path == root or root in path.parents


def _is_reparse(metadata: os.stat_result) -> bool:
    return bool(getattr(metadata, "st_file_attributes", 0) & FILE_ATTRIBUTE_REPARSE_POINT)


def _reject_reparse_components(path: Path, *, label: str) -> None:
    absolute = _absolute(path)
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current /= part
        if not os.path.lexists(current):
            break
        try:
            metadata = current.lstat()
        except OSError as exc:
            raise CaseStagingError(f"{label}のmetadataを確認できません") from exc
        if current.is_symlink() or _is_reparse(metadata):
            raise CaseStagingError(f"{label}にreparse pointは使用できません")


def _validate_existing_directory(path: Path, *, label: str) -> Path:
    absolute = _absolute(path)
    _reject_reparse_components(absolute, label=label)
    try:
        resolved = absolute.resolve(strict=True)
        metadata = resolved.lstat()
    except OSError as exc:
        raise CaseStagingError(f"{label}を安全に確認できません") from exc
    if not stat.S_ISDIR(metadata.st_mode) or resolved.is_symlink() or _is_reparse(metadata):
        raise CaseStagingError(f"{label}は通常directoryである必要があります")
    return resolved


def _prepare_output_root(path: Path, *, repository: Path, inputs: Sequence[Path]) -> Path:
    absolute = _absolute(path)
    _reject_reparse_components(absolute, label="case staging output root")
    ancestor = absolute
    while not os.path.lexists(ancestor):
        if ancestor.parent == ancestor:
            raise CaseStagingError("case staging output rootの既存parentがありません")
        ancestor = ancestor.parent
    ancestor = _validate_existing_directory(ancestor, label="case staging output parent")
    prospective = ancestor.joinpath(*absolute.relative_to(ancestor).parts)
    if _is_within(prospective, repository):
        raise CaseStagingError("case staging outputをrepository内へ作成できません")
    if any(_is_within(prospective, item) or _is_within(item, prospective) for item in inputs):
        raise CaseStagingError("case staging outputを入力rootと重複させられません")
    try:
        prospective.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise CaseStagingError("case staging output rootを作成できません") from exc
    output = _validate_existing_directory(prospective, label="case staging output root")
    if output != prospective:
        raise CaseStagingError("case staging output rootのidentityが作成中に変化しました")
    return output


def _validate_sha256(value: Any, *, label: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise CaseStagingError(f"{label}は小文字64桁のSHA-256である必要があります")
    return value


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CaseStagingError("JSONに重複keyがあります")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise CaseStagingError(f"JSONに許可しない数値定数があります: {value}")


def _read_json(path: Path, *, label: str) -> tuple[dict[str, Any], str]:
    try:
        with archive_analysis_datastore._open_verified_source(path) as (stream, identity):
            if identity.st_size <= 0 or identity.st_size > MAX_JSON_BYTES:
                raise CaseStagingError(f"{label}のsizeが上限外です")
            raw = stream.read(MAX_JSON_BYTES + 1)
    except archive_analysis_datastore.DatastoreError as exc:
        raise CaseStagingError(f"{label}を安全な単一handleで読めません") from exc
    if len(raw) != identity.st_size:
        raise CaseStagingError(f"{label}の読取sizeが一致しません")
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_strict_object,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CaseStagingError(f"{label}はstrict UTF-8 JSONではありません") from exc
    if not isinstance(value, dict):
        raise CaseStagingError(f"{label}のrootはobjectである必要があります")
    return value, hashlib.sha256(raw).hexdigest()


def _reject_sensitive_name(relative: PurePosixPath) -> None:
    for part in relative.parts:
        lowered = part.casefold()
        if (
            lowered in FORBIDDEN_SENSITIVE_NAMES
            or lowered.startswith("github_pat_")
            or lowered.endswith(FORBIDDEN_SENSITIVE_SUFFIXES)
        ):
            raise CaseStagingError(f"資格情報の可能性があるfile名を保管対象にできません: {relative.as_posix()}")


@cache
def _host_path_patterns() -> tuple[tuple[str, re.Pattern[bytes]], ...]:
    home = os.fspath(Path.home())
    candidates = {
        home.encode("utf-8", errors="strict"),
        home.replace("\\", "\\\\").encode("utf-8", errors="strict"),
        home.encode("utf-16le", errors="strict"),
    }
    return tuple(
        ("current_host_home_path", re.compile(re.escape(value), re.IGNORECASE)) for value in candidates if value
    )


def _scan_sensitive_content(data: bytes, *, relative: str) -> None:
    for rule, pattern in (*STATIC_SECRET_PATTERNS, *_host_path_patterns()):
        if pattern.search(data):
            raise CaseStagingError(f"staging対象に秘密値または不要なhost pathを検出しました: {relative} ({rule})")


def _walk_files(root: Path, *, role: str) -> list[tuple[Path, PurePosixPath]]:
    root = _validate_existing_directory(root, label=f"{role} root")
    io_root = archive_analysis_datastore._extended_length_path(root)
    pending: list[tuple[Path, PurePosixPath]] = [(io_root, PurePosixPath())]
    files: list[tuple[Path, PurePosixPath]] = []
    observed = 0
    while pending:
        directory, relative_directory = pending.pop()
        try:
            with os.scandir(directory) as iterator:
                entries = sorted(iterator, key=lambda item: item.name.casefold(), reverse=True)
        except OSError as exc:
            raise CaseStagingError(f"{role}を列挙できません") from exc
        for entry in entries:
            observed += 1
            if observed > MAX_FILES:
                raise CaseStagingError(f"{role}のentry件数が上限を超えました")
            path = Path(entry.path)
            relative = relative_directory / entry.name
            _reject_sensitive_name(relative)
            try:
                metadata = path.lstat()
            except OSError as exc:
                raise CaseStagingError(f"{role} entryのmetadataを確認できません") from exc
            if entry.is_symlink() or _is_reparse(metadata):
                raise CaseStagingError(f"{role}にreparse pointは使用できません")
            if stat.S_ISDIR(metadata.st_mode):
                pending.append((path, relative))
            elif stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1:
                files.append((path, relative))
            elif stat.S_ISREG(metadata.st_mode):
                raise CaseStagingError(f"{role}にhardlinkは使用できません")
            else:
                raise CaseStagingError(f"{role}は通常fileとdirectoryだけを許可します")
    return sorted(files, key=lambda item: item[1].as_posix().casefold())


def _copy_file(
    source: Path,
    destination: Path,
    *,
    staging_root: Path,
    role: str,
    commitments: Mapping[str, SourceCommitment],
) -> CopiedFile:
    relative = destination.relative_to(staging_root).as_posix()
    _reject_sensitive_name(PurePosixPath(relative))
    destination_io = archive_analysis_datastore._extended_length_path(destination)
    destination_io.parent.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256()
    size = 0
    carry = b""
    commitment = _required_source_commitment(source, commitments=commitments)
    try:
        with archive_analysis_datastore._open_verified_source(
            source,
            expected=commitment.identity,
        ) as (stream, identity):
            with destination_io.open("xb") as output:
                while chunk := stream.read(COPY_CHUNK_BYTES):
                    _scan_sensitive_content(carry + chunk, relative=relative)
                    carry = (carry + chunk)[-SCAN_OVERLAP_BYTES:]
                    output.write(chunk)
                    digest.update(chunk)
                    size += len(chunk)
                output.flush()
                os.fsync(output.fileno())
    except archive_analysis_datastore.DatastoreError as exc:
        raise CaseStagingError(f"{role}を安全な単一handleでcopyできません") from exc
    except OSError as exc:
        raise CaseStagingError(f"{role}を物理copyできません") from exc
    if (
        size != identity.st_size
        or size != commitment.size
        or digest.hexdigest() != commitment.sha256
    ):
        raise CaseStagingError(f"{role}がpreflight commitmentから変更されました")
    try:
        metadata = destination_io.lstat()
    except OSError as exc:
        raise CaseStagingError(f"{role}のcopy後metadataを確認できません") from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or destination_io.is_symlink()
        or _is_reparse(metadata)
    ):
        raise CaseStagingError(f"{role}の出力が独立した通常fileではありません")
    try:
        copied_sha256, copied_size, _identity = archive_analysis_datastore._hash_source_snapshot(destination)
    except archive_analysis_datastore.DatastoreError as exc:
        raise CaseStagingError(f"{role}のcopy後照合に失敗しました") from exc
    if copied_size != size or copied_sha256 != digest.hexdigest():
        raise CaseStagingError(f"{role}のcopy後SHA-256が一致しません")
    return CopiedFile(destination, relative, size, copied_sha256, role)


def _scan_file_for_sensitive_content(source: Path, *, relative: str) -> None:
    carry = b""
    try:
        with archive_analysis_datastore._open_verified_source(source) as (
            stream,
            _identity,
        ):
            while chunk := stream.read(COPY_CHUNK_BYTES):
                _scan_sensitive_content(carry + chunk, relative=relative)
                carry = (carry + chunk)[-SCAN_OVERLAP_BYTES:]
    except archive_analysis_datastore.DatastoreError as exc:
        raise CaseStagingError("秘密値preflightで入力fileを安全に読めません") from exc


def _source_commitment_key(path: Path) -> str:
    """Windowsの大小文字差も含め、同じ入力pathを一意に扱う。"""

    return os.path.normcase(os.fspath(_absolute(path)))


def _snapshot_source_commitment(source: Path, *, relative: str) -> SourceCommitment:
    """秘密値scanとSHA-256／identity固定を同じhandleで完了する。"""

    digest = hashlib.sha256()
    size = 0
    carry = b""
    try:
        with archive_analysis_datastore._open_verified_source(source) as (
            stream,
            identity,
        ):
            while chunk := stream.read(COPY_CHUNK_BYTES):
                _scan_sensitive_content(carry + chunk, relative=relative)
                carry = (carry + chunk)[-SCAN_OVERLAP_BYTES:]
                digest.update(chunk)
                size += len(chunk)
    except archive_analysis_datastore.DatastoreError as exc:
        raise CaseStagingError("秘密値preflightで入力fileを安全に固定できません") from exc
    if size != identity.st_size:
        raise CaseStagingError("秘密値preflightの入力sizeが一致しません")
    return SourceCommitment(
        path=_absolute(source),
        size=size,
        sha256=digest.hexdigest(),
        identity=identity,
    )


def _required_source_commitment(
    source: Path,
    *,
    commitments: Mapping[str, SourceCommitment],
) -> SourceCommitment:
    """列挙後に追加・差替えされた入力をcopy前に拒否する。"""

    commitment = commitments.get(_source_commitment_key(source))
    if commitment is None:
        raise CaseStagingError("copy対象がpreflight commitmentへ含まれていません")
    return commitment


def _assert_source_commitment(
    source: Path,
    *,
    commitments: Mapping[str, SourceCommitment],
    role: str,
) -> None:
    """生成JSONの元となる入力もcopy時点のcommitmentへ拘束する。"""

    commitment = _required_source_commitment(source, commitments=commitments)
    try:
        digest, size, identity = archive_analysis_datastore._hash_source_snapshot(source)
        archive_analysis_datastore._validate_source_identity(
            archive_analysis_datastore._extended_length_path(source),
            commitment.identity,
            identity,
        )
    except archive_analysis_datastore.DatastoreError as exc:
        raise CaseStagingError(f"{role}がpreflight後に変更されました") from exc
    if size != commitment.size or digest != commitment.sha256:
        raise CaseStagingError(f"{role}がpreflight commitmentから変更されました")


def _scan_staged_case_references(root: Path, *, case_sha256: str) -> None:
    """派生後成果物の明示的なcase参照が対象caseだけであることを確認する。"""

    for path, relative in _walk_files(root, role="case reference scan"):
        carry = b""
        try:
            with archive_analysis_datastore._open_verified_source(path) as (
                stream,
                _identity,
            ):
                while chunk := stream.read(COPY_CHUNK_BYTES):
                    data = carry + chunk
                    for match in CASE_SHA256_FIELD_RE.finditer(data):
                        observed = match.group(1).decode("ascii").lower()
                        if observed != case_sha256:
                            raise CaseStagingError(
                                f"case stagingに他caseの明示的なcase_sha256参照があります: {relative.as_posix()}"
                            )
                    carry = data[-SCAN_OVERLAP_BYTES:]
        except archive_analysis_datastore.DatastoreError as exc:
            raise CaseStagingError("case参照scanでstaging fileを安全に読めません") from exc


def _copy_tree(
    source: Path,
    destination: Path,
    *,
    staging_root: Path,
    role: str,
    commitments: Mapping[str, SourceCommitment],
) -> list[CopiedFile]:
    copied: list[CopiedFile] = []
    for path, relative in _walk_files(source, role=role):
        copied.append(
            _copy_file(
                path,
                destination.joinpath(*relative.parts),
                staging_root=staging_root,
                role=role,
                commitments=commitments,
            )
        )
    if not copied:
        raise CaseStagingError(f"{role}に保管対象fileがありません")
    return copied


def _json_bytes(value: Mapping[str, Any]) -> bytes:
    try:
        return (
            json.dumps(
                value,
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
                allow_nan=False,
            )
            + "\n"
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise CaseStagingError("派生manifestをcanonical JSONへ変換できません") from exc


def _write_generated_json(
    path: Path,
    value: Mapping[str, Any],
    *,
    staging_root: Path,
    role: str,
) -> CopiedFile:
    relative = path.relative_to(staging_root).as_posix()
    _reject_sensitive_name(PurePosixPath(relative))
    payload = _json_bytes(value)
    _scan_sensitive_content(payload, relative=relative)
    path_io = archive_analysis_datastore._extended_length_path(path)
    path_io.parent.mkdir(parents=True, exist_ok=True)
    descriptor: int | None = None
    try:
        descriptor = os.open(
            path_io,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0),
            0o600,
        )
        with os.fdopen(descriptor, "wb", closefd=True) as stream:
            descriptor = None
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
    except OSError as exc:
        raise CaseStagingError(f"{role}を排他作成できません") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
    metadata = path_io.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1 or path_io.is_symlink() or _is_reparse(metadata):
        raise CaseStagingError(f"{role}が独立した通常fileではありません")
    return CopiedFile(
        path=path,
        relative=relative,
        size=len(payload),
        sha256=hashlib.sha256(payload).hexdigest(),
        role=role,
    )


def _case_directories(
    root: Path,
    *,
    label: str,
    allowed_noncase_files: frozenset[str] = frozenset(),
) -> dict[str, Path]:
    result: dict[str, Path] = {}
    try:
        with os.scandir(root) as iterator:
            entries = list(iterator)
    except OSError as exc:
        raise CaseStagingError(f"{label}を列挙できません") from exc
    if len(entries) > MAX_CASES + 16:
        raise CaseStagingError(f"{label}のentry件数が上限を超えました")
    for entry in entries:
        path = Path(entry.path)
        try:
            metadata = path.lstat()
        except OSError as exc:
            raise CaseStagingError(f"{label} entryを確認できません") from exc
        if entry.is_symlink() or _is_reparse(metadata):
            raise CaseStagingError(f"{label}にreparse pointは使用できません")
        if stat.S_ISDIR(metadata.st_mode) and SHA256_RE.fullmatch(entry.name):
            result[entry.name] = path.resolve(strict=True)
            continue
        if entry.name in allowed_noncase_files and stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1:
            continue
        raise CaseStagingError(f"{label}に未束縛entryがあります")
    if not result or len(result) > MAX_CASES:
        raise CaseStagingError(f"{label}のcase件数が上限外です")
    return dict(sorted(result.items()))


def _validate_source_manifest(
    source_root: Path,
) -> tuple[dict[str, Any], str, dict[str, Path]]:
    manifest, manifest_sha256 = _read_json(
        source_root / "manifest.json",
        label="MalwareBazaar source manifest",
    )
    selected = manifest.get("selected_hashes")
    items = manifest.get("items")
    metadata_items = manifest.get("selected_metadata")
    if (
        manifest.get("schema_version") != 1
        or manifest.get("complete") is not True
        or manifest.get("archives_remain_encrypted") is not True
        or manifest.get("samples_executed") is not False
        or not isinstance(selected, list)
        or not isinstance(items, list)
        or not isinstance(metadata_items, list)
        or not 1 <= len(selected) <= MAX_CASES
        or len(items) != len(selected)
        or len(metadata_items) != len(selected)
    ):
        raise CaseStagingError("MalwareBazaar source manifestが完全・非実行契約を満たしません")
    selected_values = [_validate_sha256(value, label="selected_hashes item") for value in selected]
    if len(set(selected_values)) != len(selected_values):
        raise CaseStagingError("selected_hashesに重複があります")
    item_map: dict[str, dict[str, Any]] = {}
    metadata_map: dict[str, dict[str, Any]] = {}
    for item in items:
        if not isinstance(item, dict):
            raise CaseStagingError("source manifest itemがobjectではありません")
        digest = _validate_sha256(item.get("sha256"), label="source manifest item.sha256")
        if digest in item_map:
            raise CaseStagingError("source manifest itemに重複があります")
        item_map[digest] = item
    for item in metadata_items:
        if not isinstance(item, dict):
            raise CaseStagingError("selected_metadata itemがobjectではありません")
        digest = _validate_sha256(
            item.get("sha256_hash"),
            label="selected_metadata.sha256_hash",
        )
        if digest in metadata_map:
            raise CaseStagingError("selected_metadataに重複があります")
        metadata_map[digest] = item
    selected_set = set(selected_values)
    if set(item_map) != selected_set or set(metadata_map) != selected_set:
        raise CaseStagingError("source manifestのcase集合が一致しません")
    case_directories = _case_directories(
        source_root,
        label="source root",
        allowed_noncase_files=frozenset({"manifest.json", "family-hints.json"}),
    )
    if set(case_directories) != selected_set:
        raise CaseStagingError("source directoryとselected_hashesのcase集合が一致しません")
    for digest, directory in case_directories.items():
        expected = directory / f"{digest}.zip"
        files = _walk_files(directory, role="source")
        if (
            len(files) != 1
            or files[0][0] != archive_analysis_datastore._extended_length_path(expected)
            or files[0][1].as_posix() != expected.name
        ):
            raise CaseStagingError("source case directoryに未束縛entryがあります")
        try:
            archive_sha256, archive_size, _identity = archive_analysis_datastore._hash_source_snapshot(expected)
        except archive_analysis_datastore.DatastoreError as exc:
            raise CaseStagingError("source archiveを安全に照合できません") from exc
        item = item_map[digest]
        if (
            item.get("zip_sha256") != archive_sha256
            or item.get("zip_size") != archive_size
            or not isinstance(item.get("metadata"), Mapping)
            or item["metadata"].get("sha256_hash") != digest
        ):
            raise CaseStagingError("source archiveとmanifestのsize／SHA-256が一致しません")
    return manifest, manifest_sha256, case_directories


def _validate_one_shot_report_identity(case_directory: Path, *, digest: str) -> None:
    """one-shot report内の全case identity表現を対象directoryへ束縛する。"""

    report, _report_sha256 = _read_json(
        case_directory / "report.json",
        label="one-shot report",
    )
    authoritative: list[str] = []

    root_sha256 = report.get("sha256")
    if root_sha256 is not None:
        authoritative.append(
            _validate_sha256(root_sha256, label="one-shot report.sha256")
        )
    sample = report.get("sample")
    if sample is not None:
        if not isinstance(sample, Mapping):
            raise CaseStagingError("one-shot report.sampleはobjectである必要があります")
        authoritative.append(
            _validate_sha256(
                sample.get("sha256"),
                label="one-shot report.sample.sha256",
            )
        )
    for key in REPORT_CASE_IDENTITY_KEYS:
        if key in report:
            authoritative.append(
                _validate_sha256(
                    report[key],
                    label=f"one-shot report.{key}",
                )
            )
    if not authoritative or any(value != digest for value in authoritative):
        raise CaseStagingError(
            "one-shot reportを対象case SHA-256へ束縛できないか、他caseを参照しています"
        )

    pending: list[tuple[Any, str]] = [(report, "one-shot report")]
    while pending:
        value, location = pending.pop()
        if isinstance(value, Mapping):
            nested_sample = value.get("sample")
            if isinstance(nested_sample, Mapping) and "sha256" in nested_sample:
                observed = _validate_sha256(
                    nested_sample["sha256"],
                    label=f"{location}.sample.sha256",
                )
                if observed != digest:
                    raise CaseStagingError(
                        "one-shot reportに他caseのsample.sha256があります"
                    )
            for key, child in value.items():
                if key in REPORT_CASE_IDENTITY_KEYS:
                    observed = _validate_sha256(
                        child,
                        label=f"{location}.{key}",
                    )
                    if observed != digest:
                        raise CaseStagingError(
                            f"one-shot reportに他caseの{key}があります"
                        )
                elif key == "sample_sha256s":
                    if (
                        not isinstance(child, list)
                        or not child
                        or any(
                            _validate_sha256(
                                item,
                                label=f"{location}.sample_sha256s",
                            )
                            != digest
                            for item in child
                        )
                    ):
                        raise CaseStagingError(
                            "one-shot reportに他caseのsample_sha256sがあります"
                        )
                pending.append((child, f"{location}.{key}"))
        elif isinstance(value, list):
            pending.extend(
                (child, f"{location}[{index}]")
                for index, child in enumerate(value)
            )


def _validate_relationships(
    ghidra_root: Path,
    *,
    collection_id: str,
    expected_cases: set[str],
) -> tuple[dict[str, Any], str, dict[str, tuple[dict[str, Any], ...]], set[str]]:
    manifest, manifest_sha256 = _read_json(
        ghidra_root / "input-relationships.json",
        label="Ghidra input relationships",
    )
    relationships = manifest.get("relationships")
    if (
        manifest.get("schema_version") != 1
        or manifest.get("collection_id") != collection_id
        or manifest.get("sample_executed") is not False
        or manifest.get("network_contacted") is not False
        or not isinstance(relationships, list)
        or not 1 <= len(relationships) <= MAX_RELATIONSHIPS
        or type(manifest.get("unique_pe_objects")) is not int
    ):
        raise CaseStagingError("Ghidra relationship manifestのschemaまたは安全値が不正です")
    grouped: dict[str, list[dict[str, Any]]] = {digest: [] for digest in expected_cases}
    all_pe: set[str] = set()
    observed_rows: set[tuple[str, str, int, str | None]] = set()
    for item in relationships:
        if not isinstance(item, dict):
            raise CaseStagingError("Ghidra relationshipがobjectではありません")
        case_sha256 = _validate_sha256(
            item.get("case_sha256"),
            label="relationship.case_sha256",
        )
        layer_sha256 = _validate_sha256(
            item.get("layer_sha256"),
            label="relationship.layer_sha256",
        )
        parent = item.get("parent_sha256")
        if parent is not None:
            parent = _validate_sha256(parent, label="relationship.parent_sha256")
        depth = item.get("depth")
        size = item.get("size")
        is_pe = item.get("is_pe")
        if (
            case_sha256 not in grouped
            or type(depth) is not int
            or depth < 0
            or type(size) is not int
            or size <= 0
            or type(is_pe) is not bool
            or not isinstance(item.get("format"), str)
            or not isinstance(item.get("transform"), str)
        ):
            raise CaseStagingError("Ghidra relationshipの型またはcase帰属が不正です")
        row_key = (case_sha256, layer_sha256, depth, parent)
        if row_key in observed_rows:
            raise CaseStagingError("Ghidra relationshipに重複があります")
        observed_rows.add(row_key)
        grouped[case_sha256].append(item)
        if is_pe:
            if item.get("format") != "pe":
                raise CaseStagingError("PE relationshipのformatがpeではありません")
            all_pe.add(layer_sha256)
    if manifest["unique_pe_objects"] != len(all_pe):
        raise CaseStagingError("unique_pe_objectsとrelationship実数が一致しません")
    normalized: dict[str, tuple[dict[str, Any], ...]] = {}
    for case_sha256, case_rows in grouped.items():
        if not case_rows:
            raise CaseStagingError("relationshipがないcaseを保管できません")
        layer_set = {item["layer_sha256"] for item in case_rows}
        roots = [item for item in case_rows if item["depth"] == 0]
        if (
            len(roots) != 1
            or roots[0]["layer_sha256"] != case_sha256
            or roots[0].get("parent_sha256") is not None
            or any(
                item.get("parent_sha256") is not None and item["parent_sha256"] not in layer_set for item in case_rows
            )
        ):
            raise CaseStagingError("case relationship graphのrootまたはparentが不正です")
        normalized[case_sha256] = tuple(
            sorted(
                case_rows,
                key=lambda item: (
                    int(item["depth"]),
                    str(item["layer_sha256"]),
                    str(item.get("parent_sha256") or ""),
                ),
            )
        )
    return manifest, manifest_sha256, normalized, all_pe


def _validate_ghidra_run_complete(ghidra_root: Path, *, collection_id: str) -> None:
    expected_safety = {
        "arbitrary_ghidra_scripts_enabled": False,
        "mcp_localhost_only": True,
        "network_contacted": False,
        "sample_executed": False,
    }
    for name in ("run-progress.json", "run-summary.json"):
        document, _digest = _read_json(
            ghidra_root / name,
            label=f"Ghidra {name}",
        )
        allowed_schema_versions = {1, 2} if name == "run-progress.json" else {1}
        if (
            document.get("schema_version") not in allowed_schema_versions
            or document.get("collection_id") != collection_id
            or document.get("status") != "complete"
            or document.get("safety") != expected_safety
        ):
            raise CaseStagingError("未完または安全境界が不一致のGhidra runはcase archiveへ昇格できません")


def _validated_object_directories(
    ghidra_root: Path,
    *,
    expected_pe_sha256s: set[str],
) -> dict[str, Path]:
    objects_root = _validate_existing_directory(
        ghidra_root / "objects",
        label="Ghidra objects root",
    )
    object_directories = _case_directories(objects_root, label="Ghidra objects root")
    try:
        with os.scandir(objects_root) as iterator:
            entry_names = {entry.name for entry in iterator}
    except OSError as exc:
        raise CaseStagingError("Ghidra objects rootを列挙できません") from exc
    if entry_names != expected_pe_sha256s or set(object_directories) != expected_pe_sha256s:
        raise CaseStagingError("Ghidra object集合とPE relationship集合が一致しません")
    return object_directories


def _validated_import_files(
    ghidra_root: Path,
    *,
    expected_pe_sha256s: set[str],
) -> dict[str, Path]:
    import_root = _validate_existing_directory(
        ghidra_root / "import-staging",
        label="Ghidra import staging root",
    )
    expected_names = {f"{digest}.quarantine.bin": digest for digest in expected_pe_sha256s}
    observed: dict[str, Path] = {}
    try:
        with os.scandir(import_root) as iterator:
            entries = list(iterator)
    except OSError as exc:
        raise CaseStagingError("Ghidra import stagingを列挙できません") from exc
    if len(entries) != len(expected_names):
        raise CaseStagingError("Ghidra import stagingとPE relationship件数が一致しません")
    for entry in entries:
        path = Path(entry.path)
        try:
            metadata = path.lstat()
        except OSError as exc:
            raise CaseStagingError("Ghidra import entryを確認できません") from exc
        digest = expected_names.get(entry.name)
        if (
            digest is None
            or entry.is_symlink()
            or _is_reparse(metadata)
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
        ):
            raise CaseStagingError("Ghidra import stagingに未束縛entryがあります")
        try:
            actual_sha256, actual_size, _identity = archive_analysis_datastore._hash_source_snapshot(path)
        except archive_analysis_datastore.DatastoreError as exc:
            raise CaseStagingError("Ghidra import PEを安全に照合できません") from exc
        if actual_sha256 != digest or actual_size <= 0:
            raise CaseStagingError("Ghidra import PEの内容SHA-256がfile名と一致しません")
        observed[digest] = path.resolve(strict=True)
    return observed


def _rewrite_artifact_paths(
    artifacts: Any,
    *,
    ghidra_root: Path,
    program: Mapping[str, Any],
) -> dict[str, str | None]:
    if not isinstance(artifacts, Mapping):
        raise CaseStagingError("private validationのartifactsがobjectではありません")
    program_sha256 = _validate_sha256(
        program.get("sha256"),
        label="private validation program.sha256",
    )
    expected_root_plain = _absolute(ghidra_root / "objects" / program_sha256)
    expected_root = archive_analysis_datastore._extended_length_path(expected_root_plain).resolve(strict=True)
    rewritten: dict[str, str | None] = {}
    for key, raw in sorted(artifacts.items()):
        if not isinstance(key, str):
            raise CaseStagingError("private validationのartifact keyが文字列ではありません")
        if raw is None:
            rewritten[key] = None
            continue
        if not isinstance(raw, str) or not raw:
            raise CaseStagingError("private validationのartifact pathが不正です")
        raw_path = Path(raw)
        if not raw_path.is_absolute():
            raise CaseStagingError("private validationのartifact pathは元runの絶対pathに限定します")
        supplied = _absolute(raw_path)
        try:
            lexical_relative = supplied.relative_to(expected_root_plain)
        except ValueError as exc:
            raise CaseStagingError("private validation artifactが対応object外です") from exc
        _reject_reparse_components(supplied, label="private validation artifact")
        supplied_io = archive_analysis_datastore._extended_length_path(supplied)
        if not os.path.lexists(supplied_io):
            if (
                key == "decompilations"
                and program.get("native_function_count") == 0
                and program.get("characteristic_native_decompilation_count") == 0
            ):
                rewritten[key] = None
                continue
            raise CaseStagingError("private validationの必須artifactが存在しません")
        try:
            resolved = supplied_io.resolve(strict=True)
            resolved.relative_to(expected_root)
            metadata = resolved.lstat()
        except (OSError, ValueError) as exc:
            raise CaseStagingError("private validation artifactが対応object外です") from exc
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or resolved.is_symlink()
            or _is_reparse(metadata)
        ):
            raise CaseStagingError("private validation artifactが独立した通常fileではありません")
        rewritten[key] = (
            PurePosixPath("ghidra") / "objects" / program_sha256 / PurePosixPath(*lexical_relative.parts)
        ).as_posix()
    return rewritten


def _program_totals(
    programs: Sequence[Mapping[str, Any]],
    program_results: Mapping[str, Mapping[str, Any]],
) -> dict[str, int]:
    totals = {
        "characteristic_native_decompilations": 0,
        "exports_items": 0,
        "imports_items": 0,
        "managed_method_bodies": 0,
        "managed_methods": 0,
        "native_functions": 0,
        "programs": len(programs),
        "segments_items": 0,
        "strings_items": 0,
    }
    for program in programs:
        digest = str(program["sha256"])
        result = program_results[digest]
        for destination, source in (
            ("characteristic_native_decompilations", "characteristic_native_decompilation_count"),
            ("managed_method_bodies", "managed_method_body_count"),
            ("managed_methods", "managed_method_count"),
            ("native_functions", "native_function_count"),
        ):
            value = program.get(source)
            if type(value) is not int or value < 0:
                raise CaseStagingError("private validationのprogram countが不正です")
            totals[destination] += value
        for destination, source in (
            ("exports_items", "exports"),
            ("imports_items", "imports"),
            ("segments_items", "segments"),
        ):
            value = result.get(source)
            if not isinstance(value, list):
                raise CaseStagingError("Ghidra program resultのinventoryがlistではありません")
            totals[destination] += len(value)
        retrieval = result.get("retrieval_coverage")
        strings = retrieval.get("strings") if isinstance(retrieval, Mapping) else None
        string_count = strings.get("item_count") if isinstance(strings, Mapping) else None
        if type(string_count) is not int or string_count < 0:
            raise CaseStagingError("Ghidra strings取得件数が不正です")
        totals["strings_items"] += string_count
    return totals


def _validate_private_validation(
    ghidra_root: Path,
    *,
    expected_pe_sha256s: set[str],
    object_directories: Mapping[str, Path],
) -> tuple[
    dict[str, Any],
    str,
    dict[str, dict[str, Any]],
    dict[str, dict[str, Any]],
]:
    document, document_sha256 = _read_json(
        ghidra_root / "private-artifact-validation.json",
        label="Ghidra private artifact validation",
    )
    programs = document.get("programs")
    if (
        document.get("schema_version") != 1
        or document.get("complete") is not True
        or document.get("global_errors") != []
        or document.get("invalid_programs") != 0
        or document.get("valid_programs") != len(expected_pe_sha256s)
        or not isinstance(programs, list)
        or len(programs) != len(expected_pe_sha256s)
    ):
        raise CaseStagingError("Ghidra private validationが完全検証契約を満たしません")
    normalized: dict[str, dict[str, Any]] = {}
    program_results: dict[str, dict[str, Any]] = {}
    for raw_program in programs:
        if not isinstance(raw_program, dict):
            raise CaseStagingError("private validation programがobjectではありません")
        digest = _validate_sha256(
            raw_program.get("sha256"),
            label="private validation program.sha256",
        )
        if digest in normalized or digest not in expected_pe_sha256s:
            raise CaseStagingError("private validation program集合がPE relationshipと一致しません")
        if raw_program.get("valid") is not True or raw_program.get("errors") != []:
            raise CaseStagingError("無効なGhidra programをcase archiveへ昇格できません")
        program = dict(raw_program)
        program["artifacts"] = _rewrite_artifact_paths(
            raw_program.get("artifacts"),
            ghidra_root=ghidra_root,
            program=raw_program,
        )
        result, _result_sha256 = _read_json(
            object_directories[digest] / "program-result.json",
            label="Ghidra program result",
        )
        safety = result.get("safety")
        if (
            result.get("schema_version") != 1
            or result.get("sha256") != digest
            or result.get("status") != "complete"
            or not isinstance(safety, Mapping)
            or safety.get("sample_executed") is not False
            or safety.get("network_contacted") is not False
            or safety.get("arbitrary_ghidra_scripts_enabled") is not False
            or safety.get("raw_results_private") is not True
        ):
            raise CaseStagingError("Ghidra program resultの完全性または安全値が不正です")
        normalized[digest] = program
        program_results[digest] = result
    if set(normalized) != expected_pe_sha256s:
        raise CaseStagingError("private validation programが不足しています")
    calculated_totals = _program_totals(list(normalized.values()), program_results)
    if document.get("totals") != calculated_totals:
        raise CaseStagingError("private validationのglobal totalsをprogramから再現できません")
    return document, document_sha256, normalized, program_results


def _validate_inputs(
    *,
    repository: Path,
    collection_id: str,
    source_root: Path,
    one_shot_root: Path,
    ghidra_root: Path,
    output_root: Path,
    case_sha256s: Sequence[str],
) -> ValidatedInputs:
    if len(case_sha256s) != 1:
        raise CaseStagingError("容量制御とcase分離のため、--case-sha256は1回につき1件だけ指定してください")
    requested = [_validate_sha256(case_sha256s[0], label="--case-sha256")]
    if not COLLECTION_RE.fullmatch(collection_id):
        raise CaseStagingError("collection IDは小文字英数字で開始し、小文字英数字・._-だけを許可します")
    repository = _validate_existing_directory(repository, label="repository")
    source_root = _validate_existing_directory(source_root, label="source root")
    one_shot_root = _validate_existing_directory(one_shot_root, label="one-shot root")
    ghidra_root = _validate_existing_directory(ghidra_root, label="Ghidra root")
    inputs = (source_root, one_shot_root, ghidra_root)
    if any(_is_within(item, repository) for item in inputs):
        raise CaseStagingError("private artifact入力をrepository内から取得できません")
    if any(
        left != right and (_is_within(left, right) or _is_within(right, left))
        for index, left in enumerate(inputs)
        for right in inputs[index + 1 :]
    ):
        raise CaseStagingError("private artifact入力rootは相互に分離してください")
    output_root = _prepare_output_root(
        output_root,
        repository=repository,
        inputs=inputs,
    )
    source_manifest, source_manifest_sha256, source_cases = _validate_source_manifest(source_root)
    one_shot_cases = _case_directories(
        _validate_existing_directory(
            one_shot_root / "cases",
            label="one-shot cases root",
        ),
        label="one-shot cases root",
    )
    expected_cases = set(source_cases)
    if set(one_shot_cases) != expected_cases:
        raise CaseStagingError("sourceとone-shotのcase集合が一致しません")
    (
        relationships_manifest,
        relationships_manifest_sha256,
        relationships,
        all_pe_sha256s,
    ) = _validate_relationships(
        ghidra_root,
        collection_id=collection_id,
        expected_cases=expected_cases,
    )
    _validate_ghidra_run_complete(ghidra_root, collection_id=collection_id)
    object_directories = _validated_object_directories(
        ghidra_root,
        expected_pe_sha256s=all_pe_sha256s,
    )
    _validated_import_files(
        ghidra_root,
        expected_pe_sha256s=all_pe_sha256s,
    )
    (
        validation_manifest,
        validation_manifest_sha256,
        validation_programs,
        program_results,
    ) = _validate_private_validation(
        ghidra_root,
        expected_pe_sha256s=all_pe_sha256s,
        object_directories=object_directories,
    )
    if any(value not in expected_cases for value in requested):
        raise CaseStagingError("指定caseが検証済みsource集合にありません")
    selected_cases: dict[str, CaseInputs] = {}
    for digest in sorted(requested):
        case_rows = relationships[digest]
        pe_sha256s = tuple(sorted({str(item["layer_sha256"]) for item in case_rows if item.get("is_pe") is True}))
        if not pe_sha256s:
            raise CaseStagingError("PE objectがないcaseはこのhelperで保管できません")
        selected_cases[digest] = CaseInputs(
            case_sha256=digest,
            source_directory=source_cases[digest],
            one_shot_directory=one_shot_cases[digest],
            relationships=case_rows,
            pe_sha256s=pe_sha256s,
        )
    return ValidatedInputs(
        repository=repository,
        collection_id=collection_id,
        source_root=source_root,
        one_shot_root=one_shot_root,
        ghidra_root=ghidra_root,
        output_root=output_root,
        source_manifest=source_manifest,
        source_manifest_sha256=source_manifest_sha256,
        relationships_manifest=relationships_manifest,
        relationships_manifest_sha256=relationships_manifest_sha256,
        validation_manifest=validation_manifest,
        validation_manifest_sha256=validation_manifest_sha256,
        validation_programs=validation_programs,
        program_results=program_results,
        cases=selected_cases,
    )


def _datastore_target(collection_id: str, case_sha256: str) -> str:
    suffix = f"-{case_sha256}"
    maximum_prefix = 128 - len(suffix)
    prefix = collection_id[:maximum_prefix].rstrip("._-")
    target = f"{prefix}{suffix}" if prefix else f"case-{case_sha256}"
    try:
        return archive_analysis_datastore.validate_target(target)
    except archive_analysis_datastore.DatastoreError as exc:
        raise CaseStagingError("case別datastore targetを安全に構成できません") from exc


def _source_case_document_from_manifest(
    *,
    source_manifest: Mapping[str, Any],
    source_manifest_sha256: str,
    collection_id: str,
    case_sha256: str,
) -> dict[str, Any]:
    items = source_manifest["items"]
    selected_metadata = source_manifest["selected_metadata"]
    item = next(
        (value for value in items if isinstance(value, Mapping) and value.get("sha256") == case_sha256),
        None,
    )
    metadata = next(
        (
            value
            for value in selected_metadata
            if isinstance(value, Mapping) and value.get("sha256_hash") == case_sha256
        ),
        None,
    )
    if not isinstance(item, Mapping) or not isinstance(metadata, Mapping):
        raise CaseStagingError("case別取得provenanceをsource manifestから復元できません")
    return {
        "schema_version": ACQUISITION_SCHEMA_VERSION,
        "collection_id": collection_id,
        "case_sha256": case_sha256,
        "source_manifest_sha256": source_manifest_sha256,
        "selection_commitment_sha256": source_manifest.get("selection_commitment_sha256"),
        "source": source_manifest.get("source"),
        "selection_mode": source_manifest.get("selection_mode"),
        "selected_at": source_manifest.get("selected_at"),
        "archive": {
            "path": f"source/{case_sha256}.zip",
            "size": item.get("zip_size"),
            "sha256": item.get("zip_sha256"),
            "remains_encrypted": True,
        },
        "metadata": dict(metadata),
        "provider_metadata": dict(item["metadata"]),
        "safety": {
            "sample_executed": False,
            "archive_decrypted_for_staging": False,
            "network_contacted_for_staging": False,
        },
    }


def _source_case_document(inputs: ValidatedInputs, case: CaseInputs) -> dict[str, Any]:
    return _source_case_document_from_manifest(
        source_manifest=inputs.source_manifest,
        source_manifest_sha256=inputs.source_manifest_sha256,
        collection_id=inputs.collection_id,
        case_sha256=case.case_sha256,
    )


def _case_program_result(
    inputs: ValidatedInputs,
    case: CaseInputs,
    *,
    program_sha256: str,
) -> dict[str, Any]:
    source = inputs.program_results[program_sha256]
    relationships = source.get("relationships")
    if not isinstance(relationships, list) or any(not isinstance(item, Mapping) for item in relationships):
        raise CaseStagingError("Ghidra program resultのrelationshipがlistではありません")
    observed = [dict(item) for item in relationships if item.get("case_sha256") == case.case_sha256]
    expected = [dict(item) for item in case.relationships if item.get("layer_sha256") == program_sha256]
    canonical = lambda item: json.dumps(  # noqa: E731
        item,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )
    if sorted(map(canonical, observed)) != sorted(map(canonical, expected)):
        raise CaseStagingError("Ghidra program resultとcase relationship manifestの帰属が一致しません")
    filtered = dict(source)
    filtered["relationships"] = sorted(
        observed,
        key=lambda item: (
            int(item.get("depth", 0)),
            str(item.get("layer_sha256", "")),
            str(item.get("parent_sha256") or ""),
        ),
    )
    return filtered


def _copy_case_ghidra_object(
    inputs: ValidatedInputs,
    case: CaseInputs,
    *,
    program_sha256: str,
    staging_root: Path,
    commitments: Mapping[str, SourceCommitment],
) -> list[CopiedFile]:
    source_root = inputs.ghidra_root / "objects" / program_sha256
    destination_root = staging_root / "ghidra" / "objects" / program_sha256
    copied: list[CopiedFile] = []
    program_result_seen = False
    for source, relative in _walk_files(source_root, role="ghidra_object"):
        destination = destination_root.joinpath(*relative.parts)
        if relative.as_posix() == "program-result.json":
            program_result_seen = True
            _assert_source_commitment(
                source,
                commitments=commitments,
                role="Ghidra program result",
            )
            copied.append(
                _write_generated_json(
                    destination,
                    _case_program_result(
                        inputs,
                        case,
                        program_sha256=program_sha256,
                    ),
                    staging_root=staging_root,
                    role="ghidra_object_case_filtered",
                )
            )
        else:
            copied.append(
                _copy_file(
                    source,
                    destination,
                    staging_root=staging_root,
                    role="ghidra_object",
                    commitments=commitments,
                )
            )
    if not program_result_seen or not copied:
        raise CaseStagingError("Ghidra objectにprogram-result.jsonがありません")
    return copied


def _relationship_case_document(
    inputs: ValidatedInputs,
    case: CaseInputs,
) -> dict[str, Any]:
    return {
        "schema_version": RELATIONSHIP_SCHEMA_VERSION,
        "source_schema_version": inputs.relationships_manifest.get("schema_version"),
        "source_manifest_sha256": inputs.relationships_manifest_sha256,
        "collection_id": inputs.collection_id,
        "case_sha256": case.case_sha256,
        "relationship_count": len(case.relationships),
        "unique_pe_objects": len(case.pe_sha256s),
        "static_tools": inputs.relationships_manifest.get("static_tools"),
        "relationships": list(case.relationships),
        "safety": {
            "sample_executed": False,
            "network_contacted": False,
            "different_case_relationships_included": False,
        },
    }


def _validation_case_document(
    inputs: ValidatedInputs,
    case: CaseInputs,
) -> dict[str, Any]:
    programs = [inputs.validation_programs[digest] for digest in case.pe_sha256s]
    results = {digest: inputs.program_results[digest] for digest in case.pe_sha256s}
    return {
        "schema_version": VALIDATION_SCHEMA_VERSION,
        "source_schema_version": inputs.validation_manifest.get("schema_version"),
        "source_manifest_sha256": inputs.validation_manifest_sha256,
        "collection_id": inputs.collection_id,
        "case_sha256": case.case_sha256,
        "complete": True,
        "global_errors": [],
        "invalid_programs": 0,
        "valid_programs": len(programs),
        "programs": programs,
        "totals": _program_totals(programs, results),
        "safety": {
            "sample_executed": False,
            "network_contacted": False,
            "arbitrary_ghidra_scripts_enabled": False,
            "different_case_programs_included": False,
        },
    }


def _inventory_record(item: CopiedFile) -> dict[str, Any]:
    return {
        "path": item.relative,
        "role": item.role,
        "size": item.size,
        "sha256": item.sha256,
    }


def _inventory_sha256(records: Sequence[Mapping[str, Any]]) -> str:
    payload = json.dumps(
        list(records),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _verify_promoted_staging(
    root: Path,
    copied: Sequence[CopiedFile],
    *,
    case_sha256: str,
) -> tuple[list[archive_analysis_datastore.SourceFile], str, int]:
    """昇格後treeをcopy時のexact inventoryへ再拘束し、秘密値も再scanする。"""

    expected = {item.relative.casefold(): item for item in copied}
    if len(expected) != len(copied):
        raise CaseStagingError("case stagingの大小文字非依存pathが重複しています")
    observed: set[str] = set()
    for path, relative in _walk_files(root, role="promoted case staging"):
        _reject_sensitive_name(relative)
        key = relative.as_posix().casefold()
        item = expected.get(key)
        if item is None or item.relative != relative.as_posix() or key in observed:
            raise CaseStagingError("昇格後case stagingに未束縛fileがあります")
        _scan_file_for_sensitive_content(path, relative=relative.as_posix())
        try:
            digest, size, _identity = archive_analysis_datastore._hash_source_snapshot(
                path
            )
        except archive_analysis_datastore.DatastoreError as exc:
            raise CaseStagingError("昇格後case stagingを安全に照合できません") from exc
        if size != item.size or digest != item.sha256:
            raise CaseStagingError("昇格後case stagingがcopy commitmentから変更されました")
        observed.add(key)
    if observed != set(expected):
        raise CaseStagingError("昇格後case stagingのfile集合が一致しません")
    _scan_staged_case_references(root, case_sha256=case_sha256)
    try:
        archive_files = archive_analysis_datastore.collect_source_files([root])
    except archive_analysis_datastore.DatastoreError as exc:
        raise CaseStagingError("昇格後case stagingをarchive helperへ渡せません") from exc
    records = [
        {"path": item.archive_name, "size": item.size, "sha256": item.sha256}
        for item in archive_files
    ]
    return (
        archive_files,
        _inventory_sha256(records),
        sum(item.size for item in archive_files),
    )


def _remove_new_staging(path: Path, *, output_root: Path) -> None:
    if not os.path.lexists(path):
        return
    absolute = _absolute(path)
    if absolute.parent != output_root or not (absolute.name.startswith(".") and absolute.name.endswith(".staging")):
        raise CaseStagingError("一時stagingのcleanup境界を確認できません")
    _reject_reparse_components(absolute, label="owned一時staging")
    shutil.rmtree(archive_analysis_datastore._extended_length_path(absolute))


def _stage_one(
    inputs: ValidatedInputs,
    case: CaseInputs,
    *,
    commitments: Mapping[str, SourceCommitment],
) -> dict[str, Any]:
    target = _datastore_target(inputs.collection_id, case.case_sha256)
    final = inputs.output_root / target
    if os.path.lexists(final):
        raise CaseStagingError(f"既存case stagingを上書きしません: {target}")
    temporary: Path | None = inputs.output_root / f".{case.case_sha256[:12]}.{uuid.uuid4().hex[:12]}.staging"
    try:
        temporary.mkdir()
    except OSError as exc:
        raise CaseStagingError("case一時stagingを排他作成できません") from exc
    copied: list[CopiedFile] = []
    try:
        copied.extend(
            _copy_tree(
                case.source_directory,
                temporary / "source",
                staging_root=temporary,
                role="source",
                commitments=commitments,
            )
        )
        copied.extend(
            _copy_tree(
                case.one_shot_directory,
                temporary / "one-shot-private",
                staging_root=temporary,
                role="one_shot_private",
                commitments=commitments,
            )
        )
        for digest in case.pe_sha256s:
            copied.extend(
                _copy_case_ghidra_object(
                    inputs,
                    case,
                    program_sha256=digest,
                    staging_root=temporary,
                    commitments=commitments,
                )
            )
            copied.append(
                _copy_file(
                    inputs.ghidra_root / "import-staging" / f"{digest}.quarantine.bin",
                    temporary / "ghidra" / "import-staging" / f"{digest}.quarantine.bin",
                    staging_root=temporary,
                    role="ghidra_import",
                    commitments=commitments,
                )
            )
        copied.append(
            _write_generated_json(
                temporary / "derived" / "source-acquisition.case.json",
                _source_case_document(inputs, case),
                staging_root=temporary,
                role="derived_acquisition_manifest",
            )
        )
        copied.append(
            _write_generated_json(
                temporary / "derived" / "input-relationships.case.json",
                _relationship_case_document(inputs, case),
                staging_root=temporary,
                role="derived_relationship_manifest",
            )
        )
        copied.append(
            _write_generated_json(
                temporary / "derived" / "private-artifact-validation.case.json",
                _validation_case_document(inputs, case),
                staging_root=temporary,
                role="derived_validation_manifest",
            )
        )
        records = sorted(
            (_inventory_record(item) for item in copied),
            key=lambda item: str(item["path"]).casefold(),
        )
        if len({str(item["path"]).casefold() for item in records}) != len(records):
            raise CaseStagingError("case staging内の相対pathが重複しています")
        roles: dict[str, dict[str, int]] = {}
        for item in records:
            role = str(item["role"])
            summary = roles.setdefault(role, {"file_count": 0, "total_size": 0})
            summary["file_count"] += 1
            summary["total_size"] += int(item["size"])
        staging_manifest = {
            "schema_version": SCHEMA_VERSION,
            "target": target,
            "collection_id": inputs.collection_id,
            "case_sha256": case.case_sha256,
            "file_count_excluding_this_manifest": len(records),
            "total_size_excluding_this_manifest": sum(int(item["size"]) for item in records),
            "file_inventory_sha256": _inventory_sha256(records),
            "files": records,
            "roles": dict(sorted(roles.items())),
            "ghidra": {
                "relationship_count": len(case.relationships),
                "pe_object_count": len(case.pe_sha256s),
                "pe_sha256s": list(case.pe_sha256s),
                "source_relationship_manifest_sha256": (inputs.relationships_manifest_sha256),
                "source_validation_manifest_sha256": (inputs.validation_manifest_sha256),
            },
            "archive_handoff": {
                "tool": "analysis-framework/common/archive_analysis_datastore.py",
                "target": target,
                "source": "<this-case-staging-directory>",
                "receipt_must_remain_outside_repository": True,
                "datastore_upload_json_created": False,
            },
            "safety": {
                "physical_copy_only": True,
                "hardlinks_allowed": False,
                "symlinks_or_junctions_allowed": False,
                "host_secret_name_scan_complete": True,
                "host_secret_content_scan_complete": True,
                "different_cases_included": False,
                "sample_executed": False,
                "network_contacted": False,
                "source_deleted": False,
            },
        }
        manifest_file = _write_generated_json(
            temporary / STAGING_MANIFEST_NAME,
            staging_manifest,
            staging_root=temporary,
            role="case_staging_manifest",
        )
        copied.append(manifest_file)
        _scan_staged_case_references(temporary, case_sha256=case.case_sha256)
        try:
            archive_files = archive_analysis_datastore.collect_source_files([temporary])
        except archive_analysis_datastore.DatastoreError as exc:
            raise CaseStagingError("case stagingを既存archive helperへ安全に渡せません") from exc
        if len(archive_files) != len(copied):
            raise CaseStagingError("case staging inventoryとarchive inventoryが一致しません")
        os.replace(temporary, final)
        temporary = None
        final_archive_files, source_tree_sha256, total_size = (
            _verify_promoted_staging(
                final,
                copied,
                case_sha256=case.case_sha256,
            )
        )
        return {
            "case_sha256": case.case_sha256,
            "target": target,
            "source_path": os.fspath(final),
            "file_count": len(final_archive_files),
            "total_size": total_size,
            "source_tree_sha256": source_tree_sha256,
            "staging_manifest_sha256": manifest_file.sha256,
            "archive_arguments": [
                "--target",
                target,
                "--source",
                os.fspath(final),
            ],
            "sample_executed": False,
            "network_contacted": False,
        }
    except BaseException:
        if temporary is not None:
            _remove_new_staging(temporary, output_root=inputs.output_root)
        raise


def _projected_staging_bytes(inputs: ValidatedInputs) -> int:
    total = 0
    for case in inputs.cases.values():
        total += sum(path.lstat().st_size for path, _relative in _walk_files(case.source_directory, role="source"))
        total += sum(
            path.lstat().st_size
            for path, _relative in _walk_files(
                case.one_shot_directory,
                role="one_shot_private",
            )
        )
        for digest in case.pe_sha256s:
            total += sum(
                path.lstat().st_size
                for path, _relative in _walk_files(
                    inputs.ghidra_root / "objects" / digest,
                    role="ghidra_object",
                )
            )
            total += (inputs.ghidra_root / "import-staging" / f"{digest}.quarantine.bin").lstat().st_size
    return total + len(inputs.cases) * 1024 * 1024


def _preflight_sensitive_content(
    inputs: ValidatedInputs,
) -> dict[str, SourceCommitment]:
    files: dict[str, tuple[Path, str]] = {}

    def add(path: Path, label: str) -> None:
        key = os.path.normcase(os.fspath(_absolute(path)))
        files.setdefault(key, (path, label))

    for case in inputs.cases.values():
        for path, relative in _walk_files(case.source_directory, role="source"):
            add(path, f"source/{case.case_sha256}/{relative.as_posix()}")
        for path, relative in _walk_files(
            case.one_shot_directory,
            role="one_shot_private",
        ):
            add(
                path,
                f"one-shot-private/{case.case_sha256}/{relative.as_posix()}",
            )
        for digest in case.pe_sha256s:
            for path, relative in _walk_files(
                inputs.ghidra_root / "objects" / digest,
                role="ghidra_object",
            ):
                add(path, f"ghidra/objects/{digest}/{relative.as_posix()}")
            add(
                inputs.ghidra_root / "import-staging" / f"{digest}.quarantine.bin",
                f"ghidra/import-staging/{digest}.quarantine.bin",
            )
    commitments: dict[str, SourceCommitment] = {}
    for key, (path, relative) in sorted(files.items()):
        commitments[key] = _snapshot_source_commitment(path, relative=relative)
    return commitments


def stage_cases(
    *,
    repository: Path,
    collection_id: str,
    source_root: Path,
    one_shot_root: Path,
    ghidra_root: Path,
    output_root: Path,
    case_sha256s: Sequence[str],
) -> dict[str, Any]:
    """検証済みの単一caseを物理copyし、archive引数を返す。"""

    inputs = _validate_inputs(
        repository=repository,
        collection_id=collection_id,
        source_root=source_root,
        one_shot_root=one_shot_root,
        ghidra_root=ghidra_root,
        output_root=output_root,
        case_sha256s=case_sha256s,
    )
    targets = [_datastore_target(collection_id, digest) for digest in inputs.cases]
    if any(os.path.lexists(inputs.output_root / target) for target in targets):
        raise CaseStagingError("既存case stagingを含むbatchは開始しません")
    required = _projected_staging_bytes(inputs)
    try:
        free = shutil.disk_usage(inputs.output_root).free
    except OSError as exc:
        raise CaseStagingError("case staging filesystemの空き容量を確認できません") from exc
    if free < required + MINIMUM_FREE_RESERVE_BYTES:
        raise CaseStagingError("case stagingに必要な空き容量と安全余白がありません")
    commitments = _preflight_sensitive_content(inputs)
    for case in inputs.cases.values():
        _validate_one_shot_report_identity(
            case.one_shot_directory,
            digest=case.case_sha256,
        )
    staged = [
        _stage_one(inputs, case, commitments=commitments)
        for case in inputs.cases.values()
    ]
    return {
        "schema_version": SCHEMA_VERSION,
        "collection_id": collection_id,
        "case_count": len(staged),
        "projected_staging_bytes": required,
        "observed_free_bytes_before_staging": free,
        "preflight_secret_content_scanned_files": len(commitments),
        "cases": staged,
        "safety": {
            "case_separated": True,
            "physical_copy_only": True,
            "preflight_secret_name_and_content_scan_complete": True,
            "sample_executed": False,
            "network_contacted": False,
            "s3_upload_performed": False,
            "receipt_created": False,
            "source_deleted": False,
        },
    }


def stage_cases_without_ghidra(
    *,
    repository: Path,
    collection_id: str,
    source_root: Path,
    one_shot_root: Path,
    output_root: Path,
    case_sha256s: Sequence[str],
) -> dict[str, Any]:
    """Ghidraを実行しないrunのsourceとone-shot結果を単一caseへ分離する。"""

    if len(case_sha256s) != 1:
        raise CaseStagingError("容量制御とcase分離のため、caseは1回につき1件だけ指定してください")
    digest = _validate_sha256(case_sha256s[0], label="case SHA-256")
    if not COLLECTION_RE.fullmatch(collection_id):
        raise CaseStagingError("collection IDは小文字英数字で開始し、小文字英数字・._-だけを許可します")
    repository = _validate_existing_directory(repository, label="repository")
    source_root = _validate_existing_directory(source_root, label="source root")
    one_shot_root = _validate_existing_directory(one_shot_root, label="one-shot root")
    inputs = (source_root, one_shot_root)
    if any(_is_within(item, repository) for item in inputs):
        raise CaseStagingError("private artifact入力をrepository内から取得できません")
    if _is_within(source_root, one_shot_root) or _is_within(one_shot_root, source_root):
        raise CaseStagingError("private artifact入力rootは相互に分離してください")
    output_root = _prepare_output_root(output_root, repository=repository, inputs=inputs)
    source_manifest, source_manifest_sha256, source_cases = _validate_source_manifest(source_root)
    one_shot_cases = _case_directories(
        _validate_existing_directory(one_shot_root / "cases", label="one-shot cases root"),
        label="one-shot cases root",
    )
    if set(one_shot_cases) != set(source_cases):
        raise CaseStagingError("sourceとone-shotのcase集合が一致しません")
    if digest not in source_cases:
        raise CaseStagingError("指定caseが検証済みsource集合にありません")
    source_directory = source_cases[digest]
    one_shot_directory = one_shot_cases[digest]
    _validate_one_shot_report_identity(one_shot_directory, digest=digest)

    input_files: dict[str, tuple[Path, str]] = {}
    for root, role in (
        (source_directory, "source"),
        (one_shot_directory, "one_shot_private"),
    ):
        for path, relative in _walk_files(root, role=role):
            key = _source_commitment_key(path)
            input_files.setdefault(key, (path, f"{role}/{digest}/{relative.as_posix()}"))
    commitments = {
        key: _snapshot_source_commitment(path, relative=relative)
        for key, (path, relative) in sorted(input_files.items())
    }
    required = sum(item.size for item in commitments.values()) + 1024 * 1024
    try:
        free = shutil.disk_usage(output_root).free
    except OSError as exc:
        raise CaseStagingError("case staging filesystemの空き容量を確認できません") from exc
    if free < required + MINIMUM_FREE_RESERVE_BYTES:
        raise CaseStagingError("case stagingに必要な空き容量と安全余白がありません")

    target = _datastore_target(collection_id, digest)
    final = output_root / target
    if os.path.lexists(final):
        raise CaseStagingError(f"既存case stagingを上書きしません: {target}")
    temporary: Path | None = output_root / f".{digest[:12]}.{uuid.uuid4().hex[:12]}.staging"
    try:
        temporary.mkdir()
    except OSError as exc:
        raise CaseStagingError("case一時stagingを排他作成できません") from exc
    copied: list[CopiedFile] = []
    try:
        copied.extend(
            _copy_tree(
                source_directory,
                temporary / "source",
                staging_root=temporary,
                role="source",
                commitments=commitments,
            )
        )
        copied.extend(
            _copy_tree(
                one_shot_directory,
                temporary / "one-shot-private",
                staging_root=temporary,
                role="one_shot_private",
                commitments=commitments,
            )
        )
        copied.append(
            _write_generated_json(
                temporary / "derived" / "source-acquisition.case.json",
                _source_case_document_from_manifest(
                    source_manifest=source_manifest,
                    source_manifest_sha256=source_manifest_sha256,
                    collection_id=collection_id,
                    case_sha256=digest,
                ),
                staging_root=temporary,
                role="derived_acquisition_manifest",
            )
        )
        records = sorted(
            (_inventory_record(item) for item in copied),
            key=lambda item: str(item["path"]).casefold(),
        )
        roles: dict[str, dict[str, int]] = {}
        for item in records:
            summary = roles.setdefault(str(item["role"]), {"file_count": 0, "total_size": 0})
            summary["file_count"] += 1
            summary["total_size"] += int(item["size"])
        staging_manifest = {
            "schema_version": SCHEMA_VERSION,
            "target": target,
            "collection_id": collection_id,
            "case_sha256": digest,
            "file_count_excluding_this_manifest": len(records),
            "total_size_excluding_this_manifest": sum(int(item["size"]) for item in records),
            "file_inventory_sha256": _inventory_sha256(records),
            "files": records,
            "roles": dict(sorted(roles.items())),
            "ghidra": {"status": "not_requested", "files_included": False},
            "archive_handoff": {
                "tool": "analysis-framework/common/archive_analysis_datastore.py",
                "target": target,
                "source": "<this-case-staging-directory>",
                "receipt_must_remain_outside_repository": True,
                "datastore_upload_json_created": False,
            },
            "safety": {
                "physical_copy_only": True,
                "hardlinks_allowed": False,
                "symlinks_or_junctions_allowed": False,
                "host_secret_name_scan_complete": True,
                "host_secret_content_scan_complete": True,
                "different_cases_included": False,
                "sample_executed": False,
                "network_contacted": False,
                "source_deleted": False,
            },
        }
        manifest_file = _write_generated_json(
            temporary / STAGING_MANIFEST_NAME,
            staging_manifest,
            staging_root=temporary,
            role="case_staging_manifest",
        )
        copied.append(manifest_file)
        _scan_staged_case_references(temporary, case_sha256=digest)
        try:
            archive_files = archive_analysis_datastore.collect_source_files([temporary])
        except archive_analysis_datastore.DatastoreError as exc:
            raise CaseStagingError("case stagingを既存archive helperへ安全に渡せません") from exc
        if len(archive_files) != len(copied):
            raise CaseStagingError("case staging inventoryとarchive inventoryが一致しません")
        os.replace(temporary, final)
        temporary = None
        final_archive_files, source_tree_sha256, total_size = _verify_promoted_staging(
            final,
            copied,
            case_sha256=digest,
        )
        staged = {
            "case_sha256": digest,
            "target": target,
            "source_path": os.fspath(final),
            "file_count": len(final_archive_files),
            "total_size": total_size,
            "source_tree_sha256": source_tree_sha256,
            "staging_manifest_sha256": manifest_file.sha256,
            "archive_arguments": ["--target", target, "--source", os.fspath(final)],
            "sample_executed": False,
            "network_contacted": False,
        }
    except BaseException:
        if temporary is not None:
            _remove_new_staging(temporary, output_root=output_root)
        raise
    return {
        "schema_version": SCHEMA_VERSION,
        "collection_id": collection_id,
        "case_count": 1,
        "projected_staging_bytes": required,
        "observed_free_bytes_before_staging": free,
        "preflight_secret_content_scanned_files": len(commitments),
        "cases": [staged],
        "safety": {
            "case_separated": True,
            "physical_copy_only": True,
            "preflight_secret_name_and_content_scan_complete": True,
            "sample_executed": False,
            "network_contacted": False,
            "s3_upload_performed": False,
            "receipt_created": False,
            "source_deleted": False,
        },
    }


def reuse_case_staging(
    *,
    output_root: Path,
    collection_id: str,
    case_sha256: str,
) -> dict[str, Any]:
    """中断後に残ったowned stagingを全inventory再検証して再利用する。"""

    if not COLLECTION_RE.fullmatch(collection_id):
        raise CaseStagingError("再利用対象collection IDが不正です")
    digest = _validate_sha256(case_sha256, label="再利用対象case")
    output = _validate_existing_directory(output_root, label="case staging output root")
    target = _datastore_target(collection_id, digest)
    source = output / target
    if not os.path.lexists(source):
        raise CaseStagingError("再利用対象case stagingが存在しません")
    source = _validate_existing_directory(source, label="既存case staging")
    if source.parent != output or source.name != target:
        raise CaseStagingError("既存case stagingをowned output rootへ束縛できません")

    manifest_path = source / STAGING_MANIFEST_NAME
    manifest, manifest_sha256 = _read_json(
        manifest_path,
        label="case staging manifest",
    )
    files = manifest.get("files")
    handoff = manifest.get("archive_handoff")
    safety = manifest.get("safety")
    if (
        manifest.get("schema_version") != SCHEMA_VERSION
        or manifest.get("target") != target
        or manifest.get("collection_id") != collection_id
        or manifest.get("case_sha256") != digest
        or not isinstance(files, list)
        or not files
        or not isinstance(handoff, Mapping)
        or handoff.get("target") != target
        or handoff.get("datastore_upload_json_created") is not False
        or not isinstance(safety, Mapping)
        or safety.get("physical_copy_only") is not True
        or safety.get("hardlinks_allowed") is not False
        or safety.get("symlinks_or_junctions_allowed") is not False
        or safety.get("different_cases_included") is not False
        or safety.get("sample_executed") is not False
        or safety.get("network_contacted") is not False
        or safety.get("source_deleted") is not False
    ):
        raise CaseStagingError("既存case staging manifestの束縛または安全契約が不正です")

    declared: dict[str, dict[str, Any]] = {}
    normalized_records: list[dict[str, Any]] = []
    roles: dict[str, dict[str, int]] = {}
    for raw in files:
        if not isinstance(raw, Mapping):
            raise CaseStagingError("既存case staging inventoryがobjectではありません")
        relative_value = raw.get("path")
        role = raw.get("role")
        size = raw.get("size")
        sha256 = raw.get("sha256")
        if not isinstance(relative_value, str) or not relative_value:
            raise CaseStagingError("既存case staging inventory pathが不正です")
        relative = PurePosixPath(relative_value)
        if (
            relative.is_absolute()
            or any(part in {"", ".", ".."} or ":" in part or "\\" in part for part in relative.parts)
            or relative.as_posix() == STAGING_MANIFEST_NAME
            or not isinstance(role, str)
            or not role
            or type(size) is not int
            or size < 0
        ):
            raise CaseStagingError("既存case staging inventoryの型またはpathが不正です")
        digest_value = _validate_sha256(sha256, label="staging inventory sha256")
        key = relative.as_posix().casefold()
        if key in declared:
            raise CaseStagingError("既存case staging inventory pathが重複しています")
        record = {
            "path": relative.as_posix(),
            "role": role,
            "size": size,
            "sha256": digest_value,
        }
        declared[key] = record
        normalized_records.append(record)
        summary = roles.setdefault(role, {"file_count": 0, "total_size": 0})
        summary["file_count"] += 1
        summary["total_size"] += size

    normalized_records.sort(key=lambda item: str(item["path"]).casefold())
    if (
        manifest.get("file_count_excluding_this_manifest") != len(normalized_records)
        or manifest.get("total_size_excluding_this_manifest")
        != sum(int(item["size"]) for item in normalized_records)
        or manifest.get("file_inventory_sha256") != _inventory_sha256(normalized_records)
        or manifest.get("roles") != dict(sorted(roles.items()))
    ):
        raise CaseStagingError("既存case staging manifestのinventory集計が一致しません")

    observed = _walk_files(source, role="existing case staging")
    if len(observed) != len(normalized_records) + 1:
        raise CaseStagingError("既存case stagingのfile集合がmanifestと一致しません")
    for path, relative in observed:
        _reject_sensitive_name(relative)
        _scan_file_for_sensitive_content(path, relative=relative.as_posix())
        if relative.as_posix() == STAGING_MANIFEST_NAME:
            continue
        record = declared.get(relative.as_posix().casefold())
        if record is None or record["path"] != relative.as_posix():
            raise CaseStagingError("既存case stagingに未束縛fileがあります")
        try:
            observed_sha256, observed_size, _identity = (
                archive_analysis_datastore._hash_source_snapshot(path)
            )
        except archive_analysis_datastore.DatastoreError as exc:
            raise CaseStagingError("既存case staging fileを安全に照合できません") from exc
        if observed_size != record["size"] or observed_sha256 != record["sha256"]:
            raise CaseStagingError("既存case staging inventoryのSHA-256が一致しません")
    _scan_staged_case_references(source, case_sha256=digest)
    try:
        archive_files = archive_analysis_datastore.collect_source_files([source])
    except archive_analysis_datastore.DatastoreError as exc:
        raise CaseStagingError("既存case stagingをarchive helperへ渡せません") from exc
    if len(archive_files) != len(normalized_records) + 1:
        raise CaseStagingError("既存case stagingのarchive inventoryが一致しません")
    archive_records = [
        {"path": item.archive_name, "size": item.size, "sha256": item.sha256}
        for item in archive_files
    ]
    source_tree_sha256 = _inventory_sha256(archive_records)
    return {
        "schema_version": SCHEMA_VERSION,
        "collection_id": collection_id,
        "case_count": 1,
        "reused_existing_staging": True,
        "cases": [
            {
                "case_sha256": digest,
                "target": target,
                "source_path": os.fspath(source),
                "file_count": len(archive_files),
                "total_size": sum(item.size for item in archive_files),
                "source_tree_sha256": source_tree_sha256,
                "staging_manifest_sha256": manifest_sha256,
                "archive_arguments": ["--target", target, "--source", os.fspath(source)],
                "sample_executed": False,
                "network_contacted": False,
            }
        ],
        "safety": {
            "case_separated": True,
            "physical_copy_only": True,
            "existing_staging_fully_revalidated": True,
            "sample_executed": False,
            "network_contacted": False,
            "s3_upload_performed": False,
            "receipt_created": False,
            "source_deleted": False,
        },
    }


def remove_case_staging_after_verified_archive(
    *,
    output_root: Path,
    source_path: Path,
    collection_id: str,
    case_sha256: str,
    archive_result: Mapping[str, Any],
    archive_target: str | None = None,
) -> dict[str, Any]:
    """remote検証済みarchiveに対応するowned case stagingだけを削除する。"""

    if not COLLECTION_RE.fullmatch(collection_id):
        raise CaseStagingError("cleanup対象collection IDが不正です")
    digest = _validate_sha256(case_sha256, label="cleanup対象case")
    if archive_target is None:
        target = _datastore_target(collection_id, digest)
    else:
        try:
            target = archive_analysis_datastore.validate_target(archive_target)
        except archive_analysis_datastore.DatastoreError as exc:
            raise CaseStagingError("cleanup対象の追補archive targetが不正です") from exc
        if digest not in target:
            raise CaseStagingError("追補archive targetをcleanup対象caseへ束縛できません")
    if (
        archive_result.get("target") != target
        or archive_result.get("status") not in {"verified", "verified_reused"}
        or not isinstance(archive_result.get("archive_sha256"), str)
        or SHA256_RE.fullmatch(str(archive_result["archive_sha256"])) is None
        or not isinstance(archive_result.get("manifest_sha256"), str)
        or SHA256_RE.fullmatch(str(archive_result["manifest_sha256"])) is None
        or not isinstance(archive_result.get("source_tree_sha256"), str)
        or SHA256_RE.fullmatch(str(archive_result["source_tree_sha256"])) is None
        or type(archive_result.get("file_count")) is not int
        or int(archive_result["file_count"]) <= 0
        or type(archive_result.get("total_size")) is not int
        or int(archive_result["total_size"]) <= 0
    ):
        raise CaseStagingError("remote検証済みarchive結果をcleanup対象caseへ束縛できません")

    output = _validate_existing_directory(output_root, label="case staging output root")
    source = _absolute(source_path)
    _reject_reparse_components(source, label="owned case staging")
    if source.parent != output or source.name != target:
        raise CaseStagingError("cleanup対象がowned case staging境界外です")
    source = _validate_existing_directory(source, label="owned case staging")
    if source.parent != output or source.name != target:
        raise CaseStagingError("cleanup対象case stagingのidentityが変化しました")
    try:
        archive_files = archive_analysis_datastore.collect_source_files([source])
    except archive_analysis_datastore.DatastoreError as exc:
        raise CaseStagingError("owned case stagingをarchive sourceとして再検証できません") from exc
    source_records = [{"path": item.archive_name, "size": item.size, "sha256": item.sha256} for item in archive_files]
    if (
        archive_result.get("source_tree_sha256") != _inventory_sha256(source_records)
        or archive_result.get("file_count") != len(archive_files)
        or archive_result.get("total_size") != sum(item.size for item in archive_files)
    ):
        raise CaseStagingError("remote検証済みarchiveのsource tree commitmentがstagingと一致しません")

    staging_manifest, _manifest_sha256 = _read_json(
        source / STAGING_MANIFEST_NAME,
        label="case staging manifest",
    )
    files = staging_manifest.get("files")
    safety = staging_manifest.get("safety")
    if (
        staging_manifest.get("schema_version") != SCHEMA_VERSION
        or staging_manifest.get("target") != target
        or staging_manifest.get("collection_id") != collection_id
        or staging_manifest.get("case_sha256") != digest
        or not isinstance(files, list)
        or not isinstance(safety, Mapping)
        or safety.get("different_cases_included") is not False
        or safety.get("physical_copy_only") is not True
        or safety.get("sample_executed") is not False
        or safety.get("network_contacted") is not False
        or safety.get("source_deleted") is not False
    ):
        raise CaseStagingError("cleanup対象case staging manifestの境界または安全値が不正です")

    expected: dict[str, dict[str, Any]] = {}
    normalized_records: list[dict[str, Any]] = []
    for item in files:
        if not isinstance(item, Mapping) or set(item) != {"path", "role", "size", "sha256"}:
            raise CaseStagingError("case staging inventory itemが不正です")
        relative_value = item.get("path")
        role = item.get("role")
        size = item.get("size")
        file_sha256 = item.get("sha256")
        if (
            not isinstance(relative_value, str)
            or not relative_value
            or not isinstance(role, str)
            or not role
            or type(size) is not int
            or size < 0
            or not isinstance(file_sha256, str)
            or SHA256_RE.fullmatch(file_sha256) is None
        ):
            raise CaseStagingError("case staging inventoryの型またはhashが不正です")
        relative = PurePosixPath(relative_value)
        if (
            relative.is_absolute()
            or any(part in {"", ".", ".."} for part in relative.parts)
            or "\\" in relative_value
            or relative_value == STAGING_MANIFEST_NAME
        ):
            raise CaseStagingError("case staging inventoryに安全でない相対pathがあります")
        _reject_sensitive_name(relative)
        key = relative.as_posix().casefold()
        if key in expected:
            raise CaseStagingError("case staging inventoryの相対pathが重複しています")
        record = {
            "path": relative.as_posix(),
            "role": role,
            "size": size,
            "sha256": file_sha256,
        }
        expected[key] = record
        normalized_records.append(record)
    normalized_records.sort(key=lambda item: str(item["path"]).casefold())
    if (
        staging_manifest.get("file_count_excluding_this_manifest") != len(normalized_records)
        or staging_manifest.get("total_size_excluding_this_manifest")
        != sum(int(item["size"]) for item in normalized_records)
        or staging_manifest.get("file_inventory_sha256") != _inventory_sha256(normalized_records)
    ):
        raise CaseStagingError("case staging manifestのinventory commitmentが一致しません")

    observed: set[str] = set()
    for path, relative in _walk_files(source, role="owned case staging cleanup"):
        if relative.as_posix() == STAGING_MANIFEST_NAME:
            continue
        key = relative.as_posix().casefold()
        item = expected.get(key)
        if item is None or key in observed:
            raise CaseStagingError("owned case stagingに未束縛fileがあります")
        try:
            actual_sha256, actual_size, _identity = archive_analysis_datastore._hash_source_snapshot(path)
        except archive_analysis_datastore.DatastoreError as exc:
            raise CaseStagingError("owned case stagingをcleanup前に再検証できません") from exc
        if actual_size != item["size"] or actual_sha256 != item["sha256"]:
            raise CaseStagingError("owned case stagingがarchive検証後に変更されています")
        observed.add(key)
    if observed != set(expected):
        raise CaseStagingError("owned case stagingのfile集合がmanifestと一致しません")

    try:
        source_metadata = source.lstat()
    except OSError as exc:
        raise CaseStagingError("cleanup対象directory identityを固定できません") from exc
    if not stat.S_ISDIR(source_metadata.st_mode) or _is_reparse(source_metadata):
        raise CaseStagingError("cleanup対象が通常directoryではありません")
    source_identity = (source_metadata.st_dev, source_metadata.st_ino)

    tombstone = output / f".{digest[:12]}.{uuid.uuid4().hex[:12]}.verified-delete"
    if os.path.lexists(tombstone):
        raise CaseStagingError("owned staging cleanup用pathが既に存在します")
    try:
        os.replace(source, tombstone)
        _reject_reparse_components(tombstone, label="owned staging cleanup")
        tombstone_metadata = tombstone.lstat()
        if (
            not stat.S_ISDIR(tombstone_metadata.st_mode)
            or _is_reparse(tombstone_metadata)
            or (tombstone_metadata.st_dev, tombstone_metadata.st_ino)
            != source_identity
        ):
            raise CaseStagingError(
                f"cleanup昇格後directory identityが一致しません。保持path: {tombstone}"
            )
        try:
            tombstone_files = archive_analysis_datastore.collect_source_files(
                [tombstone]
            )
        except archive_analysis_datastore.DatastoreError as exc:
            raise CaseStagingError(
                f"cleanup昇格後treeを再検証できません。保持path: {tombstone}"
            ) from exc
        tombstone_prefix = f"data/{tombstone.name}/"
        canonical_prefix = f"data/{target}/"
        if any(
            not item.archive_name.startswith(tombstone_prefix)
            for item in tombstone_files
        ):
            raise CaseStagingError(
                f"cleanup昇格後archive pathを正規化できません。保持path: {tombstone}"
            )
        tombstone_records = [
            {
                "path": canonical_prefix + item.archive_name[len(tombstone_prefix) :],
                "size": item.size,
                "sha256": item.sha256,
            }
            for item in tombstone_files
        ]
        if (
            _inventory_sha256(tombstone_records)
            != archive_result["source_tree_sha256"]
            or len(tombstone_files) != archive_result["file_count"]
            or sum(item.size for item in tombstone_files)
            != archive_result["total_size"]
        ):
            raise CaseStagingError(
                f"cleanup昇格後tree commitmentが一致しません。保持path: {tombstone}"
            )
        shutil.rmtree(archive_analysis_datastore._extended_length_path(tombstone))
    except OSError as exc:
        raise CaseStagingError(f"検証済みowned stagingの削除に失敗しました。残存path: {tombstone}") from exc
    if os.path.lexists(source) or os.path.lexists(tombstone):
        raise CaseStagingError("検証済みowned stagingの削除完了を確認できません")
    return {
        "target": target,
        "case_sha256": digest,
        "removed": True,
        "source_deleted": False,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", required=True, type=Path)
    parser.add_argument("--collection-id", required=True)
    parser.add_argument("--source-root", required=True, type=Path)
    parser.add_argument("--one-shot-root", required=True, type=Path)
    parser.add_argument("--ghidra-root", required=True, type=Path)
    parser.add_argument("--output-root", required=True, type=Path)
    parser.add_argument(
        "--case-sha256",
        required=True,
        help="対象case。容量制御とcase分離のため1回につき1件だけ指定します",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    try:
        result = stage_cases(
            repository=arguments.repository,
            collection_id=arguments.collection_id,
            source_root=arguments.source_root,
            one_shot_root=arguments.one_shot_root,
            ghidra_root=arguments.ghidra_root,
            output_root=arguments.output_root,
            case_sha256s=[arguments.case_sha256],
        )
    except CaseStagingError as exc:
        print(
            json.dumps(
                {
                    "ok": False,
                    "error": {
                        "code": "case_datastore_staging_failed",
                        "message": str(exc),
                    },
                },
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 2
    print(
        json.dumps(
            result,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
            allow_nan=False,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
