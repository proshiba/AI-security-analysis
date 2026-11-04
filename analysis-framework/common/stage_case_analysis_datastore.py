#!/usr/bin/env python3
"""日次解析の非公開成果物を検体単位のdatastore入力へ安全に分離する。"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import sys
import uuid
from collections import Counter, defaultdict, deque
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from functools import cache
from pathlib import Path, PurePosixPath
from typing import Any

import archive_analysis_datastore
import build_malwarebazaar_job_requests as partitioner
import malwarebazaar_selection_contract as selection_contract

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
_EXPECTED_LINEAGE_UNSET = object()
MINIMUM_FREE_RESERVE_BYTES = 512 * 1024 * 1024
COPY_CHUNK_BYTES = 1024 * 1024
SCAN_OVERLAP_BYTES = 1024
FILE_ATTRIBUTE_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
STAGING_MANIFEST_NAME = "_case_staging_manifest.json"
SHARED_DERIVED_STAGING_SCHEMA_VERSION = (
    "analysis-datastore-externalized-shared-staging/v1"
)
SHARED_DERIVED_PROVENANCE_SCHEMA_VERSION = (
    "analysis-datastore-shared-derived-provenance/v1"
)
SHARED_DERIVED_REFERENCE_SCHEMA_VERSION = (
    "analysis-datastore-externalized-shared-reference/v1"
)

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
    sensitive_content_scanned: bool


@dataclass(frozen=True)
class CaseInputs:
    """1 caseへ帰属が固定された入力集合。"""

    case_sha256: str
    source_requested_sha256: str
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
    source_sidecar_commitments: Mapping[str, SourceCommitment]
    relationships_manifest: dict[str, Any]
    relationships_manifest_sha256: str
    validation_manifest: dict[str, Any]
    validation_manifest_sha256: str
    validation_programs: Mapping[str, dict[str, Any]]
    program_results: Mapping[str, dict[str, Any]]
    cases: Mapping[str, CaseInputs]


@dataclass(frozen=True)
class CaseStagingSession:
    """全体検証を1回だけ行い、case copyを逐次再照合するsession。"""

    inputs: ValidatedInputs
    requested_to_actual_case_sha256: Mapping[str, str]
    commitments: Mapping[str, SourceCommitment]
    projected_case_bytes: Mapping[str, int]
    observed_free_bytes_before_staging: int


@dataclass(frozen=True)
class OneShotLineage:
    """検証済みfollow-on graphをroot単位へ分離した契約。"""

    case_directories: Mapping[str, Path]
    materialized_case_states: Mapping[str, str]
    incomplete_case_states: Mapping[str, str]
    descendants_by_root: Mapping[str, tuple[str, ...]]
    incomplete_descendants_by_root: Mapping[str, tuple[str, ...]]
    edges_by_root: Mapping[str, tuple[dict[str, Any], ...]]
    unsafe_reasons_by_root: Mapping[str, tuple[str, ...]]
    graph_sha256: str | None
    graph_schema_version: Any


@dataclass(frozen=True)
class SharedDerivedStaging:
    """共有derivedを単独archiveへ渡すための検証済みstaging。"""

    child_sha256: str
    target: str
    source_path: Path
    source_tree_sha256: str
    file_count: int
    total_size: int
    provenance_sha256: str
    externalization_document_sha256: str


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
        current_io = archive_analysis_datastore._extended_length_path(current)
        if not os.path.lexists(current_io):
            break
        try:
            metadata = current_io.lstat()
        except OSError as exc:
            raise CaseStagingError(f"{label}のmetadataを確認できません") from exc
        if current_io.is_symlink() or _is_reparse(metadata):
            raise CaseStagingError(f"{label}にreparse pointは使用できません")


def _validate_existing_directory(path: Path, *, label: str) -> Path:
    absolute = _absolute(path)
    _reject_reparse_components(absolute, label=label)
    is_extended = os.name == "nt" and os.fspath(absolute).startswith("\\\\?\\")
    absolute_io = archive_analysis_datastore._extended_length_path(absolute)
    try:
        metadata = absolute_io.lstat()
    except OSError as exc:
        raise CaseStagingError(f"{label}を安全に確認できません") from exc
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or absolute_io.is_symlink()
        or _is_reparse(metadata)
    ):
        raise CaseStagingError(f"{label}は通常directoryである必要があります")
    return absolute_io if is_extended else absolute


def _prepare_output_root(path: Path, *, repository: Path, inputs: Sequence[Path]) -> Path:
    absolute = _absolute(path)
    _reject_reparse_components(absolute, label="case staging output root")
    ancestor = absolute
    while not os.path.lexists(archive_analysis_datastore._extended_length_path(ancestor)):
        if ancestor.parent == ancestor:
            raise CaseStagingError("case staging output rootの既存parentがありません")
        ancestor = ancestor.parent
    ancestor = _validate_existing_directory(ancestor, label="case staging output parent")
    prospective = ancestor.joinpath(*absolute.relative_to(ancestor).parts)
    if _is_within(prospective, repository):
        raise CaseStagingError("case staging outputをrepository内へ作成できません")
    if any(_is_within(prospective, item) or _is_within(item, prospective) for item in inputs):
        raise CaseStagingError("case staging outputを入力rootと重複させられません")
    created: list[tuple[Path, tuple[int, int]]] = []
    try:
        current = ancestor
        for part in prospective.relative_to(ancestor).parts:
            current_io = archive_analysis_datastore._extended_length_path(current)
            before = current_io.lstat()
            if not stat.S_ISDIR(before.st_mode) or _is_reparse(before):
                raise CaseStagingError("case staging output parentのidentityが不正です")
            child = current / part
            child_io = archive_analysis_datastore._extended_length_path(child)
            if os.path.lexists(child_io):
                child_metadata = child_io.lstat()
                if (
                    not stat.S_ISDIR(child_metadata.st_mode)
                    or child_io.is_symlink()
                    or _is_reparse(child_metadata)
                ):
                    raise CaseStagingError(
                        "case staging outputの既存componentが通常directoryではありません"
                    )
            else:
                os.mkdir(child_io)
                child_metadata = child_io.lstat()
                if not stat.S_ISDIR(child_metadata.st_mode) or _is_reparse(child_metadata):
                    raise CaseStagingError(
                        "case staging output componentを安全に作成できません"
                    )
                created.append(
                    (child, (child_metadata.st_dev, child_metadata.st_ino))
                )
            after = current_io.lstat()
            if (
                not stat.S_ISDIR(after.st_mode)
                or _is_reparse(after)
                or (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino)
            ):
                raise CaseStagingError(
                    "case staging output parentのidentityが作成中に変化しました"
                )
            current = child
    except OSError as exc:
        error: BaseException = CaseStagingError(
            "case staging output rootを作成できません"
        )
        error.__cause__ = exc
    except BaseException as exc:
        error = exc
    else:
        error = None
    if error is not None:
        cleanup_failed = False
        for created_path, expected_identity in reversed(created):
            created_io = archive_analysis_datastore._extended_length_path(created_path)
            try:
                metadata = created_io.lstat()
                if (
                    stat.S_ISDIR(metadata.st_mode)
                    and not _is_reparse(metadata)
                    and (metadata.st_dev, metadata.st_ino) == expected_identity
                ):
                    os.rmdir(created_io)
                else:
                    cleanup_failed = True
            except OSError:
                cleanup_failed = True
        if cleanup_failed:
            raise CaseStagingError(
                "case staging output root作成失敗後のowned componentを安全に削除できません"
            ) from error
        raise error
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


def _canonical_sha256(value: Any) -> str:
    """JSON値をselection側と同じcanonical形式でcommitする。"""

    payload = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


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
    # bare home（Windows既定の C:\Users\<name> など）は、検体の
    # build path、標的path、実コマンドラインにも現れるため、それだけで
    # 解析host由来と判定しない。現在のrepositoryと資格情報／daily private
    # rootを指す具体的なpathだけを漏えい候補として拒否する。
    home = Path.home()
    roots = {
        Path.cwd().resolve(),
        home / ".aws",
        home / ".codex",
        home / ".ssh",
        home / "DailyAnalysisPrivate",
        home / "DailyAnalysisWork",
        home / "DailyGhidraProjects",
    }
    candidates: set[bytes] = set()
    for root in roots:
        value = os.fspath(root)
        candidates.update(
            {
                value.encode("utf-8", errors="strict"),
                value.replace("\\", "\\\\").encode("utf-8", errors="strict"),
                value.encode("utf-16le", errors="strict"),
            }
        )
    return tuple(
        ("current_host_analysis_path", re.compile(re.escape(value), re.IGNORECASE)) for value in candidates if value
    )


def _scan_sensitive_content(data: bytes, *, relative: str) -> None:
    for rule, pattern in (*STATIC_SECRET_PATTERNS, *_host_path_patterns()):
        if pattern.search(data):
            raise CaseStagingError(f"staging対象に秘密値または不要なhost pathを検出しました: {relative} ({rule})")


def _is_verified_ghidra_import(relative: str) -> bool:
    """SHA-256拘束済みの解析対象PEだけを識別する。"""

    path = PurePosixPath(relative)
    if len(path.parts) != 3 or path.parts[:2] != ("ghidra", "import-staging"):
        return False
    name = path.name
    suffix = ".quarantine.bin"
    return name.endswith(suffix) and SHA256_RE.fullmatch(name[: -len(suffix)]) is not None


def _sensitive_content_scan_required(relative: str) -> bool:
    # 検体バイナリ自体には攻撃者が任意の秘密値形式やhost pathを埋め込める。
    # これをoperator情報の漏えいとして拒否すると誤検知になる。この除外は
    # _validate_inputsで内容SHA-256とrelationship集合を照合済みのGhidra
    # import-stagingだけに限定する。ファイル名スキャンは常に実施する。
    return not _is_verified_ghidra_import(relative)


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
    if commitment.sensitive_content_scanned != _sensitive_content_scan_required(relative):
        raise CaseStagingError(f"{role}の秘密値scan契約が出力先と一致しません")
    try:
        with archive_analysis_datastore._open_verified_source(
            source,
            expected=commitment.identity,
        ) as (stream, identity):
            with destination_io.open("xb") as output:
                while chunk := stream.read(COPY_CHUNK_BYTES):
                    if commitment.sensitive_content_scanned:
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
    if size != identity.st_size or size != commitment.size or digest.hexdigest() != commitment.sha256:
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
    if not _sensitive_content_scan_required(relative):
        return
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
    sensitive_content_scanned = _sensitive_content_scan_required(relative)
    try:
        with archive_analysis_datastore._open_verified_source(source) as (
            stream,
            identity,
        ):
            while chunk := stream.read(COPY_CHUNK_BYTES):
                if sensitive_content_scanned:
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
        sensitive_content_scanned=sensitive_content_scanned,
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


def _scan_staged_case_references(
    root: Path,
    *,
    case_sha256: str,
    allowed_case_sha256s: frozenset[str] | None = None,
) -> None:
    """派生後成果物のcase参照が対象rootと検証済み子孫だけであることを確認する。"""

    allowed = allowed_case_sha256s or frozenset({case_sha256})
    if case_sha256 not in allowed or any(SHA256_RE.fullmatch(value) is None for value in allowed):
        raise CaseStagingError("case参照scanの許可集合が不正です")

    for path, relative in _walk_files(root, role="case reference scan"):
        if _is_verified_ghidra_import(relative.as_posix()):
            continue
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
                        if observed not in allowed:
                            raise CaseStagingError(
                                f"case stagingに許可lineage外の明示的なcase_sha256参照があります: {relative.as_posix()}"
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
    files = list(_walk_files(source, role=role))
    source_absolute = _absolute(archive_analysis_datastore._extended_length_path(source))
    observed_keys = {_source_commitment_key(path) for path, _relative in files}
    expected_keys = {key for key, commitment in commitments.items() if _is_within(commitment.path, source_absolute)}
    if observed_keys != expected_keys:
        raise CaseStagingError(f"{role}のfile集合がpreflight commitmentから変更されました")
    copied: list[CopiedFile] = []
    for path, relative in files:
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


def _copy_tree_excluding(
    source: Path,
    destination: Path,
    *,
    staging_root: Path,
    role: str,
    commitments: Mapping[str, SourceCommitment],
    excluded_relative_paths: frozenset[str],
) -> list[CopiedFile]:
    """preflightで固定したfileだけを、exact相対path除外付きで物理copyする。"""

    normalized_exclusions: set[str] = set()
    for value in excluded_relative_paths:
        try:
            member = archive_analysis_datastore._validate_member_name(value)
        except archive_analysis_datastore.DatastoreError as exc:
            raise CaseStagingError(f"{role}の除外pathが安全な相対pathではありません") from exc
        normalized_exclusions.add(member)
    if len(normalized_exclusions) != len(excluded_relative_paths):
        raise CaseStagingError(f"{role}の除外pathが正規化後に重複しています")

    files = list(_walk_files(source, role=role))
    observed_by_relative = {relative.as_posix(): path for path, relative in files}
    if not normalized_exclusions.issubset(observed_by_relative):
        raise CaseStagingError(f"{role}の除外対象fileがexact source treeにありません")
    source_absolute = _absolute(archive_analysis_datastore._extended_length_path(source))
    observed_keys = {_source_commitment_key(path) for path, _relative in files}
    expected_keys = {
        key
        for key, commitment in commitments.items()
        if _is_within(commitment.path, source_absolute)
    }
    if observed_keys != expected_keys:
        raise CaseStagingError(f"{role}のfile集合がpreflight commitmentから変更されました")
    for relative in sorted(normalized_exclusions):
        _assert_source_commitment(
            observed_by_relative[relative],
            commitments=commitments,
            role=f"{role} excluded file",
        )

    copied: list[CopiedFile] = []
    for path, relative in files:
        if relative.as_posix() in normalized_exclusions:
            continue
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
        raise CaseStagingError(f"{role}は共有payload除外後に空になります")
    return copied


def _create_owned_staging_directory(
    output_root: Path,
    *,
    label: str,
) -> tuple[Path, tuple[int, int]]:
    """検証済み直親の下へWindows long path対応で排他directoryを作る。"""

    output = _validate_existing_directory(output_root, label="owned staging output root")
    candidate = output / f".candidate-{label[:16]}-{uuid.uuid4().hex[:12]}"
    output_io = archive_analysis_datastore._extended_length_path(output)
    candidate_io = archive_analysis_datastore._extended_length_path(candidate)
    before = output_io.lstat()
    if not stat.S_ISDIR(before.st_mode) or _is_reparse(before):
        raise CaseStagingError("owned staging output rootのidentityが不正です")
    if os.path.lexists(candidate_io):
        raise CaseStagingError("owned staging candidateが既に存在します")
    try:
        os.mkdir(candidate_io)
    except OSError as exc:
        raise CaseStagingError("owned staging candidateを排他作成できません") from exc
    after = output_io.lstat()
    if (
        not stat.S_ISDIR(after.st_mode)
        or _is_reparse(after)
        or (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino)
    ):
        raise CaseStagingError("owned staging parent identityが作成中に変更されました")
    validated = _validate_existing_directory(candidate_io, label="owned staging candidate")
    if validated.parent != output_io:
        raise CaseStagingError("owned staging candidateが検証済み直親から外れました")
    candidate_metadata = archive_analysis_datastore._extended_length_path(candidate).lstat()
    if not stat.S_ISDIR(candidate_metadata.st_mode) or _is_reparse(candidate_metadata):
        raise CaseStagingError("owned staging candidateのidentityが不正です")
    return candidate, (candidate_metadata.st_dev, candidate_metadata.st_ino)


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


def _write_generated_text(
    path: Path,
    value: str,
    *,
    staging_root: Path,
    role: str,
) -> CopiedFile:
    """日本語provenance文書を排他作成し、inventory commitmentを返す。"""

    relative = path.relative_to(staging_root).as_posix()
    _reject_sensitive_name(PurePosixPath(relative))
    payload = value.encode("utf-8")
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
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or path_io.is_symlink()
        or _is_reparse(metadata)
    ):
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


_FOLLOW_ON_NODE_STATES = frozenset(
    {
        "root",
        "queued",
        "analyzed",
        "resumed_complete",
        "timeout",
        "failed",
        "wall_clock_limit",
        "incomplete_case_omitted",
    }
)
_FOLLOW_ON_EDGE_STATUSES = frozenset(
    {
        "cycle_excluded",
        "depth_limit",
        "payload_size_limit",
        "shared_sha256_excluded",
        "shared_sha256_reused_complete",
        "shared_sha256_reused_incomplete",
        "artifact_count_limit",
        "total_bytes_limit",
        "child_complete",
        "child_incomplete",
    }
)
_FOLLOW_ON_ACTIVE_EDGE_STATUSES = frozenset({"child_complete", "child_incomplete"})
_FOLLOW_ON_SHARED_EDGE_STATUSES = frozenset({"shared_sha256_reused_complete", "shared_sha256_reused_incomplete"})
_FOLLOW_ON_MATERIALIZED_NODE_STATES = frozenset({"analyzed", "resumed_complete"})
_FOLLOW_ON_UNMATERIALIZED_NODE_STATES = frozenset({"timeout"})
_FOLLOW_ON_REJECTED_UNMATERIALIZED_NODE_STATES = frozenset(
    {"queued", "failed", "wall_clock_limit", "incomplete_case_omitted"}
)


def _validate_follow_on_edge_payload(
    *,
    case_directories: Mapping[str, Path],
    edge: Mapping[str, Any],
) -> None:
    """active/shared edgeのpayloadを親case内の通常fileへ束縛する。"""

    parent = str(edge["parent_sha256"])
    path_value = str(edge["path"])
    try:
        member = archive_analysis_datastore._validate_member_name(path_value)
    except archive_analysis_datastore.DatastoreError as exc:
        raise CaseStagingError("follow-on edge pathが安全な相対pathではありません") from exc
    parent_root = case_directories[parent]
    candidate = parent_root.joinpath(*PurePosixPath(member).parts)
    try:
        archive_analysis_datastore._reject_reparse_components(candidate)
    except archive_analysis_datastore.DatastoreError as exc:
        raise CaseStagingError("follow-on edge payload pathにreparse pointがあります") from exc
    candidate_io = archive_analysis_datastore._extended_length_path(candidate)
    try:
        metadata = candidate_io.lstat()
    except OSError as exc:
        raise CaseStagingError("follow-on edge payloadを親case内で確認できません") from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or candidate_io.is_symlink()
        or _is_reparse(metadata)
    ):
        raise CaseStagingError("follow-on edge payloadは親case内の独立した通常fileではありません")
    try:
        digest, size, _identity = archive_analysis_datastore._hash_source_snapshot(candidate_io)
    except archive_analysis_datastore.DatastoreError as exc:
        raise CaseStagingError("follow-on edge payloadを単一handleで照合できません") from exc
    if digest != edge["child_sha256"] or size != edge["size"]:
        raise CaseStagingError("follow-on edge payloadのsizeまたはSHA-256が一致しません")


def _validate_one_shot_lineage(
    one_shot_root: Path,
    *,
    source_case_sha256s: set[str],
) -> OneShotLineage:
    """run全体のfollow-on graphを検証し、root別の安全なlineageを算出する。"""

    cases_root = _validate_existing_directory(
        one_shot_root / "cases",
        label="one-shot cases root",
    )
    case_directories = _case_directories(cases_root, label="one-shot cases root")
    graph_path = one_shot_root / "follow-on-analysis.json"
    if not os.path.lexists(graph_path):
        if set(case_directories) != source_case_sha256s:
            raise CaseStagingError("derived caseがあるone-shot runにfollow-on-analysis.jsonがありません")
        return OneShotLineage(
            case_directories=case_directories,
            materialized_case_states={},
            incomplete_case_states={},
            descendants_by_root={digest: () for digest in sorted(source_case_sha256s)},
            incomplete_descendants_by_root={
                digest: () for digest in sorted(source_case_sha256s)
            },
            edges_by_root={digest: () for digest in sorted(source_case_sha256s)},
            unsafe_reasons_by_root={digest: () for digest in sorted(source_case_sha256s)},
            graph_sha256=None,
            graph_schema_version=None,
        )

    graph, graph_sha256 = _read_json(graph_path, label="one-shot follow-on analysis")
    roots_raw = graph.get("roots")
    nodes_raw = graph.get("nodes")
    edges_raw = graph.get("edges")
    if (
        graph.get("schema_version") != 1
        or graph.get("status")
        not in {"complete", "partial", "no_retained_payloads"}
        or graph.get("executed_sample") is not False
        or graph.get("network_contacted") is not False
        or graph.get("ai_used") not in (False, None)
        or not isinstance(roots_raw, list)
        or not isinstance(nodes_raw, list)
        or not isinstance(edges_raw, list)
        or len(nodes_raw) > MAX_CASES
        or len(edges_raw) > MAX_RELATIONSHIPS
    ):
        raise CaseStagingError("follow-on graphのschemaまたは安全契約が不正です")
    roots = [_validate_sha256(value, label="follow-on root") for value in roots_raw]
    if len(roots) != len(set(roots)) or set(roots) != source_case_sha256s:
        raise CaseStagingError("follow-on root集合がsource case集合と一致しません")

    nodes: dict[str, dict[str, Any]] = {}
    for raw in nodes_raw:
        if not isinstance(raw, Mapping):
            raise CaseStagingError("follow-on nodeがobjectではありません")
        digest = _validate_sha256(raw.get("sha256"), label="follow-on node.sha256")
        depth = raw.get("depth")
        state = raw.get("state")
        if digest in nodes or type(depth) is not int or not 0 <= depth <= 64 or state not in _FOLLOW_ON_NODE_STATES:
            raise CaseStagingError("follow-on nodeの型、状態または重複が不正です")
        case_state = raw.get("case_state")
        if state in _FOLLOW_ON_MATERIALIZED_NODE_STATES and case_state not in {
            "complete",
            "partial",
        }:
            raise CaseStagingError("materialized follow-on nodeのcase状態が不正です")
        if state in _FOLLOW_ON_REJECTED_UNMATERIALIZED_NODE_STATES:
            raise CaseStagingError(
                "evidence-only follow-on nodeはtimeout状態だけを許可します"
            )
        if (
            state in _FOLLOW_ON_UNMATERIALIZED_NODE_STATES
            and case_state is not None
        ):
            raise CaseStagingError(
                "evidence-only timeout nodeにcase_stateは許可しません"
            )
        nodes[digest] = {
            "sha256": digest,
            "depth": depth,
            "state": state,
            "case_state": case_state,
        }
    if not set(roots).issubset(nodes):
        raise CaseStagingError("follow-on root nodeが不足しています")
    expected_case_directories = set(roots) | {
        digest
        for digest, node in nodes.items()
        if node["state"] in _FOLLOW_ON_MATERIALIZED_NODE_STATES
    }
    if expected_case_directories != set(case_directories):
        raise CaseStagingError(
            "follow-on materialized node集合とone-shot case directory集合が一致しません"
        )
    if any(
        nodes[root]
        != {
            "sha256": root,
            "depth": 0,
            "state": "root",
            "case_state": None,
        }
        for root in roots
    ):
        raise CaseStagingError("follow-on root nodeのdepthまたはstateが不正です")
    if any(nodes[digest]["depth"] == 0 for digest in set(nodes) - set(roots)):
        raise CaseStagingError("derived nodeのdepthが0です")

    edges: list[dict[str, Any]] = []
    identities: set[tuple[Any, ...]] = set()
    for raw in edges_raw:
        if not isinstance(raw, Mapping):
            raise CaseStagingError("follow-on edgeがobjectではありません")
        parent = _validate_sha256(raw.get("parent_sha256"), label="follow-on edge.parent_sha256")
        child = _validate_sha256(raw.get("child_sha256"), label="follow-on edge.child_sha256")
        depth = raw.get("depth")
        size = raw.get("size")
        status = raw.get("status")
        path_value = raw.get("path")
        role = raw.get("role")
        kind = raw.get("kind")
        if (
            parent not in nodes
            or type(depth) is not int
            or not 1 <= depth <= 64
            or type(size) is not int
            or size <= 0
            or status not in _FOLLOW_ON_EDGE_STATUSES
            or not isinstance(path_value, str)
            or not path_value
            or not isinstance(role, str)
            or not role
            or not isinstance(kind, str)
            or not kind
        ):
            raise CaseStagingError("follow-on edgeの型、状態または参照が不正です")
        active_or_shared = status in (_FOLLOW_ON_ACTIVE_EDGE_STATUSES | _FOLLOW_ON_SHARED_EDGE_STATUSES)
        if active_or_shared and child not in nodes:
            raise CaseStagingError("active/shared follow-on edgeが未知nodeを参照しています")
        if active_or_shared and parent not in case_directories:
            raise CaseStagingError(
                "active/shared follow-on edgeの親nodeがmaterialized caseではありません"
            )
        if status in _FOLLOW_ON_ACTIVE_EDGE_STATUSES and (
            child in roots or nodes[child]["depth"] != nodes[parent]["depth"] + 1 or depth != nodes[child]["depth"]
        ):
            raise CaseStagingError("active follow-on edgeのdepthまたはroot境界が不正です")
        if child not in roots and status in {
            "child_complete",
            "shared_sha256_reused_complete",
        } and (
            nodes[child]["state"] not in _FOLLOW_ON_MATERIALIZED_NODE_STATES
            or nodes[child]["case_state"] != "complete"
        ):
            raise CaseStagingError("complete follow-on edgeのnode状態が不正です")
        if child not in roots and status in {
            "child_incomplete",
            "shared_sha256_reused_incomplete",
        } and (
            nodes[child]["state"] in _FOLLOW_ON_MATERIALIZED_NODE_STATES
            and nodes[child]["case_state"] == "complete"
        ):
            raise CaseStagingError("incomplete follow-on edgeのnode状態が不正です")
        edge = {
            "parent_sha256": parent,
            "child_sha256": child,
            "depth": depth,
            "path": path_value,
            "role": role,
            "kind": kind,
            "size": size,
            "status": status,
        }
        identity = tuple(edge[key] for key in sorted(edge))
        if identity in identities:
            raise CaseStagingError("follow-on edgeに重複があります")
        identities.add(identity)
        edges.append(edge)
        if active_or_shared:
            _validate_follow_on_edge_payload(case_directories=case_directories, edge=edge)

    outgoing: dict[str, list[dict[str, Any]]] = defaultdict(list)
    active_incoming: dict[str, list[str]] = defaultdict(list)
    for edge in edges:
        outgoing[edge["parent_sha256"]].append(edge)
        if edge["status"] in _FOLLOW_ON_ACTIVE_EDGE_STATUSES:
            active_incoming[edge["child_sha256"]].append(edge["parent_sha256"])
    for child in set(nodes) - set(roots):
        if len(active_incoming.get(child, [])) != 1:
            raise CaseStagingError("derived nodeのactive parentが一意ではありません")

    graph_status = str(graph["status"])
    derived_nodes = set(nodes) - set(roots)
    partial_or_incomplete_derived = any(
        node["case_state"] == "partial"
        or node["state"] in _FOLLOW_ON_UNMATERIALIZED_NODE_STATES
        for digest, node in nodes.items()
        if digest in derived_nodes
    )
    if partial_or_incomplete_derived and graph_status != "partial":
        raise CaseStagingError(
            "partial／incomplete derived nodeにはpartial follow-on graphが必要です"
        )
    if graph_status == "complete" and (
        not edges
        or any(
            edge["status"]
            not in {"child_complete", "shared_sha256_reused_complete"}
            for edge in edges
        )
    ):
        raise CaseStagingError("complete follow-on graphに未完了edgeがあります")
    if graph_status == "no_retained_payloads" and (derived_nodes or edges):
        raise CaseStagingError(
            "no_retained_payloads graphにderived nodeまたはedgeがあります"
        )

    descendants_by_root: dict[str, tuple[str, ...]] = {}
    incomplete_descendants_by_root: dict[str, tuple[str, ...]] = {}
    lineage_nodes_by_root: dict[str, tuple[str, ...]] = {}
    owners: dict[str, set[str]] = defaultdict(set)
    for root in sorted(roots):
        observed: set[str] = set()
        queue: deque[str] = deque([root])
        while queue:
            parent = queue.popleft()
            if parent in observed:
                raise CaseStagingError("follow-on active graphにcycleがあります")
            observed.add(parent)
            owners[parent].add(root)
            for edge in outgoing.get(parent, []):
                if edge["status"] in _FOLLOW_ON_ACTIVE_EDGE_STATUSES:
                    queue.append(edge["child_sha256"])
        lineage_nodes = tuple(
            sorted(
                observed - {root},
                key=lambda value: (nodes[value]["depth"], value),
            )
        )
        lineage_nodes_by_root[root] = lineage_nodes
        descendants_by_root[root] = tuple(
            value
            for value in lineage_nodes
            if nodes[value]["state"] in _FOLLOW_ON_MATERIALIZED_NODE_STATES
        )
        incomplete_descendants_by_root[root] = tuple(
            value
            for value in lineage_nodes
            if nodes[value]["state"] in _FOLLOW_ON_UNMATERIALIZED_NODE_STATES
        )
    if any(not owners.get(digest) for digest in set(nodes) - set(roots)):
        raise CaseStagingError("rootから到達できないorphan derived nodeがあります")

    unsafe: dict[str, set[str]] = {root: set() for root in roots}
    edges_by_root: dict[str, tuple[dict[str, Any], ...]] = {}
    for root in sorted(roots):
        lineage = {root, *lineage_nodes_by_root[root]}
        selected_edges = [edge for edge in edges if edge["parent_sha256"] in lineage]
        for edge in selected_edges:
            status = edge["status"]
            if status == "child_incomplete":
                unsafe[root].add("derived_child_incomplete")
            elif status in _FOLLOW_ON_SHARED_EDGE_STATUSES:
                unsafe[root].add("shared_or_cross_root_child")
                for other in owners.get(edge["child_sha256"], set()):
                    unsafe[other].add("shared_or_cross_root_child")
            elif status != "child_complete":
                unsafe[root].add(f"excluded_edge:{status}")
        edges_by_root[root] = tuple(
            sorted(
                selected_edges,
                key=lambda item: (
                    int(item["depth"]),
                    str(item["parent_sha256"]),
                    str(item["child_sha256"]),
                    str(item["path"]),
                ),
            )
        )

    errors = graph.get("errors")
    omitted = graph.get("omitted_metadata")
    commitments = graph.get("omitted_metadata_commitments")
    if errors not in (None, []):
        for root in roots:
            unsafe[root].add("follow_on_errors_present")
    if commitments not in (None, []):
        for root in roots:
            unsafe[root].add("unattributed_omission_commitment")
    if omitted not in (None, []):
        if not isinstance(omitted, list):
            raise CaseStagingError("follow-on omitted_metadataがlistではありません")
        for item in omitted:
            if not isinstance(item, Mapping):
                raise CaseStagingError("follow-on omitted metadata itemがobjectではありません")
            parent = item.get("parent_sha256")
            if parent in owners:
                for root in owners[str(parent)]:
                    unsafe[root].add("omitted_follow_on_metadata")
            else:
                for root in roots:
                    unsafe[root].add("unattributed_omitted_metadata")
    if graph.get("wall_clock_exhausted") is True:
        for root in roots:
            unsafe[root].add("follow_on_wall_clock_exhausted")

    return OneShotLineage(
        case_directories=case_directories,
        materialized_case_states={
            digest: str(node["case_state"])
            for digest, node in sorted(nodes.items())
            if node["state"] in _FOLLOW_ON_MATERIALIZED_NODE_STATES
        },
        incomplete_case_states={
            digest: str(node["state"])
            for digest, node in sorted(nodes.items())
            if node["state"] in _FOLLOW_ON_UNMATERIALIZED_NODE_STATES
        },
        descendants_by_root=descendants_by_root,
        incomplete_descendants_by_root=incomplete_descendants_by_root,
        edges_by_root=edges_by_root,
        unsafe_reasons_by_root={root: tuple(sorted(reasons)) for root, reasons in sorted(unsafe.items())},
        graph_sha256=graph_sha256,
        graph_schema_version=graph.get("schema_version"),
    )


def build_follow_on_lineage_case_document(
    lineage: OneShotLineage,
    *,
    collection_id: str,
    case_sha256: str,
) -> dict[str, Any] | None:
    """live graphからroot別の決定的なfollow-on lineage文書を構築する。"""

    if COLLECTION_RE.fullmatch(collection_id) is None:
        raise CaseStagingError("follow-on lineageのcollection IDが不正です")
    digest = _validate_sha256(case_sha256, label="follow-on lineage case SHA-256")
    if digest not in lineage.descendants_by_root:
        raise CaseStagingError("follow-on lineageに指定rootがありません")
    if lineage.graph_sha256 is None:
        return None
    derived = lineage.descendants_by_root[digest]
    incomplete = lineage.incomplete_descendants_by_root[digest]
    derived_states = {
        value: lineage.materialized_case_states[value] for value in derived
    }
    state_counts = {
        state: sum(value == state for value in derived_states.values())
        for state in ("complete", "partial")
    }
    return {
        "schema_version": "analysis-datastore-case-follow-on-lineage/v1",
        "source_schema_version": lineage.graph_schema_version,
        "source_follow_on_sha256": lineage.graph_sha256,
        "collection_id": collection_id,
        "case_sha256": digest,
        "derived_case_sha256s": list(derived),
        "derived_case_states": dict(sorted(derived_states.items())),
        "derived_case_state_counts": state_counts,
        "incomplete_derived_case_sha256s": list(incomplete),
        "incomplete_derived_case_states": {
            value: lineage.incomplete_case_states[value] for value in incomplete
        },
        "edges": [dict(edge) for edge in lineage.edges_by_root[digest]],
        "safety": {
            "different_root_cases_included": False,
            "incomplete_derived_cases_included": False,
            "incomplete_follow_on_evidence_present": bool(incomplete),
            "sample_executed": False,
            "network_contacted": False,
        },
    }


def _shared_derived_target(collection_id: str, child_sha256: str) -> str:
    """collection衝突を避けた128文字以内の共有derived targetを返す。"""

    if COLLECTION_RE.fullmatch(collection_id) is None:
        raise CaseStagingError("共有derivedのcollection IDが不正です")
    digest = _validate_sha256(child_sha256, label="共有derived child SHA-256")
    collection_commitment = hashlib.sha256(collection_id.encode("utf-8")).hexdigest()[:16]
    target = f"shared-derived-{collection_commitment}-{digest}"
    try:
        return archive_analysis_datastore.validate_target(target)
    except archive_analysis_datastore.DatastoreError as exc:
        raise CaseStagingError("共有derived datastore targetを安全に構成できません") from exc


def build_shared_derived_externalization_documents(
    lineage: OneShotLineage,
    *,
    collection_id: str,
    allow_partial_derived_cases: bool,
) -> dict[str, dict[str, Any]]:
    """共有derived leafを一意なowner／edge集合へ固定する。

    既定のroot staging拒否はこの関数だけでは解除しない。返した文書をshared
    archiveへ先にstageし、remote receiptを再検証した呼出し側だけがrootから
    bytesを外部分離できる。
    """

    if type(allow_partial_derived_cases) is not bool:
        raise CaseStagingError("共有derived partial許可値はbooleanである必要があります")
    if COLLECTION_RE.fullmatch(collection_id) is None:
        raise CaseStagingError("共有derivedのcollection IDが不正です")
    if lineage.graph_sha256 is None:
        return {}

    edge_owner_pairs: list[tuple[str, dict[str, Any]]] = []
    all_edges: dict[tuple[Any, ...], dict[str, Any]] = {}
    shared_children: set[str] = set()
    for owner_root, raw_edges in sorted(lineage.edges_by_root.items()):
        owner = _validate_sha256(owner_root, label="共有derived owner root")
        for raw_edge in raw_edges:
            edge = dict(raw_edge)
            identity = tuple(edge[key] for key in sorted(edge))
            all_edges[identity] = edge
            if edge["status"] in _FOLLOW_ON_SHARED_EDGE_STATUSES:
                shared_children.add(str(edge["child_sha256"]))
            edge_owner_pairs.append((owner, edge))

    documents: dict[str, dict[str, Any]] = {}
    for child in sorted(shared_children):
        child = _validate_sha256(child, label="共有derived child")
        incoming_by_identity: dict[tuple[Any, ...], dict[str, Any]] = {}
        owners_by_identity: dict[tuple[Any, ...], set[str]] = defaultdict(set)
        for owner, edge in edge_owner_pairs:
            if edge["child_sha256"] != child:
                continue
            identity = tuple(edge[key] for key in sorted(edge))
            incoming_by_identity[identity] = edge
            owners_by_identity[identity].add(owner)
        incoming = list(incoming_by_identity.values())
        active = [edge for edge in incoming if edge["status"] in _FOLLOW_ON_ACTIVE_EDGE_STATUSES]
        shared = [edge for edge in incoming if edge["status"] in _FOLLOW_ON_SHARED_EDGE_STATUSES]
        if len(active) != 1 or not shared:
            raise CaseStagingError("共有derived childのactive/shared edge集合が一意ではありません")
        if child not in lineage.case_directories or child not in lineage.materialized_case_states:
            raise CaseStagingError("共有derived childがmaterialized caseへ束縛されていません")
        if any(
            edge["parent_sha256"] == child
            and edge["status"] in (_FOLLOW_ON_ACTIVE_EDGE_STATUSES | _FOLLOW_ON_SHARED_EDGE_STATUSES)
            for edge in all_edges.values()
        ):
            raise CaseStagingError("共有derived childがleafではないため外部分離できません")

        owner_edges: list[dict[str, Any]] = []
        observed_owners: set[str] = set()
        for identity, edge in incoming_by_identity.items():
            edge_owners = owners_by_identity[identity]
            if len(edge_owners) != 1:
                raise CaseStagingError("共有derived edgeが複数root lineageへ重複しています")
            owner = next(iter(edge_owners))
            if owner in observed_owners:
                raise CaseStagingError("共有derived ownerに複数のincoming edgeがあります")
            observed_owners.add(owner)
            owner_edges.append({"owner_root_sha256": owner, **edge})
        if len(owner_edges) != len(incoming) or len(observed_owners) < 2:
            raise CaseStagingError("共有derived owner／edge集合が一対一ではありません")

        case_state = lineage.materialized_case_states[child]
        expected_active = "child_complete" if case_state == "complete" else "child_incomplete"
        expected_shared = (
            "shared_sha256_reused_complete"
            if case_state == "complete"
            else "shared_sha256_reused_incomplete"
        )
        if active[0]["status"] != expected_active or any(
            edge["status"] != expected_shared for edge in shared
        ):
            raise CaseStagingError("共有derived edge状態とsealed child状態が一致しません")
        if case_state == "partial" and not allow_partial_derived_cases:
            raise CaseStagingError("partial共有derivedの外部分離には明示的な許可が必要です")
        payload_sizes = {int(edge["size"]) for edge in incoming}
        if len(payload_sizes) != 1:
            raise CaseStagingError("共有derived payload copyのsizeが競合しています")

        ordered_owners = sorted(observed_owners)
        ordered_edges = sorted(
            owner_edges,
            key=lambda item: (
                str(item["owner_root_sha256"]),
                str(item["parent_sha256"]),
                str(item["path"]),
                str(item["status"]),
            ),
        )
        owner_set_commitment = _canonical_sha256(ordered_owners)
        edge_set_commitment = _canonical_sha256(ordered_edges)
        document = {
            "schema_version": SHARED_DERIVED_PROVENANCE_SCHEMA_VERSION,
            "collection_id": collection_id,
            "target": _shared_derived_target(collection_id, child),
            "child_sha256": child,
            "child_case_state": case_state,
            "source_follow_on_sha256": lineage.graph_sha256,
            "source_schema_version": lineage.graph_schema_version,
            "owners": ordered_owners,
            "owner_set_commitment_sha256": owner_set_commitment,
            "owner_edges": ordered_edges,
            "edge_set_commitment_sha256": edge_set_commitment,
            "canonical_parent_sha256": str(active[0]["parent_sha256"]),
            "payload_size": next(iter(payload_sizes)),
            "payload_copy_count": len(ordered_edges),
            "partial_policy": {
                "allow_partial_derived_cases": allow_partial_derived_cases,
                "child_case_state": case_state,
            },
            "safety": {
                "child_is_leaf": True,
                "payload_copies_sha256_verified": True,
                "root_sources_included": False,
                "root_analysis_included": False,
                "sample_executed": False,
                "network_contacted": False,
                "source_deleted": False,
            },
        }
        documents[child] = document
    return documents


def _shared_children_for_root(
    documents: Mapping[str, Mapping[str, Any]],
    *,
    root_sha256: str,
) -> tuple[str, ...]:
    """検証済みexternalization文書からrootが参照するchild集合を返す。"""

    digest = _validate_sha256(root_sha256, label="共有derived参照root")
    return tuple(
        sorted(
            child
            for child, document in documents.items()
            if digest in document.get("owners", [])
        )
    )


def _validate_exclusion_set(
    document: Mapping[str, Any],
    *,
    source_manifest: Mapping[str, Any],
    selected_sha256s: set[str],
) -> None:
    """非公開除外集合の内容を検証し、raw内容のcase混入を防ぐ。"""

    identities = document.get("identities")
    if (
        document.get("schema_version") != 1
        or document.get("identity_type") != "sha256"
        or type(document.get("identity_count")) is not int
        or not isinstance(identities, list)
        or len(identities) > MAX_RELATIONSHIPS
        or document["identity_count"] != len(identities)
        or document.get("classification") != "private"
        or document.get("contains_sample_sha256") is not True
        or document.get("publishable") is not False
    ):
        raise CaseStagingError("exclusion-set.jsonの非公開除外集合契約が不正です")
    normalized = [_validate_sha256(value, label="exclusion-set.json identities item") for value in identities]
    if normalized != sorted(normalized) or len(set(normalized)) != len(normalized):
        raise CaseStagingError("exclusion-set.jsonのidentitiesは一意な昇順SHA-256である必要があります")
    excluded_sha256 = _validate_sha256(
        document.get("excluded_hashes_sha256"),
        label="exclusion-set.json excluded_hashes_sha256",
    )
    selection_sha256 = _validate_sha256(
        document.get("selection_commitment_sha256"),
        label="exclusion-set.json selection_commitment_sha256",
    )
    if excluded_sha256 != _canonical_sha256(normalized):
        raise CaseStagingError("exclusion-set.jsonの除外集合commitmentが一致しません")
    if (
        type(source_manifest.get("excluded_hashes")) is not int
        or source_manifest.get("excluded_hashes") != len(normalized)
        or source_manifest.get("excluded_hashes_sha256") != excluded_sha256
        or source_manifest.get("selection_commitment_sha256") != selection_sha256
    ):
        raise CaseStagingError("source manifestとexclusion-set.jsonのcommitmentが一致しません")
    if selected_sha256s & set(normalized):
        raise CaseStagingError("選定caseがexclusion-set.jsonの除外集合と重複しています")


def _validate_source_sidecars(
    source_root: Path,
    *,
    source_manifest: Mapping[str, Any],
    selected_sha256s: set[str],
) -> dict[str, SourceCommitment]:
    """source共通sidecarを検証し、copyしないcommitmentへ固定する。"""

    commitments: dict[str, SourceCommitment] = {}
    for name in ("exclusion-set.json", "family-hints.json"):
        path = source_root / name
        if not os.path.lexists(path):
            continue
        document, document_sha256 = _read_json(path, label=f"source sidecar {name}")
        if name == "exclusion-set.json":
            _validate_exclusion_set(
                document,
                source_manifest=source_manifest,
                selected_sha256s=selected_sha256s,
            )
        commitment = _snapshot_source_commitment(
            path,
            relative=f"source-sidecar/{name}",
        )
        if commitment.sha256 != document_sha256:
            raise CaseStagingError(f"source sidecar {name}が検証中に変更されました")
        commitments[name] = commitment
    return commitments


def _validate_runtime_request_sidecar(
    source_root: Path,
    *,
    selected_sha256s: Sequence[str],
) -> None:
    """再解析用requestをraw非収録のruntime metadataとして検証する。"""

    path = source_root / "request-improved.json"
    if not os.path.lexists(path):
        return
    document, _document_sha256 = _read_json(path, label="source runtime request")
    options = document.get("options")
    request_inputs = document.get("inputs")
    allowed_option_keys = {
        "archive_mode",
        "assessment_only",
        "family",
        "force_container_probe",
        "max_file_size",
        "max_files",
        "max_static_layers",
        "minimum_confidence",
        "retry_max_static_layers",
        "string_scan_limit",
    }
    if (
        document.get("schema_version") != 1
        or not isinstance(document.get("job_id"), str)
        or not document["job_id"]
        or not isinstance(request_inputs, list)
        or len(request_inputs) != len(selected_sha256s)
        or len(set(request_inputs)) != len(request_inputs)
        or set(request_inputs) != set(selected_sha256s)
        or document.get("family_hint_manifest") not in (None, "family-hints.json")
        or not isinstance(options, Mapping)
        or set(options) != allowed_option_keys
        or options.get("archive_mode") != "malwarebazaar"
        or options.get("assessment_only") is not False
        or options.get("force_container_probe") is not False
    ):
        raise CaseStagingError("source runtime requestの静的・非実行契約が不正です")


def _validate_source_manifest(
    source_root: Path,
) -> tuple[
    dict[str, Any],
    str,
    dict[str, Path],
    dict[str, SourceCommitment],
]:
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
    try:
        fixed_selection = partitioner.validate_fixed_selection(manifest)
        selection_contract.validate_item_metadata_binding(
            manifest,
            expected_hashes=fixed_selection.hashes,
        )
    except (
        partitioner.PartitionContractError,
        selection_contract.SelectionMetadataContractError,
    ) as exc:
        raise CaseStagingError(f"source manifestの固定選定metadata契約が不正です: {exc}") from exc
    if tuple(selected_values) != fixed_selection.hashes:
        raise CaseStagingError("source manifestの固定選定順序が一致しません")
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
        allowed_noncase_files=frozenset(
            {
                "manifest.json",
                "family-hints.json",
                "exclusion-set.json",
                "request-improved.json",
            }
        ),
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
    _validate_runtime_request_sidecar(
        source_root,
        selected_sha256s=selected_values,
    )
    sidecar_commitments = _validate_source_sidecars(
        source_root,
        source_manifest=manifest,
        selected_sha256s=selected_set,
    )
    return manifest, manifest_sha256, case_directories, sidecar_commitments


def _validated_case_source_bindings(
    *,
    repository: Path,
    collection_id: str,
    source_manifest: Mapping[str, Any],
    source_cases: Mapping[str, Path],
    one_shot_cases: Mapping[str, Path],
) -> dict[str, str]:
    """取得時のprovider要求hashと実測case hashを公開済み証拠へ束縛する。"""

    bindings = {digest: digest for digest in set(source_cases) & set(one_shot_cases)}
    source_only = set(source_cases) - set(one_shot_cases)
    one_shot_only = set(one_shot_cases) - set(source_cases)
    if not source_only and not one_shot_only:
        return bindings
    public, _digest = _read_json(
        repository / "analysis-results" / "collections" / collection_id / "manifest.json",
        label="公開collection manifest",
    )
    items = public.get("acquisition_items")
    if public.get("collection_id") != collection_id or not isinstance(items, list):
        raise CaseStagingError("provider hash不一致の公開collection bindingがありません")
    private_items = {item["sha256"]: item for item in source_manifest["items"] if isinstance(item, Mapping)}
    for item in items:
        if not isinstance(item, Mapping):
            raise CaseStagingError("公開collection acquisition itemが不正です")
        actual = item.get("sha256")
        requested = item.get("provider_requested_sha256")
        if requested not in source_only or actual not in one_shot_only:
            continue
        integrity = item.get("source_integrity")
        metadata = item.get("metadata")
        reported = item.get("provider_reported_metadata")
        private = private_items.get(requested)
        if (
            not isinstance(actual, str)
            or SHA256_RE.fullmatch(actual) is None
            or not isinstance(requested, str)
            or SHA256_RE.fullmatch(requested) is None
            or not isinstance(integrity, Mapping)
            or integrity.get("status") != "provider_requested_sha256_mismatch"
            or integrity.get("provider_requested_sha256") != requested
            or integrity.get("analyzed_member_sha256") != actual
            or integrity.get("archive_sha256") != item.get("zip_sha256")
            or integrity.get("archive_size") != item.get("zip_size")
            or integrity.get("provider_metadata_used_for_family_attribution") is not False
            or not isinstance(metadata, Mapping)
            or metadata.get("sha256_hash") != actual
            or not isinstance(reported, Mapping)
            or reported.get("sha256_hash") != requested
            or not isinstance(private, Mapping)
            or private.get("zip_sha256") != item.get("zip_sha256")
            or private.get("zip_size") != item.get("zip_size")
            or not isinstance(private.get("metadata"), Mapping)
            or private["metadata"].get("sha256_hash") != requested
        ):
            raise CaseStagingError("provider hash不一致のarchive bindingが不正です")
        report, _report_digest = _read_json(
            one_shot_cases[actual] / "report.json",
            label="provider hash不一致のone-shot report",
        )
        sample = report.get("sample")
        if (
            not isinstance(sample, Mapping)
            or sample.get("sha256") != actual
            or sample.get("input_kind") != "authenticated_single_member_zip"
            or sample.get("outer_sha256") != item.get("zip_sha256")
            or sample.get("outer_size") != item.get("zip_size")
            or sample.get("member_name") != integrity.get("member_name")
            or not isinstance(sample.get("member_name"), str)
            or "/" in sample["member_name"].replace("\\", "/")
        ):
            raise CaseStagingError("provider hash不一致のone-shot証拠が不整合です")
        if actual in bindings:
            raise CaseStagingError("provider hash不一致のcase bindingが重複しています")
        bindings[actual] = requested
    if set(bindings) != set(one_shot_cases) or set(bindings.values()) != set(source_cases):
        raise CaseStagingError("sourceとone-shotのcase集合が一致しません")
    return bindings


def _validate_one_shot_report_identity(case_directory: Path, *, digest: str) -> None:
    """one-shot report内の全case identity表現を対象directoryへ束縛する。"""

    report, _report_sha256 = _read_json(
        case_directory / "report.json",
        label="one-shot report",
    )
    authoritative: list[str] = []

    root_sha256 = report.get("sha256")
    if root_sha256 is not None:
        authoritative.append(_validate_sha256(root_sha256, label="one-shot report.sha256"))
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
        raise CaseStagingError("one-shot reportを対象case SHA-256へ束縛できないか、他caseを参照しています")

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
                    raise CaseStagingError("one-shot reportに他caseのsample.sha256があります")
            for key, child in value.items():
                if key in REPORT_CASE_IDENTITY_KEYS:
                    observed = _validate_sha256(
                        child,
                        label=f"{location}.{key}",
                    )
                    if observed != digest:
                        raise CaseStagingError(f"one-shot reportに他caseの{key}があります")
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
                        raise CaseStagingError("one-shot reportに他caseのsample_sha256sがあります")
                pending.append((child, f"{location}.{key}"))
        elif isinstance(value, list):
            pending.extend((child, f"{location}[{index}]") for index, child in enumerate(value))


def _validate_one_shot_report_safety(case_directory: Path) -> dict[str, Any]:
    """Ghidra非要求経路でone-shot reportの非実行契約を確認する。"""

    report, _report_sha256 = _read_json(
        case_directory / "report.json",
        label="one-shot report safety",
    )
    execution_fields = [field for field in ("executed_sample", "sample_executed") if field in report]
    if not execution_fields or any(report[field] is not False for field in execution_fields):
        raise CaseStagingError("Ghidra非要求経路のone-shot reportがsample非実行を明示していません")
    if report.get("network_contacted") is not False:
        raise CaseStagingError("Ghidra非要求経路のone-shot reportがnetwork非接触を明示していません")
    ai_used = report.get("ai_used")
    if ai_used is not False and ai_used is not None:
        raise CaseStagingError("Ghidra非要求経路のone-shot reportでAI利用が記録されています")
    return {
        "sample_executed": False,
        "network_contacted": False,
        "ai_used": ai_used,
        "one_shot_report_safety_validated": True,
    }


def _validate_sealed_derived_case_state(
    case_directory: Path,
    *,
    expected_state: str | None = None,
    allow_partial: bool,
) -> str:
    """derived reportをsealed complete／明示許可済みpartialへ限定する。"""

    report, _report_sha256 = _read_json(
        case_directory / "report.json",
        label="derived one-shot report",
    )
    case_state = report.get("case_state")
    if not isinstance(case_state, Mapping):
        raise CaseStagingError("derived caseにsealed case_stateがありません")
    state = case_state.get("status")
    blockers = case_state.get("blockers")
    if expected_state is not None and state != expected_state:
        raise CaseStagingError("derived case reportとfollow-on nodeの状態が一致しません")
    if state == "complete":
        if case_state.get("complete") is not True or blockers not in (None, []):
            raise CaseStagingError("derived complete caseのsealed状態が不正です")
        return state
    if state == "partial" and allow_partial:
        if (
            case_state.get("complete") is not False
            or not isinstance(blockers, list)
            or not blockers
            or any(not isinstance(item, str) or not item for item in blockers)
            or blockers != sorted(set(blockers))
        ):
            raise CaseStagingError("derived partial caseのsealed状態が不正です")
        return state
    if state == "partial":
        raise CaseStagingError("derived partial caseには明示的な許可が必要です")
    raise CaseStagingError("derived caseはsealed complete／partial状態ではありません")


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
            if key == "decompilations" and program.get("characteristic_native_decompilation_count") == 0:
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
        "functions_items": 0,
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
            if destination == "native_functions":
                # private-artifact-validation.json の生成側は、Ghidraの
                # raw function inventoryを functions_items と
                # native_functions の両方へ記録する。case archive昇格時も
                # 同じprogram単位の拘束値から両fieldを再現する。
                totals["functions_items"] += value
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
    require_single_case: bool = True,
) -> ValidatedInputs:
    if not case_sha256s or (require_single_case and len(case_sha256s) != 1):
        raise CaseStagingError("容量制御とcase分離のため、--case-sha256は1回につき1件だけ指定してください")
    requested = [_validate_sha256(case_sha256s[0], label="--case-sha256")]
    if not require_single_case:
        requested = [_validate_sha256(value, label="case SHA-256") for value in case_sha256s]
    if len(set(requested)) != len(requested):
        raise CaseStagingError("case SHA-256に重複があります")
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
    (
        source_manifest,
        source_manifest_sha256,
        source_cases,
        source_sidecar_commitments,
    ) = _validate_source_manifest(source_root)
    one_shot_cases = _case_directories(
        _validate_existing_directory(
            one_shot_root / "cases",
            label="one-shot cases root",
        ),
        label="one-shot cases root",
    )
    source_bindings = _validated_case_source_bindings(
        repository=repository,
        collection_id=collection_id,
        source_manifest=source_manifest,
        source_cases=source_cases,
        one_shot_cases=one_shot_cases,
    )
    expected_cases = set(source_bindings)
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
    requested = [
        value
        if value in expected_cases
        else next((actual for actual, provider in source_bindings.items() if provider == value), value)
        for value in requested
    ]
    if any(value not in expected_cases for value in requested) or len(set(requested)) != len(requested):
        raise CaseStagingError("指定caseが検証済みsource集合にありません")
    selected_cases: dict[str, CaseInputs] = {}
    for digest in sorted(requested):
        case_rows = relationships[digest]
        pe_sha256s = tuple(sorted({str(item["layer_sha256"]) for item in case_rows if item.get("is_pe") is True}))
        if not pe_sha256s:
            raise CaseStagingError("PE objectがないcaseはこのhelperで保管できません")
        selected_cases[digest] = CaseInputs(
            case_sha256=digest,
            source_requested_sha256=source_bindings[digest],
            source_directory=source_cases[source_bindings[digest]],
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
        source_sidecar_commitments=source_sidecar_commitments,
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
    source_requested_sha256: str | None = None,
    source_sidecar_commitments: Mapping[str, SourceCommitment] | None = None,
) -> dict[str, Any]:
    requested = source_requested_sha256 or case_sha256
    items = source_manifest["items"]
    selected_metadata = source_manifest["selected_metadata"]
    item = next(
        (value for value in items if isinstance(value, Mapping) and value.get("sha256") == requested),
        None,
    )
    metadata = next(
        (value for value in selected_metadata if isinstance(value, Mapping) and value.get("sha256_hash") == requested),
        None,
    )
    if not isinstance(item, Mapping) or not isinstance(metadata, Mapping):
        raise CaseStagingError("case別取得provenanceをsource manifestから復元できません")
    return {
        "schema_version": ACQUISITION_SCHEMA_VERSION,
        "collection_id": collection_id,
        "case_sha256": case_sha256,
        "provider_requested_sha256": requested if requested != case_sha256 else None,
        "source_manifest_sha256": source_manifest_sha256,
        "selection_commitment_sha256": source_manifest.get("selection_commitment_sha256"),
        "source": source_manifest.get("source"),
        "selection_mode": source_manifest.get("selection_mode"),
        "selected_at": source_manifest.get("selected_at"),
        "archive": {
            "path": f"source/{requested}.zip",
            "size": item.get("zip_size"),
            "sha256": item.get("zip_sha256"),
            "remains_encrypted": True,
        },
        "metadata": dict(metadata),
        "provider_metadata": selection_contract.safe_metadata_projection(item["metadata"]),
        "source_sidecars": [
            {
                "name": name,
                "size": commitment.size,
                "sha256": commitment.sha256,
                "raw_content_included": False,
            }
            for name, commitment in sorted((source_sidecar_commitments or {}).items())
        ],
        "safety": {
            "sample_executed": False,
            "archive_decrypted_for_staging": False,
            "network_contacted_for_staging": False,
            "raw_source_sidecars_included": False,
        },
    }


def _source_case_document(inputs: ValidatedInputs, case: CaseInputs) -> dict[str, Any]:
    return _source_case_document_from_manifest(
        source_manifest=inputs.source_manifest,
        source_manifest_sha256=inputs.source_manifest_sha256,
        collection_id=inputs.collection_id,
        case_sha256=case.case_sha256,
        source_requested_sha256=case.source_requested_sha256,
        source_sidecar_commitments=inputs.source_sidecar_commitments,
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
    files = list(_walk_files(source_root, role="ghidra_object"))
    source_absolute = _absolute(archive_analysis_datastore._extended_length_path(source_root))
    observed_keys = {_source_commitment_key(path) for path, _relative in files}
    expected_keys = {key for key, commitment in commitments.items() if _is_within(commitment.path, source_absolute)}
    if observed_keys != expected_keys:
        raise CaseStagingError("ghidra_objectのfile集合がpreflight commitmentから変更されました")
    copied: list[CopiedFile] = []
    program_result_seen = False
    for source, relative in files:
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
    allowed_case_sha256s: frozenset[str] | None = None,
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
            digest, size, _identity = archive_analysis_datastore._hash_source_snapshot(path)
        except archive_analysis_datastore.DatastoreError as exc:
            raise CaseStagingError("昇格後case stagingを安全に照合できません") from exc
        if size != item.size or digest != item.sha256:
            raise CaseStagingError("昇格後case stagingがcopy commitmentから変更されました")
        observed.add(key)
    if observed != set(expected):
        raise CaseStagingError("昇格後case stagingのfile集合が一致しません")
    _scan_staged_case_references(
        root,
        case_sha256=case_sha256,
        allowed_case_sha256s=allowed_case_sha256s,
    )
    try:
        archive_files = archive_analysis_datastore.collect_source_files([root])
    except archive_analysis_datastore.DatastoreError as exc:
        raise CaseStagingError("昇格後case stagingをarchive helperへ渡せません") from exc
    records = [{"path": item.archive_name, "size": item.size, "sha256": item.sha256} for item in archive_files]
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


def _remove_owned_candidate(
    path: Path,
    *,
    output_root: Path,
    expected_identity: tuple[int, int],
) -> None:
    """新規作成したcandidateだけをidentity確認後に回収する。"""

    if not os.path.lexists(archive_analysis_datastore._extended_length_path(path)):
        return
    absolute = _absolute(path)
    output = _validate_existing_directory(output_root, label="owned candidate output root")
    if absolute.parent != output or not absolute.name.startswith(".candidate-"):
        raise CaseStagingError("owned candidateのcleanup境界を確認できません")
    _reject_reparse_components(
        archive_analysis_datastore._extended_length_path(absolute),
        label="owned candidate cleanup",
    )
    metadata = archive_analysis_datastore._extended_length_path(absolute).lstat()
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or _is_reparse(metadata)
        or (metadata.st_dev, metadata.st_ino) != expected_identity
    ):
        raise CaseStagingError("owned candidate cleanup対象のidentityが一致しません")
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
        for name, source_commitment in inputs.source_sidecar_commitments.items():
            _assert_source_commitment(
                source_commitment.path,
                commitments=commitments,
                role=f"source sidecar {name}",
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
            "analysis_output_sha256": None,
            "follow_on_lineage_sha256": None,
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
                "host_secret_content_scan_scope": "non_sample_content_only",
                "verified_malware_binary_content_scan_excluded": True,
                "verified_malware_binary_count": len(case.pe_sha256s),
                "different_cases_included": False,
                "derived_case_count": 0,
                "derived_case_state_counts": {"complete": 0, "partial": 0},
                "derived_cases_complete": True,
                "incomplete_derived_cases_included": False,
                "incomplete_follow_on_evidence_present": False,
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
        final_archive_files, source_tree_sha256, total_size = _verify_promoted_staging(
            final,
            copied,
            case_sha256=case.case_sha256,
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
                "--expected-source-tree-sha256",
                source_tree_sha256,
                "--expected-file-count",
                str(len(final_archive_files)),
                "--expected-total-size",
                str(total_size),
            ],
            "sample_executed": False,
            "network_contacted": False,
        }
    except BaseException:
        if temporary is not None:
            _remove_new_staging(temporary, output_root=inputs.output_root)
        raise


def _projected_case_staging_bytes(inputs: ValidatedInputs, case: CaseInputs) -> int:
    total = 0
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
    return total + 1024 * 1024


def _projected_staging_bytes(inputs: ValidatedInputs) -> int:
    return sum(_projected_case_staging_bytes(inputs, case) for case in inputs.cases.values())


def _preflight_sensitive_content(
    inputs: ValidatedInputs,
) -> dict[str, SourceCommitment]:
    files: dict[str, tuple[Path, str]] = {}

    def add(path: Path, label: str) -> None:
        key = os.path.normcase(os.fspath(_absolute(path)))
        files.setdefault(key, (path, label))

    for name, commitment in inputs.source_sidecar_commitments.items():
        files[_source_commitment_key(commitment.path)] = (
            commitment.path,
            f"source-sidecar/{name}",
        )

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
        commitment = _snapshot_source_commitment(path, relative=relative)
        expected = next(
            (item for item in inputs.source_sidecar_commitments.values() if _source_commitment_key(item.path) == key),
            None,
        )
        if expected is not None and (commitment.sha256 != expected.sha256 or commitment.size != expected.size):
            raise CaseStagingError("source sidecarがmanifest検証後に変更されました")
        commitments[key] = commitment
    return commitments


def prepare_case_staging_session(
    *,
    repository: Path,
    collection_id: str,
    source_root: Path,
    one_shot_root: Path,
    ghidra_root: Path,
    output_root: Path,
    case_sha256s: Sequence[str],
) -> CaseStagingSession:
    """全体manifestを1回検証し、逐次case copy用commitmentを固定する。"""

    inputs = _validate_inputs(
        repository=repository,
        collection_id=collection_id,
        source_root=source_root,
        one_shot_root=one_shot_root,
        ghidra_root=ghidra_root,
        output_root=output_root,
        case_sha256s=case_sha256s,
        require_single_case=False,
    )
    projected = {digest: _projected_case_staging_bytes(inputs, case) for digest, case in inputs.cases.items()}
    maximum_required = max(projected.values())
    try:
        free = shutil.disk_usage(
            archive_analysis_datastore._extended_length_path(inputs.output_root)
        ).free
    except OSError as exc:
        raise CaseStagingError("case staging filesystemの空き容量を確認できません") from exc
    if free < maximum_required + MINIMUM_FREE_RESERVE_BYTES:
        raise CaseStagingError("case stagingに必要な空き容量と安全余白がありません")
    commitments = _preflight_sensitive_content(inputs)
    for case in inputs.cases.values():
        _validate_one_shot_report_identity(
            case.one_shot_directory,
            digest=case.case_sha256,
        )
    return CaseStagingSession(
        inputs=inputs,
        requested_to_actual_case_sha256={
            case.source_requested_sha256: case.case_sha256 for case in inputs.cases.values()
        },
        commitments=commitments,
        projected_case_bytes=projected,
        observed_free_bytes_before_staging=free,
    )


def stage_case_from_session(
    session: CaseStagingSession,
    *,
    case_sha256: str,
) -> dict[str, Any]:
    """固定sessionから1 caseだけをcopy時再照合してstagingする。"""

    requested_digest = _validate_sha256(case_sha256, label="case SHA-256")
    digest = session.requested_to_actual_case_sha256.get(requested_digest, requested_digest)
    case = session.inputs.cases.get(digest)
    if case is None:
        raise CaseStagingError("case staging sessionに指定caseがありません")
    target = _datastore_target(session.inputs.collection_id, digest)
    if os.path.lexists(session.inputs.output_root / target):
        raise CaseStagingError(f"既存case stagingを上書きしません: {target}")
    required = session.projected_case_bytes[digest]
    try:
        free = shutil.disk_usage(
            archive_analysis_datastore._extended_length_path(
                session.inputs.output_root
            )
        ).free
    except OSError as exc:
        raise CaseStagingError("case staging filesystemの空き容量を確認できません") from exc
    if free < required + MINIMUM_FREE_RESERVE_BYTES:
        raise CaseStagingError("case stagingに必要な空き容量と安全余白がありません")
    staged = _stage_one(
        session.inputs,
        case,
        commitments=session.commitments,
    )
    return {
        "schema_version": SCHEMA_VERSION,
        "collection_id": session.inputs.collection_id,
        "case_count": 1,
        "projected_staging_bytes": required,
        "observed_free_bytes_before_staging": free,
        "preflight_secret_content_scanned_files": sum(
            item.sensitive_content_scanned for item in session.commitments.values()
        ),
        "preflight_verified_malware_binaries_excluded": sum(
            not item.sensitive_content_scanned for item in session.commitments.values()
        ),
        "cases": [staged],
        "safety": {
            "case_separated": True,
            "physical_copy_only": True,
            "preflight_secret_name_and_content_scan_complete": True,
            "preflight_secret_content_scan_scope": "non_sample_content_only",
            "sample_executed": False,
            "network_contacted": False,
            "s3_upload_performed": False,
            "receipt_created": False,
            "source_deleted": False,
        },
    }


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

    if len(case_sha256s) != 1:
        raise CaseStagingError("容量制御とcase分離のため、--case-sha256は1回につき1件だけ指定してください")
    session = prepare_case_staging_session(
        repository=repository,
        collection_id=collection_id,
        source_root=source_root,
        one_shot_root=one_shot_root,
        ghidra_root=ghidra_root,
        output_root=output_root,
        case_sha256s=case_sha256s,
    )
    return stage_case_from_session(session, case_sha256=case_sha256s[0])


def stage_externalized_shared_derived_case(
    *,
    repository: Path,
    collection_id: str,
    one_shot_root: Path,
    output_root: Path,
    expected_run_root_sha256s: Sequence[str],
    child_sha256: str,
    allow_partial_derived_cases: bool,
    expected_analysis_output_sha256: str,
    expected_externalization_document: Mapping[str, Any],
) -> dict[str, Any]:
    """共有derived leafをcanonical payload 1 copyと解析treeへ分離する。"""

    child = _validate_sha256(child_sha256, label="共有derived child SHA-256")
    analysis_output_sha256 = _validate_sha256(
        expected_analysis_output_sha256,
        label="analysis output SHA-256",
    )
    if type(allow_partial_derived_cases) is not bool:
        raise CaseStagingError("共有derived partial許可値はbooleanである必要があります")
    if not isinstance(expected_externalization_document, Mapping):
        raise CaseStagingError("共有derived externalization commitmentがobjectではありません")
    expected_document = dict(expected_externalization_document)
    repository = _validate_existing_directory(repository, label="repository")
    one_shot_root = _validate_existing_directory(one_shot_root, label="one-shot root")
    if _is_within(one_shot_root, repository):
        raise CaseStagingError("private one-shot入力をrepository内から取得できません")
    output_root = _prepare_output_root(
        output_root,
        repository=repository,
        inputs=(one_shot_root,),
    )
    roots = [
        _validate_sha256(value, label="production run root SHA-256")
        for value in expected_run_root_sha256s
    ]
    if not roots or len(roots) > MAX_CASES or len(set(roots)) != len(roots):
        raise CaseStagingError("production run root集合が空、重複、または上限超過です")
    lineage = _validate_one_shot_lineage(one_shot_root, source_case_sha256s=set(roots))
    documents = build_shared_derived_externalization_documents(
        lineage,
        collection_id=collection_id,
        allow_partial_derived_cases=allow_partial_derived_cases,
    )
    live_document = documents.get(child)
    if live_document is None or live_document != expected_document:
        raise CaseStagingError("共有derived live graphがexternalization commitmentと一致しません")
    for owner in live_document["owners"]:
        rejected = {
            reason
            for reason in lineage.unsafe_reasons_by_root[owner]
            if reason != "shared_or_cross_root_child"
            and not (
                allow_partial_derived_cases
                and reason == "derived_child_incomplete"
            )
        }
        if rejected:
            raise CaseStagingError(
                "共有derived owner lineageに外部分離できない理由があります: "
                + ", ".join(sorted(rejected))
            )

    child_directory = lineage.case_directories[child]
    _validate_one_shot_report_identity(child_directory, digest=child)
    child_safety = _validate_one_shot_report_safety(child_directory)
    child_state = _validate_sealed_derived_case_state(
        child_directory,
        expected_state=str(live_document["child_case_state"]),
        allow_partial=allow_partial_derived_cases,
    )
    if child_state != live_document["child_case_state"]:
        raise CaseStagingError("共有derived sealed状態がprovenanceと一致しません")

    graph_path = one_shot_root / "follow-on-analysis.json"
    input_files: dict[str, tuple[Path, str]] = {}
    for path, relative in _walk_files(child_directory, role="shared derived case"):
        input_files[_source_commitment_key(path)] = (
            path,
            f"one-shot-derived/{child}/{relative.as_posix()}",
        )
    payload_paths: dict[str, Path] = {}
    canonical_payload: Path | None = None
    for owner_edge in live_document["owner_edges"]:
        owner = str(owner_edge["owner_root_sha256"])
        parent = str(owner_edge["parent_sha256"])
        path_value = str(owner_edge["path"])
        if parent not in lineage.case_directories:
            raise CaseStagingError("共有derived edge parentがmaterialized caseではありません")
        try:
            member = archive_analysis_datastore._validate_member_name(path_value)
        except archive_analysis_datastore.DatastoreError as exc:
            raise CaseStagingError("共有derived edge pathが安全ではありません") from exc
        payload = lineage.case_directories[parent].joinpath(*PurePosixPath(member).parts)
        key = _source_commitment_key(payload)
        if key in payload_paths:
            raise CaseStagingError("共有derived payload pathがowner間で重複しています")
        payload_paths[key] = payload
        input_files[key] = (payload, f"owner-payload/{owner}/{member}")
        if parent == live_document["canonical_parent_sha256"]:
            if canonical_payload is not None:
                raise CaseStagingError("共有derived canonical payloadが一意ではありません")
            canonical_payload = payload
    if canonical_payload is None or len(payload_paths) != live_document["payload_copy_count"]:
        raise CaseStagingError("共有derived payload copy集合がprovenanceと一致しません")
    input_files[_source_commitment_key(graph_path)] = (
        graph_path,
        "follow-on-analysis.json",
    )

    commitments: dict[str, SourceCommitment] = {}
    for key, (path, relative) in sorted(input_files.items()):
        commitments[key] = _snapshot_source_commitment(path, relative=relative)
    graph_commitment = commitments[_source_commitment_key(graph_path)]
    if graph_commitment.sha256 != lineage.graph_sha256:
        raise CaseStagingError("follow-on graphがlineage commitmentと一致しません")
    for path in payload_paths.values():
        commitment = commitments[_source_commitment_key(path)]
        if (
            commitment.sha256 != child
            or commitment.size != live_document["payload_size"]
        ):
            raise CaseStagingError("共有derived payload copyのSHA-256またはsizeが競合しています")

    required = sum(item.size for item in commitments.values()) + 1024 * 1024
    try:
        free = shutil.disk_usage(
            archive_analysis_datastore._extended_length_path(output_root)
        ).free
    except OSError as exc:
        raise CaseStagingError("共有derived stagingの空き容量を確認できません") from exc
    if free < required + MINIMUM_FREE_RESERVE_BYTES:
        raise CaseStagingError("共有derived stagingに必要な空き容量と安全余白がありません")

    target = _shared_derived_target(collection_id, child)
    final = output_root / target
    if os.path.lexists(archive_analysis_datastore._extended_length_path(final)):
        raise CaseStagingError(f"既存共有derived stagingを上書きしません: {target}")
    temporary, temporary_identity = _create_owned_staging_directory(
        output_root,
        label=child,
    )
    copied: list[CopiedFile] = []
    externalization_document_sha256 = _canonical_sha256(live_document)
    try:
        copied.append(
            _copy_file(
                canonical_payload,
                temporary / "payload" / f"{child}.quarantine.bin",
                staging_root=temporary,
                role="shared_derived_payload",
                commitments=commitments,
            )
        )
        copied.extend(
            _copy_tree(
                child_directory,
                temporary / "one-shot-derived" / child,
                staging_root=temporary,
                role="shared_derived_analysis",
                commitments=commitments,
            )
        )
        for path in payload_paths.values():
            _assert_source_commitment(
                path,
                commitments=commitments,
                role="shared derived owner payload",
            )
        _assert_source_commitment(
            graph_path,
            commitments=commitments,
            role="shared derived follow-on graph",
        )
        provenance = {
            **live_document,
            "analysis_output_sha256": analysis_output_sha256,
            "externalization_document_sha256": externalization_document_sha256,
        }
        provenance_sha256 = _canonical_sha256(provenance)
        copied.append(
            _write_generated_json(
                temporary / "provenance" / "shared-derived.json",
                provenance,
                staging_root=temporary,
                role="shared_derived_provenance",
            )
        )
        copied.append(
            _write_generated_text(
                temporary / "README.md",
                (
                    "# 共有派生payloadの外部分離\n\n"
                    "このarchiveは、複数rootから同一SHA-256で復元された派生payloadを、"
                    "root別archiveから分離して一度だけ保管します。canonical payload 1 copy、"
                    "当該derived caseの静的解析結果、検証済みprovenanceだけを含みます。\n\n"
                    "- root source／root analysis: 含めない\n"
                    "- 検体実行: なし\n"
                    "- 解析中の外部通信: なし\n"
                    "- 元sourceの削除: なし\n"
                ),
                staging_root=temporary,
                role="shared_derived_readme",
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
        manifest_document = {
            "schema_version": SHARED_DERIVED_STAGING_SCHEMA_VERSION,
            "target": target,
            "collection_id": collection_id,
            "child_sha256": child,
            "child_case_state": child_state,
            "analysis_output_sha256": analysis_output_sha256,
            "source_follow_on_sha256": lineage.graph_sha256,
            "externalization_document_sha256": externalization_document_sha256,
            "provenance_sha256": provenance_sha256,
            "file_count_excluding_this_manifest": len(records),
            "total_size_excluding_this_manifest": sum(int(item["size"]) for item in records),
            "file_inventory_sha256": _inventory_sha256(records),
            "files": records,
            "roles": dict(sorted(roles.items())),
            "archive_handoff": {
                "tool": "analysis-framework/common/archive_analysis_datastore.py",
                "target": target,
                "source": "<this-shared-derived-staging-directory>",
                "receipt_must_remain_outside_repository": True,
                "datastore_upload_json_created": False,
            },
            "safety": {
                "physical_copy_only": True,
                "hardlinks_allowed": False,
                "symlinks_or_junctions_allowed": False,
                "shared_payload_copy_count": 1,
                "root_sources_included": False,
                "root_analysis_included": False,
                "sample_executed": False,
                "network_contacted": False,
                "ai_used": child_safety["ai_used"],
                "source_deleted": False,
            },
        }
        manifest_file = _write_generated_json(
            temporary / STAGING_MANIFEST_NAME,
            manifest_document,
            staging_root=temporary,
            role="shared_derived_staging_manifest",
        )
        copied.append(manifest_file)
        if sum(item.sha256 == child and item.size == live_document["payload_size"] for item in copied) != 1:
            raise CaseStagingError("共有derived stagingのpayloadが正確に1 copyではありません")
        _scan_staged_case_references(
            archive_analysis_datastore._extended_length_path(temporary),
            case_sha256=child,
            allowed_case_sha256s=frozenset({child, *live_document["owners"]}),
        )
        try:
            archive_files = archive_analysis_datastore.collect_source_files([temporary])
        except archive_analysis_datastore.DatastoreError as exc:
            raise CaseStagingError("共有derived stagingをarchive helperへ渡せません") from exc
        if len(archive_files) != len(copied):
            raise CaseStagingError("共有derived inventoryとarchive inventoryが一致しません")
        current_identity = archive_analysis_datastore._extended_length_path(temporary).lstat()
        if (current_identity.st_dev, current_identity.st_ino) != temporary_identity:
            raise CaseStagingError("共有derived candidate identityが昇格前に変更されました")
        os.replace(
            archive_analysis_datastore._extended_length_path(temporary),
            archive_analysis_datastore._extended_length_path(final),
        )
        temporary = None
        final_archive_files, source_tree_sha256, total_size = _verify_promoted_staging(
            archive_analysis_datastore._extended_length_path(final),
            copied,
            case_sha256=child,
            allowed_case_sha256s=frozenset({child, *live_document["owners"]}),
        )
    except BaseException:
        if temporary is not None:
            _remove_owned_candidate(
                temporary,
                output_root=output_root,
                expected_identity=temporary_identity,
            )
        raise

    staged = SharedDerivedStaging(
        child_sha256=child,
        target=target,
        source_path=final,
        source_tree_sha256=source_tree_sha256,
        file_count=len(final_archive_files),
        total_size=total_size,
        provenance_sha256=provenance_sha256,
        externalization_document_sha256=externalization_document_sha256,
    )
    return {
        "schema_version": SHARED_DERIVED_STAGING_SCHEMA_VERSION,
        "status": "staging_ready",
        "collection_id": collection_id,
        "child_sha256": child,
        "target": staged.target,
        "source_path": os.fspath(staged.source_path),
        "source_tree_sha256": staged.source_tree_sha256,
        "file_count": staged.file_count,
        "total_size": staged.total_size,
        "provenance_sha256": staged.provenance_sha256,
        "externalization_document_sha256": staged.externalization_document_sha256,
        "source_follow_on_sha256": lineage.graph_sha256,
        "owner_set_commitment_sha256": live_document["owner_set_commitment_sha256"],
        "edge_set_commitment_sha256": live_document["edge_set_commitment_sha256"],
        "child_case_state": child_state,
        "archive_arguments": [
            "--target",
            staged.target,
            "--source",
            os.fspath(staged.source_path),
            "--expected-source-tree-sha256",
            staged.source_tree_sha256,
            "--expected-file-count",
            str(staged.file_count),
            "--expected-total-size",
            str(staged.total_size),
        ],
        "sample_executed": False,
        "network_contacted": False,
        "s3_upload_performed": False,
        "source_deleted": False,
    }


def reuse_externalized_shared_derived_staging(
    *,
    output_root: Path,
    collection_id: str,
    child_sha256: str,
    allow_partial_derived_cases: bool,
    expected_analysis_output_sha256: str,
    expected_externalization_document: Mapping[str, Any],
) -> dict[str, Any]:
    """中断後の共有derived stagingを全inventory再検証して再利用する。"""

    child = _validate_sha256(child_sha256, label="共有derived再利用child")
    analysis_sha256 = _validate_sha256(
        expected_analysis_output_sha256,
        label="共有derived再利用analysis output",
    )
    if type(allow_partial_derived_cases) is not bool:
        raise CaseStagingError("共有derived partial許可値はbooleanである必要があります")
    if not isinstance(expected_externalization_document, Mapping):
        raise CaseStagingError("共有derived再利用commitmentがobjectではありません")
    expected_document = dict(expected_externalization_document)
    expected_document_sha256 = _canonical_sha256(expected_document)
    if expected_document.get("child_sha256") != child:
        raise CaseStagingError("共有derived再利用commitmentのchildが一致しません")
    partial_policy = expected_document.get("partial_policy")
    if (
        not isinstance(partial_policy, Mapping)
        or partial_policy.get("allow_partial_derived_cases")
        is not allow_partial_derived_cases
    ):
        raise CaseStagingError("共有derived再利用のpartial policyが一致しません")

    output = _validate_existing_directory(output_root, label="共有derived staging output root")
    target = _shared_derived_target(collection_id, child)
    source = output / target
    if not os.path.lexists(archive_analysis_datastore._extended_length_path(source)):
        raise CaseStagingError("再利用する共有derived stagingが存在しません")
    source = _validate_existing_directory(
        archive_analysis_datastore._extended_length_path(source),
        label="既存共有derived staging",
    )
    if source.parent != archive_analysis_datastore._extended_length_path(output) or source.name != target:
        raise CaseStagingError("共有derived stagingをowned output rootへ束縛できません")

    manifest, manifest_sha256 = _read_json(
        source / STAGING_MANIFEST_NAME,
        label="共有derived staging manifest",
    )
    files = manifest.get("files")
    safety = manifest.get("safety")
    handoff = manifest.get("archive_handoff")
    expected_state = str(expected_document.get("child_case_state"))
    if (
        manifest.get("schema_version") != SHARED_DERIVED_STAGING_SCHEMA_VERSION
        or manifest.get("target") != target
        or manifest.get("collection_id") != collection_id
        or manifest.get("child_sha256") != child
        or manifest.get("child_case_state") != expected_state
        or manifest.get("analysis_output_sha256") != analysis_sha256
        or manifest.get("source_follow_on_sha256")
        != expected_document.get("source_follow_on_sha256")
        or manifest.get("externalization_document_sha256")
        != expected_document_sha256
        or not isinstance(files, list)
        or not files
        or not isinstance(safety, Mapping)
        or safety.get("physical_copy_only") is not True
        or safety.get("hardlinks_allowed") is not False
        or safety.get("symlinks_or_junctions_allowed") is not False
        or safety.get("shared_payload_copy_count") != 1
        or safety.get("root_sources_included") is not False
        or safety.get("root_analysis_included") is not False
        or safety.get("sample_executed") is not False
        or safety.get("network_contacted") is not False
        or safety.get("source_deleted") is not False
        or not isinstance(handoff, Mapping)
        or handoff.get("target") != target
        or handoff.get("datastore_upload_json_created") is not False
    ):
        raise CaseStagingError("共有derived staging manifestの束縛または安全契約が不正です")

    declared: dict[str, dict[str, Any]] = {}
    normalized_records: list[dict[str, Any]] = []
    roles: dict[str, dict[str, int]] = {}
    for raw in files:
        if not isinstance(raw, Mapping):
            raise CaseStagingError("共有derived inventoryがobjectではありません")
        relative_value = raw.get("path")
        role = raw.get("role")
        size = raw.get("size")
        sha256 = raw.get("sha256")
        if not isinstance(relative_value, str) or not relative_value:
            raise CaseStagingError("共有derived inventory pathが不正です")
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
            raise CaseStagingError("共有derived inventoryの型またはpathが不正です")
        digest = _validate_sha256(sha256, label="共有derived inventory SHA-256")
        key = relative.as_posix().casefold()
        if key in declared:
            raise CaseStagingError("共有derived inventory pathが重複しています")
        record = {
            "path": relative.as_posix(),
            "role": role,
            "size": size,
            "sha256": digest,
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
        raise CaseStagingError("共有derived inventory集計が一致しません")

    observed = _walk_files(source, role="existing shared derived staging")
    if len(observed) != len(normalized_records) + 1:
        raise CaseStagingError("共有derived file集合がmanifestと一致しません")
    payload_copy_count = 0
    for path, relative in observed:
        _reject_sensitive_name(relative)
        _scan_file_for_sensitive_content(path, relative=relative.as_posix())
        if relative.as_posix() == STAGING_MANIFEST_NAME:
            continue
        record = declared.get(relative.as_posix().casefold())
        if record is None or record["path"] != relative.as_posix():
            raise CaseStagingError("共有derived stagingに未束縛fileがあります")
        try:
            observed_sha256, observed_size, _identity = (
                archive_analysis_datastore._hash_source_snapshot(path)
            )
        except archive_analysis_datastore.DatastoreError as exc:
            raise CaseStagingError("共有derived staging fileを照合できません") from exc
        if observed_sha256 != record["sha256"] or observed_size != record["size"]:
            raise CaseStagingError("共有derived staging inventoryが一致しません")
        if observed_sha256 == child and observed_size == expected_document["payload_size"]:
            payload_copy_count += 1
    if payload_copy_count != 1:
        raise CaseStagingError("共有derived stagingのpayloadが正確に1 copyではありません")
    if os.path.lexists(source / "source") or os.path.lexists(source / "one-shot-private"):
        raise CaseStagingError("共有derived stagingにroot sourceまたはroot analysisがあります")
    derived_directory = source / "one-shot-derived" / child
    _validate_one_shot_report_identity(derived_directory, digest=child)
    _validate_sealed_derived_case_state(
        derived_directory,
        expected_state=expected_state,
        allow_partial=allow_partial_derived_cases,
    )
    provenance, _provenance_file_sha256 = _read_json(
        source / "provenance" / "shared-derived.json",
        label="共有derived provenance",
    )
    expected_provenance = {
        **expected_document,
        "analysis_output_sha256": analysis_sha256,
        "externalization_document_sha256": expected_document_sha256,
    }
    if provenance != expected_provenance or manifest.get("provenance_sha256") != _canonical_sha256(provenance):
        raise CaseStagingError("共有derived provenanceがcommitmentと一致しません")
    _scan_staged_case_references(
        source,
        case_sha256=child,
        allowed_case_sha256s=frozenset({child, *expected_document["owners"]}),
    )
    try:
        archive_files = archive_analysis_datastore.collect_source_files([source])
    except archive_analysis_datastore.DatastoreError as exc:
        raise CaseStagingError("共有derived stagingをarchive helperへ渡せません") from exc
    if len(archive_files) != len(normalized_records) + 1:
        raise CaseStagingError("共有derived archive inventoryが一致しません")
    archive_records = [
        {"path": item.archive_name, "size": item.size, "sha256": item.sha256}
        for item in archive_files
    ]
    source_tree_sha256 = _inventory_sha256(archive_records)
    total_size = sum(item.size for item in archive_files)
    return {
        "schema_version": SHARED_DERIVED_STAGING_SCHEMA_VERSION,
        "status": "staging_ready",
        "collection_id": collection_id,
        "child_sha256": child,
        "target": target,
        "source_path": os.fspath(source),
        "source_tree_sha256": source_tree_sha256,
        "file_count": len(archive_files),
        "total_size": total_size,
        "provenance_sha256": manifest["provenance_sha256"],
        "externalization_document_sha256": expected_document_sha256,
        "source_follow_on_sha256": manifest["source_follow_on_sha256"],
        "owner_set_commitment_sha256": expected_document["owner_set_commitment_sha256"],
        "edge_set_commitment_sha256": expected_document["edge_set_commitment_sha256"],
        "child_case_state": expected_state,
        "staging_manifest_sha256": manifest_sha256,
        "archive_arguments": [
            "--target",
            target,
            "--source",
            os.fspath(source),
            "--expected-source-tree-sha256",
            source_tree_sha256,
            "--expected-file-count",
            str(len(archive_files)),
            "--expected-total-size",
            str(total_size),
        ],
        "reused_existing_staging": True,
        "sample_executed": False,
        "network_contacted": False,
        "s3_upload_performed": False,
        "source_deleted": False,
    }


def _validated_shared_receipt_reference(
    *,
    collection_id: str,
    child_sha256: str,
    externalization_document: Mapping[str, Any],
    receipt: Mapping[str, Any],
) -> dict[str, Any]:
    """remote再検証済み共有archiveの最小hash commitmentだけを返す。"""

    child = _validate_sha256(child_sha256, label="共有receipt child")
    if receipt.get("remote_reverified") is not True:
        raise CaseStagingError("共有derived receiptはremote再検証済みではありません")
    expected_target = _shared_derived_target(collection_id, child)
    expected_document_sha256 = _canonical_sha256(externalization_document)
    hashes: dict[str, str] = {}
    for key in (
        "archive_sha256",
        "manifest_sha256",
        "source_tree_sha256",
        "provenance_sha256",
        "archive_report_sha256",
    ):
        hashes[key] = _validate_sha256(receipt.get(key), label=f"共有receipt {key}")
    if (
        receipt.get("target") != expected_target
        or receipt.get("externalization_document_sha256")
        != expected_document_sha256
        or receipt.get("source_follow_on_sha256")
        != externalization_document.get("source_follow_on_sha256")
        or receipt.get("owner_set_commitment_sha256")
        != externalization_document.get("owner_set_commitment_sha256")
        or receipt.get("edge_set_commitment_sha256")
        != externalization_document.get("edge_set_commitment_sha256")
        or receipt.get("child_case_state")
        != externalization_document.get("child_case_state")
    ):
        raise CaseStagingError("共有derived receiptがexternalization commitmentと一致しません")
    return {
        "target": expected_target,
        **hashes,
        "externalization_document_sha256": expected_document_sha256,
    }


def build_shared_derived_reference_document(
    *,
    collection_id: str,
    root_sha256: str,
    source_follow_on_sha256: str,
    externalization_documents: Mapping[str, Mapping[str, Any]],
    verified_receipts: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any] | None:
    """live graph文書とremote検証済みreceiptからroot参照を決定的に作る。"""

    root = _validate_sha256(root_sha256, label="共有derived参照root")
    graph_sha256 = _validate_sha256(
        source_follow_on_sha256,
        label="共有derived参照follow-on graph",
    )
    children = _shared_children_for_root(
        externalization_documents,
        root_sha256=root,
    )
    if set(verified_receipts) != set(children):
        raise CaseStagingError("共有derived receipt集合がrootのshared child集合と一致しません")
    if not children:
        return None
    normalized = {
        child: _validated_shared_receipt_reference(
            collection_id=collection_id,
            child_sha256=child,
            externalization_document=externalization_documents[child],
            receipt=verified_receipts[child],
        )
        for child in children
    }
    return {
        "schema_version": SHARED_DERIVED_REFERENCE_SCHEMA_VERSION,
        "collection_id": collection_id,
        "root_sha256": root,
        "source_follow_on_sha256": graph_sha256,
        "items": [
            {
                "child_sha256": child,
                "externalization": dict(externalization_documents[child]),
                "shared_archive": normalized[child],
            }
            for child in children
        ],
        "safety": {
            "shared_payload_bytes_included": False,
            "shared_derived_analysis_included": False,
            "shared_archives_remote_reverified": True,
            "sample_executed": False,
            "network_contacted_during_analysis": False,
            "source_deleted": False,
        },
    }


def _stage_cases_without_ghidra(
    *,
    repository: Path,
    collection_id: str,
    source_root: Path,
    one_shot_root: Path,
    output_root: Path,
    case_sha256s: Sequence[str],
    source_requested_sha256: str | None = None,
    expected_run_root_sha256s: Sequence[str] | None = None,
    allow_partial_derived_cases: bool = False,
    expected_analysis_output_sha256: str | None = None,
    expected_follow_on_lineage_document: Mapping[str, Any] | None | object = (
        _EXPECTED_LINEAGE_UNSET
    ),
    externalized_shared_receipts: Mapping[str, Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    """Ghidraを実行しないrunのsourceとone-shot結果を単一caseへ分離する。

    ``expected_run_root_sha256s`` は、完全な取得manifestを複数のproduction
    runへ分割した呼出しだけで使用する。省略時は従来どおり、取得manifest
    全体と単一runのroot集合が一致しなければならない。指定時も取得manifest
    自体は完全検証し、run側のroot集合だけを明示された部分集合へ束縛する。
    """

    if len(case_sha256s) != 1:
        raise CaseStagingError("容量制御とcase分離のため、caseは1回につき1件だけ指定してください")
    digest = _validate_sha256(case_sha256s[0], label="case SHA-256")
    requested_digest = (
        _validate_sha256(source_requested_sha256, label="provider requested SHA-256")
        if source_requested_sha256 is not None
        else digest
    )
    if type(allow_partial_derived_cases) is not bool:
        raise CaseStagingError("derived partial許可値はbooleanである必要があります")
    analysis_output_sha256 = (
        _validate_sha256(
            expected_analysis_output_sha256,
            label="analysis output SHA-256",
        )
        if expected_analysis_output_sha256 is not None
        else None
    )
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
    (
        source_manifest,
        source_manifest_sha256,
        source_cases,
        source_sidecar_commitments,
    ) = _validate_source_manifest(source_root)
    if expected_run_root_sha256s is None:
        expected_run_roots = set(source_cases)
    else:
        expected_run_root_values = [
            _validate_sha256(value, label="production run root SHA-256")
            for value in expected_run_root_sha256s
        ]
        if (
            not expected_run_root_values
            or len(expected_run_root_values) > MAX_CASES
            or len(set(expected_run_root_values)) != len(expected_run_root_values)
        ):
            raise CaseStagingError("production run root集合が空、重複、または上限超過です")
        expected_run_roots = set(expected_run_root_values)
    lineage = _validate_one_shot_lineage(
        one_shot_root,
        source_case_sha256s=expected_run_roots,
    )
    if digest not in expected_run_roots or requested_digest not in source_cases:
        raise CaseStagingError("指定caseまたはprovider要求hashが検証済み集合にありません")
    supplied_receipts = externalized_shared_receipts
    if supplied_receipts is None:
        externalization_documents: dict[str, dict[str, Any]] = {}
        root_shared_children: tuple[str, ...] = ()
        normalized_shared_references: dict[str, dict[str, Any]] = {}
    else:
        if not isinstance(supplied_receipts, Mapping):
            raise CaseStagingError("共有derived receipt集合がobjectではありません")
        externalization_documents = build_shared_derived_externalization_documents(
            lineage,
            collection_id=collection_id,
            allow_partial_derived_cases=allow_partial_derived_cases,
        )
        root_shared_children = _shared_children_for_root(
            externalization_documents,
            root_sha256=digest,
        )
        if set(supplied_receipts) != set(root_shared_children):
            raise CaseStagingError("共有derived receipt集合がrootのshared child集合と一致しません")
        normalized_shared_references = {
            child: _validated_shared_receipt_reference(
                collection_id=collection_id,
                child_sha256=child,
                externalization_document=externalization_documents[child],
                receipt=supplied_receipts[child],
            )
            for child in root_shared_children
        }
    unsafe_reasons = lineage.unsafe_reasons_by_root[digest]
    rejected_unsafe_reasons = tuple(
        reason
        for reason in unsafe_reasons
        if not (
            allow_partial_derived_cases
            and reason == "derived_child_incomplete"
        )
        and not (
            reason == "shared_or_cross_root_child"
            and supplied_receipts is not None
            and set(normalized_shared_references) == set(root_shared_children)
            and bool(root_shared_children)
        )
    )
    if rejected_unsafe_reasons:
        raise CaseStagingError(
            "指定rootのfollow-on lineageを安全に分離できません: "
            + ", ".join(rejected_unsafe_reasons)
        )
    source_directory = source_cases[requested_digest]
    lineage_sha256s = (digest, *lineage.descendants_by_root[digest])
    one_shot_directories = {value: lineage.case_directories[value] for value in lineage_sha256s}
    safety_records: list[dict[str, Any]] = []
    derived_case_states: dict[str, str] = {}
    for value, directory in one_shot_directories.items():
        _validate_one_shot_report_identity(directory, digest=value)
        safety_records.append(_validate_one_shot_report_safety(directory))
        if value != digest:
            derived_case_states[value] = _validate_sealed_derived_case_state(
                directory,
                expected_state=lineage.materialized_case_states[value],
                allow_partial=allow_partial_derived_cases,
            )
    derived_case_state_counts = {
        state: sum(value == state for value in derived_case_states.values())
        for state in ("complete", "partial")
    }
    if sum(derived_case_state_counts.values()) != len(derived_case_states):
        raise CaseStagingError("derived case状態集計がsealed case集合と一致しません")
    incomplete_descendants = lineage.incomplete_descendants_by_root[digest]
    lineage_document = build_follow_on_lineage_case_document(
        lineage,
        collection_id=collection_id,
        case_sha256=digest,
    )
    follow_on_lineage_sha256 = (
        _canonical_sha256(lineage_document)
        if lineage_document is not None
        else None
    )
    if (
        lineage_document is not None
        and lineage_document["derived_case_state_counts"]
        != derived_case_state_counts
    ):
        raise CaseStagingError(
            "live follow-on graphとsealed derived reportの状態が一致しません"
        )
    if expected_follow_on_lineage_document is not _EXPECTED_LINEAGE_UNSET:
        if expected_follow_on_lineage_document is not None and not isinstance(
            expected_follow_on_lineage_document,
            Mapping,
        ):
            raise CaseStagingError("期待follow-on lineage文書の型が不正です")
        expected_lineage = (
            dict(expected_follow_on_lineage_document)
            if isinstance(expected_follow_on_lineage_document, Mapping)
            else None
        )
        if lineage_document != expected_lineage:
            raise CaseStagingError(
                "live follow-on lineageがcoordinator commitmentと一致しません"
            )
    shared_reference_document: dict[str, Any] | None = None
    shared_reference_sha256: str | None = None
    if normalized_shared_references:
        if lineage.graph_sha256 is None or supplied_receipts is None:
            raise CaseStagingError("共有derived referenceのgraphまたはreceiptがありません")
        shared_reference_document = build_shared_derived_reference_document(
            collection_id=collection_id,
            root_sha256=digest,
            source_follow_on_sha256=lineage.graph_sha256,
            externalization_documents=externalization_documents,
            verified_receipts=supplied_receipts,
        )
        if shared_reference_document is None:
            raise CaseStagingError("共有derived referenceを構築できません")
        shared_reference_sha256 = _canonical_sha256(shared_reference_document)
    ai_values = {record["ai_used"] for record in safety_records}
    if len(ai_values) != 1:
        raise CaseStagingError("lineage内のAI利用契約が一致しません")
    one_shot_safety = safety_records[0]
    if source_requested_sha256 is not None:
        source_item = next(
            (
                item
                for item in source_manifest["items"]
                if isinstance(item, Mapping) and item.get("sha256") == requested_digest
            ),
            None,
        )
        report, _report_sha256 = _read_json(
            one_shot_directories[digest] / "report.json",
            label="partitioned production root report",
        )
        sample = report.get("sample")
        if (
            not isinstance(source_item, Mapping)
            or not isinstance(sample, Mapping)
            or sample.get("sha256") != digest
            or sample.get("input_kind") != "authenticated_single_member_zip"
            or sample.get("outer_sha256") != source_item.get("zip_sha256")
            or sample.get("outer_size") != source_item.get("zip_size")
            or not isinstance(sample.get("member_name"), str)
            or not sample["member_name"]
            or "/" in sample["member_name"].replace("\\", "/")
        ):
            raise CaseStagingError("production run rootを取得archiveへ一意に束縛できません")

    excluded_paths_by_case: dict[str, set[str]] = defaultdict(set)
    for shared_child in root_shared_children:
        document = externalization_documents[shared_child]
        owner_edges = [
            item
            for item in document["owner_edges"]
            if item["owner_root_sha256"] == digest
        ]
        if len(owner_edges) != 1:
            raise CaseStagingError("rootに対応する共有derived edgeが一意ではありません")
        edge = owner_edges[0]
        parent = str(edge["parent_sha256"])
        if parent != digest and parent not in lineage.descendants_by_root[digest]:
            raise CaseStagingError("共有derived edge parentがroot lineage外です")
        try:
            member = archive_analysis_datastore._validate_member_name(str(edge["path"]))
        except archive_analysis_datastore.DatastoreError as exc:
            raise CaseStagingError("共有derived除外pathが安全ではありません") from exc
        excluded_paths_by_case[parent].add(member)

    input_files: dict[str, tuple[Path, str]] = {}
    for name, commitment in source_sidecar_commitments.items():
        input_files[_source_commitment_key(commitment.path)] = (
            commitment.path,
            f"source-sidecar/{name}",
        )
    for root, role, destination in (
        (source_directory, "source", "source"),
        (
            one_shot_directories[digest],
            "one_shot_private",
            "one-shot-private",
        ),
        *(
            (
                one_shot_directories[child],
                "one_shot_derived",
                f"one-shot-derived/{child}",
            )
            for child in lineage.descendants_by_root[digest]
        ),
    ):
        for path, relative in _walk_files(root, role=role):
            key = _source_commitment_key(path)
            input_files.setdefault(key, (path, f"{destination}/{relative.as_posix()}"))
    commitments: dict[str, SourceCommitment] = {}
    for key, (path, relative) in sorted(input_files.items()):
        commitment = _snapshot_source_commitment(path, relative=relative)
        expected = next(
            (item for item in source_sidecar_commitments.values() if _source_commitment_key(item.path) == key),
            None,
        )
        if expected is not None and (commitment.sha256 != expected.sha256 or commitment.size != expected.size):
            raise CaseStagingError("source sidecarがmanifest検証後に変更されました")
        commitments[key] = commitment
    required = sum(item.size for item in commitments.values()) + 1024 * 1024
    try:
        free = shutil.disk_usage(
            archive_analysis_datastore._extended_length_path(output_root)
        ).free
    except OSError as exc:
        raise CaseStagingError("case staging filesystemの空き容量を確認できません") from exc
    if free < required + MINIMUM_FREE_RESERVE_BYTES:
        raise CaseStagingError("case stagingに必要な空き容量と安全余白がありません")

    target = _datastore_target(collection_id, digest)
    final = output_root / target
    if os.path.lexists(archive_analysis_datastore._extended_length_path(final)):
        raise CaseStagingError(f"既存case stagingを上書きしません: {target}")
    temporary, temporary_identity = _create_owned_staging_directory(
        output_root,
        label=digest,
    )
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
        root_exclusions = frozenset(excluded_paths_by_case.get(digest, set()))
        copied.extend(
            _copy_tree_excluding(
                one_shot_directories[digest],
                temporary / "one-shot-private",
                staging_root=temporary,
                role="one_shot_private",
                commitments=commitments,
                excluded_relative_paths=root_exclusions,
            )
            if root_exclusions
            else _copy_tree(
                one_shot_directories[digest],
                temporary / "one-shot-private",
                staging_root=temporary,
                role="one_shot_private",
                commitments=commitments,
            )
        )
        for child in lineage.descendants_by_root[digest]:
            if child in root_shared_children:
                for path, _relative in _walk_files(
                    one_shot_directories[child],
                    role="externalized shared derived analysis",
                ):
                    _assert_source_commitment(
                        path,
                        commitments=commitments,
                        role="externalized shared derived analysis",
                    )
                continue
            child_exclusions = frozenset(excluded_paths_by_case.get(child, set()))
            copied.extend(
                _copy_tree_excluding(
                    one_shot_directories[child],
                    temporary / "one-shot-derived" / child,
                    staging_root=temporary,
                    role="one_shot_derived",
                    commitments=commitments,
                    excluded_relative_paths=child_exclusions,
                )
                if child_exclusions
                else _copy_tree(
                    one_shot_directories[child],
                    temporary / "one-shot-derived" / child,
                    staging_root=temporary,
                    role="one_shot_derived",
                    commitments=commitments,
                )
            )
        for name, source_commitment in source_sidecar_commitments.items():
            _assert_source_commitment(
                source_commitment.path,
                commitments=commitments,
                role=f"source sidecar {name}",
            )
        copied.append(
            _write_generated_json(
                temporary / "derived" / "source-acquisition.case.json",
                _source_case_document_from_manifest(
                    source_manifest=source_manifest,
                    source_manifest_sha256=source_manifest_sha256,
                    collection_id=collection_id,
                    case_sha256=digest,
                    source_requested_sha256=requested_digest,
                    source_sidecar_commitments=source_sidecar_commitments,
                ),
                staging_root=temporary,
                role="derived_acquisition_manifest",
            )
        )
        if lineage_document is not None:
            copied.append(
                _write_generated_json(
                    temporary / "derived" / "follow-on-lineage.case.json",
                    lineage_document,
                    staging_root=temporary,
                    role="derived_follow_on_lineage_manifest",
                )
            )
        if shared_reference_document is not None:
            copied.append(
                _write_generated_json(
                    temporary / "derived" / "shared-derived-reference.case.json",
                    shared_reference_document,
                    staging_root=temporary,
                    role="shared_derived_reference",
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
            "provider_requested_sha256": requested_digest if requested_digest != digest else None,
            "analysis_output_sha256": analysis_output_sha256,
            "follow_on_lineage_sha256": follow_on_lineage_sha256,
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
                "different_cases_included": bool(
                    set(lineage.descendants_by_root[digest])
                    - set(root_shared_children)
                ),
                "different_root_cases_included": False,
                "derived_case_count": len(lineage.descendants_by_root[digest]),
                "derived_case_state_counts": derived_case_state_counts,
                "derived_cases_complete": derived_case_state_counts["partial"] == 0,
                "incomplete_derived_cases_included": False,
                "incomplete_follow_on_evidence_present": bool(
                    incomplete_descendants
                ),
                "sample_executed": False,
                "network_contacted": False,
                "ai_used": one_shot_safety["ai_used"],
                "one_shot_report_safety_validated": True,
                "source_deleted": False,
            },
        }
        if root_shared_children:
            staging_manifest["externalized_shared_reference_sha256"] = (
                shared_reference_sha256
            )
            staging_manifest["safety"].update(
                {
                    "physically_included_derived_case_count": len(
                        set(lineage.descendants_by_root[digest])
                        - set(root_shared_children)
                    ),
                    "externalized_shared_child_count": len(root_shared_children),
                    "externalized_shared_child_sha256s": list(root_shared_children),
                    "externalized_lineage_derived_case_count": len(
                        set(lineage.descendants_by_root[digest])
                        & set(root_shared_children)
                    ),
                    "shared_payload_bytes_included": False,
                    "shared_derived_analysis_included": False,
                    "shared_archives_remote_reverified": True,
                }
            )
        manifest_file = _write_generated_json(
            temporary / STAGING_MANIFEST_NAME,
            staging_manifest,
            staging_root=temporary,
            role="case_staging_manifest",
        )
        copied.append(manifest_file)
        for shared_child in root_shared_children:
            document = externalization_documents[shared_child]
            if os.path.lexists(
                archive_analysis_datastore._extended_length_path(
                    temporary / "one-shot-derived" / shared_child
                )
            ):
                raise CaseStagingError("root stagingに共有derived analysisが残っています")
            owner_edge = next(
                item
                for item in document["owner_edges"]
                if item["owner_root_sha256"] == digest
            )
            parent = str(owner_edge["parent_sha256"])
            base = (
                temporary / "one-shot-private"
                if parent == digest
                else temporary / "one-shot-derived" / parent
            )
            excluded_payload = base.joinpath(
                *PurePosixPath(str(owner_edge["path"])).parts
            )
            if os.path.lexists(
                archive_analysis_datastore._extended_length_path(excluded_payload)
            ):
                raise CaseStagingError("root stagingに共有payload bytesが残っています")
            if any(
                item.sha256 == shared_child
                and item.size == int(document["payload_size"])
                for item in copied
            ):
                raise CaseStagingError("root staging inventoryに共有payload bytesがあります")
        allowed_case_sha256s = frozenset(
            (*lineage_sha256s, *incomplete_descendants, *root_shared_children)
        )
        _scan_staged_case_references(
            temporary,
            case_sha256=digest,
            allowed_case_sha256s=allowed_case_sha256s,
        )
        try:
            archive_files = archive_analysis_datastore.collect_source_files([temporary])
        except archive_analysis_datastore.DatastoreError as exc:
            raise CaseStagingError("case stagingを既存archive helperへ安全に渡せません") from exc
        if len(archive_files) != len(copied):
            raise CaseStagingError("case staging inventoryとarchive inventoryが一致しません")
        current_identity = archive_analysis_datastore._extended_length_path(temporary).lstat()
        if (current_identity.st_dev, current_identity.st_ino) != temporary_identity:
            raise CaseStagingError("root candidate identityが昇格前に変更されました")
        os.replace(
            archive_analysis_datastore._extended_length_path(temporary),
            archive_analysis_datastore._extended_length_path(final),
        )
        temporary = None
        final_archive_files, source_tree_sha256, total_size = _verify_promoted_staging(
            archive_analysis_datastore._extended_length_path(final),
            copied,
            case_sha256=digest,
            allowed_case_sha256s=allowed_case_sha256s,
        )
        staged = {
            "case_sha256": digest,
            "provider_requested_sha256": requested_digest if requested_digest != digest else None,
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
                "--expected-source-tree-sha256",
                source_tree_sha256,
                "--expected-file-count",
                str(len(final_archive_files)),
                "--expected-total-size",
                str(total_size),
            ],
            "derived_case_sha256s": list(lineage.descendants_by_root[digest]),
            "derived_case_state_counts": derived_case_state_counts,
            "incomplete_derived_case_sha256s": list(incomplete_descendants),
            "incomplete_derived_case_states": {
                value: lineage.incomplete_case_states[value]
                for value in incomplete_descendants
            },
            "follow_on_lineage_sha256": follow_on_lineage_sha256,
            "sample_executed": False,
            "network_contacted": False,
            "ai_used": one_shot_safety["ai_used"],
            "one_shot_report_safety_validated": True,
        }
        if root_shared_children:
            staged["externalized_shared_reference_sha256"] = shared_reference_sha256
            staged["externalized_shared_child_sha256s"] = list(root_shared_children)
    except BaseException:
        if temporary is not None:
            _remove_owned_candidate(
                temporary,
                output_root=output_root,
                expected_identity=temporary_identity,
            )
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
            "ai_used": one_shot_safety["ai_used"],
            "one_shot_report_safety_validated": True,
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
    source_requested_sha256: str | None = None,
    expected_run_root_sha256s: Sequence[str] | None = None,
    allow_partial_derived_cases: bool = False,
    expected_analysis_output_sha256: str | None = None,
    expected_follow_on_lineage_document: Mapping[str, Any] | None | object = (
        _EXPECTED_LINEAGE_UNSET
    ),
) -> dict[str, Any]:
    """既存互換のroot staging入口。共有derivedは常に従来どおり拒否する。"""

    return _stage_cases_without_ghidra(
        repository=repository,
        collection_id=collection_id,
        source_root=source_root,
        one_shot_root=one_shot_root,
        output_root=output_root,
        case_sha256s=case_sha256s,
        source_requested_sha256=source_requested_sha256,
        expected_run_root_sha256s=expected_run_root_sha256s,
        allow_partial_derived_cases=allow_partial_derived_cases,
        expected_analysis_output_sha256=expected_analysis_output_sha256,
        expected_follow_on_lineage_document=expected_follow_on_lineage_document,
        externalized_shared_receipts=None,
    )


def _staged_derived_directories(root: Path) -> dict[str, Path]:
    """Windows long path対応でstaged derived直下だけを列挙する。"""

    validated = _validate_existing_directory(root, label="staged derived cases root")
    io_root = archive_analysis_datastore._extended_length_path(validated)
    try:
        with os.scandir(io_root) as iterator:
            entries = list(iterator)
    except OSError as exc:
        raise CaseStagingError("staged derived cases rootを列挙できません") from exc
    if not entries or len(entries) > MAX_CASES:
        raise CaseStagingError("staged derived case件数が上限外です")
    result: dict[str, Path] = {}
    for entry in entries:
        path = Path(entry.path)
        try:
            metadata = path.lstat()
        except OSError as exc:
            raise CaseStagingError("staged derived case entryを確認できません") from exc
        if (
            SHA256_RE.fullmatch(entry.name) is None
            or entry.is_symlink()
            or _is_reparse(metadata)
            or not stat.S_ISDIR(metadata.st_mode)
        ):
            raise CaseStagingError("staged derived cases rootに未束縛entryがあります")
        result[entry.name] = path
    return dict(sorted(result.items()))


def _validate_staged_shared_reference(
    source: Path,
    *,
    digest: str,
    manifest: Mapping[str, Any],
    allow_partial_derived_cases: bool,
) -> dict[str, Mapping[str, Any]]:
    """root stagingの共有archive参照とbytes除外を再検証する。"""

    safety = manifest.get("safety")
    if not isinstance(safety, Mapping):
        raise CaseStagingError("case staging manifestにsafetyがありません")
    raw_children = safety.get("externalized_shared_child_sha256s", [])
    raw_count = safety.get("externalized_shared_child_count", 0)
    reference_sha256 = manifest.get("externalized_shared_reference_sha256")
    reference_path = source / "derived" / "shared-derived-reference.case.json"
    if not isinstance(raw_children, list):
        raise CaseStagingError("externalized shared child集合がlistではありません")
    children = [
        _validate_sha256(value, label="externalized shared child")
        for value in raw_children
    ]
    if len(children) != len(set(children)) or raw_count != len(children):
        raise CaseStagingError("externalized shared child集合が重複または集計不一致です")
    if not children:
        if reference_sha256 is not None or os.path.lexists(
            archive_analysis_datastore._extended_length_path(reference_path)
        ):
            raise CaseStagingError("externalized childなしのstagingに共有参照があります")
        if (
            safety.get("shared_payload_bytes_included", False) is not False
            or safety.get("shared_derived_analysis_included", False) is not False
            or safety.get("shared_archives_remote_reverified", False) is not False
        ):
            raise CaseStagingError("externalized childなしの共有安全値が不正です")
        return {}

    reference_sha256 = _validate_sha256(
        reference_sha256,
        label="externalized shared reference SHA-256",
    )
    if (
        safety.get("shared_payload_bytes_included") is not False
        or safety.get("shared_derived_analysis_included") is not False
        or safety.get("shared_archives_remote_reverified") is not True
    ):
        raise CaseStagingError("externalized shared安全値が不正です")
    reference, _file_sha256 = _read_json(
        reference_path,
        label="externalized shared reference",
    )
    items = reference.get("items")
    reference_safety = reference.get("safety")
    if (
        reference.get("schema_version") != SHARED_DERIVED_REFERENCE_SCHEMA_VERSION
        or reference.get("collection_id") != manifest.get("collection_id")
        or reference.get("root_sha256") != digest
        or reference.get("source_follow_on_sha256") is None
        or not isinstance(items, list)
        or len(items) != len(children)
        or not isinstance(reference_safety, Mapping)
        or reference_safety.get("shared_payload_bytes_included") is not False
        or reference_safety.get("shared_derived_analysis_included") is not False
        or reference_safety.get("shared_archives_remote_reverified") is not True
        or reference_safety.get("sample_executed") is not False
        or reference_safety.get("network_contacted_during_analysis") is not False
        or reference_safety.get("source_deleted") is not False
        or _canonical_sha256(reference) != reference_sha256
    ):
        raise CaseStagingError("externalized shared referenceのschemaまたは安全値が不正です")

    result: dict[str, Mapping[str, Any]] = {}
    for raw in items:
        if not isinstance(raw, Mapping):
            raise CaseStagingError("externalized shared reference itemがobjectではありません")
        child = _validate_sha256(raw.get("child_sha256"), label="shared reference child")
        externalization = raw.get("externalization")
        shared_archive = raw.get("shared_archive")
        if (
            child in result
            or child not in children
            or not isinstance(externalization, Mapping)
            or not isinstance(shared_archive, Mapping)
        ):
            raise CaseStagingError("externalized shared reference itemが集合と一致しません")
        owners = externalization.get("owners")
        owner_edges = externalization.get("owner_edges")
        partial_policy = externalization.get("partial_policy")
        if (
            externalization.get("schema_version")
            != SHARED_DERIVED_PROVENANCE_SCHEMA_VERSION
            or externalization.get("collection_id") != manifest.get("collection_id")
            or externalization.get("child_sha256") != child
            or externalization.get("source_follow_on_sha256")
            != reference.get("source_follow_on_sha256")
            or not isinstance(owners, list)
            or digest not in owners
            or len(owners) != len(set(owners))
            or externalization.get("owner_set_commitment_sha256")
            != _canonical_sha256(sorted(owners))
            or not isinstance(owner_edges, list)
            or externalization.get("edge_set_commitment_sha256")
            != _canonical_sha256(owner_edges)
            or not isinstance(partial_policy, Mapping)
            or partial_policy.get("allow_partial_derived_cases")
            is not allow_partial_derived_cases
        ):
            raise CaseStagingError("externalized shared provenance commitmentが不正です")
        normalized_archive = _validated_shared_receipt_reference(
            collection_id=str(manifest.get("collection_id")),
            child_sha256=child,
            externalization_document=externalization,
            receipt={**shared_archive, "remote_reverified": True,
                "source_follow_on_sha256": externalization.get("source_follow_on_sha256"),
                "owner_set_commitment_sha256": externalization.get("owner_set_commitment_sha256"),
                "edge_set_commitment_sha256": externalization.get("edge_set_commitment_sha256"),
                "child_case_state": externalization.get("child_case_state")},
        )
        if dict(shared_archive) != normalized_archive:
            raise CaseStagingError("externalized shared archive commitmentが最小schemaではありません")
        owner_edges_for_root = [
            edge
            for edge in owner_edges
            if isinstance(edge, Mapping) and edge.get("owner_root_sha256") == digest
        ]
        if len(owner_edges_for_root) != 1:
            raise CaseStagingError("externalized shared owner edgeが一意ではありません")
        edge = owner_edges_for_root[0]
        parent = _validate_sha256(edge.get("parent_sha256"), label="shared owner edge parent")
        try:
            member = archive_analysis_datastore._validate_member_name(str(edge.get("path")))
        except archive_analysis_datastore.DatastoreError as exc:
            raise CaseStagingError("externalized shared owner edge pathが不正です") from exc
        base = (
            source / "one-shot-private"
            if parent == digest
            else source / "one-shot-derived" / parent
        )
        if os.path.lexists(
            archive_analysis_datastore._extended_length_path(
                base.joinpath(*PurePosixPath(member).parts)
            )
        ):
            raise CaseStagingError("root stagingにexternalized shared payloadが残っています")
        if os.path.lexists(
            archive_analysis_datastore._extended_length_path(
                source / "one-shot-derived" / child
            )
        ):
            raise CaseStagingError("root stagingにexternalized shared analysisが残っています")
        result[child] = externalization
    if set(result) != set(children):
        raise CaseStagingError("externalized shared referenceのchild集合が一致しません")

    for path, relative in _walk_files(source, role="externalized shared bytes absence scan"):
        if relative.as_posix() == STAGING_MANIFEST_NAME:
            continue
        try:
            observed_sha256, observed_size, _identity = (
                archive_analysis_datastore._hash_source_snapshot(path)
            )
        except archive_analysis_datastore.DatastoreError as exc:
            raise CaseStagingError("externalized shared bytes absenceを照合できません") from exc
        if any(
            observed_sha256 == child
            and observed_size == int(result[child]["payload_size"])
            for child in result
        ):
            raise CaseStagingError("root stagingにexternalized shared payload bytesがあります")
    return result


def _validate_staged_derived_policy(
    source: Path,
    *,
    digest: str,
    manifest: Mapping[str, Any],
    allow_partial_derived_cases: bool,
    expected_analysis_output_sha256: str | None,
    expected_follow_on_lineage_document: Mapping[str, Any] | None | object,
    expected_externalized_shared_reference_document: (
        Mapping[str, Any] | None | object
    ) = _EXPECTED_LINEAGE_UNSET,
) -> frozenset[str]:
    """stagingのderived集合、sealed状態、incomplete証拠を再構成する。"""

    if type(allow_partial_derived_cases) is not bool:
        raise CaseStagingError("derived partial許可値はbooleanである必要があります")
    expected_analysis = (
        _validate_sha256(
            expected_analysis_output_sha256,
            label="expected analysis output SHA-256",
        )
        if expected_analysis_output_sha256 is not None
        else None
    )
    observed_analysis = manifest.get("analysis_output_sha256")
    if observed_analysis is not None:
        observed_analysis = _validate_sha256(
            observed_analysis,
            label="staging analysis output SHA-256",
        )
    if expected_analysis is not None and observed_analysis != expected_analysis:
        raise CaseStagingError("既存stagingが現在のanalysis tree commitmentと一致しません")
    expected_lineage = _EXPECTED_LINEAGE_UNSET
    if expected_follow_on_lineage_document is not _EXPECTED_LINEAGE_UNSET:
        if expected_follow_on_lineage_document is not None and not isinstance(
            expected_follow_on_lineage_document,
            Mapping,
        ):
            raise CaseStagingError("期待follow-on lineage文書の型が不正です")
        expected_lineage = (
            dict(expected_follow_on_lineage_document)
            if isinstance(expected_follow_on_lineage_document, Mapping)
            else None
        )
    observed_lineage_sha256 = manifest.get("follow_on_lineage_sha256")
    if observed_lineage_sha256 is not None:
        observed_lineage_sha256 = _validate_sha256(
            observed_lineage_sha256,
            label="staging follow-on lineage SHA-256",
        )
    if expected_lineage is not _EXPECTED_LINEAGE_UNSET:
        expected_lineage_sha256 = (
            _canonical_sha256(expected_lineage)
            if isinstance(expected_lineage, Mapping)
            else None
        )
        if observed_lineage_sha256 != expected_lineage_sha256:
            raise CaseStagingError(
                "既存stagingのfollow-on lineage commitmentがlive graphと一致しません"
            )

    safety = manifest.get("safety")
    if not isinstance(safety, Mapping):
        raise CaseStagingError("case staging manifestにsafetyがありません")
    state_counts = safety.get("derived_case_state_counts")
    if (
        not isinstance(state_counts, Mapping)
        or set(state_counts) != {"complete", "partial"}
        or any(
            type(state_counts.get(state)) is not int
            or state_counts.get(state, -1) < 0
            for state in ("complete", "partial")
        )
    ):
        raise CaseStagingError("derived case状態集計が不正です")
    normalized_counts = {
        state: int(state_counts[state]) for state in ("complete", "partial")
    }
    derived_count = sum(normalized_counts.values())
    incomplete_evidence = safety.get("incomplete_follow_on_evidence_present")
    if (
        safety.get("derived_case_count") != derived_count
        or safety.get("derived_cases_complete")
        is not (normalized_counts["partial"] == 0)
        or safety.get("incomplete_derived_cases_included") is not False
        or type(incomplete_evidence) is not bool
    ):
        raise CaseStagingError("derived case状態集計とstaging安全値が一致しません")
    if (
        normalized_counts["partial"] or incomplete_evidence
    ) and not allow_partial_derived_cases:
        raise CaseStagingError(
            "derived partial／incomplete evidence stagingの再利用には明示的な許可が必要です"
        )
    externalized_documents = _validate_staged_shared_reference(
        source,
        digest=digest,
        manifest=manifest,
        allow_partial_derived_cases=allow_partial_derived_cases,
    )
    if expected_externalized_shared_reference_document is not _EXPECTED_LINEAGE_UNSET:
        if (
            expected_externalized_shared_reference_document is not None
            and not isinstance(expected_externalized_shared_reference_document, Mapping)
        ):
            raise CaseStagingError("期待externalized shared referenceの型が不正です")
        expected_shared_reference = (
            dict(expected_externalized_shared_reference_document)
            if isinstance(expected_externalized_shared_reference_document, Mapping)
            else None
        )
        observed_reference_path = source / "derived" / "shared-derived-reference.case.json"
        if expected_shared_reference is None:
            if externalized_documents or os.path.lexists(
                archive_analysis_datastore._extended_length_path(
                    observed_reference_path
                )
            ):
                raise CaseStagingError("externalized shared referenceがlive planと一致しません")
        else:
            observed_reference, _observed_reference_file_sha256 = _read_json(
                observed_reference_path,
                label="staged externalized shared reference",
            )
            if (
                observed_reference != expected_shared_reference
                or manifest.get("externalized_shared_reference_sha256")
                != _canonical_sha256(expected_shared_reference)
            ):
                raise CaseStagingError("externalized shared referenceがlive planと一致しません")

    lineage_path = source / "derived" / "follow-on-lineage.case.json"
    if not os.path.lexists(
        archive_analysis_datastore._extended_length_path(lineage_path)
    ):
        if derived_count or incomplete_evidence:
            raise CaseStagingError("derived／incomplete follow-on stagingにlineage証拠がありません")
        if expected_lineage is not _EXPECTED_LINEAGE_UNSET and expected_lineage is not None:
            raise CaseStagingError("live graphに対応するstaged follow-on lineageがありません")
        if observed_lineage_sha256 is not None:
            raise CaseStagingError("lineage fileのないstagingにlineage commitmentがあります")
        derived_root = source / "one-shot-derived"
        if os.path.lexists(
            archive_analysis_datastore._extended_length_path(derived_root)
        ):
            raise CaseStagingError("lineage証拠のないderived directoryがあります")
        return frozenset({digest, *externalized_documents})

    lineage, _lineage_sha256 = _read_json(
        lineage_path,
        label="staged follow-on lineage",
    )
    if observed_lineage_sha256 != _canonical_sha256(lineage):
        raise CaseStagingError("staged follow-on lineage commitmentが内容と一致しません")
    if expected_lineage is not _EXPECTED_LINEAGE_UNSET and lineage != expected_lineage:
        raise CaseStagingError(
            "staged follow-on lineageがlive one-shot lineageと一致しません"
        )
    raw_derived = lineage.get("derived_case_sha256s")
    raw_incomplete = lineage.get("incomplete_derived_case_sha256s")
    raw_states = lineage.get("derived_case_states")
    raw_incomplete_states = lineage.get("incomplete_derived_case_states")
    raw_counts = lineage.get("derived_case_state_counts")
    lineage_safety = lineage.get("safety")
    if (
        lineage.get("schema_version")
        != "analysis-datastore-case-follow-on-lineage/v1"
        or lineage.get("collection_id") != manifest.get("collection_id")
        or lineage.get("case_sha256") != digest
        or not isinstance(raw_derived, list)
        or not isinstance(raw_incomplete, list)
        or not isinstance(raw_states, Mapping)
        or not isinstance(raw_incomplete_states, Mapping)
        or raw_counts != normalized_counts
        or not isinstance(lineage_safety, Mapping)
        or lineage_safety.get("different_root_cases_included") is not False
        or lineage_safety.get("incomplete_derived_cases_included") is not False
        or lineage_safety.get("incomplete_follow_on_evidence_present")
        is not incomplete_evidence
        or lineage_safety.get("sample_executed") is not False
        or lineage_safety.get("network_contacted") is not False
    ):
        raise CaseStagingError("staged follow-on lineageのschemaまたは安全値が不正です")
    derived = [
        _validate_sha256(value, label="staged derived case SHA-256")
        for value in raw_derived
    ]
    incomplete = [
        _validate_sha256(value, label="staged incomplete derived case SHA-256")
        for value in raw_incomplete
    ]
    if (
        len(set(derived)) != len(derived)
        or len(set(incomplete)) != len(incomplete)
        or digest in {*derived, *incomplete}
        or set(derived) & set(incomplete)
        or bool(incomplete) is not incomplete_evidence
        or len(derived) != derived_count
        or set(raw_states) != set(derived)
        or any(raw_states[value] not in {"complete", "partial"} for value in derived)
        or set(raw_incomplete_states) != set(incomplete)
        or any(
            raw_incomplete_states[value]
            not in _FOLLOW_ON_UNMATERIALIZED_NODE_STATES
            for value in incomplete
        )
    ):
        raise CaseStagingError("staged follow-on lineageのcase集合が不正です")
    observed_counts = Counter(str(raw_states[value]) for value in derived)
    if any(
        observed_counts.get(state, 0) != normalized_counts[state]
        for state in ("complete", "partial")
    ):
        raise CaseStagingError("staged follow-on lineageのcase状態集計が一致しません")

    derived_root = source / "one-shot-derived"
    included_derived = [value for value in derived if value not in externalized_documents]
    physical_count = safety.get("physically_included_derived_case_count", derived_count)
    externalized_lineage_count = safety.get(
        "externalized_lineage_derived_case_count",
        0,
    )
    if (
        safety.get("different_cases_included") is not bool(included_derived)
        or type(physical_count) is not int
        or not 0 <= physical_count <= derived_count
        or physical_count != len(included_derived)
        or type(externalized_lineage_count) is not int
        or not 0 <= externalized_lineage_count <= derived_count
        or externalized_lineage_count
        != len(set(derived) & set(externalized_documents))
        or physical_count + externalized_lineage_count != derived_count
    ):
        raise CaseStagingError("derived caseの物理包含集計が一致しません")
    if included_derived:
        directories = _staged_derived_directories(derived_root)
        if set(directories) != set(included_derived):
            raise CaseStagingError("staged derived directory集合がlineageと一致しません")
        for child in included_derived:
            _validate_one_shot_report_identity(directories[child], digest=child)
            _validate_sealed_derived_case_state(
                directories[child],
                expected_state=str(raw_states[child]),
                allow_partial=allow_partial_derived_cases,
            )
    elif os.path.lexists(
        archive_analysis_datastore._extended_length_path(derived_root)
    ):
        raise CaseStagingError("derived caseがないstagingにderived directoryがあります")
    return frozenset((digest, *derived, *incomplete, *externalized_documents))


def reuse_case_staging(
    *,
    output_root: Path,
    collection_id: str,
    case_sha256: str,
    allow_partial_derived_cases: bool = False,
    expected_analysis_output_sha256: str | None = None,
    expected_follow_on_lineage_document: Mapping[str, Any] | None | object = (
        _EXPECTED_LINEAGE_UNSET
    ),
    expected_externalized_shared_reference_document: (
        Mapping[str, Any] | None | object
    ) = _EXPECTED_LINEAGE_UNSET,
) -> dict[str, Any]:
    """中断後に残ったowned stagingを全inventory再検証して再利用する。"""

    if not COLLECTION_RE.fullmatch(collection_id):
        raise CaseStagingError("再利用対象collection IDが不正です")
    digest = _validate_sha256(case_sha256, label="再利用対象case")
    output = _validate_existing_directory(output_root, label="case staging output root")
    target = _datastore_target(collection_id, digest)
    source = output / target
    if not os.path.lexists(
        archive_analysis_datastore._extended_length_path(source)
    ):
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
        or safety.get("sample_executed") is not False
        or safety.get("network_contacted") is not False
        or safety.get("source_deleted") is not False
    ):
        raise CaseStagingError("既存case staging manifestの束縛または安全契約が不正です")
    allowed_case_sha256s = _validate_staged_derived_policy(
        source,
        digest=digest,
        manifest=manifest,
        allow_partial_derived_cases=allow_partial_derived_cases,
        expected_analysis_output_sha256=expected_analysis_output_sha256,
        expected_follow_on_lineage_document=expected_follow_on_lineage_document,
        expected_externalized_shared_reference_document=(
            expected_externalized_shared_reference_document
        ),
    )

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
        or manifest.get("total_size_excluding_this_manifest") != sum(int(item["size"]) for item in normalized_records)
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
            observed_sha256, observed_size, _identity = archive_analysis_datastore._hash_source_snapshot(path)
        except archive_analysis_datastore.DatastoreError as exc:
            raise CaseStagingError("既存case staging fileを安全に照合できません") from exc
        if observed_size != record["size"] or observed_sha256 != record["sha256"]:
            raise CaseStagingError("既存case staging inventoryのSHA-256が一致しません")
        if _is_verified_ghidra_import(relative.as_posix()):
            suffix = ".quarantine.bin"
            expected_sha256 = relative.name[: -len(suffix)]
            if observed_sha256 != expected_sha256:
                raise CaseStagingError("既存case stagingのGhidra importがファイル名SHA-256と一致しません")
    _scan_staged_case_references(
        source,
        case_sha256=digest,
        allowed_case_sha256s=allowed_case_sha256s,
    )
    try:
        archive_files = archive_analysis_datastore.collect_source_files([source])
    except archive_analysis_datastore.DatastoreError as exc:
        raise CaseStagingError("既存case stagingをarchive helperへ渡せません") from exc
    if len(archive_files) != len(normalized_records) + 1:
        raise CaseStagingError("既存case stagingのarchive inventoryが一致しません")
    archive_records = [{"path": item.archive_name, "size": item.size, "sha256": item.sha256} for item in archive_files]
    source_tree_sha256 = _inventory_sha256(archive_records)
    reused_case = {
        "case_sha256": digest,
        "target": target,
        "source_path": os.fspath(source),
        "file_count": len(archive_files),
        "total_size": sum(item.size for item in archive_files),
        "source_tree_sha256": source_tree_sha256,
        "staging_manifest_sha256": manifest_sha256,
        "derived_case_state_counts": dict(safety["derived_case_state_counts"]),
        "follow_on_lineage_sha256": manifest.get("follow_on_lineage_sha256"),
        "archive_arguments": [
            "--target",
            target,
            "--source",
            os.fspath(source),
            "--expected-source-tree-sha256",
            source_tree_sha256,
            "--expected-file-count",
            str(len(archive_files)),
            "--expected-total-size",
            str(sum(item.size for item in archive_files)),
        ],
        "sample_executed": False,
        "network_contacted": False,
    }
    if "externalized_shared_reference_sha256" in manifest:
        reused_case["externalized_shared_reference_sha256"] = manifest[
            "externalized_shared_reference_sha256"
        ]
    return {
        "schema_version": SCHEMA_VERSION,
        "collection_id": collection_id,
        "case_count": 1,
        "reused_existing_staging": True,
        "cases": [reused_case],
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
    allow_partial_derived_cases: bool = False,
    expected_analysis_output_sha256: str | None = None,
    expected_follow_on_lineage_document: Mapping[str, Any] | None | object = (
        _EXPECTED_LINEAGE_UNSET
    ),
    expected_externalized_shared_reference_document: (
        Mapping[str, Any] | None | object
    ) = _EXPECTED_LINEAGE_UNSET,
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
    source_normal = _absolute(source_path)
    source_io = archive_analysis_datastore._extended_length_path(source_normal)
    _reject_reparse_components(source_io, label="owned case staging")
    if source_normal.parent != output or source_normal.name != target:
        raise CaseStagingError("cleanup対象がowned case staging境界外です")
    source = _validate_existing_directory(source_io, label="owned case staging")
    if (
        source.parent != archive_analysis_datastore._extended_length_path(output)
        or source.name != target
    ):
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
        or safety.get("physical_copy_only") is not True
        or safety.get("sample_executed") is not False
        or safety.get("network_contacted") is not False
        or safety.get("source_deleted") is not False
    ):
        raise CaseStagingError("cleanup対象case staging manifestの境界または安全値が不正です")
    allowed_case_sha256s = _validate_staged_derived_policy(
        source,
        digest=digest,
        manifest=staging_manifest,
        allow_partial_derived_cases=allow_partial_derived_cases,
        expected_analysis_output_sha256=expected_analysis_output_sha256,
        expected_follow_on_lineage_document=expected_follow_on_lineage_document,
        expected_externalized_shared_reference_document=(
            expected_externalized_shared_reference_document
        ),
    )

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
    _scan_staged_case_references(
        source,
        case_sha256=digest,
        allowed_case_sha256s=allowed_case_sha256s,
    )

    source_io = archive_analysis_datastore._extended_length_path(source)
    try:
        source_metadata = source_io.lstat()
    except OSError as exc:
        raise CaseStagingError("cleanup対象directory identityを固定できません") from exc
    if not stat.S_ISDIR(source_metadata.st_mode) or _is_reparse(source_metadata):
        raise CaseStagingError("cleanup対象が通常directoryではありません")
    source_identity = (source_metadata.st_dev, source_metadata.st_ino)

    tombstone = output / f".{digest[:12]}.{uuid.uuid4().hex[:12]}.verified-delete"
    tombstone_io = archive_analysis_datastore._extended_length_path(tombstone)
    if os.path.lexists(tombstone_io):
        raise CaseStagingError("owned staging cleanup用pathが既に存在します")
    try:
        os.replace(source_io, tombstone_io)
        _reject_reparse_components(tombstone_io, label="owned staging cleanup")
        tombstone_metadata = tombstone_io.lstat()
        if (
            not stat.S_ISDIR(tombstone_metadata.st_mode)
            or _is_reparse(tombstone_metadata)
            or (tombstone_metadata.st_dev, tombstone_metadata.st_ino) != source_identity
        ):
            raise CaseStagingError(f"cleanup昇格後directory identityが一致しません。保持path: {tombstone}")
        try:
            tombstone_files = archive_analysis_datastore.collect_source_files([tombstone_io])
        except archive_analysis_datastore.DatastoreError as exc:
            raise CaseStagingError(f"cleanup昇格後treeを再検証できません。保持path: {tombstone}") from exc
        tombstone_prefix = f"data/{tombstone.name}/"
        canonical_prefix = f"data/{target}/"
        if any(not item.archive_name.startswith(tombstone_prefix) for item in tombstone_files):
            raise CaseStagingError(f"cleanup昇格後archive pathを正規化できません。保持path: {tombstone}")
        tombstone_records = [
            {
                "path": canonical_prefix + item.archive_name[len(tombstone_prefix) :],
                "size": item.size,
                "sha256": item.sha256,
            }
            for item in tombstone_files
        ]
        if (
            _inventory_sha256(tombstone_records) != archive_result["source_tree_sha256"]
            or len(tombstone_files) != archive_result["file_count"]
            or sum(item.size for item in tombstone_files) != archive_result["total_size"]
        ):
            raise CaseStagingError(f"cleanup昇格後tree commitmentが一致しません。保持path: {tombstone}")
        shutil.rmtree(tombstone_io)
    except OSError as exc:
        raise CaseStagingError(f"検証済みowned stagingの削除に失敗しました。残存path: {tombstone}") from exc
    if os.path.lexists(source_io) or os.path.lexists(tombstone_io):
        raise CaseStagingError("検証済みowned stagingの削除完了を確認できません")
    return {
        "target": target,
        "case_sha256": digest,
        "removed": True,
        "source_deleted": False,
    }


def remove_externalized_shared_staging_after_verified_archive(
    *,
    output_root: Path,
    source_path: Path,
    collection_id: str,
    child_sha256: str,
    archive_result: Mapping[str, Any],
    allow_partial_derived_cases: bool,
    expected_analysis_output_sha256: str,
    expected_externalization_document: Mapping[str, Any],
) -> dict[str, Any]:
    """remote再検証済み共有archiveに対応するowned stagingだけを削除する。"""

    child = _validate_sha256(child_sha256, label="共有cleanup child")
    target = _shared_derived_target(collection_id, child)
    if (
        archive_result.get("target") != target
        or archive_result.get("status") not in {"verified", "verified_reused"}
        or archive_result.get("remote_reverified") is not True
        or any(
            SHA256_RE.fullmatch(str(archive_result.get(key))) is None
            for key in (
                "archive_sha256",
                "manifest_sha256",
                "source_tree_sha256",
                "provenance_sha256",
            )
        )
        or type(archive_result.get("file_count")) is not int
        or int(archive_result["file_count"]) <= 0
        or type(archive_result.get("total_size")) is not int
        or int(archive_result["total_size"]) <= 0
    ):
        raise CaseStagingError("remote再検証済み共有archiveをcleanup対象へ束縛できません")
    reused = reuse_externalized_shared_derived_staging(
        output_root=output_root,
        collection_id=collection_id,
        child_sha256=child,
        allow_partial_derived_cases=allow_partial_derived_cases,
        expected_analysis_output_sha256=expected_analysis_output_sha256,
        expected_externalization_document=expected_externalization_document,
    )
    for key in (
        "source_tree_sha256",
        "file_count",
        "total_size",
        "provenance_sha256",
        "externalization_document_sha256",
    ):
        if archive_result.get(key) != reused.get(key):
            raise CaseStagingError("共有archive receiptとowned staging commitmentが一致しません")

    output = _validate_existing_directory(output_root, label="共有cleanup output root")
    source_normal = _absolute(source_path)
    source_io = archive_analysis_datastore._extended_length_path(source_normal)
    expected_source_io = archive_analysis_datastore._extended_length_path(
        _absolute(Path(str(reused["source_path"])))
    )
    if (
        os.path.normcase(os.fspath(source_io))
        != os.path.normcase(os.fspath(expected_source_io))
        or source_normal.parent != output
        or source_normal.name != target
    ):
        raise CaseStagingError("共有cleanup対象がowned staging境界外です")
    source = _validate_existing_directory(
        source_io,
        label="共有cleanup owned staging",
    )
    metadata = source.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or _is_reparse(metadata):
        raise CaseStagingError("共有cleanup対象が通常directoryではありません")
    identity = (metadata.st_dev, metadata.st_ino)
    tombstone = output / f".shared-{child[:12]}.{uuid.uuid4().hex[:12]}.verified-delete"
    tombstone_io = archive_analysis_datastore._extended_length_path(tombstone)
    if os.path.lexists(tombstone_io):
        raise CaseStagingError("共有cleanup tombstoneが既に存在します")
    try:
        os.replace(source, tombstone_io)
        _reject_reparse_components(tombstone_io, label="共有owned staging cleanup")
        moved = tombstone_io.lstat()
        if (
            not stat.S_ISDIR(moved.st_mode)
            or _is_reparse(moved)
            or (moved.st_dev, moved.st_ino) != identity
        ):
            raise CaseStagingError(
                f"共有cleanup昇格後identityが一致しません。保持path: {tombstone}"
            )
        tombstone_files = archive_analysis_datastore.collect_source_files([tombstone_io])
        old_prefix = f"data/{tombstone.name}/"
        canonical_prefix = f"data/{target}/"
        if any(not item.archive_name.startswith(old_prefix) for item in tombstone_files):
            raise CaseStagingError(
                f"共有cleanup後archive pathを正規化できません。保持path: {tombstone}"
            )
        records = [
            {
                "path": canonical_prefix + item.archive_name[len(old_prefix) :],
                "size": item.size,
                "sha256": item.sha256,
            }
            for item in tombstone_files
        ]
        if (
            _inventory_sha256(records) != archive_result["source_tree_sha256"]
            or len(tombstone_files) != archive_result["file_count"]
            or sum(item.size for item in tombstone_files) != archive_result["total_size"]
        ):
            raise CaseStagingError(
                f"共有cleanup後tree commitmentが一致しません。保持path: {tombstone}"
            )
        shutil.rmtree(tombstone_io)
    except (archive_analysis_datastore.DatastoreError, OSError) as exc:
        raise CaseStagingError(
            f"検証済み共有stagingの削除に失敗しました。残存path: {tombstone}"
        ) from exc
    if os.path.lexists(archive_analysis_datastore._extended_length_path(source_path)) or os.path.lexists(tombstone_io):
        raise CaseStagingError("検証済み共有stagingの削除完了を確認できません")
    return {
        "target": target,
        "child_sha256": child,
        "removed": True,
        "source_deleted": False,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", required=True, type=Path)
    parser.add_argument("--collection-id", required=True)
    parser.add_argument("--source-root", required=True, type=Path)
    parser.add_argument("--one-shot-root", required=True, type=Path)
    ghidra = parser.add_mutually_exclusive_group(required=True)
    ghidra.add_argument("--ghidra-root", type=Path)
    ghidra.add_argument(
        "--ghidra-not-requested",
        action="store_true",
        help="Ghidraを明示的に実行しないrunとしてsourceとone-shotだけを分離します",
    )
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
        if arguments.ghidra_not_requested:
            result = stage_cases_without_ghidra(
                repository=arguments.repository,
                collection_id=arguments.collection_id,
                source_root=arguments.source_root,
                one_shot_root=arguments.one_shot_root,
                output_root=arguments.output_root,
                case_sha256s=[arguments.case_sha256],
            )
        else:
            if arguments.ghidra_root is None:
                raise CaseStagingError("--ghidra-rootがありません")
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
