#!/usr/bin/env python3
"""リポジトリ外の解析データを対象別に暗号化し、S3へ安全に保管する。"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from typing import Any, Sequence

import pyzipper


DEFAULT_BUCKET = "malware-analysis-datastore-720232834682"
DEFAULT_PREFIX = "analysis-targets"
DEFAULT_REGION = "us-east-1"
DEFAULT_PASSWORD = b"infected"
MANIFEST_NAME = "_analysis_datastore_manifest.json"
SCHEMA_VERSION = "analysis-datastore-manifest/v1"
TARGET_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,127}\Z")
PREFIX_PART_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
FILE_ATTRIBUTE_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
FORBIDDEN_HOST_CREDENTIAL_NAMES = frozenset(
    {
        ".env",
        "credentials",
        "credentials.json",
        "creds.txt",
        "id_ed25519",
        "id_rsa",
        "known_hosts",
        "secrets.json",
    }
)


@dataclass(frozen=True)
class SourceFile:
    """ZIPへ格納する1ファイルの検証済み情報。"""

    source: Path
    archive_name: str
    size: int
    sha256: str


class DatastoreError(RuntimeError):
    """解析データ保管処理を安全に継続できない場合の例外。"""


def sha256_file(path: Path) -> str:
    """ファイルをメモリへ全読込みせずSHA-256を計算する。"""

    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _is_reparse_point(path: Path) -> bool:
    metadata = path.lstat()
    return path.is_symlink() or bool(getattr(metadata, "st_file_attributes", 0) & FILE_ATTRIBUTE_REPARSE_POINT)


def _reject_reparse_components(path: Path) -> None:
    absolute = Path(os.path.abspath(os.fspath(path)))
    parts = absolute.parts
    if not parts:
        raise DatastoreError("source pathが空です")
    current = Path(parts[0])
    for part in parts[1:]:
        current /= part
        if not current.exists():
            break
        if _is_reparse_point(current):
            raise DatastoreError(f"reparse pointは保管対象にできません: {current}")


def _validate_member_name(name: str) -> str:
    pure = PurePosixPath(name)
    if pure.is_absolute() or not pure.parts:
        raise DatastoreError(f"安全でないZIP member名です: {name}")
    if any(part in {"", ".", ".."} for part in pure.parts):
        raise DatastoreError(f"安全でないZIP member名です: {name}")
    if any(":" in part or "\\" in part or ord(character) < 32 for part in pure.parts for character in part):
        raise DatastoreError(f"安全でないZIP member名です: {name}")
    return pure.as_posix()


def validate_target(target: str) -> str:
    """S3 keyとmanifestへ使える解析対象識別子を検証する。"""

    if not TARGET_RE.fullmatch(target):
        raise DatastoreError("targetは小文字英数字で開始し、小文字英数字・`.`・`_`・`-`のみ、128文字以下にしてください")
    return target


def validate_prefix(prefix: str) -> str:
    """階層を許可しつつ、S3 key prefixの脱出表現を拒否する。"""

    normalized = prefix.strip("/")
    parts = normalized.split("/") if normalized else []
    if not parts or any(not PREFIX_PART_RE.fullmatch(part) for part in parts):
        raise DatastoreError("prefixに安全でない文字またはpath componentがあります")
    return "/".join(parts)


def _reject_host_credential_name(relative: PurePosixPath) -> None:
    for part in relative.parts:
        lowered = part.lower()
        if lowered in FORBIDDEN_HOST_CREDENTIAL_NAMES or lowered.startswith("github_pat_"):
            raise DatastoreError(f"ホスト資格情報の可能性があるため保管対象を拒否しました: {relative.as_posix()}")


def _walk_directory(root: Path) -> list[tuple[Path, PurePosixPath]]:
    results: list[tuple[Path, PurePosixPath]] = []
    stack: list[tuple[Path, PurePosixPath]] = [(root, PurePosixPath())]
    while stack:
        directory, relative_directory = stack.pop()
        with os.scandir(directory) as entries:
            for entry in sorted(entries, key=lambda item: item.name.casefold(), reverse=True):
                path = Path(entry.path)
                relative = relative_directory / entry.name
                metadata = entry.stat(follow_symlinks=False)
                if entry.is_symlink() or bool(
                    getattr(metadata, "st_file_attributes", 0) & FILE_ATTRIBUTE_REPARSE_POINT
                ):
                    raise DatastoreError(f"reparse pointは保管対象にできません: {path}")
                if stat.S_ISDIR(metadata.st_mode):
                    stack.append((path, relative))
                elif stat.S_ISREG(metadata.st_mode):
                    results.append((path, relative))
                else:
                    raise DatastoreError(f"通常ファイル以外は保管対象にできません: {path}")
    return sorted(results, key=lambda item: item[1].as_posix().casefold())


def collect_source_files(sources: Sequence[Path]) -> list[SourceFile]:
    """sourceを列挙し、暗号化ZIPへ格納する相対名とハッシュを確定する。"""

    if not sources:
        raise DatastoreError("少なくとも1つのsourceが必要です")
    top_level_names: set[str] = set()
    archive_names: set[str] = {MANIFEST_NAME.casefold()}
    collected: list[SourceFile] = []
    for supplied in sources:
        source = Path(os.path.abspath(os.fspath(supplied)))
        if not source.exists():
            raise DatastoreError(f"sourceが存在しません: {source}")
        _reject_reparse_components(source)
        if _is_reparse_point(source):
            raise DatastoreError(f"reparse pointは保管対象にできません: {source}")
        root_name = source.name
        root_key = root_name.casefold()
        if root_key in top_level_names:
            raise DatastoreError(f"sourceの最上位名が重複しています: {root_name}")
        top_level_names.add(root_key)

        if source.is_file():
            members = [(source, PurePosixPath(root_name))]
        elif source.is_dir():
            members = _walk_directory(source)
        else:
            raise DatastoreError(f"sourceは通常ファイルまたはdirectoryではありません: {source}")

        for path, relative in members:
            archive_relative = PurePosixPath("data") / root_name
            if source.is_dir():
                archive_relative /= relative
            _reject_host_credential_name(archive_relative)
            archive_name = _validate_member_name(archive_relative.as_posix())
            archive_key = archive_name.casefold()
            if archive_key in archive_names:
                raise DatastoreError(f"ZIP member名が重複しています: {archive_name}")
            archive_names.add(archive_key)
            metadata_before = path.stat(follow_symlinks=False)
            digest = sha256_file(path)
            metadata_after = path.stat(follow_symlinks=False)
            if (
                metadata_before.st_size != metadata_after.st_size
                or metadata_before.st_mtime_ns != metadata_after.st_mtime_ns
            ):
                raise DatastoreError(f"ハッシュ計算中にsourceが変更されました: {path}")
            collected.append(
                SourceFile(
                    source=path,
                    archive_name=archive_name,
                    size=metadata_after.st_size,
                    sha256=digest,
                )
            )
    return sorted(collected, key=lambda item: item.archive_name.casefold())


def build_manifest(
    *,
    target: str,
    created_at: datetime,
    files: Sequence[SourceFile],
) -> dict[str, Any]:
    """絶対pathやホスト情報を含めない暗号化manifestを生成する。"""

    return {
        "schema_version": SCHEMA_VERSION,
        "target": validate_target(target),
        "created_at_utc": created_at.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
        "archive": {
            "format": "zip",
            "encryption": "WinZip AES-256",
            "password_convention": "infected",
        },
        "file_count": len(files),
        "total_uncompressed_size": sum(item.size for item in files),
        "files": [
            {
                "path": item.archive_name,
                "size": item.size,
                "sha256": item.sha256,
            }
            for item in files
        ],
    }


def manifest_bytes(manifest: dict[str, Any]) -> bytes:
    return (json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")


def create_encrypted_archive(
    archive_path: Path,
    files: Sequence[SourceFile],
    manifest: dict[str, Any],
    *,
    password: bytes = DEFAULT_PASSWORD,
) -> None:
    """全memberをAES-256で暗号化した新規ZIPを排他作成する。"""

    if archive_path.exists():
        raise DatastoreError(f"既存archiveを上書きしません: {archive_path}")
    archive_path.parent.mkdir(parents=True, exist_ok=True)
    with archive_path.open("xb") as output:
        with pyzipper.AESZipFile(
            output,
            "w",
            compression=pyzipper.ZIP_DEFLATED,
            encryption=pyzipper.WZ_AES,
            allowZip64=True,
        ) as archive:
            archive.setpassword(password)
            archive.setencryption(pyzipper.WZ_AES, nbits=256)
            archive.writestr(MANIFEST_NAME, manifest_bytes(manifest))
            for item in files:
                metadata_before = item.source.stat(follow_symlinks=False)
                archive.write(item.source, arcname=item.archive_name)
                metadata_after = item.source.stat(follow_symlinks=False)
                if (
                    metadata_before.st_size != item.size
                    or metadata_after.st_size != item.size
                    or metadata_before.st_mtime_ns != metadata_after.st_mtime_ns
                ):
                    raise DatastoreError(f"archive作成中にsourceが変更されました: {item.source}")


def verify_encrypted_archive(
    archive_path: Path,
    files: Sequence[SourceFile],
    manifest: dict[str, Any],
    *,
    password: bytes = DEFAULT_PASSWORD,
) -> None:
    """復号後の全memberを再ハッシュし、manifestと一致することを確認する。"""

    expected_names = {MANIFEST_NAME, *(item.archive_name for item in files)}
    with pyzipper.AESZipFile(archive_path, "r") as archive:
        archive.setpassword(password)
        observed_names = set(archive.namelist())
        if observed_names != expected_names:
            raise DatastoreError("archive member一覧が作成時のinventoryと一致しません")
        observed_manifest = json.loads(archive.read(MANIFEST_NAME).decode("utf-8"))
        if observed_manifest != manifest:
            raise DatastoreError("archive内manifestが作成時の内容と一致しません")
        for item in files:
            digest = hashlib.sha256()
            size = 0
            with archive.open(item.archive_name, "r") as member:
                while chunk := member.read(1024 * 1024):
                    digest.update(chunk)
                    size += len(chunk)
            if size != item.size or digest.hexdigest() != item.sha256:
                raise DatastoreError(f"archive内memberの検証に失敗しました: {item.archive_name}")


def find_aws_cli(explicit: Path | None = None) -> Path:
    """PATHとWindows既定先からAWS CLI v2を検出する。"""

    candidates: list[Path] = []
    if explicit is not None:
        candidates.append(explicit)
    discovered = shutil.which("aws")
    if discovered:
        candidates.append(Path(discovered))
    candidates.append(Path(r"C:\Program Files\Amazon\AWSCLIV2\aws.exe"))
    for candidate in candidates:
        absolute = Path(os.path.abspath(os.fspath(candidate)))
        if absolute.is_file():
            return absolute
    raise DatastoreError("AWS CLI v2が見つかりません")


def _run_aws(
    aws_cli: Path,
    arguments: Sequence[str],
    *,
    expect_json: bool = False,
) -> Any:
    command = [os.fspath(aws_cli), *arguments, "--no-cli-pager"]
    completed = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", errors="replace")
    if completed.returncode != 0:
        message = completed.stderr.strip() or completed.stdout.strip() or "詳細なし"
        raise DatastoreError(f"AWS CLIが失敗しました: {message}")
    if not expect_json:
        return completed.stdout
    try:
        return json.loads(completed.stdout or "{}")
    except json.JSONDecodeError as exc:
        raise DatastoreError("AWS CLIのJSON応答を解析できません") from exc


def build_s3_key(prefix: str, target: str, created_at: datetime, archive_name: str) -> str:
    """対象別・年月別のS3 object keyを生成する。"""

    validated_prefix = validate_prefix(prefix)
    validated_target = validate_target(target)
    utc = created_at.astimezone(timezone.utc)
    return f"{validated_prefix}/{validated_target}/{utc:%Y/%m}/{archive_name}"


def build_upload_command(
    *,
    aws_cli: Path,
    archive_path: Path,
    bucket: str,
    key: str,
    region: str,
    archive_sha256: str,
    manifest_sha256: str,
    target: str,
) -> list[str]:
    """SSE-S3と検証用metadataを付けるAWS CLI upload commandを構築する。"""

    metadata = (
        f"archive-sha256={archive_sha256},manifest-sha256={manifest_sha256},analysis-target={validate_target(target)}"
    )
    return [
        os.fspath(aws_cli),
        "s3",
        "cp",
        os.fspath(archive_path),
        f"s3://{bucket}/{key}",
        "--region",
        region,
        "--sse",
        "AES256",
        "--checksum-algorithm",
        "SHA256",
        "--metadata",
        metadata,
        "--only-show-errors",
        "--no-progress",
        "--no-cli-pager",
    ]


def _assert_object_absent(aws_cli: Path, *, bucket: str, key: str, region: str) -> None:
    command = [
        os.fspath(aws_cli),
        "s3api",
        "head-object",
        "--bucket",
        bucket,
        "--key",
        key,
        "--region",
        region,
        "--no-cli-pager",
    ]
    completed = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", errors="replace")
    if completed.returncode == 0:
        raise DatastoreError(f"既存S3 objectを上書きしません: s3://{bucket}/{key}")
    message = f"{completed.stderr}\n{completed.stdout}".lower()
    if "404" not in message and "not found" not in message and "nosuchkey" not in message:
        raise DatastoreError("S3 objectの上書き有無を確認できません: " + completed.stderr.strip())


def verify_head_object(
    response: dict[str, Any],
    *,
    expected_size: int,
    archive_sha256: str,
    manifest_sha256: str,
    target: str,
) -> None:
    """S3側のsize、SSE-S3、検証用metadataを照合する。"""

    metadata = {str(key).lower(): str(value) for key, value in response.get("Metadata", {}).items()}
    failures: list[str] = []
    if response.get("ContentLength") != expected_size:
        failures.append("ContentLength")
    if response.get("ServerSideEncryption") != "AES256":
        failures.append("ServerSideEncryption")
    if metadata.get("archive-sha256") != archive_sha256:
        failures.append("archive-sha256")
    if metadata.get("manifest-sha256") != manifest_sha256:
        failures.append("manifest-sha256")
    if metadata.get("analysis-target") != target:
        failures.append("analysis-target")
    if failures:
        raise DatastoreError("S3 upload後検証に失敗しました: " + ", ".join(failures))


def upload_archive(
    *,
    aws_cli: Path,
    archive_path: Path,
    bucket: str,
    key: str,
    region: str,
    archive_sha256: str,
    manifest_sha256: str,
    target: str,
) -> dict[str, Any]:
    """IAMロールを確認してuploadし、HeadObjectで結果を検証する。"""

    identity = _run_aws(
        aws_cli,
        ["sts", "get-caller-identity", "--region", region, "--output", "json"],
        expect_json=True,
    )
    _run_aws(
        aws_cli,
        ["s3api", "head-bucket", "--bucket", bucket, "--region", region, "--output", "json"],
    )
    _assert_object_absent(aws_cli, bucket=bucket, key=key, region=region)
    command = build_upload_command(
        aws_cli=aws_cli,
        archive_path=archive_path,
        bucket=bucket,
        key=key,
        region=region,
        archive_sha256=archive_sha256,
        manifest_sha256=manifest_sha256,
        target=target,
    )
    completed = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", errors="replace")
    if completed.returncode != 0:
        message = completed.stderr.strip() or completed.stdout.strip() or "詳細なし"
        raise DatastoreError(f"S3 uploadに失敗しました: {message}")
    response = _run_aws(
        aws_cli,
        [
            "s3api",
            "head-object",
            "--bucket",
            bucket,
            "--key",
            key,
            "--region",
            region,
            "--output",
            "json",
        ],
        expect_json=True,
    )
    verify_head_object(
        response,
        expected_size=archive_path.stat().st_size,
        archive_sha256=archive_sha256,
        manifest_sha256=manifest_sha256,
        target=target,
    )
    return {
        "account": str(identity.get("Account", "")),
        "role_arn": str(identity.get("Arn", "")),
        "etag": str(response.get("ETag", "")).strip('"'),
        "server_side_encryption": response.get("ServerSideEncryption"),
    }


def _write_report(path: Path, report: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="解析対象別のAES-256 ZIPを作成し、AWS CLIでS3へ保管します。",
    )
    parser.add_argument("--target", required=True, help="小文字英数字中心の解析対象識別子")
    parser.add_argument(
        "--source", type=Path, action="append", required=True, help="保管するfileまたはdirectory。複数指定可"
    )
    parser.add_argument("--bucket", default=DEFAULT_BUCKET, help="保存先S3 bucket")
    parser.add_argument("--prefix", default=DEFAULT_PREFIX, help="S3 object key prefix")
    parser.add_argument("--region", default=DEFAULT_REGION, help="S3 bucketのAWS region")
    parser.add_argument("--aws-cli", type=Path, help="aws.exeの明示path")
    parser.add_argument("--report", type=Path, help="機密情報を含まないupload reportの保存先")
    parser.add_argument("--keep-local-archive", action="store_true", help="成功後も暗号化ZIPをstagingに残す")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    target = validate_target(args.target)
    prefix = validate_prefix(args.prefix)
    created_at = datetime.now(timezone.utc)
    files = collect_source_files(args.source)
    manifest = build_manifest(target=target, created_at=created_at, files=files)
    manifest_payload = manifest_bytes(manifest)
    manifest_sha256 = hashlib.sha256(manifest_payload).hexdigest()
    timestamp = created_at.strftime("%Y%m%dT%H%M%SZ")
    archive_name = f"{target}-{timestamp}-{manifest_sha256[:12]}.zip"
    staging = Path(tempfile.mkdtemp(prefix=f"analysis-datastore-{target[:32]}-"))
    archive_path = staging / archive_name
    success = False
    try:
        create_encrypted_archive(archive_path, files, manifest)
        verify_encrypted_archive(archive_path, files, manifest)
        archive_sha256 = sha256_file(archive_path)
        key = build_s3_key(prefix, target, created_at, archive_name)
        aws_cli = find_aws_cli(args.aws_cli)
        s3 = upload_archive(
            aws_cli=aws_cli,
            archive_path=archive_path,
            bucket=args.bucket,
            key=key,
            region=args.region,
            archive_sha256=archive_sha256,
            manifest_sha256=manifest_sha256,
            target=target,
        )
        report = {
            "schema_version": "analysis-datastore-upload-report/v1",
            "status": "verified",
            "target": target,
            "created_at_utc": manifest["created_at_utc"],
            "object_uri": f"s3://{args.bucket}/{key}",
            "archive_sha256": archive_sha256,
            "manifest_sha256": manifest_sha256,
            "archive_size": archive_path.stat().st_size,
            "file_count": manifest["file_count"],
            "total_uncompressed_size": manifest["total_uncompressed_size"],
            "s3_verification": s3,
            "local_source_deleted": False,
            "local_archive_retained": bool(args.keep_local_archive),
        }
        if args.report:
            _write_report(args.report, report)
        print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
        success = True
        return 0
    except BaseException:
        print(f"保管処理に失敗したためstagingを保持します: {staging}", file=sys.stderr)
        raise
    finally:
        if success and not args.keep_local_archive:
            shutil.rmtree(staging)


if __name__ == "__main__":
    raise SystemExit(main())
