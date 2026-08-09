#!/usr/bin/env python3
"""AgentTesla/RemcosRAT一括静的解析をcross-platformで安全に起動する。"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
import tempfile
import uuid
from pathlib import Path, PureWindowsPath
from typing import Any

from invoke_analysis import (
    FRAMEWORK_ROOT,
    JapaneseArgumentParser,
    OrchestrationError,
    load_json_object,
    resolve_python,
    run_python,
)

FAMILIES = ("agenttesla", "remcosrat")
FIXED_ARCHIVE_PASSWORD = "infected"
AUTOMATIC_ATTRIBUTION_BASES = frozenset({"known_outer_sha256", "known_inner_sha256", "type_detector_structure"})
AUTOMATIC_CONFIDENCE_LEVELS = frozenset({"high", "medium"})
_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")
_REPARSE_POINT = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
MAX_EXISTING_OUTPUT_ENTRIES = 100_000
SUMMARY_SCHEMA_VERSION = 2
CASE_LOCK_NAME = ".analysis-lock"


def _entry_exists(path: Path) -> bool:
    """broken symlinkを含め、path entryが存在するかをlstatで返す。"""

    try:
        path.lstat()
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise OrchestrationError(f"pathを検査できません: {path}") from exc
    return True


def _is_symlink_or_reparse(path: Path) -> bool:
    """Windows junctionを含むsymlink/reparse pointかどうかを返す。"""

    try:
        information = path.lstat()
    except OSError as exc:
        raise OrchestrationError(f"pathを検査できません: {path}") from exc
    attributes = int(getattr(information, "st_file_attributes", 0))
    return path.is_symlink() or bool(attributes & _REPARSE_POINT)


def _ensure_contained(path: Path, root: Path, *, label: str) -> Path:
    """既存pathの解決先をroot内へ限定する。"""

    try:
        resolved = path.resolve(strict=True)
        resolved.relative_to(root.resolve(strict=True))
    except (OSError, ValueError) as exc:
        raise OrchestrationError(f"{label}が許可root外です: {path}") from exc
    return resolved


def validate_case_directory(case_directory: Path, *, sample_root: Path) -> tuple[Path, Path]:
    """lowercase SHA-256 caseと通常ZIPをsymlinkなしで検証する。"""

    if not _SHA256_PATTERN.fullmatch(case_directory.name):
        raise OrchestrationError(f"case directory名はlowercase SHA-256である必要があります: {case_directory.name}")
    if not _entry_exists(case_directory):
        raise OrchestrationError(f"case directoryがありません: {case_directory}")
    if _is_symlink_or_reparse(case_directory):
        raise OrchestrationError(f"case directoryにsymlink/junctionは使用できません: {case_directory}")
    try:
        if not stat.S_ISDIR(case_directory.lstat().st_mode):
            raise OrchestrationError(f"case pathがdirectoryではありません: {case_directory}")
    except OSError as exc:
        raise OrchestrationError(f"case directoryを検査できません: {case_directory}") from exc
    case = _ensure_contained(case_directory, sample_root, label="case directory")
    archive = case / f"{case.name}.zip"
    if not _entry_exists(archive):
        raise OrchestrationError(f"期待する検体ZIPがありません: {archive}")
    if _is_symlink_or_reparse(archive):
        raise OrchestrationError(f"検体ZIPにsymlink/reparse pointは使用できません: {archive}")
    try:
        if not stat.S_ISREG(archive.lstat().st_mode):
            raise OrchestrationError(f"検体ZIPが通常fileではありません: {archive}")
    except OSError as exc:
        raise OrchestrationError(f"検体ZIPを検査できません: {archive}") from exc
    return case, _ensure_contained(archive, case, label="検体ZIP")


def sha256_file(path: Path) -> str:
    """通常fileをstream処理してSHA-256を返す。"""

    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as exc:
        raise OrchestrationError(f"検体ZIPのSHA-256を計算できません: {path}") from exc
    return digest.hexdigest()


def _stat_identity(information: os.stat_result) -> tuple[int, int, int, int]:
    """file差し替え検知に使う安定したidentityを返す。"""

    return (
        int(information.st_dev),
        int(information.st_ino),
        int(information.st_size),
        int(information.st_mtime_ns),
    )


def materialize_archive_snapshot(archive: Path) -> tuple[Path, Path, str]:
    """外装ZIPを専用temp directoryへ1回だけcopyし、全stage用の不変入力にする。"""

    try:
        directory = Path(tempfile.mkdtemp(prefix="asa-family-input-"))
    except OSError as exc:
        raise OrchestrationError("検体snapshot用temp directoryを作成できません。") from exc
    snapshot = directory / "outer.zip"
    descriptor: int | None = None
    try:
        before = archive.lstat()
        if _is_symlink_or_reparse(archive) or not stat.S_ISREG(before.st_mode) or before.st_nlink > 1:
            raise OrchestrationError("検体ZIPはsymlink/reparse/hardlinkでない通常fileが必要です。")
        with archive.open("rb") as source:
            opened = os.fstat(source.fileno())
            if not stat.S_ISREG(opened.st_mode) or _stat_identity(opened) != _stat_identity(before):
                raise OrchestrationError("検体ZIPがopen前に差し替えられました。")
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | int(getattr(os, "O_BINARY", 0))
            descriptor = os.open(snapshot, flags, 0o600)
            digest = hashlib.sha256()
            copied = 0
            with os.fdopen(descriptor, "wb") as destination:
                descriptor = None
                for chunk in iter(lambda: source.read(1024 * 1024), b""):
                    digest.update(chunk)
                    destination.write(chunk)
                    copied += len(chunk)
            opened_after = os.fstat(source.fileno())
        after = archive.lstat()
        expected_identity = _stat_identity(before)
        if _stat_identity(opened_after) != expected_identity or _stat_identity(after) != expected_identity:
            raise OrchestrationError("検体ZIPがsnapshot作成中に変更または差し替えられました。")
        snapshot_information = snapshot.lstat()
        if (
            _is_symlink_or_reparse(snapshot)
            or not stat.S_ISREG(snapshot_information.st_mode)
            or snapshot_information.st_nlink != 1
            or snapshot_information.st_size != copied
        ):
            raise OrchestrationError("検体snapshotのfile identityが不正です。")
        return directory, snapshot, digest.hexdigest()
    except BaseException as exc:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
        try:
            if _entry_exists(snapshot):
                snapshot.unlink()
            directory.rmdir()
        except OSError as cleanup_exc:
            raise OrchestrationError(f"検体snapshot作成失敗後のcleanupにも失敗しました: {cleanup_exc}") from exc
        raise


def verify_archive_snapshot(snapshot: Path, expected_sha256: str) -> None:
    """全stage終了後もsnapshot byte列が変化していないことを確認する。"""

    if not _entry_exists(snapshot) or _is_symlink_or_reparse(snapshot):
        raise OrchestrationError("検体snapshotが消失または差し替えられました。")
    information = snapshot.lstat()
    if not stat.S_ISREG(information.st_mode) or information.st_nlink != 1:
        raise OrchestrationError("検体snapshotが通常の単一link fileではありません。")
    if sha256_file(snapshot) != expected_sha256:
        raise OrchestrationError("検体snapshotが解析中に変更されました。")


def remove_archive_snapshot(directory: Path, snapshot: Path, original_error: BaseException | None = None) -> None:
    """snapshot 1 fileと専用temp directoryだけを安全に削除する。"""

    try:
        if _entry_exists(snapshot):
            if _is_symlink_or_reparse(snapshot):
                raise OrchestrationError("cleanup対象snapshotがsymlink/reparse pointへ変化しました。")
            information = snapshot.lstat()
            if not stat.S_ISREG(information.st_mode) or information.st_nlink != 1:
                raise OrchestrationError("cleanup対象snapshotが通常の単一link fileではありません。")
            snapshot.unlink()
        if not _entry_exists(directory) or _is_symlink_or_reparse(directory):
            raise OrchestrationError("snapshot temp directoryが消失または差し替えられました。")
        directory.rmdir()
    except BaseException as cleanup_exc:
        if isinstance(cleanup_exc, OrchestrationError):
            details = str(cleanup_exc)
        else:
            details = f"{type(cleanup_exc).__name__}: {cleanup_exc}"
        raise OrchestrationError(f"検体snapshotをcleanupできません: {details}") from original_error


def acquire_case_lock(case_directory: Path) -> Path:
    """case単位の排他directoryをatomicに作成し、同時実行を拒否する。"""

    lock = case_directory / CASE_LOCK_NAME
    try:
        lock.mkdir(mode=0o700)
    except FileExistsError as exc:
        raise OrchestrationError(f"case lockが既に存在します。同時実行または未確認のstale lockです: {lock}") from exc
    except OSError as exc:
        raise OrchestrationError(f"case lockを作成できません: {lock}") from exc
    try:
        if _is_symlink_or_reparse(lock) or not stat.S_ISDIR(lock.lstat().st_mode):
            raise OrchestrationError("作成したcase lockのidentityが不正です。")
        return lock
    except BaseException as exc:
        try:
            lock.rmdir()
        except OSError:
            pass
        raise exc


def release_case_lock(lock: Path, original_error: BaseException | None = None) -> None:
    """自身が作成した空のcase lockだけを解除する。"""

    try:
        if not _entry_exists(lock) or _is_symlink_or_reparse(lock):
            raise OrchestrationError("case lockが消失または差し替えられました。")
        if not stat.S_ISDIR(lock.lstat().st_mode):
            raise OrchestrationError("case lockがdirectoryではありません。")
        lock.rmdir()
    except BaseException as cleanup_exc:
        if isinstance(cleanup_exc, OrchestrationError):
            details = str(cleanup_exc)
        else:
            details = f"{type(cleanup_exc).__name__}: {cleanup_exc}"
        raise OrchestrationError(f"case lockを解除できません: {details}") from original_error


def authenticate_existing_summary(
    summary: dict[str, Any],
    *,
    case_name: str,
    family: str,
    outer_sha256: str,
) -> None:
    """rollback対象の旧成果が同じ入力で完了したschema 2成果かを検証する。"""

    if summary.get("schema_version") != SUMMARY_SCHEMA_VERSION:
        raise OrchestrationError("既存analysis-outputのsummary schemaが未対応です。")
    expected = {
        "sample_sha256": case_name,
        "outer_sha256": outer_sha256,
        "member_sha256": case_name,
        "family": family,
    }
    for key, value in expected.items():
        if summary.get(key) != value:
            raise OrchestrationError(f"既存analysis-outputのsummary field {key!r}が一致しません。")
    if summary.get("executed") is not False or summary.get("network_contacted") is not False:
        raise OrchestrationError("既存analysis-outputの実行・通信flagが不正です。")
    member_type = summary.get("member_type")
    campaign_type = summary.get("campaign_type")
    completed = summary.get("completed_stages")
    if not isinstance(member_type, str) or not member_type.strip():
        raise OrchestrationError("既存analysis-outputのmember_typeが不正です。")
    if not isinstance(campaign_type, str) or not campaign_type.strip() or campaign_type.strip().casefold() == "unknown":
        raise OrchestrationError("既存analysis-outputのcampaign_typeが不正です。")
    if (
        not isinstance(completed, list)
        or completed[:2] != ["triage", "classification"]
        or any(not isinstance(stage, str) or not stage for stage in completed)
        or len(completed) != len(set(completed))
    ):
        raise OrchestrationError("既存analysis-outputのcompleted_stagesが不正です。")


def _validate_existing_output_tree(output: Path) -> None:
    """既存成果treeのsymlink/reparse、hardlink、特殊fileを拒否する。"""

    pending = [output]
    visited = 0
    while pending:
        current = pending.pop()
        visited += 1
        if visited > MAX_EXISTING_OUTPUT_ENTRIES:
            raise OrchestrationError(f"既存analysis-outputは最大{MAX_EXISTING_OUTPUT_ENTRIES} entryです。")
        if _is_symlink_or_reparse(current):
            raise OrchestrationError(f"既存analysis-outputにsymlink/reparse pointがあります: {current}")
        try:
            information = current.lstat()
        except OSError as exc:
            raise OrchestrationError(f"既存analysis-outputを検査できません: {current}") from exc
        if stat.S_ISDIR(information.st_mode):
            try:
                pending.extend(current.iterdir())
            except OSError as exc:
                raise OrchestrationError(f"既存analysis-outputを列挙できません: {current}") from exc
        elif not stat.S_ISREG(information.st_mode):
            raise OrchestrationError(f"既存analysis-outputに通常file以外があります: {current}")
        elif information.st_nlink > 1:
            raise OrchestrationError(f"既存analysis-outputにhardlinkがあります: {current}")


def prepare_output_directory(
    case_directory: Path,
    *,
    family: str,
    outer_sha256: str,
) -> tuple[Path, Path | None]:
    """認証済み旧成果を原子的に退避し、fresh outputを作成する。"""

    output = case_directory / "analysis-output"
    previous: Path | None = None
    if _entry_exists(output):
        _validate_existing_output_tree(output)
        if not stat.S_ISDIR(output.lstat().st_mode):
            raise OrchestrationError(f"analysis-outputがdirectoryではありません: {output}")
        summary_path = output / "batch-run-summary.json"
        if not _entry_exists(summary_path):
            raise OrchestrationError("既存analysis-outputに認証可能なbatch-run-summary.jsonがありません。")
        summary = load_json_object(summary_path, label=f"{case_directory.name}の既存batch summary")
        authenticate_existing_summary(
            summary,
            case_name=case_directory.name,
            family=family,
            outer_sha256=outer_sha256,
        )
        previous = case_directory / f".analysis-output-previous-{uuid.uuid4().hex}"
        if _entry_exists(previous):
            raise OrchestrationError(f"旧成果の退避先が既に存在します: {previous}")
        try:
            output.rename(previous)
        except OSError as exc:
            raise OrchestrationError("既存analysis-outputを原子的に退避できません。") from exc
    try:
        output.mkdir()
    except OSError as exc:
        if previous is not None:
            try:
                previous.rename(output)
            except OSError as restore_exc:
                raise OrchestrationError(
                    f"fresh analysis-output作成と旧成果復元の両方に失敗しました: {exc}; {restore_exc}"
                ) from exc
        raise OrchestrationError(f"fresh analysis-outputを作成できません: {output}") from exc
    return _ensure_contained(output, case_directory, label="analysis-output"), previous


def rollback_output_transaction(
    case_directory: Path,
    output: Path,
    previous: Path | None,
    original_error: BaseException,
) -> Path | None:
    """失敗成果を隔離し、認証済み旧成果があれば原子的に復元する。"""

    failed: Path | None = None
    rollback_errors: list[str] = []
    if _entry_exists(output):
        failed = case_directory / f".analysis-output-failed-{uuid.uuid4().hex}"
        try:
            output.rename(failed)
        except OSError as exc:
            rollback_errors.append(f"fresh成果の隔離失敗: {exc}")
    if previous is not None:
        try:
            previous.rename(output)
        except OSError as exc:
            rollback_errors.append(f"旧成果の復元失敗: {exc}")
    if rollback_errors:
        details = "; ".join(rollback_errors)
        raise OrchestrationError(
            f"解析失敗後のrollbackにも失敗しました。元のエラー: {original_error}; rollback: {details}"
        ) from original_error
    return failed


def build_parser() -> argparse.ArgumentParser:
    """Invoke-FamilyBatch.ps1と対応するCLI引数を構築する。"""

    parser = JapaneseArgumentParser(description="AgentTesla/RemcosRAT検体集合を実行せずに静的解析します。")
    parser.add_argument("--family", required=True, choices=FAMILIES, help="解析対象family。")
    parser.add_argument("--sample-root", required=True, type=Path, help="SHA-256名のcase directoryだけを含むroot。")
    parser.add_argument("--python", help="子stageに使う実Python interpreter。")
    parser.add_argument(
        "--password",
        default=FIXED_ARCHIVE_PASSWORD,
        choices=(FIXED_ARCHIVE_PASSWORD,),
        help="MalwareBazaar外装ZIPの固定password。",
    )
    return parser


def authenticated_member(triage: dict[str, Any], *, case_name: str) -> dict[str, Any]:
    """唯一のtriage memberがcase SHA-256へ一致することを検証する。"""

    members = triage.get("members")
    if not isinstance(members, list) or len(members) != 1:
        raise OrchestrationError(f"{case_name}: family-triage.jsonのmemberは正確に1件である必要があります。")
    member = members[0]
    if not isinstance(member, dict) or member.get("sha256") != case_name:
        raise OrchestrationError(f"{case_name}: 内側SHA-256がcase identityと一致しません。")
    return member


def _required_mapping(value: Any, *, label: str, sample_hash: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise OrchestrationError(f"{sample_hash}: {label}がobjectではありません。")
    return value


def authenticate_classification(
    classification: dict[str, Any],
    *,
    family: str,
    sample_hash: str,
    outer_sha256: str,
) -> str:
    """独立分類と外装・内側SHA証拠が自動routingに十分かを検証する。"""

    classified_family = classification.get("malware_type")
    if classified_family != family:
        raise OrchestrationError(
            f"{sample_hash}: 指定family {family!r} と独立分類結果 {classified_family!r} が一致しません。"
        )
    basis = classification.get("attribution_basis")
    if basis not in AUTOMATIC_ATTRIBUTION_BASES:
        raise OrchestrationError(f"{sample_hash}: 自動routingに利用できない分類根拠です: {basis!r}")
    confidence = classification.get("malware_type_confidence")
    if confidence not in AUTOMATIC_CONFIDENCE_LEVELS:
        raise OrchestrationError(f"{sample_hash}: family分類confidenceが不足しています: {confidence!r}")
    campaign_type = classification.get("campaign_type")
    if not isinstance(campaign_type, str) or not campaign_type.strip() or campaign_type.strip().casefold() == "unknown":
        raise OrchestrationError(f"{sample_hash}: campaignが未解決です。")
    observations = _required_mapping(
        classification.get("observations"), label="classification.observations", sample_hash=sample_hash
    )
    if observations.get("sha256") != outer_sha256:
        raise OrchestrationError(f"{sample_hash}: classificationの外装SHA-256が検体ZIPと一致しません。")
    type_detector = _required_mapping(
        observations.get("type_detector"),
        label="classification.observations.type_detector",
        sample_hash=sample_hash,
    )
    if type_detector.get("inner_sha256") != sample_hash:
        raise OrchestrationError(f"{sample_hash}: top-level detectorの内側SHA-256がcase identityと一致しません。")
    evaluations = classification.get("detector_evaluations")
    if not isinstance(evaluations, list):
        raise OrchestrationError(f"{sample_hash}: detector_evaluationsがありません。")
    matching = [item for item in evaluations if isinstance(item, dict) and item.get("malware_type") == family]
    if len(matching) != 1:
        raise OrchestrationError(f"{sample_hash}: 対象familyのdetector_evaluationが一意ではありません。")
    evaluation = matching[0]
    if "error" not in evaluation or evaluation["error"] is not None:
        raise OrchestrationError(f"{sample_hash}: 対象family detectorが正常完了していません。")
    if evaluation.get("automatic_route_eligible") is not True:
        raise OrchestrationError(f"{sample_hash}: 対象family detectorは自動routing対象外です。")
    detection = _required_mapping(evaluation.get("detection"), label="対象detector.detection", sample_hash=sample_hash)
    detector_observations = _required_mapping(
        detection.get("observations"), label="対象detector.detection.observations", sample_hash=sample_hash
    )
    if detector_observations.get("inner_sha256") != sample_hash:
        raise OrchestrationError(f"{sample_hash}: 対象detectorの内側SHA-256がcase identityと一致しません。")
    return campaign_type


def invoke_stage(name: str, arguments: list[str | Path], completed: list[str], python: str) -> None:
    """1つの静的解析stageを実行し、成功時だけ完了一覧へ追加する。"""

    run_python(python, arguments, stage=name)
    completed.append(name)


def _run_case_stages(
    *,
    case: Path,
    archive: Path,
    output: Path,
    previous_output: Path | None,
    family: str,
    password: str,
    python: str,
    framework_root: Path,
    outer_sha256: str,
) -> dict[str, Any]:
    """fresh output内で1 caseの全stageとsummary生成を実施する。"""

    sample_hash = case.name
    registry = framework_root / "registry" / "malware_types.json"
    common = framework_root / "common"
    completed: list[str] = []
    invoke_stage(
        "triage",
        [common / "analyze_family_sample.py", "--outer-zip", archive, "--output-dir", output, "--password", password],
        completed,
        python,
    )
    invoke_stage(
        "classification",
        [
            framework_root / "classifiers" / "classify_sample.py",
            "--sample",
            archive,
            "--registry",
            registry,
            "--output",
            output / "classification.json",
        ],
        completed,
        python,
    )
    triage = load_json_object(output / "family-triage.json", label=f"{sample_hash}のtriage結果")
    if triage.get("outer_sha256") != outer_sha256:
        raise OrchestrationError(f"{sample_hash}: triageの外装SHA-256が検体ZIPと一致しません。")
    member = authenticated_member(triage, case_name=sample_hash)
    classification = load_json_object(output / "classification.json", label=f"{sample_hash}の分類結果")
    campaign_type = authenticate_classification(
        classification, family=family, sample_hash=sample_hash, outer_sha256=outer_sha256
    )
    member_name = member.get("name")
    if not isinstance(member_name, str) or not member_name:
        raise OrchestrationError(f"{sample_hash}: 認証済みmemberのnameが不正です。")
    extension = Path(member_name).suffix.lower() or PureWindowsPath(member_name).suffix.lower()
    if member.get("type") == "script":
        stages = [
            (
                "script-layers",
                [
                    common / "analyze_script_layers.py",
                    "--outer-zip",
                    archive,
                    "--output",
                    output / "script-layers.json",
                    "--password",
                    password,
                ],
            ),
            (
                "script-logic",
                [
                    common / "extract_script_logic.py",
                    "--outer-zip",
                    archive,
                    "--output",
                    output / "script-logic.json",
                    "--password",
                    password,
                ],
            ),
            (
                "encoded-text",
                [
                    common / "extract_encoded_text.py",
                    "--outer-zip",
                    archive,
                    "--output-dir",
                    output / "encoded-text",
                    "--password",
                    password,
                ],
            ),
        ]
        for name, command in stages:
            invoke_stage(name, command, completed, python)
        if extension in {".vbs", ".vbe"}:
            invoke_stage(
                "vbs-variable-trace",
                [
                    common / "trace_vbs_variables.py",
                    "--outer-zip",
                    archive,
                    "--output",
                    output / "vbs-variable-trace.json",
                    "--password",
                    password,
                ],
                completed,
                python,
            )
        if "unicode_marker" in campaign_type or "png_stage" in campaign_type:
            invoke_stage(
                "unicode-marker",
                [
                    common / "strip_unicode_marker.py",
                    "--outer-zip",
                    archive,
                    "--output-dir",
                    output / "deobfuscated",
                    "--password",
                    password,
                ],
                completed,
                python,
            )
    if family == "agenttesla":
        invoke_stage(
            "agenttesla-static-recovery",
            [
                framework_root / "malware" / "agenttesla" / "agenttesla_recover.py",
                "--outer-zip",
                archive,
                "--output-dir",
                output / "agenttesla-static-recovery",
                "--password",
                password,
            ],
            completed,
            python,
        )
    if extension in {".iso", ".img"}:
        invoke_stage(
            "iso9660",
            [
                common / "analyze_iso9660.py",
                "--outer-zip",
                archive,
                "--output",
                output / "iso9660.json",
                "--password",
                password,
            ],
            completed,
            python,
        )
    summary = {
        "schema_version": SUMMARY_SCHEMA_VERSION,
        "family": family,
        "sample_sha256": sample_hash,
        "outer_sha256": outer_sha256,
        "member_sha256": member["sha256"],
        "member_type": member.get("type"),
        "campaign_type": campaign_type,
        "completed_stages": completed,
        "previous_output_directory": str(previous_output) if previous_output else None,
        "executed": False,
        "network_contacted": False,
    }
    try:
        (output / "batch-run-summary.json").write_text(
            json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
    except OSError as exc:
        raise OrchestrationError(f"{sample_hash}: batch summaryを書き込めません。") from exc
    return summary


def analyze_case(
    case_directory: Path,
    *,
    family: str,
    password: str,
    python: str,
    framework_root: Path,
) -> dict[str, Any]:
    """1つの認証済みhash caseを排他・入力snapshot・成果transaction内で解析する。"""

    if family not in FAMILIES:
        raise OrchestrationError(f"未登録familyです: {family}")
    if password != FIXED_ARCHIVE_PASSWORD:
        raise OrchestrationError(f"外装ZIP passwordは{FIXED_ARCHIVE_PASSWORD!r}に固定されています。")
    case, archive = validate_case_directory(case_directory, sample_root=case_directory.parent)
    lock = acquire_case_lock(case)
    active_error: BaseException | None = None
    try:
        snapshot_directory, snapshot, outer_sha256 = materialize_archive_snapshot(archive)
        snapshot_active = True
        output: Path | None = None
        previous: Path | None = None
        try:
            output, previous = prepare_output_directory(
                case,
                family=family,
                outer_sha256=outer_sha256,
            )
            result = _run_case_stages(
                case=case,
                archive=snapshot,
                output=output,
                previous_output=previous,
                family=family,
                password=password,
                python=python,
                framework_root=framework_root,
                outer_sha256=outer_sha256,
            )
            verify_archive_snapshot(snapshot, outer_sha256)
            remove_archive_snapshot(snapshot_directory, snapshot)
            snapshot_active = False
            return result
        except BaseException as exc:
            failure: BaseException = exc
            if snapshot_active:
                try:
                    remove_archive_snapshot(snapshot_directory, snapshot, exc)
                    snapshot_active = False
                except BaseException as cleanup_exc:
                    failure = cleanup_exc
            active_error = failure
            if output is not None:
                rollback_output_transaction(case, output, previous, failure)
            if failure is not exc:
                raise failure
            raise
    except BaseException as exc:
        active_error = active_error or exc
        raise
    finally:
        release_case_lock(lock, active_error)


def run_batch(args: argparse.Namespace, *, framework_root: Path = FRAMEWORK_ROOT) -> list[dict[str, Any]]:
    """認証済みcase directoryを名前順に処理し、0件成功を拒否する。"""

    if args.password != FIXED_ARCHIVE_PASSWORD:
        raise OrchestrationError(f"外装ZIP passwordは{FIXED_ARCHIVE_PASSWORD!r}に固定されています。")
    if not _entry_exists(args.sample_root):
        raise OrchestrationError(f"sample rootがありません: {args.sample_root}")
    if _is_symlink_or_reparse(args.sample_root):
        raise OrchestrationError("sample rootにsymlink/junctionは使用できません。")
    try:
        if not stat.S_ISDIR(args.sample_root.lstat().st_mode):
            raise OrchestrationError(f"sample rootがdirectoryではありません: {args.sample_root}")
        sample_root = args.sample_root.resolve(strict=True)
        entries = sorted(sample_root.iterdir(), key=lambda path: path.name)
    except OSError as exc:
        raise OrchestrationError(f"sample rootを列挙できません: {args.sample_root}") from exc
    case_directories: list[Path] = []
    for entry in entries:
        if _is_symlink_or_reparse(entry):
            raise OrchestrationError(f"sample root直下にsymlink/junctionがあります: {entry}")
        if stat.S_ISDIR(entry.lstat().st_mode):
            validate_case_directory(entry, sample_root=sample_root)
            case_directories.append(entry)
    if not case_directories:
        raise OrchestrationError("解析可能なcaseが0件です。")
    python = resolve_python(args.python, framework_root)
    summaries = [
        analyze_case(
            case,
            family=args.family,
            password=args.password,
            python=python,
            framework_root=framework_root,
        )
        for case in case_directories
    ]
    if not summaries:
        raise OrchestrationError("完了したcaseが0件です。")
    return summaries


def main(argv: list[str] | None = None) -> int:
    """CLIから従来family batchをcross-platformで実行する。"""

    args = build_parser().parse_args(argv)
    try:
        summaries = run_batch(args)
    except OrchestrationError as exc:
        print(f"エラー: {exc}", file=sys.stderr)
        return 1
    print(f"{args.family}の安全な静的解析を{len(summaries)}件完了しました。検体実行とC2接続は行っていません。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
