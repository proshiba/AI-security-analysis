#!/usr/bin/env python3
"""RemusStealer の process dump を静的に一括解析する。

full process dump から expanded-memory PE を復元し、各 PE 候補へ Remus
config 抽出を適用する。config が一意に復元できた場合だけ、その同一検体の
根拠から C2 判定 profile を生成する。検体の実行、エミュレーション、外部
通信は一切行わない。
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import re
import stat
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

COMMON_ROOT = Path(__file__).resolve().parent
if str(COMMON_ROOT) not in sys.path:
    sys.path.insert(0, str(COMMON_ROOT))
import recover_process_dump_pe as pe_recovery
import remus_c2_profile
import remus_memory_config
import remus_profile_evidence
from safe_private_output import (
    reject_existing_reparse_components,
    write_private_outputs,
)

REPORT_NAME = "analysis-report.json"
SHA256_RE = re.compile(r"[0-9a-fA-F]{64}")
FILE_ATTRIBUTE_REPARSE_POINT = getattr(
    stat,
    "FILE_ATTRIBUTE_REPARSE_POINT",
    0x400,
)


class RemusProcessDumpAnalysisError(ValueError):
    """入力、安全境界、または一括解析処理の失敗を表す。"""


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _normalise_parent_sha256(value: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise RemusProcessDumpAnalysisError("parent_sha256 は必須の 64 桁 hex SHA-256 です")
    return value.casefold()


def _normalise_pinned_ip(value: str | None) -> str | None:
    if value in {None, ""}:
        return None
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise RemusProcessDumpAnalysisError("pinned_ip は正しい IP address で指定してください") from exc
    if not address.is_global:
        raise RemusProcessDumpAnalysisError("pinned_ip には review 済みの global IP だけを指定してください")
    return address.compressed.casefold()


def _stage_safety() -> dict[str, bool]:
    return {
        "executed": False,
        "emulated": False,
        "network_contacted": False,
    }


def _safe_fields(value: Any, allowed: tuple[str, ...]) -> dict[str, Any]:
    """既知 schema の field だけを新しい dict へ複製する。"""

    if not isinstance(value, Mapping):
        return {}
    return {field: value[field] for field in allowed if field in value}


def _sanitise_endpoint(value: Any) -> dict[str, Any]:
    return _safe_fields(
        value,
        (
            "slot_index",
            "uri",
            "scheme",
            "host",
            "port",
            "explicit_port",
            "uri_sha256",
            "cipher_rva",
        ),
    )


def _sanitise_config(report: Mapping[str, Any]) -> dict[str, Any]:
    """runtime token 値や暗号 material を反射しない公開可能 schemaへ絞る。"""

    config = report.get("config") if isinstance(report.get("config"), Mapping) else {}
    runtime = config.get("runtime") if isinstance(config.get("runtime"), Mapping) else {}
    crypto = report.get("crypto") if isinstance(report.get("crypto"), Mapping) else {}
    return {
        "schema_version": report.get("schema_version"),
        "analysis": report.get("analysis"),
        "status": report.get("status"),
        "input": _safe_fields(
            report.get("input"),
            ("sha256", "size", "requested_layout", "selected_layout"),
        ),
        "pe": _safe_fields(
            report.get("pe"),
            (
                "machine",
                "optional_magic",
                "image_base",
                "size_of_image",
                "section_count",
                "dotnet",
            ),
        ),
        "config": {
            "sentinels": [
                _sanitise_endpoint(item) for item in config.get("sentinels", []) if isinstance(item, Mapping)
            ],
            "endpoints": [
                _sanitise_endpoint(item) for item in config.get("endpoints", []) if isinstance(item, Mapping)
            ],
            "tag": _safe_fields(
                config.get("tag"),
                (
                    "status",
                    "value",
                    "rva",
                    "sha256",
                    "candidate_count",
                    "assessment",
                    "confidence",
                    "section_index",
                    "distance_from_static_key",
                    "evidence",
                    "reason_ja",
                ),
            ),
            "exp": _safe_fields(
                config.get("exp"),
                ("status", "value", "reason_ja", "rva", "confidence"),
            ),
            "selector": _safe_fields(
                config.get("selector"),
                (
                    "status",
                    "code_rva",
                    "selector_rva",
                    "encoded_value",
                    "xor_mask",
                    "selected_index",
                    "selected_slot_recovered",
                    "selected_slot_is_sentinel",
                    "selected_slot_uri_sha256",
                    "reason_ja",
                ),
            ),
            "runtime": {
                "selected_endpoint": _safe_fields(
                    runtime.get("selected_endpoint"),
                    (
                        "present",
                        "occurrence_count",
                        "rva",
                        "length",
                        "sha256",
                        "value_published",
                    ),
                ),
                "access_token": _safe_fields(
                    runtime.get("access_token"),
                    (
                        "present",
                        "format",
                        "rva",
                        "length",
                        "sha256",
                        "value_published",
                    ),
                ),
            },
        },
        "crypto": _safe_fields(
            crypto,
            (
                "algorithm",
                "state_rva",
                "state_occurrence_count",
                "static_key_rva",
                "cipher_rva",
                "runtime_counter",
                "key_sha256",
                "nonce_sha256",
                "slot_size",
                "recovered_slot_count",
                "first_non_uri_slot",
                "key_published",
                "nonce_published",
            ),
        ),
        "safety": _safe_fields(
            report.get("safety"),
            (
                "sample_executed",
                "emulated",
                "network_contacted",
                "access_token_value_published",
                "runtime_endpoint_value_published",
            ),
        ),
    }


def _profile_inputs(
    config_report: Mapping[str, Any],
    *,
    parent_sha256: str,
    recovered_pe_sha256: str,
    dump_sha256: str,
    reviewed_tag: str | None,
    exp: int | None,
    reviewed_http_host: str | None,
    pinned_ip: str | None,
    source_reference: str | None,
    evidence_binding: Mapping[str, Any] | None,
    repository_root: Path | None,
    forbidden_evidence_paths: Sequence[Path],
) -> dict[str, Any]:
    config = config_report["config"]
    selector = config.get("selector") or {}
    selected_index = selector.get("selected_index")
    endpoints = [dict(item) for item in config.get("endpoints", [])]
    if pinned_ip is not None:
        for endpoint in endpoints:
            if endpoint.get("slot_index") == selected_index:
                endpoint["pinned_ips"] = [pinned_ip]
    recovered_exp: Any = config.get("exp")
    return {
        "endpoints": endpoints,
        "selected_index": selected_index,
        "tag_candidate": (
            {"status": "reviewed", "value": reviewed_tag} if reviewed_tag is not None else config.get("tag")
        ),
        "exp": exp if exp is not None else recovered_exp,
        "reviewed_http_host": reviewed_http_host,
        "parent_sha256": parent_sha256,
        "recovered_pe_sha256": recovered_pe_sha256,
        "dump_sha256": dump_sha256,
        "source_reference": source_reference,
        "evidence_binding": evidence_binding,
        "repository_root": repository_root,
        "forbidden_evidence_paths": forbidden_evidence_paths,
    }


def analyze_remus_process_dump_bytes(
    data: bytes,
    *,
    parent_sha256: str,
    source_name: str = "<memory>",
    reviewed_tag: str | None = None,
    exp: int | None = None,
    reviewed_http_host: str | None = None,
    pinned_ip: str | None = None,
    source_reference: str | None = None,
    max_input_bytes: int = pe_recovery.DEFAULT_MAX_INPUT_BYTES,
    max_candidates: int = pe_recovery.DEFAULT_MAX_CANDIDATES,
    evidence_binding: Mapping[str, Any] | None = None,
    repository_root: Path | None = None,
    forbidden_evidence_paths: Sequence[Path] = (),
    max_candidate_bytes: int = pe_recovery.DEFAULT_MAX_CANDIDATE_BYTES,
    max_output_bytes: int = pe_recovery.DEFAULT_MAX_OUTPUT_BYTES,
    max_image_bytes: int = remus_memory_config.DEFAULT_MAX_IMAGE_BYTES,
    max_slots: int = remus_memory_config.DEFAULT_MAX_SLOTS,
) -> tuple[list[pe_recovery.RecoveredPE], dict[str, Any]]:
    """dump bytesを解析し、非公開PE payloadとsanitize済みreportを返す。"""

    parent_hash = _normalise_parent_sha256(parent_sha256)
    pin = _normalise_pinned_ip(pinned_ip)
    recovered, recovery_report = pe_recovery.recover_process_dump_bytes(
        data,
        source_name=source_name,
        max_input_bytes=max_input_bytes,
        max_candidates=max_candidates,
        max_candidate_bytes=max_candidate_bytes,
        max_output_bytes=max_output_bytes,
        mapped_mode="expanded_memory_sections",
    )

    candidate_results: list[dict[str, Any]] = []
    successes: list[tuple[pe_recovery.RecoveredPE, dict[str, Any]]] = []
    for item in recovered:
        output_sha256 = str(item.metadata["output_sha256"])
        candidate: dict[str, Any] = {
            "output_name": item.metadata["output_name"],
            "recovered_pe_sha256": output_sha256,
            "recovered_pe_size": len(item.payload),
            "status": "not_remus_config",
        }
        try:
            extracted = remus_memory_config.extract_remus_memory_config(
                item.payload,
                layout="file",
                max_input_bytes=max_output_bytes,
                max_image_bytes=max_image_bytes,
                max_slots=max_slots,
            )
        except (OSError, remus_memory_config.RemusMemoryConfigError) as exc:
            candidate["error_ja"] = str(exc)
        else:
            sanitised = _sanitise_config(extracted)
            candidate["status"] = "extracted"
            candidate["config"] = sanitised
            successes.append((item, sanitised))
        candidate["safety"] = _stage_safety()
        candidate_results.append(candidate)

    config_count = len(successes)
    profile_stage: dict[str, Any] = {
        "status": "not_run",
        "reason_ja": "Remus config が一意でないため C2 profile は生成していません",
        "safety": _stage_safety(),
    }
    semantic_error: dict[str, Any] | None = None
    if config_count != 1:
        code = "remus_config_not_found" if config_count == 0 else "remus_config_ambiguous"
        semantic_error = {
            "code": code,
            "message_ja": (
                "Remus config を復元できる PE 候補がありません"
                if config_count == 0
                else "Remus config を復元できる PE 候補が複数あり、一意に決定できません"
            ),
            "successful_config_candidates": config_count,
            "recovered_pe_candidates": len(recovered),
        }
    else:
        selected, sanitised_config = successes[0]
        try:
            profile = remus_c2_profile.build_remus_c2_profile(
                **_profile_inputs(
                    sanitised_config,
                    parent_sha256=parent_hash,
                    recovered_pe_sha256=str(selected.metadata["output_sha256"]),
                    reviewed_tag=reviewed_tag,
                    exp=exp,
                    dump_sha256=str(recovery_report["source"]["sha256"]),
                    reviewed_http_host=reviewed_http_host,
                    pinned_ip=pin,
                    source_reference=source_reference,
                    evidence_binding=evidence_binding,
                    repository_root=repository_root,
                    forbidden_evidence_paths=forbidden_evidence_paths,
                )
            )
        except (OSError, remus_c2_profile.RemusC2ProfileError) as exc:
            semantic_error = {
                "code": "c2_profile_generation_failed",
                "message_ja": str(exc),
                "successful_config_candidates": 1,
                "recovered_pe_candidates": len(recovered),
            }
            profile_stage = {
                "status": "error",
                "error_ja": str(exc),
                "safety": _stage_safety(),
            }
        else:
            profile_stage = {
                "status": profile["status"],
                "selected_recovered_pe_sha256": selected.metadata["output_sha256"],
                "sanitized_profile": profile,
                "safety": _stage_safety(),
            }

    if semantic_error is not None:
        overall_status = "error"
    elif profile_stage["status"] == "ready":
        overall_status = "complete"
    else:
        overall_status = "partial"

    report: dict[str, Any] = {
        "schema_version": 1,
        "analysis": "remus_process_dump_orchestrator",
        "status": overall_status,
        "input": {
            "parent_sha256": parent_hash,
            "dump_sha256": recovery_report["source"]["sha256"],
            "dump_size": recovery_report["source"]["size"],
            "source_name": Path(source_name).name if source_name != "<memory>" else source_name,
        },
        "stages": {
            "pe_recovery": {
                "status": "complete",
                "mapped_mode": "expanded_memory_sections",
                "summary": recovery_report["summary"],
                "recovered_outputs": [
                    {
                        "output_name": item.metadata["output_name"],
                        "recovered_pe_sha256": item.metadata["output_sha256"],
                        "recovered_pe_size": item.metadata["output_size"],
                        "source_offset": item.metadata["offset"],
                        "source_layout": item.metadata["layout"],
                        "mapped_mode": item.metadata["mapped_mode"],
                    }
                    for item in recovered
                ],
                "safety": _stage_safety(),
            },
            "config_extraction": {
                "status": "complete" if config_count == 1 else "error",
                "successful_candidates": config_count,
                "candidates": candidate_results,
                "safety": _stage_safety(),
            },
            "c2_profile_generation": profile_stage,
        },
        "error": semantic_error,
        "safety": {
            **_stage_safety(),
            "other_sample_defaults_used": False,
            "runtime_uuid_published": False,
            "chacha_key_value_published": False,
            "chacha_nonce_value_published": False,
        },
    }
    return recovered, report


def _normalised_path(path: Path) -> Path:
    return Path(os.path.abspath(os.fspath(path)))


def _path_key(path: Path) -> str:
    return os.path.normcase(os.path.normpath(os.fspath(_normalised_path(path))))


def _path_contains(root: Path, candidate: Path) -> bool:
    try:
        common = os.path.commonpath([_path_key(root), _path_key(candidate)])
    except ValueError:
        return False
    return common == _path_key(root)


def _path_exists(path: Path) -> bool:
    try:
        path.lstat()
    except FileNotFoundError:
        return False
    return True


def _prepare_new_output_directory(input_path: Path, output_dir: Path) -> Path:
    output = _normalised_path(output_dir)
    input_absolute = _normalised_path(input_path)
    reject_existing_reparse_components(input_absolute)
    reject_existing_reparse_components(output)
    if _path_exists(output):
        raise RemusProcessDumpAnalysisError(f"既存の出力 directory は使用できません: {output}")
    if _path_contains(output, input_absolute) or _path_contains(input_absolute, output):
        raise RemusProcessDumpAnalysisError("入力と出力 directory は互いを内包しない別 path にしてください")

    output.parent.mkdir(parents=True, exist_ok=True)
    reject_existing_reparse_components(output.parent)
    try:
        output.mkdir()
    except FileExistsError as exc:
        raise RemusProcessDumpAnalysisError(f"出力 directory が競合しました: {output}") from exc
    reject_existing_reparse_components(output)
    metadata = output.stat(follow_symlinks=False)
    if not stat.S_ISDIR(metadata.st_mode) or bool(
        getattr(metadata, "st_file_attributes", 0) & FILE_ATTRIBUTE_REPARSE_POINT
    ):
        raise RemusProcessDumpAnalysisError(f"作成した出力が通常 directory ではありません: {output}")
    return output


def analyze_remus_process_dump_file(
    input_path: Path,
    output_dir: Path,
    *,
    parent_sha256: str,
    reviewed_tag: str | None = None,
    exp: int | None = None,
    reviewed_http_host: str | None = None,
    pinned_ip: str | None = None,
    source_reference: str | None = None,
    evidence_binding: Mapping[str, Any] | None = None,
    repository_root: Path | None = None,
    forbidden_evidence_paths: Sequence[Path] = (),
    max_input_bytes: int = pe_recovery.DEFAULT_MAX_INPUT_BYTES,
    max_candidates: int = pe_recovery.DEFAULT_MAX_CANDIDATES,
    max_candidate_bytes: int = pe_recovery.DEFAULT_MAX_CANDIDATE_BYTES,
    max_output_bytes: int = pe_recovery.DEFAULT_MAX_OUTPUT_BYTES,
    max_image_bytes: int = remus_memory_config.DEFAULT_MAX_IMAGE_BYTES,
    max_slots: int = remus_memory_config.DEFAULT_MAX_SLOTS,
) -> dict[str, Any]:
    """dump fileを安全に読み、新規 private directoryへ結果を排他保存する。"""

    input_absolute = _normalised_path(input_path)
    output_absolute = _normalised_path(output_dir)
    if _path_key(input_absolute) == _path_key(output_absolute):
        raise RemusProcessDumpAnalysisError("入力ファイルと出力 directory に同一 path は指定できません")
    parent_hash = _normalise_parent_sha256(parent_sha256)
    data, _ = pe_recovery._read_input_file(input_absolute, max_input_bytes)
    recovered, report = analyze_remus_process_dump_bytes(
        data,
        parent_sha256=parent_hash,
        source_name=input_absolute.name,
        reviewed_tag=reviewed_tag,
        exp=exp,
        reviewed_http_host=reviewed_http_host,
        pinned_ip=pinned_ip,
        source_reference=source_reference,
        evidence_binding=evidence_binding,
        repository_root=repository_root,
        forbidden_evidence_paths=tuple(forbidden_evidence_paths)
        + (input_absolute, output_absolute, output_absolute / REPORT_NAME),
        max_input_bytes=max_input_bytes,
        max_candidates=max_candidates,
        max_candidate_bytes=max_candidate_bytes,
        max_output_bytes=max_output_bytes,
        max_image_bytes=max_image_bytes,
        max_slots=max_slots,
    )

    rendered = (json.dumps(report, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    planned: list[tuple[Path, bytes, str]] = [
        (
            output_absolute / str(item.metadata["output_name"]),
            item.payload,
            str(item.metadata["output_sha256"]),
        )
        for item in recovered
    ]
    planned.append((output_absolute / REPORT_NAME, rendered, _sha256(rendered)))

    output_root = _prepare_new_output_directory(input_absolute, output_absolute)
    try:
        written = write_private_outputs(
            planned,
            allowed_root=output_root,
            create_root=False,
        )
    except (OSError, ValueError) as exc:
        raise RemusProcessDumpAnalysisError(f"解析結果を安全に保存できません: {exc}") from exc
    for path in written:
        metadata = path.stat(follow_symlinks=False)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise RemusProcessDumpAnalysisError(f"作成した出力が単一リンクの通常ファイルではありません: {path}")
    return report


def _positive_cli(value: str) -> int:
    try:
        parsed = int(value, 0)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("正の整数を指定してください") from exc
    if parsed <= 0:
        raise argparse.ArgumentTypeError("正の整数を指定してください")
    return parsed


def _integer_cli(value: str) -> int:
    try:
        return int(value, 0)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("整数を指定してください") from exc


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path, help="full process dump")
    parser.add_argument(
        "--output-dir",
        required=True,
        type=Path,
        help="復元 PE と JSON report を保存する新規 private directory",
    )
    parser.add_argument(
        "--parent-sha256",
        required=True,
        help="元検体の SHA-256。他検体の値は補完しません",
    )
    parser.add_argument(
        "--reviewed-tag",
        help="同一検体からreview済みの32桁hex tag。候補文字列だけでは指定しません",
    )
    parser.add_argument("--exp", type=_integer_cli, help="同一検体から review 済みの exp")
    parser.add_argument(
        "--reviewed-http-host",
        help="同一検体から review 済みの HTTP Host",
    )
    parser.add_argument(
        "--pinned-ip",
        help="選択 endpoint と同一検体で review 済みの global IP",
    )
    parser.add_argument(
        "--source-reference",
        help="repo 相対 path:成果物位置の review 済み根拠参照",
    )
    parser.add_argument(
        "--evidence-manifest-source",
        help="field-level evidence manifestのrepository相対path",
    )
    parser.add_argument(
        "--evidence-manifest-sha256",
        help="field-level evidence manifestのSHA-256 pin",
    )
    parser.add_argument(
        "--evidence-review-id",
        help="固定review registryにallowlistされたreview ID",
    )
    parser.add_argument(
        "--repository-root",
        type=Path,
        default=remus_profile_evidence.default_repository_root(),
        help="evidence manifestを解決するrepository root",
    )
    parser.add_argument("--max-input-bytes", type=_positive_cli, default=pe_recovery.DEFAULT_MAX_INPUT_BYTES)
    parser.add_argument("--max-candidates", type=_positive_cli, default=pe_recovery.DEFAULT_MAX_CANDIDATES)
    parser.add_argument(
        "--max-candidate-bytes",
        type=_positive_cli,
        default=pe_recovery.DEFAULT_MAX_CANDIDATE_BYTES,
    )
    parser.add_argument("--max-output-bytes", type=_positive_cli, default=pe_recovery.DEFAULT_MAX_OUTPUT_BYTES)
    parser.add_argument(
        "--max-image-bytes",
        type=_positive_cli,
        default=remus_memory_config.DEFAULT_MAX_IMAGE_BYTES,
    )
    parser.add_argument("--max-slots", type=_positive_cli, default=remus_memory_config.DEFAULT_MAX_SLOTS)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        evidence_binding = None
        if any(
            value is not None
            for value in (args.evidence_manifest_source, args.evidence_manifest_sha256, args.evidence_review_id)
        ):
            evidence_binding = remus_profile_evidence.build_evidence_binding(
                args.evidence_manifest_source,
                args.evidence_manifest_sha256,
                args.evidence_review_id,
            )
        report = analyze_remus_process_dump_file(
            args.input,
            args.output_dir,
            parent_sha256=args.parent_sha256,
            exp=args.exp,
            reviewed_tag=args.reviewed_tag,
            reviewed_http_host=args.reviewed_http_host,
            pinned_ip=args.pinned_ip,
            source_reference=args.source_reference,
            evidence_binding=evidence_binding,
            repository_root=args.repository_root,
            max_input_bytes=args.max_input_bytes,
            max_candidates=args.max_candidates,
            max_candidate_bytes=args.max_candidate_bytes,
            max_output_bytes=args.max_output_bytes,
            max_image_bytes=args.max_image_bytes,
            max_slots=args.max_slots,
        )
    except (OSError, ValueError) as exc:
        error = {
            "schema_version": 1,
            "analysis": "remus_process_dump_orchestrator",
            "status": "error",
            "error_ja": str(exc),
            "safety": _stage_safety(),
        }
        sys.stderr.write(json.dumps(error, ensure_ascii=False) + "\n")
        return 2
    sys.stdout.write(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    exit_codes = {"complete": 0, "error": 2, "partial": 3}
    return exit_codes.get(str(report.get("status")), 2)


if __name__ == "__main__":
    raise SystemExit(main())
