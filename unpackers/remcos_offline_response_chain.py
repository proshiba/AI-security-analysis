"""Remcos PowerShell配送の保存済みresponseを通信なしで静的連鎖解析する。

親PowerShellから検証済みremote transformを復元し、保存済みresponseから子script、
native span、zero-pad/dword XOR後のstage、埋め込み定数の順に解析する。検体、
PowerShell、shellcodeは実行しない。復元byteは指定時にだけpassword ``infected`` の
WinZip AES-256 archiveへ保存する。
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from unpackers.powershell_cyclic_xor_calls import (
    recover_remote_payload_from_transform,
    recover_reviewed_cyclic_xor_context,
)
from unpackers.powershell_inherited_cyclic_xor import (
    DEFAULT_LIMITS as INHERITED_LIMITS,
)
from unpackers.powershell_inherited_cyclic_xor import (
    recover_inherited_cyclic_xor_loader,
)
from unpackers.remcos_native_constant_writer import recover_remcos_native_constants
from unpackers.static_unpacker import write_artifacts


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _deduplicate_artifacts(
    artifacts: list[tuple[str, bytes]],
) -> list[tuple[str, bytes]]:
    seen: set[str] = set()
    output: list[tuple[str, bytes]] = []
    for name, blob in artifacts:
        digest = _sha256(blob)
        if digest in seen:
            continue
        seen.add(digest)
        output.append((name, blob))
    return output


def _select_logical_stage(
    chain_report: dict[str, object],
    artifacts: list[tuple[str, bytes]],
) -> tuple[dict[str, object], bytes | None]:
    """正規化済みnative stageまたはpoly-only復元物を一意に選択する。"""

    response = chain_report.get("response_recovery", {})
    if not isinstance(response, dict):
        return {"status": "response_report_missing"}, None
    normalization = response.get("native_stage_normalization", {})
    native = response.get("native_span_stage", {})
    polymorphic = response.get("polymorphic_xor_loader", {})
    primary_name: str | None = None
    reason: str | None = None
    if (
        isinstance(normalization, dict)
        and normalization.get("status") == "single_logical_candidate"
        and isinstance(normalization.get("primary_artifact"), str)
    ):
        primary_name = str(normalization["primary_artifact"])
        reason = "normalized_native_stage"
    elif isinstance(native, dict) and native.get("status") == "stage_recovered":
        primary_name = "remcos-native-stage-03.bin"
        reason = "native_stage_only"
    elif (
        isinstance(polymorphic, dict)
        and polymorphic.get("status") == "shellcode_recovered"
    ):
        primary_name = "remcos-polymorphic-xor-shellcode.bin"
        reason = "polymorphic_prefix_only"
    if primary_name is None:
        return {"status": "stage_not_recovered"}, None
    matching = [(name, blob) for name, blob in artifacts if name == primary_name]
    if len(matching) != 1:
        return {
            "status": "stage_artifact_not_unique",
            "selected_name": primary_name,
            "observed_count": len(matching),
        }, None
    blob = matching[0][1]
    return {
        "status": "stage_selected",
        "selected_name": primary_name,
        "selection_reason": reason,
        "size": len(blob),
        "sha256": _sha256(blob),
        "terminal_payload_confirmed": False,
    }, blob


def analyze_remcos_offline_response_chain(
    parent_data: bytes,
    response_data: bytes,
) -> tuple[dict[str, object], list[tuple[str, bytes]]]:
    """親scriptと保存済みresponseだけを使い、復元可能な全段を静的解析する。"""

    report: dict[str, object] = {
        "schema_version": 1,
        "profile": "remcos-powershell-saved-response-chain-v1",
        "status": "rejected",
        "parent_size": len(parent_data) if isinstance(parent_data, bytes) else None,
        "parent_sha256": (
            _sha256(parent_data) if isinstance(parent_data, bytes) else None
        ),
        "response_size": (
            len(response_data) if isinstance(response_data, bytes) else None
        ),
        "response_sha256": (
            _sha256(response_data) if isinstance(response_data, bytes) else None
        ),
        "candidate_set_complete": False,
        "candidate_set_truncated": False,
        "safety": {
            "sample_executed": False,
            "powershell_started": False,
            "shellcode_executed": False,
            "network_contacted": False,
            "general_expression_evaluator_used": False,
            "raw_key_included": False,
        },
        "evidence_boundary": {
            "family_attribution_allowed": False,
            "c2_confirmation_allowed": False,
            "delivery_candidate_is_c2_confirmation": False,
            "recovered_stage_is_terminal_payload": False,
        },
    }
    if not isinstance(parent_data, bytes) or not isinstance(response_data, bytes):
        raise TypeError("parent_dataとresponse_dataはbytesである必要があります")
    if (
        not parent_data
        or len(parent_data) > INHERITED_LIMITS.max_parent_bytes
        or not response_data
        or len(response_data) > INHERITED_LIMITS.max_response_bytes
    ):
        report["status"] = "input_size_rejected"
        return report, []

    context = recover_reviewed_cyclic_xor_context(parent_data)
    report["parent_context"] = context.report
    transform = context.report.get("remote_payload_transform")
    if (
        context.key is None
        or context.function_name is None
        or not isinstance(transform, dict)
    ):
        report["status"] = "parent_context_rejected"
        return report, []

    child_report, child_data = recover_remote_payload_from_transform(
        response_data, transform
    )
    report["remote_child_recovery"] = child_report
    if child_data is None:
        report["status"] = "remote_child_rejected"
        return report, []

    chain_report, artifacts = recover_inherited_cyclic_xor_loader(
        parent_data,
        child_data,
        response_data=response_data,
    )
    report["inherited_chain"] = chain_report
    output_artifacts = [("remote-child.ps1", child_data), *artifacts]
    logical_stage, stage_blob = _select_logical_stage(chain_report, artifacts)
    report["logical_stage"] = logical_stage
    if stage_blob is not None:
        constants_report, constant_artifacts = recover_remcos_native_constants(
            stage_blob
        )
        report["native_stage_constants"] = constants_report
        output_artifacts.extend(constant_artifacts)
    else:
        constants_report = {
            "status": "not_applicable_stage_selection",
            "stage_selection_status": logical_stage.get("status"),
        }
        report["native_stage_constants"] = constants_report

    output_artifacts = _deduplicate_artifacts(output_artifacts)
    stage_recovered = stage_blob is not None
    constants_recovered = constants_report.get("status") == "constants_recovered"
    report.update(
        {
            "status": (
                "constants_recovered"
                if constants_recovered
                else "stage_recovered"
                if stage_recovered
                else "child_chain_partial"
            ),
            "candidate_set_complete": bool(
                chain_report.get("candidate_set_complete", False)
            ),
            "candidate_set_truncated": bool(
                chain_report.get("candidate_set_truncated", False)
            ),
            "artifact_count": len(output_artifacts),
            "artifacts": [
                {"name": name, "size": len(blob), "sha256": _sha256(blob)}
                for name, blob in output_artifacts
            ],
        }
    )
    return report, output_artifacts


def build_parser() -> argparse.ArgumentParser:
    """通信なしCLIの引数を構築する。"""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--parent", required=True, type=Path)
    parser.add_argument("--response", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--artifact-zip", required=True, type=Path)
    return parser


def _bounded_read(path: Path, maximum: int) -> bytes:
    size = path.stat().st_size
    if size <= 0 or size > maximum:
        raise ValueError(f"入力sizeが許容範囲外です: {path.name}")
    return path.read_bytes()


def main(argv: list[str] | None = None) -> int:
    """保存済み2入力を解析し、JSONとAES-256 artifact archiveを保存する。"""

    args = build_parser().parse_args(argv)
    resolved = [
        args.parent.resolve(),
        args.response.resolve(),
        args.report.resolve(),
        args.artifact_zip.resolve(),
    ]
    if len(set(resolved)) != len(resolved):
        raise ValueError("入力・report・artifact archiveのpathは分離してください")
    parent_data = _bounded_read(args.parent, INHERITED_LIMITS.max_parent_bytes)
    response_data = _bounded_read(args.response, INHERITED_LIMITS.max_response_bytes)
    report, artifacts = analyze_remcos_offline_response_chain(
        parent_data, response_data
    )
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    if artifacts:
        write_artifacts(args.artifact_zip, artifacts)
    print(
        json.dumps(
            {
                "status": report["status"],
                "report": str(args.report),
                "artifact_zip": str(args.artifact_zip) if artifacts else None,
                "artifact_count": len(artifacts),
            },
            ensure_ascii=False,
        )
    )
    return 0 if artifacts else 1


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["analyze_remcos_offline_response_chain", "build_parser", "main"]
