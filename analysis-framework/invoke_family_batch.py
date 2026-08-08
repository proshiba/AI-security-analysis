#!/usr/bin/env python3
"""AgentTesla/RemcosRATの従来一括静的解析をcross-platformで起動する。"""

from __future__ import annotations

import argparse
import json
from pathlib import Path, PureWindowsPath
import sys
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


def build_parser() -> argparse.ArgumentParser:
    """Invoke-FamilyBatch.ps1と対応するCLI引数を構築する。"""

    parser = JapaneseArgumentParser(
        description="AgentTesla/RemcosRAT検体集合を実行せずに静的解析します。"
    )
    parser.add_argument("--family", required=True, choices=FAMILIES, help="解析対象family。")
    parser.add_argument(
        "--sample-root",
        required=True,
        type=Path,
        help="SHA-256名のcase directoryを含むroot。",
    )
    parser.add_argument(
        "--python",
        help="子stageに使うPython。省略時はOS別のanalysis-framework/.venvを検出します。",
    )
    parser.add_argument("--password", default="infected", help="外装ZIPのpassword。")
    return parser


def first_member(triage: dict[str, Any], *, case_name: str) -> dict[str, Any]:
    """family triageの先頭memberを検証して返す。"""

    members = triage.get("members")
    if not isinstance(members, list) or not members or not isinstance(members[0], dict):
        raise OrchestrationError(f"{case_name}: family-triage.jsonにmemberがありません。")
    return members[0]


def invoke_stage(
    name: str,
    arguments: list[str | Path],
    completed: list[str],
    python: str,
) -> None:
    """1つの静的解析stageを実行し、成功時だけ完了一覧へ追加する。"""

    run_python(python, arguments, stage=name)
    completed.append(name)


def analyze_case(
    case_directory: Path,
    *,
    family: str,
    password: str,
    python: str,
    framework_root: Path,
) -> dict[str, Any] | None:
    """1つのhash caseへPowerShell版と同じstage順を適用する。"""

    sample_hash = case_directory.name
    archive = case_directory / f"{sample_hash}.zip"
    if not archive.is_file():
        print(f"警告: {sample_hash}をskipします。期待するZIPがありません: {archive}", file=sys.stderr)
        return None

    output = case_directory / "analysis-output"
    output.mkdir(parents=True, exist_ok=True)
    registry = framework_root / "registry" / "malware_types.json"
    common = framework_root / "common"
    completed: list[str] = []

    invoke_stage(
        "triage",
        [
            common / "analyze_family_sample.py",
            "--outer-zip",
            archive,
            "--output-dir",
            output,
            "--password",
            password,
        ],
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
    classification = load_json_object(
        output / "classification.json", label=f"{sample_hash}の分類結果"
    )
    member = first_member(triage, case_name=sample_hash)
    member_name = member.get("name")
    if not isinstance(member_name, str) or not member_name:
        raise OrchestrationError(f"{sample_hash}: 先頭memberのnameが不正です。")
    # ZIP metadataにはPOSIX形式とWindows形式のどちらのpathも残り得る。
    extension = Path(member_name).suffix.lower() or PureWindowsPath(member_name).suffix.lower()

    if member.get("type") == "script":
        script_stages: list[tuple[str, list[str | Path]]] = [
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
        for name, command in script_stages:
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
        campaign_type = classification.get("campaign_type")
        if isinstance(campaign_type, str) and (
            "unicode_marker" in campaign_type or "png_stage" in campaign_type
        ):
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
        "schema_version": 2,
        "family": family,
        "sample_sha256": sample_hash,
        "member_sha256": member.get("sha256"),
        "member_type": member.get("type"),
        "campaign_type": classification.get("campaign_type"),
        "completed_stages": completed,
        "executed": False,
        "network_contacted": False,
    }
    (output / "batch-run-summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return summary


def run_batch(
    args: argparse.Namespace,
    *,
    framework_root: Path = FRAMEWORK_ROOT,
) -> list[dict[str, Any]]:
    """case directoryを名前順に処理し、完了summaryを返す。"""

    if not args.sample_root.is_dir():
        raise OrchestrationError(f"sample rootがdirectoryではありません: {args.sample_root}")
    python = resolve_python(args.python, framework_root)
    summaries: list[dict[str, Any]] = []
    for case_directory in sorted(
        (path for path in args.sample_root.iterdir() if path.is_dir()), key=lambda path: path.name
    ):
        summary = analyze_case(
            case_directory,
            family=args.family,
            password=args.password,
            python=python,
            framework_root=framework_root,
        )
        if summary is not None:
            summaries.append(summary)
    return summaries


def main(argv: list[str] | None = None) -> int:
    """CLIから従来family batchをcross-platformで実行する。"""

    args = build_parser().parse_args(argv)
    try:
        summaries = run_batch(args)
    except OrchestrationError as exc:
        print(f"エラー: {exc}", file=sys.stderr)
        return 1
    print(
        f"{args.family}の安全な静的解析を{len(summaries)}件完了しました。"
        "検体実行とC2接続は行っていません。"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
