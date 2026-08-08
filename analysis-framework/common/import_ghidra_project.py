#!/usr/bin/env python3
"""Ghidra headless projectへ解析対象をWindows/Linux共通でimportする。"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys


class GhidraImportError(RuntimeError):
    """安全なGhidra importを継続できない場合のエラー。"""


class JapaneseArgumentParser(argparse.ArgumentParser):
    """argparseの固定見出しと標準helpを日本語で表示する。"""

    def format_help(self) -> str:
        """標準help内の固定英語だけを日本語へ置換する。"""

        return (
            super()
            .format_help()
            .replace("usage:", "使用法:")
            .replace("options:", "オプション:")
            .replace("show this help message and exit", "このヘルプを表示して終了します")
        )


def resolve_analyze_headless(requested: str | None) -> str:
    """明示指定、GHIDRA_HOME、PATHの順でanalyzeHeadlessを解決する。"""

    if requested:
        return requested

    executable_name = "analyzeHeadless.bat" if os.name == "nt" else "analyzeHeadless"
    ghidra_home = os.environ.get("GHIDRA_HOME")
    if ghidra_home:
        candidate = Path(ghidra_home) / "support" / executable_name
        if candidate.is_file():
            return str(candidate)
    discovered = shutil.which(executable_name)
    if discovered:
        return discovered
    raise GhidraImportError(
        "analyzeHeadlessを特定できません。--analyze-headlessまたはGHIDRA_HOMEを指定してください。"
    )


def contained_target(payload_directory: Path, target: str) -> Path:
    """payload directory外やdirectory自体をGhidraへ渡さない。"""

    root = payload_directory.resolve()
    candidate = (payload_directory / target).resolve()
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise GhidraImportError(f"Ghidra targetがpayload directory外です: {target}") from exc
    if not candidate.is_file():
        raise GhidraImportError(f"Ghidra targetが見つからないかfileではありません: {candidate}")
    return candidate


def build_parser() -> argparse.ArgumentParser:
    """Import-GhidraProject.ps1と対応するCLI引数を構築する。"""

    parser = JapaneseArgumentParser(
        description="検体を実行せず、Ghidra headless projectへ対象fileをimportします。"
    )
    parser.add_argument("--payload-directory", required=True, type=Path, help="対象fileのroot。")
    parser.add_argument("--project-directory", required=True, type=Path, help="Ghidra project保存先。")
    parser.add_argument("--project-name", required=True, help="Ghidra project名。")
    parser.add_argument(
        "--target",
        required=True,
        action="append",
        help="payload directoryからの相対path。複数回指定できます。",
    )
    parser.add_argument(
        "--analyze-headless",
        help="analyzeHeadless(.bat)のpath。省略時はGHIDRA_HOMEとPATHを調べます。",
    )
    parser.add_argument(
        "--analysis-timeout-per-file",
        type=int,
        default=600,
        help="Ghidraへ渡すfile単位の解析timeout秒。",
    )
    return parser


def import_project(args: argparse.Namespace) -> dict[str, object]:
    """引数listだけでGhidra headless importを起動する。"""

    if args.analysis_timeout_per_file <= 0:
        raise GhidraImportError("--analysis-timeout-per-fileは正の整数で指定してください。")
    if not args.payload_directory.is_dir():
        raise GhidraImportError(f"payload directoryが見つかりません: {args.payload_directory}")
    if not args.project_name.strip() or Path(args.project_name).name != args.project_name:
        raise GhidraImportError("--project-nameにはpath区切りを含まない名前を指定してください。")

    analyze_headless = resolve_analyze_headless(args.analyze_headless)
    targets = [contained_target(args.payload_directory, target) for target in args.target]
    args.project_directory.mkdir(parents=True, exist_ok=True)
    command = [analyze_headless, str(args.project_directory), args.project_name]
    for target in targets:
        command.extend(("-import", str(target)))
    command.extend(
        ("-analysisTimeoutPerFile", str(args.analysis_timeout_per_file), "-overwrite")
    )
    try:
        completed = subprocess.run(command, check=False)
    except OSError as exc:
        raise GhidraImportError(f"Ghidra headless解析を起動できません: {exc}") from exc
    if completed.returncode != 0:
        raise GhidraImportError(f"Ghidra解析が終了code {completed.returncode}で失敗しました。")

    return {
        "project": str(args.project_directory / f"{args.project_name}.gpr"),
        "targets": args.target,
        "executed_sample": False,
    }


def main(argv: list[str] | None = None) -> int:
    """CLIからGhidra headless importを実行する。"""

    args = build_parser().parse_args(argv)
    try:
        result = import_project(args)
    except GhidraImportError as exc:
        print(f"エラー: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
