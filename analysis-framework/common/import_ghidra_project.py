#!/usr/bin/env python3
"""Ghidra headless projectへ解析対象をWindows/Linux共通で安全にimportする。"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import stat
import subprocess
import sys
from pathlib import Path, PureWindowsPath

FRAMEWORK_ROOT = Path(__file__).resolve().parents[1]
if str(FRAMEWORK_ROOT) not in sys.path:
    sys.path.insert(0, str(FRAMEWORK_ROOT))

from common.bounded_process import run_bounded  # noqa: E402

_PROJECT_NAME_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
_WINDOWS_RESERVED_NAMES = frozenset(
    {"CON", "PRN", "AUX", "NUL"} | {f"COM{index}" for index in range(1, 10)} | {f"LPT{index}" for index in range(1, 10)}
)
_WINDOWS_CMD_UNSAFE_PATTERN = re.compile(r'[&|<>^()%!\r\n\x00"]')
_REPARSE_POINT = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
MAX_GHIDRA_ACTIVE_PROCESSES = 64
MAX_GHIDRA_MEMORY_BYTES = 8 * 1024 * 1024 * 1024


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

    def format_usage(self) -> str:
        """usage見出しも日本語へ置換する。"""

        return super().format_usage().replace("usage:", "使用法:")


def _entry_exists(path: Path) -> bool:
    """broken symlinkを含め、path entryが存在するかをlstatで返す。"""

    try:
        path.lstat()
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise GhidraImportError(f"pathを検査できません: {path}") from exc
    return True


def _is_symlink_or_reparse(path: Path) -> bool:
    """Windows junctionを含むsymlink/reparse pointかどうかを返す。"""

    try:
        information = path.lstat()
    except OSError as exc:
        raise GhidraImportError(f"pathを検査できません: {path}") from exc
    attributes = int(getattr(information, "st_file_attributes", 0))
    return path.is_symlink() or bool(attributes & _REPARSE_POINT)


def validate_project_name(project_name: str) -> str:
    """Ghidra project名を両OSで安全な単一識別子へ限定する。"""

    if (
        not isinstance(project_name, str)
        or not _PROJECT_NAME_PATTERN.fullmatch(project_name)
        or project_name in {".", ".."}
        or project_name.endswith(".")
        or project_name.split(".", 1)[0].upper() in _WINDOWS_RESERVED_NAMES
    ):
        raise GhidraImportError(
            "--project-nameは英数字で始まる英数字・dot・underscore・hyphenの安全な識別子が必要です。"
        )
    return project_name


def resolve_analyze_headless(requested: str | None) -> str:
    """明示指定、GHIDRA_HOME、PATHの順でanalyzeHeadlessを解決する。"""

    if requested:
        return requested
    executable_name = "analyzeHeadless.bat" if os.name == "nt" else "analyzeHeadless"
    ghidra_home = os.environ.get("GHIDRA_HOME")
    if ghidra_home:
        candidate = Path(ghidra_home) / "support" / executable_name
        if candidate.is_file() and (os.name == "nt" or os.access(candidate, os.X_OK)):
            return str(candidate)
    discovered = shutil.which(executable_name)
    if discovered:
        return discovered
    raise GhidraImportError("analyzeHeadlessを特定できません。--analyze-headlessまたはGHIDRA_HOMEを指定してください。")


def contained_target(payload_directory: Path, target: str) -> Path:
    """payload directory外、symlink、directory自体をGhidraへ渡さない。"""

    if not isinstance(target, str) or not target or len(target) > 4096 or "\x00" in target:
        raise GhidraImportError("Ghidra targetは有界な非空相対pathで指定してください。")
    lexical_root = Path(os.path.abspath(payload_directory))
    if not _entry_exists(lexical_root) or _is_symlink_or_reparse(lexical_root):
        raise GhidraImportError("payload directoryはsymlinkでない実directoryが必要です。")
    try:
        if not stat.S_ISDIR(lexical_root.lstat().st_mode):
            raise GhidraImportError("payload directoryはsymlinkでない実directoryが必要です。")
        root = lexical_root.resolve(strict=True)
    except OSError as exc:
        raise GhidraImportError("payload directoryを検査できません。") from exc
    lexical = Path(os.path.abspath(lexical_root / target))
    try:
        lexical.relative_to(lexical_root)
    except ValueError as exc:
        raise GhidraImportError(f"Ghidra targetがpayload directory外です: {target}") from exc
    current = lexical_root
    for part in lexical.relative_to(current).parts:
        current /= part
        if not _entry_exists(current):
            raise GhidraImportError(f"Ghidra targetが見つかりません: {target}")
        if _is_symlink_or_reparse(current):
            raise GhidraImportError(f"Ghidra targetにsymlink/reparse pointは使用できません: {target}")
    try:
        candidate = lexical.resolve(strict=True)
        candidate.relative_to(root)
    except (OSError, ValueError) as exc:
        raise GhidraImportError(f"Ghidra targetがpayload directory外です: {target}") from exc
    try:
        if not stat.S_ISREG(candidate.lstat().st_mode):
            raise GhidraImportError(f"Ghidra targetが通常fileではありません: {candidate}")
    except OSError as exc:
        raise GhidraImportError(f"Ghidra targetを検査できません: {candidate}") from exc
    return candidate


def _prepare_project_directory(project_directory: Path, payload_directory: Path) -> Path:
    """project出力をpayload tree外のsymlinkでないdirectoryへ限定する。"""

    lexical_project = Path(os.path.abspath(project_directory))
    project_chain = (*reversed(lexical_project.parents), lexical_project)
    for component in project_chain:
        if not _entry_exists(component):
            continue
        if _is_symlink_or_reparse(component):
            raise GhidraImportError("project directory pathにsymlink/reparse pointは使用できません。")
        if component == lexical_project:
            try:
                if not stat.S_ISDIR(component.lstat().st_mode):
                    raise GhidraImportError("project directoryは実directoryである必要があります。")
            except OSError as exc:
                raise GhidraImportError("project directoryを検査できません。") from exc
    try:
        lexical_project.mkdir(parents=True, exist_ok=True)
        for component in project_chain:
            if _entry_exists(component) and _is_symlink_or_reparse(component):
                raise GhidraImportError("project directory pathにsymlink/reparse pointは使用できません。")
        project = lexical_project.resolve(strict=True)
        payload = payload_directory.resolve(strict=True)
    except GhidraImportError:
        raise
    except OSError as exc:
        raise GhidraImportError("project directoryを作成または解決できません。") from exc
    try:
        project.relative_to(payload)
    except ValueError:
        pass
    else:
        raise GhidraImportError("project directoryはpayload directoryの外に配置してください。")
    return project


def uses_windows_batch_shell(executable: str, *, os_name: str | None = None) -> bool:
    """Windowsのbatch/cmd境界だけPython側のshell escapingを有効にする。"""

    platform_os = os.name if os_name is None else os_name
    return platform_os == "nt" and PureWindowsPath(executable).suffix.casefold() in {".bat", ".cmd"}


def validate_windows_batch_argument(value: object, *, label: str) -> str:
    """cmd.exe境界へ渡せないmetacharacterを含む引数を拒否する。"""

    text = str(value)
    if _WINDOWS_CMD_UNSAFE_PATTERN.search(text):
        raise GhidraImportError(
            f"Windows batch境界の{label}にcmd metacharacter、改行、NUL、double quoteは使用できません。"
        )
    return text


def validate_windows_batch_boundary(
    analyze_headless: str,
    project_directory: Path,
    project_name: str,
    targets: list[Path],
) -> None:
    """shell=TrueになるWindows batch境界の全可変引数をfail-closedで検証する。"""

    validate_windows_batch_argument(analyze_headless, label="analyzeHeadless path")
    validate_windows_batch_argument(project_directory, label="project directory")
    validate_windows_batch_argument(project_name, label="project name")
    for index, target in enumerate(targets, start=1):
        validate_windows_batch_argument(target, label=f"target path[{index}]")


def validate_fresh_project(project_directory: Path, project_name: str) -> tuple[Path, Path]:
    """既存のGhidra project file/repositoryを再利用しない。"""

    project_path = project_directory / f"{project_name}.gpr"
    repository_path = project_directory / f"{project_name}.rep"
    if _entry_exists(project_path) or _entry_exists(repository_path):
        raise GhidraImportError("既存Ghidra projectがあります。未使用の--project-nameを指定してください。")
    return project_path, repository_path


def validate_created_project(project_path: Path, repository_path: Path) -> None:
    """成功後のproject fileと任意repository directoryを検証する。"""

    if not _entry_exists(project_path) or _is_symlink_or_reparse(project_path):
        raise GhidraImportError("Ghidraは成功終了しましたが期待するproject fileを生成しませんでした。")
    try:
        if not stat.S_ISREG(project_path.lstat().st_mode):
            raise GhidraImportError("Ghidra project fileが通常fileではありません。")
    except OSError as exc:
        raise GhidraImportError("Ghidra project fileを検査できません。") from exc
    if _entry_exists(repository_path):
        if _is_symlink_or_reparse(repository_path):
            raise GhidraImportError("Ghidra repositoryにsymlink/reparse pointは使用できません。")
        try:
            if not stat.S_ISDIR(repository_path.lstat().st_mode):
                raise GhidraImportError("Ghidra repositoryがdirectoryではありません。")
        except OSError as exc:
            raise GhidraImportError("Ghidra repositoryを検査できません。") from exc


def build_parser() -> argparse.ArgumentParser:
    """Import-GhidraProject.ps1と対応するCLI引数を構築する。"""

    parser = JapaneseArgumentParser(description="検体を実行せず、Ghidra headless projectへ対象fileをimportします。")
    parser.add_argument("--payload-directory", required=True, type=Path, help="対象fileのroot。")
    parser.add_argument("--project-directory", required=True, type=Path, help="Ghidra project保存先。")
    parser.add_argument("--project-name", required=True, help="未使用の安全なGhidra project識別子。")
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
    """OS別shell境界を明示し、fresh Ghidra headless importを起動する。"""

    if (
        isinstance(args.analysis_timeout_per_file, bool)
        or not isinstance(args.analysis_timeout_per_file, int)
        or not 1 <= args.analysis_timeout_per_file <= 3600
    ):
        raise GhidraImportError("--analysis-timeout-per-fileは1から3600の整数で指定してください。")
    if not _entry_exists(args.payload_directory):
        raise GhidraImportError("payload directoryはsymlinkでない実directoryが必要です。")
    if _is_symlink_or_reparse(args.payload_directory):
        raise GhidraImportError("payload directoryはsymlinkでない実directoryが必要です。")
    try:
        if not stat.S_ISDIR(args.payload_directory.lstat().st_mode):
            raise GhidraImportError(f"payload directoryがdirectoryではありません: {args.payload_directory}")
    except OSError as exc:
        raise GhidraImportError("payload directoryを検査できません。") from exc
    project_name = validate_project_name(args.project_name)
    analyze_headless = resolve_analyze_headless(args.analyze_headless)
    targets = [contained_target(args.payload_directory, target) for target in args.target]
    project_directory = _prepare_project_directory(
        args.project_directory,
        args.payload_directory,
    )
    project_path, repository_path = validate_fresh_project(project_directory, project_name)
    use_shell = uses_windows_batch_shell(analyze_headless)
    if use_shell:
        validate_windows_batch_boundary(
            analyze_headless,
            project_directory,
            project_name,
            targets,
        )
    command = [analyze_headless, str(project_directory), project_name]
    for target in targets:
        command.extend(("-import", str(target)))
    command.extend(("-analysisTimeoutPerFile", str(args.analysis_timeout_per_file), "-overwrite"))
    child_environment = os.environ.copy()
    for secret_name in (
        "VT_API_KEY",
        "TRIAGE_API_KEY",
        "MAXMIND_LICENSE_KEY",
        "GITHUB_TOKEN",
        "GH_TOKEN",
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
    ):
        child_environment.pop(secret_name, None)
    total_timeout = min(24 * 60 * 60, args.analysis_timeout_per_file * len(targets) + 120)
    try:
        completed = run_bounded(
            command,
            check=False,
            shell=use_shell,
            timeout=total_timeout,
            env=child_environment,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            require_containment=True,
            maximum_active_processes=MAX_GHIDRA_ACTIVE_PROCESSES,
            maximum_memory_bytes=MAX_GHIDRA_MEMORY_BYTES,
        )
    except subprocess.TimeoutExpired as exc:
        raise GhidraImportError(f"Ghidra headless解析が{total_timeout}秒でtimeoutしました。") from exc
    except (OSError, RuntimeError, ValueError) as exc:
        raise GhidraImportError("Ghidra headless解析を封じ込めて起動できません。") from exc
    if completed.returncode != 0:
        raise GhidraImportError(f"Ghidra解析が終了code {completed.returncode}で失敗しました。")
    validate_created_project(project_path, repository_path)
    return {
        "project": str(project_path),
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
