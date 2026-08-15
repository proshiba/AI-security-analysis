#!/usr/bin/env python3
"""WindowsとLinuxで同じ静的解析フローを安全に起動する。"""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
import subprocess
import sys
from collections.abc import Iterable, Mapping
from pathlib import Path, PureWindowsPath
from typing import Any

FRAMEWORK_ROOT = Path(__file__).resolve().parent
if str(FRAMEWORK_ROOT) not in sys.path:
    sys.path.insert(0, str(FRAMEWORK_ROOT))

from common.bounded_process import run_bounded  # noqa: E402

ALLOWED_ARCHIVE_MODES = ("auto", "raw", "malwarebazaar")
MAX_JSON_BYTES = 16 * 1024 * 1024
MAX_LIVE_C2_TARGETS = 32
MAX_SEND_HEX_CHARACTERS = 2048
MAX_STAGE_TIMEOUT_SECONDS = 24 * 60 * 60
MAX_STAGE_ACTIVE_PROCESSES = 32
MAX_STAGE_MEMORY_BYTES = 4 * 1024 * 1024 * 1024
MAX_EXISTING_OUTPUT_ENTRIES = 100_000
DEFAULT_STAGE_TIMEOUT_SECONDS = 30 * 60
NETWORK_STAGE_TIMEOUT_SECONDS = 120
_PROTOCOLS = frozenset({"tcp", "udp", "vvas", "n520", "http", "https", "tls", "mxgo"})
_ENVIRONMENT_KEY_PATTERN = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_REPARSE_POINT = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))


class OrchestrationError(RuntimeError):
    """解析stageを安全に継続できない場合のエラー。"""


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


def _validate_python_interpreter(command: str) -> str:
    """Windows command scriptをPython interpreterとして受け付けない。"""

    if PureWindowsPath(command).suffix.lower() in {".bat", ".cmd"}:
        raise OrchestrationError("--pythonには.bat/.cmdではなく実際のPython interpreterを指定してください。")
    return command


def resolve_python(
    requested: str | None,
    framework_root: Path = FRAMEWORK_ROOT,
    *,
    os_name: str | None = None,
) -> str:
    """明示指定、OS別venv、現在のinterpreterの順でPythonを選ぶ。"""

    if requested:
        return _validate_python_interpreter(requested)
    platform_os = os.name if os_name is None else os_name
    candidate = (
        framework_root / ".venv" / "Scripts" / "python.exe"
        if platform_os == "nt"
        else framework_root / ".venv" / "bin" / "python"
    )
    if candidate.is_file() and (platform_os == "nt" or os.access(candidate, os.X_OK)):
        return _validate_python_interpreter(str(candidate))
    if not sys.executable:
        raise OrchestrationError("利用可能なPython interpreterを特定できません。--pythonで指定してください。")
    return _validate_python_interpreter(sys.executable)


def _child_environment(
    environment_overlay: Mapping[str, str | None] | None,
) -> dict[str, str]:
    """秘密値を既定で除外し、明示された値だけを子processへ追加する。"""

    environment = os.environ.copy()
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
        environment.pop(secret_name, None)
    for key, value in (environment_overlay or {}).items():
        if not isinstance(key, str) or not _ENVIRONMENT_KEY_PATTERN.fullmatch(key):
            raise OrchestrationError("子processの環境変数名が不正です。")
        if value is None:
            environment.pop(key, None)
            continue
        if not isinstance(value, str) or "\x00" in value:
            raise OrchestrationError(f"子processの環境変数 {key} が不正です。")
        environment[key] = value
    return environment


def run_python(
    python: str,
    arguments: Iterable[object],
    *,
    stage: str,
    allowed_exit_codes: frozenset[int] = frozenset({0}),
    environment_overlay: Mapping[str, str | None] | None = None,
    timeout_seconds: int = DEFAULT_STAGE_TIMEOUT_SECONDS,
) -> int:
    """shellを介さず有界時間でPython stageを実行し、許可外の終了codeを拒否する。"""

    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, int)
        or not 1 <= timeout_seconds <= MAX_STAGE_TIMEOUT_SECONDS
    ):
        raise OrchestrationError(f"{stage}のtimeoutは1から{MAX_STAGE_TIMEOUT_SECONDS}秒で指定してください。")
    command = [python, *(str(argument) for argument in arguments)]
    try:
        completed = run_bounded(
            command,
            check=False,
            env=_child_environment(environment_overlay),
            timeout=timeout_seconds,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            require_containment=True,
            maximum_active_processes=MAX_STAGE_ACTIVE_PROCESSES,
            maximum_memory_bytes=MAX_STAGE_MEMORY_BYTES,
        )
    except (OSError, RuntimeError, ValueError) as exc:
        raise OrchestrationError(f"{stage}を封じ込めて起動できません。") from exc
    except subprocess.TimeoutExpired as exc:
        raise OrchestrationError(f"{stage}が{timeout_seconds}秒でtimeoutしました。") from exc
    if completed.returncode not in allowed_exit_codes:
        raise OrchestrationError(f"{stage}が終了code {completed.returncode}で失敗しました。")
    return completed.returncode


def _reject_duplicate_json_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise OrchestrationError(f"JSON keyが重複しています: {key}")
        result[key] = value
    return result


def _reject_nonfinite_json(value: str) -> None:
    raise OrchestrationError(f"JSONの非有限値は使用できません: {value}")


def load_json_object(path: Path, *, label: str) -> dict[str, Any]:
    """上限付きUTF-8 JSON objectを重複keyと非有限値を拒否して読み込む。"""

    try:
        with path.open("rb") as stream:
            raw = stream.read(MAX_JSON_BYTES + 1)
    except OSError as exc:
        raise OrchestrationError(f"{label}を読み込めません: {path}") from exc
    if len(raw) > MAX_JSON_BYTES:
        raise OrchestrationError(f"{label}が上限{MAX_JSON_BYTES} byteを超えています: {path}")
    try:
        text = raw.decode("utf-8-sig")
        value = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_json_pairs,
            parse_constant=_reject_nonfinite_json,
        )
    except OrchestrationError:
        raise
    except (UnicodeError, json.JSONDecodeError, ValueError, RecursionError) as exc:
        raise OrchestrationError(f"{label}は厳格なUTF-8 JSONではありません: {path}") from exc
    if not isinstance(value, dict):
        raise OrchestrationError(f"{label}の最上位はJSON objectである必要があります: {path}")
    return value


def require_mapping(value: Any, *, label: str) -> dict[str, Any]:
    """profile内の必須objectを検証する。"""

    if not isinstance(value, dict):
        raise OrchestrationError(f"{label}はJSON objectである必要があります。")
    return value


def require_value(mapping: dict[str, Any], key: str, *, label: str) -> Any:
    """空でない必須profile値を返す。"""

    value = mapping.get(key)
    if value is None or value == "":
        raise OrchestrationError(f"{label}に必須値 {key!r} がありません。")
    return value


def safe_filename_component(value: Any) -> str:
    """WindowsとPOSIXの双方で安全な有界file名要素へ変換する。"""

    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", str(value)).strip("._")
    return (cleaned or "target")[:96]


def build_parser() -> argparse.ArgumentParser:
    """Invoke-Analysis.ps1と対応するCLI引数を構築する。"""

    parser = JapaneseArgumentParser(description="検体を実行せず、Windows/Linux共通の静的解析フローを起動します。")
    parser.add_argument("--sample", required=True, type=Path, help="解析する検体fileまたはdirectory。")
    parser.add_argument("--output-directory", required=True, type=Path, help="解析結果の出力先。")
    parser.add_argument("--profile-path", type=Path, help="review済みValleyRAT profile。")
    parser.add_argument("--network-evidence", type=Path, help="既存のnetwork evidence JSON。")
    parser.add_argument("--malware-type", help="分類対象を登録済みマルウェア種へ限定します。")
    parser.add_argument(
        "--fetch-virus-total-evidence",
        action="store_true",
        help="旧フローでVT evidence取得を明示許可します。keyはVT_API_KEYから読みます。",
    )
    parser.add_argument(
        "--allow-live-c2-check",
        action="store_true",
        help="review済みprofileのtargetだけに限定したlive C2確認を許可します。",
    )
    parser.add_argument(
        "--collect-jarm",
        action="store_true",
        help="廃止済みです。active C2観測はNmap NSEだけを使用します。",
    )
    parser.add_argument(
        "--jarm-script",
        type=Path,
        help="廃止済みです。外部Python JARM helperはactive C2観測に使用しません。",
    )
    parser.add_argument(
        "--nmap",
        help="live C2観測に使用するNmap実体。省略時はNMAP_EXE、固定候補、PATHの順で解決します。",
    )
    parser.add_argument(
        "--archive-mode",
        choices=ALLOWED_ARCHIVE_MODES,
        default="auto",
        help="通常のone-shot静的解析へ渡すarchive mode。",
    )
    parser.add_argument("--assessment-only", action="store_true", help="通常フローで適用可否判定だけを実行します。")
    parser.add_argument(
        "--legacy-valley-workflow",
        action="store_true",
        help="旧ValleyRAT campaign handlerフローを明示的に使用します。",
    )
    parser.add_argument(
        "--python",
        help="子stageに使う実Python interpreter。.bat/.cmdは拒否します。省略時はOS別venvを検出します。",
    )
    return parser


def run_one_shot(args: argparse.Namespace, python: str, framework_root: Path) -> None:
    """標準の一括静的解析へ引数をそのまま委譲する。"""

    command: list[str | Path] = [
        framework_root / "common" / "analyze_sample.py",
        "--input",
        args.sample,
        "--output",
        args.output_directory,
        "--archive-mode",
        args.archive_mode,
    ]
    if args.malware_type:
        command.extend(("--family", args.malware_type))
    if args.assessment_only:
        command.append("--assessment-only")
    run_python(python, command, stage="one-shot静的解析")


def classify_legacy(
    args: argparse.Namespace,
    python: str,
    framework_root: Path,
    classification_path: Path,
) -> dict[str, Any]:
    """旧フロー用の構造分類を実行する。"""

    command: list[str | Path] = [
        framework_root / "classifiers" / "classify_sample.py",
        "--sample",
        args.sample,
        "--registry",
        framework_root / "registry" / "malware_types.json",
        "--output",
        classification_path,
    ]
    if args.malware_type:
        command.extend(("--malware-type", args.malware_type))
    run_python(python, command, stage="検体分類")
    return load_json_object(classification_path, label="分類結果")


def fetch_vt_evidence(
    selected: dict[str, Any],
    api_key: str,
    output_directory: Path,
    python: str,
    framework_root: Path,
) -> Path:
    """完全hash限定VT evidenceをkey非公開の子environmentで取得する。"""

    observations = require_mapping(selected.get("observations"), label="分類結果のobservations")
    sample_hash = require_value(observations, "sha256", label="分類結果のobservations")
    if not isinstance(sample_hash, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", sample_hash):
        raise OrchestrationError("分類結果のSHA-256が不正です。")
    output = output_directory / "virustotal-sandbox.json"
    run_python(
        python,
        [
            framework_root / "common" / "vt_sandbox.py",
            "--sha256",
            sample_hash.lower(),
            "--output",
            output,
        ],
        stage="VirusTotal sandbox evidence取得",
        environment_overlay={"VT_API_KEY": api_key},
        timeout_seconds=NETWORK_STAGE_TIMEOUT_SECONDS,
    )
    return output


def validate_profile(
    sample: Path,
    profile_path: Path,
    python: str,
    framework_root: Path,
) -> None:
    """review済みprofileと検体hashの対応を検証する。"""

    run_python(
        python,
        [
            framework_root / "malware" / "valleyrat" / "common" / "validate_profile.py",
            "--sample",
            sample,
            "--profile",
            profile_path,
        ],
        stage="ValleyRAT profile検証",
    )


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


def _prepare_fresh_legacy_output(output_directory: Path) -> Path:
    """旧フロー出力のlexical chainを検査し、空の実directoryだけを許可する。"""

    lexical = Path(os.path.abspath(output_directory))
    for component in (*reversed(lexical.parents), lexical):
        if _entry_exists(component) and _is_symlink_or_reparse(component):
            raise OrchestrationError(f"旧フロー出力pathにsymlink/reparse pointは使用できません: {component}")
    if _entry_exists(lexical):
        try:
            if not stat.S_ISDIR(lexical.lstat().st_mode):
                raise OrchestrationError(f"旧フロー出力pathがdirectoryではありません: {lexical}")
            if next(lexical.iterdir(), None) is not None:
                raise OrchestrationError(
                    "旧フロー出力directoryは空である必要があります。新しい出力先を指定してください。"
                )
        except OSError as exc:
            raise OrchestrationError(f"旧フロー出力directoryを検査できません: {lexical}") from exc
    else:
        try:
            lexical.mkdir(parents=True)
        except OSError as exc:
            raise OrchestrationError(f"旧フロー出力directoryを作成できません: {lexical}") from exc
        for component in (*reversed(lexical.parents), lexical):
            if _entry_exists(component) and _is_symlink_or_reparse(component):
                raise OrchestrationError(f"旧フロー出力pathにsymlink/reparse pointは使用できません: {component}")
    return lexical


def _validate_standard_output_tree(output: Path) -> None:
    """既存one-shot成果treeのlink・特殊file・過大entry数を拒否する。"""

    pending = [output]
    visited = 0
    while pending:
        current = pending.pop()
        visited += 1
        if visited > MAX_EXISTING_OUTPUT_ENTRIES:
            raise OrchestrationError(f"既存one-shot出力は最大{MAX_EXISTING_OUTPUT_ENTRIES} entryです。")
        if _is_symlink_or_reparse(current):
            raise OrchestrationError(f"既存one-shot出力にsymlink/reparse pointがあります: {current}")
        try:
            information = current.lstat()
        except OSError as exc:
            raise OrchestrationError(f"既存one-shot出力を検査できません: {current}") from exc
        if stat.S_ISDIR(information.st_mode):
            try:
                pending.extend(current.iterdir())
            except OSError as exc:
                raise OrchestrationError(f"既存one-shot出力を列挙できません: {current}") from exc
        elif not stat.S_ISREG(information.st_mode):
            raise OrchestrationError(f"既存one-shot出力に通常file以外があります: {current}")
        elif information.st_nlink > 1:
            raise OrchestrationError(f"既存one-shot出力にhardlinkがあります: {current}")


def _prepare_standard_output(output_directory: Path) -> Path:
    """one-shot出力rootをsymlink/reparseなしの実directoryとして用意する。"""

    lexical = Path(os.path.abspath(output_directory))
    chain = (*reversed(lexical.parents), lexical)
    for component in chain:
        if not _entry_exists(component):
            continue
        if _is_symlink_or_reparse(component):
            raise OrchestrationError(f"one-shot出力pathにsymlink/reparse pointは使用できません: {component}")
        if component == lexical and not stat.S_ISDIR(component.lstat().st_mode):
            raise OrchestrationError(f"one-shot出力pathがdirectoryではありません: {component}")
    if _entry_exists(lexical):
        _validate_standard_output_tree(lexical)
    try:
        lexical.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise OrchestrationError(f"one-shot出力directoryを作成できません: {lexical}") from exc
    for component in chain:
        if _entry_exists(component) and _is_symlink_or_reparse(component):
            raise OrchestrationError(f"one-shot出力pathにsymlink/reparse pointは使用できません: {component}")
    _validate_standard_output_tree(lexical)
    try:
        if not stat.S_ISDIR(lexical.lstat().st_mode):
            raise OrchestrationError(f"one-shot出力pathがdirectoryではありません: {lexical}")
        return lexical.resolve(strict=True)
    except OSError as exc:
        raise OrchestrationError(f"one-shot出力directoryを検査できません: {lexical}") from exc


def _contained_payload_input(payload: Path, raw_name: Any) -> Path:
    """review済みprofileの入力fileを展開root内の通常fileへ限定する。"""

    if not isinstance(raw_name, str) or not raw_name or len(raw_name) > 4096:
        raise OrchestrationError("profileのvvas.inputが不正です。")
    windows = PureWindowsPath(raw_name)
    normalized_parts = tuple(part for part in raw_name.replace("\\", "/").split("/") if part)
    if (
        windows.is_absolute()
        or windows.drive
        or raw_name.startswith(("/", "\\"))
        or not normalized_parts
        or any(part in {".", ".."} for part in normalized_parts)
        or ":" in raw_name
    ):
        raise OrchestrationError("profileのvvas.inputは安全な相対pathで指定してください。")
    lexical_root = Path(os.path.abspath(payload))
    if not _entry_exists(lexical_root):
        raise OrchestrationError("payload rootはsymlinkでない実directoryが必要です。")
    if _is_symlink_or_reparse(lexical_root):
        raise OrchestrationError("payload rootはsymlinkでない実directoryが必要です。")
    try:
        if not stat.S_ISDIR(lexical_root.lstat().st_mode):
            raise OrchestrationError("payload rootはsymlinkでない実directoryが必要です。")
    except OSError as exc:
        raise OrchestrationError("payload rootを検査できません。") from exc
    lexical_candidate = lexical_root.joinpath(*normalized_parts)
    current = lexical_root
    for part in normalized_parts:
        current /= part
        if not _entry_exists(current):
            raise OrchestrationError("profileのvvas.inputが見つかりません。")
        if _is_symlink_or_reparse(current):
            raise OrchestrationError("profileのvvas.inputにsymlink/reparse pointは使用できません。")
    try:
        root = lexical_root.resolve(strict=True)
        candidate = lexical_candidate.resolve(strict=True)
        candidate.relative_to(root)
    except (OSError, ValueError) as exc:
        raise OrchestrationError("profileのvvas.inputが展開root外を指しています。") from exc
    try:
        if not stat.S_ISREG(candidate.lstat().st_mode):
            raise OrchestrationError("profileのvvas.inputはroot内の通常fileが必要です。")
    except OSError as exc:
        raise OrchestrationError("profileのvvas.inputを検査できません。") from exc
    return candidate


def run_vvas_campaign(
    args: argparse.Namespace,
    profile: dict[str, Any],
    python: str,
    framework_root: Path,
) -> None:
    """DLL sideload vvaS campaignを静的に展開、復号、解析する。"""

    vvas = require_mapping(profile.get("vvas"), label="profileのvvas")
    payload = args.output_directory / "payload"
    run_python(
        python,
        [
            framework_root / "common" / "safe_extract_zip.py",
            "--archive",
            args.sample,
            "--output",
            payload,
        ],
        stage="vvaS bundle安全展開",
    )
    source = _contained_payload_input(payload, require_value(vvas, "input", label="profileのvvas"))
    plain = args.output_directory / "decrypted" / "vvaS.xor.bin"
    run_python(
        python,
        [
            framework_root / "malware" / "valleyrat" / "campaigns" / "dll_sideload_vvas_bundle" / "decrypt_vvas.py",
            source,
            plain,
            "--key",
            require_value(vvas, "xor_key", label="profileのvvas"),
            "--expected-sha256",
            require_value(vvas, "expected_plain_sha256", label="profileのvvas"),
        ],
        stage="vvaS復号",
    )
    run_python(
        python,
        [
            framework_root / "malware" / "valleyrat" / "campaigns" / "dll_sideload_vvas_bundle" / "analyze_vvas.py",
            plain,
            "--output-dir",
            args.output_directory / "decoded-analysis",
            "--marker",
            require_value(vvas, "marker", label="profileのvvas"),
        ],
        stage="vvaS静的解析",
    )


def first_msi_member(selected: dict[str, Any]) -> str:
    """先頭candidateからMSI memberを取得する。"""

    candidates = selected.get("candidates")
    if not isinstance(candidates, list) or not candidates or not isinstance(candidates[0], dict):
        raise OrchestrationError("分類結果にMSI memberがありません。")
    value = candidates[0].get("msi_member")
    if not isinstance(value, str) or not value:
        raise OrchestrationError("分類結果にMSI memberがありません。")
    return value


def run_msi_campaign(
    args: argparse.Namespace,
    selected: dict[str, Any],
    python: str,
    framework_root: Path,
) -> None:
    """MSI/CAB custom action campaignの静的解析を実行する。"""

    msi_member = first_msi_member(selected)
    campaign_root = framework_root / "malware" / "valleyrat" / "campaigns" / "msi_embedded_cab_custom_actions"
    run_python(
        python,
        [
            campaign_root / "analyze_msi.py",
            "--inner-zip",
            args.sample,
            "--member",
            msi_member,
            "--output",
            args.output_directory / "msi-analysis.json",
        ],
        stage="MSI静的解析",
    )
    chain_command: list[str | Path] = [
        campaign_root / "analyze_chain_c2.py",
        "--inner-zip",
        args.sample,
        "--msi-member",
        msi_member,
        "--output",
        args.output_directory / "msi-chain-c2-analysis.json",
    ]
    if args.network_evidence:
        chain_command.extend(("--network-evidence", args.network_evidence))
    run_python(python, chain_command, stage="MSI chain/C2静的解析")


def reviewed_targets(profile: dict[str, Any]) -> list[dict[str, Any]]:
    """review済みlive target一覧を件数・型・送信量上限付きで読み取る。"""

    raw_targets = profile.get("live_c2_targets")
    if not isinstance(raw_targets, list) or not raw_targets:
        raise OrchestrationError("profileにreview済みlive_c2_targetsがありません。")
    if len(raw_targets) > MAX_LIVE_C2_TARGETS:
        raise OrchestrationError(f"live C2 targetは最大{MAX_LIVE_C2_TARGETS}件です。")
    targets: list[dict[str, Any]] = []
    for index, raw_target in enumerate(raw_targets, start=1):
        target = require_mapping(raw_target, label=f"live_c2_targets[{index}]")
        host = require_value(target, "host", label=f"live_c2_targets[{index}]")
        port = require_value(target, "port", label=f"live_c2_targets[{index}]")
        protocol = require_value(target, "protocol", label=f"live_c2_targets[{index}]")
        if (
            not isinstance(host, str)
            or not 1 <= len(host) <= 253
            or any(ord(character) < 33 or ord(character) == 127 for character in host)
        ):
            raise OrchestrationError(f"live_c2_targets[{index}].hostが不正です。")
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            raise OrchestrationError(f"live_c2_targets[{index}].portが不正です。")
        if not isinstance(protocol, str) or protocol not in _PROTOCOLS:
            raise OrchestrationError(f"live_c2_targets[{index}].protocolが不正です。")
        send_hex = target.get("send_hex")
        if send_hex is not None and (
            not isinstance(send_hex, str)
            or len(send_hex) > MAX_SEND_HEX_CHARACTERS
            or len(send_hex) % 2
            or re.fullmatch(r"[0-9a-fA-F]*", send_hex) is None
        ):
            raise OrchestrationError(f"live_c2_targets[{index}].send_hexが不正です。")
        expected_size = target.get("expected_stage_size")
        if expected_size is not None and (
            isinstance(expected_size, bool)
            or not isinstance(expected_size, int)
            or not 1 <= expected_size <= 16 * 1024 * 1024
        ):
            raise OrchestrationError(f"live_c2_targets[{index}].expected_stage_sizeが不正です。")
        targets.append(target)
    return targets


def validate_jarm_script(script: Path | None) -> Path:
    """JARM helperをsymlink/reparse/hardlinkでない有界なPython fileへ限定する。"""

    if script is None:
        raise OrchestrationError("--collect-jarmには--jarm-scriptの明示指定が必要です。")
    lexical = Path(os.path.abspath(script))
    for component in (*reversed(lexical.parents), lexical):
        if _entry_exists(component) and _is_symlink_or_reparse(component):
            raise OrchestrationError(f"JARM script pathにsymlink/reparse pointは使用できません: {component}")
    if not _entry_exists(lexical):
        raise OrchestrationError(f"JARM scriptが見つかりません: {lexical}")
    try:
        information = lexical.lstat()
    except OSError as exc:
        raise OrchestrationError(f"JARM scriptを検査できません: {lexical}") from exc
    if (
        not stat.S_ISREG(information.st_mode)
        or information.st_nlink != 1
        or not 1 <= information.st_size <= 16 * 1024 * 1024
    ):
        raise OrchestrationError("JARM scriptは16 MiB以下の通常単一link fileである必要があります。")
    try:
        return lexical.resolve(strict=True)
    except OSError as exc:
        raise OrchestrationError(f"JARM scriptを解決できません: {lexical}") from exc


def run_live_checks(
    profile: dict[str, Any],
    collect_jarm: bool,
    output_directory: Path,
    python: str,
    framework_root: Path,
    *,
    jarm_script: Path | None = None,
    nmap_executable: str | Path | None = None,
) -> list[dict[str, Any]]:
    """review済みtargetだけを対象に、Nmap NSE live probeを実行する。"""

    if collect_jarm or jarm_script is not None:
        raise OrchestrationError("active C2観測はNmap NSE-onlyです。外部JARM helperは使用できません。")

    targets = reviewed_targets(profile)
    live_directory = output_directory / "c2-live"
    live_directory.mkdir(parents=True, exist_ok=True)
    results: list[dict[str, Any]] = []
    for index, target in enumerate(targets, start=1):
        host = target["host"]
        port = target["port"]
        protocol = target["protocol"]
        output = live_directory / (f"{index:02d}-{safe_filename_component(host)}-{safe_filename_component(port)}.json")
        command: list[object] = [
            framework_root / "nmap" / "nmap_c2_detector.py",
            host,
            port,
            "--protocol",
            protocol,
            "--timeout",
            "8",
            "--allow-network",
            "--output",
            output,
        ]
        for key, option in (("http_host", "--http-host"), ("http_path", "--http-path")):
            if target.get(key) is not None:
                command.extend((option, target[key]))
        case_id = profile.get("case_id")
        if isinstance(case_id, str) and re.fullmatch(r"[0-9a-fA-F]{64}", case_id):
            command.extend(("--sample-sha256", case_id.casefold()))
        if protocol == "vvas":
            command.append("--allow-reviewed-application-probes")
        if nmap_executable is not None:
            command.extend(("--nmap", nmap_executable))
        run_python(
            python,
            command,
            stage=f"C2 probe {index}",
            allowed_exit_codes=frozenset({0, 1}),
            timeout_seconds=NETWORK_STAGE_TIMEOUT_SECONDS,
        )
        results.append(load_json_object(output, label=f"C2 probe {index}結果"))
    return results


def _virus_total_api_key(args: argparse.Namespace) -> str | None:
    """明示opt-in時だけ環境からVT keyを解決する。"""

    if not args.fetch_virus_total_evidence:
        return None
    key = os.environ.get("VT_API_KEY")
    if not isinstance(key, str) or not key or key.strip() != key:
        raise OrchestrationError("VirusTotal取得を許可しましたがVT_API_KEYが未設定または不正です。")
    return key


def run_legacy(args: argparse.Namespace, python: str, framework_root: Path) -> None:
    """旧ValleyRAT workflowを明示された外部通信だけで再現する。"""

    vt_api_key = _virus_total_api_key(args)
    classification_path = args.output_directory / "classification.json"
    selected = classify_legacy(args, python, framework_root, classification_path)
    vt_evidence: Path | None = None
    if vt_api_key is not None:
        vt_evidence = fetch_vt_evidence(
            selected,
            vt_api_key,
            args.output_directory,
            python,
            framework_root,
        )
    malware_type = selected.get("malware_type")
    if malware_type != "valleyrat":
        raise OrchestrationError(f"登録済みhandlerがないmalware_typeです: {malware_type}")
    profile: dict[str, Any] | None = None
    if args.profile_path:
        validate_profile(args.sample, args.profile_path, python, framework_root)
        profile = load_json_object(args.profile_path, label="ValleyRAT profile")
    campaign_type = selected.get("campaign_type")
    if campaign_type == "dll_sideload_vvas_bundle":
        if args.profile_path is None or profile is None:
            raise OrchestrationError("このhandlerには--profile-pathが必要です。")
        run_vvas_campaign(args, profile, python, framework_root)
    elif campaign_type == "msi_embedded_cab_custom_actions":
        run_msi_campaign(args, selected, python, framework_root)
    else:
        raise OrchestrationError(f"登録済みhandlerがないcampaign_typeです: {campaign_type}")
    live_results: list[dict[str, Any]] = []
    if args.allow_live_c2_check:
        if args.profile_path is None:
            raise OrchestrationError(
                "--allow-live-c2-checkにはreview済みlive_c2_targetsを持つ--profile-pathが必要です。"
            )
        if profile is None:
            profile = load_json_object(args.profile_path, label="ValleyRAT profile")
        live_results = run_live_checks(
            profile,
            args.collect_jarm,
            args.output_directory,
            python,
            framework_root,
            jarm_script=args.jarm_script,
            nmap_executable=args.nmap,
        )
    summary = {
        "malware_type": malware_type,
        "campaign_type": campaign_type,
        "output_directory": str(args.output_directory),
        "executed": False,
        "network_contacted": bool(args.allow_live_c2_check or vt_evidence is not None),
        "vt_sandbox_evidence": str(vt_evidence) if vt_evidence else None,
        "live_c2_results": live_results,
    }
    try:
        (args.output_directory / "run-summary.json").write_text(
            json.dumps(summary, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
    except OSError as exc:
        raise OrchestrationError("run-summary.jsonを書き込めません。") from exc


def orchestrate(
    args: argparse.Namespace,
    *,
    framework_root: Path = FRAMEWORK_ROOT,
) -> None:
    """引数に応じて標準または旧ValleyRATフローを選択する。"""

    if args.collect_jarm:
        raise OrchestrationError("--collect-jarmは廃止済みです。active C2観測はNmap NSE-onlyです。")
    if args.jarm_script is not None:
        raise OrchestrationError("--jarm-scriptは廃止済みです。active C2観測はNmap NSE-onlyです。")
    vt_requested = args.fetch_virus_total_evidence
    legacy_requested = bool(
        args.legacy_valley_workflow
        or args.profile_path
        or args.network_evidence
        or args.allow_live_c2_check
        or vt_requested
    )
    if legacy_requested:
        args.output_directory = _prepare_fresh_legacy_output(args.output_directory)
    else:
        args.output_directory = _prepare_standard_output(args.output_directory)
    python = resolve_python(args.python, framework_root)
    if not legacy_requested:
        run_one_shot(args, python, framework_root)
        print(f"静的解析が完了しました（検体実行・外部接続なし）: {args.output_directory}")
        return
    run_legacy(args, python, framework_root)
    print(f"検体を実行せずに解析が完了しました: {args.output_directory}")


def main(argv: list[str] | None = None) -> int:
    """CLIを解析してcross-platform静的解析を起動する。"""

    args = build_parser().parse_args(argv)
    try:
        orchestrate(args)
    except OrchestrationError as exc:
        print(f"エラー: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
