#!/usr/bin/env python3
"""WindowsとLinuxで同じ静的解析フローを起動する。"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from typing import Any, Iterable


FRAMEWORK_ROOT = Path(__file__).resolve().parent
ALLOWED_ARCHIVE_MODES = ("auto", "raw", "malwarebazaar")


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


def resolve_python(
    requested: str | None,
    framework_root: Path = FRAMEWORK_ROOT,
    *,
    os_name: str | None = None,
) -> str:
    """明示指定、OS別venv、現在のinterpreterの順でPythonを選ぶ。"""

    if requested:
        return requested

    platform_os = os.name if os_name is None else os_name
    if platform_os == "nt":
        candidate = framework_root / ".venv" / "Scripts" / "python.exe"
    else:
        candidate = framework_root / ".venv" / "bin" / "python"
    if candidate.is_file():
        return str(candidate)
    if not sys.executable:
        raise OrchestrationError(
            "利用可能なPython interpreterを特定できません。--pythonで指定してください。"
        )
    return sys.executable


def run_python(
    python: str,
    arguments: Iterable[object],
    *,
    stage: str,
    allowed_exit_codes: frozenset[int] = frozenset({0}),
) -> int:
    """shellを介さずPython stageを実行し、許可外の終了codeを拒否する。"""

    command = [python, *(str(argument) for argument in arguments)]
    try:
        completed = subprocess.run(command, check=False)
    except OSError as exc:
        raise OrchestrationError(f"{stage}を起動できません: {exc}") from exc
    if completed.returncode not in allowed_exit_codes:
        raise OrchestrationError(f"{stage}が終了code {completed.returncode}で失敗しました。")
    return completed.returncode


def load_json_object(path: Path, *, label: str) -> dict[str, Any]:
    """UTF-8/BOM付きUTF-8のJSON objectを読み込む。"""

    try:
        value = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise OrchestrationError(f"{label}を読み込めません: {path}: {exc}") from exc
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
    """WindowsとPOSIXの双方で安全な結果file名要素へ変換する。"""

    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", str(value)).strip("._")
    return cleaned or "target"


def build_parser() -> argparse.ArgumentParser:
    """Invoke-Analysis.ps1と対応するCLI引数を構築する。"""

    parser = JapaneseArgumentParser(
        description="検体を実行せず、Windows/Linux共通の静的解析フローを起動します。"
    )
    parser.add_argument("--sample", required=True, type=Path, help="解析する検体fileまたはdirectory。")
    parser.add_argument("--output-directory", required=True, type=Path, help="解析結果の出力先。")
    parser.add_argument("--profile-path", type=Path, help="review済みValleyRAT profile。")
    parser.add_argument("--network-evidence", type=Path, help="既存のnetwork evidence JSON。")
    parser.add_argument("--malware-type", help="分類対象を登録済みマルウェア種へ限定します。")
    parser.add_argument(
        "--virus-total-api-key",
        default=os.environ.get("VT_API_KEY"),
        help="旧フローでVT sandbox evidenceを取得するAPI key。既定はVT_API_KEY。",
    )
    parser.add_argument(
        "--allow-live-c2-check",
        action="store_true",
        help="review済みprofileのtargetだけに限定したlive C2確認を許可します。",
    )
    parser.add_argument(
        "--collect-jarm",
        action="store_true",
        help="live TLS系targetでJARMも収集します。",
    )
    parser.add_argument(
        "--archive-mode",
        choices=ALLOWED_ARCHIVE_MODES,
        default="auto",
        help="通常のone-shot静的解析へ渡すarchive mode。",
    )
    parser.add_argument(
        "--assessment-only",
        action="store_true",
        help="通常フローで適用可否判定だけを実行します。",
    )
    parser.add_argument(
        "--legacy-valley-workflow",
        action="store_true",
        help="旧ValleyRAT campaign handlerフローを明示的に使用します。",
    )
    parser.add_argument(
        "--python",
        help="子stageに使うPython。省略時はOS別のanalysis-framework/.venvを検出します。",
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
    """旧フローと同じ完全hash限定VT sandbox evidenceを取得する。"""

    observations = require_mapping(selected.get("observations"), label="分類結果のobservations")
    sample_hash = require_value(observations, "sha256", label="分類結果のobservations")
    output = output_directory / "virustotal-sandbox.json"
    run_python(
        python,
        [
            framework_root / "common" / "vt_sandbox.py",
            "--sha256",
            sample_hash,
            "--api-key",
            api_key,
            "--output",
            output,
        ],
        stage="VirusTotal sandbox evidence取得",
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

    plain = args.output_directory / "decrypted" / "vvaS.xor.bin"
    run_python(
        python,
        [
            framework_root
            / "malware"
            / "valleyrat"
            / "campaigns"
            / "dll_sideload_vvas_bundle"
            / "decrypt_vvas.py",
            payload / str(require_value(vvas, "input", label="profileのvvas")),
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
            framework_root
            / "malware"
            / "valleyrat"
            / "campaigns"
            / "dll_sideload_vvas_bundle"
            / "analyze_vvas.py",
            plain,
            "--output-dir",
            args.output_directory / "decoded-analysis",
            "--marker",
            require_value(vvas, "marker", label="profileのvvas"),
        ],
        stage="vvaS静的解析",
    )


def first_msi_member(selected: dict[str, Any]) -> str:
    """PowerShell版と同じ先頭candidateからMSI memberを取得する。"""

    candidates = selected.get("candidates")
    if not isinstance(candidates, list) or not candidates or not isinstance(candidates[0], dict):
        raise OrchestrationError("Classifier did not return the MSI member.")
    value = candidates[0].get("msi_member")
    if not isinstance(value, str) or not value:
        raise OrchestrationError("Classifier did not return the MSI member.")
    return value


def run_msi_campaign(
    args: argparse.Namespace,
    selected: dict[str, Any],
    python: str,
    framework_root: Path,
) -> None:
    """MSI/CAB custom action campaignの静的解析を実行する。"""

    msi_member = first_msi_member(selected)
    campaign_root = (
        framework_root
        / "malware"
        / "valleyrat"
        / "campaigns"
        / "msi_embedded_cab_custom_actions"
    )
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
    """review済みlive target一覧を厳格に読み取る。"""

    raw_targets = profile.get("live_c2_targets")
    if not isinstance(raw_targets, list) or not raw_targets:
        raise OrchestrationError("Profile contains no reviewed live_c2_targets.")
    targets: list[dict[str, Any]] = []
    for index, target in enumerate(raw_targets, start=1):
        targets.append(require_mapping(target, label=f"live_c2_targets[{index}]"))
    return targets


def run_live_checks(
    profile: dict[str, Any],
    collect_jarm: bool,
    output_directory: Path,
    python: str,
    framework_root: Path,
) -> list[dict[str, Any]]:
    """review済みtargetだけを対象に、上限付きlive probeを実行する。"""

    targets = reviewed_targets(profile)
    live_directory = output_directory / "c2-live"
    live_directory.mkdir(parents=True, exist_ok=True)
    results: list[dict[str, Any]] = []
    for index, target in enumerate(targets, start=1):
        host = require_value(target, "host", label=f"live_c2_targets[{index}]")
        port = require_value(target, "port", label=f"live_c2_targets[{index}]")
        protocol = require_value(target, "protocol", label=f"live_c2_targets[{index}]")
        output = live_directory / (
            f"{index:02d}-{safe_filename_component(host)}-{safe_filename_component(port)}.json"
        )
        command: list[object] = [
            framework_root / "common" / "c2_detector.py",
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
        optional_values = (
            ("send_hex", "--send-hex"),
            ("expected_stage_size", "--expected-stage-size"),
            ("http_host", "--http-host"),
            ("sni", "--sni"),
        )
        for key, option in optional_values:
            if target.get(key):
                command.extend((option, target[key]))
        if collect_jarm and str(protocol) in {"https", "tls", "n520"}:
            command.append("--collect-jarm")
        run_python(
            python,
            command,
            stage=f"C2 probe {index}",
            allowed_exit_codes=frozenset({0, 1}),
        )
        results.append(load_json_object(output, label=f"C2 probe {index}結果"))
    return results


def run_legacy(args: argparse.Namespace, python: str, framework_root: Path) -> None:
    """Invoke-Analysis.ps1の旧ValleyRAT workflowを再現する。"""

    classification_path = args.output_directory / "classification.json"
    selected = classify_legacy(args, python, framework_root, classification_path)
    vt_evidence: Path | None = None
    if args.virus_total_api_key:
        vt_evidence = fetch_vt_evidence(
            selected,
            args.virus_total_api_key,
            args.output_directory,
            python,
            framework_root,
        )

    malware_type = selected.get("malware_type")
    if malware_type != "valleyrat":
        raise OrchestrationError(f"No malware handler is registered for: {malware_type}")

    profile: dict[str, Any] | None = None
    if args.profile_path:
        validate_profile(args.sample, args.profile_path, python, framework_root)
        profile = load_json_object(args.profile_path, label="ValleyRAT profile")

    campaign_type = selected.get("campaign_type")
    if campaign_type == "dll_sideload_vvas_bundle":
        if args.profile_path is None or profile is None:
            raise OrchestrationError("This handler requires --profile-path.")
        run_vvas_campaign(args, profile, python, framework_root)
    elif campaign_type == "msi_embedded_cab_custom_actions":
        run_msi_campaign(args, selected, python, framework_root)
    else:
        raise OrchestrationError(f"No campaign handler is registered for: {campaign_type}")

    live_results: list[dict[str, Any]] = []
    if args.allow_live_c2_check:
        if args.profile_path is None:
            raise OrchestrationError(
                "--allow-live-c2-check requires a reviewed --profile-path with live_c2_targets."
            )
        if profile is None:
            profile = load_json_object(args.profile_path, label="ValleyRAT profile")
        live_results = run_live_checks(
            profile,
            args.collect_jarm,
            args.output_directory,
            python,
            framework_root,
        )

    summary = {
        "malware_type": malware_type,
        "campaign_type": campaign_type,
        "output_directory": str(args.output_directory),
        "executed": False,
        "network_contacted": bool(args.allow_live_c2_check or args.virus_total_api_key),
        "vt_sandbox_evidence": str(vt_evidence) if vt_evidence else None,
        "live_c2_results": live_results,
    }
    (args.output_directory / "run-summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def orchestrate(
    args: argparse.Namespace,
    *,
    framework_root: Path = FRAMEWORK_ROOT,
) -> None:
    """引数に応じて標準または旧ValleyRATフローを選択する。"""

    args.output_directory.mkdir(parents=True, exist_ok=True)
    python = resolve_python(args.python, framework_root)
    legacy_requested = bool(
        args.legacy_valley_workflow
        or args.profile_path
        or args.network_evidence
        or args.allow_live_c2_check
        or args.collect_jarm
    )
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
