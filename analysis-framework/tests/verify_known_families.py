#!/usr/bin/env python3
"""既知AgentTesla/RemcosRAT集合の分類をWindows/Linux共通で検証する。"""

from __future__ import annotations

import argparse
from pathlib import Path
import sys
import tempfile


FRAMEWORK_ROOT = Path(__file__).resolve().parents[1]
if str(FRAMEWORK_ROOT) not in sys.path:
    sys.path.insert(0, str(FRAMEWORK_ROOT))

from invoke_analysis import (  # noqa: E402
    JapaneseArgumentParser,
    OrchestrationError,
    load_json_object,
    resolve_python,
    run_python,
)


EXPECTED_CASES = 10


def build_parser() -> argparse.ArgumentParser:
    """Test-KnownFamilies.ps1と対応するCLI引数を構築する。"""

    parser = JapaneseArgumentParser(
        description="既知20検体のfamily、campaign、内側SHA-256を回帰確認します。"
    )
    parser.add_argument("--agenttesla-root", required=True, type=Path)
    parser.add_argument("--remcos-root", required=True, type=Path)
    parser.add_argument(
        "--python",
        help="classifierに使うPython。省略時はOS別のanalysis-framework/.venvを検出します。",
    )
    return parser


def verify_set(family: str, root: Path, python: str, temporary: Path) -> int:
    """1つのfamily集合を分類し、既知の契約を検証する。"""

    if not root.is_dir():
        raise OrchestrationError(f"{family} rootがdirectoryではありません: {root}")
    cases = sorted((path for path in root.iterdir() if path.is_dir()), key=lambda path: path.name)
    if len(cases) != EXPECTED_CASES:
        raise OrchestrationError(
            f"{family}は{EXPECTED_CASES}件必要ですが、{len(cases)}件でした: {root}"
        )

    classifier = FRAMEWORK_ROOT / "classifiers" / "classify_sample.py"
    registry = FRAMEWORK_ROOT / "registry" / "malware_types.json"
    for case in cases:
        archive = case / f"{case.name}.zip"
        if not archive.is_file():
            raise OrchestrationError(f"既知検体ZIPがありません: {archive}")
        output = temporary / f"{family}-{case.name}.json"
        run_python(
            python,
            [
                classifier,
                "--sample",
                archive,
                "--registry",
                registry,
                "--output",
                output,
            ],
            stage=f"{family}/{case.name}分類",
        )
        result = load_json_object(output, label=f"{family}/{case.name}分類結果")
        if result.get("malware_type") != family:
            raise OrchestrationError(
                f"family不一致 {case.name}: {result.get('malware_type')!r}"
            )
        if result.get("campaign_type") == "unknown":
            raise OrchestrationError(f"campaign未解決: {case.name}")
        observations = result.get("observations")
        type_detector = observations.get("type_detector") if isinstance(observations, dict) else None
        inner_hash = type_detector.get("inner_sha256") if isinstance(type_detector, dict) else None
        if inner_hash != case.name:
            raise OrchestrationError(
                f"内側SHA-256不一致 {case.name}: {inner_hash!r}"
            )
    return len(cases)


def main(argv: list[str] | None = None) -> int:
    """既知2 familyの回帰確認を実行する。"""

    args = build_parser().parse_args(argv)
    try:
        python = resolve_python(args.python, FRAMEWORK_ROOT)
        with tempfile.TemporaryDirectory(prefix="known-families-") as temporary_name:
            temporary = Path(temporary_name)
            tested = verify_set("agenttesla", args.agenttesla_root, python, temporary)
            tested += verify_set("remcosrat", args.remcos_root, python, temporary)
    except OrchestrationError as exc:
        print(f"エラー: {exc}", file=sys.stderr)
        return 1
    print(
        f"PASS: {tested}/20件で内側SHA-256を検証し、既知familyとcampaignへ分類しました。"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
