#!/usr/bin/env python3
"""既知AgentTesla/RemcosRAT集合を安全なpath契約で検証する。"""

from __future__ import annotations

import argparse
from pathlib import Path
import re
import stat
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
_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")
_REPARSE_POINT = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))


def _entry_exists(path: Path) -> bool:
    """broken symlinkを含め、path entryの存在をlstatで確認する。"""

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


def _validated_cases(root: Path, *, family: str) -> list[tuple[Path, Path]]:
    """10件のlowercase SHA-256 caseと通常ZIPをroot内へ限定する。"""

    if not _entry_exists(root) or _is_symlink_or_reparse(root):
        raise OrchestrationError(f"{family} rootはsymlinkでない実directoryが必要です: {root}")
    try:
        if not stat.S_ISDIR(root.lstat().st_mode):
            raise OrchestrationError(f"{family} rootがdirectoryではありません: {root}")
        resolved_root = root.resolve(strict=True)
        entries = sorted(resolved_root.iterdir(), key=lambda path: path.name)
    except OSError as exc:
        raise OrchestrationError(f"{family} rootを列挙できません: {root}") from exc
    cases: list[tuple[Path, Path]] = []
    for entry in entries:
        if _is_symlink_or_reparse(entry):
            raise OrchestrationError(f"{family} root直下にsymlink/junctionがあります: {entry}")
        try:
            mode = entry.lstat().st_mode
        except OSError as exc:
            raise OrchestrationError(f"{family} entryを検査できません: {entry}") from exc
        if not stat.S_ISDIR(mode):
            continue
        if not _SHA256_PATTERN.fullmatch(entry.name):
            raise OrchestrationError(f"{family} case名がlowercase SHA-256ではありません: {entry.name}")
        try:
            case = entry.resolve(strict=True)
            case.relative_to(resolved_root)
        except (OSError, ValueError) as exc:
            raise OrchestrationError(f"{family} caseがroot外です: {entry}") from exc
        archive = case / f"{case.name}.zip"
        if not _entry_exists(archive) or _is_symlink_or_reparse(archive):
            raise OrchestrationError(f"既知検体ZIPがないかsymlinkです: {archive}")
        try:
            if not stat.S_ISREG(archive.lstat().st_mode):
                raise OrchestrationError(f"既知検体ZIPが通常fileではありません: {archive}")
            resolved_archive = archive.resolve(strict=True)
            resolved_archive.relative_to(case)
        except (OSError, ValueError) as exc:
            raise OrchestrationError(f"既知検体ZIPがcase外です: {archive}") from exc
        cases.append((case, resolved_archive))
    if len(cases) != EXPECTED_CASES:
        raise OrchestrationError(f"{family}は{EXPECTED_CASES}件必要ですが、{len(cases)}件でした: {root}")
    return cases


def build_parser() -> argparse.ArgumentParser:
    """Test-KnownFamilies.ps1と対応するCLI引数を構築する。"""

    parser = JapaneseArgumentParser(description="既知20検体のfamily、campaign、内側SHA-256を回帰確認します。")
    parser.add_argument("--agenttesla-root", required=True, type=Path, help="AgentTesla 10件のroot。")
    parser.add_argument("--remcos-root", required=True, type=Path, help="RemcosRAT 10件のroot。")
    parser.add_argument(
        "--python",
        help="classifierに使うPython。省略時はOS別のanalysis-framework/.venvを検出します。",
    )
    return parser


def verify_set(family: str, root: Path, python: str, temporary: Path) -> int:
    """1つのfamily集合を分類し、既知の契約を検証する。"""

    cases = _validated_cases(root, family=family)
    classifier = FRAMEWORK_ROOT / "classifiers" / "classify_sample.py"
    registry = FRAMEWORK_ROOT / "registry" / "malware_types.json"
    for case, archive in cases:
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
            raise OrchestrationError(f"family不一致 {case.name}: {result.get('malware_type')!r}")
        campaign_type = result.get("campaign_type")
        if not isinstance(campaign_type, str) or not campaign_type or campaign_type == "unknown":
            raise OrchestrationError(f"campaign未解決: {case.name}")
        observations = result.get("observations")
        type_detector = observations.get("type_detector") if isinstance(observations, dict) else None
        inner_hash = type_detector.get("inner_sha256") if isinstance(type_detector, dict) else None
        if inner_hash != case.name:
            raise OrchestrationError(f"内側SHA-256不一致 {case.name}: {inner_hash!r}")
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
    print(f"PASS: {tested}/20件で内側SHA-256を検証し、既知familyとcampaignへ分類しました。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
