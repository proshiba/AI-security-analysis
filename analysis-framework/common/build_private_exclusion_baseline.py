#!/usr/bin/env python3
"""既存manifestとcase directoryからprivate除外baselineをオフライン生成する。

入力JSONでは``malwarebazaar_batch.manifest_hashes``が認識する検体identity欄だけを
参照し、directory入力ではSHA-256そのものを名前に持つdirectoryだけを参照する。
検体、archive、payloadを開かず、API keyや外部通信も使用しない。出力には検体
SHA-256が含まれるため、解析repository外の通常fileへだけ保存する。
"""

from __future__ import annotations

import argparse
import json
import os
import stat
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

COMMON_ROOT = Path(__file__).resolve().parent
if str(COMMON_ROOT) not in sys.path:
    sys.path.insert(0, str(COMMON_ROOT))

import malwarebazaar_batch

SCHEMA_VERSION = 1
REPOSITORY_ROOT = COMMON_ROOT.parent.parent.resolve()
MAXIMUM_DIRECTORY_ENTRIES = 1_000_000
MAXIMUM_DIRECTORY_DEPTH = 128
MAXIMUM_JSON_TREE_ENTRIES = 1_000_000
MAXIMUM_JSON_TREE_FILES = 20_000
MAXIMUM_JSON_TREE_FILE_BYTES = 128 * 1024 * 1024
MAXIMUM_JSON_TREE_TOTAL_BYTES = 4 * 1024 * 1024 * 1024
MAXIMUM_JSON_TREE_NODES_PER_FILE = 12_000_000
MAXIMUM_JSON_TREE_DEPTH = 128


class BaselineBuildError(ValueError):
    """private baseline生成の安全契約違反を表す。"""


class JapaneseArgumentParser(argparse.ArgumentParser):
    """argparseの固定見出しを日本語へ変換する。"""

    def format_help(self) -> str:
        return (
            super()
            .format_help()
            .replace("usage:", "使用法:")
            .replace("options:", "オプション:")
            .replace(
                "show this help message and exit", "このヘルプを表示して終了します"
            )
        )


@dataclass(frozen=True)
class _TreeEntrySnapshot:
    """JSON tree entryのpath、種類、identity、変更検知用metadata。"""

    relative_path: str
    kind: str
    information: os.stat_result


def _absolute(path: Path) -> Path:
    """symlinkを追跡せず、比較用の絶対pathを返す。"""

    return Path(os.path.abspath(os.fspath(path)))


def _is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdefABCDEF" for character in value)
    )


def _same_lexical_path(first: Path, second: Path) -> bool:
    return os.path.normcase(os.fspath(_absolute(first))) == os.path.normcase(
        os.fspath(_absolute(second))
    )


def _path_sort_key(path: Path) -> tuple[str, str]:
    """Windowsの大小文字差も含め、安定したpath順を返す。"""

    raw = os.fspath(_absolute(path)).replace("\\", "/")
    return raw.casefold(), raw


def _is_within(path: Path, directory: Path) -> bool:
    """case-insensitiveなWindows pathを含め、pathがdirectory配下か判定する。"""

    normalized_path = os.path.normcase(os.fspath(_absolute(path)))
    normalized_directory = os.path.normcase(os.fspath(_absolute(directory)))
    try:
        return (
            os.path.commonpath([normalized_path, normalized_directory])
            == normalized_directory
        )
    except ValueError:
        return False


def _validate_output_location(output: Path) -> Path:
    """private出力がrepository外の非reparse pathであることを確認する。"""

    absolute = _absolute(output)
    malwarebazaar_batch._validate_download_destination_path(absolute)
    try:
        malwarebazaar_batch._reject_existing_download_reparse(absolute)
    except RuntimeError as exc:
        raise BaselineBuildError("出力pathにreparse pointを使用できません。") from exc
    if _is_within(absolute, REPOSITORY_ROOT):
        raise BaselineBuildError(
            "検体SHA-256を含むprivate baselineは解析repository外へ保存してください。"
        )
    if os.path.lexists(absolute):
        information = absolute.lstat()
        if (
            not stat.S_ISREG(information.st_mode)
            or information.st_nlink != 1
            or malwarebazaar_batch._is_reparse_information(information)
        ):
            raise BaselineBuildError(
                "既存出力は単一linkの通常fileである必要があります。"
            )
    return absolute


def _directory_identities(path: Path) -> tuple[frozenset[str], os.stat_result]:
    """非reparse treeを検査し、SHA-256 directory名だけを返す。"""

    absolute = _absolute(path)
    try:
        malwarebazaar_batch._reject_existing_download_reparse(absolute)
        root_identity = absolute.lstat()
    except (OSError, RuntimeError) as exc:
        raise BaselineBuildError("directory入力を安全に確認できません。") from exc
    if (
        not stat.S_ISDIR(root_identity.st_mode)
        or stat.S_ISLNK(root_identity.st_mode)
        or malwarebazaar_batch._is_reparse_information(root_identity)
    ):
        raise BaselineBuildError("directory入力は通常directoryである必要があります。")

    identities: set[str] = set()
    pending: list[tuple[Path, int]] = [(absolute, 0)]
    observed_entries = 0
    while pending:
        current, depth = pending.pop()
        if depth > MAXIMUM_DIRECTORY_DEPTH:
            raise BaselineBuildError("directory入力が深さ上限を超えました。")
        try:
            with os.scandir(current) as iterator:
                entries = list(iterator)
        except OSError as exc:
            raise BaselineBuildError("directory入力を走査できません。") from exc
        observed_entries += len(entries)
        if observed_entries > MAXIMUM_DIRECTORY_ENTRIES:
            raise BaselineBuildError("directory入力のentry数が上限を超えました。")
        for entry in entries:
            try:
                information = entry.stat(follow_symlinks=False)
            except OSError as exc:
                raise BaselineBuildError(
                    "directory入力のidentityを確認できません。"
                ) from exc
            if entry.is_symlink() or malwarebazaar_batch._is_reparse_information(
                information
            ):
                # --input directoryではSHA-256名の実directoryだけを採用する。
                # reparse entryは開かず、追跡せず、identityにも採用しない。
                continue
            entry_path = Path(entry.path)
            if stat.S_ISDIR(information.st_mode):
                if _is_sha256(entry.name):
                    identities.add(entry.name.lower())
                pending.append((entry_path, depth + 1))
            elif stat.S_ISREG(information.st_mode):
                # --input directoryではfile内容もfile名も参照しないため、通常fileの
                # hardlink数はSHA-256 directory identity集合へ影響しない。
                pass
            else:
                raise BaselineBuildError(
                    "directory入力内に通常file／directory以外を使用できません。"
                )

    try:
        final_identity = absolute.lstat()
    except OSError as exc:
        raise BaselineBuildError(
            "directory入力のidentityが走査中に変化しました。"
        ) from exc
    if (
        not stat.S_ISDIR(final_identity.st_mode)
        or malwarebazaar_batch._is_reparse_information(final_identity)
        or not malwarebazaar_batch._same_file_identity(root_identity, final_identity)
    ):
        raise BaselineBuildError("directory入力のidentityが走査中に変化しました。")
    return frozenset(identities), final_identity


def _validate_input_collision(inputs: Sequence[Path], output: Path) -> None:
    """出力と入力file／directoryの重複を拒否する。"""

    for source in inputs:
        if _same_lexical_path(source, output):
            raise BaselineBuildError("入力と出力に同じpathを指定できません。")
        try:
            information = _absolute(source).lstat()
        except OSError as exc:
            raise BaselineBuildError("入力pathが存在しません。") from exc
        if stat.S_ISDIR(information.st_mode) and _is_within(output, source):
            raise BaselineBuildError("directory入力の配下へ出力を保存できません。")
        if os.path.lexists(output) and stat.S_ISREG(information.st_mode):
            try:
                if os.path.samefile(source, output):
                    raise BaselineBuildError("入力と出力のhardlink衝突を検出しました。")
            except OSError as exc:
                raise BaselineBuildError(
                    "入力と出力のidentityを比較できません。"
                ) from exc


def _tree_entry_is_unchanged(
    first: _TreeEntrySnapshot, second: _TreeEntrySnapshot
) -> bool:
    """tree entryのidentityと解析に影響するmetadataが一致するか返す。"""

    first_information = first.information
    second_information = second.information
    return (
        first.relative_path == second.relative_path
        and first.kind == second.kind
        and malwarebazaar_batch._same_file_identity(
            first_information, second_information
        )
        and first_information.st_mode == second_information.st_mode
        and first_information.st_nlink == second_information.st_nlink
        and first_information.st_size == second_information.st_size
        and first_information.st_mtime_ns == second_information.st_mtime_ns
        and first_information.st_ctime_ns == second_information.st_ctime_ns
    )


def _json_tree_snapshot(
    path: Path,
) -> tuple[tuple[Path, ...], tuple[_TreeEntrySnapshot, ...]]:
    """非reparse treeを決定的に走査し、JSON通常fileと全entry snapshotを返す。"""

    absolute = _absolute(path)
    try:
        malwarebazaar_batch._reject_existing_download_reparse(absolute)
        root_information = absolute.lstat()
    except (OSError, RuntimeError) as exc:
        raise BaselineBuildError("JSON tree入力を安全に確認できません。") from exc
    if (
        not stat.S_ISDIR(root_information.st_mode)
        or stat.S_ISLNK(root_information.st_mode)
        or malwarebazaar_batch._is_reparse_information(root_information)
    ):
        raise BaselineBuildError("JSON tree入力は通常directoryである必要があります。")

    snapshots: list[_TreeEntrySnapshot] = [
        _TreeEntrySnapshot(".", "directory", root_information)
    ]
    json_files: list[Path] = []
    pending: list[tuple[Path, int]] = [(absolute, 0)]
    observed_entries = 0
    while pending:
        current, depth = pending.pop()
        if depth > MAXIMUM_DIRECTORY_DEPTH:
            raise BaselineBuildError("JSON tree入力が深さ上限を超えました。")
        try:
            with os.scandir(current) as iterator:
                entries = sorted(
                    iterator,
                    key=lambda entry: (entry.name.casefold(), entry.name),
                )
        except OSError as exc:
            raise BaselineBuildError("JSON tree入力を走査できません。") from exc
        observed_entries += len(entries)
        if observed_entries > MAXIMUM_JSON_TREE_ENTRIES:
            raise BaselineBuildError("JSON tree入力のentry数が上限を超えました。")

        child_directories: list[tuple[Path, int]] = []
        for entry in entries:
            entry_path = Path(entry.path)
            try:
                # WindowsのDirEntry.statは通常fileでもst_nlink=0を返す場合があるため、
                # hardlink判定を含むidentity固定にはPath.lstatを使用する。
                information = entry_path.lstat()
            except OSError as exc:
                raise BaselineBuildError(
                    "JSON tree入力のidentityを確認できません。"
                ) from exc
            if entry.is_symlink() or malwarebazaar_batch._is_reparse_information(
                information
            ):
                raise BaselineBuildError(
                    "JSON tree入力内にreparse pointを使用できません。"
                )
            try:
                relative = entry_path.relative_to(absolute).as_posix()
            except ValueError as exc:
                raise BaselineBuildError(
                    "JSON tree入力のpath境界を確認できません。"
                ) from exc
            if stat.S_ISDIR(information.st_mode):
                snapshots.append(_TreeEntrySnapshot(relative, "directory", information))
                child_directories.append((entry_path, depth + 1))
            elif stat.S_ISREG(information.st_mode):
                if information.st_nlink != 1:
                    raise BaselineBuildError(
                        "JSON tree入力内にhardlinkを使用できません。"
                    )
                snapshots.append(_TreeEntrySnapshot(relative, "file", information))
                if entry_path.suffix.casefold() == ".json":
                    json_files.append(entry_path)
            else:
                raise BaselineBuildError(
                    "JSON tree入力内に通常file／directory以外を使用できません。"
                )

        # stackから取り出したときもpath順になるよう逆順で積む。
        pending.extend(reversed(child_directories))

    snapshots.sort(key=lambda item: (item.relative_path.casefold(), item.relative_path))
    json_files.sort(key=_path_sort_key)
    return tuple(json_files), tuple(snapshots)


def _collect_json_tree_hashes(json_trees: Sequence[Path]) -> set[str]:
    """bounded JSON treeをstrict parseし、走査前後のidentityを再確認する。"""

    roots_by_key: dict[str, Path] = {}
    for root in json_trees:
        absolute = _absolute(root)
        key = os.path.normcase(os.fspath(absolute))
        roots_by_key.setdefault(key, absolute)
    roots = sorted(roots_by_key.values(), key=_path_sort_key)

    before_snapshots: dict[Path, tuple[_TreeEntrySnapshot, ...]] = {}
    files_by_key: dict[str, Path] = {}
    file_information_by_key: dict[str, os.stat_result] = {}
    for root in roots:
        files, snapshot = _json_tree_snapshot(root)
        before_snapshots[root] = snapshot
        for file_path in files:
            key = os.path.normcase(os.fspath(_absolute(file_path)))
            if key in files_by_key:
                continue
            information = file_path.lstat()
            files_by_key[key] = file_path
            file_information_by_key[key] = information

    files = sorted(files_by_key.values(), key=_path_sort_key)
    if len(files) > MAXIMUM_JSON_TREE_FILES:
        raise BaselineBuildError("JSON tree入力のJSON file数が上限を超えました。")
    total_bytes = 0
    for file_path in files:
        key = os.path.normcase(os.fspath(_absolute(file_path)))
        size = file_information_by_key[key].st_size
        if not 0 < size <= MAXIMUM_JSON_TREE_FILE_BYTES:
            raise BaselineBuildError("JSON tree入力の単体JSON sizeが上限外です。")
        total_bytes += size
        if total_bytes > MAXIMUM_JSON_TREE_TOTAL_BYTES:
            raise BaselineBuildError("JSON tree入力のJSON総sizeが上限を超えました。")

    hashes: set[str] = set()
    if files:
        try:
            hashes = malwarebazaar_batch.manifest_hashes(
                files,
                max_json_bytes=MAXIMUM_JSON_TREE_FILE_BYTES,
                max_json_nodes=MAXIMUM_JSON_TREE_NODES_PER_FILE,
                max_json_depth=MAXIMUM_JSON_TREE_DEPTH,
            )
        except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
            raise BaselineBuildError(
                "JSON tree入力をstrict JSONとして読み取れません。"
            ) from exc

    for root in roots:
        _, after = _json_tree_snapshot(root)
        before = before_snapshots[root]
        if len(before) != len(after) or any(
            not _tree_entry_is_unchanged(first, second)
            for first, second in zip(before, after, strict=True)
        ):
            raise BaselineBuildError("JSON tree入力が読取り中に変化しました。")
    return hashes


def _collect_manifest_hashes(inputs: Sequence[Path]) -> set[str]:
    """strict snapshotを前後照合し、既存manifest_hashesで検体identityを集約する。"""

    collected: set[str] = set()
    for source in inputs:
        absolute = _absolute(source)
        try:
            malwarebazaar_batch._reject_existing_download_reparse(absolute)
            information = absolute.lstat()
        except (OSError, RuntimeError) as exc:
            raise BaselineBuildError("入力pathを安全に確認できません。") from exc

        if stat.S_ISREG(information.st_mode):
            if information.st_nlink != 1 or malwarebazaar_batch._is_reparse_information(
                information
            ):
                raise BaselineBuildError(
                    "JSON入力は単一linkの通常fileである必要があります。"
                )
            try:
                before = malwarebazaar_batch._strict_json_object_snapshot(
                    absolute,
                    max_bytes=malwarebazaar_batch.MAX_MANIFEST_BYTES,
                )
                observed = malwarebazaar_batch.manifest_hashes([absolute])
                after = malwarebazaar_batch._strict_json_object_snapshot(
                    absolute,
                    max_bytes=malwarebazaar_batch.MAX_MANIFEST_BYTES,
                )
            except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
                raise BaselineBuildError(
                    "JSON入力をstrict manifestとして読み取れません。"
                ) from exc
            if before != after:
                raise BaselineBuildError("JSON入力が読取り中に変化しました。")
            collected.update(observed)
            continue

        if stat.S_ISDIR(information.st_mode):
            before_hashes, before_identity = _directory_identities(absolute)
            after_hashes, after_identity = _directory_identities(absolute)
            if (
                before_hashes != after_hashes
                or not malwarebazaar_batch._same_file_identity(
                    before_identity, after_identity
                )
            ):
                raise BaselineBuildError("directory入力が走査中に変化しました。")
            # 個別directoryにSHA-256名directoryが0件でも、複数入力をunionする
            # baselineでは正当な補助入力になり得る。
            collected.update(before_hashes)
            continue

        raise BaselineBuildError(
            "入力はJSON通常fileまたは通常directoryに限定されます。"
        )
    return collected


def baseline_document(identities: Sequence[str]) -> dict[str, Any]:
    """migrate-stateと互換なstrict private baseline文書を返す。"""

    normalized = sorted(
        {identity.lower() for identity in identities if _is_sha256(identity)}
    )
    if len(normalized) != len(set(identities)) or any(
        not _is_sha256(identity) for identity in identities
    ):
        raise BaselineBuildError("baseline identity集合が不正です。")
    return {
        "schema_version": SCHEMA_VERSION,
        "identity_type": "sha256",
        "identity_count": len(normalized),
        "identities": normalized,
        "excluded_hashes_sha256": malwarebazaar_batch._canonical_sha256(normalized),
        "classification": "private",
        "contains_sample_sha256": True,
        "publishable": False,
    }


def build_private_exclusion_baseline(
    inputs: Sequence[Path],
    output: Path,
    *,
    json_trees: Sequence[Path] = (),
) -> tuple[dict[str, Any], str]:
    """複数入力を集約し、同一内容だけ再利用可能なprivate baselineを保存する。"""

    if not inputs and not json_trees:
        raise BaselineBuildError("少なくとも1件の--inputまたは--json-treeが必要です。")
    normalized_inputs = tuple(_absolute(path) for path in inputs)
    normalized_trees = tuple(_absolute(path) for path in json_trees)
    normalized_output = _validate_output_location(output)
    _validate_input_collision(
        (*normalized_inputs, *normalized_trees), normalized_output
    )
    identities = _collect_manifest_hashes(normalized_inputs)
    identities.update(_collect_json_tree_hashes(normalized_trees))
    if not identities:
        raise BaselineBuildError("全入力の検体SHA-256 identity集合が空です。")
    document = baseline_document(sorted(identities))

    if os.path.lexists(normalized_output):
        try:
            existing = malwarebazaar_batch._strict_json_object_snapshot(
                normalized_output,
                max_bytes=malwarebazaar_batch.MAX_MANIFEST_BYTES,
            )
        except RuntimeError as exc:
            raise BaselineBuildError(
                "既存baselineをstrict JSONとして検証できません。"
            ) from exc
        if existing != document:
            raise BaselineBuildError(
                "既存baselineと収集結果が一致しないため差替えを拒否しました。"
            )
        return document, "validated_existing"

    try:
        malwarebazaar_batch._write_json_atomic(normalized_output, document)
    except RuntimeError as exc:
        raise BaselineBuildError("private baselineを原子的に保存できません。") from exc
    return document, "written"


def build_parser() -> argparse.ArgumentParser:
    """private除外baseline生成CLIの引数を定義する。"""

    parser = JapaneseArgumentParser(description=__doc__, add_help=False)
    parser.add_argument(
        "-h", "--help", action="help", help="このヘルプを表示して終了します"
    )
    parser.add_argument(
        "--input",
        action="append",
        default=[],
        type=Path,
        help=(
            "既存のJSON manifest、またはSHA-256 directory名だけを収集するcase directory。"
            "繰返し指定できます。"
        ),
    )
    parser.add_argument(
        "--json-tree",
        action="append",
        default=[],
        type=Path,
        help=(
            "配下の.jsonをpath順にstrict parseするbounded JSON tree。"
            "繰返し指定できます。"
        ),
    )
    parser.add_argument(
        "--output",
        required=True,
        type=Path,
        help="repository外へ保存するprivate baseline JSON。",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """外部通信せずprivate除外baselineを生成する。"""

    args = build_parser().parse_args(argv)
    try:
        document, status = build_private_exclusion_baseline(
            args.input,
            args.output,
            json_trees=args.json_tree,
        )
    except BaselineBuildError as exc:
        raise SystemExit(str(exc)) from exc
    print(
        json.dumps(
            {
                "schema_version": SCHEMA_VERSION,
                "status": status,
                "identity_count": document["identity_count"],
                "excluded_hashes_sha256": document["excluded_hashes_sha256"],
                "sample_identifiers_included": False,
                "network_contacted": False,
            },
            ensure_ascii=False,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
