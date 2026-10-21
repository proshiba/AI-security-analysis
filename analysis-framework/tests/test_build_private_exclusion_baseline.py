"""private除外baseline生成CLIの安全契約を検証する。"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

COMMON = Path(__file__).parents[1] / "common"
sys.path.insert(0, str(COMMON))

import build_private_exclusion_baseline as baseline
import evaluate_valleyrat_cycles as cycles
import malwarebazaar_batch


def _outside_repository(tmp_path: Path, name: str = "baseline.json") -> Path:
    assert not baseline._is_within(tmp_path, baseline.REPOSITORY_ROOT)
    return tmp_path / name


def test_builds_exact_sorted_schema_from_known_manifest_fields_and_directories(
    tmp_path: Path,
) -> None:
    """既知identity欄とSHA directoryだけを集約し、任意64hexは除外する。"""

    direct = "a" * 64
    nested = "b" * 64
    selected = "c" * 64
    case_key = "d" * 64
    directory_hash = "e" * 64
    credential_like = "f" * 64
    archive_hash = "1" * 64
    manifest = tmp_path / "source.json"
    manifest.write_text(
        json.dumps(
            {
                "sha256": direct.upper(),
                "items": [{"sha256_hash": nested}],
                "selected_hashes": [selected],
                "cases": {case_key: {"status": "partial"}},
                "api_key": credential_like,
                "token": credential_like,
                "arbitrary": [credential_like],
                "zip_sha256": archive_hash,
            }
        ),
        encoding="utf-8",
    )
    cases = tmp_path / "cases"
    (cases / directory_hash).mkdir(parents=True)
    (cases / credential_like[:63]).mkdir()
    ignored_directory_json_hash = "2" * 64
    (cases / "ignored.json").write_text(
        json.dumps({"sha256": ignored_directory_json_hash}),
        encoding="utf-8",
    )
    output = _outside_repository(tmp_path, "private-baseline.json")

    document, status = baseline.build_private_exclusion_baseline(
        [manifest, cases],
        output,
    )

    expected = sorted({direct, nested, selected, case_key, directory_hash})
    assert status == "written"
    assert document == {
        "schema_version": 1,
        "identity_type": "sha256",
        "identity_count": len(expected),
        "identities": expected,
        "excluded_hashes_sha256": malwarebazaar_batch._canonical_sha256(expected),
        "classification": "private",
        "contains_sample_sha256": True,
        "publishable": False,
    }
    assert json.loads(output.read_text(encoding="utf-8")) == document
    assert credential_like not in document["identities"]
    assert archive_hash not in document["identities"]
    assert ignored_directory_json_hash not in document["identities"]
    assert cycles._baseline_hashes_from_files([output]) == tuple(expected)
    assert malwarebazaar_batch.manifest_hashes([output]) == set(expected)


def test_existing_output_is_only_reused_for_identical_content(tmp_path: Path) -> None:
    """冪等再実行だけを許可し、異なる集合による差替えを拒否する。"""

    first, second = "a" * 64, "b" * 64
    source = tmp_path / "source.json"
    source.write_text(json.dumps({"selected_hashes": [first]}), encoding="utf-8")
    output = _outside_repository(tmp_path)
    original, status = baseline.build_private_exclusion_baseline([source], output)
    assert status == "written"
    original_bytes = output.read_bytes()

    repeated, status = baseline.build_private_exclusion_baseline([source], output)
    assert status == "validated_existing"
    assert repeated == original
    assert output.read_bytes() == original_bytes

    source.write_text(
        json.dumps({"selected_hashes": [first, second]}), encoding="utf-8"
    )
    with pytest.raises(baseline.BaselineBuildError, match="差替え"):
        baseline.build_private_exclusion_baseline([source], output)
    assert output.read_bytes() == original_bytes


def test_rejects_output_input_collisions_and_repository_output(tmp_path: Path) -> None:
    """同一file、directory内出力、repository内private出力を拒否する。"""

    source = tmp_path / "source.json"
    source.write_text(json.dumps({"sha256": "a" * 64}), encoding="utf-8")
    with pytest.raises(baseline.BaselineBuildError, match="同じpath"):
        baseline.build_private_exclusion_baseline([source], source)

    source_dir = tmp_path / "cases"
    source_dir.mkdir()
    with pytest.raises(baseline.BaselineBuildError, match="配下"):
        baseline.build_private_exclusion_baseline(
            [source_dir],
            source_dir / "baseline.json",
        )

    repository_output = baseline.REPOSITORY_ROOT / ".work" / "private-baseline.json"
    with pytest.raises(baseline.BaselineBuildError, match="repository外"):
        baseline.build_private_exclusion_baseline([source], repository_output)


def test_rejects_hardlinked_input_and_output(tmp_path: Path) -> None:
    """JSON入力と既存出力のhardlinkを拒否する。"""

    source = tmp_path / "source.json"
    source.write_text(json.dumps({"sha256": "a" * 64}), encoding="utf-8")
    hardlinked_source = tmp_path / "source-hardlink.json"
    try:
        os.link(source, hardlinked_source)
    except OSError as exc:
        pytest.skip(f"hardlinkを作成できない環境です: {exc}")
    with pytest.raises(baseline.BaselineBuildError, match="単一link"):
        baseline.build_private_exclusion_baseline(
            [hardlinked_source],
            _outside_repository(tmp_path),
        )

    standalone = tmp_path / "standalone.json"
    standalone.write_text(json.dumps({"sha256": "b" * 64}), encoding="utf-8")
    output = _outside_repository(tmp_path, "existing.json")
    output.write_text("{}\n", encoding="utf-8")
    output_alias = tmp_path / "output-alias.json"
    os.link(output, output_alias)
    with pytest.raises(baseline.BaselineBuildError, match="単一link"):
        baseline.build_private_exclusion_baseline([standalone], output)


def test_regular_file_hardlinks_do_not_affect_input_directory_identities(
    tmp_path: Path,
) -> None:
    """--input directoryは内容を読まない通常file hardlinkを安全に無視する。"""

    directory_hash = "a" * 64
    ignored_hash = "b" * 64
    cases = tmp_path / "cases"
    (cases / directory_hash).mkdir(parents=True)
    source = cases / "source.json"
    source.write_text(json.dumps({"sha256": ignored_hash}), encoding="utf-8")
    alias = cases / "source-alias.json"
    try:
        os.link(source, alias)
    except OSError as exc:
        pytest.skip(f"hardlinkを作成できない環境です: {exc}")

    document, status = baseline.build_private_exclusion_baseline(
        [cases],
        _outside_repository(tmp_path),
    )
    assert status == "written"
    assert document["identities"] == [directory_hash]
    assert ignored_hash not in document["identities"]


def test_input_directory_skips_reparse_entries_without_following(
    tmp_path: Path,
) -> None:
    """--input directory配下のreparse entryは開かずidentityにも採用しない。"""

    direct_hash = "a" * 64
    linked_name_hash = "b" * 64
    linked_child_hash = "c" * 64
    cases = tmp_path / "cases"
    external = tmp_path / "external"
    (cases / direct_hash).mkdir(parents=True)
    (external / linked_child_hash).mkdir(parents=True)
    linked_directory = cases / linked_name_hash
    try:
        linked_directory.symlink_to(external, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"symlinkを作成できない環境です: {exc}")

    document, status = baseline.build_private_exclusion_baseline(
        [cases],
        _outside_repository(tmp_path),
    )
    assert status == "written"
    assert document["identities"] == [direct_hash]
    assert linked_name_hash not in document["identities"]
    assert linked_child_hash not in document["identities"]


def test_empty_input_directory_is_allowed_when_final_union_is_nonempty(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """0件の補助directoryは許可し、manifest_hashesへdirectoryを渡さない。"""

    digest = "a" * 64
    empty_directory = tmp_path / "empty-cases"
    empty_directory.mkdir()
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps({"sha256": digest}), encoding="utf-8")
    original = malwarebazaar_batch.manifest_hashes
    observed: list[tuple[Path, ...]] = []

    def observe(paths: list[Path], **limits: int) -> set[str]:
        assert all(not path.is_dir() for path in paths)
        observed.append(tuple(paths))
        return original(paths, **limits)

    monkeypatch.setattr(malwarebazaar_batch, "manifest_hashes", observe)
    document, status = baseline.build_private_exclusion_baseline(
        [empty_directory, manifest],
        _outside_repository(tmp_path),
    )
    assert status == "written"
    assert document["identities"] == [digest]
    assert observed == [(baseline._absolute(manifest),)]


def test_rejects_empty_final_identity_union(tmp_path: Path) -> None:
    """全収集元が0件なら空baselineを保存せずfail-closedにする。"""

    empty_directory = tmp_path / "empty-cases"
    empty_tree = tmp_path / "empty-tree"
    empty_directory.mkdir()
    empty_tree.mkdir()
    output = _outside_repository(tmp_path)
    with pytest.raises(baseline.BaselineBuildError, match="identity集合が空"):
        baseline.build_private_exclusion_baseline(
            [empty_directory],
            output,
            json_trees=[empty_tree],
        )
    assert not output.exists()


def test_rejects_reparse_input_and_output_parent(tmp_path: Path) -> None:
    """利用可能な環境ではsymlink／junction相当を入力・出力とも拒否する。"""

    source = tmp_path / "source.json"
    source.write_text(json.dumps({"sha256": "a" * 64}), encoding="utf-8")
    linked_source = tmp_path / "linked-source.json"
    real_output_parent = tmp_path / "real-output"
    real_output_parent.mkdir()
    linked_output_parent = tmp_path / "linked-output"
    try:
        linked_source.symlink_to(source)
        linked_output_parent.symlink_to(real_output_parent, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"symlinkを作成できない環境です: {exc}")

    with pytest.raises(baseline.BaselineBuildError, match="入力path"):
        baseline.build_private_exclusion_baseline(
            [linked_source],
            _outside_repository(tmp_path),
        )
    with pytest.raises(baseline.BaselineBuildError, match="reparse point"):
        baseline.build_private_exclusion_baseline(
            [source],
            linked_output_parent / "baseline.json",
        )


def test_cli_is_offline_requires_no_api_key_and_has_japanese_help(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """CLIはAPI keyなしで完了し、公開summaryへidentityとpathを出さない。"""

    monkeypatch.delenv("MALWAREBAZAAR_AUTH_KEY", raising=False)
    source = tmp_path / "source.json"
    source.write_text(json.dumps({"sha256": "a" * 64}), encoding="utf-8")
    output = _outside_repository(tmp_path)
    assert baseline.main(["--input", str(source), "--output", str(output)]) == 0
    summary = json.loads(capsys.readouterr().out)
    assert summary["identity_count"] == 1
    assert summary["sample_identifiers_included"] is False
    assert summary["network_contacted"] is False
    assert "a" * 64 not in json.dumps(summary)
    assert str(output) not in json.dumps(summary)

    help_text = baseline.build_parser().format_help()
    assert "使用法:" in help_text
    assert "repository外" in help_text


def test_duplicate_key_and_non_object_json_are_rejected(tmp_path: Path) -> None:
    """入力はbounded strict UTF-8 JSON objectでなければならない。"""

    output = _outside_repository(tmp_path)
    duplicate = tmp_path / "duplicate.json"
    duplicate.write_text(
        '{"sha256":"' + "a" * 64 + '","sha256":"' + "b" * 64 + '"}',
        encoding="utf-8",
    )
    with pytest.raises(baseline.BaselineBuildError, match="strict manifest"):
        baseline.build_private_exclusion_baseline([duplicate], output)

    array = tmp_path / "array.json"
    array.write_text(json.dumps([{"sha256": "a" * 64}]), encoding="utf-8")
    with pytest.raises(baseline.BaselineBuildError, match="strict manifest"):
        baseline.build_private_exclusion_baseline([array], output)


def test_json_tree_parses_known_fields_in_path_order_and_supports_bom_arrays(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """JSON treeはpath順にstrict parseし、BOM付き配列と既知欄だけを収集する。"""

    first, second, credential_like = "a" * 64, "b" * 64, "c" * 64
    tree_a = tmp_path / "tree-a"
    tree_b = tmp_path / "tree-b"
    (tree_a / "nested").mkdir(parents=True)
    tree_b.mkdir()
    (tree_a / "nested" / "Z.JSON").write_bytes(
        b"\xef\xbb\xbf"
        + json.dumps(
            [
                {"sha256": first},
                {
                    "api_key": credential_like,
                    "token": credential_like,
                    "unknown": [credential_like],
                },
            ]
        ).encode("utf-8")
    )
    (tree_b / "a.json").write_text(
        json.dumps({"selected_hashes": [second], "zip_sha256": credential_like}),
        encoding="utf-8",
    )
    (tree_a / "ignored.txt").write_text(
        json.dumps({"sha256": credential_like}),
        encoding="utf-8",
    )
    ignored_directory_hash = "d" * 64
    (tree_a / ignored_directory_hash).mkdir()

    observed_paths: list[Path] = []
    original = malwarebazaar_batch.manifest_hashes

    def observe(paths: list[Path], **limits: int) -> set[str]:
        observed_paths.extend(paths)
        return original(paths, **limits)

    monkeypatch.setattr(malwarebazaar_batch, "manifest_hashes", observe)
    output = _outside_repository(tmp_path)
    document, _ = baseline.build_private_exclusion_baseline(
        [],
        output,
        json_trees=[tree_b, tree_a],
    )

    assert document["identities"] == [first, second]
    assert credential_like not in document["identities"]
    assert ignored_directory_hash not in document["identities"]
    assert observed_paths == sorted(observed_paths, key=baseline._path_sort_key)
    assert {path.suffix.casefold() for path in observed_paths} == {".json"}


@pytest.mark.parametrize(
    "payload",
    [
        '{"sha256":"' + "a" * 64 + '","sha256":"' + "b" * 64 + '"}',
        '{"sha256":"' + "a" * 64 + '","score":NaN}',
        '{"sha256":"' + "a" * 64 + '","score":Infinity}',
    ],
)
def test_json_tree_rejects_duplicate_keys_and_nonfinite_values(
    tmp_path: Path,
    payload: str,
) -> None:
    """tree内JSONのduplicate keyと非有限値をfail-closedで拒否する。"""

    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "invalid.json").write_text(payload, encoding="utf-8")
    with pytest.raises(baseline.BaselineBuildError, match="strict JSON"):
        baseline.build_private_exclusion_baseline(
            [],
            _outside_repository(tmp_path),
            json_trees=[tree],
        )


def test_json_tree_rejects_hardlinks_reparse_and_output_collision(
    tmp_path: Path,
) -> None:
    """tree内hardlink／reparseとtree配下の出力を拒否する。"""

    hardlink_tree = tmp_path / "hardlink-tree"
    hardlink_tree.mkdir()
    source = hardlink_tree / "source.json"
    source.write_text(json.dumps({"sha256": "a" * 64}), encoding="utf-8")
    alias = hardlink_tree / "alias.json"
    try:
        os.link(source, alias)
    except OSError as exc:
        pytest.skip(f"hardlinkを作成できない環境です: {exc}")
    with pytest.raises(baseline.BaselineBuildError, match="hardlink"):
        baseline.build_private_exclusion_baseline(
            [],
            _outside_repository(tmp_path),
            json_trees=[hardlink_tree],
        )

    normal_tree = tmp_path / "normal-tree"
    normal_tree.mkdir()
    (normal_tree / "valid.json").write_text(
        json.dumps({"sha256": "b" * 64}),
        encoding="utf-8",
    )
    with pytest.raises(baseline.BaselineBuildError, match="配下"):
        baseline.build_private_exclusion_baseline(
            [],
            normal_tree / "private.json",
            json_trees=[normal_tree],
        )

    real_directory = tmp_path / "real-directory"
    real_directory.mkdir()
    linked_directory = normal_tree / "linked-directory"
    try:
        linked_directory.symlink_to(real_directory, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"symlinkを作成できない環境です: {exc}")
    with pytest.raises(baseline.BaselineBuildError, match="reparse point"):
        baseline.build_private_exclusion_baseline(
            [],
            _outside_repository(tmp_path, "linked.json"),
            json_trees=[normal_tree],
        )


def test_json_tree_enforces_explicit_file_and_byte_bounds(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """明示したfile数・単体・総byte上限を超えたtreeをparse前に拒否する。"""

    assert baseline.MAXIMUM_JSON_TREE_FILES >= 10_000
    assert baseline.MAXIMUM_JSON_TREE_FILE_BYTES >= 128 * 1024 * 1024
    assert baseline.MAXIMUM_JSON_TREE_TOTAL_BYTES >= 4 * 1024 * 1024 * 1024

    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "a.json").write_text('{"sha256":"' + "a" * 64 + '"}', encoding="utf-8")
    (tree / "b.json").write_text('{"sha256":"' + "b" * 64 + '"}', encoding="utf-8")
    output = _outside_repository(tmp_path)

    monkeypatch.setattr(baseline, "MAXIMUM_JSON_TREE_FILES", 1)
    with pytest.raises(baseline.BaselineBuildError, match="file数"):
        baseline.build_private_exclusion_baseline([], output, json_trees=[tree])

    monkeypatch.setattr(baseline, "MAXIMUM_JSON_TREE_FILES", 2)
    monkeypatch.setattr(baseline, "MAXIMUM_JSON_TREE_FILE_BYTES", 4)
    with pytest.raises(baseline.BaselineBuildError, match="単体JSON"):
        baseline.build_private_exclusion_baseline([], output, json_trees=[tree])

    monkeypatch.setattr(baseline, "MAXIMUM_JSON_TREE_FILE_BYTES", 1024)
    monkeypatch.setattr(baseline, "MAXIMUM_JSON_TREE_TOTAL_BYTES", 100)
    with pytest.raises(baseline.BaselineBuildError, match="JSON総size"):
        baseline.build_private_exclusion_baseline([], output, json_trees=[tree])


def test_json_tree_detects_mutation_after_parse(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """parse後にtree fileが変化した場合はbaselineを保存しない。"""

    tree = tmp_path / "tree"
    tree.mkdir()
    source = tree / "source.json"
    source.write_text(json.dumps({"sha256": "a" * 64}), encoding="utf-8")
    original = malwarebazaar_batch.manifest_hashes

    def mutate_after_read(paths: list[Path], **limits: int) -> set[str]:
        hashes = original(paths, **limits)
        source.write_text(
            json.dumps({"sha256": "b" * 64, "changed": True}),
            encoding="utf-8",
        )
        return hashes

    monkeypatch.setattr(malwarebazaar_batch, "manifest_hashes", mutate_after_read)
    output = _outside_repository(tmp_path)
    with pytest.raises(baseline.BaselineBuildError, match="変化"):
        baseline.build_private_exclusion_baseline([], output, json_trees=[tree])
    assert not output.exists()


def test_json_tree_cli_can_repeat_without_regular_input(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """CLIは複数treeだけでもAPI keyなしでprivate baselineを生成する。"""

    monkeypatch.delenv("MALWAREBAZAAR_AUTH_KEY", raising=False)
    first_tree = tmp_path / "first"
    second_tree = tmp_path / "second"
    first_tree.mkdir()
    second_tree.mkdir()
    (first_tree / "first.json").write_text(
        json.dumps({"sha256": "a" * 64}),
        encoding="utf-8",
    )
    (second_tree / "second.json").write_text(
        json.dumps({"sha256_hash": "b" * 64}),
        encoding="utf-8",
    )
    output = _outside_repository(tmp_path)
    assert (
        baseline.main(
            [
                "--json-tree",
                str(second_tree),
                "--json-tree",
                str(first_tree),
                "--output",
                str(output),
            ]
        )
        == 0
    )
    summary = json.loads(capsys.readouterr().out)
    assert summary["identity_count"] == 2
    assert summary["network_contacted"] is False
    assert "--json-tree" in baseline.build_parser().format_help()


def test_builder_requires_input_or_json_tree(tmp_path: Path) -> None:
    """空の収集元は誤って空baselineを作らず拒否する。"""

    with pytest.raises(baseline.BaselineBuildError, match="--json-tree"):
        baseline.build_private_exclusion_baseline([], _outside_repository(tmp_path))
