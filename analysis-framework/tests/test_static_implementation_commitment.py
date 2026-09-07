"""静的解析実装treeの有界commitmentと変更検知を検証する。"""

from __future__ import annotations

import hashlib
import importlib
import os
import sys
from pathlib import Path

import pytest

COMMON = Path(__file__).resolve().parents[1] / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

target = importlib.import_module("static_implementation_commitment")


def _repository(tmp_path: Path) -> Path:
    repository = tmp_path / "repository"
    for relative, _suffixes in target.SOURCE_ROOTS:
        (repository / relative).mkdir(parents=True, exist_ok=True)
    for relative in target.SOURCE_FILES:
        path = repository / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("fixture dependency\n", encoding="utf-8")
    (repository / "analysis-framework" / "common" / "entry.py").write_text(
        "VALUE = 1\n",
        encoding="utf-8",
    )
    (repository / "extractors" / "helper.py").write_text(
        "def extract(data): return data\n",
        encoding="utf-8",
    )
    return repository


def _commitment(repository: Path) -> dict[str, object]:
    commitment, _sources = target.build_implementation_commitment(
        repository,
        hash_file=lambda source: hashlib.sha256(source.path.read_bytes()).hexdigest(),
    )
    return commitment


def _safe_snapshot(
    repository: Path,
) -> tuple[tuple[target.ImplementationSource, ...], dict[str, str]]:
    """productionと同じ単一handle読取りでharmless treeを固定する。"""

    hashes: dict[str, str] = {}

    def hash_source(source: target.ImplementationSource) -> str:
        digest = hashlib.sha256(target.read_implementation_source(repository, source)).hexdigest()
        hashes[source.relative_path] = digest
        return digest

    _summary, sources = target.build_implementation_commitment(repository, hash_file=hash_source)
    return sources, hashes


def test_commitment_changes_for_content_membership_and_removal(tmp_path: Path) -> None:
    """内容、追加、削除をすべてmanifest digestへ反映する。"""

    repository = _repository(tmp_path)
    first = _commitment(repository)
    entry = repository / "analysis-framework" / "common" / "entry.py"
    entry.write_text("VALUE = 2\n", encoding="utf-8")
    changed = _commitment(repository)
    added = repository / "unpackers" / "new_layer.py"
    added.write_text("MARKER = b'fixture'\n", encoding="utf-8")
    expanded = _commitment(repository)
    added.unlink()
    restored_membership = _commitment(repository)

    assert first["manifest_sha256"] != changed["manifest_sha256"]
    assert changed["manifest_sha256"] != expanded["manifest_sha256"]
    assert expanded["file_count"] == changed["file_count"] + 1
    assert restored_membership == changed


def test_tests_and_unrelated_documents_are_excluded(tmp_path: Path) -> None:
    """回帰testと説明文の変更をproduction解析実装へ混在させない。"""

    repository = _repository(tmp_path)
    before = _commitment(repository)
    test_file = repository / "unpackers" / "tests" / "test_fixture.py"
    test_file.parent.mkdir()
    test_file.write_text("raise AssertionError\n", encoding="utf-8")
    document = repository / "extractors" / "README.md"
    document.write_text("fixture\n", encoding="utf-8")

    assert _commitment(repository) == before


def test_excluded_directory_matching_is_case_insensitive(tmp_path: Path) -> None:
    """Windows上の表記揺れでも回帰testをproduction実装へ混在させない。"""

    repository = _repository(tmp_path)
    before = _commitment(repository)
    helper = repository / "extractors" / "Tests" / "fixture_helper.py"
    helper.parent.mkdir()
    helper.write_text("VALUE = 'test only'\n", encoding="utf-8")

    assert _commitment(repository) == before


def test_test_module_matching_is_case_insensitive(tmp_path: Path) -> None:
    """test module名の大小文字差をproduction実装へ混在させない。"""

    repository = _repository(tmp_path)
    before = _commitment(repository)
    test_module = repository / "unpackers" / "Test_fixture.py"
    test_module.write_text("VALUE = 'test only'\n", encoding="utf-8")

    assert _commitment(repository) == before


def test_file_count_limit_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """source件数が上限を超えた場合は不完全なcommitmentを返さない。"""

    repository = _repository(tmp_path)
    monkeypatch.setattr(target, "MAX_IMPLEMENTATION_FILES", 2)

    with pytest.raises(target.StaticImplementationError, match="file件数"):
        target.discover_implementation_sources(repository)


def test_hardlinked_source_is_rejected(tmp_path: Path) -> None:
    """複数pathから同じinodeを参照する実装sourceを受理しない。"""

    repository = _repository(tmp_path)
    source = repository / "analysis-framework" / "common" / "entry.py"
    linked = source.with_name("linked.py")
    try:
        os.link(source, linked)
    except OSError:
        pytest.skip("この環境ではhardlinkを作成できません")

    with pytest.raises(target.StaticImplementationError, match="単一link"):
        target.discover_implementation_sources(repository)


def test_snapshot_rejects_content_or_identity_change(tmp_path: Path) -> None:
    """同じpath・同じsizeでも列挙後の置換や内容変更をfail-closedにする。"""

    repository = _repository(tmp_path)
    sources, hashes = _safe_snapshot(repository)
    entry = repository / "analysis-framework" / "common" / "entry.py"
    replacement = entry.with_suffix(".replacement")
    replacement.write_text("VALUE = 2\n", encoding="utf-8")
    entry.unlink()
    replacement.rename(entry)

    with pytest.raises(target.StaticImplementationError, match="membership|identity|変更"):
        target.verify_implementation_snapshot(repository, sources, hashes)


def test_snapshot_rejects_membership_addition(tmp_path: Path) -> None:
    """fingerprint読取り後に追加された実装sourceを起動前検証で拒否する。"""

    repository = _repository(tmp_path)
    sources, hashes = _safe_snapshot(repository)
    (repository / "unpackers" / "late_member.py").write_text("VALUE = 3\n", encoding="utf-8")

    with pytest.raises(target.StaticImplementationError, match="membership"):
        target.verify_implementation_snapshot(repository, sources, hashes)
