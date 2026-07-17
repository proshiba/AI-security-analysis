"""成果物レイアウト計画・適用の fail-closed 契約を検証する。"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import tempfile

import pytest

import normalize_result_layout as cli
import result_layout as layout


@pytest.fixture
def short_tmp() -> Path:
    base = Path(r"C:\tmp") if os.name == "nt" else None
    if base is not None:
        base.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="rl-", dir=base) as value:
        yield Path(value)


def _sha(character: str) -> str:
    return character * 64


def _base_repository(tmp_path: Path) -> Path:
    results = tmp_path / "analysis-results"
    results.mkdir(parents=True)
    (results / "README.md").write_text("# 成果物\n", encoding="utf-8")
    (results / "AGENTS.md").write_text("# 規則\n", encoding="utf-8")
    (results / "IOC-INDEX.md").write_text("# IOC 索引\n", encoding="utf-8")
    (tmp_path / "analysis_history.yaml").write_text("analyses: []\n", encoding="utf-8")
    return tmp_path


def _case(
    repository: Path,
    family: str,
    digest: str,
    *,
    collection: str | None = None,
    document: tuple[str, dict] | None = None,
) -> Path:
    root = repository / "analysis-results" / family
    if collection:
        root /= collection
    case = root / "cases" / digest
    case.mkdir(parents=True)
    (case / "README.md").write_text("# case\n", encoding="utf-8")
    (case / "IOC-LIST.md").write_text("# IOC\n", encoding="utf-8")
    if document:
        (case / document[0]).write_text(
            json.dumps(document[1], ensure_ascii=False), encoding="utf-8"
        )
    return case


def _tree_snapshot(root: Path) -> list[tuple[str, str]]:
    rows: list[tuple[str, str]] = []
    for path in sorted(root.rglob("*"), key=lambda item: item.as_posix()):
        relative = path.relative_to(root).as_posix()
        if path.is_dir():
            rows.append((relative, "directory"))
        else:
            rows.append((relative, hashlib.sha256(path.read_bytes()).hexdigest()))
    return rows


def test_version_resolver_uses_only_family_specific_evidence(tmp_path: Path) -> None:
    repository = _base_repository(tmp_path)
    cases = {
        "amadey": _case(
            repository,
            "amadey",
            _sha("a"),
            document=("analysis.json", {"config": {"config": {"version": "4.13"}}}),
        ),
        "latrodectus": _case(
            repository,
            "latrodectus",
            _sha("b"),
            document=(
                "analysis.json",
                {
                    "config": {
                        "config": {
                            "selected_layer_config": {"config": {"version": "1.2.24"}}
                        }
                    }
                },
            ),
        ),
        "remcosrat": _case(
            repository,
            "remcosrat",
            _sha("c"),
            document=("indicators.json", {"version": "7.2.6 Pro"}),
        ),
        "spyglace": _case(
            repository,
            "spyglace",
            _sha("d"),
            document=("config.json", {"config": {"version": "3.1.15"}}),
        ),
        "venomrat": _case(
            repository,
            "venomrat",
            _sha("e"),
            document=("indicators.json", {"version": "6.0.3", "source": "tria.ge"}),
        ),
        "purehvnc": _case(
            repository,
            "purehvnc",
            _sha("f"),
            document=("config.json", {"config": {"version_candidates": ["4.4.1"]}}),
        ),
        "other": _case(
            repository,
            "other",
            _sha("1"),
            document=(
                "config.json",
                {
                    "schema_version": "9.9.9",
                    "runtime_version": "8.0.0",
                    "packer_version": "1.2.3",
                    "file_version": "7.7.7",
                    "dependencies": [{"version": "6.6.6"}],
                },
            ),
        ),
    }
    values = {
        family: layout.resolve_malware_version(case, family, repository)
        for family, case in cases.items()
    }
    assert values["amadey"]["normalized_key"] == "v4.13"
    assert values["amadey"]["evidence"][0]["artifact"] == "analysis.json"
    assert values["latrodectus"]["normalized_key"] == "v1.2.24"
    assert values["remcosrat"]["reason"] == "family_config_or_process_attributed_evidence"
    assert values["spyglace"]["status"] == "confirmed"
    assert values["purehvnc"]["reason"] == "terminal_managed_static_config"
    assert values["venomrat"]["status"] == "reported"
    assert values["venomrat"]["confidence"] == "medium"
    assert values["other"]["status"] == "unknown"
    assert {value["status"] for value in values.values()} <= {
        "confirmed",
        "reported",
        "unknown",
        "not_applicable",
    }

    (cases["purehvnc"] / "config.json").write_text(
        json.dumps({"config": {"version_candidates": ["4.4.1", "4.5.0"]}}),
        encoding="utf-8",
    )
    ambiguous = layout.resolve_malware_version(
        cases["purehvnc"], "purehvnc", repository
    )
    assert ambiguous["status"] == "unknown"
    assert ambiguous["normalized_key"] == "unknown"


def _migration_repository(tmp_path: Path, *, with_manifest: bool = False) -> Path:
    repository = _base_repository(tmp_path)
    first = _case(repository, "family", _sha("a"))
    second = _case(
        repository,
        "family",
        _sha("b"),
        collection="refresh-20260715",
    )
    npm = _case(repository, "npm-supply-chain", _sha("c"))
    (repository / "analysis-results" / "family" / "README.md").write_text(
        f"[case](cases/{first.name}/README.md)\n", encoding="utf-8"
    )
    run = repository / "analysis-results" / "family" / "refresh-20260715"
    (run / "README.md").write_text(
        f"[case](cases/{second.name}/README.md)\n", encoding="utf-8"
    )
    (repository / "analysis-results" / "npm-supply-chain" / "README.md").write_text(
        "# npm supply chain\n", encoding="utf-8"
    )
    campaign = (
        repository
        / "analysis-results"
        / "atlascross"
        / "campaigns"
        / "silver-fox-vpn-2026"
    )
    campaign.mkdir(parents=True)
    (campaign / "README.md").write_text("# campaign\n", encoding="utf-8")
    (repository / "analysis-results" / "atlascross" / "README.md").write_text(
        "# AtlasCross\n", encoding="utf-8"
    )
    trivy = (
        repository
        / "analysis-results"
        / "supply-chain"
        / "trivy-teampcp-2026"
    )
    trivy.mkdir(parents=True)
    (trivy / "README.md").write_text("# Trivy\n", encoding="utf-8")
    refresh = repository / "analysis-results" / "REFRESH-2026-07-15.md"
    unpacking = (
        repository / "analysis-results" / "UNPACKING-REASSESSMENT-2026-07-15.md"
    )
    refresh.write_text("# refresh\n", encoding="utf-8")
    unpacking.write_text("# unpacking\n", encoding="utf-8")
    root_readme = repository / "analysis-results" / "README.md"
    root_readme.write_text(
        "[refresh](REFRESH-2026-07-15.md)\n"
        "[unpacking](UNPACKING-REASSESSMENT-2026-07-15.md)\n",
        encoding="utf-8",
    )
    (repository / "analysis_history.yaml").write_text(
        "analyses:\n"
        f"  - sample_sha256: {first.name}\n"
        f"    result_path: analysis-results/family/cases/{first.name}/\n"
        f"  - sample_sha256: {npm.name}\n"
        f"    result_path: analysis-results/npm-supply-chain/cases/{npm.name}/\n",
        encoding="utf-8",
    )
    if with_manifest:
        (repository / "analysis-results" / "family" / "manifest.sha256").write_text(
            "0" * 64 + "  README.md\n", encoding="utf-8"
        )
    return repository


def test_plan_is_deterministic_and_separates_supply_chain(tmp_path: Path) -> None:
    repository = _migration_repository(tmp_path)
    audit_root = repository / "analysis-results" / "static-audit-20260717"
    audit_root.mkdir()
    audit_json = audit_root / "coverage-audit.json"
    audit_json.write_text(
        json.dumps(
            {
                "path": (
                    "analysis-results/family/cases/"
                    + _sha("a")
                    + "/README.md"
                )
            }
        ),
        encoding="utf-8",
    )
    first = layout.build_layout_plan(repository, maximum_path_length=320)
    second = layout.build_layout_plan(repository, maximum_path_length=320)
    assert first == second
    assert first["errors"] == []
    assert first["counts"]["case_directories"] == 3
    assert first["counts"]["malware_cases"] == 2
    assert first["counts"]["supply_chain_payload_cases"] == 1
    assert first["counts"]["collections"] == 1
    assert first["counts"]["collection_memberships"] == 1
    assert first["collections"][0]["family_sources"] == [
        {"family": "family", "path": "sources/family"}
    ]
    npm = next(case for case in first["cases"] if case["case_kind"] == "supply_chain_payload")
    assert npm["target"].startswith(
        "analysis-results/research/supply-chain/npm/"
        "axios-plain-crypto-js-2026/cases/"
    )
    assert npm["malware_version"]["status"] == "not_applicable"
    assert first["catalog"]["document"]["cases"][npm["sha256"]]["case_kind"] == (
        "supply_chain_payload"
    )
    moves = {(item["source"], item["target"]) for item in first["move_map"]}
    assert (
        "analysis-results/REFRESH-2026-07-15.md",
        "analysis-results/collections/refresh-20260715/REPORT.md",
    ) in moves
    assert (
        "analysis-results/UNPACKING-REASSESSMENT-2026-07-15.md",
        "analysis-results/research/audits/unpacking-reassessment-20260715.md",
    ) in moves
    assert (
        "analysis-results/atlascross/README.md",
        "analysis-results/malware/atlascross/README.md",
    ) in moves
    markdown = first["reference_update_plan"]["markdown"]
    assert any(item["old"] == "REFRESH-2026-07-15.md" for item in markdown)
    assert any(
        item["old"] == "UNPACKING-REASSESSMENT-2026-07-15.md" for item in markdown
    )
    json_updates = first["reference_update_plan"]["json"]
    coverage_update = next(
        item
        for item in json_updates
        if item["file"].endswith("coverage-audit.json")
    )
    assert coverage_update["new"] == (
        "analysis-results/malware/family/versions/unknown/cases/"
        + _sha("a")
        + "/README.md"
    )
    assert not coverage_update["new"].startswith("../")


def test_canonical_helpers_and_unclassified_metadata(tmp_path: Path) -> None:
    repository = _base_repository(tmp_path)
    digest = _sha("d")
    case = _case(
        repository,
        "unclassified",
        digest,
        collection="malwarebazaar-unknown-20260717",
        document=(
            "case.json",
            {"attribution": {"family": "genesisstealer", "confidence": "low"}},
        ),
    )
    plan = layout.build_layout_plan(repository, maximum_path_length=320)
    item = plan["cases"][0]
    assert item["case_kind"] == "unclassified"
    assert item["attribution_status"] == "provisional"
    assert item["malware_version"]["status"] == "unknown"
    assert item["metadata"]["attribution_status"] == "provisional"
    assert plan["catalog"]["document"]["cases"][digest]["case_kind"] == "unclassified"
    assert plan["counts"]["unclassified_cases"] == 1
    assert plan["counts"]["provisional_unclassified_cases"] == 1
    expected = (
        repository
        / "analysis-results"
        / "malware"
        / "unclassified"
        / "versions"
        / "unknown"
        / "cases"
        / digest
    ).resolve()
    assert layout.canonical_malware_case_path(
        repository / "analysis-results", "unclassified", digest
    ) == expected
    assert layout.canonical_collection_source_path(
        repository / "analysis-results",
        "malwarebazaar-unknown-20260717",
        "unclassified",
    ).relative_to(repository).as_posix() == (
        "analysis-results/collections/malwarebazaar-unknown-20260717/"
        "sources/unclassified"
    )
    assert case.is_dir()
    with pytest.raises(layout.LayoutPlanError, match="unsafe family"):
        layout.canonical_malware_case_path(
            repository / "analysis-results", "../escape", digest
        )

    mx_repository = _base_repository(tmp_path / "mx")
    mx_digest = _sha("e")
    _case(mx_repository, "unclassified", mx_digest, collection="mx-go")
    mx_plan = layout.build_layout_plan(mx_repository, maximum_path_length=320)
    mx_case = mx_plan["cases"][0]
    assert mx_case["attribution_status"] == "provisional"
    assert mx_case["provisional_cluster_id"] == "mx-go"
    assert mx_case["metadata"]["provisional_cluster_id"] == "mx-go"
    assert mx_plan["catalog"]["document"]["cases"][mx_digest][
        "provisional_cluster_id"
    ] == "mx-go"


def test_canonical_supply_chain_case_is_idempotent(short_tmp: Path) -> None:
    repository = _base_repository(short_tmp / "supply")
    digest = _sha("c")
    case = (
        repository
        / "analysis-results"
        / "research"
        / "supply-chain"
        / "npm"
        / "axios-plain-crypto-js-2026"
        / "cases"
        / digest
    )
    case.mkdir(parents=True)
    (case / "README.md").write_text("# supply-chain payload\n", encoding="utf-8")
    (case / "IOC-LIST.md").write_text("# IOC\n", encoding="utf-8")

    plan = layout.build_layout_plan(repository, maximum_path_length=320)

    assert plan["errors"] == []
    assert plan["counts"]["case_moves"] == 0
    assert plan["counts"]["supply_chain_payload_cases"] == 1
    assert plan["cases"][0]["case_kind"] == "supply_chain_payload"
    assert plan["cases"][0]["family"] == "npm-supply-chain"
    assert plan["catalog"]["document"]["cases"][digest]["family"] == (
        "npm-supply-chain"
    )
    assert plan["cases"][0]["target"] == case.relative_to(repository).as_posix()


def test_canonical_research_campaigns_are_idempotent(short_tmp: Path) -> None:
    repository = _base_repository(short_tmp / "campaigns")
    campaign = (
        repository
        / "analysis-results"
        / "research"
        / "campaigns"
        / "atlascross"
        / "silver-fox-vpn-2026"
    )
    campaign.mkdir(parents=True)
    (campaign / "README.md").write_text("# キャンペーン\n", encoding="utf-8")

    plan = layout.build_layout_plan(repository, maximum_path_length=320)

    assert plan["errors"] == []
    assert plan["counts"]["research_moves"] == 0
    assert not any(
        "/research/" in item["target"] for item in plan["move_map"]
    )


def test_canonical_unclassified_metadata_is_idempotent(short_tmp: Path) -> None:
    repository = _base_repository(short_tmp / "unclassified")
    digest = _sha("d")
    case = layout.canonical_malware_case_path(
        repository / "analysis-results", "unclassified", digest
    )
    case.mkdir(parents=True)
    (case / "README.md").write_text("# 未分類\n", encoding="utf-8")
    (case / "IOC-LIST.md").write_text("# IOC\n", encoding="utf-8")
    (case / "metadata.json").write_text(
        json.dumps(
            {
                "case_kind": "unclassified",
                "family": "unclassified",
                "attribution_status": "provisional",
                "provisional_cluster_id": "mx-go",
            }
        ),
        encoding="utf-8",
    )

    plan = layout.build_layout_plan(repository, maximum_path_length=320)

    item = plan["cases"][0]
    assert plan["counts"]["case_moves"] == 0
    assert item["case_kind"] == "unclassified"
    assert item["attribution_status"] == "provisional"
    assert item["provisional_cluster_id"] == "mx-go"
    assert plan["catalog"]["document"]["cases"][digest][
        "provisional_cluster_id"
    ] == "mx-go"


def test_cli_default_writes_only_the_requested_plan(tmp_path: Path) -> None:
    repository = _migration_repository(tmp_path)
    before = _tree_snapshot(repository / "analysis-results")
    output = repository / "layout-plan.json"
    assert (
        cli.main(
            [
                "--repository",
                str(repository),
                "--output",
                str(output),
                "--maximum-path-length",
                "320",
            ]
        )
        == 0
    )
    assert _tree_snapshot(repository / "analysis-results") == before
    assert json.loads(output.read_text(encoding="utf-8"))["write_performed"] is False


def test_duplicate_collision_path_length_and_output_containment(short_tmp: Path) -> None:
    repository = _base_repository(short_tmp)
    digest = _sha("d")
    _case(repository, "one", digest)
    _case(repository, "two", digest)
    duplicate = layout.build_layout_plan(repository, maximum_path_length=320)
    assert any(item["code"] == "duplicate_sha256" for item in duplicate["errors"])

    repository = _base_repository(short_tmp / "collision")
    _case(repository, "family", digest)
    target = (
        repository
        / "analysis-results"
        / "malware"
        / "family"
        / "versions"
        / "unknown"
        / "cases"
        / digest
    )
    target.mkdir(parents=True)
    (target / "different.txt").write_text("different", encoding="utf-8")
    collision = layout.build_layout_plan(repository, maximum_path_length=320)
    assert collision["counts"]["content_conflicts"] >= 1

    repository = _base_repository(short_tmp / "length")
    case = _case(repository, "family", _sha("e"))
    (case / ("x" * 100 + ".json")).write_text("{}", encoding="utf-8")
    too_long = layout.build_layout_plan(repository, maximum_path_length=160)
    assert any(item["code"] == "target_path_too_long" for item in too_long["errors"])
    with pytest.raises(layout.LayoutPlanError, match="within the repository"):
        cli.main(
            [
                "--repository",
                str(repository),
                "--output",
                str(repository.parent / "outside.json"),
            ]
        )


def test_apply_handles_research_parent_merge_and_fixed_postconditions(
    short_tmp: Path,
) -> None:
    repository = _migration_repository(short_tmp, with_manifest=True)
    plan = layout.build_layout_plan(repository, maximum_path_length=320)
    assert plan["counts"]["checksum_manifests_to_regenerate"] == 1
    applied = layout.apply_layout_plan(repository, plan)
    assert applied["write_performed"] is True
    catalog = repository / "analysis-results" / "catalog" / "cases.json"
    assert catalog.is_file()
    assert (
        repository
        / "analysis-results"
        / "research"
        / "supply-chain"
        / "trivy-teampcp-2026"
        / "README.md"
    ).is_file()
    npm = next(case for case in plan["cases"] if case["case_kind"] == "supply_chain_payload")
    assert (repository / npm["target"] / "metadata.json").is_file()
    collection_manifest = json.loads(
        (
            repository
            / "analysis-results"
            / "collections"
            / "refresh-20260715"
            / "manifest.json"
        ).read_text(encoding="utf-8")
    )
    assert collection_manifest["family_sources"] == [
        {"family": "family", "path": "sources/family"}
    ]
    post_plan = layout.build_layout_plan(repository, maximum_path_length=320)
    assert post_plan["counts"]["case_moves"] == 0
    assert post_plan["counts"]["artifact_moves"] == 0
    assert post_plan["counts"]["research_moves"] == 0
    assert post_plan["counts"]["collections"] == 1
    assert post_plan["counts"]["collection_memberships"] == 1
    assert post_plan["counts"]["checksum_manifests_to_regenerate"] == 0
    assert post_plan["errors"] == []
    assert post_plan["catalog"]["document"] == plan["catalog"]["document"]
    before_second_apply = _tree_snapshot(repository)
    second_applied = layout.apply_layout_plan(repository, post_plan)
    assert second_applied["write_performed"] is True
    assert _tree_snapshot(repository) == before_second_apply
    root_directories = {
        path.name
        for path in (repository / "analysis-results").iterdir()
        if path.is_dir()
    }
    assert root_directories <= {"_shared", "catalog", "collections", "malware", "research"}


def test_apply_failure_restores_complete_tree(
    short_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = _migration_repository(short_tmp, with_manifest=True)
    before = _tree_snapshot(repository)
    plan = layout.build_layout_plan(repository, maximum_path_length=320)

    def fail_manifest(path: Path) -> None:
        raise RuntimeError(f"forced failure for {path}")

    monkeypatch.setattr(layout, "_regenerate_manifest", fail_manifest)
    with pytest.raises(RuntimeError, match="forced failure"):
        layout.apply_layout_plan(repository, plan)
    assert _tree_snapshot(repository) == before
    for name in ("catalog", "collections", "malware", "research"):
        assert not (repository / "analysis-results" / name).exists()


def test_existing_collection_manifest_must_match_case_metadata(short_tmp: Path) -> None:
    repository = _migration_repository(short_tmp / "membership")
    plan = layout.build_layout_plan(repository, maximum_path_length=320)
    layout.apply_layout_plan(repository, plan)
    member = next(case for case in plan["cases"] if case["collections"])
    metadata_path = repository / member["target"] / "metadata.json"
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    metadata["collections"] = []
    metadata_path.write_text(json.dumps(metadata), encoding="utf-8")

    mismatch = layout.build_layout_plan(repository, maximum_path_length=320)

    assert any(
        item["code"] == "collection_membership_mismatch"
        for item in mismatch["errors"]
    )
    with pytest.raises(layout.LayoutPlanError, match="preflight errors"):
        layout.apply_layout_plan(repository, mismatch)


def test_stale_source_fingerprint_is_rejected_before_any_write(short_tmp: Path) -> None:
    repository = _migration_repository(short_tmp / "artifact")
    plan = layout.build_layout_plan(repository, maximum_path_length=320)
    collection_move = next(
        move for move in plan["move_map"] if move["kind"] == "collection_source"
    )
    assert collection_move["fingerprint_method"] == (
        "sha256_relative_path_nul_size_u64_content_v1"
    )
    assert collection_move["fingerprint_excluded_case_sources"] == [
        "analysis-results/family/refresh-20260715/cases/" + _sha("b")
    ]
    run_readme = (
        repository
        / "analysis-results"
        / "family"
        / "refresh-20260715"
        / "README.md"
    )
    run_readme.write_text(run_readme.read_text(encoding="utf-8") + "changed\n", encoding="utf-8")
    mutated = _tree_snapshot(repository)
    with pytest.raises(layout.LayoutPlanError, match="stale source fingerprint"):
        layout.apply_layout_plan(repository, plan)
    assert _tree_snapshot(repository) == mutated

    repository = _migration_repository(short_tmp / "case")
    plan = layout.build_layout_plan(repository, maximum_path_length=320)
    case_readme = (
        repository
        / "analysis-results"
        / "family"
        / "cases"
        / _sha("a")
        / "README.md"
    )
    case_readme.write_text("# changed case\n", encoding="utf-8")
    mutated = _tree_snapshot(repository)
    with pytest.raises(layout.LayoutPlanError, match="stale source fingerprint"):
        layout.apply_layout_plan(repository, plan)
    assert _tree_snapshot(repository) == mutated
