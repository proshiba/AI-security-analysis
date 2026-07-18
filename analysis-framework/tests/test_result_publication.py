"""固定レイアウトのcase公開とindex同期を検証する。"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import result_publication as publication


SHA = "a" * 64


def _context(tmp_path: Path) -> tuple[Path, Path]:
    results = tmp_path / "analysis-results"
    aggregate = (
        results
        / "collections"
        / "refresh-20260718"
        / "sources"
        / "agenttesla"
    )
    aggregate.mkdir(parents=True)
    return results, aggregate


def test_canonical_publication_writes_case_metadata_catalog_and_collection(
    short_tmp: Path,
) -> None:
    results, aggregate = _context(short_tmp)
    case, context = publication.publication_case_path(
        aggregate, "agenttesla", SHA
    )
    assert context is not None
    case.mkdir(parents=True)
    (case / "README.md").write_text("# 解析\n", encoding="utf-8")

    result = publication.register_publication_cases(context, [case])

    assert result["cases"] == 1
    metadata = json.loads((case / "metadata.json").read_text(encoding="utf-8"))
    assert metadata["collections"] == ["refresh-20260718"]
    assert metadata["malware_version"]["status"] == "unknown"
    catalog = json.loads(
        (results / "catalog" / "cases.json").read_text(encoding="utf-8")
    )
    assert catalog["cases"][SHA]["canonical_path"] == metadata["canonical_path"]
    collection = json.loads(
        (
            results
            / "collections"
            / "refresh-20260718"
            / "manifest.json"
        ).read_text(encoding="utf-8")
    )
    assert collection["cases"] == [{"case_id": f"sha256:{SHA}"}]
    assert collection["family_sources"] == [
        {"family": "agenttesla", "path": "sources/agenttesla"}
    ]


def test_publication_preserves_existing_catalog_extension_fields(short_tmp: Path) -> None:
    results, aggregate = _context(short_tmp)
    case, context = publication.publication_case_path(
        aggregate, "agenttesla", SHA
    )
    assert context is not None
    case.mkdir(parents=True)
    metadata = {
        "family": "agenttesla",
        "collections": [],
        "malware_version": {
            "status": "unknown",
            "normalized_key": "unknown",
        },
    }
    (case / "metadata.json").write_text(json.dumps(metadata), encoding="utf-8")
    catalog = results / "catalog" / "cases.json"
    catalog.parent.mkdir(parents=True)
    catalog.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "cases": {
                    SHA: {
                        "case_id": f"sha256:{SHA}",
                        "family": "agenttesla",
                        "case_kind": "malware",
                        "version_key": "unknown",
                        "canonical_path": case.relative_to(short_tmp).as_posix(),
                        "review_state": "analyst-reviewed",
                    }
                },
            }
        ),
        encoding="utf-8",
    )

    publication.register_publication_cases(context, [case])

    updated = json.loads(catalog.read_text(encoding="utf-8"))
    assert updated["cases"][SHA]["review_state"] == "analyst-reviewed"


def test_non_result_destination_keeps_isolated_legacy_fixture(tmp_path: Path) -> None:
    destination = tmp_path / "isolated"
    case, context = publication.publication_case_path(
        destination, "agenttesla", SHA
    )
    assert context is None
    assert case == destination / "cases" / SHA


def test_rejects_mismatched_family_and_invalid_existing_index(short_tmp: Path) -> None:
    results, aggregate = _context(short_tmp)
    with pytest.raises(publication.PublicationError, match="family mismatch"):
        publication.detect_publication_context(aggregate, "remcosrat")
    catalog = results / "catalog" / "cases.json"
    catalog.parent.mkdir(parents=True)
    catalog.write_text("{broken", encoding="utf-8")
    case = (
        results
        / "malware"
        / "agenttesla"
        / "versions"
        / "unknown"
        / "cases"
        / SHA
    )
    case.mkdir(parents=True)
    context = publication.detect_publication_context(aggregate, "agenttesla")
    assert context is not None
    with pytest.raises(publication.PublicationError, match="invalid JSON index"):
        publication.register_publication_cases(context, [case])


def test_rejects_noncanonical_case_even_when_catalog_exists(short_tmp: Path) -> None:
    results, aggregate = _context(short_tmp)
    catalog = results / "catalog" / "cases.json"
    catalog.parent.mkdir(parents=True)
    catalog.write_text(
        json.dumps({"schema_version": 1, "cases": {}}), encoding="utf-8"
    )
    misplaced = results / "collections" / "misplaced" / SHA
    misplaced.mkdir(parents=True)
    context = publication.detect_publication_context(aggregate, "agenttesla")
    assert context is not None

    with pytest.raises(
        publication.PublicationError, match="does not match metadata version"
    ):
        publication.register_publication_cases(context, [misplaced])


def test_rejects_malformed_existing_case_metadata(short_tmp: Path) -> None:
    _results, aggregate = _context(short_tmp)
    case, context = publication.publication_case_path(
        aggregate, "agenttesla", SHA
    )
    assert context is not None
    case.mkdir(parents=True)
    (case / "metadata.json").write_text(
        json.dumps({"malware_version": "unknown"}), encoding="utf-8"
    )

    with pytest.raises(publication.PublicationError, match="invalid malware_version"):
        publication.register_publication_cases(context, [case])


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("schema_version", 2, "schema_version mismatch"),
        ("sha256", "b" * 64, "sha256 mismatch"),
        ("case_id", f"sha256:{'b' * 64}", "case_id mismatch"),
        ("case_kind", "supply_chain_payload", "case_kind mismatch"),
        ("canonical_path", "analysis-results/outside", "canonical_path mismatch"),
    ],
)
def test_rejects_conflicting_existing_metadata_identity(
    short_tmp: Path,
    field: str,
    value: object,
    message: str,
) -> None:
    _results, aggregate = _context(short_tmp)
    case, context = publication.publication_case_path(
        aggregate, "agenttesla", SHA
    )
    assert context is not None
    case.mkdir(parents=True)
    metadata = {
        "malware_version": {"status": "unknown", "normalized_key": "unknown"},
        field: value,
    }
    (case / "metadata.json").write_text(json.dumps(metadata), encoding="utf-8")

    with pytest.raises(publication.PublicationError, match=message):
        publication.register_publication_cases(context, [case])


def test_rejects_invalid_existing_version_status(short_tmp: Path) -> None:
    _results, aggregate = _context(short_tmp)
    case, context = publication.publication_case_path(
        aggregate, "agenttesla", SHA
    )
    assert context is not None
    case.mkdir(parents=True)
    (case / "metadata.json").write_text(
        json.dumps(
            {"malware_version": {"status": "guessed", "normalized_key": "unknown"}}
        ),
        encoding="utf-8",
    )

    with pytest.raises(publication.PublicationError, match="version status"):
        publication.register_publication_cases(context, [case])


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("cases", [{"case_id": "not-a-sha256"}], "case identity"),
        (
            "cases",
            [{"case_id": f"sha256:{'A' * 64}"}],
            "case hash",
        ),
        (
            "family_sources",
            [{"family": "agenttesla", "path": "../agenttesla"}],
            "family source",
        ),
        (
            "family_sources",
            [{"family": "../agenttesla", "path": "sources/../agenttesla"}],
            "family source",
        ),
    ],
)
def test_rejects_malformed_existing_collection_members(
    short_tmp: Path,
    field: str,
    value: list[dict[str, str]],
    message: str,
) -> None:
    results, aggregate = _context(short_tmp)
    case, context = publication.publication_case_path(
        aggregate, "agenttesla", SHA
    )
    assert context is not None
    case.mkdir(parents=True)
    manifest = aggregate.parents[1] / "manifest.json"
    document = {
        "schema_version": 1,
        "collection_id": "refresh-20260718",
        "cases": [],
        "family_sources": [],
    }
    document[field] = value
    manifest.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(publication.PublicationError, match=message):
        publication.register_publication_cases(context, [case])
