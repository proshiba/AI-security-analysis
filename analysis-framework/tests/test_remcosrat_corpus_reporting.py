from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import sys
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[2]
FAMILY_DIR = ROOT / "analysis-framework" / "malware" / "remcosrat"
COMMON_DIR = ROOT / "analysis-framework" / "common"


def load(name: str, filename: str):
    path = FAMILY_DIR / filename
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.path[:0] = [str(FAMILY_DIR), str(COMMON_DIR)]
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path.remove(str(FAMILY_DIR))
        sys.path.remove(str(COMMON_DIR))
    return module


def test_analysis_entrypoints_isolate_same_named_family_helpers(monkeypatch: pytest.MonkeyPatch) -> None:
    """Remcosの直接読込後も共通名moduleを上書きしない。"""

    poisoned_c2 = ModuleType("c2_detector")
    poisoned_config = ModuleType("extract_config")
    monkeypatch.setitem(sys.modules, "c2_detector", poisoned_c2)
    monkeypatch.setitem(sys.modules, "extract_config", poisoned_config)

    corpus = load("remcos_isolated_corpus", "analyze_corpus.py")
    triage = load("remcos_isolated_triage", "analyze_triage_artifacts.py")

    assert corpus.build_hunt.__module__ == "_analysis_framework_malware_remcosrat.c2_detector"
    assert triage.build_hunt.__module__ == "_analysis_framework_malware_remcosrat.c2_detector"
    assert triage.extract_config.__module__ == "_analysis_framework_malware_remcosrat.extract_config"
    assert sys.modules["c2_detector"] is poisoned_c2
    assert sys.modules["extract_config"] is poisoned_config


def test_publication_redacts_private_material_and_local_paths(tmp_path: Path) -> None:
    module = load("remcos_publish_test", "publish_corpus_report.py")
    parent = "1" * 64
    peer = "2" * 64
    analysis = {
        "schema_version": 2,
        "selection": {
            "signature": "RemcosRAT",
            "selected_at": "2026-10-04T14:07:10Z",
            "requested": 1,
            "newest_first": True,
        },
        "counts": {
            "selected": 1,
            "archive_verified": 1,
            "root_pe": 1,
            "root_non_pe_delivery": 0,
            "static_family_confirmed": 1,
            "confirmed_unique_c2": 1,
            "external_public_analysis_matched": 1,
            "external_config_reported": 1,
            "external_unique_config_endpoints": 1,
        },
        "confirmed_unique_c2": ["c2.example:2404"],
        "external_reported_unique_config_endpoints": ["c2.example:2404"],
        "c2_hunting": {
            "endpoints": [{"endpoint": "c2.example:2404", "sources": ["confirmed_static_configuration"]}],
            "configured_certificate_pivots": [{"sha256": peer}],
        },
        "samples": [
            {
                "sha256": parent,
                "first_seen": "2026-10-04 07:16:05",
                "provider_file_type": "exe",
                "inner_size": 4096,
                "input_role": "terminal_pe",
                "static_family_confirmed": True,
                "config_status": "recovered",
                "version_candidates": ["7.3.1 Pro"],
                "c2": [{"endpoint": "c2.example:2404", "tls_enabled": True}],
                "config": {
                    "botnet": "reviewed",
                    "connect_interval_seconds": 1,
                    "initial_connect_delay_seconds": 0,
                    "field_count": 57,
                    "schema_profile": "published_56_field_or_later",
                    "tls_material": {
                        "peer_certificate_sha256": peer,
                        "private_key_present": True,
                        "private_key": "private-secret-must-not-be-published",
                    },
                    "source_path": r"C:\Users\Example\private\sample.exe",
                },
                "terminal_artifacts": [],
                "external_analysis": {
                    "public_analysis_match_count": 1,
                    "reported_config_endpoints": ["c2.example:2404"],
                },
            }
        ],
        "safety": {
            "sample_executed": False,
            "network_contacted": False,
            "raw_config_published": False,
            "credentials_published": False,
            "private_key_published": False,
        },
    }
    source = tmp_path / "analysis.json"
    source.write_text(json.dumps(analysis), encoding="utf-8")
    output = tmp_path / "public"

    result = module.publish(source, output)

    assert result == {"files": 5, "samples": 1, "validated_configs": 1}
    combined = "\n".join(path.read_text(encoding="utf-8") for path in output.iterdir())
    assert "private-secret-must-not-be-published" not in combined
    assert r"C:\Users\Example" not in combined
    validated = json.loads((output / "validated-configs.json").read_text(encoding="utf-8"))
    assert validated["configs"][0]["private_key_present"] is True
    assert validated["configs"][0]["private_key_published"] is False


def test_external_analysis_only_publishes_strict_normalized_endpoints() -> None:
    module = load("remcos_corpus_external_endpoint_test", "analyze_corpus.py")
    analysis = module._external_analysis(
        {
            "matches": [
                {
                    "sample_id": "261018-abcdefghij",
                    "triage_url": "https://tria.ge/261018-abcdefghij",
                    "families": ["Remcos"],
                    "config_endpoints": [
                        "Good.Example.:2404",
                        "operator@evil.example:2404",
                        "hostname:evil.example port:443:2404",
                        "evil.example:2404?token=secret",
                    ],
                }
            ]
        }
    )

    assert analysis["reported_config_endpoints"] == ["good.example:2404"]
    assert [item["endpoint"] for item in analysis["hunt_targets"]] == ["good.example:2404"]
    rendered = json.dumps(analysis, ensure_ascii=False)
    assert "operator@" not in rendered
    assert "hostname:evil" not in rendered
    assert "token=secret" not in rendered


def test_triage_result_merge_rejects_duplicate_parent_artifact_pair() -> None:
    module = load("remcos_triage_merge_test", "analyze_triage_artifacts.py")
    artifact = {
        "parent_sha256": "1" * 64,
        "artifact_sha256": "2" * 64,
        "status": "remcos_config_recovered",
        "archive_verified": True,
        "artifact_verified": True,
        "config": {"decoded_settings_sha256": "3" * 64},
        "c2": [{"endpoint": "c2.example:2404"}],
    }
    result = {
        "artifacts": [artifact],
        "confirmed_static_c2": ["c2.example:2404"],
        "configured_peer_certificate_sha256": ["3" * 64],
    }

    with pytest.raises(ValueError, match="重複"):
        module.merge_results([result, result])


def test_triage_result_merge_keeps_evidence_counts_and_safety_boundary() -> None:
    module = load("remcos_triage_merge_count_test", "analyze_triage_artifacts.py")
    results = []
    for index, endpoint in enumerate(("first.example:2404", "second.example:4489"), start=1):
        results.append(
            {
                "artifacts": [
                    {
                        "parent_sha256": str(index) * 64,
                        "artifact_sha256": str(index + 2) * 64,
                        "status": "remcos_config_recovered",
                        "archive_verified": True,
                        "artifact_verified": True,
                        "config": {
                            "decoded_settings_sha256": str(index + 4) * 64,
                            "tls_material": {"peer_certificate_sha256": str(index + 4) * 64},
                        },
                        "c2": [{"endpoint": endpoint}],
                    }
                ],
                "confirmed_static_c2": [endpoint],
                "configured_peer_certificate_sha256": [str(index + 4) * 64],
            }
        )

    merged = module.merge_results(results)

    assert merged["counts"] == {
        "artifact_batches": 2,
        "artifacts": 2,
        "archive_verified": 2,
        "artifact_verified": 2,
        "config_recovered": 2,
        "config_recovered_parent": 2,
        "configuration_conflict_parent": 0,
        "invalid_configuration_evidence": 0,
        "unique_c2": 2,
        "unique_peer_certificate_sha256": 2,
    }
    assert merged["safety"]["sample_executed"] is False
    assert merged["safety"]["network_contacted"] is False
    assert merged["safety"]["plaintext_artifact_written"] is False


def test_triage_result_merge_rejects_cross_batch_parent_config_conflict() -> None:
    module = load("remcos_triage_parent_conflict_test", "analyze_triage_artifacts.py")
    parent = "1" * 64
    results = []
    for index, (settings, endpoint) in enumerate(
        (("3" * 64, "first.example:2404"), ("4" * 64, "second.example:4489")),
        start=1,
    ):
        results.append(
            {
                "artifacts": [
                    {
                        "parent_sha256": parent,
                        "artifact_sha256": str(index + 4) * 64,
                        "status": "remcos_config_recovered",
                        "archive_verified": True,
                        "artifact_verified": True,
                        "config": {"decoded_settings_sha256": settings},
                        "c2": [{"endpoint": endpoint}],
                        "hunt": {"targets": [{"endpoint": endpoint}]},
                    }
                ]
            }
        )

    merged = module.merge_results(results)

    assert merged["counts"]["config_recovered"] == 0
    assert merged["counts"]["config_recovered_parent"] == 0
    assert merged["counts"]["configuration_conflict_parent"] == 1
    assert merged["confirmed_static_c2"] == []
    assert merged["configuration_conflict_parent_sha256"] == [parent]
    assert {item["status"] for item in merged["artifacts"]} == {"configuration_conflict_rejected"}
    assert all(item["accepted_for_parent"] is False for item in merged["artifacts"])
    assert all("c2" not in item and "config" not in item for item in merged["artifacts"])


def test_triage_result_merge_never_reaccepts_a_previously_conflicted_parent() -> None:
    module = load("remcos_triage_sticky_conflict_test", "analyze_triage_artifacts.py")
    parent = "1" * 64

    conflicted = module._summarize_artifacts(
        [
            {
                "parent_sha256": parent,
                "artifact_sha256": "2" * 64,
                "status": "remcos_config_recovered",
                "archive_verified": True,
                "artifact_verified": True,
                "config": {"decoded_settings_sha256": "3" * 64},
                "c2": [{"endpoint": "first.example:2404"}],
            },
            {
                "parent_sha256": parent,
                "artifact_sha256": "4" * 64,
                "status": "remcos_config_recovered",
                "archive_verified": True,
                "artifact_verified": True,
                "config": {"decoded_settings_sha256": "5" * 64},
                "c2": [{"endpoint": "second.example:4489"}],
            },
        ]
    )
    later_single_success = {
        "artifacts": [
            {
                "parent_sha256": parent,
                "artifact_sha256": "6" * 64,
                "status": "remcos_config_recovered",
                "archive_verified": True,
                "artifact_verified": True,
                "config": {"decoded_settings_sha256": "3" * 64},
                "c2": [{"endpoint": "first.example:2404"}],
            }
        ]
    }

    merged = module.merge_results([conflicted, later_single_success])

    assert merged["configuration_conflict_parent_sha256"] == [parent]
    assert merged["counts"]["configuration_conflict_parent"] == 1
    assert merged["counts"]["config_recovered"] == 0
    assert merged["counts"]["config_recovered_parent"] == 0
    assert merged["confirmed_static_c2"] == []
    assert {item["status"] for item in merged["artifacts"]} == {"configuration_conflict_rejected"}
    assert all(item["accepted_for_parent"] is False for item in merged["artifacts"])
    assert all("config" not in item and "c2" not in item for item in merged["artifacts"])


def test_corpus_recovery_rate_counts_parents_not_artifacts() -> None:
    module = load("remcos_parent_recovery_count_test", "analyze_corpus.py")
    recovered = "1" * 64
    unresolved = "2" * 64
    samples = [
        {
            "sha256": recovered,
            "config_status": "not_recovered",
            "terminal_artifacts": [
                {"status": "remcos_config_recovered"},
                {"status": "remcos_config_recovered"},
            ],
        },
        {
            "sha256": unresolved,
            "config_status": "not_recovered",
            "terminal_artifacts": [],
        },
    ]

    counts = module._parent_recovery_counts(samples)

    assert counts == {
        "root_config_recovered": 0,
        "terminal_artifact_config_recovered_parent": 1,
        "terminal_artifact_config_recovered": 2,
        "configuration_conflict_parent": 0,
        "config_recovered": 1,
        "config_recovered_denominator": 2,
        "config_recovered_rate": 0.5,
    }


def test_corpus_rejects_root_terminal_configuration_conflict() -> None:
    module = load("remcos_root_terminal_conflict_test", "analyze_corpus.py")
    record = {
        "config_status": "recovered",
        "static_family_confirmed": True,
        "config": {"decoded_settings_sha256": "1" * 64},
        "c2": [{"endpoint": "root.example:2404"}],
        "version_candidates": ["7.3.1 Pro"],
        "hunt": {"targets": [{"endpoint": "root.example:2404"}]},
        "terminal_artifacts": [
            {
                "status": "remcos_config_recovered",
                "config": {"decoded_settings_sha256": "2" * 64},
                "c2": [{"endpoint": "terminal.example:4489"}],
                "hunt": {"targets": [{"endpoint": "terminal.example:4489"}]},
            }
        ],
    }

    module._enforce_parent_configuration_consistency(record)

    assert record["parent_configuration_conflict"] is True
    assert record["config_status"] == "configuration_conflict_rejected"
    assert record["c2"] == []
    assert "config" not in record
    assert record["hunt"] is None
    terminal = record["terminal_artifacts"][0]
    assert terminal["status"] == "configuration_conflict_rejected"
    assert terminal["accepted_for_parent"] is False
    assert "c2" not in terminal and "config" not in terminal and "hunt" not in terminal


def test_corpus_output_cannot_overlap_manifest_archive_root_or_auxiliary(
    tmp_path: Path,
) -> None:
    module = load("remcos_output_boundary_test", "analyze_corpus.py")
    archive_root = tmp_path / "archives"
    archive_root.mkdir()
    manifest = archive_root / "manifest.json"
    manifest.write_text("{}", encoding="utf-8")
    auxiliary = tmp_path / "triage.json"
    auxiliary.write_text("{}", encoding="utf-8")

    with pytest.raises(ValueError, match="archive root"):
        module._validate_output_boundary(
            archive_root / "report.json",
            manifest=manifest,
            auxiliary_inputs=(auxiliary,),
        )
    with pytest.raises(ValueError, match="同じpath"):
        module._validate_output_boundary(
            auxiliary,
            manifest=manifest,
            auxiliary_inputs=(auxiliary,),
        )


def test_existing_terminal_conflict_rejects_other_parent_candidates() -> None:
    module = load("remcos_existing_parent_conflict_test", "analyze_corpus.py")
    record = {
        "config_status": "recovered",
        "config": {"decoded_settings_sha256": "1" * 64},
        "c2": [{"endpoint": "root.example:2404"}],
        "version_candidates": [],
        "hunt": {"targets": []},
        "terminal_artifacts": [
            {
                "status": "configuration_conflict_rejected",
                "accepted_for_parent": False,
            }
        ],
    }

    module._enforce_parent_configuration_consistency(record)

    assert record["parent_configuration_conflict"] is True
    assert record["config_status"] == "configuration_conflict_rejected"
    assert record["c2"] == []
    assert "config" not in record


def test_corpus_rejects_duplicate_selected_parent_hashes(tmp_path: Path) -> None:
    module = load("remcos_duplicate_parent_test", "analyze_corpus.py")
    digest = "1" * 64
    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "selection_mode": "signature_newest",
                "signature": "RemcosRAT",
                "selected_hashes": [digest, digest],
                "items": [],
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="重複"):
        module.analyze_manifest(manifest, "infected")


def test_terminal_artifact_contract_is_revalidated_and_secrets_are_discarded(
    tmp_path: Path,
) -> None:
    module = load("remcos_terminal_contract_test", "analyze_corpus.py")
    parent = "1" * 64
    artifact = "2" * 64
    c2 = [
        {
            "endpoint": "c2.example:2404",
            "host": "c2.example",
            "host_kind": "dns",
            "port": 2404,
            "tls_enabled": True,
            "third_field_kind": "tls_flag",
            "monitor_eligible": True,
            "role": "interactive_c2",
            "confidence": "confirmed_static_configuration",
        }
    ]
    config = {
        "static_config_recovered": True,
        "decoded_config_recovered": True,
        "family_attribution_confirmed": True,
        "endpoints": ["c2.example:2404"],
        "settings_resource_sha256": "3" * 64,
        "decoded_settings_sha256": "4" * 64,
        "rc4_key_sha256": "5" * 64,
        "rc4_key_published": False,
        "decoded_settings_published": False,
        "credential_value_published": False,
        "delimiter_hex": "7c1f1e1e7c",
        "field_count": 57,
        "schema_profile": "published_56_field_or_later",
        "c2_record_count": 1,
        "maximum_c2_record_count": 32,
        "botnet": "fixture",
        "connect_interval_seconds": 5,
        "initial_connect_delay_seconds": 0,
        "mutex_sha256": "6" * 64,
        "mutex_length": 10,
        "credential_or_unknown_c2_field_present": False,
        "validated_field_indices": [0, 1, 2, 14, 41],
        "complete_c2_record_set_validated": True,
        "family_specific_mutex_prefix_validated": True,
        "settings_resource_size": 1024,
        "rc4_key_size": 16,
        "private_key": "must-not-propagate",
        "tls_material": {
            "agent_certificate_present": False,
            "agent_certificate_sha256": None,
            "private_key_present": True,
            "private_key_published": False,
            "private_key": "must-not-propagate",
            "peer_certificate_present": False,
            "peer_certificate_sha256": None,
        },
    }
    identity = module._configuration_identity({"config": config, "c2": c2})
    assert identity is not None
    identity_sha256 = hashlib.sha256(
        json.dumps(
            [identity[0], list(identity[1])],
            ensure_ascii=True,
            separators=(",", ":"),
        ).encode("ascii")
    ).hexdigest()
    value = {
        "schema_version": 2,
        "analysis": "remcosrat_triage_terminal_artifacts",
        "configuration_conflict_parent_sha256": [],
        "artifacts": [
            {
                "parent_sha256": parent,
                "artifact_sha256": artifact,
                "sample_id": "fixture",
                "task_id": "behavioral1",
                "kind": "memory",
                "status": "remcos_config_recovered",
                "archive_verified": True,
                "artifact_verified": True,
                "family": "remcosrat",
                "accepted_for_parent": True,
                "parent_configuration_identity_sha256": identity_sha256,
                "version_candidates": [],
                "c2": c2,
                "config": config,
            }
        ],
        "safety": {
            "sample_executed": False,
            "network_contacted": False,
            "plaintext_artifact_written": False,
            "raw_config_published": False,
            "credentials_published": False,
            "private_key_published": False,
        },
    }
    source = tmp_path / "terminal.json"
    source.write_text(json.dumps(value), encoding="utf-8")

    parsed = module._terminal_artifacts(source, {parent})

    rendered = json.dumps(parsed, ensure_ascii=False)
    assert "must-not-propagate" not in rendered
    assert parsed[parent][0]["hunt"]["network_contacted"] is False

    value["artifacts"][0]["c2"][0]["endpoint"] = "forged.example:2404"
    source.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(ValueError, match="正規化field"):
        module._terminal_artifacts(source, {parent})
    value["artifacts"][0]["c2"][0]["endpoint"] = "c2.example:2404"

    value["artifacts"][0]["config"]["botnet"] = "A" * 129
    source.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(ValueError, match="config field契約"):
        module._terminal_artifacts(source, {parent})
    value["artifacts"][0]["config"]["botnet"] = "fixture"

    value["safety"]["network_contacted"] = True
    source.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(ValueError, match="安全境界"):
        module._terminal_artifacts(source, {parent})


def test_triage_manifest_rejects_duplicate_parent_child_before_archive_read(
    tmp_path: Path,
) -> None:
    module = load("remcos_triage_duplicate_manifest_test", "analyze_triage_artifacts.py")
    download = {
        "parent_sha256": "1" * 64,
        "artifact_sha256": "2" * 64,
        "archive_path": str(tmp_path / "missing.zip"),
    }
    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "query_type": "exact_sha256_public_triage_analysis",
                "downloads": [download, download],
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="重複"):
        module.analyze_manifest(manifest, "infected")


def _triage_download_fixture(tmp_path: Path) -> tuple[dict[str, object], Path]:
    parent = "1" * 64
    artifact = "2" * 64
    sample_id = "261018-abcdefghij"
    task_id = "behavioral1"
    name = "1234-7-0x0000000000400000-0x0000000000490000-memory.dmp"
    archive = tmp_path / parent / sample_id / f"artifact-{artifact[:16]}.zip"
    archive.parent.mkdir(parents=True)
    archive.write_bytes(b"encrypted-fixture-placeholder")
    download: dict[str, object] = {
        "parent_sha256": parent,
        "sample_id": sample_id,
        "task_id": task_id,
        "kind": "memory_image",
        "name": name,
        "endpoint_path": f"/samples/{sample_id}/{task_id}/memory/{name}",
        "reference_sha256": hashlib.sha256(f"memory/{name}".encode()).hexdigest(),
        "selection": "reported_region_memory",
        "reported_pid": 1234,
        "reported_procid": 9,
        "reported_region_index": 7,
        "reported_address": 0x400000,
        "reported_length": 0x90000,
        "http_status": 200,
        "content_type": "application/octet-stream",
        "content_length_header": str(0x90000),
        "redirects_followed": False,
        "artifact_sha256": artifact,
        "size": 0x90000,
        "archive_path": str(archive),
        "archive_sha256": "3" * 64,
        "archive_reused": False,
        "archive_encryption": "AES-256",
        "duplicate_of_parent": False,
        "executed": False,
    }
    return download, archive


def test_triage_download_evidence_binds_parent_task_endpoint_and_report_metadata(
    tmp_path: Path,
) -> None:
    module = load("remcos_triage_binding_test", "analyze_triage_artifacts.py")
    download, _archive = _triage_download_fixture(tmp_path)
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text("{}", encoding="utf-8")

    validated = module._validate_download_evidence(
        download,
        manifest_path=manifest_path,
        manifest_sha256="4" * 64,
        manifest_sha256_pinned=True,
        manifest_profile="legacy_bounded_subset_v1",
    )

    assert validated["parent_sha256"] == "1" * 64
    assert validated["sample_id"] == "261018-abcdefghij"
    assert validated["evidence"]["manifest_sha256_pinned"] is True
    assert validated["evidence"]["provider_parent_binding"] == "legacy_subset_manifest_claim"
    assert len(validated["evidence"]["download_record_binding_sha256"]) == 64

    forged = dict(download)
    forged["endpoint_path"] = (
        "/samples/261018-abcdefghij/behavioral2/memory/1234-7-0x0000000000400000-0x0000000000490000-memory.dmp"
    )
    with pytest.raises(ValueError, match="endpoint_path"):
        module._validate_download_evidence(
            forged,
            manifest_path=manifest_path,
            manifest_sha256="4" * 64,
            manifest_sha256_pinned=True,
            manifest_profile="legacy_bounded_subset_v1",
        )

    forged = dict(download)
    forged["reported_address"] = 0x500000
    with pytest.raises(ValueError, match="metadata"):
        module._validate_download_evidence(
            forged,
            manifest_path=manifest_path,
            manifest_sha256="4" * 64,
            manifest_sha256_pinned=True,
            manifest_profile="legacy_bounded_subset_v1",
        )


def test_triage_overview_reference_hash_and_manifest_pin_are_fail_closed(
    tmp_path: Path,
) -> None:
    module = load("remcos_triage_pin_test", "analyze_triage_artifacts.py")
    download, _archive = _triage_download_fixture(tmp_path)
    download.pop("selection")
    download["reference_sha256"] = hashlib.sha256(
        f"{download['task_id']}/memory/{download['name']}".encode()
    ).hexdigest()
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "query_type": "exact_sha256_public_triage_analysis",
                "downloads": [download],
            }
        ),
        encoding="utf-8",
    )

    validated = module._validate_download_evidence(
        download,
        manifest_path=manifest_path,
        manifest_sha256="4" * 64,
        manifest_sha256_pinned=False,
        manifest_profile="legacy_bounded_subset_v1",
    )
    assert validated["evidence"]["selection"] == "overview_extracted_artifact"

    forged = dict(download)
    forged["reference_sha256"] = "5" * 64
    with pytest.raises(ValueError, match="参照hash"):
        module._validate_download_evidence(
            forged,
            manifest_path=manifest_path,
            manifest_sha256="4" * 64,
            manifest_sha256_pinned=False,
            manifest_profile="legacy_bounded_subset_v1",
        )

    with pytest.raises(ValueError, match="SHA-256 pin"):
        module.analyze_manifest(
            manifest_path,
            "infected",
            expected_manifest_sha256="6" * 64,
        )


def test_triage_canonical_manifest_requires_complete_provider_verification_flags(
    tmp_path: Path,
) -> None:
    module = load("remcos_triage_canonical_profile_test", "analyze_triage_artifacts.py")
    download, _archive = _triage_download_fixture(tmp_path)
    download["metadata_sha256_verified"] = True
    download["public_analysis_verified"] = True
    candidate = {
        key: download[key]
        for key in (
            "parent_sha256",
            "sample_id",
            "task_id",
            "kind",
            "name",
            "endpoint_path",
            "reference_sha256",
            "selection",
        )
    }
    candidate["metadata_sha256_verified"] = True
    candidate["public_analysis_verified"] = True
    manifest = {
        "schema_version": 1,
        "created_at_utc": "2026-10-18T00:00:00+00:00",
        "query_type": "exact_sha256_public_triage_analysis",
        "requested_hashes": 1,
        "discovered_candidate_count": 1,
        "candidate_count": 1,
        "candidates": [candidate],
        "selected_candidate_reference_sha256": [download["reference_sha256"]],
        "report_memory_limits": {
            "max_bytes": 64 * 1024 * 1024,
            "max_total_bytes": 256 * 1024 * 1024,
            "max_candidates": 100,
        },
        "download_attempted": True,
        "downloaded_count": 1,
        "downloaded_total_bytes": download["size"],
        "downloads": [download],
        "errors": [],
        "safety": {
            "sample_submitted": False,
            "sample_executed_locally": False,
            "artifact_executed": False,
            "network_contacted": True,
            "redirects_followed": False,
            "plaintext_artifact_written": False,
            "api_key_published": False,
        },
    }

    assert module._validate_retrieval_manifest_metadata(manifest) == "canonical_triage_artifact_retrieval_v1_verified"
    validated = module._validate_download_evidence(
        download,
        manifest_path=tmp_path / "manifest.json",
        manifest_sha256="4" * 64,
        manifest_sha256_pinned=True,
        manifest_profile="canonical_triage_artifact_retrieval_v1_verified",
    )
    assert (
        validated["evidence"]["provider_parent_binding"]
        == "metadata_sha256_and_public_analysis_verified_by_retrieval_tool"
    )
    assert validated["evidence"]["metadata_sha256_verified_by_retrieval_tool"] is True
    assert validated["evidence"]["public_analysis_verified_by_retrieval_tool"] is True

    download["public_analysis_verified"] = False
    with pytest.raises(ValueError, match="証跡flag"):
        module._validate_retrieval_manifest_metadata(manifest)


def test_triage_manifest_hash_pin_rejects_hardlink_alias(tmp_path: Path) -> None:
    module = load("remcos_triage_manifest_alias_test", "analyze_triage_artifacts.py")
    manifest = tmp_path / "manifest.json"
    alias = tmp_path / "manifest-alias.json"
    manifest.write_text("{}", encoding="utf-8")
    os.link(manifest, alias)

    with pytest.raises(ValueError, match="単一link"):
        module._manifest_file_sha256(alias)


def test_triage_output_cannot_be_written_inside_archive_root(tmp_path: Path) -> None:
    module = load("remcos_triage_output_boundary_test", "analyze_triage_artifacts.py")
    archive_root = tmp_path / "triage"
    archive_root.mkdir()
    manifest = archive_root / "manifest.json"
    manifest.write_text("{}", encoding="utf-8")

    with pytest.raises(ValueError, match="archive root"):
        module._validate_output_boundary(archive_root / "result.json", [manifest])
