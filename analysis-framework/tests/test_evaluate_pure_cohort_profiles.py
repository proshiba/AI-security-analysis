"""PureLogs／PureRAT共通コホート評価profileの回帰テスト。"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path

import pytest

COMMON = Path(__file__).parents[1] / "common"
ENGINE_PATH = COMMON / "evaluate_purelogs_cohort.py"
SPEC = importlib.util.spec_from_file_location("evaluate_pure_cohort_engine", ENGINE_PATH)
ENGINE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(ENGINE)
PROFILE_MODULE = sys.modules["pure_cohort_profiles"]


def _layer(data: bytes, *, depth: int = 0) -> object:
    digest = hashlib.sha256(data).hexdigest()
    return ENGINE.StaticLayer(
        name="fixture.bin",
        data=data,
        sha256=digest,
        parent_sha256=None if depth == 0 else "0" * 64,
        depth=depth,
        transform="submission" if depth == 0 else "fixture-transform",
    )


def _purerat_detection(
    digest: str,
    *,
    managed: bool,
    endpoint: str = "rat.example.test:56001",
    campaign: str = "fixture-campaign",
    certificate_sha256: str = "a" * 64,
    pfx_sha256: str = "b" * 64,
) -> dict:
    return {
        "matched": True,
        "confidence": "high",
        "sha256": digest,
        "observations": {
            "managed_terminal": {
                "matched": managed,
                "endpoints": [endpoint] if managed else [],
                "campaign_id": campaign if managed else None,
                "version": "4.4.1" if managed else None,
                "certificate_sha256": certificate_sha256 if managed else None,
                "pfx_sha256": pfx_sha256 if managed else None,
            }
        },
    }


def _purerat_extraction(
    digest: str,
    *,
    endpoint: str = "rat.example.test:56001",
    campaign: str = "fixture-campaign",
    certificate_sha256: str = "a" * 64,
    pfx_sha256: str = "b" * 64,
) -> dict:
    host, raw_port = endpoint.rsplit(":", 1)
    port = int(raw_port)
    return {
        "sample_sha256": digest,
        "family": "purehvnc",
        "config": {
            "variant": "managed_purerat",
            "static_config_recovered": True,
            "decoded_config_recovered": True,
            "status": "managed_terminal_config_recovered",
            "terminal_family_confirmation_requires_detector": True,
            "c2_host": host,
            "c2_ports": [port],
            "endpoints": [endpoint],
            "campaign_id": campaign,
            "version_candidates": ["4.4.1"],
            "certificate": {
                "certificate_sha256": certificate_sha256,
                "pfx_sha256": pfx_sha256,
            },
        },
        "c2": [
            {
                "host": host,
                "port": port,
                "role": "c2",
                "confidence": "confirmed_static_configuration",
                "evidence": {
                    "kind": "managed_base64_gzip_protobuf_config",
                    "variant": "managed_purerat",
                    "host_and_ports_validated": True,
                    "endpoint_correlated": True,
                },
            }
        ],
    }


def test_purerat_loader_match_does_not_become_terminal_success() -> None:
    layer = _layer(b"AppV loader fixture")

    result = ENGINE.evaluate_layers(
        [layer],
        profile=ENGINE.PURELOGS_PROFILE.__class__(
            **{
                **ENGINE.PURERAT_PROFILE.__dict__,
                "detector": lambda _data, _path: _purerat_detection(layer.sha256, managed=False),
                "extractor": lambda _data, _name: {"sample_sha256": layer.sha256, "family": "purehvnc"},
            }
        ),
    )

    assert result["root_family_confirmed"] is True
    assert result["loader_family_confirmed"] is True
    assert result["terminal_payload_reached"] is False
    assert result["terminal_family_confirmed"] is False
    assert result["strict_success"] is False
    assert result["primary_failure_reason"] == "loader_only_terminal_not_recovered"


def test_purerat_managed_detector_and_config_same_layer_are_strict_success() -> None:
    layer = _layer(b"managed PureRAT fixture")
    profile = ENGINE.PURERAT_PROFILE

    result = ENGINE.evaluate_layers(
        [layer],
        profile=profile,
        detector=lambda _data, _path: _purerat_detection(layer.sha256, managed=True),
        extractor=lambda _data, _name: _purerat_extraction(layer.sha256),
    )

    assert result["root_family_confirmed"] is True
    assert result["terminal_payload_reached"] is True
    assert result["terminal_family_confirmed"] is True
    assert result["validated_config_recovered"] is True
    assert result["qualified_c2_recovered"] is True
    assert result["strict_success"] is True
    assert result["primary_failure_reason"] == "strict_success"
    serialized = json.dumps(result)
    assert "rat.example.test" not in serialized
    assert result["strict_evidence_layers"][0]["raw_endpoint_published"] is False


def test_purerat_same_endpoint_different_certificate_is_conflict() -> None:
    first = _layer(b"managed PureRAT fixture one")
    second = _layer(b"managed PureRAT fixture two", depth=1)

    def detector(data: bytes, _path: Path | None) -> dict:
        digest = hashlib.sha256(data).hexdigest()
        cert = "a" * 64 if data == first.data else "c" * 64
        return _purerat_detection(digest, managed=True, certificate_sha256=cert)

    def extractor(data: bytes, _name: str) -> dict:
        digest = hashlib.sha256(data).hexdigest()
        cert = "a" * 64 if data == first.data else "c" * 64
        return _purerat_extraction(digest, certificate_sha256=cert)

    result = ENGINE.evaluate_layers(
        [first, second],
        profile=ENGINE.PURERAT_PROFILE,
        detector=detector,
        extractor=extractor,
    )

    assert result["configuration_conflict"] is True
    assert result["validated_config_recovered"] is False
    assert result["strict_success"] is False
    assert result["primary_failure_reason"] == "conflicting_configuration_candidates"


def test_purerat_config_from_different_sha_is_rejected() -> None:
    layer = _layer(b"managed PureRAT same-layer fixture")
    other_sha256 = hashlib.sha256(b"different layer").hexdigest()

    result = ENGINE.evaluate_layers(
        [layer],
        profile=ENGINE.PURERAT_PROFILE,
        detector=lambda _data, _path: _purerat_detection(layer.sha256, managed=True),
        extractor=lambda _data, _name: _purerat_extraction(other_sha256),
    )

    assert result["terminal_family_confirmed"] is True
    assert result["validated_config_recovered"] is False
    assert result["qualified_c2_recovered"] is False
    assert result["strict_success"] is False
    assert result["primary_failure_reason"] == "terminal_family_config_not_recovered"


def test_purerat_detector_from_different_sha_cannot_validate_config() -> None:
    layer = _layer(b"managed PureRAT detector layer fixture")
    other_sha256 = hashlib.sha256(b"different detector layer").hexdigest()

    result = ENGINE.evaluate_layers(
        [layer],
        profile=ENGINE.PURERAT_PROFILE,
        detector=lambda _data, _path: _purerat_detection(other_sha256, managed=True),
        extractor=lambda _data, _name: _purerat_extraction(layer.sha256),
    )

    assert result["terminal_family_confirmed"] is False
    assert result["validated_config_recovered"] is False
    assert result["qualified_c2_recovered"] is False
    assert result["strict_success"] is False


def test_layer_cache_is_namespaced_by_profile() -> None:
    layer = _layer(b"shared layer fixture")
    cache: dict = {}

    ENGINE.evaluate_layers(
        [layer],
        profile=ENGINE.PURERAT_PROFILE,
        detector=lambda _data, _path: _purerat_detection(layer.sha256, managed=False),
        extractor=lambda _data, _name: {"sample_sha256": layer.sha256, "family": "purehvnc"},
        layer_cache=cache,
    )
    ENGINE.evaluate_layers(
        [layer],
        profile=ENGINE.PURELOGS_PROFILE,
        detector=lambda _data, _path: {"matched": False, "confidence": "none", "sha256": layer.sha256},
        extractor=lambda _data, _name: {"sample_sha256": layer.sha256, "family": "purelogs"},
        layer_cache=cache,
    )

    assert set(cache) == {
        ("purerat", layer.sha256, layer.name, layer.transform),
        ("purelogs", layer.sha256, layer.name, layer.transform),
    }


def test_load_cohort_accepts_only_complete_committed_signature_manifest(tmp_path: Path) -> None:
    digest = "d" * 64
    manifest = {
        "schema_version": 1,
        "source": "MalwareBazaar Community API",
        "selection_mode": "signature_newest",
        "signature": "PureRAT",
        "query_limit": 1000,
        "selected_at": "2026-10-29T00:00:00+00:00",
        "requested": 1,
        "excluded_hashes": 0,
        "excluded_hashes_sha256": hashlib.sha256(b"").hexdigest(),
        "selected_hashes": [digest],
        "selected_metadata": [{"sha256_hash": digest, "signature": "PureRAT"}],
        "max_download_bytes": 1024,
        "max_total_download_bytes": 2048,
        "minimum_free_bytes": 4096,
        "archives_remain_encrypted": True,
        "samples_executed": False,
        "selection_only": False,
        "downloaded": 1,
        "complete": True,
    }
    manifest["selection_commitment_sha256"] = ENGINE._signature_selection_commitment(manifest)
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(manifest), encoding="utf-8")

    cohort, hashes, source_sha256 = ENGINE.load_cohort(path, "PureRAT")

    assert hashes == [digest]
    assert cohort["selection_commitment_sha256"] == manifest["selection_commitment_sha256"]
    assert source_sha256 == hashlib.sha256(path.read_bytes()).hexdigest()

    manifest["complete"] = False
    path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(ENGINE.CohortEvaluationError, match="固定signature cohort契約"):
        ENGINE.load_cohort(path, "PureRAT")


def test_profile_import_binding_covers_transitive_sources() -> None:
    """入口だけでなく実際のrepo内transitive sourceをimport前hashへ束縛する。"""

    binding = dict(ENGINE.PURERAT_PROFILE.import_source_sha256)

    assert {
        "analysis-framework/common/pe_structural_profile.py",
        "analysis-framework/malware/purehvnc/detect.py",
        "extractors/common.py",
        "extractors/purehvnc/extractor.py",
        "unpackers/managed_cil_cfg.py",
        "unpackers/managed_constructor_guard.py",
    } <= set(binding)
    assert all(len(digest) == 64 for digest in binding.values())


@pytest.mark.parametrize(
    "module_name",
    (
        "extractors.purehvnc.extractor",
        "extractors.purelogs.extractor",
        "unpackers.managed_cil_cfg",
    ),
)
def test_profile_dependencies_are_loaded_from_import_time_snapshot(module_name: str) -> None:
    """profileが参照する依存moduleをlive fileでなく固定bytesから読み込む。"""

    module = sys.modules[module_name]

    assert isinstance(module.__loader__, PROFILE_MODULE._FrozenRepoSourceLoader)
    source_path = Path(module.__file__).resolve()
    expected = dict(ENGINE.PURERAT_PROFILE.import_source_sha256)[
        source_path.relative_to(ENGINE.REPOSITORY_ROOT).as_posix()
    ]
    assert hashlib.sha256(module.__loader__._data).hexdigest() == expected


def test_frozen_loader_does_not_reopen_live_source(tmp_path: Path) -> None:
    """disk内容が異なってもloaderはimport前に保持したbytesだけを実行する。"""

    source_path = tmp_path / "fixture_module.py"
    source_path.write_text("VALUE = 'live'\n", encoding="utf-8")
    loader = PROFILE_MODULE._FrozenRepoSourceLoader(
        source_path,
        b"VALUE = 'frozen'\n",
        is_package=False,
    )
    spec = importlib.util.spec_from_loader("frozen_fixture_module", loader)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)

    loader.exec_module(module)

    assert module.VALUE == "frozen"
