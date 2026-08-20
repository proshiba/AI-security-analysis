"""複数検体C2 profile packとoffline detectorを検証する。"""

from __future__ import annotations

import importlib
import json
import sys
from copy import deepcopy
from pathlib import Path

import pytest

COMMON = Path(__file__).parents[1] / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

COLLECTION = importlib.import_module("reviewed_c2_collection")
HOST = importlib.import_module("tls_messagepack_rat_host_emulator")


def _analysis_document() -> dict:
    return {
        "schema_version": 2,
        "sample_executed": False,
        "network_contacted": False,
        "raw_keys_published": False,
        "results": [
            {
                "source_member": "bundle/client-a.exe",
                "root_sha256": "1" * 64,
                "sample_executed": False,
                "network_contacted": False,
                "terminal": {"sha256": "2" * 64},
                "config": {
                    "family": COLLECTION.BW_FAMILY,
                    "endpoints": [
                        {
                            "endpoint": "192.0.2.10:443",
                            "host": "192.0.2.10",
                            "port": 443,
                            "external": True,
                        }
                    ],
                    "certificate": {"sha256": "3" * 64},
                },
            },
            {
                "source_member": "bundle/client-b.exe",
                "root_sha256": "4" * 64,
                "sample_executed": False,
                "network_contacted": False,
                "terminal": {"sha256": "5" * 64},
                "config": {
                    "family": COLLECTION.VVAS_FAMILY,
                    "endpoints": [
                        {
                            "endpoint": "198.51.100.20:1617",
                            "host": "198.51.100.20",
                            "port": 1617,
                            "external": True,
                        },
                        {
                            "endpoint": "198.51.100.20:1618",
                            "host": "198.51.100.20",
                            "port": 1618,
                            "external": True,
                        },
                    ],
                },
            },
            {
                "source_member": "bundle/client-c.exe",
                "root_sha256": "6" * 64,
                "sample_executed": False,
                "network_contacted": False,
                "terminal": {"sha256": "7" * 64},
                "config": {"family": COLLECTION.VVAS_FAMILY, "endpoints": []},
            },
        ],
    }


def _pack(tmp_path: Path) -> tuple[Path, object]:
    analysis = tmp_path / "analysis.json"
    analysis.write_text(
        json.dumps(_analysis_document(), ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    document = COLLECTION.build_collection(
        analysis,
        collection_id="test-collection-20260819",
        source_path_label="private analysis fixture",
    )
    profiles = tmp_path / "profiles.json"
    COLLECTION.write_collection(profiles, document)
    return profiles, COLLECTION.load_collection(profiles)


def test_builder_binds_three_samples_and_three_external_targets(tmp_path: Path) -> None:
    profiles_path, collection = _pack(tmp_path)
    plans = COLLECTION.detector_plans(collection)

    assert profiles_path.exists()
    assert len(collection.profiles) == 3
    assert len(plans) == 3
    assert {plan["execution_backend"] for plan in plans} == {"nmap_nse_only"}
    assert all(plan["network_contacted"] is False for plan in plans)
    assert all(plan["requires_current_task_network_authorization"] is True for plan in plans)
    bw_plan = next(plan for plan in plans if plan["family"] == COLLECTION.BW_FAMILY)
    assert bw_plan["script"].endswith("dotnet-rat-c2.nse")
    assert "dotnet-rat.expected-cert=" + "3" * 64 in bw_plan["script_args"]
    vvas_plans = [plan for plan in plans if plan["family"] == COLLECTION.VVAS_FAMILY]
    assert len(vvas_plans) == 2
    assert all("valleyrat.mode=vvas" in plan["script_args"] for plan in vvas_plans)


def test_profile_mutation_is_rejected_fail_closed(tmp_path: Path) -> None:
    analysis = tmp_path / "analysis.json"
    analysis.write_text(json.dumps(_analysis_document()), encoding="utf-8")
    document = COLLECTION.build_collection(
        analysis,
        collection_id="test-collection-20260819",
        source_path_label="private analysis fixture",
    )
    mutated = deepcopy(document)
    mutated["profiles"][0]["detector"]["packet_key"] = "Packet"
    path = tmp_path / "mutated.json"
    path.write_text(json.dumps(mutated), encoding="utf-8")

    with pytest.raises(COLLECTION.ReviewedC2CollectionError, match="profile_sha256"):
        COLLECTION.load_collection(path)


@pytest.mark.parametrize(
    ("host", "port"),
    [("127.0.0.1", 443), ("localhost", 443), ("192.0.2.1", 0), ("224.0.0.1", 80)],
)
def test_unsafe_endpoint_is_rejected(tmp_path: Path, host: str, port: int) -> None:
    document = _analysis_document()
    endpoint = document["results"][0]["config"]["endpoints"][0]
    endpoint.update({"endpoint": f"{host}:{port}", "host": host, "port": port})
    analysis = tmp_path / "analysis.json"
    analysis.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(COLLECTION.ReviewedC2CollectionError):
        COLLECTION.build_collection(
            analysis,
            collection_id="test-collection-20260819",
            source_path_label="private analysis fixture",
        )


def test_bwrat_offline_classifier_requires_tls_and_exact_pong(tmp_path: Path) -> None:
    _, collection = _pack(tmp_path)
    profile = next(
        value for value in collection.profiles.values() if value.family == COLLECTION.BW_FAMILY
    )
    frame = HOST.encode_frame({"Pac_ket": "Po_ng"})
    result = COLLECTION.classify_bwrat_response(
        profile,
        frame,
        tls_version="TLSv1.2",
        certificate_sha256="3" * 64,
    )

    assert result["c2_confirmed"] is True
    assert result["certificate_exact_match"] is True
    assert result["raw_response_retained"] is False
    mismatch = COLLECTION.classify_bwrat_response(
        profile,
        HOST.encode_frame({"Pac_ket": "plugin"}),
        tls_version="TLSv1.2",
        certificate_sha256="8" * 64,
    )
    assert mismatch["c2_confirmed"] is False
    assert mismatch["certificate_exact_match"] is False
    assert mismatch["certificate_mismatch_excludes_c2"] is False


def test_vvas_offline_classifier_accepts_header_without_retaining_stage(tmp_path: Path) -> None:
    _, collection = _pack(tmp_path)
    profile = next(
        value for value in collection.profiles.values() if value.family == COLLECTION.VVAS_FAMILY
    )
    header = (307214).to_bytes(4, "little") + b"\x00" * 10
    result = COLLECTION.classify_vvas_response(profile, header)

    assert result["c2_confirmed"] is True
    assert result["stage_downloaded"] is False
    assert result["stage_body_retained"] is False
    assert COLLECTION.classify_vvas_response(profile, b"bad")["c2_confirmed"] is False


def test_builder_rejects_positive_analysis_safety_flags(tmp_path: Path) -> None:
    document = _analysis_document()
    document["network_contacted"] = True
    analysis = tmp_path / "analysis.json"
    analysis.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(COLLECTION.ReviewedC2CollectionError, match="safety"):
        COLLECTION.build_collection(
            analysis,
            collection_id="test-collection-20260819",
            source_path_label="private analysis fixture",
        )
