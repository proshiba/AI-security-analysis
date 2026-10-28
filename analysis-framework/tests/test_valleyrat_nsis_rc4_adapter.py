"""NSIS／RC4 sidecar adapterのfail-closed回帰テスト。"""

from __future__ import annotations

import copy
import hashlib
from pathlib import PurePosixPath

from extractors.valleyrat.nsis_rc4_sidecar import NsisRc4SidecarLineage

from common import static_layer_pipeline as pipeline
from common import valleyrat_nsis_rc4_adapter as adapter


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _fixture() -> tuple[bytes, dict[str, object], list[tuple[str, bytes]]]:
    parent = b"MZ" + b"P" * 128
    members = [
        ("config.xml", "config.xml", "data", b"ciphertext"),
        ("controller.dll", "controller.dll", "pe", b"MZ-controller"),
        ("resources.zip", "resources.zip", "zip", b"PK\x03\x04archive"),
    ]
    inventory = [
        {
            "name": name,
            "output_name": output_name,
            "size": len(data),
            "sha256": _sha256(data),
            "format": format_label,
            "crc_available": False,
            "crc_verified": False,
        }
        for name, output_name, format_label, data in members
    ]
    artifacts = [
        (f"nsis-member-{index:03d}-{format_label}{PurePosixPath(name).suffix}", data)
        for index, (name, _output_name, format_label, data) in enumerate(members)
    ]
    report: dict[str, object] = {
        "format": "pe",
        "sha256": _sha256(parent),
        "size": len(parent),
        "executed": False,
        "network_contacted": False,
        "sevenzip": {
            "status": "selectively_extracted",
            "candidate": True,
            "executed": False,
            "sample_executed": False,
            "network_contacted": False,
            "external_parser_started": True,
            "inventory_complete": True,
            "archive_test_complete": True,
            "extraction_complete": True,
            "archive_types": ["Nsis"],
            "tool": {
                "available": True,
                "version_supported": True,
                "identity_unchanged": True,
            },
            "container_envelope": {"container_layout_validated": True},
            "selective_extraction": {
                "enabled": True,
                "selected_member_count": len(inventory),
                "omitted_member_count": 11,
            },
            "ratio_validation": {
                "complete": True,
                "blocked_member_count": 0,
            },
            "inventory": inventory,
            "retained_members": len(inventory),
            "total_members": len(inventory) + 11,
            "extracted_total_size": sum(len(data) for *_rest, data in members),
        },
    }
    return parent, report, artifacts


def test_verified_nsis_bundle_is_joined_and_terminal_is_returned(monkeypatch) -> None:
    parent, report, artifacts = _fixture()
    terminal = b"MZ-terminal"
    observed: list[dict[str, bytes]] = []

    def fake_analyze(components):
        observed.append(dict(components))
        return NsisRc4SidecarLineage(
            observation={
                "status": "validated_nsis_xor_zipcrypto_rc4_to_vvas_terminal",
                "supports_family_attribution": True,
                "terminal_family_confirmed": True,
                "terminal_network_lineage_proven": True,
                "terminal": {"endpoint_count": 3},
                "sample_executed": False,
                "network_contacted": False,
            },
            terminal_component=terminal,
            recovered_components=(),
        )

    monkeypatch.setattr(adapter, "analyze_nsis_rc4_sidecar_bundle", fake_analyze)
    result = adapter.recover_verified_nsis_rc4_sidecar_layer(
        parent_data=parent,
        parent_sha256=_sha256(parent),
        report=report,
        artifacts=artifacts,
    )
    assert result is not None
    assert result.data == terminal
    assert set(observed[0]) == {"config.xml", "controller.dll", "resources.zip"}
    public = result.public()
    assert public["proof"]["terminal_endpoint_count"] == 3
    assert public["evidence_boundary"]["raw_network_values_included"] is False
    assert "endpoint" not in public


def test_verified_nsis_bundle_rejects_missing_or_mismatched_member(monkeypatch) -> None:
    parent, report, artifacts = _fixture()
    monkeypatch.setattr(
        adapter,
        "analyze_nsis_rc4_sidecar_bundle",
        lambda _components: (_ for _ in ()).throw(AssertionError("呼ばれないこと")),
    )
    assert (
        adapter.recover_verified_nsis_rc4_sidecar_layer(
            parent_data=parent,
            parent_sha256=_sha256(parent),
            report=report,
            artifacts=artifacts[:-1],
        )
        is None
    )
    broken = copy.deepcopy(report)
    broken["sevenzip"]["inventory"][0]["sha256"] = "0" * 64
    assert (
        adapter.recover_verified_nsis_rc4_sidecar_layer(
            parent_data=parent,
            parent_sha256=_sha256(parent),
            report=broken,
            artifacts=artifacts,
        )
        is None
    )


def test_verified_nsis_bundle_rejects_incomplete_extraction(monkeypatch) -> None:
    parent, report, artifacts = _fixture()
    report["sevenzip"]["extraction_complete"] = False
    monkeypatch.setattr(
        adapter,
        "analyze_nsis_rc4_sidecar_bundle",
        lambda _components: (_ for _ in ()).throw(AssertionError("呼ばれないこと")),
    )
    assert (
        adapter.recover_verified_nsis_rc4_sidecar_layer(
            parent_data=parent,
            parent_sha256=_sha256(parent),
            report=report,
            artifacts=artifacts,
        )
        is None
    )


def test_static_pipeline_queues_verified_terminal(monkeypatch) -> None:
    parent = b"root"
    parent_sha256 = _sha256(parent)
    terminal = b"MZ-terminal"
    layer = adapter.VerifiedNsisRc4SidecarLayer(
        data=terminal,
        parent_sha256=parent_sha256,
        terminal_sha256=_sha256(terminal),
        inventory_member_count=3,
        inventory_total_size=123,
        omitted_member_count=9,
        observation={"terminal": {"endpoint_count": 2}},
    )
    monkeypatch.setattr(
        pipeline,
        "recover_verified_nsis_rc4_sidecar_layer",
        lambda **_kwargs: layer,
    )

    def unpacker(data: bytes, _name: str, **_kwargs):
        if data == parent:
            return {"format": "pe"}, [("ordinary-data", b"ordinary")]
        return {"format": "pe"}, []

    unit = pipeline.InputUnit(
        source_name="sample.exe",
        data=parent,
        input_kind="raw",
        outer_sha256=parent_sha256,
        outer_size=len(parent),
    )
    layers, report = pipeline.recover_static_layers(
        unit,
        unpacker=unpacker,
        policy=pipeline.StaticLayerPolicy(
            max_layers=4,
            max_depth=2,
            max_layer_size=128,
            max_total_size=256,
        ),
    )
    recovered = next(item for item in layers if item.data == terminal)
    assert recovered.transform == "verified-nsis-rc4-terminal-pe"
    public = report["steps"][0]["report"]["verified_nsis_rc4_sidecar_adapter"]
    assert public["proof"]["terminal_endpoint_count"] == 2
