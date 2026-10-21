"""検証済みRAR同居member adapterのfail-closed回帰テスト。"""

from __future__ import annotations

import copy
import hashlib
import io
import json
import zipfile
import zlib
from types import SimpleNamespace

import pytest

from common import valleyrat_verified_sibling_adapter as adapter


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _fixture() -> tuple[bytes, dict[str, object], list[tuple[str, bytes]], dict[str, bytes]]:
    parent = b"MZ" + b"P" * 96
    blobs = {
        "bundle/host.exe": b"MZ-host-fixture",
        "bundle/host-copy.exe": b"MZ-host-fixture",
        "bundle/loader.dll": b"MZ-loader-fixture",
        "bundle/carrier.bin": b"carrier-fixture",
        "alternate/loader2.dll": b"MZ-second-loader-fixture",
    }
    definitions = {
        "bundle/host.exe": ("pe", 0),
        "bundle/host-copy.exe": ("pe", 1),
        "bundle/loader.dll": ("pe", 2),
        "bundle/carrier.bin": ("data", 3),
        "alternate/loader2.dll": ("pe", 4),
    }
    inventory: list[dict[str, object]] = []
    for path in (
        "alternate/loader2.dll",
        "bundle/loader.dll",
        "bundle/host.exe",
        "bundle/carrier.bin",
        "bundle/host-copy.exe",
    ):
        format_label, priority = definitions[path]
        item: dict[str, object] = {
            "name": path,
            "size": len(blobs[path]),
            "sha256": _sha256(blobs[path]),
            "format": format_label,
            "status": "extracted",
        }
        if priority is not None:
            item["recovery_priority"] = priority
        inventory.append(item)
    selected = sorted(
        (item for item in inventory if "recovery_priority" in item),
        key=lambda item: (item["recovery_priority"], str(item["name"]).lower()),
    )
    hints = {
        "schema_version": 1,
        "complete": True,
        "items": [
            {
                "artifact_index": index,
                "artifact_kind": f"7z-{item['format']}",
                "sha256": item["sha256"],
                "member_basename": str(item["name"]).rsplit("/", 1)[-1],
            }
            for index, item in enumerate(selected)
        ],
    }
    full_size = sum(len(value) for value in blobs.values())
    sevenzip = {
        "status": "extracted",
        "exit_code": 0,
        "extract_exit_code": 0,
        "archive_types": ["Rar5"],
        "member_layout_ambiguous": False,
        "member_listing_boundary_observed": True,
        "member_record_limit_exceeded": False,
        "unsafe_member_count": 0,
        "inventory": inventory,
        "members": list(reversed(list(blobs))),
        "total_members": len(blobs),
        "declared_total_size": full_size,
        "extracted_total_size": full_size,
        "retained_members": len(selected),
        "artifact_name_hints": hints,
        "all_bounded_member_retention": {
            "enabled": True,
            "retained_member_count": len(blobs),
            "full_inventory_count": len(blobs),
            "complete": True,
        },
        "safe_member_continuation": {
            "applied": False,
            "blocked_member_count": 0,
            "explicit_safe_member_count": len(blobs),
            "unsafe_member_names_published": False,
            "archive_inventory_complete": True,
        },
        "selective_extraction": {
            "enabled": False,
            "reason": "not_required",
            "selected_members": [],
            "selected_total_size": 0,
            "full_inventory_count": len(blobs),
        },
    }
    report = {
        "format": "pe",
        "sha256": _sha256(parent),
        "size": len(parent),
        "executed": False,
        "network_contacted": False,
        "pe": {
            "winrar_sfx": {
                "status": "validated_sfx_container",
                "candidate": True,
                "scan_complete": True,
                "header_crc_verified": True,
                "family_attribution_allowed": False,
                "c2_confirmation_allowed": False,
                "terminal_promotion_eligible": False,
            }
        },
        "sevenzip": sevenzip,
        "artifact_name_hints": hints,
    }
    artifacts = [
        ("7z-pe", blobs["bundle/host.exe"]),
        ("7z-pe", blobs["bundle/loader.dll"]),
        ("7z-data", blobs["bundle/carrier.bin"]),
        ("7z-pe", blobs["alternate/loader2.dll"]),
    ]
    return parent, report, artifacts, blobs


def _strict_stub(members):
    by_path = {item.path: item for item in members}
    return SimpleNamespace(
        terminal_sha256=_sha256(b"terminal-fixture"),
        host_sha256=by_path["bundle/host.exe"].sha256,
        loader_sha256=by_path["bundle/loader.dll"].sha256,
        carrier_sha256=by_path["bundle/carrier.bin"].sha256,
    )


def test_complete_identity_join_builds_deterministic_analysis_bundle(monkeypatch) -> None:
    """全inventoryと重複排除artifactを結合できた場合だけZIPを返す。"""

    parent, report, artifacts, blobs = _fixture()
    observed: dict[str, object] = {}

    def fake_recover(**kwargs):
        observed.update(kwargs)
        return _strict_stub(kwargs["members"])

    monkeypatch.setattr(adapter, "recover_verified_sibling_shellcode", fake_recover)
    result = adapter.recover_verified_sibling_bundle_layer(
        parent_data=parent,
        parent_sha256=_sha256(parent),
        report=report,
        artifacts=artifacts,
    )

    assert result is not None
    assert observed["collection_complete"] is True
    assert observed["declared_member_count"] == 5
    assert observed["declared_total_size"] == sum(len(value) for value in blobs.values())
    with zipfile.ZipFile(io.BytesIO(result.data)) as archive:
        assert archive.namelist() == sorted(
            blobs,
            key=str.casefold,
        )
        assert all(archive.read(path) == blobs[path] for path in archive.namelist())
    repeat = adapter.recover_verified_sibling_bundle_layer(
        parent_data=parent,
        parent_sha256=_sha256(parent),
        report=report,
        artifacts=artifacts,
    )
    assert repeat is not None
    assert repeat.data == result.data
    public = result.public()
    assert public["evidence_boundary"]["adapter_confirms_family"] is False
    assert public["evidence_boundary"]["adapter_confirms_c2"] is False
    assert public["inventory"]["full_member_count"] == 5
    assert public["inventory"]["materialized_member_count"] == 4
    assert public["inventory"]["normalized_member_count"] == 5
    assert public["inventory"]["distinct_artifact_count"] == 4
    assert public["inventory"]["verified_duplicate_alias_count"] == 1
    assert public["inventory"]["source_deduplicated_alias_count"] == 1
    assert public["inventory"]["all_inventory_rows_reconstructed"] is True
    assert public["inventory"]["materialized_identity_set_equals_inventory_identity_set"] is True
    assert public["proof"]["collection_complete"] is True
    rendered = json.dumps(public, sort_keys=True)
    assert all(path not in rendered for path in blobs)


def test_available_crc_is_verified(monkeypatch) -> None:
    """inventoryにCRCがある場合はmaterialized bytesへ再計算する。"""

    parent, report, artifacts, blobs = _fixture()
    inventory = report["sevenzip"]["inventory"]
    target = next(item for item in inventory if item["name"] == "bundle/loader.dll")
    target["crc32"] = f"{zlib.crc32(blobs['bundle/loader.dll']) & 0xFFFFFFFF:08x}"
    monkeypatch.setattr(
        adapter,
        "recover_verified_sibling_shellcode",
        lambda **kwargs: _strict_stub(kwargs["members"]),
    )

    result = adapter.recover_verified_sibling_bundle_layer(
        parent_data=parent,
        parent_sha256=_sha256(parent),
        report=report,
        artifacts=artifacts,
    )
    assert result is not None
    assert result.crc32_verified_member_count == 1

    target["crc32"] = "00000000"
    assert (
        adapter.recover_verified_sibling_bundle_layer(
            parent_data=parent,
            parent_sha256=_sha256(parent),
            report=report,
            artifacts=artifacts,
        )
        is None
    )


@pytest.mark.parametrize(
    "mutation",
    [
        "unsafe_member",
        "unvalidated_sfx",
        "retention_incomplete",
        "incomplete_inventory",
        "count_mismatch",
        "size_mismatch",
        "hint_index_mismatch",
        "hint_hash_mismatch",
        "path_traversal",
        "path_ads",
        "nfkc_casefold_path_collision",
        "duplicate_alias_size_mismatch",
        "omitted_second_chain_member",
        "extra_artifact",
        "strict_proof_missing",
    ],
)
def test_incomplete_or_ambiguous_join_is_rejected(monkeypatch, mutation: str) -> None:
    """件数・size・path・identity・strict proofの不一致をfail closedにする。"""

    parent, report, artifacts, _blobs = _fixture()
    report = copy.deepcopy(report)
    artifacts = list(artifacts)
    if mutation == "unsafe_member":
        report["sevenzip"]["unsafe_member_count"] = 1
    elif mutation == "unvalidated_sfx":
        report["pe"]["winrar_sfx"]["header_crc_verified"] = False
    elif mutation == "retention_incomplete":
        report["sevenzip"]["all_bounded_member_retention"]["complete"] = False
    elif mutation == "incomplete_inventory":
        report["sevenzip"]["safe_member_continuation"]["archive_inventory_complete"] = False
    elif mutation == "count_mismatch":
        report["sevenzip"]["total_members"] += 1
    elif mutation == "size_mismatch":
        report["sevenzip"]["declared_total_size"] += 1
    elif mutation == "hint_index_mismatch":
        report["artifact_name_hints"]["items"][0]["artifact_index"] = 9
    elif mutation == "hint_hash_mismatch":
        report["artifact_name_hints"]["items"][0]["sha256"] = "0" * 64
    elif mutation == "path_traversal":
        inventory = report["sevenzip"]["inventory"]
        target = next(item for item in inventory if item["name"] == "alternate/loader2.dll")
        report["sevenzip"]["members"].remove("alternate/loader2.dll")
        target["name"] = "../note.txt"
        report["sevenzip"]["members"].append("../note.txt")
    elif mutation == "path_ads":
        inventory = report["sevenzip"]["inventory"]
        target = next(item for item in inventory if item["name"] == "alternate/loader2.dll")
        report["sevenzip"]["members"].remove("alternate/loader2.dll")
        target["name"] = "docs/note.txt:stream"
        report["sevenzip"]["members"].append("docs/note.txt:stream")
    elif mutation == "nfkc_casefold_path_collision":
        inventory = report["sevenzip"]["inventory"]
        target = next(item for item in inventory if item["name"] == "alternate/loader2.dll")
        report["sevenzip"]["members"].remove("alternate/loader2.dll")
        target["name"] = "bundle/ＨＯＳＴ.exe"
        report["sevenzip"]["members"].append("bundle/ＨＯＳＴ.exe")
    elif mutation == "duplicate_alias_size_mismatch":
        inventory = report["sevenzip"]["inventory"]
        target = next(item for item in inventory if item["name"] == "bundle/host-copy.exe")
        target["size"] += 1
        report["sevenzip"]["declared_total_size"] += 1
        report["sevenzip"]["extracted_total_size"] += 1
    elif mutation == "omitted_second_chain_member":
        # full inventory/hint/retentionがcompleteを主張したまま、第2 chainの
        # unique bytesだけがmaterializeされないpartial resultを再現する。
        artifacts.pop()
    elif mutation == "extra_artifact":
        artifacts.append(("7z-data", b"unreferenced"))
    monkeypatch.setattr(
        adapter,
        "recover_verified_sibling_shellcode",
        (
            (lambda **_kwargs: None)
            if mutation == "strict_proof_missing"
            else (lambda **kwargs: _strict_stub(kwargs["members"]))
        ),
    )

    assert (
        adapter.recover_verified_sibling_bundle_layer(
            parent_data=parent,
            parent_sha256=_sha256(parent),
            report=report,
            artifacts=artifacts,
        )
        is None
    )
