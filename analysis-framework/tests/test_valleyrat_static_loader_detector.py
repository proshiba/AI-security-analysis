"""ValleyRATのhash非依存loader profileと候補config routeを検証する。"""

from __future__ import annotations

import hashlib
import importlib.util
import sys
from pathlib import Path

import pytest

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
FRAMEWORK_ROOT = REPOSITORY_ROOT / "analysis-framework"
COMMON = FRAMEWORK_ROOT / "common"
for import_root in (REPOSITORY_ROOT, FRAMEWORK_ROOT, COMMON):
    if str(import_root) not in sys.path:
        sys.path.insert(0, str(import_root))


def _load_detector():
    path = FRAMEWORK_ROOT / "malware" / "valleyrat" / "detect.py"
    spec = importlib.util.spec_from_file_location("valleyrat_static_loader_detect", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


DETECTOR = _load_detector()


def _profile_view(profile: str) -> dict:
    """profile matcherへ渡す、header結合済みcomponent viewを作る。"""

    header = {
        "machine": 0x8664,
        "is_dll": False,
        "subsystem": 2,
        "security_size": 0,
        "clr_size": 0,
        "overlay_size": 0,
        "resource_pairs": set(),
        "resource_top_ids": set(),
        "resource_leaf_count": 0,
    }
    sections = DETECTOR.PE_LOADER_PROFILE_SECTION_SEQUENCES.get(
        profile,
        (".text", ".rdata", ".data", ".pdata", ".rsrc", ".reloc"),
    )
    size = 400 * 1024
    export_count = 0
    export_sample: list[str] = []
    component = {"sha256": "a" * 64, "machine": "0x8664"}
    section_by_name = {
        name: {"name": name, "raw_size": 512, "virtual_size": 4, "entropy": 0.02}
        for name in sections
    }

    if profile == "bin_hell_resource_dropper":
        header.update(
            resource_pairs={"BIN/HELL1", "BIN/HELL2", "#3/#1", "#14/IDI_ICON1"},
            resource_leaf_count=4,
        )
    elif profile == "run_dll_native_core":
        header.update(machine=0x14C, is_dll=True)
        component.update(machine="0x14c")
        export_count, export_sample = 1, ["run"]
    elif profile == "compact_cef_wininet_loader":
        header.update(machine=0x14C, is_dll=True, security_size=11_416, overlay_size=11_416)
        component.update(machine="0x14c", proxy_type="cef_proxy")
        size = 125_080
        export_count = 76
        export_sample = [f"cef_export_{index:02d}" for index in range(32)]
    elif profile == "ares_service_facade_loader":
        header.update(
            is_dll=True,
            resource_top_ids={16, 24},
            resource_leaf_count=2,
        )
        size = 1_507_840
        export_count = 308
        export_sample = [f"ares_export_{index:02d}" for index in range(32)]
        component.update(export_target_count=1, export_target_peak_ratio=1.0)
    elif profile == "mingw_resource_stage_dropper":
        header.update(
            machine=0x14C,
            overlay_size=190_000,
            resource_pairs={
                "BIN/IDR_HELPER",
                "BIN/IDR_HELPER_DAT",
                "BIN/IDR_MAIN",
            },
            resource_leaf_count=3,
        )
        component.update(machine="0x14c")
        size = 2 * 1024 * 1024
    elif profile == "d3d11_system_probe_loader":
        sections = (".text", ".rdata", ".data", ".pdata", ".rsrc", ".reloc")
        section_by_name = {
            name: {"name": name, "raw_size": 512, "virtual_size": 512, "entropy": 5.0}
            for name in sections
        }
        size = 900_000
    elif profile == "d3dserver_debug_attribute_loader":
        header.update(security_size=8_000)
    elif profile == "d3d11_eventlog_context_loader":
        sections = (
            ".text",
            ".data",
            ".rdata",
            ".pdata",
            ".xdata",
            ".bss",
            ".idata",
            ".CRT",
            ".tls",
            ".rsrc",
            ".reloc",
        )
        section_by_name = {
            name: {"name": name, "raw_size": 512, "virtual_size": 512, "entropy": 5.0}
            for name in sections
        }
    elif profile == "symtab_thread_context_loader":
        size = 2 * 1024 * 1024

    header["section_names"] = sections
    return {
        "component": component,
        "size": size,
        "libraries": set(DETECTOR.PE_LOADER_PROFILE_LIBRARIES[profile]),
        "apis": set(DETECTOR.PE_LOADER_PROFILE_APIS[profile]),
        "sections": sections,
        "section_by_name": section_by_name,
        "export_count": export_count,
        "export_sample": export_sample,
        "header": header,
    }


@pytest.mark.parametrize(
    "profile",
    (
        "bin_hell_resource_dropper",
        "run_dll_native_core",
        "compact_cef_wininet_loader",
        "ares_service_facade_loader",
        "mingw_resource_stage_dropper",
        "d3d11_system_probe_loader",
        "d3dserver_debug_attribute_loader",
        "d3d11_eventlog_context_loader",
        "symtab_thread_context_loader",
    ),
)
def test_known_loader_profiles_route_without_hash_or_family_attribution(
    monkeypatch: pytest.MonkeyPatch,
    profile: str,
) -> None:
    """A-Jの9構造profileをexact hashなしで識別する。"""

    view = _profile_view(profile)
    monkeypatch.setattr(DETECTOR, "_static_component_view", lambda *_args: view)
    data = (
        b"MZ fixture \\x64\\Release\\D3dServer.pdb"
        if profile == "d3dserver_debug_attribute_loader"
        else b"MZ fixture"
    )

    result = DETECTOR._static_loader_profile_observation({}, data)

    assert result is not None
    assert result["profile"] == profile
    assert result["raw_payload_included"] is False
    assert result["executed"] is False
    assert result["network_contacted"] is False


@pytest.mark.parametrize(
    "mutation",
    (
        lambda view: view["header"].update(clr_size=72),
        lambda view: view["libraries"].add("unexpected"),
        lambda view: view["apis"].discard("CreateProcessW"),
        lambda view: view.update(sections=(".text", ".data")),
        lambda view: view.update(export_count=1),
        lambda view: view["header"].update(resource_leaf_count=3),
    ),
    ids=("clr", "library", "api", "sections", "exports", "resources"),
)
def test_static_loader_profile_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
    mutation,
) -> None:
    view = _profile_view("bin_hell_resource_dropper")
    mutation(view)
    monkeypatch.setattr(DETECTOR, "_static_component_view", lambda *_args: view)

    assert DETECTOR._static_loader_profile_observation({}, b"MZ fixture") is None


def _outer_candidate_view() -> dict:
    return {
        "component": {"sha256": "b" * 64, "machine": "0x14c"},
        "size": 532_480,
        "libraries": {"mscoree"},
        "apis": {"_CorExeMain"},
        "sections": (".text", ".rsrc", ".reloc"),
        "section_by_name": {},
        "export_count": 0,
        "export_sample": [],
        "header": {
            "machine": 0x14C,
            "is_dll": False,
            "subsystem": 2,
            "security_size": 0,
            "clr_size": 72,
            "overlay_size": 0,
            "resource_pairs": set(),
            "resource_top_ids": {14},
            "resource_leaf_count": 1,
        },
    }


def _child_candidate_view(child_sha256: str) -> dict:
    return {
        "component": {"sha256": child_sha256, "machine": "0x14c"},
        "size": 143_872,
        "libraries": {"bcrypt", "kernel32", "shell32", "shlwapi", "user32", "winmm", "ws2_32"},
        "apis": {
            "GetThreadContext",
            "SetThreadContext",
            "VirtualAllocEx",
            "WriteProcessMemory",
            "WSAStartup",
            "connect",
            "recv",
            "send",
            "socket",
        },
        "sections": (".text", ".rdata", ".data", ".rsrc", ".reloc"),
        "section_by_name": {},
        "export_count": 1,
        "export_sample": ["Fuck"],
        "header": {
            "machine": 0x14C,
            "is_dll": False,
            "subsystem": 2,
            "security_size": 0,
            "clr_size": 0,
            "overlay_size": 0,
            "resource_pairs": {"#24/#1"},
            "resource_top_ids": {24},
            "resource_leaf_count": 1,
        },
    }


def _candidate_extractor_result(data: bytes) -> dict:
    endpoints = ["hidden.example:443", "198.51.100.7:8856"]
    return {
        "family": "valleyrat",
        "sample_sha256": hashlib.sha256(data).hexdigest(),
        "executed": False,
        "network_contacted": False,
        "config": {
            "variant": "vvas_reversed_config_pe_candidate",
            "static_config_recovered": False,
            "decoded_config_recovered": False,
            "candidate_config_recovered": True,
            "terminal_family_confirmed": False,
            "attribution_scope": "component_handler_route",
            "c2_liveness_confirmed": False,
            "decoded_vvas": {"endpoint_1": endpoints[0], "endpoint_2": endpoints[1]},
            "decoded_vvas_slots": [
                {"slot": 1, "transport": "tcp", "endpoint": endpoints[0]},
                {"slot": 2, "transport": "tcp", "endpoint": endpoints[1]},
            ],
            "endpoints": sorted(endpoints),
            "vvas_recovery": {
                "status": "decoded_unique",
                "candidate_count": 1,
                "unique_configuration_count": 1,
                "configured_slot_count": 2,
                "tcp_transport_slot_count": 2,
                "udp_transport_slot_count": 0,
                "configuration_identity_sha256": "c" * 64,
                "format_corroboration": {"matched": False},
            },
        },
    }


def test_nested_vvas_candidate_is_strict_and_redacted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """K nested binderはcandidate configだけを秘匿要約してrouteする。"""

    data = b"MZ BSJB Bound Open files.resources fixture"
    child = b"MZ" + bytes(143_870)
    outer_view = _outer_candidate_view()
    child_view = _child_candidate_view(hashlib.sha256(child).hexdigest())
    monkeypatch.setattr(
        DETECTOR,
        "_static_component_view",
        lambda _analysis, blob: outer_view if blob == data else child_view,
    )
    monkeypatch.setattr(
        DETECTOR,
        "resource_blobs",
        lambda _data: (
            [
                {
                    "container_name": "files.resources",
                    "resource_type": "System.ByteArray",
                    "value_encoding": "binary",
                    "data": child,
                },
                {
                    "container_name": "files.resources",
                    "resource_type": "System.ByteArray",
                    "value_encoding": "binary",
                    "data": b"\xff\xd8\xff" + bytes(100_835),
                },
            ],
            [],
        ),
    )
    monkeypatch.setattr(DETECTOR, "analyze_signed_proxy_sideload", lambda *_args: {})
    monkeypatch.setattr(
        DETECTOR,
        "extract_valleyrat_config",
        lambda blob, _name: _candidate_extractor_result(blob),
    )

    result = DETECTOR._vvas_pe_candidate_observation(data, {})

    assert result is not None
    assert result["candidate_endpoint_count"] == 2
    assert result["tcp_slot_count"] == 2
    assert result["raw_endpoints_included"] is False
    serialized = repr(result)
    assert "hidden.example" not in serialized
    assert "198.51.100.7" not in serialized


def test_nested_vvas_candidate_rejects_incomplete_child_network_cluster(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    data = b"MZ BSJB Bound Open files.resources fixture"
    child = b"MZ" + bytes(143_870)
    outer_view = _outer_candidate_view()
    child_view = _child_candidate_view(hashlib.sha256(child).hexdigest())
    child_view["apis"].remove("socket")
    monkeypatch.setattr(
        DETECTOR,
        "_static_component_view",
        lambda _analysis, blob: outer_view if blob == data else child_view,
    )
    monkeypatch.setattr(
        DETECTOR,
        "resource_blobs",
        lambda _data: (
            [
                {
                    "container_name": "files.resources",
                    "resource_type": "System.ByteArray",
                    "value_encoding": "binary",
                    "data": child,
                },
                {
                    "container_name": "files.resources",
                    "resource_type": "System.ByteArray",
                    "value_encoding": "binary",
                    "data": b"\xff\xd8\xff" + bytes(100_835),
                },
            ],
            [],
        ),
    )
    monkeypatch.setattr(DETECTOR, "analyze_signed_proxy_sideload", lambda *_args: {})

    assert DETECTOR._vvas_pe_candidate_observation(data, {}) is None


def test_static_loader_detector_result_stays_route_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    data = b"MZ static profile integration fixture"
    observation = {
        "status": "validated_static_loader_component",
        "profile": "run_dll_native_core",
        "raw_payload_included": False,
        "executed": False,
        "network_contacted": False,
    }
    monkeypatch.setattr(DETECTOR, "_terminal_configuration_detection", lambda *_args: None)
    monkeypatch.setattr(
        DETECTOR,
        "_appdomainmanager_loader_shape",
        lambda *_args: {"matched": False},
    )
    monkeypatch.setattr(DETECTOR, "analyze_signed_proxy_sideload", lambda *_args: {})
    monkeypatch.setattr(DETECTOR, "_static_loader_profile_observation", lambda *_args: observation)

    result = DETECTOR.detect(data, Path("unknown.dll"))

    assert result["matched"] is True
    assert result["supports_family_attribution"] is False
    campaign = result["campaigns"][0]
    assert campaign["campaign_type"] == "static_pe_loader_component"
    assert campaign["attribution_scope"] == "component_handler_route"
    assert campaign["supports_family_attribution"] is False
    assert campaign["terminal_family_confirmed"] is False
