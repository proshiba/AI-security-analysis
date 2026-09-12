"""ZIP side-load終端とraw vvaS候補のdetector境界を検証する。"""

from __future__ import annotations

import importlib.util
import io
import sys
import zipfile
from pathlib import Path
from types import SimpleNamespace

import pytest

MODULE_PATH = Path(__file__).resolve().parents[1] / "malware" / "valleyrat" / "detect.py"


def _load_detector():
    spec = importlib.util.spec_from_file_location("valleyrat_zip_lineage_detect", MODULE_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _zip_fixture() -> bytes:
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        archive.writestr("host.exe", b"MZ-host")
        archive.writestr("proxy.dll", b"MZ-proxy")
        archive.writestr("carrier.dat", b"carrier")
    return stream.getvalue()


def _terminal_probe() -> dict[str, object]:
    return {
        "matched": True,
        "family": "valleyrat",
        "variant": "zip_sideload_shellcode_vvas_terminal",
        "supports_family_attribution": True,
        "terminal_family_confirmed": True,
        "attribution_scope": "validated_terminal_component_structure",
        "static_config_recovered": True,
        "evidence": {
            "source_transform_sink_lineage": True,
            "raw_network_values_included": False,
        },
        "config": {
            "endpoint_count": 1,
            "raw_network_values_included": False,
        },
    }


def test_zip_terminal_campaign_supports_family_without_raw_values(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    detector = _load_detector()
    members = [
        SimpleNamespace(name="host.exe", data=b"MZ-host"),
        SimpleNamespace(name="proxy.dll", data=b"MZ-proxy"),
        SimpleNamespace(name="carrier.dat", data=b"carrier"),
    ]
    monkeypatch.setattr(detector, "read_aes_zip_members", lambda *_args, **_kwargs: members)
    monkeypatch.setattr(detector, "probe_zip_sideload_shellcode", lambda _data: _terminal_probe())

    observations, campaigns = detector.inspect_zip(_zip_fixture())

    assert campaigns == [
        {
            "campaign_type": "zip_sideload_shellcode_vvas_terminal",
            "confidence": "high",
            "reasons": campaigns[0]["reasons"],
            "attribution_scope": "validated_terminal_component_structure",
            "supports_family_attribution": True,
            "terminal_family_confirmed": True,
        }
    ]
    assert observations["zip_sideload_shellcode_terminal"]["config"] == {
        "endpoint_count": 1,
        "raw_network_values_included": False,
    }


def test_raw_shellcode_detector_remains_route_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    detector = _load_detector()
    raw = b"raw-vvas-transport-fixture"
    monkeypatch.setattr(detector, "_terminal_configuration_detection", lambda *_args: None)
    monkeypatch.setattr(
        detector,
        "probe_raw_vvas_shellcode",
        lambda _data: {
            "matched": True,
            "supports_family_attribution": False,
            "terminal_family_confirmed": False,
            "evidence": {"raw_network_values_included": False},
            "config": {"endpoint_count": 1, "raw_network_values_included": False},
        },
    )

    result = detector.detect(raw, Path("anonymous.bin"))

    assert result["matched"] is True
    assert result["supports_family_attribution"] is False
    campaign = result["campaigns"][0]
    assert campaign["campaign_type"] == "raw_vvas_codemark_transport_candidate"
    assert campaign["terminal_family_confirmed"] is False
    assert campaign["supports_family_attribution"] is False
