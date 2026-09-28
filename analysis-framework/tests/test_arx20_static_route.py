"""ARX20包装を通常layerへ渡す接続と証拠境界を無害fixtureで検証する。"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import capstone
import pytest

REPOSITORY = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPOSITORY))

from unpackers import arx20_chunk_unpacker as arx
from unpackers import arx20_static_route as route
from unpackers.static_unpacker import unpack_bytes


@pytest.fixture
def harmless_source(monkeypatch):
    path = Path(__file__).with_name("test_arx20_chunk_unpacker.py")
    spec = importlib.util.spec_from_file_location("arx_harmless_fixture", path)
    fixture = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fixture)
    machine = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    machine.detail = True
    instructions = list(machine.disasm(fixture._state_decoder(), 0x1600))
    shape = arx._shape_hash(instructions, 0x180, 0x1600)
    monkeypatch.setattr(arx, "VERIFIED_COMPILER_SHAPES", frozenset({shape}))
    return fixture._fixture()


def test_route_preserves_bytes_and_does_not_confirm_family(harmless_source):
    source, child = harmless_source
    report, artifacts = route.recover_arx20_static_route(source)
    assert artifacts == [("arx20-chunks-decoded-pe", child)]
    assert report["status"] == "recovered"
    assert report["candidate_set_complete"] is True
    assert report["family_attribution_allowed"] is False
    assert report["c2_confirmation_allowed"] is False
    assert report["terminal_promotion_eligible"] is False
    assert report["sample_executed"] is False


def test_normal_static_unpacker_collects_arx_child(harmless_source):
    source, child = harmless_source
    report, artifacts = unpack_bytes(source, name="harmless.bin")
    assert report["arx20_chunk_reassembly"]["status"] == "recovered"
    assert ("arx20-chunks-decoded-pe", child) in artifacts


def test_limit_rejection_is_visible_without_partial_payload(monkeypatch):
    def exceed(_):
        raise arx.Arx20ChunkLimitError("cipher_work_bytes", 1025, 1024)

    monkeypatch.setattr(route, "recover_arx20_chunk_payloads", exceed)
    report, artifacts = route.recover_arx20_static_route(b"MZ")
    assert artifacts == []
    assert report["status"] == "limit_exceeded"
    assert report["constraint"] == "cipher_work_bytes"
    assert report["partial_results_returned"] is False


@pytest.mark.parametrize("data", [b"", b"ordinary text", b"MZinvalid"])
def test_non_candidate_has_no_artifact(data):
    report, artifacts = route.recover_arx20_static_route(data)
    assert artifacts == []
    assert report["status"] in {"not_candidate", "structure_rejected"}


def test_input_limit_is_not_silently_truncated(monkeypatch):
    monkeypatch.setattr(route, "MAX_INPUT_BYTES", 2)
    report, artifacts = route.recover_arx20_static_route(b"MZoversize")
    assert report["status"] == "input_limit_exceeded"
    assert artifacts == []
