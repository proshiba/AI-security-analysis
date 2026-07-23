"""ACRStealer上限付き静的復元器のテスト。"""

from __future__ import annotations

import io
import struct
import zipfile

from extractors.acrstealer import extractor


def _minimal_cab() -> bytes:
    value = bytearray(36)
    value[:4] = b"MSCF"
    struct.pack_into("<I", value, 8, len(value))
    return bytes(value)


def test_cab_carve_requires_contained_declared_size() -> None:
    cab = _minimal_cab()
    recovered, report = extractor._cab_from_prefix(b"padding" + cab)
    assert recovered == cab
    assert report["status"] == "recovered"
    broken = bytearray(cab)
    struct.pack_into("<I", broken, 8, 4096)
    assert extractor._cab_from_prefix(bytes(broken))[0] is None


def test_pumped_zip_reads_bounded_prefix_and_carves_cab(monkeypatch) -> None:
    monkeypatch.setattr(extractor, "PUMPED_SIZE_THRESHOLD", 128)
    monkeypatch.setattr(extractor, "PUMPED_RATIO_THRESHOLD", 2.0)
    member = b"not-a-pe" + _minimal_cab() + bytes(4096)
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("setup.exe", member)
    artifacts, observations = extractor.recover_artifacts(output.getvalue())
    assert len(artifacts) == 1
    assert artifacts[0].kind == "pumped-pe-cab"
    assert artifacts[0].data == _minimal_cab()
    assert observations[0]["status"] == "carved_cab"


def test_reviewed_related_payload_is_not_promoted_to_static_config() -> None:
    result = extractor.extract(b"MZ" + bytes(64), "fixture.exe")
    assert result["config"]["static_config_recovered"] is False
    assert result["executed"] is False
    assert result["network_contacted"] is False
