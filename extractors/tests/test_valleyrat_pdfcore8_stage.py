import extractors.valleyrat.extractor as valley_extractor
from extractors.valleyrat.extractor import extract, identify_variant


def test_identifies_recovered_pdfcore8_winos_stage() -> None:
    strings = [
        "IpDatespecial",
        "SeDebugPrivilege",
        "192.168.1.200",
        "REMARK",
        "GROUP",
    ]
    assert identify_variant(strings) == "pdfcore8_winos_recovered_stage"


def test_private_default_slots_are_not_published_as_c2() -> None:
    data = (
        b"IpDatespecial\x00SeDebugPrivilege\x00192.168.1.200:6669\x00"
        b"192.168.1.200:9999\x00REMARK\x00GROUP\x00"
    )
    result = extract(data, "recovered-stage.bin")
    assert result["config"]["variant"] == "pdfcore8_winos_recovered_stage"
    assert result["config"]["endpoints"] == []
    assert result["config"]["placeholder_defaults_excluded"] == [
        "192.168.1.200:6669",
        "192.168.1.200:9999",
    ]
    assert not [
        item for item in result["findings"] if item["kind"].startswith("network.")
    ]


def test_reviewed_rotated_pdfcore8_returns_structural_evidence_without_endpoint(monkeypatch) -> None:
    digest = "8136a9b1252e0d8c293c6c99444b371f3f7dc9fccbf351597a0aec029fe92a96"
    monkeypatch.setattr(valley_extractor, "sha256_bytes", lambda _data: digest)

    result = valley_extractor.extract(b"synthetic reviewed bytes", "pdfCORE8.dlL")

    assert result["config"]["variant"] == "pdfcore8_rotated_resource_proxy_component_20260813"
    assert result["config"]["reviewed_hash"] is True
    assert result["config"]["matched_patterns"] == [
        "reviewed_exact_sha256",
        "pdfcore8_rotated_resource_lineage",
    ]
    assert result["config"]["terminal_family_attribution"] == (
        "pdfcore8_winos_lineage_correlated_terminal_unrecovered"
    )
    assert result["config"]["static_config_recovered"] is False
    assert result["config"]["final_rat_confirmed"] is False
    assert result["config"]["endpoints"] == []
    assert result["findings"] == []
    assert result["executed"] is False
    assert result["network_contacted"] is False
