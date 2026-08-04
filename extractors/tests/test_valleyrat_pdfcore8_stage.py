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
