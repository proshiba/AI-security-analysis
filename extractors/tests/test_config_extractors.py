"""Unit tests for every function in the unified config extractor package."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from extractors import common
from extractors.agenttesla.extractor import (
    extract as agent_extract,
    protocol_for,
    sanitize_url,
)
from extractors.config_extractor import (
    build_parser,
    extract_file,
    get_extractor,
    main,
    normalize_family,
)
from extractors.remcosrat.extractor import extract as remcos_extract, marker_score
from extractors.unclassified.mx_go.extractor import (
    embedded_config,
    extract as mx_extract,
    public_config,
)
from extractors.valleyrat.extractor import (
    decode_vvas_reversed_config,
    extract as valley_extract,
    identify_variant,
)
from extractors.venomrat import integrated as venom_integrated
from extractors.venomrat.extractor import (
    extract as venom_extract,
    family_markers,
    structural_evidence,
)


def test_common_functions() -> None:
    data = b"abc.example:443 http://site.example/a\x00w\x00i\x00d\x00e\x00\x00"
    assert len(common.sha256_bytes(data)) == 64
    strings = common.extract_strings(data)
    assert any(value.endswith("wide") for value in strings)
    assert common.valid_host("1.2.3.4") and not common.valid_host("999.2.3.4")
    assert common.endpoint_candidates(strings) == ["abc.example:443"]
    assert common.ipv4_candidates(["x 1.2.3.4 y", "999.2.3.4"]) == ["1.2.3.4"]
    assert common.url_candidates(strings) == ["http://site.example/a"]
    result = common.build_result("test", data, {}, [], [])
    assert result["executed"] is False and result["credentials_published"] is False


def test_valleyrat_functions() -> None:
    assert (
        identify_variant(["vvaS.bin", "LoggerCollector.dll"])
        == "dll_sideload_vvas_bundle"
    )
    assert identify_variant(["/config.enc", "N520"]) == "single_pe_n520_managed"
    assert identify_variant(["SilverFox"]) == "silverfox_related"
    assert identify_variant([]) == "unresolved_variant"
    assert decode_vvas_reversed_config(
        ["|8888:2o|72.8.59.202:2p|6666:1o|72.8.59.202:1p|"]
    ) == {
        "endpoint_1": "202.95.8.27:6666",
        "endpoint_2": "202.95.8.27:8888",
    }
    result = valley_extract(b"LoggerCollector.dll vvaS.bin 1.2.3.4:6666", "x")
    assert result["config"]["endpoints"] == ["1.2.3.4:6666"]
    duplicate = valley_extract(
        b"|3441:3o|04.11.34.301:3p|3441:2o|04.11.34.301:2p|3441:1o|04.11.34.301:1p|",
        "x",
    )
    assert duplicate["config"]["endpoints"] == ["103.43.11.40:1443"]
    assert duplicate["config"]["static_config_recovered"] is True
    assert duplicate["config"]["c2_liveness_confirmed"] is False
    assert duplicate["findings"][0]["confidence"] == "confirmed_static_config"
    invalid = valley_extract(
        b"|99999:1o|999.43.11.40:1p|",
        "x",
    )
    assert invalid["config"]["endpoints"] == []
    filtered = valley_extract(
        b"vvaS.bin LoggerCollector.dll http://ocsp.digicert.com0A "
        b"https://evil.example/stage.zip",
        "x",
    )
    unresolved = valley_extract(b"0.skz:7 https://jrsoftware.org/ishelp/index.php", "x")
    assert unresolved["config"]["endpoints"] == []
    assert unresolved["config"]["urls"] == []
    assert filtered["config"]["urls"] == ["https://evil.example/stage.zip"]


def test_agenttesla_functions() -> None:
    sanitized, secret = sanitize_url("ftp://user:pass@ftp.example/a?q=1")
    assert sanitized == "ftp://ftp.example/a" and secret
    assert protocol_for("ftp://ftp.example/a") == "FTP"
    assert protocol_for("https://api.telegram.org/bot") == "Telegram"
    assert protocol_for("https://discord.com/api/webhooks/x") == "Discord"
    assert protocol_for("mail.example:587") == "SMTP"
    assert protocol_for("other.example:80") == "unknown"
    result = agent_extract(b"ftp://user:pass@ftp.example/a")
    assert result["credentials_published"] is False


def test_remcos_functions() -> None:
    assert marker_score(["Remcos Agent", "RMC-1"])[0] == 3
    result = remcos_extract(b"Remcos Agent c2.example:2404")
    assert result["findings"][0]["confidence"] == "inferred"


def test_venom_functions() -> None:
    assert family_markers(["Quasar.Client", "RECONNECTDELAY"]) == [
        "quasar.client",
        "reconnectdelay",
    ]
    result = venom_extract(b"Quasar.Client RECONNECTDELAY c2.example:4444")
    assert result["config"]["recovery_status"] == "not_attempted_structural_mismatch"
    assert result["findings"] == []
    weak = venom_extract(b"mutex xmp.did:4307 http://ns.adobe.com/xap/1.0/")
    assert weak["config"]["endpoints"] == []
    assert weak["config"]["dynamic_config_url"] is None
    assert weak["findings"] == []


def _venom_structural_fixture() -> bytes:
    fields = sorted(
        {
            "Key",
            "Por_ts",
            "Hos_ts",
            "Ver_sion",
            "In_stall",
            "Paste_bin",
            "An_ti",
            "Group",
            "Certifi_cate",
            "Pac_ket",
            "Po_ng",
        }
    )
    return b"MZ" + b"\x00" * 64 + b"BSJB\x00" + "\x00".join(fields).encode()


def test_venom_requires_strong_managed_structure_before_recovery(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = 0

    def should_not_run(_data: bytes) -> dict:
        nonlocal calls
        calls += 1
        raise AssertionError("構造不一致で復元器を呼んではならない")

    monkeypatch.setattr(venom_integrated, "_validated_recovery", should_not_run)
    result = venom_extract(
        b"MZ BSJB Key Por_ts Hos_ts Paste_bin Certifi_cate c2.example:4444"
    )
    assert calls == 0
    assert result["config"]["static_config_recovered"] is False
    assert result["findings"] == []


def test_venom_integrates_only_validated_config(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _venom_structural_fixture()
    assert structural_evidence(fixture)["matched"] is True
    monkeypatch.setattr(
        venom_integrated,
        "_validated_recovery",
        lambda _data: {
            "version": "Venom RAT v6.0.3",
            "install": "true",
            "group": "start",
            "anti_analysis": "false",
            "endpoints": [{"host": "c2.example.test", "port": 2794}],
            "dynamic_config_url": "https://pastebin.com/raw/example",
            "certificate": {
                "sha256": "a" * 64,
                "size": 573,
                "certificate_mismatch_excludes_c2": False,
            },
        },
    )
    result = venom_extract(fixture)
    assert result["config"]["static_config_recovered"] is True
    assert result["config"]["version"] == "Venom RAT v6.0.3"
    assert result["config"]["endpoints"] == [
        {"host": "c2.example.test", "port": 2794}
    ]
    assert {item["role"] for item in result["findings"]} == {
        "configured_c2",
        "dynamic_config_resolver",
        "tls_certificate_pin",
    }
    assert all(
        item["confidence"] == "confirmed_static_config"
        for item in result["findings"]
    )


def test_venom_fail_closed_when_authenticated_recovery_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _venom_structural_fixture() + b" c2.example.test:2794"

    def reject(_data: bytes) -> dict:
        raise ValueError("HMAC mismatch")

    monkeypatch.setattr(venom_integrated, "_validated_recovery", reject)
    result = venom_extract(fixture)
    assert result["config"]["recovery_status"] == "rejected_or_not_recovered"
    assert result["config"]["endpoints"] == []
    assert result["findings"] == []


def test_mx_go_functions() -> None:
    assert normalize_family("spygrace") == "spyglace"
    data = (
        b'prefix {"control_server":"http://127.0.0.1:5000","api_token":"secret"} suffix'
    )
    config, offset = embedded_config(data)
    assert config["control_server"].endswith(":5000") and offset is not None
    assert public_config(config) == {"control_server": "http://127.0.0.1:5000"}
    assert embedded_config(b"none") == ({}, None)
    result = mx_extract(data)
    assert result["findings"][0]["confidence"] == "confirmed"


def test_dispatcher_functions(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert normalize_family(" Remcos ") == "remcosrat"
    assert callable(get_extractor("venom"))
    with pytest.raises(ValueError, match="unsupported"):
        get_extractor("missing")
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"Remcos Agent c2.example:2404")
    assert extract_file("remcos", sample)["family"] == "remcosrat"
    assert (
        build_parser()
        .parse_args(
            [
                "--family",
                "remcos",
                "--input",
                str(sample),
                "--output",
                str(tmp_path / "o.json"),
            ]
        )
        .family
        == "remcos"
    )
    output = tmp_path / "result.json"
    assert (
        main(["--family", "remcos", "--input", str(sample), "--output", str(output)])
        == 0
    )
    assert json.loads(output.read_text())["family"] == "remcosrat"
    assert "result.json" in capsys.readouterr().out
