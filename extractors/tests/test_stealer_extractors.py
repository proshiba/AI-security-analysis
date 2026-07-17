"""Unit tests for new stealer configuration extractors."""

from __future__ import annotations

from extractors.amosstealer import extract as extract_amos
from extractors.config_extractor import get_extractor, normalize_family
from extractors.formbook import extract as extract_formbook
from extractors.lummastealer import extract as extract_lumma
from extractors.remusstealer import extract as extract_remus
from extractors.stealer_common import (
    campaign_shape,
    clean_url,
    extract_stealer,
    feature_hits,
    infrastructure_urls,
    url_role,
)
from extractors.vidar import extract as extract_vidar


def test_stealer_common_functions() -> None:
    """Cover URL filtering, roles, campaign shapes, features, and result construction."""
    assert clean_url("https://evil.example/api/x)") == "https://evil.example/api/x"
    assert clean_url("http://www.apple.com/x") is None
    assert clean_url("http://ocsp.digicert.com0X") is None
    assert clean_url("https://api.ipify.orghttps://noise") is None
    assert clean_url("http://ccsca2021.ocsp-certum.com05") is None
    assert infrastructure_urls(["https://evil.example/a", "https://go.dev/x"]) == [
        "https://evil.example/a"
    ]
    assert url_role("https://evil.example/ledger/x") == "c2_or_exfil_candidate"
    assert url_role("https://evil.example/payload.exe") == "payload_or_dependency_url"
    assert campaign_shape("x.vbs", b"text") == "vbs_script_delivery"
    assert campaign_shape("x.sh", b"text") == "sh_script_delivery"
    assert clean_url("https://1.1.1.1/dns-query?name=x") is None
    assert feature_hits(["LOGIN DATA"], {"browser": ("Login Data",)})["browser"]
    result = extract_stealer(
        "fixture",
        b"Marker https://evil.example/api/x",
        "x.bin",
        ("Marker",),
        {"test": ("Marker",)},
        ["fixture"],
    )
    assert result["findings"][0]["role"] == "c2_or_exfil_candidate"
    assert not result["config"]["static_config_recovered"]
    assert result["config"]["candidate_infrastructure_recovered"]


def test_family_extractors_and_dispatcher() -> None:
    """Exercise each family wrapper and accepted aliases."""
    fixtures = {
        "formbook": (extract_formbook, b"FormBook Login Data"),
        "vidar": (extract_vidar, b"Vidar information.txt wallet.dat"),
        "lummastealer": (extract_lumma, b"LummaC2 build_id /api/"),
        "remusstealer": (extract_remus, b"RemusStealer Login Data"),
        "amosstealer": (
            extract_amos,
            b"Atomic keychain https://evil.example/ledger/id",
        ),
    }
    for family, (extractor, data) in fixtures.items():
        assert extractor(data, "sample.bin")["family"] == family
        assert get_extractor(family)(data, "sample.bin")["family"] == family
    assert normalize_family("AMOS") == "amosstealer"
    assert normalize_family("lumma") == "lummastealer"
    assert normalize_family("remus") == "remusstealer"
