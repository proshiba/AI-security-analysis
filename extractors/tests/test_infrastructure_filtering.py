"""Tests for shared infrastructure-reference filtering."""

from extractors.stealer_common import clean_url, infrastructure_urls


def test_certificate_and_vendor_references_are_filtered() -> None:
    """Exclude certificate distribution and known vendor documentation hosts."""
    values = [
        "http://crl.globalsign.net/root-r3.crl0",
        "http://ocsp.sectigo.com0",
        "https://jira.adguard.com/browse/AG-15916",
        "https://www.autoitscript.com/autoit3/",
        "http://evcs-aia.ws.symantec.com/evcs.cer0",
        "https://www.verisign.com/cps0",
        "https://jrsoftware.org/ishelp/index.php?topic=setupcmdline",
        "http://schemas.xmlsoap.org/soap/envelope/",
    ]
    assert infrastructure_urls(values) == []


def test_unknown_infrastructure_and_dead_drops_remain() -> None:
    """Retain non-reference IP, Telegram, and Steam infrastructure candidates."""
    assert clean_url("http://157.90.113.100:80") == "http://157.90.113.100:80"
    values = infrastructure_urls(
        [
            "https://t.me/dionysus_tg",
            "https://steamcommunity.com/profiles/76561199482248283",
        ]
    )
    assert values == [
        "https://steamcommunity.com/profiles/76561199482248283",
        "https://t.me/dionysus_tg",
    ]


def test_runtime_documentation_and_embedded_browser_references_are_filtered() -> None:
    """実検体で観測した.NET文書とブラウザー部品の参照先を除外する。"""
    values = [
        "https://aka.ms/GlobalizationInvariantMode",
        "http://chromium.org",
        "http://download.divx.com/divx/autoupdate/player/DivXWebPlayerInstaller.exe",
        "http://xmlsoft.org/XSLT/",
        "https://maps.googleapis.com/maps/api/browserlocation/json",
        "https://www.google.com/speech-api/v1/recognize?client=chromium",
    ]
    assert infrastructure_urls(values) == []
