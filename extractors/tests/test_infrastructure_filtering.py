"""Tests for shared infrastructure-reference filtering."""

from extractors.stealer_common import clean_url, infrastructure_urls


def test_certificate_and_vendor_references_are_filtered() -> None:
    """Exclude certificate distribution and known vendor documentation hosts."""
    values = [
        "http://crl.globalsign.net/root-r3.crl0",
        "http://ocsp.sectigo.com0",
        "https://jira.adguard.com/browse/AG-15916",
        "https://www.autoitscript.com/autoit3/",
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
