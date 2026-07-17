"""Tests for syntactically bounded domain and URL host validation."""

from extractors.common import valid_host
from extractors.stealer_common import clean_url


def test_valid_host_rejects_der_suffix_artifacts() -> None:
    """Reject URL hostnames polluted by adjacent DER/string bytes."""
    assert valid_host("c2.example")
    assert valid_host("157.90.113.100")
    assert not valid_host("sv.symcd.com0&")
    assert not valid_host("www.w3")
    assert clean_url("http://sv.symcd.com0&") is None
