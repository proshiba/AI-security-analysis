from __future__ import annotations

import importlib.util
from pathlib import Path


MODULE = Path(__file__).resolve().parents[1] / "clickfix" / "clickfix_browser_observer.py"
SPEC = importlib.util.spec_from_file_location("clickfix_browser_observer", MODULE)
assert SPEC and SPEC.loader
observer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(observer)


def test_is_public_address_rejects_non_global_ranges() -> None:
    assert observer.is_public_address("8.8.8.8") is True
    assert observer.is_public_address("127.0.0.1") is False
    assert observer.is_public_address("10.0.0.1") is False
    assert observer.is_public_address("169.254.169.254") is False
    assert observer.is_public_address("::1") is False


def test_observation_url_prefers_explicit_landing_url() -> None:
    assert (
        observer.observation_url({"domain": "example.com", "landing_url": "https://example.com/a"})
        == "https://example.com/a"
    )
    assert observer.observation_url({"domain": "example.com"}) == "https://example.com/"


def test_lure_markers_are_deduplicated() -> None:
    assert observer.lure_markers("Verify CAPTCHA then copy PowerShell") == ["captcha", "copy", "powershell", "verify"]


def test_safe_methods_do_not_include_post() -> None:
    assert "GET" in observer.SAFE_METHODS
    assert "POST" not in observer.SAFE_METHODS
