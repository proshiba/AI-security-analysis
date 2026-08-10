"""共通TriageClientの認証header付きredirect拒否契約を検証する。"""

from __future__ import annotations

import sys
import urllib.error
import urllib.request
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
COMMON = ROOT / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

import external_api_helpers as api  # noqa: E402


def test_redirect_and_rate_limit_symbols_are_separate_public_exports() -> None:
    """公開symbol名のcomma欠落による文字列連結を防止する。"""

    expected = {"NoRedirectHandler", "RateLimitError", "RateLimiter"}
    assert expected <= set(api.__all__)


def test_triage_client_default_http_declares_redirect_denial() -> None:
    """既定transportはredirect拒否capabilityを公開する。"""

    client = api.TriageClient()
    assert client.http.redirects_denied is True
    assert any(
        isinstance(handler, api.NoRedirectHandler)
        for handler in client.http._opener.handlers  # noqa: SLF001
    )


@pytest.mark.parametrize(
    "redirect_url",
    [
        "https://tria.ge/api/v0/samples/260810-abcdefghij/sample2",
        "https://example.invalid/credential-capture",
    ],
)
def test_triage_no_redirect_rejects_same_and_cross_host(redirect_url: str) -> None:
    """same-host／cross-hostの30xを新規requestへ変換しない。"""

    handler = api.NoRedirectHandler()
    request = urllib.request.Request(
        "https://tria.ge/api/v0/samples/260810-abcdefghij/sample",
        headers={"Authorization": "Bearer test-secret"},
    )
    with pytest.raises(urllib.error.HTTPError, match="redirect refused"):
        handler.redirect_request(request, None, 302, "Found", {}, redirect_url)


@pytest.mark.parametrize("unsafe_http", [api.HttpClient(), object()])
def test_triage_client_rejects_unsafe_explicit_transport(unsafe_http: object) -> None:
    """redirect拒否を証明できない明示transportはfail closedにする。"""

    with pytest.raises(ValueError, match="redirect拒否capability"):
        api.TriageClient(http=unsafe_http)


def test_triage_client_preserves_safe_explicit_http_dependency() -> None:
    """redirect拒否handler付きの明示HTTP clientだけを保持する。"""

    http = api.HttpClient(
        opener=urllib.request.build_opener(api.NoRedirectHandler())
    )
    client = api.TriageClient(http=http)
    assert client.http is http
    assert client.http.redirects_denied is True
