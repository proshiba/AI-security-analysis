"""オフラインC2候補検出器のテスト。"""

from __future__ import annotations

import json
from pathlib import Path
import sys

import pytest

COMMON = Path(__file__).parents[1] / "common"
sys.path.insert(0, str(COMMON))

import c2_candidate_detector as detector  # noqa: E402


def test_target_queries_and_assessment() -> None:
    """URL・endpoint解析、受動検索式、確度選択を確認する。"""
    assert detector.target_from_finding({"kind": "network.url", "value": "https://evil.example:8443/a"}) == (
        "evil.example",
        8443,
    )
    assert detector.target_from_finding({"kind": "network.endpoint", "value": "1.2.3.4:443"}) == (
        "1.2.3.4",
        443,
    )
    assert detector.target_from_finding(
        {"kind": "network.endpoint", "value": "[2001:4860:4860::8888]:853"}
    ) == ("2001:4860:4860::8888", 853)
    assert detector.target_from_finding({"kind": "exfiltration.endpoint", "value": "mail.example:587"}) == (
        "mail.example",
        587,
    )
    assert detector.shodan_queries("1.2.3.4", 443) == ["ip:1.2.3.4 port:443"]
    result = detector.assess(
        {
            "family": "fixture",
            "findings": [
                {
                    "kind": "network.url",
                    "value": "https://evil.example/api/",
                    "confidence": "probable",
                }
            ],
        }
    )
    discovery = detector.assess(
        {
            "family": "njrat",
            "findings": [
                {
                    "kind": "network.url",
                    "value": "https://ipinfo.io/json",
                    "role": "host_discovery_service",
                    "confidence": "probable",
                }
            ],
        }
    )
    assert discovery["assessment"] == "none" and discovery["targets"] == []
    assert result["assessment"] == "probable" and result["network_contacted"] is False
    profile = detector.protocol_profile("guloader")
    assert profile and profile["category"] == "loader"
    assert profile["active_confirmation_default"] == "disabled"


@pytest.mark.parametrize(
    "host",
    [
        "localhost",
        "localhost.",
        "sub.localhost",
        "127.0.0.1",
        "10.0.0.1",
        "100.64.0.1",
        "169.254.1.1",
        "192.0.2.1",
        "198.51.100.8",
        "203.0.113.9",
        "198.18.0.1",
        "224.0.0.1",
        "0.0.0.0",
        "255.255.255.255",
        "::",
        "::1",
        "fc00::1",
        "fe80::1",
        "2001:db8::1",
        "3fff::1",
        "ff02::1",
        f"{'a' * 56}.onion",
        "service.local",
        "service.test",
        "service.invalid",
        "example.com",
        "sub.example.org",
        "single-label",
        "http://127.0.0.1:8080/admin",
    ],
)
def test_shodan_queries_exclude_non_public_targets(host: str) -> None:
    """Tor・ローカル・特殊用途・文書用の対象を検索式から除外する。"""
    assert detector.shodan_queries(host, 443) == []


@pytest.mark.parametrize(
    ("target", "port", "expected"),
    [
        ("1.2.3.4", 443, ["ip:1.2.3.4 port:443"]),
        ("2001:4860:4860::8888", 53, ["ip:2001:4860:4860::8888 port:53"]),
        ("WWW.PYTHON.ORG.", 443, ["hostname:www.python.org port:443"]),
        ("BÜCHER.DE.", 443, ["hostname:xn--bcher-kva.de port:443"]),
        ("www.python.org:8443", None, ["hostname:www.python.org port:8443"]),
        ("[2001:4860:4860::8888]:853", None, ["ip:2001:4860:4860::8888 port:853"]),
        (
            "https://private-user:private-password@BÜCHER.DE.:8443/gate"
            "?token=private-token#private-fragment",
            None,
            ["hostname:xn--bcher-kva.de port:8443"],
        ),
    ],
)
def test_shodan_queries_normalize_public_targets(target: str, port: int | None, expected: list[str]) -> None:
    """公開IP・公開DNS名・URL・IDNA・末尾dot・埋め込みportを正規化する。"""
    assert detector.shodan_queries(target, port) == expected


@pytest.mark.parametrize(
    ("target", "port"),
    [
        ("www.python.org", 0),
        ("www.python.org", 65536),
        ("www.python.org", True),
        ("www.python.org:443", 8443),
        ("www.python.org:", None),
        ("www.python.org port:22", 443),
        ("*.python.org", 443),
        ("bad_name.python.org", 443),
        ("-bad.python.org", 443),
        ("python.org-", 443),
        ("999.999.999.999", 443),
        ("https://[2001:db8::1", None),
        ("https://www.python.org:invalid/path", None),
        ("https://www.python.org:65536/path", None),
        ("https://www.python.org/\r\nhostname:attacker.example", None),
        ("www.python.org\r\n", 443),
    ],
)
def test_shodan_queries_fail_closed_for_ambiguous_or_injectable_input(target: str, port: object) -> None:
    """不正port、曖昧なauthority、検索式注入候補をfail-closedで拒否する。"""
    assert detector.shodan_queries(target, port) == []


def test_assessment_redacts_url_secrets_from_artifact() -> None:
    """資格情報・query・fragmentを評価成果物へ残さない。"""
    finding = {
        "kind": "network.url",
        "value": (
            "https://unique-user:unique-password@BÜCHER.DE.:8443/gate"
            "?api_key=unique-token#unique-fragment"
        ),
        "confidence": "probable",
        "source": "static_config",
    }
    result = detector.assess({"family": "fixture", "findings": [finding]})
    target = result["targets"][0]
    assert target["host"] == "xn--bcher-kva.de"
    assert target["port"] == 8443
    assert target["finding"]["value"] == "https://xn--bcher-kva.de:8443/gate"
    assert target["passive_queries"] == ["hostname:xn--bcher-kva.de port:8443"]
    serialized = json.dumps(result)
    for secret in ("unique-user", "unique-password", "unique-token", "unique-fragment"):
        assert secret not in serialized


def test_assessment_sanitizes_ipv6_url_and_endpoint_values() -> None:
    """IPv6の括弧を保ち、URLとendpointの秘密値を正規化する。"""
    result = detector.assess(
        {
            "family": "fixture",
            "findings": [
                {
                    "kind": "network.url",
                    "value": (
                        "https://ipv6-user:ipv6-password@[2001:4860:4860::8888]:8443/gate"
                        "?token=ipv6-token#ipv6-fragment"
                    ),
                    "confidence": "probable",
                },
                {
                    "kind": "network.endpoint",
                    "value": "endpoint-user:endpoint-password@www.python.org:443?token=endpoint-token",
                    "confidence": "candidate",
                },
            ],
        }
    )
    assert result["targets"][0]["finding"]["value"] == "https://[2001:4860:4860::8888]:8443/gate"
    assert result["targets"][1]["finding"]["value"] == "www.python.org:443"
    serialized = json.dumps(result)
    for secret in (
        "ipv6-user",
        "ipv6-password",
        "ipv6-token",
        "ipv6-fragment",
        "endpoint-user",
        "endpoint-password",
        "endpoint-token",
    ):
        assert secret not in serialized


def test_cli_does_not_log_or_persist_url_secrets(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """CLIの標準出力とJSON成果物からURL秘密値を除去する。"""
    source, output = tmp_path / "extractor-secret.json", tmp_path / "c2-secret.json"
    source.write_text(
        json.dumps(
            {
                "family": "fixture",
                "findings": [
                    {
                        "kind": "network.url",
                        "value": (
                            "https://cli-user:cli-password@www.python.org:443/gate"
                            "?token=cli-token#cli-fragment"
                        ),
                        "confidence": "probable",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    assert detector.main(["--extractor-result", str(source), "--output", str(output)]) == 0
    public_text = capsys.readouterr().out + output.read_text(encoding="utf-8")
    for secret in ("cli-user", "cli-password", "cli-token", "cli-fragment"):
        assert secret not in public_text


def test_cli(tmp_path: Path) -> None:
    """CLIパーサーと決定的な出力を確認する。"""
    source, output = tmp_path / "extractor.json", tmp_path / "c2.json"
    source.write_text(json.dumps({"family": "fixture", "findings": []}), encoding="utf-8")
    args = ["--extractor-result", str(source), "--output", str(output)]
    assert detector.build_parser().parse_args(args).output == output
    assert detector.main(args) == 0
    assert json.loads(output.read_text())["targets"] == []
