"""共有profileの上限、省略状態、通信値の役割を合成literalだけで検証する。"""

from __future__ import annotations

import pytest

from extractors import profiled_family as profiles


@pytest.mark.parametrize("encoding", ["ascii", "utf-16le"])
def test_overlong_run_is_omitted_without_artificial_fragments(monkeypatch, encoding) -> None:
    monkeypatch.setattr(profiles, "MAX_STRING_CHARS", 40)
    text = "AsyncRAT Server HwidGen Hosts https://node.example.org/" + "x" * 80
    result = profiles.extract_family("asyncrat", text.encode(encoding))
    assert result["findings"] == []
    assert result["config"]["marker_hits"] == []
    assert result["config"]["scan_diagnostics"]["overlong_string_count"] == 1
    assert result["config"]["scan_diagnostics"]["scan_complete"] is False
    assert result["config"]["static_config_recovered"] is False


@pytest.mark.parametrize("limit", [-1, True, 1.5, profiles.MAX_STRINGS + 1])
def test_string_limit_is_strict(limit) -> None:
    with pytest.raises(ValueError, match="limit"):
        profiles.bounded_strings(b"fixture", limit)


def test_string_and_finding_limit_omissions_are_explicit(monkeypatch) -> None:
    monkeypatch.setattr(profiles, "MAX_STRINGS", 2)
    result = profiles.extract_family("asyncrat", b"Alpha\0Bravo\0Charlie\0Delta")
    assert result["config"]["scan_diagnostics"]["string_limit_reached"] is True
    assert result["config"]["scan_diagnostics"]["retained_string_count"] == 2
    monkeypatch.setattr(profiles, "MAX_STRINGS", 50_000)
    monkeypatch.setattr(profiles, "MAX_FINDINGS", 1)
    result = profiles.extract_family("asyncrat", b"https://alpha.example.org/\0https://bravo.example.org/")
    assert len(result["findings"]) == 1
    assert result["config"]["scan_diagnostics"]["omitted_finding_count"] == 1
    assert result["config"]["scan_diagnostics"]["scan_complete"] is False


def test_sampled_scan_is_never_reported_complete(monkeypatch) -> None:
    monkeypatch.setattr(profiles, "FULL_SCAN_LIMIT", 8)
    monkeypatch.setattr(profiles, "SAMPLE_WINDOW", 5)
    result = profiles.extract_family("asyncrat", b"Alpha\0Bravo\0Charlie")
    assert result["config"]["scan_scope"] == "deterministic_three_window_sample"
    assert result["config"]["scan_diagnostics"]["scan_complete"] is False


def test_bare_endpoint_roles_match_url_roles_and_filter_benign_hosts() -> None:
    result = profiles.extract_family("asyncrat", (
        b"www.microsoft.com:443\0ocsp.digicert.com:80\0ipinfo.io:443\0"
        b"raw.githubusercontent.com:443\0node.example.org:8443"
    ))
    findings = {item["value"]: item["role"] for item in result["findings"]}
    assert findings == {
        "ipinfo.io:443": "host_discovery_service",
        "raw.githubusercontent.com:443": "stage_url_candidate",
        "node.example.org:8443": "c2_candidate",
    }
    assert all(item["confidence"] == "candidate" for item in result["findings"])
    assert result["config"]["static_config_recovered"] is False


def test_finite_complete_scan_and_no_evidence_remain_distinct() -> None:
    result = profiles.extract_family("asyncrat", b"ordinary-fixture")
    assert result["config"]["scan_diagnostics"]["scan_complete"] is True
    assert result["findings"] == []
    assert result["config"]["profile_literal_correlation"] is False
    assert result["executed"] is False and result["network_contacted"] is False
