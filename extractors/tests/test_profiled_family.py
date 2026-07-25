"""profile定義済みfamily向け共有抽出器の単体テスト。"""

from __future__ import annotations

import json
import os

import pytest

from extractors import profiled_family


def test_profiles_normalization_and_validation(tmp_path) -> None:
    """11個のprofileを読み、aliasを正規化し、不正文書を拒否する。"""
    profiles = profiled_family.load_profiles()
    assert len(profiles) == 11
    assert profiled_family.normalize_family("Ghost-RAT", profiles) == "gh0strat"
    assert profiled_family.normalize_family("Quasar-RAT", profiles) == "quasarrat"
    assert profiled_family.profile_for("cloud eye")["family"] == "guloader"
    invalid = tmp_path / "invalid.json"
    invalid.write_text(json.dumps({"schema_version": 2}), encoding="utf-8")
    with pytest.raises(ValueError, match="不正"):
        profiled_family.load_profiles(invalid)
    duplicate = tmp_path / "duplicate.json"
    duplicate.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "profiles": {
                    "fixture": {
                        "markers": ["Marker", "marker"],
                        "minimum_markers": 2,
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="marker.*不正"):
        profiled_family.load_profiles(duplicate)


def _profile_document(second_marker: str) -> dict:
    return {
        "schema_version": 1,
        "profiles": {
            "fixture": {
                "markers": ["Alpha", second_marker],
                "minimum_markers": 2,
            }
        },
    }


def test_profile_cache_tracks_file_identity(tmp_path) -> None:
    """profile変更時は同一processでもmtime/size identityにより再読込する。"""

    path = tmp_path / "profiles.json"
    path.write_text(json.dumps(_profile_document("Bravo")), encoding="utf-8")
    assert profiled_family.load_profiles(path)["fixture"]["markers"][1] == "Bravo"
    path.write_text(json.dumps(_profile_document("Charlie")), encoding="utf-8")
    assert profiled_family.load_profiles(path)["fixture"]["markers"][1] == "Charlie"


def test_profile_cache_can_be_explicitly_cleared_for_same_identity(tmp_path) -> None:
    """mtimeとsizeが同じ外部更新も明示clear後は確実に再読込する。"""

    path = tmp_path / "profiles.json"
    path.write_text(json.dumps(_profile_document("Bravo")), encoding="utf-8")
    assert profiled_family.load_profiles(path)["fixture"]["markers"][1] == "Bravo"
    original = path.stat()
    path.write_text(json.dumps(_profile_document("Delta")), encoding="utf-8")
    os.utime(
        path,
        ns=(original.st_atime_ns, original.st_mtime_ns),
    )
    assert path.stat().st_size == original.st_size
    assert profiled_family.load_profiles(path)["fixture"]["markers"][1] == "Bravo"
    profiled_family.clear_profile_cache()
    assert profiled_family.load_profiles(path)["fixture"]["markers"][1] == "Delta"


def test_bounded_strings_uses_three_windows(monkeypatch) -> None:
    """全量scan上限超過時も先頭、中央、末尾の文字列を保持する。"""
    monkeypatch.setattr(profiled_family, "FULL_SCAN_LIMIT", 8)
    monkeypatch.setattr(profiled_family, "SAMPLE_WINDOW", 5)
    data = b"FIRST" + b"x" * 10 + b"MIDDLE" + b"y" * 10 + b"LAST"
    values = profiled_family.bounded_strings(data)
    text = " ".join(values)
    assert "FIRST" in text and "LAST" in text
    assert profiled_family.sanitize_network_url("http://ns.adobe.com/xap/1.0/") is None
    assert (
        profiled_family.sanitize_network_url("http://oneocsp.microsoft.com/ocsp0")
        is None
    )
    assert profiled_family.bounded_strings(data, 0) == []


def test_url_sanitization_and_profile_literal_correlation() -> None:
    """相関したAsyncRAT literalと復号済み設定を区別する。"""
    assert (
        profiled_family.sanitize_network_url(
            "https://user:pass@evil.example.org/a?q=secret#x"
        )
        == "https://evil.example.org/a"
    )
    assert profiled_family.sanitize_network_url("http://127.0.0.1/test") is None
    data = b"AsyncRAT Server HwidGen Hosts Ports https://evil.example.org/gate?token=redacted"
    result = profiled_family.extract_family("asyncrat", data, "fixture.exe")
    assert (
        profiled_family.sanitize_network_url("http://schemas.microsoft.com/SMI") is None
    )
    assert (
        profiled_family.sanitize_network_url(
            "https://discord.com/api/webhooks/123/SECRET"
        )
        == "https://discord.com/api/webhooks/123"
    )
    assert (
        profiled_family.sanitize_network_url(
            "https://api.telegram.org/bot123456789:SECRET/send"
        )
        == "https://api.telegram.org/bot-REDACTED/send"
    )
    assert profiled_family.sanitize_network_url("https://t.me/example") is None
    assert (
        profiled_family.url_role("c2_candidate", "https://ipinfo.io/json")
        == "host_discovery_service"
    )
    assert (
        profiled_family.url_role("c2_candidate", "https://onedrive.live.com/download")
        == "stage_url_candidate"
    )
    assert (
        profiled_family.url_role("c2_candidate", "https://evil.example.org/payload.exe")
        == "stage_url_candidate"
    )
    assert result["family"] == "asyncrat"
    assert result["config"]["profile_literal_correlation"] is True
    assert result["config"]["decoded_config_recovered"] is False
    assert result["config"]["static_config_recovered"] is False
    assert result["findings"][0]["value"] == "https://evil.example.org/gate"
    assert result["network_contacted"] is False


def test_extractor_factory_and_candidate_confidence() -> None:
    """profileをbindし、孤立literalだけで確認済みと主張しない。"""
    extractor = profiled_family.extractor_for("idatloader")
    result = extractor(b"https://stage.example.org/a", "loader.js")
    assert result["family"] == "hijackloader"
    assert result["findings"][0]["confidence"] == "candidate"
    assert result["config"]["static_config_recovered"] is False


def test_hijackloader_rejects_short_substrings_inside_identifiers() -> None:
    """Go等の長い識別子に含まれるidat／esalをfamily証拠にしない。"""

    result = profiled_family.extract_family(
        "hijackloader",
        (
            b"runtime.moduleDataVerify runtime.typesAliases "
            b"Module URL https://node.example.org/payload.exe"
        ),
        "fixture.exe",
    )
    assert result["config"]["marker_hits"] == []
    assert result["config"]["profile_literal_correlation"] is False


def test_hijackloader_requires_two_high_specificity_literals() -> None:
    """固有phrase 2個と設定key・配布候補が揃う場合だけ相関させる。"""

    result = profiled_family.extract_family(
        "hijackloader",
        (b"HijackLoader module stomping URL=https://node.example.org/payload.exe"),
        "fixture.exe",
    )
    assert result["config"]["marker_hits"] == [
        "hijackloader",
        "module stomping",
    ]
    assert result["config"]["profile_literal_correlation"] is True


def test_gh0strat_requires_independent_markers() -> None:
    """単一製品literalを拒否し、相関値を候補として保持する。"""
    isolated = profiled_family.extract_family(
        "gh0strat",
        b"Gh0st Server Host Port https://node.example.org/gate",
        "fixture.exe",
    )
    assert isolated["config"]["marker_hits"] == ["gh0st server"]
    assert isolated["config"]["profile_literal_correlation"] is False
    correlated = profiled_family.extract_family(
        "gh0strat",
        b"Gh0st Server GameOver Host Port https://node.example.org/gate",
        "fixture.exe",
    )
    assert correlated["network_contacted"] is False
    assert correlated["config"]["profile_literal_correlation"] is True
    assert correlated["config"]["static_config_recovered"] is False
    assert correlated["findings"][0]["confidence"] == "candidate"


def test_overlapping_profile_literal_counts_once() -> None:
    """長いfamily literalとそのsubstringを2つのmarkerとして数えない。"""
    result = profiled_family.extract_family(
        "asyncrat",
        b"AsyncRAT Server Hosts https://evil.example.org/gate",
        "fixture.exe",
    )
    assert result["config"]["marker_hits"] == ["asyncrat server"]
    assert result["config"]["profile_literal_correlation"] is False


def test_generic_markers_and_url_require_a_config_key() -> None:
    """marker数と任意URLだけでは共有profileをfamily一致へ昇格しない。"""

    result = profiled_family.extract_family(
        "asyncrat",
        b"AsyncRAT Server HwidGen https://evil.example.org/gate",
        "fixture.exe",
    )
    assert result["config"]["marker_hits"] == ["asyncrat server", "hwidgen"]
    assert result["config"]["observed_config_keys"] == []
    assert result["config"]["correlation_requirements"]["config_key"] is False
    assert result["config"]["profile_literal_correlation"] is False


def test_asyncrat_rejects_generic_pong_hwid_fixture() -> None:
    """汎用PONG・HWID・設定語と任意URLをAsyncRATへ昇格しない。"""

    result = profiled_family.extract_family(
        "asyncrat",
        b"MZ pong hwid Hosts Ports Version Install Mutex https://go.dev/issue/66821",
        "fixture.exe",
    )
    assert result["config"]["marker_hits"] == []
    assert result["config"]["profile_literal_correlation"] is False


def test_semantic_marker_variants_count_once() -> None:
    """空白・句読点だけが異なるfamily名を独立証拠に数えない。"""

    assert profiled_family._independent_marker_hits(
        ["hijackloader", "hijack loader", "module stomping"],
        "HijackLoader Hijack Loader",
    ) == ["hijackloader"]

    hijack = profiled_family.extract_family(
        "hijackloader",
        b"HijackLoader Hijack Loader URL https://node.example.org/a",
        "fixture.exe",
    )
    assert hijack["config"]["marker_hits"] == ["hijackloader"]
    assert hijack["config"]["profile_literal_correlation"] is False

    snake = profiled_family.extract_family(
        "snakekeylogger",
        b"Snake Keylogger SnakeKeylogger Host https://node.example.org/a",
        "fixture.exe",
    )
    assert snake["config"]["marker_hits"] == ["snake keylogger"]
    assert snake["config"]["profile_literal_correlation"] is False
