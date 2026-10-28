"""ValleyRAT modern ur／ps補助設定の安全な静的抽出を検証する。"""

from __future__ import annotations

import hashlib
import json

from extractors.valleyrat import extractor

TRANSPORT_KEY_HEX = "0123456789abcdef" * 4
FALLBACK_URL = "https://fallback.example.org/hm.txt"


def _canonical_config(
    *,
    fallback_url: str = FALLBACK_URL,
    transport_key: str = TRANSPORT_KEY_HEX,
) -> str:
    fields = [
        ("p1", "198.51.100.24"),
        ("o1", "443"),
        ("t1", "1"),
        ("p2", ""),
        ("o2", ""),
        ("t2", "1"),
        ("p3", ""),
        ("o3", ""),
        ("t3", "1"),
        ("dd", "1"),
        ("cl", "3"),
        ("fz", "default"),
        ("bb", "1.0"),
        ("bz", "unit"),
        ("jp", "1"),
        ("bh", "0"),
        ("ll", "0"),
        ("dl", "0"),
        ("sh", "0"),
        ("kl", "0"),
        ("bd", "0"),
        ("ur", fallback_url),
        ("ps", transport_key),
    ]
    return "|" + "|".join(f"{key}:{value}" for key, value in fields) + "|"


def test_modern_fallback_and_transport_key_are_validated_without_raw_key() -> None:
    """完全なfield列だけからresolver URLとkey fingerprintを復元する。"""

    stored = _canonical_config()[::-1]
    decoded, evidence = extractor._decode_vvas_reversed_config([stored])
    modern = evidence["modern_fallback_config"]

    assert decoded == {"endpoint_1": "198.51.100.24:443"}
    assert modern["status"] == "validated_unique"
    assert modern["fallback_urls"] == [FALLBACK_URL]
    assert modern["fallback_url_role"] == "fallback_c2_resolver_candidate"
    assert modern["transport_key_length"] == 32
    assert (
        modern["transport_key_sha256"]
        == hashlib.sha256(bytes.fromhex(TRANSPORT_KEY_HEX)).hexdigest()
    )
    assert modern["raw_transport_key_included"] is False
    assert modern["raw_configuration_included"] is False
    assert modern["supports_family_attribution"] is False
    assert modern["command_c2_confirmed"] is False
    assert TRANSPORT_KEY_HEX not in json.dumps(evidence, sort_keys=True)


def test_modern_fallback_is_published_as_resolver_candidate_only() -> None:
    """raw routeではfallbackを直接C2またはfamily確定へ昇格しない。"""

    stored = _canonical_config()[::-1].encode("ascii")
    result = extractor.extract(b"odaktomk " + stored, "modern-stage.bin")

    assert result["config"]["endpoints"] == ["198.51.100.24:443"]
    assert result["config"]["urls"] == [FALLBACK_URL]
    assert result["config"]["fallback_c2_resolver_urls"] == [FALLBACK_URL]
    assert result["config"]["static_config_recovered"] is False
    assert result["config"]["terminal_family_confirmed"] is False
    fallback_finding = next(
        item for item in result["findings"] if item.get("value") == FALLBACK_URL
    )
    assert fallback_finding["role"] == "fallback_c2_resolver_candidate"
    assert fallback_finding["source"] == "validated_modern_vvas_auxiliary_config"
    assert TRANSPORT_KEY_HEX not in json.dumps(result, sort_keys=True)


def test_conflicting_modern_auxiliary_is_rejected_without_losing_base_slots() -> None:
    """同じp/o/tに異なるresolverがあれば補助情報だけをfail-closedにする。"""

    first = _canonical_config()[::-1]
    second = _canonical_config(fallback_url="https://fallback.example.org/backup.txt")[
        ::-1
    ]
    decoded, evidence = extractor._decode_vvas_reversed_config([first, second])
    modern = evidence["modern_fallback_config"]

    assert decoded == {"endpoint_1": "198.51.100.24:443"}
    assert modern["status"] == "ambiguous_rejected"
    assert modern["unique_configuration_count"] == 2
    assert modern["fallback_urls"] == []
    assert "transport_key_sha256" not in modern


def test_incomplete_or_reordered_auxiliary_does_not_replace_base_config() -> None:
    """ur／psの欠落や順序違反は補助情報として採用しない。"""

    canonical = _canonical_config()
    missing_ps = canonical.rsplit("|ps:", 1)[0] + "|"
    reordered = canonical.replace(
        f"|ur:{FALLBACK_URL}|ps:{TRANSPORT_KEY_HEX}|",
        f"|ps:{TRANSPORT_KEY_HEX}|ur:{FALLBACK_URL}|",
    )
    for candidate in (missing_ps, reordered):
        decoded, evidence = extractor._decode_vvas_reversed_config([candidate[::-1]])
        assert decoded == {"endpoint_1": "198.51.100.24:443"}
        assert evidence["modern_fallback_config"]["status"] == "invalid_rejected"
        assert evidence["modern_fallback_config"]["fallback_urls"] == []


def test_non_public_or_stateful_fallback_url_is_rejected() -> None:
    """private host、資格情報、query付きURLをresolver候補にしない。"""

    invalid_urls = (
        "http://127.0.0.1/hm.txt",
        "https://user:password@fallback.example.org/hm.txt",
        "https://fallback.example.org/hm.txt?token=hidden",
        "https://fallback.example.org/payload.bin",
    )
    for fallback_url in invalid_urls:
        decoded, evidence = extractor._decode_vvas_reversed_config(
            [_canonical_config(fallback_url=fallback_url)[::-1]]
        )
        assert decoded == {"endpoint_1": "198.51.100.24:443"}
        assert evidence["modern_fallback_config"]["status"] == "invalid_rejected"
        assert evidence["modern_fallback_config"]["fallback_urls"] == []


def test_invalid_transport_key_or_typed_field_is_rejected() -> None:
    """ps長、boolean、待機値、versionの型違反を採用しない。"""

    invalid_configs = (
        _canonical_config(transport_key="ab" * 31),
        _canonical_config().replace("|jp:1|", "|jp:2|"),
        _canonical_config().replace("|dd:1|", "|dd:-1|"),
        _canonical_config().replace("|bb:1.0|", "|bb:latest|"),
    )
    for candidate in invalid_configs:
        decoded, evidence = extractor._decode_vvas_reversed_config([candidate[::-1]])
        assert decoded == {"endpoint_1": "198.51.100.24:443"}
        assert evidence["modern_fallback_config"]["status"] == "invalid_rejected"
        assert evidence["modern_fallback_config"]["fallback_urls"] == []
