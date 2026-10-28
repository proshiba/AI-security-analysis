"""ValleyRATの19文字鍵RC4完全設定抽出を検証する。"""

from __future__ import annotations

import json

import pytest

from extractors.valleyrat import extractor, rc4_full_config

KEY = b"3FE030CD5BF6376A61A"


def _rc4_reference(data: bytes, key: bytes) -> bytes:
    """fixture生成用の独立した標準RC4実装。"""

    state = list(range(256))
    j = 0
    for i in range(256):
        j = (j + state[i] + key[i % len(key)]) & 0xFF
        state[i], state[j] = state[j], state[i]
    output = bytearray()
    i = j = 0
    for value in data:
        i = (i + 1) & 0xFF
        j = (j + state[i]) & 0xFF
        state[i], state[j] = state[j], state[i]
        output.append(value ^ state[(state[i] + state[j]) & 0xFF])
    return bytes(output)


def _plaintext(
    *,
    identifier: str = "A16A6736FB5DC030EF3",
    first_host: str = "one.c2-fixture.net",
    second_host: str = "two.c2-fixture.net",
    third_host: str = "three.c2-fixture.net",
    first_port: int = 7880,
) -> str:
    return (
        f"|{identifier}"
        f"|A1:{first_host}|o1:{first_port}|t1:1"
        f"|S2:{second_host}|o2:7881|t2:1"
        f"|p3:{third_host}|o3:7882|t3:0"
        "|dd:10|cl:30|fz:fixture"
        "|bb:11171030|bz:2025.11.20"
        "|jp:0|bh:0|ll:0|dl:0|sh:0|kl:0|bd:0|"
    )


def _blob(
    plaintext: str | None = None,
    *,
    key: bytes = KEY,
    prefix: bytes = b"MZ\0fixture\0",
) -> tuple[bytes, bytes]:
    raw = (plaintext or _plaintext()).encode("utf-8")
    encrypted = _rc4_reference(raw[::-1], key)
    encoded = encrypted.hex().upper().encode("ascii")
    return prefix + key + encoded + b"\0tail", encoded


def test_recovers_proofpoint_style_aliases_without_raw_secrets() -> None:
    """A1／S2／p3を含む完全設定を候補として復元する。"""

    data, encoded = _blob()
    result = rc4_full_config.probe_rc4_full_config(data)

    assert result is not None
    assert result["status"] == "validated_route_only_rc4_full_config"
    assert result["variant_profile"] == "proofpoint_2026_full_rc4_config"
    assert result["key_length"] == 19
    assert result["decoder"].endswith("reverse_bytes_after_rc4")
    assert result["candidate_config_recovered"] is True
    assert result["static_config_recovered"] is False
    assert result["config"]["slots"] == [
        {
            "index": 1,
            "host_field": "a1",
            "host": "one.c2-fixture.net",
            "port": 7880,
            "transport_selector": 1,
            "transport": "tcp",
            "endpoint": "one.c2-fixture.net:7880",
            "endpoint_role": "interactive_c2_candidate",
        },
        {
            "index": 2,
            "host_field": "s2",
            "host": "two.c2-fixture.net",
            "port": 7881,
            "transport_selector": 1,
            "transport": "tcp",
            "endpoint": "two.c2-fixture.net:7881",
            "endpoint_role": "interactive_c2_candidate",
        },
        {
            "index": 3,
            "host_field": "p3",
            "host": "three.c2-fixture.net",
            "port": 7882,
            "transport_selector": 0,
            "transport": "udp",
            "endpoint": "three.c2-fixture.net:7882",
            "endpoint_role": "interactive_c2_candidate",
        },
    ]
    assert result["config"]["settings"]["dd"] == 10
    assert result["config"]["settings"]["cl"] == 30
    assert result["evidence_boundary"]["supports_family_attribution"] is False
    assert result["evidence_boundary"]["used_for_c2_confirmation"] is False

    serialized = json.dumps(result, ensure_ascii=False, sort_keys=True)
    assert KEY.decode("ascii") not in serialized
    assert encoded.decode("ascii") not in serialized
    assert _plaintext() not in serialized
    assert result["safety"] == {
        "sample_executed": False,
        "network_contacted": False,
        "raw_key_included": False,
        "raw_ciphertext_included": False,
        "raw_plaintext_included": False,
    }


def test_nonhex_ascii_key_is_supported_with_strict_boundary() -> None:
    """19文字ASCII鍵がhexだけでないvariantも同じ文法で復元する。"""

    key = b"Key-For-Fixture_123"
    assert len(key) == 19
    data, _encoded = _blob(key=key)

    result = rc4_full_config.probe_rc4_full_config(data)

    assert result is not None
    assert result["key_length"] == 19
    assert result["config"]["slots"][0]["port"] == 7880


def test_non_utf8_fz_is_hashed_instead_of_published() -> None:
    """legacy code page由来のfz値を生で返さず、構造だけを保持する。"""

    raw = _plaintext().encode("utf-8").replace(b"fz:fixture", b"fz:\xac\xc4\xcf\xc8")
    encrypted = _rc4_reference(raw[::-1], KEY)
    data = b"\0" + KEY + encrypted.hex().encode("ascii") + b"\0"

    result = rc4_full_config.probe_rc4_full_config(data)

    assert result is not None
    settings = result["config"]["settings"]
    assert settings["fz_length"] == 4
    assert len(settings["fz_sha256"]) == 64
    serialized = json.dumps(result, ensure_ascii=False, sort_keys=True)
    assert "\\u00ac" not in serialized


@pytest.mark.parametrize(
    "plaintext",
    [
        _plaintext(first_port=0),
        _plaintext(first_port=65536),
        _plaintext().replace("|dd:10", "|dd:not-a-number"),
        _plaintext().replace("|cl:30", "|cl:0"),
        _plaintext().replace("|jp:0", "|jp:2"),
        _plaintext().replace("|S2:", "|o2:"),
        _plaintext().replace("|bz:2025.11.20", ""),
        _plaintext().replace("|p3:", "|p1:"),
    ],
)
def test_rejects_broken_complete_config_grammar(plaintext: str) -> None:
    """port、型、必須field、slot順序の破損をfail-closedで拒否する。"""

    data, _encoded = _blob(plaintext)

    assert rc4_full_config.probe_rc4_full_config(data) is None


def test_rejects_wrong_key_length_plaintext_decoy_and_random_hex() -> None:
    """鍵長違い、平文decoy、無関係なhex文字列を候補にしない。"""

    raw = _plaintext().encode("utf-8")
    short_key = b"K" * 18
    encrypted = _rc4_reference(raw, short_key).hex().encode("ascii")
    short_key_blob = b"\0" + short_key + encrypted + b"\0"
    assert rc4_full_config.probe_rc4_full_config(short_key_blob) is None

    assert rc4_full_config.probe_rc4_full_config(b"\0" + raw + b"\0") is None
    random_hex = b"\0" + KEY + (b"AA" * 512) + b"\0"
    assert rc4_full_config.probe_rc4_full_config(random_hex) is None


def test_same_config_duplicates_are_kept_as_one_identity() -> None:
    """同一設定の複製は相反扱いせず、観測数を保持する。"""

    first, _encoded = _blob(prefix=b"\0")
    second, _encoded = _blob(prefix=b"\0")
    result = rc4_full_config.probe_rc4_full_config(first + second)

    assert result is not None
    assert result["validated_candidate_count"] == 2
    assert result["candidate_set_complete"] is True


def test_conflicting_configs_are_rejected() -> None:
    """異なるC2を復号する候補が共存する入力を自動統合しない。"""

    first, _encoded = _blob(prefix=b"\0")
    second, _encoded = _blob(
        _plaintext(first_host="conflict.c2-fixture.net"), prefix=b"\0"
    )

    with pytest.raises(rc4_full_config.Rc4FullConfigError, match="相反"):
        rc4_full_config.recover_config(first + second)


def test_candidate_limit_discards_earlier_valid_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """未走査候補が残る場合は先頭の成功だけを採用しない。"""

    first, _encoded = _blob(prefix=b"\0")
    second, _encoded = _blob(prefix=b"\0")
    monkeypatch.setattr(rc4_full_config, "MAXIMUM_CANDIDATE_ATTEMPTS", 1)

    with pytest.raises(rc4_full_config.Rc4FullConfigLimitError, match="候補数"):
        rc4_full_config.recover_config(first + second)


def test_input_and_hex_run_limits_are_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """過大入力または未走査hex領域を部分成功にしない。"""

    monkeypatch.setattr(rc4_full_config, "MAXIMUM_INPUT_SIZE", 8)
    with pytest.raises(rc4_full_config.Rc4FullConfigLimitError, match="入力size"):
        rc4_full_config.recover_config(b"A" * 9)

    monkeypatch.setattr(rc4_full_config, "MAXIMUM_INPUT_SIZE", 1_000_000)
    monkeypatch.setattr(rc4_full_config, "MAXIMUM_CIPHERTEXT_BYTES", 100)
    oversized = b"\0" + KEY + b"AA" * 101 + b"\0"
    with pytest.raises(rc4_full_config.Rc4FullConfigLimitError, match="run"):
        rc4_full_config.recover_config(oversized)


def test_valid_data_remains_route_only_without_code_binding() -> None:
    """復号成功だけではfamily／C2確定へ昇格しない。"""

    data, _encoded = _blob()
    result = rc4_full_config.probe_rc4_full_config(data)

    assert result is not None
    boundary = result["evidence_boundary"]
    assert boundary["terminal_family_confirmed"] is False
    assert boundary["used_for_family_resolution"] is False
    assert boundary["used_for_c2_confirmation"] is False
    assert boundary["config_consumer_code_lineage_proven"] is False
    assert boundary["config_to_connect_send_receive_proven"] is False


@pytest.mark.parametrize(
    "host",
    ["127.0.0.1", "10.0.0.1", "169.254.1.2", "fixture.invalid"],
)
def test_non_public_endpoint_is_not_published_as_c2(host: str) -> None:
    """loopback、private、link-local、予約domainをC2候補にしない。"""

    data, _encoded = _blob(_plaintext(first_host=host))
    result = rc4_full_config.probe_rc4_full_config(data)

    assert result is not None
    first = result["config"]["slots"][0]
    assert first["endpoint"] is None
    assert first["endpoint_role"] == "non_public_placeholder"
    assert result["candidate_config_recovered"] is True


def test_all_non_public_slots_are_not_c2_candidates() -> None:
    """構造化configを保持しても、非公開slotだけならC2候補にしない。"""

    data, _encoded = _blob(
        _plaintext(
            first_host="127.0.0.1",
            second_host="10.0.0.1",
            third_host="fixture.invalid",
        )
    )
    result = rc4_full_config.probe_rc4_full_config(data)

    assert result is not None
    assert result["candidate_config_recovered"] is False
    assert result["config"]["endpoint_role"] == "non_public_placeholder_only"
    assert all(item["endpoint"] is None for item in result["config"]["slots"])


def test_shared_extractor_publishes_rc4_full_config_as_route_only() -> None:
    data, _encoded = _blob()
    result = extractor.extract(data, "candidate.bin")

    config = result["config"]
    assert config["variant"] == "proofpoint_2026_full_rc4_config_candidate"
    assert config["candidate_config_recovered"] is True
    assert config["static_config_recovered"] is False
    assert config["terminal_family_confirmed"] is False
    assert len(config["endpoints"]) == 3


def test_rc4_data_candidate_does_not_preempt_existing_structural_route(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """data-only候補よりcode lineageを持つ既存routeを優先する。"""

    data, _encoded = _blob()
    structural = {
        "family": "valleyrat",
        "config": {
            "variant": "stronger_codemark_route",
            "static_config_recovered": True,
            "candidate_config_recovered": False,
            "terminal_family_confirmed": False,
        },
        "findings": [],
        "notes": [],
    }
    monkeypatch.setattr(
        extractor,
        "_extract_codemark_stage",
        lambda _data, _name: structural,
    )

    result = extractor.extract(data, "candidate-with-structural-route.bin")

    assert result["config"]["variant"] == "stronger_codemark_route"
