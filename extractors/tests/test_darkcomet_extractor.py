"""DarkComet RCDATA設定抽出器の回帰テスト。"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from extractors.config_extractor import get_extractor
from extractors.darkcomet import extractor as darkcomet


def _encode(value: str) -> bytes:
    ciphertext = darkcomet.rc4_crypt(
        value.encode("ascii"), darkcomet.build_resource_key()
    )
    return ciphertext.hex().upper().encode("ascii")


def test_resource_key_and_network_key_are_distinct() -> None:
    assert darkcomet.build_resource_key() == b"#KCMDDC5#-890"
    assert darkcomet.NETWORK_KEY == b"#KCMDDC5#-"
    assert darkcomet.NETWORK_KEY != darkcomet.build_resource_key()


def test_decode_config_and_normalize_netdata() -> None:
    decoded = darkcomet.decode_config_resources(
        {
            "NETDATA": _encode(
                "one.example:1604|Two.example:1604|third.example :1604"
            ),
            "PWD": _encode("fixture-password"),
            "PDNS": _encode("one.example:8.8.8.8"),
            "DVCLAL": b"\xa2\x8c\xdf",
        }
    )
    endpoints, normalization = darkcomet.parse_netdata(decoded["NETDATA"])
    assert [item["endpoint"] for item in endpoints] == [
        "one.example:1604",
        "two.example:1604",
        "third.example:1604",
    ]
    assert normalization == [
        {
            "index": 1,
            "original_host": "Two.example",
            "normalized_host": "two.example",
            "reasons": ["case_normalized"],
        },
        {
            "index": 2,
            "original_host": "third.example ",
            "normalized_host": "third.example",
            "reasons": ["whitespace_removed"],
        },
    ]
    assert "DVCLAL" not in decoded


def test_netdata_normalization_reasons_are_specific() -> None:
    endpoints, normalization = darkcomet.parse_netdata(
        "  Mixed.Example. :1604"
    )
    assert [item["endpoint"] for item in endpoints] == [
        "mixed.example:1604"
    ]
    assert normalization == [
        {
            "index": 0,
            "original_host": "  Mixed.Example. ",
            "normalized_host": "mixed.example",
            "reasons": [
                "whitespace_removed",
                "trailing_dot_removed",
                "case_normalized",
            ],
        }
    ]


@pytest.mark.parametrize(
    "raw",
    [b"", b"0", b"GG", b"00" * (darkcomet.MAX_RESOURCE_SIZE + 1)],
    ids=["empty", "odd", "non_hex", "oversized"],
)
def test_decode_resource_rejects_invalid_or_oversized_hex(raw: bytes) -> None:
    with pytest.raises(darkcomet.DarkCometConfigError):
        darkcomet.decode_resource_value(raw)


def test_extract_promotes_only_decrypted_netdata(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    resources = {
        "NETDATA": _encode("one.example:1604|second.example :1700"),
        "PWD": _encode("fixture-password"),
        "PDNS": _encode("one.example:8.8.8.8"),
        "MUTEX": _encode("fixture_mutex"),
    }
    monkeypatch.setattr(darkcomet, "rcdata_resources", lambda _data: resources)
    data = b"MZ IDTYPE SERVER GetSIN infoes"
    result = darkcomet.extract(data, "terminal.exe")
    assert result["config"]["static_config_recovered"] is True
    assert result["config"]["endpoints"] == [
        "one.example:1604",
        "second.example:1700",
    ]
    assert result["config"]["sensitive_settings"]["values_published"] is False
    assert "pwd" not in result["config"]["settings"]
    profile = result["config"]["protocol_analysis"]
    assert profile["network_key"]["value_hex"] == b"#KCMDDC5#-".hex()
    assert profile["network_key"]["password_concatenated"] is False
    assert profile["protocol_markers"] == [
        "IDTYPE",
        "SERVER",
        "GetSIN",
        "infoes",
    ]
    assert all(
        item["confidence"] == "confirmed_static_config"
        for item in result["findings"]
    )


def test_dispatch_uses_dedicated_darkcomet_extractor() -> None:
    assert get_extractor("darkcomet") is darkcomet.extract
    assert get_extractor("dark-comet") is darkcomet.extract


def test_rcdata_reader_rejects_duplicate_languages(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    record = SimpleNamespace(OffsetToData=1, Size=2)
    language = SimpleNamespace(data=SimpleNamespace(struct=record))
    name = SimpleNamespace(
        name="NETDATA",
        struct=SimpleNamespace(Id=1),
        directory=SimpleNamespace(entries=[language, language]),
    )
    resource_type = SimpleNamespace(
        struct=SimpleNamespace(Id=darkcomet.RCDATA_TYPE_ID),
        directory=SimpleNamespace(entries=[name]),
    )
    image = SimpleNamespace(
        DIRECTORY_ENTRY_RESOURCE=SimpleNamespace(entries=[resource_type]),
        get_data=lambda *_args: b"00",
    )
    monkeypatch.setattr(darkcomet.pefile, "PE", lambda **_kwargs: image)
    with pytest.raises(darkcomet.DarkCometConfigError, match="language数"):
        darkcomet.rcdata_resources(b"MZ")
