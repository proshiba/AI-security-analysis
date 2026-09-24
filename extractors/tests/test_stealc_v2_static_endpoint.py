"""StealC v2系のC2ベースURL限定復元を合成データで検証する。"""

from __future__ import annotations

import base64

from extractors.stealc.v2_memory import LocatedString, rc4
from extractors.stealc.v2_static_endpoint import recover_from_strings


def _fixture(
    *,
    include_second_url: bool = False,
    omit_protocol: bool = False,
    count: int = 65,
) -> list[LocatedString]:
    key = b"fixtureKey42"
    clear = [
        "http://192.0.2.10",
        "create",
        "upload_file",
        "loader",
        "done",
        "access_token",
        "build",
        "type",
        "Login Data",
        "Local State",
        "Steam",
    ]
    if include_second_url:
        clear.append("http://192.0.2.11")
    if omit_protocol:
        clear.remove("done")
        clear.remove("loader")
    clear.extend(f"fixture_{index}" for index in range(count))
    values = [LocatedString(100, key)]
    offset = 128
    for item in clear:
        value = base64.b64encode(rc4(item.encode("ascii"), key))
        values.append(LocatedString(offset, value))
        offset += len(value) + 4
    return values


def test_recovers_only_c2_base_with_independent_markers() -> None:
    profile = recover_from_strings(_fixture(), core_role_confirmed=True)
    assert profile is not None
    public = profile.public_dict()
    assert public["c2_base_url"] == "http://192.0.2.10"
    assert public["gate_path"] is None
    assert public["traffic_key_recovered"] is False
    assert public["table_count"] >= 64
    assert public["decoded_count"] >= 60
    assert "fixtureKey42" not in str(public)


def test_rejects_unconfirmed_core_or_missing_protocol_markers() -> None:
    assert recover_from_strings(_fixture(), core_role_confirmed=False) is None
    assert (
        recover_from_strings(
            _fixture(omit_protocol=True), core_role_confirmed=True
        )
        is None
    )


def test_rejects_conflicting_urls_or_short_table() -> None:
    assert (
        recover_from_strings(
            _fixture(include_second_url=True), core_role_confirmed=True
        )
        is None
    )
    assert recover_from_strings(_fixture(count=10), core_role_confirmed=True) is None
