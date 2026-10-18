"""PureLogs managed resource静的復元器の境界テスト。"""

from __future__ import annotations

import hashlib
import json
import zlib
from dataclasses import replace
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from extractors.purelogs import managed_resource, yqty_resource


def _seven_bit(value: int) -> bytes:
    output = bytearray()
    while value >= 0x80:
        output.append((value & 0x7F) | 0x80)
        value >>= 7
    output.append(value)
    return bytes(output)


def _string_table(records: tuple[str, ...]) -> bytes:
    output = bytearray(b"\x11\x9bFixture")
    for value in records:
        encoded = value.encode("utf-8")
        output.extend(_seven_bit(len(encoded)))
        output.extend(encoded)
    return bytes(output)


def _resource(
    records: tuple[str, ...],
    *,
    table: bytes | None = None,
    trailing_deflate: bytes = b"",
) -> tuple[bytes, bytes]:
    key = bytes(range(32))
    iv = bytes(range(16, 32))
    identifier = b"fixture-profile"
    header = (
        _seven_bit(len(identifier)) + identifier + bytes((3, 2, 29, len(key))) + key
    )
    encrypted_header = bytes(
        value ^ iv[index % len(iv)] for index, value in enumerate(header)
    )
    compressor = zlib.compressobj(level=9, wbits=-zlib.MAX_WBITS)
    packed = compressor.compress(table or _string_table(records)) + compressor.flush()
    clear = b"\x01\x02\x03\x04" + packed + trailing_deflate
    padding = 16 - (len(clear) % 16)
    padded = clear + bytes((padding,)) * padding
    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    resource = (
        len(header).to_bytes(2, "little")
        + encrypted_header
        + bytes((len(iv),))
        + iv
        + ciphertext
    )
    return resource, key


def test_decodes_reviewed_aes_deflate_dotnet_string_profile() -> None:
    """既知profileを復元し、公開evidenceへ鍵や文字列を含めない。"""

    records = (
        "/plugin",
        "/userinfo",
        "/filesearch/req",
        "/finish",
        "X-Api-Key",
    )
    resource, key = _resource(records)

    result = managed_resource.decode_purelogs_resource_blob(resource)

    assert result.records == records
    assert result.public_evidence()["record_count"] == len(records)
    published = json.dumps(result.public_evidence(), sort_keys=True)
    assert key.hex() not in published
    assert "X-Api-Key" not in published
    assert "X-Api-Key" not in repr(result)


def test_rejects_truncated_ciphertext_and_noncanonical_record_length() -> None:
    """不完全な暗号文と非canonicalな.NET長をfail-closedで拒否する。"""

    resource, _ = _resource(("/plugin",))
    with pytest.raises(
        managed_resource.PureLogsResourceError,
        match="暗号文長",
    ):
        managed_resource.decode_purelogs_resource_blob(resource[:-1])

    malformed_table = b"\x11\x9bFixture\x81\x00A"
    malformed, _ = _resource((), table=malformed_table)
    with pytest.raises(
        managed_resource.PureLogsResourceError,
        match="非canonical",
    ):
        managed_resource.decode_purelogs_resource_blob(malformed)


def test_rejects_trailing_deflate_and_output_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """複数member相当の余剰byteと展開上限超過を拒否する。"""

    trailing, _ = _resource(("/plugin",), trailing_deflate=b"\x00")
    with pytest.raises(
        managed_resource.PureLogsResourceError,
        match="stream境界",
    ):
        managed_resource.decode_purelogs_resource_blob(trailing)

    resource, _ = _resource(("A" * 256,))
    monkeypatch.setattr(managed_resource, "MAX_INFLATED_BYTES", 32)
    with pytest.raises(
        managed_resource.PureLogsResourceLimitError,
        match="安全上限",
    ):
        managed_resource.decode_purelogs_resource_blob(resource)


def test_non_managed_input_is_not_a_candidate() -> None:
    """単なるMZ風byte列をmanaged resource候補へ昇格させない。"""

    assert managed_resource.recover_purelogs_managed_strings(b"MZ" + b"A" * 512) is None


def _bind_managed_image(
    monkeypatch: pytest.MonkeyPatch,
    blobs: tuple[bytes, ...],
) -> object:
    """dnfileを起動せず合成resource一覧をmanaged scannerへ渡す。"""

    image = SimpleNamespace(
        net=SimpleNamespace(
            resources=tuple(SimpleNamespace(data=blob) for blob in blobs)
        )
    )
    monkeypatch.setattr(managed_resource, "has_clr_metadata", lambda _data: True)
    monkeypatch.setattr(managed_resource.dnfile, "dnPE", lambda **_kwargs: image)
    return image


def test_resource_absence_keeps_raw_only_path_available(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """managed resourceが存在しないときは正常のno-matchとして返す。"""

    _bind_managed_image(monkeypatch, ())

    assert managed_resource.recover_purelogs_managed_strings(b"MZ fixture") is None


def test_metadata_parse_failure_is_not_collapsed_to_absence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CLR metadata解析失敗をresource不在として扱わない。"""

    monkeypatch.setattr(managed_resource, "has_clr_metadata", lambda _data: True)
    monkeypatch.setattr(
        managed_resource.dnfile,
        "dnPE",
        lambda **_kwargs: (_ for _ in ()).throw(ValueError("broken metadata")),
    )

    with pytest.raises(managed_resource.PureLogsResourceScanIncomplete):
        managed_resource.recover_purelogs_managed_strings(b"MZ fixture")


def test_resource_count_limit_has_distinct_failure_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """resource件数上限を通常のno-matchへ降格しない。"""

    _bind_managed_image(monkeypatch, (b"not-a-candidate",))
    monkeypatch.setattr(managed_resource, "MAX_RESOURCE_COUNT", 0)

    with pytest.raises(managed_resource.PureLogsResourceLimitError):
        managed_resource.recover_purelogs_managed_strings(b"MZ fixture")


def test_committed_resource_parse_failure_is_incomplete(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """outer profile一致後のparse失敗をresource不在として扱わない。"""

    resource, _key = _resource(("/plugin", "/userinfo", "/filesearch/req", "/finish"))
    malformed = resource[:-1]
    image = _bind_managed_image(monkeypatch, (malformed,))
    failure_hash = hashlib.sha256(malformed).hexdigest()
    monkeypatch.setattr(
        yqty_resource,
        "_scan_purelogs_yqty_candidates",
        lambda _image, _data, _resources: yqty_resource._YqtyCandidateScan(
            None,
            (failure_hash,),
            1,
        ),
    )

    assert image.net.resources
    with pytest.raises(managed_resource.PureLogsResourceScanIncomplete):
        managed_resource.recover_purelogs_managed_strings(b"MZ fixture")


def test_multiple_legacy_resource_candidates_are_conflicting(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """複数の正常resource候補を1件目の成功で隠蔽しない。"""

    records = ("/plugin", "/userinfo", "/filesearch/req", "/finish")
    first, _key = _resource(records)
    second, _key = _resource(records + ("second",))
    _bind_managed_image(monkeypatch, (first, second))

    with pytest.raises(managed_resource.PureLogsResourceConflictError):
        managed_resource.recover_purelogs_managed_strings(b"MZ fixture")


def _overlapping_profile_results() -> tuple[
    managed_resource.PureLogsManagedResource,
    yqty_resource.PureLogsYqtyResource,
]:
    """同じouter resourceとrecord列へ収束する2 profileを生成する。"""

    records = ("/plugin", "/userinfo", "/filesearch/req", "/finish", "config")
    common = {
        "records": records,
        "resource_sha256": "1" * 64,
        "decrypted_sha256": "2" * 64,
        "protector_key_sha256": "3" * 64,
        "header_identifier_sha256": "4" * 64,
    }
    legacy = managed_resource.PureLogsManagedResource(
        **common,
        inflated_sha256="5" * 64,
    )
    yqty = yqty_resource.PureLogsYqtyResource(
        **common,
        inflated_sha256="6" * 64,
        configuration_fingerprint_sha256="7" * 64,
        compressed_offset=1,
        string_table_offset=12,
        boundary_candidate_count=1,
        equivalent_boundary_count=3,
        pn5_profile_count=1,
    )
    return legacy, yqty


def test_collapses_identical_legacy_and_yqty_profile_overlap() -> None:
    """同一resource・同一recordへ収束するresync重複はYqTY証拠へ畳む。"""

    legacy, yqty = _overlapping_profile_results()

    assert managed_resource._resolve_profile_overlap(legacy, yqty) is yqty


@pytest.mark.parametrize(
    ("field", "replacement"),
    (
        ("resource_sha256", "8" * 64),
        ("decrypted_sha256", "8" * 64),
        ("protector_key_sha256", "8" * 64),
        ("header_identifier_sha256", "8" * 64),
        ("records", ("/plugin", "/userinfo", "/filesearch/req", "/finish", "other")),
    ),
)
def test_rejects_nonidentical_legacy_and_yqty_profile_overlap(
    field: str,
    replacement: object,
) -> None:
    """outer identityまたは完全record列が異なるprofile競合を拒否する。"""

    legacy, yqty = _overlapping_profile_results()
    conflicting = replace(yqty, **{field: replacement})

    with pytest.raises(managed_resource.PureLogsResourceConflictError):
        managed_resource._resolve_profile_overlap(legacy, conflicting)
