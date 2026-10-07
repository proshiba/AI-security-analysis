"""暗号化OOXML既定パスワード経路のfail-closed回帰テスト。"""

from __future__ import annotations

import io
import os
import zipfile
from pathlib import Path

import pytest
from msoffcrypto import exceptions as msoffcrypto_exceptions

from unpackers import office_encrypted_package as office
from unpackers import static_unpacker


def _minimal_ooxml() -> bytes:
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(
            "[Content_Types].xml",
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>',
        )
        archive.writestr(
            "_rels/.rels",
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>',
        )
        archive.writestr("xl/workbook.xml", "<workbook/>")
    return stream.getvalue()


class _FakeEncryptedOffice:
    """実OfficeやCLRを起動しないmsoffcrypto境界fixture。"""

    expected_password: str | None = None
    plaintext = _minimal_ooxml()

    def __init__(self, _source: io.BytesIO) -> None:
        pass

    def is_encrypted(self) -> bool:
        return True

    def load_key(self, *, password: str, verify_password: bool) -> None:
        assert verify_password is True
        if self.expected_password is not None and password != self.expected_password:
            raise msoffcrypto_exceptions.InvalidKeyError("fixture mismatch")

    def decrypt(self, output: io.BytesIO) -> None:
        output.write(self.plaintext)


def _preflight(_data: bytes) -> office._OlePreflight:
    return office._OlePreflight(224, 4096, 6)


def test_default_password_ooxml_is_recovered_without_publishing_password(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(office, "_ole_preflight", _preflight)
    monkeypatch.setattr(office.msoffcrypto, "OfficeFile", _FakeEncryptedOffice)

    report, artifacts = office.recover_default_password_ooxml(office.OLE_MAGIC + b"A")

    assert report["status"] == "default_password_ooxml_recovered"
    assert report["password_profile"] == office.DEFAULT_PASSWORD_PROFILE
    assert report["password_value_published"] is False
    assert report["dictionary_search_performed"] is False
    assert report["document_type"] == "xlsx"
    assert report["executed"] is False
    assert report["network_contacted"] is False
    assert artifacts == [("office-decrypted-xlsx", _FakeEncryptedOffice.plaintext)]
    assert "VelvetSweatshop" not in str(report)


def test_wrong_default_password_and_size_limit_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class WrongPassword(_FakeEncryptedOffice):
        expected_password = "different"

    monkeypatch.setattr(office, "_ole_preflight", _preflight)
    monkeypatch.setattr(office.msoffcrypto, "OfficeFile", WrongPassword)
    report, artifacts = office.recover_default_password_ooxml(office.OLE_MAGIC + b"A")
    assert report["status"] == "default_password_not_matched"
    assert artifacts == []

    blocked, blocked_artifacts = office.recover_default_password_ooxml(
        office.OLE_MAGIC + b"A",
        maximum_input_size=len(office.OLE_MAGIC),
    )
    assert blocked["status"] == "input_size_blocked"
    assert blocked_artifacts == []


def test_decrypted_output_limit_and_invalid_ooxml_are_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(office, "_ole_preflight", _preflight)
    monkeypatch.setattr(office.msoffcrypto, "OfficeFile", _FakeEncryptedOffice)
    report, artifacts = office.recover_default_password_ooxml(
        office.OLE_MAGIC + b"A",
        maximum_decrypted_size=64,
    )
    assert report["status"] == "decrypt_or_validation_failed"
    assert report["error_type"] == "OfficeEncryptedPackageError"
    assert artifacts == []

    class InvalidOoxml(_FakeEncryptedOffice):
        plaintext = b"PK-not-a-valid-archive"

    monkeypatch.setattr(office.msoffcrypto, "OfficeFile", InvalidOoxml)
    report, artifacts = office.recover_default_password_ooxml(office.OLE_MAGIC + b"A")
    assert report["status"] == "decrypt_or_validation_failed"
    assert artifacts == []


def test_static_unpacker_routes_decrypted_ooxml_as_recursive_layer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plaintext = _minimal_ooxml()
    monkeypatch.setattr(
        static_unpacker,
        "recover_default_password_ooxml",
        lambda *_args, **_kwargs: (
            {"status": "default_password_ooxml_recovered"},
            [("office-decrypted-xlsx", plaintext)],
        ),
    )
    monkeypatch.setattr(
        static_unpacker,
        "recover_ole_streams",
        lambda *_args, **_kwargs: ({"status": "no_artifact_recovered"}, []),
    )

    report, artifacts = static_unpacker.unpack_bytes(
        office.OLE_MAGIC + b"fixture",
        "encrypted.xlsx",
    )

    assert report["office_encrypted_package"]["status"] == (
        "default_password_ooxml_recovered"
    )
    assert ("office-decrypted-xlsx", plaintext) in artifacts


@pytest.mark.skipif(
    "FORMBOOK_XLOADER25_ENCRYPTED_XLSX" not in os.environ,
    reason="repo外のXLoader 2.5暗号化XLSX実検体が未指定です",
)
def test_private_xloader25_encrypted_xlsx_uses_default_password() -> None:
    path = Path(os.environ["FORMBOOK_XLOADER25_ENCRYPTED_XLSX"])
    data = path.read_bytes()
    report, artifacts = office.recover_default_password_ooxml(data)

    assert report["status"] == "default_password_ooxml_recovered"
    assert report["document_type"] == "xlsx"
    assert artifacts and artifacts[0][1].startswith(b"PK")
    assert report["executed"] is False
    assert report["network_contacted"] is False
