#!/usr/bin/env python3
"""Office既定パスワードの暗号化OOXMLを実行せず有界に復号する。

このモジュールはOLE container内の ``EncryptionInfo`` と
``EncryptedPackage`` を先に検証し、Microsoft Officeで用いられる既定
パスワード ``VelvetSweatshop`` だけを試す。辞書探索、検体実行、Office起動、
外部通信は行わない。復号結果はOOXML ZIPの最小構造を確認した場合だけ、後続の
固定点解析へ渡す。
"""

from __future__ import annotations

import hashlib
import io
import zipfile
from dataclasses import dataclass

import msoffcrypto
import olefile
from msoffcrypto import exceptions as msoffcrypto_exceptions

OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
DEFAULT_PASSWORD_PROFILE = "office_default_velvet_sweatshop"
_DEFAULT_PASSWORD = "VelvetSweatshop"
MAX_INPUT_SIZE = 64 * 1024 * 1024
MAX_ENCRYPTION_INFO_SIZE = 1024 * 1024
MAX_DECRYPTED_SIZE = 128 * 1024 * 1024
MAX_ZIP_MEMBERS = 4096


class OfficeEncryptedPackageError(ValueError):
    """暗号化Office containerの安全境界違反を表す。"""


class _BoundedBytesIO(io.BytesIO):
    """書込み総量が上限を超える前に停止するmemory sink。"""

    def __init__(self, maximum_size: int) -> None:
        super().__init__()
        self._maximum_size = maximum_size

    def write(self, value: bytes | bytearray) -> int:
        if self.tell() + len(value) > self._maximum_size:
            raise OfficeEncryptedPackageError("復号OOXMLがsize上限を超えています")
        return super().write(value)


@dataclass(frozen=True)
class _OlePreflight:
    """公開可能な暗号化Office streamの事前検証結果。"""

    encryption_info_size: int
    encrypted_package_size: int
    stream_count: int


def _ole_preflight(data: bytes) -> _OlePreflight | None:
    """暗号化OOXMLに必要な2 streamを名前とsizeだけで検証する。"""

    if not data.startswith(OLE_MAGIC):
        return None
    try:
        with olefile.OleFileIO(io.BytesIO(data)) as container:
            paths = container.listdir(streams=True, storages=False)
            canonical = {tuple(str(part) for part in path): path for path in paths}
            info_path = canonical.get(("EncryptionInfo",))
            package_path = canonical.get(("EncryptedPackage",))
            if info_path is None or package_path is None:
                return None
            info_size = int(container.get_size(info_path))
            package_size = int(container.get_size(package_path))
    except (OSError, ValueError, olefile.OleFileError) as exc:
        raise OfficeEncryptedPackageError(
            f"OLE containerを検証できません: {type(exc).__name__}"
        ) from exc

    if not 1 <= info_size <= MAX_ENCRYPTION_INFO_SIZE:
        raise OfficeEncryptedPackageError("EncryptionInfoのsizeが上限外です")
    # EncryptedPackageは先頭に平文長を持つため、復号上限より小幅に大きくなり得る。
    if not 8 <= package_size <= MAX_DECRYPTED_SIZE + 4096:
        raise OfficeEncryptedPackageError("EncryptedPackageのsizeが上限外です")
    return _OlePreflight(info_size, package_size, len(paths))


def _validate_ooxml(data: bytes) -> tuple[int, str]:
    """復号byte列が最小OOXML構造を持つZIPであることを確認する。"""

    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            infos = archive.infolist()
            if not infos or len(infos) > MAX_ZIP_MEMBERS:
                raise OfficeEncryptedPackageError(
                    "復号OOXMLのmember数が許容範囲外です"
                )
            names = [item.filename for item in infos]
            if len(names) != len(set(names)):
                raise OfficeEncryptedPackageError(
                    "復号OOXMLに重複member名があります"
                )
            if "[Content_Types].xml" not in names or "_rels/.rels" not in names:
                raise OfficeEncryptedPackageError(
                    "復号結果にOOXML必須memberがありません"
                )
            document_type = (
                "xlsx"
                if "xl/workbook.xml" in names
                else "docx"
                if "word/document.xml" in names
                else "pptx"
                if "ppt/presentation.xml" in names
                else "ooxml"
            )
            return len(infos), document_type
    except zipfile.BadZipFile as exc:
        raise OfficeEncryptedPackageError(
            "復号結果が有効なOOXML ZIPではありません"
        ) from exc


def recover_default_password_ooxml(
    data: bytes,
    *,
    maximum_input_size: int = MAX_INPUT_SIZE,
    maximum_decrypted_size: int = MAX_DECRYPTED_SIZE,
) -> tuple[dict[str, object], list[tuple[str, bytes]]]:
    """Office既定パスワードに一致する暗号化OOXMLだけを復元する。"""

    if type(maximum_input_size) is not int or not 1 <= maximum_input_size <= MAX_INPUT_SIZE:
        raise OfficeEncryptedPackageError("入力size上限が不正です")
    if (
        type(maximum_decrypted_size) is not int
        or not 1 <= maximum_decrypted_size <= MAX_DECRYPTED_SIZE
    ):
        raise OfficeEncryptedPackageError("復号size上限が不正です")
    if not data.startswith(OLE_MAGIC):
        return {"status": "not_office_encrypted_ooxml"}, []
    if not 1 <= len(data) <= maximum_input_size:
        return {
            "status": "input_size_blocked",
            "input_size": len(data),
            "maximum_input_size": maximum_input_size,
            "executed": False,
            "network_contacted": False,
        }, []

    try:
        preflight = _ole_preflight(data)
    except OfficeEncryptedPackageError as exc:
        return {
            "status": "preflight_rejected",
            "reason": str(exc),
            "executed": False,
            "network_contacted": False,
        }, []
    if preflight is None:
        return {"status": "not_office_encrypted_ooxml"}, []

    try:
        office = msoffcrypto.OfficeFile(io.BytesIO(data))
        if not office.is_encrypted():
            return {
                "status": "encryption_metadata_inconsistent",
                "executed": False,
                "network_contacted": False,
            }, []
        office.load_key(password=_DEFAULT_PASSWORD, verify_password=True)
        output = _BoundedBytesIO(maximum_decrypted_size)
        office.decrypt(output)
        plaintext = output.getvalue()
        member_count, document_type = _validate_ooxml(plaintext)
    except msoffcrypto_exceptions.InvalidKeyError:
        return {
            "status": "default_password_not_matched",
            "password_profile": DEFAULT_PASSWORD_PROFILE,
            "password_value_published": False,
            "dictionary_search_performed": False,
            "executed": False,
            "network_contacted": False,
        }, []
    except (
        msoffcrypto_exceptions.DecryptionError,
        msoffcrypto_exceptions.FileFormatError,
        msoffcrypto_exceptions.ParseError,
        OfficeEncryptedPackageError,
        OSError,
        ValueError,
    ) as exc:
        return {
            "status": "decrypt_or_validation_failed",
            "error_type": type(exc).__name__,
            "password_profile": DEFAULT_PASSWORD_PROFILE,
            "password_value_published": False,
            "dictionary_search_performed": False,
            "executed": False,
            "network_contacted": False,
        }, []

    return {
        "status": "default_password_ooxml_recovered",
        "password_profile": DEFAULT_PASSWORD_PROFILE,
        "password_value_published": False,
        "dictionary_search_performed": False,
        "input_size": len(data),
        "input_sha256": hashlib.sha256(data).hexdigest(),
        "encryption_info_size": preflight.encryption_info_size,
        "encrypted_package_size": preflight.encrypted_package_size,
        "ole_stream_count": preflight.stream_count,
        "decrypted_size": len(plaintext),
        "decrypted_sha256": hashlib.sha256(plaintext).hexdigest(),
        "ooxml_member_count": member_count,
        "document_type": document_type,
        "executed": False,
        "network_contacted": False,
        "office_application_started": False,
    }, [(f"office-decrypted-{document_type}", plaintext)]
