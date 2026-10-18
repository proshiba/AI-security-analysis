"""Remcos配送script復元器が共有する非実行の検証処理。"""

from __future__ import annotations

import hashlib
import zlib

import pefile


def sha256_bytes(value: bytes) -> str:
    """byte列のSHA-256を16進文字列で返す。"""

    return hashlib.sha256(value).hexdigest()


def looks_like_powershell(value: bytes) -> bool:
    """UTF-8、可読率、PowerShell固有構造を同時に検証する。"""

    try:
        text = value.decode("utf-8-sig")
    except UnicodeDecodeError:
        return False
    if not text or "\x00" in text:
        return False
    printable = sum(char.isprintable() or char in "\r\n\t" for char in text)
    if printable / len(text) < 0.98:
        return False
    lowered = text.lower()
    markers = (
        "fromba`se64string",
        "frombase64string",
        "gzipstream",
        "createdecryptor",
        "new-object",
        "[byte[]]",
    )
    return (
        text.lstrip().startswith(("$", "try", "function", "param"))
        and sum(marker in lowered for marker in markers) >= 2
    )


def strict_gzip_decompress(value: bytes, maximum_output_bytes: int) -> bytes | None:
    """単一member、末尾dataなし、出力上限内のGZipだけを展開する。"""

    if not value.startswith(b"\x1f\x8b") or maximum_output_bytes < 1:
        return None
    inflater = zlib.decompressobj(16 + zlib.MAX_WBITS)
    try:
        output = inflater.decompress(value, maximum_output_bytes + 1)
        if len(output) > maximum_output_bytes:
            return None
        output += inflater.flush(maximum_output_bytes - len(output) + 1)
    except zlib.error:
        return None
    if (
        len(output) > maximum_output_bytes
        or not inflater.eof
        or inflater.unused_data
        or inflater.unconsumed_tail
    ):
        return None
    return output


def is_valid_pe(value: bytes) -> bool:
    """PE headerとsection tableを構文解析し、単なるMZ接頭辞を除外する。"""

    if len(value) < 0x100 or not value.startswith(b"MZ"):
        return False
    try:
        image = pefile.PE(data=value, fast_load=True)
        section_count = int(image.FILE_HEADER.NumberOfSections)
        optional_magic = int(image.OPTIONAL_HEADER.Magic)
        signature = int(image.NT_HEADERS.Signature)
        return (
            signature == 0x4550
            and optional_magic in {0x10B, 0x20B}
            and 1 <= section_count <= 96
            and len(image.sections) == section_count
        )
    except (AttributeError, ValueError, pefile.PEFormatError):
        return False
    finally:
        try:
            image.close()
        except (AttributeError, UnboundLocalError):
            pass
