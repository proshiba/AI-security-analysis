"""PureLogs managed resourceの文字列tableを実行せずに復元する。

対応するのは、静的解析で確認したXOR header、AES-256-CBC/PKCS#7、
4 byte wrapper付きraw Deflate、連続する.NET UTF-8文字列の組合せに限る。
CLRやCILは実行せず、未知のalgorithm、曖昧な複数候補、不完全なstream、
非canonicalな長さ表現はすべてfail-closedで拒否する。

復元した文字列には暗号化設定が含まれ得るため、このmoduleは文字列を
公開用evidenceへ含めない。呼出し側はfamily固有anchorと構造化設定を
別途相関し、生の鍵材料を出力しないこと。
"""

from __future__ import annotations

import hashlib
import re
import zlib
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

import dnfile
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from extractors.managed_pe import has_clr_metadata

if TYPE_CHECKING:
    from extractors.purelogs.yqty_resource import PureLogsYqtyResource

MAX_INPUT_BYTES = 32 << 20
MAX_RESOURCE_COUNT = 64
MAX_RESOURCE_BYTES = 4 << 20
MAX_TOTAL_RESOURCE_BYTES = 16 << 20
MAX_HEADER_BYTES = 4 << 10
MAX_HEADER_NAME_BYTES = 128
MAX_INFLATED_BYTES = 8 << 20
MAX_INFLATED_RATIO = 128
MAX_RECORD_COUNT = 4_096
MAX_RECORD_BYTES = 1 << 20
MAX_RECORD_TOTAL_BYTES = 8 << 20

_FAMILY_PATHS = frozenset({"/plugin", "/userinfo", "/filesearch/req", "/finish"})
_TABLE_KEY_RE = re.compile(rb"[A-Za-z0-9]{7}\Z")


class PureLogsResourceError(ValueError):
    """検証済みresource profileを外れた入力を表す。"""


@dataclass(frozen=True)
class PureLogsManagedResource:
    """秘密値を公開evidenceから分離した復元結果。"""

    records: tuple[str, ...] = field(repr=False)
    resource_sha256: str
    decrypted_sha256: str
    inflated_sha256: str
    protector_key_sha256: str
    header_identifier_sha256: str

    @property
    def text(self) -> str:
        """既存の文字列・protobuf抽出器へ渡す内部textを返す。"""

        return "\n".join(self.records)

    def public_evidence(self) -> dict[str, object]:
        """鍵や復元文字列を含まない公開可能な復元証拠だけを返す。"""

        return public_recovery_evidence(self)


def public_recovery_evidence(
    recovered: PureLogsManagedResource,
) -> dict[str, object]:
    """鍵や復元文字列を含まない固定schemaの証拠を返す。"""

    if not isinstance(recovered, PureLogsManagedResource):
        raise TypeError("PureLogs managed resource結果が不正です")
    return {
        "status": "recovered",
        "format": "xor_header_aes256_cbc_raw_deflate_dotnet_strings",
        "resource_sha256": recovered.resource_sha256,
        "decrypted_sha256": recovered.decrypted_sha256,
        "inflated_sha256": recovered.inflated_sha256,
        "protector_key_sha256": recovered.protector_key_sha256,
        "header_identifier_sha256": recovered.header_identifier_sha256,
        "record_count": len(recovered.records),
        "protector_key_material_published": False,
        "decoded_records_published": False,
        "sample_executed": False,
        "network_contacted": False,
    }


def _resolve_profile_overlap(
    legacy: PureLogsManagedResource | None,
    yqty: PureLogsYqtyResource | None,
) -> PureLogsManagedResource | PureLogsYqtyResource | None:
    """同一resource・同一recordへ収束するprofile重複だけを一候補へ畳む。"""

    if legacy is None:
        return yqty
    if yqty is None:
        return legacy
    # 異なるresource、outer復号結果、鍵、識別子、またはrecord列を同じ設定と
    # 推測してはならない。全identityが一致した場合だけ、Pn5 CIL形状と一意な
    # protobuf設定まで検証するYqTY側を、同じsemantic候補の強い証拠として返す。
    if (
        legacy.resource_sha256 != yqty.resource_sha256
        or legacy.decrypted_sha256 != yqty.decrypted_sha256
        or legacy.protector_key_sha256 != yqty.protector_key_sha256
        or legacy.header_identifier_sha256 != yqty.header_identifier_sha256
        or legacy.records != yqty.records
    ):
        return None
    return yqty


def _encode_7bit_integer(value: int) -> bytes:
    """canonical .NET 7-bit integerをtestを含む再検証用に生成する。"""

    if not 0 <= value <= 0x7FFFFFFF:
        raise PureLogsResourceError("7-bit integerがInt32範囲外です")
    output = bytearray()
    remaining = value
    while remaining >= 0x80:
        output.append((remaining & 0x7F) | 0x80)
        remaining >>= 7
    output.append(remaining)
    return bytes(output)


def _read_7bit_integer(data: bytes, offset: int, *, limit: int) -> tuple[int, int]:
    """境界内のcanonical .NET 7-bit integerを1個読む。"""

    if not 0 <= offset < limit <= len(data):
        raise PureLogsResourceError("7-bit integer開始位置が範囲外です")
    start = offset
    value = 0
    for index in range(5):
        if offset >= limit:
            raise PureLogsResourceError("7-bit integerが途中で終わっています")
        current = data[offset]
        offset += 1
        if index == 4 and current > 0x07:
            raise PureLogsResourceError("7-bit integerがInt32範囲外です")
        value |= (current & 0x7F) << (index * 7)
        if current < 0x80:
            if data[start:offset] != _encode_7bit_integer(value):
                raise PureLogsResourceError("7-bit integerが非canonicalです")
            return value, offset
    raise PureLogsResourceError("7-bit integerが終端されていません")


def _read_header_string(data: bytes, offset: int) -> tuple[bytes, int]:
    """header先頭の長さ付きUTF-8識別子を読む。"""

    length, offset = _read_7bit_integer(data, offset, limit=len(data))
    if not 1 <= length <= MAX_HEADER_NAME_BYTES or length > len(data) - offset:
        raise PureLogsResourceError("header識別子長が不正です")
    value = data[offset : offset + length]
    try:
        text = value.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise PureLogsResourceError("header識別子がUTF-8ではありません") from exc
    if not text.isprintable():
        raise PureLogsResourceError("header識別子に非表示文字があります")
    return value, offset + length


def _inflate_raw_deflate(data: bytes) -> bytes:
    """単一raw Deflate memberを展開率・出力長上限付きで復元する。"""

    if not data:
        raise PureLogsResourceError("raw Deflate入力が空です")
    output_limit = min(MAX_INFLATED_BYTES, len(data) * MAX_INFLATED_RATIO)
    if output_limit <= 0:
        raise PureLogsResourceError("raw Deflate出力上限が不正です")
    inflater = zlib.decompressobj(wbits=-zlib.MAX_WBITS)
    try:
        output = inflater.decompress(data, output_limit + 1)
        if len(output) > output_limit or inflater.unconsumed_tail:
            raise PureLogsResourceError("raw Deflate出力が安全上限を超えました")
        output += inflater.flush(output_limit + 1 - len(output))
    except zlib.error as exc:
        raise PureLogsResourceError("raw Deflate streamが不正です") from exc
    if len(output) > output_limit:
        raise PureLogsResourceError("raw Deflate出力が安全上限を超えました")
    if not inflater.eof or inflater.unused_data or inflater.unconsumed_tail:
        raise PureLogsResourceError("raw Deflate stream境界が一意ではありません")
    return output


def _parse_string_table(data: bytes) -> tuple[str, ...]:
    """2 byte wrapper、7 byte table key、連続.NET文字列を厳格に読む。"""

    if len(data) < 10 or not _TABLE_KEY_RE.fullmatch(data[2:9]):
        raise PureLogsResourceError("PureLogs文字列table headerが不正です")
    offset = 9
    total = 0
    records: list[str] = []
    while offset < len(data):
        if len(records) >= MAX_RECORD_COUNT:
            raise PureLogsResourceError("PureLogs文字列件数が安全上限を超えました")
        length, offset = _read_7bit_integer(data, offset, limit=len(data))
        if length > MAX_RECORD_BYTES or length > len(data) - offset:
            raise PureLogsResourceError("PureLogs文字列長が不正です")
        total += length
        if total > MAX_RECORD_TOTAL_BYTES:
            raise PureLogsResourceError("PureLogs文字列総量が安全上限を超えました")
        raw = data[offset : offset + length]
        offset += length
        try:
            records.append(raw.decode("utf-8"))
        except UnicodeDecodeError as exc:
            raise PureLogsResourceError("PureLogs文字列がUTF-8ではありません") from exc
    if not records:
        raise PureLogsResourceError("PureLogs文字列tableが空です")
    return tuple(records)


def decode_purelogs_resource_blob(blob: bytes) -> PureLogsManagedResource:
    """単一resource blobを検証済みPureLogs文字列tableとして復元する。"""

    if not isinstance(blob, bytes):
        raise PureLogsResourceError("resource blobはbytesである必要があります")
    if not 0 < len(blob) <= MAX_RESOURCE_BYTES or len(blob) < 2:
        raise PureLogsResourceError("resource blob長が安全上限外です")

    header_length = int.from_bytes(blob[:2], "little")
    if not 16 <= header_length <= MAX_HEADER_BYTES:
        raise PureLogsResourceError("XOR header長が安全上限外です")
    iv_length_offset = 2 + header_length
    if iv_length_offset >= len(blob):
        raise PureLogsResourceError("XOR headerが途中で終わっています")
    iv_length = blob[iv_length_offset]
    iv_offset = iv_length_offset + 1
    ciphertext_offset = iv_offset + iv_length
    if iv_length != 16 or ciphertext_offset > len(blob):
        raise PureLogsResourceError("AES-CBC IV長または境界が不正です")
    iv = blob[iv_offset:ciphertext_offset]
    encrypted_header = blob[2:iv_length_offset]
    header = bytes(
        value ^ iv[index % iv_length] for index, value in enumerate(encrypted_header)
    )

    identifier, offset = _read_header_string(header, 0)
    if len(header) - offset < 4:
        raise PureLogsResourceError("暗号profile headerが途中で終わっています")
    flags, selector, key_source, key_length = header[offset : offset + 4]
    offset += 4
    if flags != 3 or selector != 2 or key_source >= 64 or key_length != 32:
        raise PureLogsResourceError("未対応の暗号profileです")
    if len(header) - offset != key_length:
        raise PureLogsResourceError("AES鍵長またはheader終端が不正です")
    key = header[offset:]

    ciphertext = blob[ciphertext_offset:]
    if not ciphertext or len(ciphertext) % 16:
        raise PureLogsResourceError("AES-CBC暗号文長が不正です")
    try:
        decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
        padded = decryptor.update(ciphertext) + decryptor.finalize()
    except ValueError as exc:
        raise PureLogsResourceError("AES-CBC復号に失敗しました") from exc
    padding = padded[-1]
    if not 1 <= padding <= 16 or padded[-padding:] != bytes((padding,)) * padding:
        raise PureLogsResourceError("AES-CBC PKCS#7 paddingが不正です")
    clear = padded[:-padding]
    if len(clear) < 5:
        raise PureLogsResourceError("復号済みDeflate wrapperが短すぎます")
    inflated = _inflate_raw_deflate(clear[4:])
    records = _parse_string_table(inflated)

    return PureLogsManagedResource(
        records=records,
        resource_sha256=hashlib.sha256(blob).hexdigest(),
        decrypted_sha256=hashlib.sha256(clear).hexdigest(),
        inflated_sha256=hashlib.sha256(inflated).hexdigest(),
        protector_key_sha256=hashlib.sha256(key).hexdigest(),
        header_identifier_sha256=hashlib.sha256(identifier).hexdigest(),
    )


def recover_purelogs_managed_strings(
    data: bytes,
) -> PureLogsManagedResource | PureLogsYqtyResource | None:
    """managed PE内で一意なPureLogs文字列resourceだけを返す。"""

    if (
        not isinstance(data, bytes)
        or not 0 < len(data) <= MAX_INPUT_BYTES
        or not has_clr_metadata(data)
    ):
        return None
    try:
        image = dnfile.dnPE(data=data, clr_lazy_load=False)
        resources = list(getattr(getattr(image, "net", None), "resources", ()) or ())
    except Exception:  # noqa: BLE001 - 壊れたmetadataは候補なしとして拒否する
        return None
    if len(resources) > MAX_RESOURCE_COUNT:
        return None

    candidates: list[PureLogsManagedResource] = []
    total = 0
    for item in resources:
        blob = getattr(item, "data", None)
        if not isinstance(blob, bytes):
            continue
        if not 0 < len(blob) <= MAX_RESOURCE_BYTES:
            return None
        total += len(blob)
        if total > MAX_TOTAL_RESOURCE_BYTES:
            return None
        try:
            recovered = decode_purelogs_resource_blob(blob)
        except PureLogsResourceError:
            continue
        anchors = _FAMILY_PATHS.intersection(
            value.casefold() for value in recovered.records
        )
        if len(anchors) >= 3:
            candidates.append(recovered)
            if len(candidates) > 1:
                return None
    legacy = candidates[0] if len(candidates) == 1 else None

    # YqTY/Pn5はclear[4:]固定の既存profileとは異なる。Pn5 CIL形状、
    # 上限付き境界探索、完全なstring table、固有path、一意なprotobuf設定を
    # 独立moduleで全て確認し、両profileが同時成立する曖昧入力は拒否する。
    from extractors.purelogs.yqty_resource import recover_purelogs_yqty_strings

    yqty = recover_purelogs_yqty_strings(data)
    return _resolve_profile_overlap(legacy, yqty)


__all__ = [
    "PureLogsManagedResource",
    "PureLogsResourceError",
    "decode_purelogs_resource_blob",
    "public_recovery_evidence",
    "recover_purelogs_managed_strings",
]
