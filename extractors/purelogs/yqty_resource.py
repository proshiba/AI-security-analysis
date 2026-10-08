"""YqTY/Pn5系PureLogs文字列resourceを実行せずに復元する。

このprofileは、review済みPn5型のCIL形状、AES-256-CBC outer wrapper、
先頭64 byte以内で一意になる完全なraw Deflate member、4 byte wrapper後の
canonical .NET UTF-8文字列、PureLogs固有path、かつ一意なprotobuf設定を
すべて要求する。候補境界の総当たりだけでは受理せず、検体、CLR、CIL、
復元byteを実行しない。鍵materialや復元文字列は公開evidenceへ含めない。
"""

from __future__ import annotations

import hashlib
import json
import zlib
from dataclasses import dataclass, field

import dnfile
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from dncil.cil.body.reader import read_method_body_from_bytes

from extractors.managed_pe import has_clr_metadata

MAX_INPUT_BYTES = 32 << 20
MAX_RESOURCE_COUNT = 64
MAX_RESOURCE_BYTES = 4 << 20
MAX_TOTAL_RESOURCE_BYTES = 16 << 20
MAX_HEADER_BYTES = 4 << 10
MAX_IDENTIFIER_BYTES = 128
MAX_BOUNDARY_OFFSET = 64
MAX_STRING_TABLE_OFFSET = 64
MAX_INFLATED_BYTES = 8 << 20
MAX_INFLATED_RATIO = 128
# 境界探索全体のworkを個別stream上限とは別に制限する。review済みYqTYは
# clear約1.4 KiB、展開約2.5 KiBであり、以下は十分な余裕を保ちつつ、
# adversarial resourceで65経路すべてを最大展開・全offset parseする事態を防ぐ。
MAX_BOUNDARY_TOTAL_COMPRESSED_BYTES = 4 << 20
MAX_BOUNDARY_TOTAL_INFLATED_BYTES = 64 << 20
MAX_BOUNDARY_TOTAL_PARSE_BYTES = 64 << 20
MAX_BOUNDARY_PARSE_ATTEMPTS = (MAX_BOUNDARY_OFFSET + 1) * (MAX_STRING_TABLE_OFFSET + 1)
MAX_BOUNDARY_CONFIGURATION_ATTEMPTS = 128
MAX_BOUNDARY_CANDIDATES = 512
MAX_RECORD_COUNT = 4_096
MAX_RECORD_BYTES = 1 << 20
MAX_RECORD_TOTAL_BYTES = 8 << 20
MAX_METHOD_COUNT = 4_096
MAX_METHOD_BYTES = 256 << 10
MAX_METHOD_INSTRUCTIONS = 20_000
# review済みterminalはflattened CILを含み109,289命令になる。入力・MethodDef・
# method単位上限とは別に、128 Ki命令でassembly全体をfail-closedに制限する。
MAX_TOTAL_INSTRUCTIONS = 128 << 10

_REQUIRED_PATHS = frozenset({"/plugin", "/userinfo", "/filesearch/req", "/finish"})
_PN5_READ_SIGNATURE = bytes.fromhex("2003081d050808")
_PN5_BOOL_SIGNATURE = bytes.fromhex("200002")


class PureLogsYqtyError(ValueError):
    """YQTY/Pn5 profileの不一致、曖昧性、上限超過を表す。"""


@dataclass(frozen=True)
class _MethodShape:
    """公開名に依存しない有界CIL method形状。"""

    token: int
    owner_token: int
    name: str
    signature: bytes
    opcodes: tuple[str, ...]
    integer_constants: tuple[int, ...]
    method_operands: tuple[int, ...]


@dataclass(frozen=True)
class PureLogsYqtyResource:
    """秘密値と復元文字列を公開evidenceから分離した復元結果。"""

    records: tuple[str, ...] = field(repr=False)
    resource_sha256: str
    decrypted_sha256: str
    inflated_sha256: str
    protector_key_sha256: str
    header_identifier_sha256: str
    configuration_fingerprint_sha256: str
    compressed_offset: int
    string_table_offset: int
    boundary_candidate_count: int
    equivalent_boundary_count: int
    pn5_profile_count: int

    @property
    def text(self) -> str:
        """既存のPureLogs family/config抽出器へ渡す内部textを返す。"""

        return "\n".join(self.records)

    def public_evidence(self) -> dict[str, object]:
        """鍵や復元文字列を含まない公開可能な構造証拠だけを返す。"""

        return public_recovery_evidence(self)


def public_recovery_evidence(
    recovered: PureLogsYqtyResource,
) -> dict[str, object]:
    """YqTY復元結果から公開可能な固定schemaだけを返す。"""

    if not isinstance(recovered, PureLogsYqtyResource):
        raise TypeError("PureLogs YqTY resource結果が不正です")
    return {
        "status": "recovered",
        "format": ("yqty_aes256_cbc_validated_boundary_raw_deflate_dotnet_strings"),
        "profile": "pn5_validated_boundary_search_v1",
        "resource_sha256": recovered.resource_sha256,
        "decrypted_sha256": recovered.decrypted_sha256,
        "inflated_sha256": recovered.inflated_sha256,
        "protector_key_sha256": recovered.protector_key_sha256,
        "header_identifier_sha256": recovered.header_identifier_sha256,
        "configuration_fingerprint_sha256": (
            recovered.configuration_fingerprint_sha256
        ),
        "compressed_offset": recovered.compressed_offset,
        "string_table_offset": recovered.string_table_offset,
        "boundary_search_max_offset": MAX_BOUNDARY_OFFSET,
        "string_table_search_max_offset": MAX_STRING_TABLE_OFFSET,
        "boundary_candidate_count": recovered.boundary_candidate_count,
        "equivalent_boundary_count": recovered.equivalent_boundary_count,
        "record_count": len(recovered.records),
        "pn5_cil_profile_verified": recovered.pn5_profile_count == 1,
        "pn5_profile_count": recovered.pn5_profile_count,
        "protector_key_material_published": False,
        "decoded_records_published": False,
        "sample_executed": False,
        "network_contacted": False,
    }


def _encode_7bit_integer(value: int) -> bytes:
    if not 0 <= value <= 0x7FFFFFFF:
        raise PureLogsYqtyError("7-bit integerがInt32範囲外です")
    output = bytearray()
    while value >= 0x80:
        output.append((value & 0x7F) | 0x80)
        value >>= 7
    output.append(value)
    return bytes(output)


def _read_7bit_integer(data: bytes, offset: int, *, limit: int) -> tuple[int, int]:
    if not 0 <= offset < limit <= len(data):
        raise PureLogsYqtyError("7-bit integer開始位置が範囲外です")
    start = offset
    value = 0
    for index in range(5):
        if offset >= limit:
            raise PureLogsYqtyError("7-bit integerが途中で終わっています")
        current = data[offset]
        offset += 1
        if index == 4 and current > 0x07:
            raise PureLogsYqtyError("7-bit integerがInt32範囲外です")
        value |= (current & 0x7F) << (index * 7)
        if current < 0x80:
            if data[start:offset] != _encode_7bit_integer(value):
                raise PureLogsYqtyError("7-bit integerが非canonicalです")
            return value, offset
    raise PureLogsYqtyError("7-bit integerが終端されていません")


def _read_identifier(data: bytes) -> tuple[bytes, int]:
    length, offset = _read_7bit_integer(data, 0, limit=len(data))
    if not 1 <= length <= MAX_IDENTIFIER_BYTES or length > len(data) - offset:
        raise PureLogsYqtyError("header識別子長が不正です")
    value = data[offset : offset + length]
    try:
        text = value.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise PureLogsYqtyError("header識別子がUTF-8ではありません") from exc
    if not text.isprintable():
        raise PureLogsYqtyError("header識別子に非表示文字があります")
    return value, offset + length


def _decode_outer(blob: bytes) -> tuple[bytes, bytes, bytes]:
    """構造検証したouter wrapperを復号し、clear/key/identifierを返す。"""

    if not isinstance(blob, bytes):
        raise PureLogsYqtyError("resource blobはbytesである必要があります")
    if not 0 < len(blob) <= MAX_RESOURCE_BYTES or len(blob) < 2:
        raise PureLogsYqtyError("resource blob長が安全上限外です")
    header_length = int.from_bytes(blob[:2], "little")
    if not 16 <= header_length <= MAX_HEADER_BYTES:
        raise PureLogsYqtyError("XOR header長が安全上限外です")
    iv_length_offset = 2 + header_length
    if iv_length_offset >= len(blob):
        raise PureLogsYqtyError("XOR headerが途中で終わっています")
    iv_length = blob[iv_length_offset]
    iv_offset = iv_length_offset + 1
    ciphertext_offset = iv_offset + iv_length
    if iv_length != 16 or ciphertext_offset > len(blob):
        raise PureLogsYqtyError("AES-CBC IV長または境界が不正です")
    iv = blob[iv_offset:ciphertext_offset]
    header = bytes(
        value ^ iv[index % iv_length]
        for index, value in enumerate(blob[2:iv_length_offset])
    )
    identifier, offset = _read_identifier(header)
    if len(header) - offset < 4:
        raise PureLogsYqtyError("暗号profile headerが途中で終わっています")
    flags, selector, key_source, key_length = header[offset : offset + 4]
    offset += 4
    if flags != 3 or selector != 2 or key_source >= 64 or key_length != 32:
        raise PureLogsYqtyError("未対応の暗号profileです")
    if len(header) - offset != key_length:
        raise PureLogsYqtyError("AES鍵長またはheader終端が不正です")
    key = header[offset:]
    ciphertext = blob[ciphertext_offset:]
    if not ciphertext or len(ciphertext) % 16:
        raise PureLogsYqtyError("AES-CBC暗号文長が不正です")
    try:
        decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
        padded = decryptor.update(ciphertext) + decryptor.finalize()
    except ValueError as exc:
        raise PureLogsYqtyError("AES-CBC復号に失敗しました") from exc
    padding = padded[-1]
    if not 1 <= padding <= 16 or padded[-padding:] != bytes((padding,)) * padding:
        raise PureLogsYqtyError("AES-CBC PKCS#7 paddingが不正です")
    return padded[:-padding], key, identifier


def _inflate_raw_deflate(data: bytes) -> bytes:
    """余剰byteを許さない単一raw Deflate memberを有界展開する。"""

    if not data:
        raise PureLogsYqtyError("raw Deflate入力が空です")
    output_limit = min(MAX_INFLATED_BYTES, len(data) * MAX_INFLATED_RATIO)
    inflater = zlib.decompressobj(wbits=-zlib.MAX_WBITS)
    try:
        output = inflater.decompress(data, output_limit + 1)
        if len(output) > output_limit or inflater.unconsumed_tail:
            raise PureLogsYqtyError("raw Deflate出力が安全上限を超えました")
        output += inflater.flush(output_limit + 1 - len(output))
    except zlib.error as exc:
        raise PureLogsYqtyError("raw Deflate streamが不正です") from exc
    if len(output) > output_limit:
        raise PureLogsYqtyError("raw Deflate出力が安全上限を超えました")
    if not inflater.eof or inflater.unused_data or inflater.unconsumed_tail:
        raise PureLogsYqtyError("raw Deflate stream境界が完全ではありません")
    return output


def _parse_string_table_from(data: bytes, start: int) -> tuple[str, ...]:
    """指定境界からcanonical .NET UTF-8文字列をEOFまで読む。"""

    if not 0 <= start < len(data):
        raise PureLogsYqtyError("PureLogs文字列tableが短すぎます")
    offset = start
    total = 0
    records: list[str] = []
    while offset < len(data):
        if len(records) >= MAX_RECORD_COUNT:
            raise PureLogsYqtyError("PureLogs文字列件数が安全上限を超えました")
        length, offset = _read_7bit_integer(data, offset, limit=len(data))
        if length > MAX_RECORD_BYTES or length > len(data) - offset:
            raise PureLogsYqtyError("PureLogs文字列長が不正です")
        total += length
        if total > MAX_RECORD_TOTAL_BYTES:
            raise PureLogsYqtyError("PureLogs文字列総量が安全上限を超えました")
        raw = data[offset : offset + length]
        offset += length
        try:
            value = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise PureLogsYqtyError("PureLogs文字列がUTF-8ではありません") from exc
        if any(
            not character.isprintable() and character not in "\r\n\t"
            for character in value
        ):
            raise PureLogsYqtyError("PureLogs文字列に非表示文字があります")
        records.append(value)
    if len(records) < len(_REQUIRED_PATHS):
        raise PureLogsYqtyError("PureLogs文字列tableの件数が不足しています")
    return tuple(records)


def _parse_string_table(data: bytes) -> tuple[str, ...]:
    """既知profileの4 byte wrapper後を文字列tableとして読む。"""

    if len(data) < 5:
        raise PureLogsYqtyError("PureLogs文字列tableが短すぎます")
    return _parse_string_table_from(data, 4)


def _configuration_fingerprint(records: tuple[str, ...]) -> str:
    """既存の有界protobuf抽出器で一意な設定だけを相関する。"""

    # 循環importを避けるためruntimeに限定する。呼出し時点ではextractorの
    # module初期化は完了しており、外部通信やfile書込みは発生しない。
    from extractors.purelogs.extractor import decode_config_blob

    try:
        candidate = decode_config_blob("\n".join(records))
    except ValueError as exc:
        raise PureLogsYqtyError("PureLogs protobuf設定が一意ではありません") from exc
    endpoints = candidate.get("endpoints")
    key_hashes = candidate.get("aes_key_sha256")
    if (
        not isinstance(endpoints, list)
        or not endpoints
        or not all(isinstance(item, str) and item for item in endpoints)
        or not isinstance(key_hashes, list)
        or len(key_hashes) != 1
        or not all(
            isinstance(item, str)
            and len(item) == 64
            and all(character in "0123456789abcdef" for character in item)
            for item in key_hashes
        )
        or candidate.get("aes_key_length_bytes") != 32
    ):
        raise PureLogsYqtyError("PureLogs protobuf設定の必須fieldが不足しています")
    identity = json.dumps(
        {"endpoints": sorted(endpoints), "aes_key_sha256": sorted(key_hashes)},
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    return hashlib.sha256(identity).hexdigest()


def _decode_boundary(
    clear: bytes,
) -> tuple[int, int, str, tuple[str, ...], str, int, int]:
    """圧縮境界と文字列境界を有界探索し、最大完全tableを一意化する。

    buildにより展開後tableの前置きは4 byteとは限らない。table record数が
    最大になる候補だけを残し、raw Deflateのresyncで同一tableへ到達する
    経路は同じsemantic候補へ畳み込む。record列・canonical byte列・設定
    fingerprintのいずれかが競合する場合はfail-closedで拒否する。
    """

    # canonical string parserはrecord列を一意なbyte列へ対応させるため、重い
    # inflated/table byteを候補ごとに保持せず、最大record数のsemantic identity
    # （完全record列 + config fingerprint）と軽量routeだけを保持する。
    maximal: dict[
        tuple[tuple[str, ...], str],
        list[tuple[int, int, str]],
    ] = {}
    maximum_records = -1
    total_compressed_bytes = 0
    total_inflated_bytes = 0
    total_parse_bytes = 0
    parse_attempts = 0
    configuration_attempts = 0
    candidate_count = 0
    upper = min(MAX_BOUNDARY_OFFSET, len(clear) - 1)
    for compressed_offset in range(upper + 1):
        compressed = clear[compressed_offset:]
        total_compressed_bytes += len(compressed)
        if total_compressed_bytes > MAX_BOUNDARY_TOTAL_COMPRESSED_BYTES:
            raise PureLogsYqtyError("圧縮境界探索の総入力work上限を超えました")
        try:
            inflated = _inflate_raw_deflate(compressed)
        except PureLogsYqtyError:
            continue
        total_inflated_bytes += len(inflated)
        if total_inflated_bytes > MAX_BOUNDARY_TOTAL_INFLATED_BYTES:
            raise PureLogsYqtyError("圧縮境界探索の総展開work上限を超えました")
        inflated_sha256 = hashlib.sha256(inflated).hexdigest()
        table_upper = min(MAX_STRING_TABLE_OFFSET, len(inflated) - 1)
        for table_offset in range(table_upper + 1):
            parse_attempts += 1
            total_parse_bytes += len(inflated) - table_offset
            if (
                parse_attempts > MAX_BOUNDARY_PARSE_ATTEMPTS
                or total_parse_bytes > MAX_BOUNDARY_TOTAL_PARSE_BYTES
            ):
                raise PureLogsYqtyError("文字列境界探索の総parse work上限を超えました")
            try:
                records = _parse_string_table_from(inflated, table_offset)
            except PureLogsYqtyError:
                continue
            normalized = {value.casefold() for value in records}
            if not _REQUIRED_PATHS.issubset(normalized):
                continue
            configuration_attempts += 1
            if configuration_attempts > MAX_BOUNDARY_CONFIGURATION_ATTEMPTS:
                raise PureLogsYqtyError("文字列境界探索の設定検証work上限を超えました")
            try:
                fingerprint = _configuration_fingerprint(records)
            except PureLogsYqtyError:
                continue
            candidate_count += 1
            if candidate_count > MAX_BOUNDARY_CANDIDATES:
                raise PureLogsYqtyError("圧縮境界候補数が安全上限を超えました")
            record_count = len(records)
            if record_count > maximum_records:
                maximum_records = record_count
                maximal = {}
            if record_count != maximum_records:
                continue
            identity = (records, fingerprint)
            if identity not in maximal:
                maximal[identity] = []
            maximal[identity].append((compressed_offset, table_offset, inflated_sha256))
    if not maximal:
        raise PureLogsYqtyError("検証済み圧縮境界が一意に得られません")
    if len(maximal) != 1:
        raise PureLogsYqtyError("圧縮境界候補が曖昧です")
    ((identity, equivalent),) = maximal.items()
    records, fingerprint = identity
    # 4-byte wrapperは既存buildでCIL追跡済みの境界なので最優先する。
    # 次にCIL追跡済みの19-byte outer header境界を優先する。
    # どちらもないbuildでは、同一内容へresyncできる後方suffixよりも、
    # 最初に完全展開できた圧縮境界を優先する。
    # equivalent_boundary_countを併記し、resync経路が複数ある事実は隠さない。
    selected = min(
        equivalent,
        key=lambda item: (
            0 if item[1] == 4 else 1,
            0 if item[0] == 19 else 1,
            item[0],
            item[1],
        ),
    )
    compressed_offset, table_offset, inflated_sha256 = selected
    return (
        compressed_offset,
        table_offset,
        inflated_sha256,
        records,
        fingerprint,
        len(maximal),
        len(equivalent),
    )


def decode_yqty_resource_blob(
    blob: bytes,
    *,
    pn5_profile_count: int,
) -> PureLogsYqtyResource:
    """構造検証済みYqTY resource blobを静的復元する。"""

    if pn5_profile_count != 1:
        raise PureLogsYqtyError("review済みPn5 CIL profileが一意ではありません")
    clear, key, identifier = _decode_outer(blob)
    (
        offset,
        table_offset,
        inflated_sha256,
        records,
        fingerprint,
        candidate_count,
        equivalent_count,
    ) = _decode_boundary(clear)
    return PureLogsYqtyResource(
        records=records,
        resource_sha256=hashlib.sha256(blob).hexdigest(),
        decrypted_sha256=hashlib.sha256(clear).hexdigest(),
        inflated_sha256=inflated_sha256,
        protector_key_sha256=hashlib.sha256(key).hexdigest(),
        header_identifier_sha256=hashlib.sha256(identifier).hexdigest(),
        configuration_fingerprint_sha256=fingerprint,
        compressed_offset=offset,
        string_table_offset=table_offset,
        boundary_candidate_count=candidate_count,
        equivalent_boundary_count=equivalent_count,
        pn5_profile_count=pn5_profile_count,
    )


def _integer_constant(opcode: str, operand: object) -> int | None:
    if opcode in {"ldc.i4", "ldc.i4.s"}:
        value = getattr(operand, "value", operand)
        return value if isinstance(value, int) and not isinstance(value, bool) else None
    if opcode == "ldc.i4.m1":
        return -1
    if opcode.startswith("ldc.i4.") and opcode[-1:].isdigit():
        return int(opcode[-1])
    return None


def _method_shapes(image: object, data: bytes) -> tuple[_MethodShape, ...]:
    """MethodDefを上限付きで正規化する。"""

    tables = image.net.mdtables
    type_rows = list(getattr(getattr(tables, "TypeDef", None), "rows", ()) or ())
    method_rows = list(getattr(getattr(tables, "MethodDef", None), "rows", ()) or ())
    if not 0 < len(method_rows) <= MAX_METHOD_COUNT:
        raise PureLogsYqtyError("MethodDef件数が安全上限外です")
    owners: dict[int, int] = {}
    for type_index, row in enumerate(type_rows, 1):
        for reference in getattr(row, "MethodList", ()) or ():
            index = getattr(reference, "row_index", None)
            if isinstance(index, int):
                owners[index] = 0x02000000 | type_index
    total_instructions = 0
    result: list[_MethodShape] = []
    for index, row in enumerate(method_rows, 1):
        rva = int(getattr(row, "Rva", 0) or 0)
        if not rva:
            continue
        start = image.get_offset_from_rva(rva)
        if not isinstance(start, int) or not 0 <= start < len(data):
            raise PureLogsYqtyError("MethodDef RVAがfile範囲外です")
        body = read_method_body_from_bytes(data[start : start + MAX_METHOD_BYTES])
        if (
            int(body.size) > MAX_METHOD_BYTES
            or len(body.instructions) > MAX_METHOD_INSTRUCTIONS
        ):
            raise PureLogsYqtyError("method bodyが安全上限を超えています")
        total_instructions += len(body.instructions)
        if total_instructions > MAX_TOTAL_INSTRUCTIONS:
            raise PureLogsYqtyError("総CIL命令数が安全上限を超えています")
        opcodes: list[str] = []
        integers: list[int] = []
        method_operands: list[int] = []
        for instruction in body.instructions:
            opcode = str(instruction.opcode.name)
            opcodes.append(opcode)
            integer = _integer_constant(opcode, instruction.operand)
            if integer is not None:
                integers.append(integer)
            raw = getattr(instruction.operand, "value", instruction.operand)
            if (
                opcode in {"call", "callvirt", "newobj"}
                and isinstance(raw, int)
                and raw >> 24 == 0x06
            ):
                method_operands.append(raw)
        result.append(
            _MethodShape(
                token=0x06000000 | index,
                owner_token=owners.get(index, 0),
                name=str(getattr(row, "Name", "")),
                signature=bytes(getattr(row.Signature, "value", b"")),
                opcodes=tuple(opcodes),
                integer_constants=tuple(integers),
                method_operands=tuple(method_operands),
            )
        )
    return tuple(result)


def _pn5_profile_count(methods: tuple[_MethodShape, ...]) -> int:
    """name/token/hashに依存せずreview済みPn5型の個数を返す。"""

    by_owner: dict[int, list[_MethodShape]] = {}
    for method in methods:
        if method.owner_token not in by_owner:
            by_owner[method.owner_token] = []
        by_owner[method.owner_token].append(method)
    profiles = 0
    for owner, owned in by_owner.items():
        if not owner:
            continue
        constructors = [
            method
            for method in owned
            if method.name == ".ctor"
            and 32769 in method.integer_constants
            and method.opcodes.count("newobj") >= 2
        ]
        read_methods = [
            method for method in owned if method.signature == _PN5_READ_SIGNATURE
        ]
        bool_methods = [
            method
            for method in owned
            if method.signature == _PN5_BOOL_SIGNATURE
            and len(method.opcodes) >= 400
            and method.opcodes.count("switch") >= 3
            and any(opcode.startswith("ldloca") for opcode in method.opcodes)
        ]
        if len(constructors) != 1 or len(read_methods) < 2 or not bool_methods:
            continue
        constructor = constructors[0]
        wrappers = [
            method
            for method in methods
            if method.owner_token != owner
            and constructor.token in method.method_operands
            and 81920 in method.integer_constants
            and "newarr" in method.opcodes
            and "ldlen" in method.opcodes
            and method.opcodes.count("switch") >= 2
        ]
        if len(wrappers) == 1:
            profiles += 1
    return profiles


def recover_purelogs_yqty_strings(data: bytes) -> PureLogsYqtyResource | None:
    """managed PE内でPn5形状と一意に結び付くYqTY profileだけを返す。"""

    if (
        not isinstance(data, bytes)
        or not 0 < len(data) <= MAX_INPUT_BYTES
        or not has_clr_metadata(data)
    ):
        return None
    try:
        image = dnfile.dnPE(data=data, clr_lazy_load=False)
        methods = _method_shapes(image, data)
        profile_count = _pn5_profile_count(methods)
        if profile_count != 1:
            return None
        resources = list(getattr(getattr(image, "net", None), "resources", ()) or ())
    except Exception:  # noqa: BLE001 - 壊れたmetadataは候補なしとして拒否する
        return None
    if len(resources) > MAX_RESOURCE_COUNT:
        return None
    candidates: list[PureLogsYqtyResource] = []
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
            recovered = decode_yqty_resource_blob(
                blob,
                pn5_profile_count=profile_count,
            )
        except PureLogsYqtyError:
            continue
        candidates.append(recovered)
        if len(candidates) > 1:
            return None
    return candidates[0] if len(candidates) == 1 else None


__all__ = [
    "PureLogsYqtyError",
    "PureLogsYqtyResource",
    "decode_yqty_resource_blob",
    "public_recovery_evidence",
    "recover_purelogs_yqty_strings",
]
