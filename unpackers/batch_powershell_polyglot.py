"""Batch／PowerShell／JavaScript polyglotの埋込み層を静的に復元する。

検体を評価・起動せず、Batchの ``set "PREFIX..."`` 行だけを読み取る。
コンテナ内のsize／SHA-256メタデータへ一致した成分と、GZip magicで一意に
決まる単一byte変換だけを受理する。後段のAES経路も、復元PowerShell内で
key／IV配列、共通XOR、CBC、PKCS7、RSC変数の受渡しが同時に確認できる場合に
限って適用する。
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
import zlib
from dataclasses import dataclass

import pefile
from Cryptodome.Cipher import AES

from unpackers.javascript_obfuscator import decode_script_text
from unpackers.managed_handoff_image import inspect_managed_handoff_image
from unpackers.native_kmta_loader import recover_native_kmta_payload

MAX_SCRIPT_SIZE = 16 * 1024 * 1024
MAX_LINE_COUNT = 65_536
# minifiedな単一行も総script上限の内側なら解析対象にする。line数と後段の
# carrier／work quotaは別に維持し、総入力上限を超える値は先に拒否する。
MAX_LINE_SIZE = MAX_SCRIPT_SIZE
MAX_METADATA_RECORDS = 32
MAX_PREFIX_CANDIDATES = 4_096
MAX_CARRIER_SIZE = 8 * 1024 * 1024
MAX_CANDIDATE_WORK = 64 * 1024 * 1024
MAX_METADATA_WORK = 128 * 1024 * 1024
MAX_METADATA_OUTPUT_WORK = 64 * 1024 * 1024
MAX_HEX_TRANSFORM_WORK = 128 * 1024 * 1024
MAX_STAGE_OUTPUT_WORK = 64 * 1024 * 1024
MAX_STAGE_GZIP_ATTEMPTS = 64
MAX_COMPONENT_SIZE = 32 * 1024 * 1024
MAX_EXPANSION_RATIO = 512
MIN_CARRIER_BODY = 64

_ROLES = frozenset({"AMSI", "BOOT", "HBT", "HCS", "PLD", "PS", "RSC"})
_METADATA_RE = re.compile(
    r"^::(?P<label>[A-Z][A-Z0-9_]{5,63})\|"
    r"(?P<version>[1-9][0-9]{0,3})\|"
    r"(?P<size>[0-9]{1,9})\|"
    r"(?P<sha256>[0-9a-fA-F]{64})\|"
    r"(?P<codec>[01])(?:\|(?P<xor>[0-9]{1,3}))?\r?$",
    re.MULTILINE,
)
_SET_RE = re.compile(r'^\s*set\s+"(?P<body>[^\r\n]*)$', re.IGNORECASE)
_PREFIX_RE = re.compile(r"[A-Z0-9_]{4,32}")
_BASE64_RE = re.compile(r"[A-Za-z0-9+/=]+")
_HEX_RE = re.compile(r"[0-9A-Fa-f]+")
_ARRAY_RE = re.compile(
    r"\$(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*"
    r"\[byte\[\]\]\s*\(\s*@\((?P<values>[0-9,\s]+)\)\s*\|\s*"
    r"ForEach-Object\s*\{\s*\[byte\]\s*\(\s*\$_\s*-bxor\s*"
    r"\$(?P<mask>[A-Za-z_][A-Za-z0-9_]*)\s*\)\s*\}\s*\)",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class _Metadata:
    prefix: str
    role: str
    version: int
    size: int
    sha256: str
    codec: int
    xor_key: int | None


@dataclass(frozen=True)
class _Carrier:
    prefix: str
    chunks: int
    encoded: str


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _base_report(status: str) -> dict[str, object]:
    return {
        "status": status,
        "executed": False,
        "network_contacted": False,
    }


def _split_label(label: str) -> tuple[str, str] | None:
    for role in sorted(_ROLES, key=len, reverse=True):
        if label.endswith(role) and len(label) - len(role) >= 4:
            return label[: -len(role)], role
    return None


def _metadata(text: str) -> tuple[list[_Metadata], str | None]:
    records: list[_Metadata] = []
    prefixes: set[str] = set()
    roles: set[str] = set()
    for match in _METADATA_RE.finditer(text):
        split = _split_label(match.group("label"))
        if split is None:
            continue
        prefix, role = split
        size = int(match.group("size"))
        xor_text = match.group("xor")
        xor_key = int(xor_text) if xor_text is not None else None
        if not 1 <= size <= MAX_COMPONENT_SIZE:
            return [], "metadata_size_blocked"
        if xor_key is not None and not 0 <= xor_key <= 255:
            return [], "metadata_invalid"
        if role in roles:
            return [], "metadata_ambiguous"
        roles.add(role)
        prefixes.add(prefix)
        records.append(
            _Metadata(
                prefix=prefix,
                role=role,
                version=int(match.group("version")),
                size=size,
                sha256=match.group("sha256").lower(),
                codec=int(match.group("codec")),
                xor_key=xor_key,
            )
        )
        if len(records) > MAX_METADATA_RECORDS:
            return [], "metadata_limit_blocked"
    if len(records) < 3:
        return [], None
    if len(prefixes) != 1:
        return [], "metadata_ambiguous"
    return records, None


def _polyglot_shape(text: str) -> bool:
    stripped = text.lstrip("\ufeff\r\n\t ")
    if not stripped.startswith("/*") or "*/" not in stripped:
        return False
    if re.search(r"(?im)^\s*rem(?:\s|$)", text) is None:
        return False
    markers = (
        "$env:" in text,
        "[char]34" in text,
        "Get'+'Method" in text or 'Get"+"Method' in text,
        "[Convert]::" in text,
        'set "' in text,
    )
    return sum(markers) >= 3


def _carrier_bodies(lines: list[str]) -> list[str] | None:
    bodies: list[str] = []
    for line in lines:
        match = _SET_RE.match(line)
        if match is None:
            continue
        body = match.group("body")
        body = body.removesuffix('"')
        # 短い最終chunkも連結対象へ残す。prefix候補の生成だけは下で長い行に
        # 限定し、通常の短いBatch変数から候補集合を膨張させない。
        if len(body) >= 8:
            bodies.append(body)
    return bodies


def _carriers(bodies: list[str]) -> tuple[list[_Carrier], str | None]:
    prefixes: set[str] = set()
    for body in bodies:
        if len(body) < MIN_CARRIER_BODY:
            continue
        match = _PREFIX_RE.match(body)
        if match is None:
            continue
        value = match.group(0)
        for length in range(4, len(value) + 1):
            prefixes.add(value[:length])
            if len(prefixes) > MAX_PREFIX_CANDIDATES:
                return [], "carrier_prefix_limit_blocked"

    carriers: list[_Carrier] = []
    work = 0
    for prefix in sorted(prefixes, key=lambda item: (len(item), item)):
        chunks = [body[len(prefix) :] for body in bodies if body.startswith(prefix)]
        encoded = "".join(chunks).replace("_", "")
        if len(encoded) < 32:
            continue
        if len(encoded) > MAX_CARRIER_SIZE:
            return [], "carrier_size_blocked"
        work += len(encoded)
        if work > MAX_CANDIDATE_WORK:
            return [], "carrier_work_limit_blocked"
        carriers.append(_Carrier(prefix=prefix, chunks=len(chunks), encoded=encoded))
    return carriers, None


def _strict_base64(value: str) -> bytes | None:
    if len(value) % 4 or _BASE64_RE.fullmatch(value) is None:
        return None
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error):
        return None
    if not 1 <= len(decoded) <= MAX_COMPONENT_SIZE:
        return None
    return decoded


def _bounded_gzip(data: bytes, maximum: int = MAX_COMPONENT_SIZE) -> bytes | None:
    if (
        not 1 <= len(data) <= MAX_COMPONENT_SIZE
        or not 1 <= maximum <= MAX_COMPONENT_SIZE
    ):
        return None
    decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
    try:
        output = decoder.decompress(data, maximum + 1)
        if len(output) > maximum or decoder.unconsumed_tail:
            return None
        remaining = maximum + 1 - len(output)
        if remaining > 0:
            output += decoder.flush(remaining)
    except zlib.error:
        return None
    if (
        len(output) > maximum
        or not decoder.eof
        or decoder.unused_data
        or decoder.unconsumed_tail
        or len(output) > max(1, len(data)) * MAX_EXPANSION_RATIO
    ):
        return None
    return output


def _metadata_transform(raw: bytes, record: _Metadata) -> tuple[bytes | None, int]:
    value = raw
    if record.xor_key is not None:
        value = bytes(item ^ record.xor_key for item in value)
    if record.codec == 1:
        if not value.startswith(b"\x1f\x8b"):
            return None, 0
        value = _bounded_gzip(value, record.size)
        if value is None:
            return None, 0
        output_work = len(value)
    else:
        output_work = 0
    if len(value) != record.size or _sha256(value) != record.sha256:
        return None, output_work
    return value, output_work


def _decode_custom_nibbles(value: str, expected_size: int) -> bytes | None:
    if len(value) != 16 + expected_size * 2:
        return None
    alphabet = value[:16]
    encoded = value[16:]
    if len(set(alphabet)) != 16 or any(item not in alphabet for item in encoded):
        return None
    indexes = {item: index for index, item in enumerate(alphabet)}
    output = bytearray(expected_size)
    for offset in range(expected_size):
        value_byte = (indexes[encoded[offset * 2]] << 4) | indexes[
            encoded[offset * 2 + 1]
        ]
        output[offset] = ((value_byte & 0x0F) << 4) | (value_byte >> 4)
    return bytes(output)


def _valid_pe(data: bytes) -> bool:
    if len(data) < 0x200 or not data.startswith(b"MZ"):
        return False
    try:
        image = pefile.PE(data=data, fast_load=True)
    except (AttributeError, ValueError, pefile.PEFormatError):
        return False
    if not 1 <= image.FILE_HEADER.NumberOfSections <= 96:
        return False
    if len(image.sections) != image.FILE_HEADER.NumberOfSections:
        return False
    for section in image.sections:
        start = int(section.PointerToRawData)
        size = int(section.SizeOfRawData)
        if start < 0 or size < 0 or start + size > len(data):
            return False
    return True


def _looks_like_powershell(data: bytes) -> bool:
    if not 32 <= len(data) <= MAX_COMPONENT_SIZE:
        return False
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError:
        return False
    printable = sum(item.isprintable() or item in "\r\n\t\x1e" for item in text)
    if printable / max(1, len(text)) < 0.88:
        return False
    lowered = text.casefold()
    markers = (
        "$env:" in lowered,
        "[convert]" in lowered,
        "new-object" in lowered,
        "function " in lowered,
        "frombase64string" in lowered,
        "gzipstream" in lowered,
        "readalllines" in lowered,
        "scriptblock" in lowered,
        "getmethod" in lowered,
        "[appdomain]" in lowered,
        "[system.reflection." in lowered,
        "[string]::" in lowered,
    )
    return "$" in text and sum(markers) >= 2


def _xor_gzip(raw: bytes) -> bytes | None:
    if len(raw) < 18:
        return None
    key = raw[0] ^ 0x1F
    if raw[1] ^ key != 0x8B:
        return None
    transformed = bytes(item ^ key for item in raw)
    return _bounded_gzip(transformed)


def _hex_script_stages(
    carriers: list[_Carrier],
) -> tuple[list[tuple[_Carrier, str, bytes]], str | None]:
    stages: list[tuple[_Carrier, str, bytes]] = []
    seen_inputs: set[str] = set()
    work = 0
    for carrier in carriers:
        value = carrier.encoded
        if len(value) % 2 or _HEX_RE.fullmatch(value) is None:
            continue
        raw = bytes.fromhex(value)
        digest = _sha256(raw)
        if digest in seen_inputs:
            continue
        seen_inputs.add(digest)
        work += len(raw) * 256 * 2
        if work > MAX_HEX_TRANSFORM_WORK:
            return [], "hex_transform_work_limit_blocked"
        for transform in ("subtract", "xor"):
            for key in range(256):
                if transform == "subtract":
                    decoded = bytes((item - key) & 0xFF for item in raw)
                else:
                    decoded = bytes(item ^ key for item in raw)
                if _looks_like_powershell(decoded):
                    stages.append((carrier, f"hex_{transform}_single_byte", decoded))
                    break
    # 短い誤prefixが同じcarrier群の途中だけを独立scriptに見せる場合がある。
    # 同じ変換で親prefix全体も成立するなら、部分prefix側は保持しない。
    return (
        [
            item
            for item in stages
            if not any(
                item[0].prefix.startswith(parent[0].prefix)
                and item[0].prefix != parent[0].prefix
                and item[1] == parent[1]
                and len(item[2]) < len(parent[2])
                for parent in stages
            )
        ],
        None,
    )


def _parse_byte_values(value: str) -> bytes | None:
    parts = [item.strip() for item in value.split(",")]
    if not parts or any(not item.isdigit() for item in parts):
        return None
    numbers = [int(item) for item in parts]
    if any(not 0 <= item <= 255 for item in numbers):
        return None
    return bytes(numbers)


def _aes_recipe(text: str) -> tuple[bytes, bytes] | None:
    lowered = text.casefold()
    if "'cbc'" not in lowered or "'pkcs7'" not in lowered:
        return None
    role_match = re.search(
        r"\$(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*"
        r"__[A-Za-z_][A-Za-z0-9_]*\s+['\"]RSC['\"]\s+\$[A-Za-z_]",
        text,
        re.IGNORECASE,
    )
    if role_match is None:
        return None
    rsc_variable = role_match.group("name")

    arrays: list[tuple[re.Match[str], str, str, bytes, int]] = []
    for match in _ARRAY_RE.finditer(text):
        values = _parse_byte_values(match.group("values"))
        if values is None or len(values) not in {16, 24, 32}:
            continue
        mask_name = match.group("mask")
        assignment_re = re.compile(
            rf"\${re.escape(mask_name)}\s*=\s*([0-9]{{1,3}})\s*;",
            re.IGNORECASE,
        )
        assignments = [
            item
            for item in assignment_re.finditer(
                text, max(0, match.start() - 2048), match.start()
            )
            if int(item.group(1)) <= 255
        ]
        if not assignments:
            continue
        arrays.append(
            (
                match,
                match.group("name"),
                mask_name,
                values,
                int(assignments[-1].group(1)),
            )
        )

    for key_item in arrays:
        key_match, key_name, mask_name, key_values, mask = key_item
        if len(key_values) not in {16, 24, 32}:
            continue
        for iv_item in arrays:
            iv_match, iv_name, iv_mask_name, iv_values, iv_mask = iv_item
            if (
                iv_match.start() <= key_match.start()
                or iv_match.start() - key_match.end() > 4096
                or len(iv_values) != 16
                or iv_mask_name.casefold() != mask_name.casefold()
                or iv_mask != mask
            ):
                continue
            tail = text[iv_match.end() : iv_match.end() + 8192]
            call_re = re.compile(
                rf"\${re.escape(rsc_variable)}\b[\s\S]*?"
                rf"\${re.escape(key_name)}\s+\${re.escape(iv_name)}\s*\)",
                re.IGNORECASE,
            )
            if call_re.search(tail) is None:
                continue
            key = bytes(item ^ mask for item in key_values)
            iv = bytes(item ^ mask for item in iv_values)
            return key, iv
    return None


def _recover_rsc_pe(powershell: bytes, ciphertext: bytes) -> bytes | None:
    try:
        text = powershell.decode("utf-8-sig")
    except UnicodeDecodeError:
        return None
    recipe = _aes_recipe(text)
    if recipe is None or not ciphertext or len(ciphertext) % AES.block_size:
        return None
    key, iv = recipe
    if len(key) not in {16, 24, 32} or len(iv) != AES.block_size:
        return None
    plaintext = AES.new(key, AES.MODE_CBC, iv).decrypt(ciphertext)
    padding = plaintext[-1]
    if not 1 <= padding <= AES.block_size:
        return None
    if plaintext[-padding:] != bytes([padding]) * padding:
        return None
    decompressed = _bounded_gzip(plaintext[:-padding])
    if decompressed is None or not _valid_pe(decompressed):
        return None
    return decompressed


def recover_batch_powershell_polyglot(
    data: bytes,
) -> tuple[dict[str, object], list[tuple[str, bytes]]]:
    """メタデータ付きBatch／PowerShell polyglotを上限内で静的復元する。"""

    if len(data) > MAX_SCRIPT_SIZE:
        return _base_report("size_blocked"), []
    text = decode_script_text(data)
    lines = text.splitlines()
    if len(lines) > MAX_LINE_COUNT:
        return _base_report("line_limit_blocked"), []
    if any(len(line) > MAX_LINE_SIZE for line in lines):
        return _base_report("line_size_blocked"), []

    records, metadata_error = _metadata(text)
    if metadata_error is not None:
        return _base_report(metadata_error), []
    if not records or not _polyglot_shape(text):
        return _base_report("pattern_not_found"), []

    bodies = _carrier_bodies(lines)
    carriers, carrier_error = _carriers(bodies or [])
    if carrier_error is not None:
        return _base_report(carrier_error), []

    base64_values: dict[str, bytes] = {}
    for carrier in carriers:
        decoded = _strict_base64(carrier.encoded)
        if decoded is not None:
            base64_values[carrier.prefix] = decoded

    verified: dict[str, tuple[_Metadata, _Carrier, bytes, str]] = {}
    ambiguous_roles: list[str] = []
    metadata_work = 0
    metadata_output_work = 0
    for record in records:
        matches: list[tuple[_Carrier, bytes, str]] = []
        for carrier in carriers:
            raw = base64_values.get(carrier.prefix)
            if raw is not None:
                metadata_work += len(raw)
                if metadata_work > MAX_METADATA_WORK:
                    return _base_report("metadata_work_limit_blocked"), []
                transformed, output_work = _metadata_transform(raw, record)
                metadata_output_work += output_work
                if metadata_output_work > MAX_METADATA_OUTPUT_WORK:
                    return _base_report("metadata_output_work_limit_blocked"), []
                if transformed is not None:
                    matches.append((carrier, transformed, "base64"))
            if record.role == "HBT":
                metadata_work += len(carrier.encoded)
                if metadata_work > MAX_METADATA_WORK:
                    return _base_report("metadata_work_limit_blocked"), []
                custom = _decode_custom_nibbles(carrier.encoded, record.size)
                if custom is not None and _sha256(custom) == record.sha256:
                    matches.append((carrier, custom, "custom_alphabet_nibble_swap"))
        unique = {(item[0].prefix, _sha256(item[1]), item[2]): item for item in matches}
        if len(unique) == 1:
            carrier, component, decoder = next(iter(unique.values()))
            verified[record.role] = (record, carrier, component, decoder)
        elif len(unique) > 1:
            ambiguous_roles.append(record.role)

    artifacts: list[tuple[str, bytes]] = []
    artifact_hashes: set[str] = set()
    stage_reports: list[dict[str, object]] = []

    def retain(kind: str, value: bytes) -> None:
        digest = _sha256(value)
        if digest not in artifact_hashes:
            artifact_hashes.add(digest)
            artifacts.append((kind, value))

    seen_stage_hashes: set[str] = set()
    stage_output_work = 0
    stage_gzip_attempts = 0
    for carrier in carriers:
        raw = base64_values.get(carrier.prefix)
        if raw is None:
            continue
        if len(raw) >= 2 and (raw[0] ^ 0x1F) == (raw[1] ^ 0x8B):
            stage_gzip_attempts += 1
            if stage_gzip_attempts > MAX_STAGE_GZIP_ATTEMPTS:
                return _base_report("stage_gzip_attempt_limit_blocked"), []
        decoded = _xor_gzip(raw)
        if decoded is None:
            continue
        stage_output_work += len(decoded)
        if stage_output_work > MAX_STAGE_OUTPUT_WORK:
            return _base_report("stage_output_work_limit_blocked"), []
        if not _looks_like_powershell(decoded):
            continue
        digest = _sha256(decoded)
        if digest in seen_stage_hashes:
            continue
        seen_stage_hashes.add(digest)
        stage_reports.append(
            {
                "carrier_prefix": carrier.prefix,
                "chunk_count": carrier.chunks,
                "transform": "base64_single_byte_xor_gzip",
                "decoded_size": len(decoded),
                "decoded_sha256": digest,
            }
        )
        retain("batch-powershell-xor-gzip-script", decoded)

    hex_stages, hex_error = _hex_script_stages(carriers)
    if hex_error is not None:
        return _base_report(hex_error), []
    for carrier, transform, decoded in hex_stages:
        digest = _sha256(decoded)
        if digest in seen_stage_hashes:
            continue
        seen_stage_hashes.add(digest)
        stage_reports.append(
            {
                "carrier_prefix": carrier.prefix,
                "chunk_count": carrier.chunks,
                "transform": transform,
                "decoded_size": len(decoded),
                "decoded_sha256": digest,
            }
        )
        retain("batch-powershell-hex-script", decoded)

    if "HBT" in verified:
        hbt = verified["HBT"][2]
        if _valid_pe(hbt):
            retain("batch-metadata-hbt-pe", hbt)

    managed_report: dict[str, object] = {"status": "component_not_verified"}
    if "HCS" in verified:
        hcs = verified["HCS"][2]
        managed_report = inspect_managed_handoff_image(hcs)
        if managed_report["status"] == "parsed":
            retain("batch-metadata-hcs-managed-image", hcs)

    # PLDは後段native loaderだけが解釈する場合でも、同梱metadataでsize/hashを
    # 検証できた暗号blobである。実行可能形式へ昇格せず、独立した隔離artifactと
    # して保持し、native静的解析へ渡せるようにする。
    if "PLD" in verified:
        retain("batch-metadata-pld-encrypted", verified["PLD"][2])

    powershell: bytes | None = None
    if "PS" in verified:
        powershell = _xor_gzip(verified["PS"][2])
        if powershell is not None and _looks_like_powershell(powershell):
            retain("batch-metadata-powershell", powershell)

    rsc_pe: bytes | None = None
    aes_report: dict[str, object] = {"status": "recipe_not_recovered"}
    if powershell is not None and "RSC" in verified:
        rsc_pe = _recover_rsc_pe(powershell, verified["RSC"][2])
        if rsc_pe is not None:
            retain("batch-rsc-aes-gzip-pe", rsc_pe)
            aes_report = {
                "status": "pe_recovered",
                "cipher": "AES-CBC",
                "padding": "PKCS7",
                "compression": "gzip",
                "decoded_size": len(rsc_pe),
                "decoded_sha256": _sha256(rsc_pe),
            }

    native_report: dict[str, object] = {"status": "prerequisites_not_recovered"}
    if rsc_pe is not None and "PLD" in verified:
        native_report, native_payload = recover_native_kmta_payload(
            rsc_pe, verified["PLD"][2]
        )
        if native_payload is not None and native_report["status"] == "pe_recovered":
            retain("batch-rsc-kmta-pe", native_payload)

    verified_reports = []
    for role in sorted(verified):
        record, carrier, component, decoder = verified[role]
        verified_reports.append(
            {
                "role": role,
                "version": record.version,
                "carrier_prefix": carrier.prefix,
                "chunk_count": carrier.chunks,
                "decoder": decoder,
                "metadata_xor_applied": record.xor_key is not None,
                "metadata_gzip_applied": record.codec == 1,
                "decoded_size": len(component),
                "decoded_sha256": _sha256(component),
            }
        )

    blockers: list[str] = []
    if "PLD" in verified and native_report["status"] != "pe_recovered":
        blockers.append("metadata_verified_pld_requires_native_loader_analysis")
    if "HCS" in verified and managed_report["status"] != "parsed":
        blockers.append("metadata_verified_hcs_structure_unresolved")
    if ambiguous_roles:
        blockers.append("ambiguous_metadata_carrier")

    status = "artifacts_recovered" if artifacts else "metadata_mismatch"
    if verified and not artifacts:
        status = "metadata_verified_no_artifact"
    report = _base_report(status)
    report.update(
        {
            "metadata_record_count": len(records),
            "carrier_candidate_count": len(carriers),
            "verified_components": verified_reports,
            "ambiguous_roles": sorted(ambiguous_roles),
            "script_stages": stage_reports,
            "rsc_aes_gzip": aes_report,
            "managed_handoff": managed_report,
            "native_kmta": native_report,
            "blockers": blockers,
        }
    )
    return report, artifacts


__all__ = ["recover_batch_powershell_polyglot"]
