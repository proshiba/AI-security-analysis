"""BIN/101 native loaderのshellcodeを実行せず静的復元する。

対象profileはAMD64 PE内の名前付き ``BIN``／ID 101 resourceを、状態依存の
nibble rotate変換とRC4で復号する。単なるresource名や鍵byte列だけでは受理せず、
外層のresolver定数、復号後のx64命令列、``codemark`` 設定markerをすべて検証する。
この構造だけでは終端malware familyを断定しない。
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass
from typing import Any

import pefile
from capstone import CS_ARCH_X86, CS_MODE_64, Cs

MAX_INPUT_SIZE = 16 * 1024 * 1024
MIN_RESOURCE_SIZE = 512
MAX_RESOURCE_SIZE = 4 * 1024 * 1024
MAX_RESOURCE_LEAVES = 512
AMD64_MACHINE = 0x8664
RESOURCE_TYPE = "BIN"
RESOURCE_ID = 101
FNV_SEED = (0x811C9DC5).to_bytes(4, "little")
FNV_PRIME = (0x01000193).to_bytes(4, "little")
RC4_KEY = bytes.fromhex("deadbeefcafebabe")
CODEMARK = b"codemark"


class Bin101RecoveryError(ValueError):
    """profile、resource境界または復号結果を検証できない場合の例外。"""


@dataclass(frozen=True)
class Bin101Recovery:
    """復元payloadと公開可能な検証情報を保持する。"""

    payload: bytes
    input_sha256: str
    resource_size: int
    resource_sha256: str
    transformed_sha256: str
    instruction_count: int
    instruction_coverage: float
    branch_count: int
    codemark_offset: int

    @property
    def payload_sha256(self) -> str:
        """復元payloadのSHA-256を返す。"""

        return hashlib.sha256(self.payload).hexdigest()

    def metadata(self) -> dict[str, object]:
        """生鍵、resource、payloadを含まない公開可能な要約を返す。"""

        return public_recovery_summary(self)


def public_recovery_summary(recovery: Bin101Recovery) -> dict[str, object]:
    """BIN/101復元結果から秘密値を除いた決定的な要約を返す。"""

    if not isinstance(recovery, Bin101Recovery):
        raise TypeError("Bin101Recoveryが必要です")
    payload_sha256 = hashlib.sha256(recovery.payload).hexdigest()
    return {
        "schema_version": 1,
        "status": "shellcode_recovered",
        "component": "bin101_nibble_rc4_loader",
        "family_attribution": "unresolved_component_only",
        "input_sha256": recovery.input_sha256,
        "resource": {
            "type": RESOURCE_TYPE,
            "id": RESOURCE_ID,
            "size": recovery.resource_size,
            "sha256": recovery.resource_sha256,
            "raw_value_included": False,
        },
        "resolver_constants": {
            "fnv1a_seed_present": True,
            "fnv1a_prime_present": True,
        },
        "transforms": ["stateful_nibble_rotate", "rc4"],
        "rc4_key": {
            "size": len(RC4_KEY),
            "sha256": hashlib.sha256(RC4_KEY).hexdigest(),
            "raw_value_included": False,
        },
        "transformed_sha256": recovery.transformed_sha256,
        "payload_size": len(recovery.payload),
        "payload_sha256": payload_sha256,
        "raw_payload_included": False,
        "x64_validation": {
            "instruction_count": recovery.instruction_count,
            "instruction_coverage": round(recovery.instruction_coverage, 6),
            "branch_count": recovery.branch_count,
            "peb_walk_present": True,
        },
        "terminal_config_marker": {
            "name": CODEMARK.decode("ascii"),
            "offset": recovery.codemark_offset,
            "present": True,
        },
        "executed": False,
        "network_contacted": False,
    }


def looks_like_bin101_profile(data: bytes) -> bool:
    """重いPE resource解析前にBIN/101固有定数を有界確認する。"""

    return (
        isinstance(data, bytes)
        and MIN_RESOURCE_SIZE <= len(data) <= MAX_INPUT_SIZE
        and data.startswith(b"MZ")
        and FNV_SEED in data
        and FNV_PRIME in data
        and RC4_KEY in data
    )


def _entry_name(entry: object) -> str:
    """pefileのresource名を制御文字なしの文字列へ正規化する。"""

    value = getattr(entry, "name", None)
    if value is None:
        return ""
    text = str(value).strip()
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in text):
        return ""
    return text


def _parse_image(data: bytes) -> Any:
    """上限内のnative AMD64 PEだけをresource走査へ送る。"""

    if not MIN_RESOURCE_SIZE <= len(data) <= MAX_INPUT_SIZE:
        raise Bin101RecoveryError("入力sizeがprofile上限外です")
    if not data.startswith(b"MZ"):
        raise Bin101RecoveryError("入力はPEではありません")
    try:
        image = pefile.PE(data=data, fast_load=True)
        image.parse_data_directories(
            directories=[
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]
            ]
        )
    except (
        AttributeError,
        IndexError,
        KeyError,
        pefile.PEFormatError,
        struct.error,
        TypeError,
        ValueError,
    ) as exc:
        raise Bin101RecoveryError("PE resource directoryを解析できません") from exc
    try:
        if int(image.FILE_HEADER.Machine) != AMD64_MACHINE:
            raise Bin101RecoveryError("AMD64 PEではありません")
        directories = image.OPTIONAL_HEADER.DATA_DIRECTORY
        if len(directories) > 14 and int(directories[14].VirtualAddress):
            raise Bin101RecoveryError("managed PEは対象外です")
    except (AttributeError, IndexError, TypeError, ValueError) as exc:
        if isinstance(exc, Bin101RecoveryError):
            raise
        raise Bin101RecoveryError("PE machine／CLR属性を検証できません") from exc
    return image


def _resource_blob(image: Any) -> bytes:
    """一意なBIN/101 resourceを境界検証して取得する。"""

    try:
        type_entries = list(image.DIRECTORY_ENTRY_RESOURCE.entries)
    except AttributeError as exc:
        raise Bin101RecoveryError("PEにresource directoryがありません") from exc
    candidates: list[bytes] = []
    leaf_count = 0
    for type_entry in type_entries:
        type_name = _entry_name(type_entry).upper()
        for name_entry in list(getattr(type_entry.directory, "entries", ())):
            name_id = getattr(name_entry, "id", None)
            for language_entry in list(getattr(name_entry.directory, "entries", ())):
                leaf_count += 1
                if leaf_count > MAX_RESOURCE_LEAVES:
                    raise Bin101RecoveryError("resource leaf件数が上限を超えています")
                if type_name != RESOURCE_TYPE or name_id != RESOURCE_ID:
                    continue
                try:
                    item = language_entry.data.struct
                    rva = int(item.OffsetToData)
                    size = int(item.Size)
                except (AttributeError, TypeError, ValueError) as exc:
                    raise Bin101RecoveryError("BIN/101 resource属性が不正です") from exc
                if not MIN_RESOURCE_SIZE <= size <= MAX_RESOURCE_SIZE:
                    raise Bin101RecoveryError("BIN/101 resource sizeが上限外です")
                try:
                    blob = bytes(image.get_data(rva, size))
                except (AttributeError, TypeError, ValueError) as exc:
                    raise Bin101RecoveryError("BIN/101 resourceを取得できません") from exc
                if len(blob) != size:
                    raise Bin101RecoveryError("BIN/101 resourceが宣言sizeより短いです")
                candidates.append(blob)
    unique = {hashlib.sha256(item).hexdigest(): item for item in candidates}
    if len(unique) != 1:
        raise Bin101RecoveryError("BIN/101 resourceを一意に決定できません")
    return next(iter(unique.values()))


def stateful_nibble_transform(data: bytes) -> bytes:
    """loaderの状態依存byte変換を境界内で再現する。"""

    if not MIN_RESOURCE_SIZE <= len(data) <= MAX_RESOURCE_SIZE:
        raise Bin101RecoveryError("変換対象sizeが上限外です")
    state = 0x55
    output = bytearray(len(data))
    for index, value in enumerate(data):
        mixed = value ^ state
        rotated = ((mixed << 4) & 0xFF) | (mixed >> 4)
        decoded = ((((state ^ 0xAA) + index) & 0xFF) ^ rotated) & 0xFF
        output[index] = decoded
        state = (state + decoded + 0x0D) & 0xFF
    return bytes(output)


def _rc4(data: bytes, key: bytes = RC4_KEY) -> bytes:
    """標準RC4 KSA／PRGAを適用する。"""

    if not key or len(key) > 256:
        raise Bin101RecoveryError("RC4 key lengthが不正です")
    state = list(range(256))
    j = 0
    for i in range(256):
        j = (j + state[i] + key[i % len(key)]) & 0xFF
        state[i], state[j] = state[j], state[i]
    output = bytearray(len(data))
    i = j = 0
    for offset, value in enumerate(data):
        i = (i + 1) & 0xFF
        j = (j + state[i]) & 0xFF
        state[i], state[j] = state[j], state[i]
        output[offset] = value ^ state[(state[i] + state[j]) & 0xFF]
    return bytes(output)


def _validate_x64_shellcode(payload: bytes) -> tuple[int, float, int, int]:
    """命令被覆、PEB参照、codemarkの一意性を検証する。"""

    if not MIN_RESOURCE_SIZE <= len(payload) <= MAX_RESOURCE_SIZE:
        raise Bin101RecoveryError("復号payload sizeが上限外です")
    if payload.startswith(b"MZ"):
        raise Bin101RecoveryError("復号payloadは期待するraw shellcodeではありません")
    marker_offsets: list[int] = []
    cursor = 0
    while len(marker_offsets) < 2:
        offset = payload.find(CODEMARK, cursor)
        if offset < 0:
            break
        marker_offsets.append(offset)
        cursor = offset + len(CODEMARK)
    if len(marker_offsets) != 1:
        raise Bin101RecoveryError("codemark設定markerを一意に検証できません")
    probe = payload[: min(1024, len(payload))]
    engine = Cs(CS_ARCH_X86, CS_MODE_64)
    try:
        instructions = list(engine.disasm(probe, 0))
    except (AttributeError, TypeError, ValueError) as exc:
        raise Bin101RecoveryError("x64命令列を解析できません") from exc
    covered = sum(int(item.size) for item in instructions)
    coverage = covered / len(probe)
    branches = sum(
        item.mnemonic.startswith(("call", "j", "ret")) for item in instructions
    )
    peb_walk = any("gs:[0x60]" in item.op_str.casefold() for item in instructions)
    if (
        len(instructions) < 64
        or coverage < 0.90
        or branches < 4
        or not peb_walk
    ):
        raise Bin101RecoveryError("復号payloadのx64構造を検証できません")
    return len(instructions), coverage, branches, marker_offsets[0]


def recover_bin101_payload(data: bytes) -> Bin101Recovery | None:
    """構造と復号後payloadを全て検証できた場合だけ結果を返す。"""

    if not looks_like_bin101_profile(data):
        return None
    try:
        image = _parse_image(data)
        resource = _resource_blob(image)
        transformed = stateful_nibble_transform(resource)
        payload = _rc4(transformed)
        instruction_count, coverage, branches, marker_offset = (
            _validate_x64_shellcode(payload)
        )
    except (
        AttributeError,
        Bin101RecoveryError,
        IndexError,
        KeyError,
        pefile.PEFormatError,
        struct.error,
        TypeError,
        ValueError,
    ):
        return None
    return Bin101Recovery(
        payload=payload,
        input_sha256=hashlib.sha256(data).hexdigest(),
        resource_size=len(resource),
        resource_sha256=hashlib.sha256(resource).hexdigest(),
        transformed_sha256=hashlib.sha256(transformed).hexdigest(),
        instruction_count=instruction_count,
        instruction_coverage=coverage,
        branch_count=branches,
        codemark_offset=marker_offset,
    )


__all__ = [
    "Bin101Recovery",
    "Bin101RecoveryError",
    "looks_like_bin101_profile",
    "public_recovery_summary",
    "recover_bin101_payload",
    "stateful_nibble_transform",
]
