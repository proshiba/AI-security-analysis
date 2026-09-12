"""NSIS scriptに記録されたNHENCV1復号recipeを静的に検証・適用する。"""

from __future__ import annotations

import hashlib
import hmac
import re
import struct
from collections import defaultdict
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import PurePosixPath

from Cryptodome.Cipher import AES

from unpackers.nsis_static import NsisMember

NHENCV1_HEADER_SIZE = 96
NHENCV1_KEY_SIZE = 32
NHENCV1_BLOCK_SIZE = 16
MAX_SCRIPT_INSTRUCTIONS = 32_768
MAX_DECRYPT_RECIPES = 1024
MAX_RECIPE_INSTRUCTIONS = 512

_FUNCTION = re.compile(r"^Function\s+(\S+)\s*$", re.IGNORECASE)
_FUNCTION_END = re.compile(r"^FunctionEnd\s*$", re.IGNORECASE)
_CALL = re.compile(r"^Call\s+(\S+)\s*$", re.IGNORECASE)
_FILE = re.compile(r"^File\s+(\$[A-Za-z0-9_]+)\s*$", re.IGNORECASE)
_PUSH = re.compile(r"^Push\s+(.+?)\s*$", re.IGNORECASE)
_STRCPY_INTEGER = re.compile(
    r"^StrCpy\s+(\$[A-Za-z0-9_]+)\s+(-?(?:0x[0-9A-Fa-f]+|\d+))\s*$",
    re.IGNORECASE,
)
_XOR = re.compile(
    r"^IntOp\s+(\$[A-Za-z0-9_]+)\s+"
    r"(-?(?:0x[0-9A-Fa-f]+|\d+))\s+\^\s+(\$[A-Za-z0-9_]+)\s*$",
    re.IGNORECASE,
)
_POINTER_ADD = re.compile(
    r"^IntOp\s+(\$[A-Za-z0-9_]+)\s+(\$[A-Za-z0-9_]+)\s+\+\s+"
    r"(0|4|8|12|16|20|24|28)\s*$",
    re.IGNORECASE,
)
_POINTER_WRITE = re.compile(
    r'^System::Call\s+"\*(\$[A-Za-z0-9_]+)\(i\s+([A-Za-z0-9_$]+)\)"\s*$',
    re.IGNORECASE,
)

_TRANSFORM_MARKERS = (
    "0x4e45484e",
    "0x00315643",
    "bcryptopenalgorithmprovider",
    "sha256",
    "bcryptcreatehash",
    "bcrypthashdata",
    "bcryptfinishhash",
    "bcryptgeneratesymmetrickey",
    "chainingmodecbc",
    "bcryptdecrypt",
    "&v16",
    "&v24",
    "&v32",
)


@dataclass(frozen=True)
class NhencRecipe:
    """decompiled NSIS命令から完全復元した1個の復号recipe。"""

    call_line: int
    source_variable: str
    destination: str
    aes_key: bytes
    hmac_key: bytes


def _instructions(script: bytes) -> tuple[list[tuple[int, str]], bool]:
    """commentと空行を除外し、上限付き命令列へ変換する。"""

    text = script.decode("utf-8-sig", errors="replace")
    instructions: list[tuple[int, str]] = []
    truncated = False
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith(";"):
            continue
        if len(instructions) >= MAX_SCRIPT_INSTRUCTIONS:
            truncated = True
            break
        instructions.append((line_number, line))
    return instructions, truncated


def _transform_functions(instructions: Sequence[tuple[int, str]]) -> set[str]:
    """NHENCV1 header、HMAC、AES-CBCを全て持つ関数だけを採用する。"""

    functions: dict[str, list[str]] = {}
    active: str | None = None
    body: list[str] = []
    for _, instruction in instructions:
        start = _FUNCTION.fullmatch(instruction)
        if start:
            active = start.group(1).casefold()
            body = []
            continue
        if active is None:
            continue
        if _FUNCTION_END.fullmatch(instruction):
            functions[active] = body
            active = None
            body = []
            continue
        body.append(instruction)
    accepted: set[str] = set()
    for name, lines in functions.items():
        normalized = "\n".join(lines).casefold()
        if all(marker in normalized for marker in _TRANSFORM_MARKERS):
            accepted.add(name)
    return accepted


def _parse_u32(value: str) -> int:
    return int(value, 0) & 0xFFFFFFFF


def _key_writes(block: Sequence[tuple[int, str]]) -> dict[str, bytes]:
    """XOR定数→pointer offset→32-bit writeの連鎖だけから鍵を復元する。"""

    integers: dict[str, int] = {}
    writes: dict[str, dict[int, int]] = defaultdict(dict)
    index = 0
    while index < len(block):
        instruction = block[index][1]
        assignment = _STRCPY_INTEGER.fullmatch(instruction)
        if assignment:
            integers[assignment.group(1).casefold()] = _parse_u32(assignment.group(2))
            index += 1
            continue
        xor = _XOR.fullmatch(instruction)
        if xor is None or index + 2 >= len(block):
            index += 1
            continue
        pointer = _POINTER_ADD.fullmatch(block[index + 1][1])
        write = _POINTER_WRITE.fullmatch(block[index + 2][1])
        if pointer is None or write is None:
            index += 1
            continue
        source_variable = xor.group(3).casefold()
        if source_variable not in integers:
            index += 1
            continue
        result_variable = xor.group(1).casefold()
        pointer_variable = pointer.group(1).casefold()
        if (
            write.group(1).casefold() != pointer_variable
            or write.group(2).casefold().lstrip("$")
            != result_variable.lstrip("$")
        ):
            index += 1
            continue
        key_pointer = pointer.group(2).casefold()
        offset = int(pointer.group(3))
        if offset in writes[key_pointer]:
            raise ValueError("同じ鍵offsetへの重複書込みを検出しました")
        writes[key_pointer][offset] = (
            _parse_u32(xor.group(2)) ^ integers[source_variable]
        )
        index += 3

    complete: dict[str, bytes] = {}
    required_offsets = tuple(range(0, NHENCV1_KEY_SIZE, 4))
    for pointer, values in writes.items():
        if tuple(sorted(values)) != required_offsets:
            continue
        complete[pointer] = b"".join(
            struct.pack("<I", values[offset]) for offset in required_offsets
        )
    return complete


def _recipes(
    instructions: Sequence[tuple[int, str]], transform_functions: set[str]
) -> tuple[list[NhencRecipe], int]:
    """File→鍵組立て→5引数Push→復号Callを順序付きで結ぶ。"""

    recipes: list[NhencRecipe] = []
    rejected = 0
    previous_call = -1
    for call_index, (line_number, instruction) in enumerate(instructions):
        call = _CALL.fullmatch(instruction)
        if call is None or call.group(1).casefold() not in transform_functions:
            continue
        if len(recipes) >= MAX_DECRYPT_RECIPES:
            rejected += 1
            continue
        block_start = max(previous_call + 1, call_index - MAX_RECIPE_INSTRUCTIONS)
        previous_call = call_index
        block = instructions[block_start:call_index]
        file_positions = [
            (index, match)
            for index, (_, value) in enumerate(block)
            if (match := _FILE.fullmatch(value)) is not None
        ]
        pushes = [
            match.group(1).strip()
            for _, value in block[-5:]
            if (match := _PUSH.fullmatch(value)) is not None
        ]
        if len(file_positions) != 1 or len(pushes) != 5:
            rejected += 1
            continue
        file_index, file_match = file_positions[0]
        source_variable = file_match.group(1).casefold()
        if pushes[0].casefold() != source_variable:
            rejected += 1
            continue
        try:
            keys = _key_writes(block[file_index + 1 : -5])
        except ValueError:
            rejected += 1
            continue
        aes_pointer = pushes[3].casefold()
        hmac_pointer = pushes[4].casefold()
        if (
            aes_pointer == hmac_pointer
            or aes_pointer not in keys
            or hmac_pointer not in keys
        ):
            rejected += 1
            continue
        recipes.append(
            NhencRecipe(
                call_line=line_number,
                source_variable=source_variable,
                destination=pushes[1],
                aes_key=keys[aes_pointer],
                hmac_key=keys[hmac_pointer],
            )
        )
    return recipes, rejected


def _decrypt(blob: bytes, recipe: NhencRecipe, max_output_size: int) -> bytes:
    """NHENCV1 header、HMAC、PKCS#7、平文長を全て検証して復号する。"""

    if len(blob) < NHENCV1_HEADER_SIZE + NHENCV1_BLOCK_SIZE:
        raise ValueError("NHENCV1 blobが短すぎます")
    if blob[:8] != b"NHENCV1\0":
        raise ValueError("NHENCV1 magicが一致しません")
    version, header_size, cipher_id, auth_id, flags = struct.unpack_from(
        "<HHBBH", blob, 8
    )
    plain_size, encrypted_size = struct.unpack_from("<QQ", blob, 16)
    if (version, header_size, cipher_id, auth_id, flags) != (1, 96, 1, 1, 0):
        raise ValueError("NHENCV1 header contractが一致しません")
    if (
        plain_size > max_output_size
        or encrypted_size < NHENCV1_BLOCK_SIZE
        or encrypted_size % NHENCV1_BLOCK_SIZE
        or encrypted_size != len(blob) - NHENCV1_HEADER_SIZE
    ):
        raise ValueError("NHENCV1 size contractが一致しません")
    expected_auth = hmac.new(
        recipe.hmac_key,
        blob[:64] + blob[NHENCV1_HEADER_SIZE:],
        hashlib.sha256,
    ).digest()
    if not hmac.compare_digest(expected_auth, blob[64:96]):
        raise ValueError("NHENCV1 HMACが一致しません")
    padded = AES.new(recipe.aes_key, AES.MODE_CBC, iv=blob[32:48]).decrypt(
        blob[NHENCV1_HEADER_SIZE:]
    )
    padding_size = padded[-1]
    if (
        not 1 <= padding_size <= NHENCV1_BLOCK_SIZE
        or padded[-padding_size:] != bytes([padding_size]) * padding_size
        or len(padded) - padding_size != plain_size
    ):
        raise ValueError("NHENCV1 PKCS#7または平文長が一致しません")
    return padded[:-padding_size]


def _source_group(
    members: Sequence[tuple[NsisMember, bytes]], source_variable: str
) -> list[tuple[NsisMember, bytes]]:
    """7-Zip listing順を維持し、File変数と同名のduplicate groupを選ぶ。"""

    return [
        item
        for item in members
        if PurePosixPath(item[0].normalized_name).name.casefold() == source_variable
    ]


def recover_nsis_nhencv1(
    script: bytes,
    members: Sequence[tuple[NsisMember, bytes]],
    *,
    max_output_size: int,
    max_total_size: int,
) -> tuple[dict[str, object], list[tuple[str, bytes]]]:
    """認証済みNHENCV1 payloadを実行せず、全件一致時だけ復元する。"""

    report: dict[str, object] = {
        "schema_version": 1,
        "status": "not_applicable",
        "transform_profile": "hmac_sha256_aes256_cbc_pkcs7",
        "transform_function_count": 0,
        "recipe_count": 0,
        "rejected_recipe_count": 0,
        "source_member_count": 0,
        "recovered_count": 0,
        "recovered_total_size": 0,
        "entries": [],
        "secret_material_in_report": False,
        "terminal_promotion_eligible": False,
        "terminal_validation_required": True,
        "executed": False,
        "sample_executed": False,
        "network_contacted": False,
    }
    if (
        isinstance(max_output_size, bool)
        or not isinstance(max_output_size, int)
        or max_output_size <= 0
        or isinstance(max_total_size, bool)
        or not isinstance(max_total_size, int)
        or max_total_size <= 0
    ):
        raise ValueError("復号出力上限は正の整数で指定してください")
    instructions, truncated = _instructions(script)
    if truncated:
        report["status"] = "script_instruction_limit"
        return report, []
    transform_functions = _transform_functions(instructions)
    report["transform_function_count"] = len(transform_functions)
    if len(transform_functions) != 1:
        report["status"] = (
            "not_applicable" if not transform_functions else "ambiguous_transform"
        )
        return report, []
    recipes, rejected = _recipes(instructions, transform_functions)
    report["recipe_count"] = len(recipes)
    report["rejected_recipe_count"] = rejected
    if rejected or not recipes:
        report["status"] = "recipe_validation_failed"
        return report, []

    grouped_recipes: dict[str, list[NhencRecipe]] = defaultdict(list)
    for recipe in recipes:
        grouped_recipes[recipe.source_variable].append(recipe)
    source_groups: dict[str, list[tuple[NsisMember, bytes]]] = {}
    for source_variable, source_recipes in grouped_recipes.items():
        source_members = _source_group(members, source_variable)
        if len(source_members) != len(source_recipes):
            report["status"] = "source_member_mapping_failed"
            return report, []
        source_groups[source_variable] = source_members
    group_indexes: dict[str, int] = defaultdict(int)
    ordered_pairs: list[tuple[NhencRecipe, NsisMember, bytes]] = []
    consumed_outputs: set[str] = set()
    for recipe in recipes:
        group_index = group_indexes[recipe.source_variable]
        member, blob = source_groups[recipe.source_variable][group_index]
        group_indexes[recipe.source_variable] = group_index + 1
        folded_output = member.output_name.casefold()
        if folded_output in consumed_outputs:
            report["status"] = "source_member_mapping_failed"
            return report, []
        consumed_outputs.add(folded_output)
        ordered_pairs.append((recipe, member, blob))
    report["source_member_count"] = len(ordered_pairs)
    if len(ordered_pairs) != len(recipes):
        report["status"] = "source_member_mapping_failed"
        return report, []

    recovered: list[tuple[str, bytes]] = []
    entries: list[dict[str, object]] = []
    total = 0
    for index, (recipe, member, blob) in enumerate(ordered_pairs):
        try:
            plaintext = _decrypt(blob, recipe, max_output_size)
        except ValueError as exc:
            report["status"] = "authenticated_decryption_failed"
            report["failure_reason"] = str(exc)
            return report, []
        total += len(plaintext)
        if total > max_total_size:
            report["status"] = "recovered_total_size_limit"
            return report, []
        digest = hashlib.sha256(plaintext).hexdigest()
        source_digest = hashlib.sha256(blob).hexdigest()
        detected_format = (
            "pe"
            if plaintext.startswith(b"MZ")
            else "zip"
            if plaintext.startswith(b"PK\x03\x04")
            else "data"
        )
        entries.append(
            {
                "sequence": index,
                "call_line": recipe.call_line,
                "source_output_name": member.output_name,
                "source_sha256": source_digest,
                "destination": recipe.destination,
                "size": len(plaintext),
                "sha256": digest,
                "format": detected_format,
                "hmac_verified": True,
                "pkcs7_verified": True,
                "plain_size_verified": True,
            }
        )
        recovered.append((f"nsis-nhencv1-{index:03d}-{detected_format}", plaintext))
    report.update(
        status="recovered",
        recovered_count=len(recovered),
        recovered_total_size=total,
        entries=entries,
    )
    return report, recovered


__all__ = ["NHENCV1_HEADER_SIZE", "NhencRecipe", "recover_nsis_nhencv1"]
