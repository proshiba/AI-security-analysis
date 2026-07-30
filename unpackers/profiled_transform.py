#!/usr/bin/env python3
"""上限付きbyte変換を宣言型プロファイルから静的に適用する。"""

from __future__ import annotations

import argparse
from functools import lru_cache
import hashlib
import json
from pathlib import Path
import re
from typing import Any, Mapping
import zipfile
import io

import pefile

from unpackers.donut_unpacker import find_donut_shellcodes


DEFAULT_PROFILE_PATH = (
    Path(__file__).resolve().parent / "profiles" / "byte_transforms.json"
)
PROFILE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,127}$")
ALLOWED_FORMATS = {
    "any",
    "data",
    "pe",
    "script",
    "zip",
    "7z",
    "cab",
    "rar",
    "xz",
    "png",
    "asar",
}
ALLOWED_OPERATIONS = {
    "reverse",
    "rotate_left",
    "rotate_right",
    "xor_byte",
    "xor_repeating",
    "slice",
}
ALLOWED_VALIDATORS = {"donut_shellcode", "magic", "pe", "zip"}
MAX_INPUT_SIZE = 64 * 1024 * 1024
MAX_PROFILES = 128
MAX_OPERATIONS = 16


class TransformProfileError(ValueError):
    """変換プロファイルまたは変換結果が契約を満たさない場合に送出する。"""


def sha256_bytes(data: bytes) -> str:
    """小文字のSHA-256を返す。"""

    return hashlib.sha256(data).hexdigest()


def _integer(value: object, field: str, minimum: int, maximum: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise TransformProfileError(f"{field}は整数である必要があります")
    if not minimum <= value <= maximum:
        raise TransformProfileError(
            f"{field}は{minimum}から{maximum}の範囲で指定してください"
        )
    return value


def _hex_bytes(value: object, field: str) -> bytes:
    if not isinstance(value, str) or not value:
        raise TransformProfileError(f"{field}は空でないhex文字列である必要があります")
    try:
        result = bytes.fromhex(value)
    except ValueError as exc:
        raise TransformProfileError(f"{field}が不正なhexです") from exc
    if not result:
        raise TransformProfileError(f"{field}を空にできません")
    return result


def _validate_operation(value: object, index: int) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise TransformProfileError(f"operations[{index}]はobjectである必要があります")
    operation = value.get("operation")
    if operation not in ALLOWED_OPERATIONS:
        raise TransformProfileError(f"未対応operationです: {operation!r}")
    normalized: dict[str, Any] = {"operation": operation}
    if operation in {"rotate_left", "rotate_right"}:
        normalized["amount"] = _integer(
            value.get("amount"),
            f"operations[{index}].amount",
            0,
            2**63 - 1,
        )
    elif operation == "xor_byte":
        normalized["key"] = _integer(
            value.get("key"),
            f"operations[{index}].key",
            0,
            255,
        )
    elif operation == "xor_repeating":
        key = _hex_bytes(value.get("key_hex"), f"operations[{index}].key_hex")
        if len(key) > 4096:
            raise TransformProfileError("xor_repeating keyが4096 bytesを超えています")
        normalized["key"] = key
    elif operation == "slice":
        normalized["offset"] = _integer(
            value.get("offset", 0),
            f"operations[{index}].offset",
            0,
            MAX_INPUT_SIZE,
        )
        length = value.get("length")
        normalized["length"] = (
            None
            if length is None
            else _integer(
                length,
                f"operations[{index}].length",
                0,
                MAX_INPUT_SIZE,
            )
        )
    return normalized


def _validate_validator(value: object) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise TransformProfileError("validatorはobjectである必要があります")
    validator_type = value.get("type")
    if validator_type not in ALLOWED_VALIDATORS:
        raise TransformProfileError(f"未対応validatorです: {validator_type!r}")
    normalized: dict[str, Any] = {"type": validator_type}
    if validator_type == "donut_shellcode":
        strides = value.get("strides", [1])
        if not isinstance(strides, list) or not strides:
            raise TransformProfileError(
                "donut_shellcode.stridesは空でない配列が必要です"
            )
        normalized["strides"] = tuple(
            _integer(item, "donut_shellcode.strides", 1, 4096) for item in strides
        )
    elif validator_type == "magic":
        normalized["magic"] = _hex_bytes(value.get("magic_hex"), "magic_hex")
        offset = _integer(value.get("offset", 0), "magic.offset", 0, MAX_INPUT_SIZE)
        normalized["offset"] = offset
    return normalized


def validate_profile(value: object) -> dict[str, Any]:
    """一つの変換プロファイルを検証・正規化する。"""

    if not isinstance(value, Mapping):
        raise TransformProfileError("profileはobjectである必要があります")
    profile_id = value.get("id")
    artifact_kind = value.get("artifact_kind")
    if not isinstance(profile_id, str) or PROFILE_ID_RE.fullmatch(profile_id) is None:
        raise TransformProfileError("profile.idが不正です")
    if (
        not isinstance(artifact_kind, str)
        or PROFILE_ID_RE.fullmatch(artifact_kind) is None
    ):
        raise TransformProfileError("artifact_kindが不正です")
    formats = value.get("input_formats", ["any"])
    if (
        not isinstance(formats, list)
        or not formats
        or any(item not in ALLOWED_FORMATS for item in formats)
    ):
        raise TransformProfileError("input_formatsが不正です")
    suffixes = value.get("name_suffixes", [])
    if not isinstance(suffixes, list) or any(
        not isinstance(item, str) or not item.startswith(".") for item in suffixes
    ):
        raise TransformProfileError("name_suffixesが不正です")
    operations = value.get("operations")
    if not isinstance(operations, list) or not 1 <= len(operations) <= MAX_OPERATIONS:
        raise TransformProfileError(
            f"operationsは1から{MAX_OPERATIONS}件で指定してください"
        )
    maximum = _integer(
        value.get("max_input_size", MAX_INPUT_SIZE),
        "max_input_size",
        1,
        MAX_INPUT_SIZE,
    )
    minimum = _integer(
        value.get("min_input_size", 1),
        "min_input_size",
        1,
        maximum,
    )
    return {
        "id": profile_id,
        "description": str(value.get("description") or ""),
        "artifact_kind": artifact_kind,
        "input_formats": frozenset(formats),
        "name_suffixes": tuple(item.casefold() for item in suffixes),
        "min_input_size": minimum,
        "max_input_size": maximum,
        "operations": tuple(
            _validate_operation(item, index) for index, item in enumerate(operations)
        ),
        "validator": _validate_validator(value.get("validator")),
    }


@lru_cache(maxsize=16)
def _load_profiles_cached(
    resolved_path: str,
    modified_ns: int,
    size: int,
) -> tuple[dict[str, Any], ...]:
    del modified_ns, size
    document = json.loads(Path(resolved_path).read_text(encoding="utf-8-sig"))
    if not isinstance(document, Mapping) or document.get("schema_version") != 1:
        raise TransformProfileError("変換プロファイルのschema_versionが不正です")
    values = document.get("profiles")
    if not isinstance(values, list) or len(values) > MAX_PROFILES:
        raise TransformProfileError(f"profilesは最大{MAX_PROFILES}件の配列が必要です")
    profiles: list[dict[str, Any]] = []
    ids: set[str] = set()
    for value in values:
        profile = validate_profile(value)
        if profile["id"] in ids:
            raise TransformProfileError(f"profile idが重複しています: {profile['id']}")
        ids.add(profile["id"])
        profiles.append(profile)
    return tuple(profiles)


def load_profiles(
    path: Path = DEFAULT_PROFILE_PATH,
) -> tuple[dict[str, Any], ...]:
    """ファイルidentityをcache keyとして検証済みプロファイルを返す。"""

    resolved = path.resolve(strict=True)
    stat_result = resolved.stat()
    return _load_profiles_cached(
        str(resolved),
        stat_result.st_mtime_ns,
        stat_result.st_size,
    )


def apply_operations(
    data: bytes,
    operations: tuple[Mapping[str, Any], ...] | list[Mapping[str, Any]],
    *,
    max_input_size: int = MAX_INPUT_SIZE,
) -> bytes:
    """許可リストにある可逆byte操作を順番どおり適用する。"""

    if not data:
        raise TransformProfileError("入力を空にできません")
    if len(data) > max_input_size:
        raise TransformProfileError(f"入力が上限 {max_input_size} bytesを超えています")
    current = data
    for item in operations:
        operation = item["operation"]
        if operation == "reverse":
            current = current[::-1]
        elif operation in {"rotate_left", "rotate_right"}:
            shift = int(item["amount"]) % len(current)
            if shift:
                current = (
                    current[shift:] + current[:shift]
                    if operation == "rotate_left"
                    else current[-shift:] + current[:-shift]
                )
        elif operation == "xor_byte":
            key = int(item["key"])
            current = bytes(value ^ key for value in current)
        elif operation == "xor_repeating":
            key = bytes(item["key"])
            current = bytes(
                value ^ key[index % len(key)] for index, value in enumerate(current)
            )
        elif operation == "slice":
            offset = int(item["offset"])
            length = item["length"]
            current = (
                current[offset:]
                if length is None
                else current[offset : offset + int(length)]
            )
        else:
            raise TransformProfileError(f"未対応operationです: {operation}")
        if not current:
            raise TransformProfileError(f"{operation}の結果が空になりました")
        if len(current) > max_input_size:
            raise TransformProfileError(
                f"{operation}の結果が上限 {max_input_size} bytesを超えています"
            )
    return current


def validate_output(
    data: bytes,
    validator: Mapping[str, Any],
) -> tuple[bool, dict[str, Any]]:
    """変換後byte列を構造で検証し、単なる復号推測を成果物にしない。"""

    validator_type = validator["type"]
    if validator_type == "donut_shellcode":
        candidates = find_donut_shellcodes(data, strides=validator["strides"])
        return bool(candidates), {
            "type": validator_type,
            "candidate_count": len(candidates),
            "candidate_offsets": [item.offset for item in candidates[:16]],
        }
    if validator_type == "magic":
        offset = int(validator["offset"])
        matched = data[offset : offset + len(validator["magic"])] == validator["magic"]
        return matched, {"type": validator_type, "offset": offset}
    if validator_type == "pe":
        if not data.startswith(b"MZ"):
            return False, {"type": validator_type, "parse_status": "not_pe"}
        try:
            pefile.PE(data=data, fast_load=True)
        except pefile.PEFormatError:
            return False, {"type": validator_type, "parse_status": "parse_failed"}
        return True, {"type": validator_type, "parse_status": "parsed"}
    if validator_type == "zip":
        matched = zipfile.is_zipfile(io.BytesIO(data))
        return matched, {
            "type": validator_type,
            "parse_status": "parsed" if matched else "not_zip",
        }
    raise TransformProfileError(f"未対応validatorです: {validator_type}")


def _recover_validated_profile(
    data: bytes,
    normalized: Mapping[str, Any],
) -> tuple[dict[str, Any], list[tuple[str, bytes]]]:
    """検証済みプロファイルを適用する内部入口。"""

    if not normalized["min_input_size"] <= len(data) <= normalized["max_input_size"]:
        return (
            {
                "profile_id": normalized["id"],
                "status": "input_outside_bounds",
                "input_size": len(data),
                "min_input_size": normalized["min_input_size"],
                "max_input_size": normalized["max_input_size"],
                "executed": False,
                "network_contacted": False,
            },
            [],
        )
    clear = apply_operations(
        data,
        normalized["operations"],
        max_input_size=normalized["max_input_size"],
    )
    matched, validation = validate_output(clear, normalized["validator"])
    report = {
        "profile_id": normalized["id"],
        "status": "validated_artifact_recovered" if matched else "validation_failed",
        "input_sha256": sha256_bytes(data),
        "input_size": len(data),
        "output_sha256": sha256_bytes(clear) if matched else None,
        "output_size": len(clear) if matched else None,
        "operations": [
            {
                key: value.hex() if isinstance(value, bytes) else value
                for key, value in item.items()
            }
            for item in normalized["operations"]
        ],
        "validation": validation,
        "executed": False,
        "network_contacted": False,
    }
    artifacts = [(normalized["artifact_kind"], clear)] if matched else []
    return report, artifacts


def recover_transform_profile(
    data: bytes,
    profile: Mapping[str, Any],
) -> tuple[dict[str, Any], list[tuple[str, bytes]]]:
    """一つの未検証変換プロファイルを検証して適用する。"""

    return _recover_validated_profile(data, validate_profile(profile))


def recover_profiled_transforms(
    data: bytes,
    *,
    input_format: str,
    source_name: str = "",
    profiles_path: Path = DEFAULT_PROFILE_PATH,
) -> tuple[dict[str, Any], list[tuple[str, bytes]]]:
    """形式と任意suffixに合う全プロファイルを決定的に評価する。"""

    attempts: list[dict[str, Any]] = []
    artifacts: list[tuple[str, bytes]] = []
    suffix = Path(source_name).suffix.casefold()
    for profile in load_profiles(profiles_path):
        if (
            "any" not in profile["input_formats"]
            and input_format not in profile["input_formats"]
        ):
            attempts.append(
                {"profile_id": profile["id"], "status": "skipped_input_format"}
            )
            continue
        if profile["name_suffixes"] and suffix not in profile["name_suffixes"]:
            attempts.append(
                {"profile_id": profile["id"], "status": "skipped_name_suffix"}
            )
            continue
        report, recovered = _recover_validated_profile(data, profile)
        attempts.append(report)
        artifacts.extend(recovered)
    return (
        {
            "schema_version": 1,
            "status": (
                "validated_artifacts_recovered"
                if artifacts
                else "no_profile_recovered_artifact"
            ),
            "profiles_evaluated": sum(
                item["status"] not in {"skipped_input_format", "skipped_name_suffix"}
                for item in attempts
            ),
            "attempts": attempts,
            "executed": False,
            "network_contacted": False,
        },
        artifacts,
    )


def build_parser() -> argparse.ArgumentParser:
    """宣言型変換CLIのparserを構築する。"""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--profiles", type=Path, default=DEFAULT_PROFILE_PATH)
    parser.add_argument(
        "--input-format", default="data", choices=sorted(ALLOWED_FORMATS)
    )
    parser.add_argument("--json", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    """復元byteを書き出さず、宣言型変換の検証結果だけを返す。"""

    args = build_parser().parse_args(argv)
    data = args.input.read_bytes()
    report, artifacts = recover_profiled_transforms(
        data,
        input_format=args.input_format,
        source_name=args.input.name,
        profiles_path=args.profiles,
    )
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(
            json.dumps(report, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
    print(
        json.dumps(
            {
                "status": report["status"],
                "recovered": len(artifacts),
                "executed": False,
                "network_contacted": False,
            },
            ensure_ascii=False,
        )
    )
    return 0 if artifacts else 20


if __name__ == "__main__":
    raise SystemExit(main())
