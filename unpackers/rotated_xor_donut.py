"""回転と単一byte XORで包まれたDonut sidecar用の互換ラッパー。"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Mapping

from unpackers.profiled_transform import (
    MAX_INPUT_SIZE,
    TransformProfileError,
    apply_operations,
    recover_transform_profile,
)


DEFAULT_ROTATION = 0x3EF14
DEFAULT_XOR_KEY = 0xC6


def _profile(
    *,
    rotation: int,
    xor_key: int,
    max_input_size: int,
) -> dict[str, Any]:
    return {
        "id": "rotate_right_xor_c6_donut",
        "artifact_kind": "rotated-xor-donut-shellcode",
        "input_formats": ["data"],
        "min_input_size": 1,
        "max_input_size": max_input_size,
        "operations": [
            {"operation": "rotate_right", "amount": rotation},
            {"operation": "xor_byte", "key": xor_key},
        ],
        "validator": {"type": "donut_shellcode", "strides": [1]},
    }


def decode_rotated_xor(
    data: bytes,
    *,
    rotation: int = DEFAULT_ROTATION,
    xor_key: int = DEFAULT_XOR_KEY,
    max_input_size: int = MAX_INPUT_SIZE,
) -> bytes:
    """右回転後に単一byte XORを適用し、sidecarの平文を返す。"""

    if rotation < 0:
        raise ValueError("rotationは0以上で指定してください")
    if not 0 <= xor_key <= 0xFF:
        raise ValueError("xor_keyは0から255で指定してください")
    try:
        return apply_operations(
            data,
            [
                {"operation": "rotate_right", "amount": rotation},
                {"operation": "xor_byte", "key": xor_key},
            ],
            max_input_size=max_input_size,
        )
    except TransformProfileError as exc:
        raise ValueError(str(exc)) from exc


def legacy_report_from_attempt(
    attempt: Mapping[str, Any],
    *,
    rotation: int = DEFAULT_ROTATION,
    xor_key: int = DEFAULT_XOR_KEY,
) -> dict[str, Any]:
    """宣言型変換の試行結果を従来のreport shapeへ変換する。"""

    status = attempt.get("status")
    legacy_status = {
        "validated_artifact_recovered": "donut_shellcode_recovered",
        "validation_failed": "profile_not_matched",
    }.get(status, status)
    validation = attempt.get("validation")
    validation = validation if isinstance(validation, Mapping) else {}
    input_size = int(attempt.get("input_size") or 0)
    return {
        "status": legacy_status,
        "input_sha256": attempt.get("input_sha256"),
        "input_size": input_size,
        "max_input_size": attempt.get("max_input_size"),
        "rotation": rotation,
        "effective_rotation": rotation % input_size if input_size else None,
        "xor_key": f"0x{xor_key:02x}",
        "output_sha256": attempt.get("output_sha256"),
        "output_size": attempt.get("output_size"),
        "candidate_count": int(validation.get("candidate_count") or 0),
        "candidate_offsets": list(validation.get("candidate_offsets") or []),
        "executed": False,
        "network_contacted": False,
    }


def recover_rotated_xor_donut(
    data: bytes,
    *,
    rotation: int = DEFAULT_ROTATION,
    xor_key: int = DEFAULT_XOR_KEY,
    max_input_size: int = MAX_INPUT_SIZE,
) -> tuple[dict, list[tuple[str, bytes]]]:
    """従来APIを維持し、実処理を宣言型変換エンジンへ委譲する。"""

    if not data or len(data) > max_input_size:
        return (
            {
                "status": "input_outside_bounds",
                "input_size": len(data),
                "max_input_size": max_input_size,
                "executed": False,
                "network_contacted": False,
            },
            [],
        )
    if rotation < 0:
        raise ValueError("rotationは0以上で指定してください")
    if not 0 <= xor_key <= 0xFF:
        raise ValueError("xor_keyは0から255で指定してください")
    attempt, artifacts = recover_transform_profile(
        data,
        _profile(
            rotation=rotation,
            xor_key=xor_key,
            max_input_size=max_input_size,
        ),
    )
    return (
        legacy_report_from_attempt(
            attempt,
            rotation=rotation,
            xor_key=xor_key,
        ),
        artifacts,
    )


def build_parser() -> argparse.ArgumentParser:
    """CLI parserを構築する。"""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--json", type=Path)
    parser.add_argument(
        "--rotation", type=lambda value: int(value, 0), default=DEFAULT_ROTATION
    )
    parser.add_argument(
        "--xor-key", type=lambda value: int(value, 0), default=DEFAULT_XOR_KEY
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """sidecarを実行せず復号し、Donut検証に成功した場合だけ保存する。"""

    args = build_parser().parse_args(argv)
    data = args.input.read_bytes()
    report, artifacts = recover_rotated_xor_donut(
        data,
        rotation=args.rotation,
        xor_key=args.xor_key,
    )
    if args.output and artifacts:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_bytes(artifacts[0][1])
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(
            json.dumps(report, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
    print(json.dumps(report, ensure_ascii=False))
    return 0 if artifacts else 20


if __name__ == "__main__":
    raise SystemExit(main())
