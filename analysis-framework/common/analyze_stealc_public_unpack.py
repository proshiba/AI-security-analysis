#!/usr/bin/env python3
"""公開unpack JSONからStealCの終端hash・config・C2を検証して復元する。"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
COMMON_ROOT = Path(__file__).resolve().parent
for import_root in (REPOSITORY_ROOT, COMMON_ROOT):
    if str(import_root) not in sys.path:
        sys.path.insert(0, str(import_root))

from extractors.stealc.public_unpack import extract_public_unpack_evidence
from immutable_snapshot import (
    decode_strict_json,
    ensure_new_output,
    read_bounded_snapshot,
    write_new_json,
)

MAX_INPUT_BYTES = 16 * 1024 * 1024


def load_bounded_json(path: Path) -> tuple[dict, str, dict[str, int | str]]:
    """不変snapshotから上限内のJSON objectだけを読み込む。"""
    snapshot = read_bounded_snapshot(path, MAX_INPUT_BYTES)
    payload = decode_strict_json(snapshot.data)
    if not isinstance(payload, dict):
        raise TypeError("公開unpack JSONのrootがobjectではありません")
    return payload, snapshot.identity.sha256, snapshot.identity.public_dict()


def main() -> int:
    """CLI entry point。"""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--expected-parent-sha256", required=True)
    parser.add_argument("--expected-provider-result-id", required=True)
    parser.add_argument("--expected-provider-json-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    source = arguments.input
    output = ensure_new_output(arguments.output, (source,))
    payload, actual_json_sha256, snapshot_identity = load_bounded_json(source)
    report = extract_public_unpack_evidence(
        payload,
        arguments.expected_parent_sha256,
        expected_provider_result_id=arguments.expected_provider_result_id,
        expected_provider_json_sha256=arguments.expected_provider_json_sha256,
        actual_provider_json_sha256=actual_json_sha256,
    )
    report["input_snapshot"] = snapshot_identity
    write_new_json(output, report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
