#!/usr/bin/env python3
"""RedLine静的復元レポートから安全なMethodDefメタデータ一覧を生成する。"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any

from analyze_redline_process_dump import read_regular_file, write_new_json

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
TOKEN_RE = re.compile(r"^0x06[0-9a-f]{6}$")
LOGICAL_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
DATASTORE_PREFIX = "s3://malware-analysis-datastore-720232834682/"


class InventoryError(ValueError):
    """入力レポートが期待する静的解析契約を満たさない場合の例外。"""


def _strict_json(data: bytes) -> dict[str, Any]:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise InventoryError(f"JSONに重複キーがあります: {key}")
            result[key] = value
        return result

    def reject_constant(value: str) -> None:
        raise InventoryError(f"非標準数値は使用できません: {value}")

    try:
        value = json.loads(
            data.decode("utf-8-sig"),
            object_pairs_hook=reject_duplicates,
            parse_constant=reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise InventoryError("入力は厳格なUTF-8 JSONではありません") from exc
    if not isinstance(value, dict):
        raise InventoryError("入力JSONの最上位はobjectである必要があります")
    return value


def build_inventory(
    source_data: bytes,
    *,
    sample_sha256: str,
    source_logical_id: str,
    source_availability: str,
    source_archive_uri: str,
) -> dict[str, Any]:
    """生CILを含めず、全MethodDefの識別子と意味フィンガープリントだけを返す。"""

    sample_digest = sample_sha256.casefold()
    if not SHA256_RE.fullmatch(sample_digest):
        raise InventoryError("sample SHA-256が不正です")
    if not LOGICAL_ID_RE.fullmatch(source_logical_id):
        raise InventoryError("source logical IDが不正です")
    if source_availability != "private_s3_archive":
        raise InventoryError("source availabilityが不正です")
    if not source_archive_uri.startswith(DATASTORE_PREFIX):
        raise InventoryError("source archive URIは指定datastore配下に限定されます")

    document = _strict_json(source_data)
    candidates = document.get("candidates")
    if not isinstance(candidates, list):
        raise InventoryError("candidates配列がありません")
    terminals = [item for item in candidates if isinstance(item, dict) and item.get("terminal") is True]
    if len(terminals) != 1:
        raise InventoryError("terminal candidateは正確に1件必要です")
    terminal = terminals[0]
    identity = terminal.get("identity")
    managed = terminal.get("managed_methods")
    methods = managed.get("inventory") if isinstance(managed, dict) else None
    if not isinstance(identity, dict) or not isinstance(methods, list):
        raise InventoryError("terminal identityまたはmanaged method inventoryがありません")

    expected_count = managed.get("metadata_method_count")
    parsed_count = managed.get("cil_body_count")
    if expected_count != len(methods) or not isinstance(parsed_count, int):
        raise InventoryError("MethodDef件数が入力レポート内で一致しません")

    output_methods: list[dict[str, Any]] = []
    seen_tokens: set[str] = set()
    body_count = 0
    for item in methods:
        if not isinstance(item, dict):
            raise InventoryError("method recordがobjectではありません")
        token = str(item.get("method_token") or "").casefold()
        owner = item.get("owner")
        name = item.get("name")
        has_body = item.get("has_cil_body")
        fingerprint = item.get("normalized_fingerprint_sha256")
        if (
            not TOKEN_RE.fullmatch(token)
            or token in seen_tokens
            or not isinstance(owner, str)
            or not isinstance(name, str)
            or not isinstance(has_body, bool)
        ):
            raise InventoryError("method recordの識別子または型が不正です")
        if has_body:
            body_count += 1
            if not isinstance(fingerprint, str) or not SHA256_RE.fullmatch(fingerprint.casefold()):
                raise InventoryError("CIL bodyを持つmethodのfingerprintが不正です")
            fingerprint = fingerprint.casefold()
        elif fingerprint is not None:
            raise InventoryError("CIL bodyを持たないmethodにfingerprintがあります")
        seen_tokens.add(token)
        output_methods.append(
            {
                "method_token": token,
                "owner": owner,
                "name": name,
                "has_cil_body": has_body,
                "normalized_fingerprint_sha256": fingerprint,
            }
        )
    if body_count != parsed_count:
        raise InventoryError("CIL body件数が入力レポート内で一致しません")

    terminal_sha = str(terminal.get("sha256") or "").casefold()
    cil_sha = str(terminal.get("cil_semantic_sha256") or "").casefold()
    mvid = identity.get("mvid")
    if (
        not SHA256_RE.fullmatch(terminal_sha)
        or not SHA256_RE.fullmatch(cil_sha)
        or not isinstance(mvid, str)
        or not mvid
    ):
        raise InventoryError("terminal identityが不正です")

    return {
        "schema_version": 1,
        "artifact_type": "redline_managed_method_inventory",
        "sample_sha256": sample_digest,
        "terminal_candidate": {
            "sha256": terminal_sha,
            "mvid": mvid,
            "cil_semantic_sha256": cil_sha,
        },
        "summary": {
            "method_definition_count": expected_count,
            "parsed_cil_body_count": parsed_count,
            "inventory_count": len(output_methods),
            "raw_cil_included": False,
        },
        "source": {
            "logical_id": source_logical_id,
            "availability": source_availability,
            "archive_uri": source_archive_uri,
            "sha256": hashlib.sha256(source_data).hexdigest(),
            "size": len(source_data),
            "json_pointer": "/candidates/0/managed_methods/inventory",
        },
        "methods": output_methods,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--sample-sha256", required=True)
    parser.add_argument("--source-logical-id", required=True)
    parser.add_argument(
        "--source-availability",
        choices=("private_s3_archive",),
        default="private_s3_archive",
    )
    parser.add_argument("--source-archive-uri", required=True)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    source = read_regular_file(args.input, maximum=64 * 1024 * 1024)
    inventory = build_inventory(
        source,
        sample_sha256=args.sample_sha256,
        source_logical_id=args.source_logical_id,
        source_availability=args.source_availability,
        source_archive_uri=args.source_archive_uri,
    )
    write_new_json(args.output, inventory, root=Path.cwd())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
