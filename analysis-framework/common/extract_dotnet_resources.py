#!/usr/bin/env python3
""".NETマニフェストリソースを実行せず抽出し、ハッシュ一覧を作成する。"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path

import dnfile


SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]+")


def safe_name(value: str, index: int) -> str:
    """リソース名を単一の安全なファイル名へ正規化する。"""
    name = SAFE_NAME.sub("_", Path(value.replace("\\", "/")).name).strip("._")
    return name or f"resource-{index:04d}.bin"


def _entry_bytes(value: object) -> tuple[bytes, str] | None:
    if isinstance(value, bytes):
        return value, "binary"
    if isinstance(value, str):
        return value.encode("utf-8"), "utf-8"
    return None


def resource_blobs(data: bytes) -> tuple[list[dict], list[str]]:
    """抽出可能なblob/stringリソースと解析上の警告を返す。"""
    warnings: list[str] = []
    try:
        pe = dnfile.dnPE(data=data)
    except Exception as exc:
        return [], [f"dnfileでPEを解析できませんでした: {type(exc).__name__}"]
    if pe.net is None:
        return [], ["CLRヘッダーがないため.NETリソースを解析できません。"]
    try:
        resources = list(pe.net.resources or [])
    except Exception as exc:
        return [], [f".NETリソース表を読めませんでした: {type(exc).__name__}"]

    results: list[dict] = []
    output_index = 0
    for resource in resources:
        direct = _entry_bytes(resource.data)
        if direct is not None:
            raw, encoding = direct
            output_index += 1
            results.append({
                "index": output_index,
                "original_name": str(resource.name),
                "container_name": None,
                "resource_type": "manifest_blob" if encoding == "binary" else "System.String",
                "value_encoding": encoding,
                "output_name": safe_name(str(resource.name), output_index),
                "size": len(raw),
                "sha256": hashlib.sha256(raw).hexdigest(),
                "data": raw,
            })
            continue
        entries = getattr(resource.data, "entries", None)
        if entries is None:
            warnings.append(f"{resource.name}: 未対応の複合.resources形式です。")
            continue
        for entry in entries:
            converted = _entry_bytes(getattr(entry, "value", None))
            if converted is None:
                continue
            value, encoding = converted
            output_index += 1
            entry_name = str(getattr(entry, "name", f"entry-{output_index:04d}"))
            results.append({
                "index": output_index,
                "original_name": entry_name,
                "container_name": str(resource.name),
                "resource_type": str(getattr(entry, "type_name", "unknown")),
                "value_encoding": encoding,
                "output_name": safe_name(entry_name, output_index),
                "size": len(value),
                "sha256": hashlib.sha256(value).hexdigest(),
                "data": value,
            })
    return results, warnings


def extract(input_path: Path, output_dir: Path, expected_sha256: str) -> dict:
    """入力ハッシュを検証してから抽出物と機械可読manifestを作る。"""
    data = input_path.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != expected_sha256.lower():
        raise ValueError(f"SHA-256不一致: expected={expected_sha256.lower()} actual={digest}")

    resources, warnings = resource_blobs(data)
    output_dir.mkdir(parents=True, exist_ok=True)
    used_names: set[str] = set()
    public_resources: list[dict] = []
    for item in resources:
        name = item["output_name"]
        if name.lower() in used_names:
            name = f"{item['index']:04d}-{name}"
        used_names.add(name.lower())
        target = output_dir / name
        target.write_bytes(item["data"])
        public_resources.append({key: value for key, value in item.items() if key != "data"} | {"output_name": name})

    result = {
        "schema_version": 2,
        "parent_sha256": digest,
        "resource_count": len(public_resources),
        "resources": public_resources,
        "warnings": warnings,
        "executed": False,
        "network_contacted": False,
    }
    (output_dir / "manifest.json").write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--expected-sha256", required=True)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()
    result = extract(args.input, args.output_dir, args.expected_sha256)
    print(json.dumps({"resource_count": result["resource_count"]}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
