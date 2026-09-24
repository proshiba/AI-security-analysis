#!/usr/bin/env python3
"""認証済み検体の指定静的レイヤーだけを私有AES-256 ZIPへ書き出す。"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import zipfile
from pathlib import Path

import pyzipper

from analyze_sample import REPOSITORY_ROOT, read_input_unit, recover_static_layers


SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
MAX_SOURCE_BYTES = 512 * 1024 * 1024
MAX_LAYERS = 256


def _digest(value: str) -> str:
    """SHA-256引数を小文字の完全値に限定する。"""

    if SHA256_RE.fullmatch(value) is None:
        raise ValueError("完全な小文字SHA-256が必要です")
    return value


def _private_destination(path: Path) -> Path:
    """repository内への生レイヤー出力と既存ファイル上書きを拒否する。"""

    resolved = path.resolve()
    if resolved.is_relative_to(REPOSITORY_ROOT.resolve()):
        raise ValueError("復元レイヤーはrepository外に保存してください")
    if resolved.suffix.lower() != ".zip":
        raise ValueError("出力は暗号化ZIPに限定します")
    if path.exists():
        raise FileExistsError(f"出力先は既に存在します: {path}")
    return resolved


def _write_verified_archive(path: Path, *, digest: str, data: bytes) -> str:
    """排他的に暗号化ZIPを作成し、復号後のサイズとハッシュを照合する。"""

    path.parent.mkdir(parents=True, exist_ok=True)
    member = f"{digest}.quarantine.bin"
    with path.open("xb") as stream:
        with pyzipper.AESZipFile(
            stream,
            "w",
            compression=zipfile.ZIP_DEFLATED,
            encryption=pyzipper.WZ_AES,
        ) as archive:
            archive.setpassword(b"infected")
            archive.setencryption(pyzipper.WZ_AES, nbits=256)
            archive.writestr(member, data)
    with pyzipper.AESZipFile(path) as archive:
        infos = archive.infolist()
        if len(infos) != 1 or infos[0].filename != member or not infos[0].flag_bits & 1:
            raise ValueError("暗号化ZIPのmember検証に失敗しました")
        archive.setpassword(b"infected")
        recovered = archive.read(member)
    if len(recovered) != len(data) or hashlib.sha256(recovered).hexdigest() != digest:
        raise ValueError("暗号化ZIPの復号後ハッシュが一致しません")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def export_verified_layer(
    source_zip: Path,
    output_zip: Path,
    *,
    expected_outer_sha256: str,
    expected_root_sha256: str,
    target_sha256: str,
    target_parent_sha256: str,
) -> dict[str, object]:
    """親子ハッシュを検証して指定した復元レイヤーだけを暗号化保存する。"""

    expected_outer_sha256 = _digest(expected_outer_sha256)
    expected_root_sha256 = _digest(expected_root_sha256)
    target_sha256 = _digest(target_sha256)
    target_parent_sha256 = _digest(target_parent_sha256)
    output = _private_destination(output_zip)
    if source_zip.resolve() == output:
        raise ValueError("入力と出力が同一です")
    unit = read_input_unit(
        source_zip,
        password="infected",
        archive_mode="malwarebazaar",
        max_file_size=MAX_SOURCE_BYTES,
    )
    if unit.input_kind != "authenticated_single_member_zip":
        raise ValueError("認証済み単一member ZIPが必要です")
    if unit.outer_sha256 != expected_outer_sha256:
        raise ValueError("外装ZIPのSHA-256が一致しません")
    if hashlib.sha256(unit.data).hexdigest() != expected_root_sha256:
        raise ValueError("ルート検体のSHA-256が一致しません")
    layers, report = recover_static_layers(unit, max_static_layers=MAX_LAYERS)
    if report.get("limit_events"):
        raise ValueError("静的復元が上限に達したため書き出しません")
    matches = [layer for layer in layers if layer.sha256 == target_sha256]
    if len(matches) != 1:
        raise ValueError("指定レイヤーを一意に復元できません")
    layer = matches[0]
    if layer.parent_sha256 != target_parent_sha256:
        raise ValueError("指定レイヤーの親SHA-256が一致しません")
    if hashlib.sha256(layer.data).hexdigest() != target_sha256:
        raise ValueError("復元レイヤーのバイト列とSHA-256が一致しません")
    archive_sha256 = _write_verified_archive(output, digest=target_sha256, data=layer.data)
    return {
        "schema_version": 1,
        "root_sha256": expected_root_sha256,
        "outer_zip_sha256": expected_outer_sha256,
        "target_sha256": target_sha256,
        "target_parent_sha256": target_parent_sha256,
        "target_size": len(layer.data),
        "target_depth": layer.depth,
        "target_transform": layer.transform,
        "archive_sha256": archive_sha256,
        "sample_executed": False,
        "network_contacted": False,
    }


def main() -> int:
    """認証済みの親子SHA-256をCLIから受け取り静的レイヤーを輸出する。"""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-zip", required=True, type=Path)
    parser.add_argument("--output-zip", required=True, type=Path)
    parser.add_argument("--expected-outer-sha256", required=True)
    parser.add_argument("--expected-root-sha256", required=True)
    parser.add_argument("--target-sha256", required=True)
    parser.add_argument("--target-parent-sha256", required=True)
    args = parser.parse_args()
    result = export_verified_layer(
        args.source_zip,
        args.output_zip,
        expected_outer_sha256=args.expected_outer_sha256,
        expected_root_sha256=args.expected_root_sha256,
        target_sha256=args.target_sha256,
        target_parent_sha256=args.target_parent_sha256,
    )
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
