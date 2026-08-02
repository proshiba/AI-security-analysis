from __future__ import annotations
import argparse
import io
import zipfile
from pathlib import Path
from malware_io import persist_archive_members, read_aes_zip_members, read_zip_members, safety_metadata, write_json

def extract_zip_bytes(data: bytes, destination: Path) -> int:
    """内包ZIPを全件検証してから、上書きせずに保存する。"""

    members = read_zip_members(data)
    return len(persist_archive_members(members, destination))

def main() -> int:
    parser = argparse.ArgumentParser(description="確認済み内包ZIPをhash完全一致後に安全保存する。")
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--case-root", required=True, type=Path)
    parser.add_argument("--password", default="infected")
    parser.add_argument("--expected-inner-sha256", required=True)
    args = parser.parse_args()
    members = read_aes_zip_members(args.archive, password=args.password)
    matches = [member for member in members if member.sha256.lower() == args.expected_inner_sha256.lower()]
    if len(matches) != 1:
        raise ValueError(f"内包hash一致は1件だけ必要です: {len(matches)}件")
    inner = matches[0]
    if not zipfile.is_zipfile(io.BytesIO(inner.data)):
        raise ValueError(f"内包メンバーはZIPではありません: {inner.name}")
    extracted = args.case_root / "workflow-output" / "extracted"
    payload = args.case_root / "workflow-output" / "payload"
    payload_members = read_zip_members(inner.data)
    inner_path = persist_archive_members([inner], extracted, preserve_paths=False)[0]
    count = len(persist_archive_members(payload_members, payload))
    result = {"schema_version": 2, "outer_archive": str(args.archive), "inner_sample": str(inner_path), "inner_sha256": inner.sha256, "payload_directory": str(payload), "payload_file_count": count, **safety_metadata()}
    write_json(args.case_root / "workflow-output" / "extraction-result.json", result)
    print(result)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
