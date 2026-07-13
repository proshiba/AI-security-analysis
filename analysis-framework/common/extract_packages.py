from __future__ import annotations
import argparse
import io
import zipfile
from pathlib import Path
from malware_io import read_aes_zip_members, safe_output_name, safety_metadata, validate_member_name, write_json

def extract_zip_bytes(data: bytes, destination: Path) -> int:
    destination.mkdir(parents=True, exist_ok=True)
    count = 0
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        for info in archive.infolist():
            if info.is_dir():
                continue
            name = validate_member_name(info.filename)
            target = destination.joinpath(*Path(name).parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(archive.read(info))
            count += 1
    return count

def main() -> int:
    parser = argparse.ArgumentParser(description="Safely persist a reviewed inner ZIP payload after exact hash verification.")
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--case-root", required=True, type=Path)
    parser.add_argument("--password", default="infected")
    parser.add_argument("--expected-inner-sha256", required=True)
    args = parser.parse_args()
    members = read_aes_zip_members(args.archive, password=args.password)
    matches = [member for member in members if member.sha256.lower() == args.expected_inner_sha256.lower()]
    if len(matches) != 1:
        raise ValueError(f"expected exactly one inner hash match, found {len(matches)}")
    inner = matches[0]
    if not zipfile.is_zipfile(io.BytesIO(inner.data)):
        raise ValueError(f"inner member is not a ZIP archive: {inner.name}")
    extracted = args.case_root / "workflow-output" / "extracted"
    payload = args.case_root / "workflow-output" / "payload"
    extracted.mkdir(parents=True, exist_ok=True)
    inner_path = extracted / safe_output_name(inner.name)
    inner_path.write_bytes(inner.data)
    count = extract_zip_bytes(inner.data, payload)
    result = {"schema_version": 2, "outer_archive": str(args.archive), "inner_sample": str(inner_path), "inner_sha256": inner.sha256, "payload_directory": str(payload), "payload_file_count": count, **safety_metadata()}
    write_json(args.case_root / "workflow-output" / "extraction-result.json", result)
    print(result)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
