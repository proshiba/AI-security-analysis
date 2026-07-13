from __future__ import annotations
import argparse, hashlib, json, zipfile
from pathlib import Path
import pyzipper

def sha256(path: Path) -> str:
    """Implement the sha256 operation for the analysis framework."""
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()

def safe_members(names: list[str]) -> None:
    """Implement the safe members operation for the analysis framework."""
    for name in names:
        candidate = Path(name)
        if candidate.is_absolute() or ".." in candidate.parts:
            raise ValueError(f"unsafe archive member: {name}")

def main() -> int:
    """Implement the main operation for the analysis framework."""
    parser = argparse.ArgumentParser(description="Safely extract the MalwareBazaar and nested ZIP archives.")
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--case-root", required=True, type=Path)
    parser.add_argument("--password", default="infected")
    parser.add_argument("--expected-inner-sha256", required=True)
    args = parser.parse_args()
    extracted = args.case_root / "workflow-output" / "extracted"
    payload = args.case_root / "workflow-output" / "payload"
    extracted.mkdir(parents=True, exist_ok=True)
    payload.mkdir(parents=True, exist_ok=True)
    with pyzipper.AESZipFile(args.archive) as archive:
        safe_members(archive.namelist())
        archive.extractall(extracted, pwd=args.password.encode())
    candidates = [p for p in extracted.rglob("*") if p.is_file()]
    matches = [p for p in candidates if sha256(p).lower() == args.expected_inner_sha256.lower()]
    if len(matches) != 1:
        raise RuntimeError(f"expected exactly one inner hash match, found {len(matches)}")
    inner = matches[0]
    if not zipfile.is_zipfile(inner):
        raise RuntimeError(f"inner sample is not a ZIP archive: {inner}")
    with zipfile.ZipFile(inner) as archive:
        safe_members(archive.namelist())
        archive.extractall(payload)
    result = {
        "outer_archive": str(args.archive), "inner_sample": str(inner),
        "inner_sha256": sha256(inner), "payload_directory": str(payload),
        "payload_file_count": sum(1 for p in payload.rglob("*") if p.is_file()),
        "executed": False,
    }
    (args.case_root / "workflow-output" / "extraction-result.json").write_text(
        json.dumps(result, indent=2), encoding="utf-8"
    )
    print(json.dumps(result, indent=2))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())

