"""Statically reconstruct the APT-C-60 LNK/Base64/TAR downloader chain.

No JavaScript, LNK, Git executable, or reconstructed payload is executed.
Tar members are read in memory with traversal and size checks.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import tarfile

MAX_ARCHIVE = 256 * 1024 * 1024
MAX_MEMBER = 128 * 1024 * 1024


def sha256_bytes(data: bytes) -> str:
    """Return a lowercase SHA-256 digest."""
    return hashlib.sha256(data).hexdigest()


def decode_base64_tar(data: bytes) -> bytes:
    """Strictly decode a whitespace-wrapped Base64 TAR payload."""
    compact = b"".join(data.split())
    if not compact or len(compact) > MAX_ARCHIVE * 2:
        raise ValueError("Base64 carrier is empty or exceeds the size limit")
    try:
        decoded = base64.b64decode(compact, validate=True)
    except binascii.Error as exc:
        raise ValueError("carrier is not strict Base64") from exc
    if len(decoded) > MAX_ARCHIVE:
        raise ValueError("decoded TAR exceeds the size limit")
    try:
        with tarfile.open(fileobj=io.BytesIO(decoded), mode="r:*") as archive:
            archive.getmembers()
    except tarfile.TarError as exc:
        raise ValueError("decoded data is not a TAR archive") from exc
    return decoded


def safe_member_name(name: str) -> str:
    """Normalize one TAR member and reject unsafe path forms."""
    normalized = name.replace("\\", "/")
    path = PurePosixPath(normalized)
    if (
        not normalized
        or normalized.startswith("/")
        or re.match(r"^[A-Za-z]:", normalized)
    ):
        raise ValueError(f"unsafe TAR member: {name}")
    if any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError(f"unsafe TAR member: {name}")
    return normalized


def read_tar_members(tar_data: bytes) -> dict[str, bytes]:
    """Return regular TAR members in memory after link, path, and size checks."""
    members: dict[str, bytes] = {}
    total = 0
    with tarfile.open(fileobj=io.BytesIO(tar_data), mode="r:*") as archive:
        for info in archive.getmembers():
            name = safe_member_name(info.name)
            if info.issym() or info.islnk():
                raise ValueError(f"TAR links are not accepted: {name}")
            if not info.isfile():
                continue
            if info.size > MAX_MEMBER:
                raise ValueError(f"TAR member exceeds size limit: {name}")
            total += info.size
            if total > MAX_ARCHIVE:
                raise ValueError("TAR members exceed aggregate size limit")
            stream = archive.extractfile(info)
            if stream is None:
                raise ValueError(f"failed to read TAR member: {name}")
            members[name] = stream.read(MAX_MEMBER + 1)
    return members


def parse_copy_b_script(text: str) -> tuple[list[str], str]:
    """Parse the binary-concatenation command from an APT-C-60 install script."""
    match = re.search(r"copy\s+/b\s+(.+?)\s+([^\s\r\n]+)\s*$", text, re.I | re.M)
    if not match:
        raise ValueError("copy /b reconstruction command not found")
    source_expression, destination = match.groups()
    fragments = [item.strip().strip('"') for item in source_expression.split("+")]
    if len(fragments) < 2 or any(not item for item in fragments):
        raise ValueError("copy /b fragment list is invalid")
    return fragments, destination.strip().strip('"')


def reconstruct_fragmented_payload(carrier: bytes) -> tuple[dict, bytes]:
    """Decode a Base64 TAR and reconstruct the payload named by its script."""
    tar_data = decode_base64_tar(carrier)
    members = read_tar_members(tar_data)
    scripts = [
        (name, value)
        for name, value in members.items()
        if name.lower().endswith((".log", ".cmd", ".bat"))
    ]
    for script_name, script_data in scripts:
        text = script_data.decode("utf-8", errors="replace")
        try:
            fragments, destination = parse_copy_b_script(text)
        except ValueError:
            continue
        by_basename = {
            PurePosixPath(name).name.lower(): value for name, value in members.items()
        }
        missing = [
            name
            for name in fragments
            if PurePosixPath(name).name.lower() not in by_basename
        ]
        if missing:
            raise ValueError(f"script references missing fragments: {missing}")
        payload = b"".join(
            by_basename[PurePosixPath(name).name.lower()] for name in fragments
        )
        return {
            "schema_version": 1,
            "carrier_sha256": sha256_bytes(carrier),
            "tar_sha256": sha256_bytes(tar_data),
            "script": script_name,
            "script_sha256": sha256_bytes(script_data),
            "fragment_names": fragments,
            "fragment_sha256": [
                sha256_bytes(by_basename[PurePosixPath(name).name.lower()])
                for name in fragments
            ],
            "destination": destination,
            "payload_sha256": sha256_bytes(payload),
            "payload_size": len(payload),
            "member_count": len(members),
            "executed": False,
        }, payload
    raise ValueError("no supported install script found in TAR")


def extract_printable_strings(data: bytes, minimum: int = 4) -> list[str]:
    """Extract ordered ASCII and UTF-16LE strings from a delivery artifact."""
    ascii_pattern = re.compile(rb"[\x20-\x7e]{%d,}" % minimum)
    wide_pattern = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % minimum)
    values = [
        match.group().decode("ascii", errors="ignore")
        for match in ascii_pattern.finditer(data)
    ]
    values.extend(
        match.group().decode("utf-16le", errors="ignore")
        for match in wide_pattern.finditer(data)
    )
    return list(dict.fromkeys(value for value in values if value))


def inspect_lnk(data: bytes) -> dict:
    """Extract embedded script URLs and high-signal actions from LNK bytes."""
    strings = extract_printable_strings(data)
    text = "\n".join(strings)
    urls = sorted(set(re.findall(r"https?://[^\s\"'<>]+", text, re.I)))
    actions = [
        marker
        for marker in (
            "mshta",
            "certutil -decode",
            "tar -xzvf",
            "CopyFile",
            "copy /b",
            "reg add",
            "WScript.Shell",
        )
        if marker.lower() in text.lower()
    ]
    scripts = re.findall(r"<script\b.*?</script>", text, re.I | re.S)
    return {
        "schema_version": 1,
        "sha256": sha256_bytes(data),
        "urls": urls,
        "actions": actions,
        "embedded_script_count": len(scripts),
        "embedded_script_sha256": [
            sha256_bytes(item.encode("utf-8")) for item in scripts
        ],
        "executed": False,
    }


def build_parser() -> argparse.ArgumentParser:
    """Build the static delivery-chain command-line parser."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--kind", choices=("auto", "lnk", "base64-tar"), default="auto")
    parser.add_argument("--payload-output", type=Path)
    parser.add_argument("--report", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    """Inspect one carrier and optionally persist a reconstructed payload."""
    args = build_parser().parse_args(argv)
    data = args.input.read_bytes()
    kind = args.kind
    if kind == "auto":
        kind = "lnk" if data[:4] == b"L\x00\x00\x00" else "base64-tar"
    if kind == "lnk":
        report, payload = inspect_lnk(data), None
    else:
        report, payload = reconstruct_fragmented_payload(data)
    report["network_contacted"] = False
    if args.payload_output and payload is not None:
        args.payload_output.parent.mkdir(parents=True, exist_ok=True)
        args.payload_output.write_bytes(payload)
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(
            json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
