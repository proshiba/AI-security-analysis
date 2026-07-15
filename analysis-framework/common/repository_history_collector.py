"""Inventory every reachable blob in a local Git mirror without executing content."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from collections import defaultdict
from pathlib import Path, PurePosixPath
from typing import Any

URL_RE = re.compile(rb"https?://[^\x00-\x20\"'<>]{4,500}", re.I)
IP_RE = re.compile(rb"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")


def git_output(git_dir: Path, arguments: list[str], text: bool = False) -> bytes | str:
    """Run a read-only Git query against an explicit repository directory."""
    command = ["git", f"--git-dir={git_dir}", *arguments]
    result = subprocess.run(command, check=True, capture_output=True, text=text)
    return result.stdout


def safe_suffix(path: str) -> str:
    """Return a short sanitized suffix that preserves the original extension."""
    suffix = PurePosixPath(path).suffix.lower()
    return suffix if re.fullmatch(r"\.[a-z0-9]{1,10}", suffix) else ".blob"


def detect_format(data: bytes) -> str:
    """Identify common container, executable, script, and text formats by bytes."""
    if data.startswith(b"MZ"):
        return "pe"
    if data.startswith(b"PK\x03\x04"):
        return "zip"
    if data.startswith(b"Rar!\x1a\x07"):
        return "rar"
    if data.startswith(b"\x7fELF"):
        return "elf"
    if data.startswith(b"\x1f\x8b"):
        return "gzip"
    sample = data[:8192]
    if not sample:
        return "empty"
    printable = sum(byte in b"\t\r\n" or 0x20 <= byte < 0x7F for byte in sample)
    return "text" if printable / len(sample) >= 0.85 else "binary"


def static_iocs(data: bytes) -> dict[str, list[str]]:
    """Extract literal URLs and validated IPv4 candidates from one blob."""
    urls = sorted({value.decode("utf-8", errors="replace").rstrip(".,;)") for value in URL_RE.findall(data)})
    ips = set()
    for raw in IP_RE.findall(data):
        value = raw.decode("ascii")
        try:
            if all(0 <= int(part) <= 255 for part in value.split(".")):
                ips.add(value)
        except ValueError:
            continue
    return {"urls": urls, "ipv4": sorted(ips)}


def reachable_commits(git_dir: Path) -> list[str]:
    """Return every reachable commit in deterministic oldest-first order."""
    output = git_output(git_dir, ["rev-list", "--reverse", "--all"], text=True)
    return [line for line in output.splitlines() if line]


def commit_metadata(git_dir: Path, commit: str) -> dict[str, str]:
    """Read publish-safe author and timestamp metadata for one commit."""
    pattern = "%H%x00%an%x00%ae%x00%aI%x00%cn%x00%ce%x00%cI%x00%s"
    raw = git_output(git_dir, ["show", "-s", f"--format={pattern}", commit])
    values = raw.rstrip(b"\n").split(b"\x00", 7)
    if len(values) != 8:
        raise ValueError(f"unexpected commit metadata for {commit}")
    keys = (
        "sha",
        "author_name",
        "author_email",
        "author_time",
        "committer_name",
        "committer_email",
        "committer_time",
        "subject",
    )
    return {key: value.decode("utf-8", errors="replace") for key, value in zip(keys, values)}


def tree_entries(git_dir: Path, commit: str) -> list[tuple[str, int, str]]:
    """Return path, declared size, and blob SHA-1 for a commit tree."""
    raw = git_output(git_dir, ["ls-tree", "-r", "-l", "-z", commit])
    entries = []
    for record in raw.split(b"\x00"):
        if not record:
            continue
        header, path = record.split(b"\t", 1)
        mode, kind, object_id, size = header.split()
        if kind != b"blob":
            continue
        entries.append((path.decode("utf-8", errors="replace"), int(size), object_id.decode("ascii")))
    return entries


def collect_repository(
    git_dir: Path, export_dir: Path | None = None, maximum_blob_size: int = 64 * 1024 * 1024
) -> dict[str, Any]:
    """Inventory all historical blobs and optionally export each unique byte sequence."""
    git_dir = git_dir.resolve()
    if maximum_blob_size <= 0:
        raise ValueError("maximum blob size must be positive")
    commits = reachable_commits(git_dir)
    paths: dict[str, set[str]] = defaultdict(set)
    appearances: dict[str, set[str]] = defaultdict(set)
    sizes: dict[str, int] = {}
    commit_rows = []
    for commit in commits:
        commit_rows.append(commit_metadata(git_dir, commit))
        for path, size, object_id in tree_entries(git_dir, commit):
            paths[object_id].add(path)
            appearances[object_id].add(commit)
            sizes[object_id] = size
    if export_dir:
        export_dir.mkdir(parents=True, exist_ok=True)
    blobs = []
    for object_id in sorted(paths):
        size = sizes[object_id]
        row: dict[str, Any] = {
            "git_object": object_id,
            "size": size,
            "paths": sorted(paths[object_id]),
            "commits": sorted(appearances[object_id]),
        }
        if size <= maximum_blob_size:
            data = git_output(git_dir, ["cat-file", "blob", object_id])
            digest = hashlib.sha256(data).hexdigest()
            row.update({"sha256": digest, "format": detect_format(data), "iocs": static_iocs(data)})
            if export_dir:
                target = export_dir / f"{digest}{safe_suffix(row['paths'][0])}"
                target.write_bytes(data)
                row["exported_as"] = target.name
        else:
            row["skipped"] = "maximum_blob_size"
        blobs.append(row)
    return {
        "schema_version": 1,
        "git_dir": str(git_dir),
        "commit_count": len(commits),
        "commits": commit_rows,
        "blob_count": len(blobs),
        "blobs": blobs,
        "executed": False,
        "network_contacted": False,
    }


def build_parser() -> argparse.ArgumentParser:
    """Build the local Git-mirror inventory command-line parser."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--git-dir", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--export-dir", type=Path)
    parser.add_argument("--maximum-blob-size", type=int, default=64 * 1024 * 1024)
    return parser


def main(argv: list[str] | None = None) -> int:
    """Inventory one mirror and write deterministic JSON metadata."""
    args = build_parser().parse_args(argv)
    report = collect_repository(args.git_dir, args.export_dir, args.maximum_blob_size)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(args.output), "commits": report["commit_count"], "blobs": report["blob_count"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
