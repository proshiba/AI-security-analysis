"""Targeted NSIS -> 7z -> Electron ASAR recovery using 7-Zip as a parser."""

from __future__ import annotations

import hashlib
from pathlib import Path, PurePosixPath
import subprocess
import tempfile

from unpackers.path_safety import safe_member_name
from unpackers.asar_unpacker import is_asar

MAX_ARCHIVE = 256 * 1024 * 1024
MAX_ASAR = 64 * 1024 * 1024
MAX_MEMBERS = 512


def safe_archive_member(name: str) -> str:
    """Normalize and validate one untrusted 7-Zip member path."""
    return safe_member_name(name, "archive")


def select_nested_7z_members(names: list[str]) -> list[str]:
    """Return bounded nested 7z candidates from an NSIS listing."""
    candidates = []
    for name in names[:MAX_MEMBERS]:
        normalized = safe_archive_member(name)
        if normalized.lower().endswith(".7z"):
            candidates.append(name)
    return candidates[:8]


def select_asar_members(names: list[str]) -> list[str]:
    """Return bounded app.asar candidates, preferring the canonical path."""
    candidates = []
    for name in names[:MAX_MEMBERS]:
        normalized = safe_archive_member(name)
        if normalized.lower().endswith(".asar"):
            priority = 0 if normalized.lower().endswith("resources/app.asar") else 1
            candidates.append((priority, normalized.lower(), name))
    return [item[2] for item in sorted(candidates)[:8]]


def list_archive(path: Path, executable: Path, timeout: float = 60.0) -> dict:
    """List one archive with 7-Zip and return bounded type/member metadata."""
    completed = subprocess.run(
        [str(executable), "l", "-slt", "--", str(path)],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    names, types = [], []
    for line in completed.stdout.splitlines():
        if line.startswith("Path = "):
            value = line[7:]
            if value != str(path):
                names.append(value)
        elif line.startswith("Type = "):
            types.append(line[7:])
    return {
        "status": "listed" if completed.returncode == 0 else "unsupported",
        "exit_code": completed.returncode,
        "types": sorted(set(types)),
        "members": names[:MAX_MEMBERS],
        "total_members": len(names),
    }


def extract_member(path: Path, member: str, output: Path, executable: Path, timeout: float = 180.0) -> Path:
    """Extract one validated archive member and return its unambiguous local path."""
    normalized = safe_archive_member(member)
    output.mkdir(parents=True, exist_ok=True)
    completed = subprocess.run(
        [str(executable), "x", "-y", "-bd", "-bb0", f"-o{output}", str(path), member],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    if completed.returncode != 0:
        raise ValueError(f"7-Zip extraction failed: {completed.returncode}")
    basename = PurePosixPath(normalized).name
    matches = [item for item in output.rglob(basename) if item.is_file()]
    if len(matches) != 1:
        raise ValueError("extracted member was missing or ambiguous")
    return matches[0]


def recover_electron_asars(data: bytes, executable: Path) -> tuple[dict, list[tuple[str, bytes]]]:
    """Recover nested Electron ASAR bytes without expanding the full app bundle."""
    if not executable.is_file():
        return {"status": "unavailable", "path": str(executable)}, []
    if not 0 < len(data) <= MAX_ARCHIVE:
        return {"status": "outer_size_blocked", "size": len(data)}, []
    reports, artifacts = [], []
    with tempfile.TemporaryDirectory(prefix="asa-electron-nsis-") as directory:
        root = Path(directory)
        outer = root / "outer.bin"
        outer.write_bytes(data)
        outer_listing = list_archive(outer, executable)
        if "Nsis" not in outer_listing.get("types", []) and "nsis" not in {
            value.lower() for value in outer_listing.get("types", [])
        }:
            return {**outer_listing, "status": "not_nsis"}, []
        for index, nested_name in enumerate(select_nested_7z_members(outer_listing["members"])):
            item = {"nested_member": safe_archive_member(nested_name)}
            try:
                nested = extract_member(outer, nested_name, root / f"outer-{index}", executable)
                if not 0 < nested.stat().st_size <= MAX_ARCHIVE:
                    item.update(status="nested_size_blocked", size=nested.stat().st_size)
                    reports.append(item)
                    continue
                listing = list_archive(nested, executable)
                item["nested_listing"] = listing
                for asar_index, asar_name in enumerate(select_asar_members(listing["members"])):
                    path = extract_member(nested, asar_name, root / f"asar-{index}-{asar_index}", executable)
                    if not 0 < path.stat().st_size <= MAX_ASAR:
                        continue
                    blob = path.read_bytes()
                    if not is_asar(blob):
                        continue
                    digest = hashlib.sha256(blob).hexdigest()
                    artifacts.append(("electron-app-asar", blob))
                    item.setdefault("asars", []).append(
                        {"name": safe_archive_member(asar_name), "size": len(blob), "sha256": digest}
                    )
                item["status"] = "asar_recovered" if item.get("asars") else "no_asar"
            except (OSError, subprocess.TimeoutExpired, ValueError) as exc:
                item.update(status="recovery_failed", error=type(exc).__name__)
            reports.append(item)
    seen, deduplicated = set(), []
    for kind, blob in artifacts:
        digest = hashlib.sha256(blob).hexdigest()
        if digest not in seen:
            seen.add(digest)
            deduplicated.append((kind, blob))
    return {
        "status": "asar_recovered" if deduplicated else "no_asar_recovered",
        "outer_listing": outer_listing,
        "nested": reports,
        "sample_executed": False,
    }, deduplicated
