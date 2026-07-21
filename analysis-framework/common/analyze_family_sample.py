#!/usr/bin/env python3
"""Safe recursive static triage for authenticated MalwareBazaar submissions."""
from __future__ import annotations

import argparse
import base64
import binascii
import io
import math
import re
import zipfile
from pathlib import Path

import pefile

from malware_io import (
    SCHEMA_VERSION,
    decode_text,
    read_aes_zip_members,
    safe_output_name,
    safety_metadata,
    sha256_bytes,
    sha256_file,
    validate_member_name,
    write_json,
)
from elf_utils import parse_elf_layout

PRINTABLE = re.compile(rb"[\x20-\x7e]{4,}")
WIDE = re.compile(rb"(?:[\x20-\x7e]\x00){4,}")
URL = re.compile(r"https?://[^\s\"'<>]{4,400}", re.I)
IP = re.compile(r"(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?")
DOMAIN = re.compile(r"(?<![\w.-])(?:[a-z0-9-]{1,63}\.)+[a-z]{2,24}(?::\d{1,5})?", re.I)
SCRIPT_EXT = {
    ".js",
    ".jse",
    ".vbs",
    ".vbe",
    ".hta",
    ".ps1",
    ".cmd",
    ".bat",
    ".sh",
    ".php",
    ".wsf",
    ".html",
    ".htm",
}
GENERIC_MAX_MEMBER_SIZE = 64 * 1024 * 1024
GENERIC_MAX_MEMBERS = 256
GENERIC_MAX_TOTAL_SIZE = 256 * 1024 * 1024
GENERIC_MAX_COMPRESSION_RATIO = 100.0


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for value in data:
        counts[value] += 1
    return round(-sum((n / len(data)) * math.log2(n / len(data)) for n in counts if n), 4)


def extract_strings(data: bytes, limit: int = 20_000) -> list[dict]:
    strings = [
        {"offset": match.start(), "encoding": "ascii", "value": match.group().decode("ascii")}
        for match in PRINTABLE.finditer(data)
    ]
    strings.extend(
        {"offset": match.start(), "encoding": "utf-16-le", "value": match.group()[::2].decode("ascii")}
        for match in WIDE.finditer(data)
    )
    strings.sort(key=lambda item: item["offset"])
    return strings[:limit]


def extract_iocs(strings: list[dict]) -> dict:
    text = "\n".join(item["value"] for item in strings)
    return {
        "urls": sorted(set(URL.findall(text)))[:500],
        "ips": sorted(set(IP.findall(text)))[:200],
        "domains": sorted({value.lower().rstrip(".,;)") for value in DOMAIN.findall(text)})[:500],
    }


def script_info(
    name: str,
    data: bytes,
    output_dir: Path,
    *,
    persist_normalized_text: bool = True,
) -> dict:
    """スクリプトを実行せず解析し、必要な場合だけ正規化本文を保存する。"""

    text, encoding = decode_text(data)
    lowered = text.lower()
    indicators = {
        "wscript_shell": "wscript.shell" in lowered,
        "shell_application": "shell.application" in lowered,
        "xmlhttp": "xmlhttp" in lowered or "winhttprequest" in lowered,
        "adodb_stream": "adodb.stream" in lowered,
        "powershell": "powershell" in lowered,
        "cmd": "cmd.exe" in lowered or "cmd /c" in lowered,
        "mshta": "mshta" in lowered,
        "rundll32": "rundll32" in lowered,
        "regsvr32": "regsvr32" in lowered,
        "scheduled_task": "schtasks" in lowered,
        "run_key": "currentversion\\run" in lowered,
        "from_char_code": "fromcharcode" in lowered,
        "eval": bool(re.search(r"\beval\s*\(", lowered)),
        "unescape": "unescape(" in lowered,
    }
    base64_hits = []
    for match in re.finditer(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{80,}={0,2}(?![A-Za-z0-9+/])", text):
        try:
            blob = base64.b64decode(match.group(), validate=True)
        except (ValueError, binascii.Error):
            continue
        if len(blob) >= 32:
            base64_hits.append({
                "offset": match.start(),
                "encoded_length": len(match.group()),
                "decoded_size": len(blob),
                "decoded_sha256": sha256_bytes(blob),
                "magic": blob[:16].hex(),
            })
    filename = safe_output_name(name)
    normalized_text = None
    if persist_normalized_text:
        output_dir.mkdir(parents=True, exist_ok=True)
        (output_dir / f"{filename}.normalized.txt").write_text(
            text, encoding="utf-8", errors="replace"
        )
        normalized_text = f"scripts/{filename}.normalized.txt"
    strings = [
        {"offset": match.start(), "encoding": "text", "value": match.group()}
        for match in re.finditer(r"[\x20-\x7e]{4,}", text)
    ][:20_000]
    return {
        "encoding": encoding,
        "line_count": text.count("\n") + 1,
        "indicators": indicators,
        "base64_candidates": base64_hits[:100],
        "iocs": extract_iocs(strings),
        "normalized_text": normalized_text,
    }


def pe_info(data: bytes) -> dict:
    pe = pefile.PE(data=data, fast_load=False)
    imports = {
        entry.dll.decode(errors="replace"): [
            item.name.decode(errors="replace") if item.name else f"ordinal:{item.ordinal}"
            for item in entry.imports
        ]
        for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", [])
    }
    strings = extract_strings(data)
    com = pe.OPTIONAL_HEADER.DATA_DIRECTORY[14]
    return {
        "machine": hex(pe.FILE_HEADER.Machine),
        "timestamp": pe.FILE_HEADER.TimeDateStamp,
        "entry_point_rva": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
        "imphash": pe.get_imphash(),
        "is_dotnet": bool(com.VirtualAddress and com.Size),
        "imports": imports,
        "sections": [
            {
                "name": section.Name.rstrip(b"\0").decode(errors="replace"),
                "raw_size": section.SizeOfRawData,
                "virtual_size": section.Misc_VirtualSize,
                "entropy": round(section.get_entropy(), 4),
            }
            for section in pe.sections
        ],
        "iocs": extract_iocs(strings),
        "behavior_strings": sorted({
            item["value"] for item in strings if re.search(
                r"(?i)(smtp|ftp|telegram|discord|password|credential|keylog|wallet|outlook|firefox|chrome|mutex|remcos|agent.?tesla|registry|schtasks|powershell)",
                item["value"],
            )
        })[:1000],
    }


def analyze(
    name: str,
    data: bytes,
    output_dir: Path,
    depth: int = 0,
    *,
    persist_normalized_text: bool = True,
    _archive_budget: dict[str, int] | None = None,
) -> dict:
    """1つのバイト列を上限付きで汎用静的トリアージする。"""

    if _archive_budget is None:
        _archive_budget = {"remaining": GENERIC_MAX_TOTAL_SIZE}
    result = {
        "name": name,
        "size": len(data),
        "sha256": sha256_bytes(data),
        "magic": data[:16].hex(),
        "entropy": entropy(data),
    }
    suffix = Path(name).suffix.lower()
    if suffix in SCRIPT_EXT or data[:32].lstrip().lower().startswith((b"<hta", b"<html", b"var ", b"function ")):
        result.update(
            type="script",
            script=script_info(
                name,
                data,
                output_dir,
                persist_normalized_text=persist_normalized_text,
            ),
        )
    elif data.startswith(b"\x7fELF"):
        result["type"] = "elf"
        try:
            layout = parse_elf_layout(data)
            strings = extract_strings(data)
            result["elf"] = {
                "bits": layout.bits,
                "byte_order": layout.byte_order,
                "machine": layout.machine,
                "entry_point": hex(layout.entry_point),
                "load_segments": [
                    {
                        "offset": segment.offset, "virtual_address": hex(segment.virtual_address),
                        "file_size": segment.file_size, "memory_size": segment.memory_size,
                    }
                    for segment in layout.segments
                ],
                "iocs": extract_iocs(strings),
            }
        except Exception as exc:
            result["elf_error"] = f"{type(exc).__name__}: {exc}"
    elif data.startswith(b"MZ"):
        result["type"] = "pe"
        try:
            result["pe"] = pe_info(data)
        except Exception as exc:
            result["pe_error"] = f"{type(exc).__name__}: {exc}"
    elif depth < 4 and zipfile.is_zipfile(io.BytesIO(data)):
        result["type"] = "zip"
        try:
            remaining = _archive_budget["remaining"]
            if remaining <= 0:
                raise ValueError("汎用ZIP展開の総量上限を使い切りました")
            members = read_aes_zip_members(
                data,
                password="infected",
                max_member_size=min(GENERIC_MAX_MEMBER_SIZE, remaining),
                max_members=GENERIC_MAX_MEMBERS,
                max_total_size=min(GENERIC_MAX_TOTAL_SIZE, remaining),
                max_compression_ratio=GENERIC_MAX_COMPRESSION_RATIO,
            )
            _archive_budget["remaining"] -= sum(member.size for member in members)
            result["members"] = [
                analyze(
                    validate_member_name(member.name),
                    member.data,
                    output_dir,
                    depth + 1,
                    persist_normalized_text=persist_normalized_text,
                    _archive_budget=_archive_budget,
                )
                for member in members
            ]
        except Exception as exc:
            result["parse_error"] = f"{type(exc).__name__}: {exc}"
    elif data.startswith(b"Rar!"):
        result.update(type="rar", note="RAR inventory only; use a reviewed external extractor")
    else:
        result.update(type="data", iocs=extract_iocs(extract_strings(data)))
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="Safely triage an authenticated MalwareBazaar ZIP.")
    parser.add_argument("--outer-zip", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--password", default="infected")
    args = parser.parse_args()
    members = read_aes_zip_members(args.outer_zip, password=args.password)
    analyzed = [analyze(member.name, member.data, args.output_dir / "scripts") for member in members]
    result = {
        "schema_version": SCHEMA_VERSION,
        "outer_zip": str(args.outer_zip),
        "outer_sha256": sha256_file(args.outer_zip),
        "members": analyzed,
        **safety_metadata(),
    }
    destination = args.output_dir / "family-triage.json"
    write_json(destination, result)
    print({"output": str(destination), "types": [item["type"] for item in analyzed]})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
