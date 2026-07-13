#!/usr/bin/env python3
"""Non-executing recursive script-layer analyzer."""
from __future__ import annotations

import argparse
import base64
import collections
import re
from pathlib import Path

import pefile

from malware_io import decode_text, read_single_aes_zip_member, safety_metadata, sha256_bytes, write_json

B64 = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{80,}={0,2}(?![A-Za-z0-9+/])")
QUOTED = re.compile(r"(['\"])(.*?)(?<!\\)\1", re.S)
CHARCODE = re.compile(r"(?i)(?:String\.)?fromCharCode\s*\(([^)]{3,200000})\)")
URL = re.compile(r"https?://[^\s\"'<>]{4,500}", re.I)
DOMAIN = re.compile(r"(?<![\w.-])(?:[a-z0-9-]{1,63}\.)+[a-z]{2,24}(?::\d{1,5})?", re.I)


def pe_summary(data: bytes) -> dict:
    pe = pefile.PE(data=data, fast_load=False)
    com = pe.OPTIONAL_HEADER.DATA_DIRECTORY[14]
    imports = sorted({entry.dll.decode(errors="replace") for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", [])})
    strings = [match.group().decode("ascii") for match in re.finditer(rb"[\x20-\x7e]{5,}", data)]
    interesting = sorted({value for value in strings if re.search(
        r"(?i)(remcos|agent.?tesla|smtp|ftp|telegram|password|credential|keylog|wallet|chrome|firefox|outlook|mutex|install|startup|registry)",
        value,
    )})[:500]
    text = "\n".join(strings)
    return {
        "machine": hex(pe.FILE_HEADER.Machine),
        "is_dotnet": bool(com.VirtualAddress and com.Size),
        "entry_point_rva": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
        "imphash": pe.get_imphash(),
        "imports": imports,
        "urls": sorted(set(URL.findall(text)))[:200],
        "domains": sorted({value.lower() for value in DOMAIN.findall(text)})[:300],
        "interesting_strings": interesting,
    }


def decode_base64(text: str) -> list[bytes]:
    decoded: list[bytes] = []
    seen: set[str] = set()
    for match in B64.finditer(text):
        value = match.group()
        try:
            blob = base64.b64decode(value + "=" * (-len(value) % 4), validate=False)
        except Exception:
            continue
        digest = sha256_bytes(blob)
        if len(blob) >= 32 and digest not in seen:
            seen.add(digest)
            decoded.append(blob)
    return decoded


def blob_summary(blob: bytes, source: str, depth: int = 0) -> dict:
    item = {"source": source, "size": len(blob), "sha256": sha256_bytes(blob), "magic": blob[:16].hex()}
    if blob.startswith(b"MZ"):
        item["type"] = "pe"
        try:
            item["pe"] = pe_summary(blob)
        except Exception as exc:
            item["parse_error"] = f"{type(exc).__name__}: {exc}"
    elif blob.startswith((b"PK\x03\x04", b"Rar!", b"7z\xbc\xaf")):
        item["type"] = "archive"
    else:
        text, encoding = decode_text(blob)
        printable = sum(char.isprintable() or char in "\r\n\t" for char in text) / max(1, len(text))
        item.update(type="text" if printable > 0.80 else "data", encoding=encoding)
        if item["type"] == "text" and depth < 2:
            item["urls"] = sorted(set(URL.findall(text)))[:200]
            item["domains"] = sorted({value.lower() for value in DOMAIN.findall(text)})[:300]
            item["nested_base64"] = [
                blob_summary(value, f"{source}:nested[{index}]", depth + 1)
                for index, value in enumerate(decode_base64(text)[:25])
            ]
    return item


def main() -> int:
    parser = argparse.ArgumentParser(description="Analyze encoded layers in a single script submission.")
    parser.add_argument("--outer-zip", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--password", default="infected")
    args = parser.parse_args()
    member = read_single_aes_zip_member(args.outer_zip, password=args.password)
    text, encoding = decode_text(member.data)
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    counts = collections.Counter(lines)
    quoted = [match.group(2) for match in QUOTED.finditer(text)]
    charcode_blobs = []
    for match in CHARCODE.finditer(text):
        numbers = re.findall(r"(?:0x[0-9a-f]+|\d+)", match.group(1), re.I)
        if len(numbers) >= 4:
            try:
                charcode_blobs.append(bytes(int(value, 0) & 0xFF for value in numbers))
            except ValueError:
                pass
    base64_blobs = decode_base64(text)
    decoded = [blob_summary(blob, f"base64[{index}]") for index, blob in enumerate(base64_blobs[:100])]
    decoded.extend(blob_summary(blob, f"charcode[{index}]") for index, blob in enumerate(charcode_blobs[:100]))
    result = {
        "schema_version": 2,
        "member_name": member.name,
        "sha256": member.sha256,
        "size": member.size,
        "encoding": encoding,
        "line_count": len(lines),
        "unique_line_count": len(counts),
        "top_repeated_lines": [
            {"count": count, "sha256": sha256_bytes(line.encode()), "preview": line[:160]}
            for line, count in counts.most_common(20)
        ],
        "rare_line_previews": [line[:500] for line in lines if counts[line] <= 2][:200],
        "quoted_string_count": len(quoted),
        "longest_quoted_strings": [
            {"length": len(value), "sha256": sha256_bytes(value.encode(errors="replace")), "preview": value[:200]}
            for value in sorted(quoted, key=len, reverse=True)[:50]
        ],
        "direct_urls": sorted(set(URL.findall(text)))[:300],
        "direct_domains": sorted({value.lower() for value in DOMAIN.findall(text)})[:500],
        "decoded_layers": decoded,
        **safety_metadata(),
    }
    write_json(args.output, result)
    print({
        "output": str(args.output),
        "decoded_layers": len(decoded),
        "pe_layers": sum(item.get("type") == "pe" for item in decoded),
        "unique_lines": len(counts),
    })
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
