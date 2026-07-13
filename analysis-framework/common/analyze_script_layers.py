#!/usr/bin/env python3
"""Non-executing script-layer analyzer for MalwareBazaar delivery files."""
from __future__ import annotations

import argparse, base64, collections, hashlib, io, json, re, zlib
from pathlib import Path

import pefile, pyzipper

B64 = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{80,}={0,2}(?![A-Za-z0-9+/])")
QUOTED = re.compile(r"(['\"])(.*?)(?<!\\)\1", re.S)
CHARCODE = re.compile(r"(?i)(?:String\.)?fromCharCode\s*\(([^)]{3,200000})\)")
URL = re.compile(r"https?://[^\s\"'<>]{4,500}", re.I)
DOMAIN = re.compile(r"(?<![\w.-])(?:[a-z0-9-]{1,63}\.)+[a-z]{2,24}(?::\d{1,5})?", re.I)

def sha(data: bytes) -> str: return hashlib.sha256(data).hexdigest()

def decode_text(data: bytes) -> str:
    for enc in ("utf-8-sig", "utf-16", "utf-16le", "latin1"):
        try:
            text = data.decode(enc)
            if enc not in ("utf-16", "utf-16le") or text.count("\x00") < max(2, len(text)//20): return text
        except Exception: pass
    return data.decode("latin1", errors="replace")

def pe_summary(data: bytes) -> dict:
    pe = pefile.PE(data=data, fast_load=False)
    com = pe.OPTIONAL_HEADER.DATA_DIRECTORY[14]
    imports = sorted({entry.dll.decode(errors="replace") for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", [])})
    strings = [m.group().decode("ascii") for m in re.finditer(rb"[\x20-\x7e]{5,}", data)]
    interesting = sorted({s for s in strings if re.search(
        r"(?i)(remcos|agent.?tesla|smtp|ftp|telegram|password|credential|keylog|wallet|chrome|firefox|outlook|mutex|install|startup|registry)", s)})[:500]
    text = "\n".join(strings)
    return {"machine": hex(pe.FILE_HEADER.Machine), "is_dotnet": bool(com.VirtualAddress and com.Size),
            "entry_point_rva": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint), "imphash": pe.get_imphash(),
            "imports": imports, "urls": sorted(set(URL.findall(text)))[:200],
            "domains": sorted({x.lower() for x in DOMAIN.findall(text)})[:300],
            "interesting_strings": interesting}

def blob_summary(blob: bytes, source: str, depth: int = 0) -> dict:
    item = {"source": source, "size": len(blob), "sha256": sha(blob), "magic": blob[:16].hex()}
    if blob.startswith(b"MZ"):
        item["type"] = "pe"
        try: item["pe"] = pe_summary(blob)
        except Exception as exc: item["parse_error"] = f"{type(exc).__name__}: {exc}"
    elif blob.startswith((b"PK\x03\x04", b"Rar!", b"7z\xbc\xaf")):
        item["type"] = "archive"
    else:
        text = decode_text(blob)
        printable = sum(ch.isprintable() or ch in "\r\n\t" for ch in text) / max(1, len(text))
        item["type"] = "text" if printable > .80 else "data"
        if item["type"] == "text" and depth < 2:
            item["urls"] = sorted(set(URL.findall(text)))[:200]
            item["domains"] = sorted({x.lower() for x in DOMAIN.findall(text)})[:300]
            item["nested_base64"] = [blob_summary(x, f"{source}:nested[{n}]", depth+1)
                for n, x in enumerate(decode_base64(text)[:25])]
    return item

def decode_base64(text: str) -> list[bytes]:
    out, seen = [], set()
    for match in B64.finditer(text):
        value = match.group()
        try:
            blob = base64.b64decode(value + "=" * (-len(value) % 4), validate=False)
            digest = sha(blob)
            if len(blob) >= 32 and digest not in seen: seen.add(digest); out.append(blob)
        except Exception: pass
    return out

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--outer-zip", required=True, type=Path)
    ap.add_argument("--output", required=True, type=Path)
    ap.add_argument("--password", default="infected")
    args = ap.parse_args()
    with pyzipper.AESZipFile(args.outer_zip) as zf:
        zf.setpassword(args.password.encode())
        infos = [x for x in zf.infolist() if not x.is_dir()]
        if len(infos) != 1: raise RuntimeError("expected one MalwareBazaar member")
        info = infos[0]; raw = zf.read(info)
    text = decode_text(raw)
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    counts = collections.Counter(lines)
    quoted = [m.group(2) for m in QUOTED.finditer(text)]
    charcode_blobs = []
    for match in CHARCODE.finditer(text):
        nums = re.findall(r"(?:0x[0-9a-f]+|\d+)", match.group(1), re.I)
        if len(nums) >= 4:
            try: charcode_blobs.append(bytes(int(x, 0) & 0xff for x in nums))
            except Exception: pass
    b64_blobs = decode_base64(text)
    decoded = [blob_summary(blob, f"base64[{i}]") for i, blob in enumerate(b64_blobs[:100])]
    decoded += [blob_summary(blob, f"charcode[{i}]") for i, blob in enumerate(charcode_blobs[:100])]
    result = {
        "member_name": info.filename, "sha256": sha(raw), "size": len(raw),
        "line_count": len(lines), "unique_line_count": len(counts),
        "top_repeated_lines": [{"count": n, "sha256": sha(line.encode()), "preview": line[:160]}
                               for line, n in counts.most_common(20)],
        "rare_line_previews": [line[:500] for line in lines if counts[line] <= 2][:200],
        "quoted_string_count": len(quoted),
        "longest_quoted_strings": [{"length": len(s), "sha256": sha(s.encode(errors="replace")), "preview": s[:200]}
                                   for s in sorted(quoted, key=len, reverse=True)[:50]],
        "direct_urls": sorted(set(URL.findall(text)))[:300],
        "direct_domains": sorted({x.lower() for x in DOMAIN.findall(text)})[:500],
        "decoded_layers": decoded, "executed": False, "network_contacted": False,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({"output": str(args.output), "decoded_layers": len(decoded),
                      "pe_layers": sum(x.get("type") == "pe" for x in decoded),
                      "unique_lines": len(counts)}))
    return 0

if __name__ == "__main__": raise SystemExit(main())
