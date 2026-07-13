#!/usr/bin/env python3
"""Safe recursive static triage for MalwareBazaar samples.

Decrypts only in memory, never executes content, and writes text/JSON evidence only.
"""
from __future__ import annotations

import argparse, base64, hashlib, io, json, math, re, zipfile
from pathlib import Path

import pefile
import pyzipper

PRINTABLE = re.compile(rb"[\x20-\x7e]{4,}")
WIDE = re.compile(rb"(?:[\x20-\x7e]\x00){4,}")
URL = re.compile(r"https?://[^\s\"'<>]{4,400}", re.I)
IP = re.compile(r"(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?")
DOMAIN = re.compile(r"(?<![\w.-])(?:[a-z0-9-]{1,63}\.)+[a-z]{2,24}(?::\d{1,5})?", re.I)
SCRIPT_EXT = {".js", ".jse", ".vbs", ".vbe", ".hta", ".ps1", ".cmd", ".bat", ".wsf", ".html", ".htm"}
ARCHIVE_MAGIC = {b"Rar!": "rar", b"7z\xbc\xaf": "7z"}

def sha(data: bytes) -> str: return hashlib.sha256(data).hexdigest()

def entropy(data: bytes) -> float:
    if not data: return 0.0
    counts = [0] * 256
    for value in data: counts[value] += 1
    return round(-sum((n/len(data))*math.log2(n/len(data)) for n in counts if n), 4)

def extract_strings(data: bytes, limit: int = 20000) -> list[dict]:
    out = [{"offset": m.start(), "encoding": "ascii", "value": m.group().decode("ascii")}
           for m in PRINTABLE.finditer(data)]
    out += [{"offset": m.start(), "encoding": "utf16le", "value": m.group()[::2].decode("ascii")}
            for m in WIDE.finditer(data)]
    out.sort(key=lambda x: x["offset"])
    return out[:limit]

def iocs(strings: list[dict]) -> dict:
    text = "\n".join(item["value"] for item in strings)
    urls = sorted(set(URL.findall(text)))[:500]
    ips = sorted(set(IP.findall(text)))[:200]
    domains = sorted({x.lower().rstrip(".,;)") for x in DOMAIN.findall(text)})[:500]
    return {"urls": urls, "ips": ips, "domains": domains}

def decode_text(data: bytes) -> tuple[str, str]:
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        return data.decode("utf-16", errors="replace"), "utf-16"
    for encoding in ("utf-8-sig", "utf-16le", "latin1"):
        try:
            text = data.decode(encoding)
            if encoding != "utf-16le" or text.count("\x00") < max(2, len(text)//20):
                return text, encoding
        except UnicodeError: pass
    return data.decode("latin1", errors="replace"), "latin1"

def script_info(name: str, data: bytes, output_dir: Path) -> dict:
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
            if len(blob) >= 32:
                base64_hits.append({"offset": match.start(), "encoded_length": len(match.group()),
                                    "decoded_size": len(blob), "decoded_sha256": sha(blob),
                                    "magic": blob[:16].hex()})
        except Exception: pass
    safe_name = re.sub(r"[^A-Za-z0-9._-]+", "_", Path(name).name)[:120] or "script.txt"
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / f"{safe_name}.normalized.txt").write_text(text, encoding="utf-8", errors="replace")
    strings = [{"offset": m.start(), "encoding": "text", "value": m.group()}
               for m in re.finditer(r"[\x20-\x7e]{4,}", text)][:20000]
    return {"encoding": encoding, "line_count": text.count("\n") + 1,
            "indicators": indicators, "base64_candidates": base64_hits[:100],
            "iocs": iocs(strings), "normalized_text": f"scripts/{safe_name}.normalized.txt"}

def pe_info(data: bytes) -> dict:
    pe = pefile.PE(data=data, fast_load=False)
    imports = {}
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
        imports[entry.dll.decode(errors="replace")] = [
            imp.name.decode(errors="replace") if imp.name else f"ordinal:{imp.ordinal}" for imp in entry.imports]
    strings = extract_strings(data)
    com = pe.OPTIONAL_HEADER.DATA_DIRECTORY[14]
    return {
        "machine": hex(pe.FILE_HEADER.Machine), "timestamp": pe.FILE_HEADER.TimeDateStamp,
        "entry_point_rva": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint), "imphash": pe.get_imphash(),
        "is_dotnet": bool(com.VirtualAddress and com.Size), "imports": imports,
        "sections": [{"name": s.Name.rstrip(b"\0").decode(errors="replace"),
                      "raw_size": s.SizeOfRawData, "virtual_size": s.Misc_VirtualSize,
                      "entropy": round(s.get_entropy(), 4)} for s in pe.sections],
        "iocs": iocs(strings),
        "behavior_strings": sorted({x["value"] for x in strings if re.search(
            r"(?i)(smtp|ftp|telegram|discord|password|credential|keylog|wallet|outlook|firefox|chrome|mutex|remcos|agent.?tesla|registry|schtasks|powershell)", x["value"])})[:1000]
    }

def analyze(name: str, data: bytes, output_dir: Path, depth: int = 0) -> dict:
    result = {"name": name, "size": len(data), "sha256": sha(data), "magic": data[:16].hex(), "entropy": entropy(data)}
    suffix = Path(name).suffix.lower()
    if suffix in SCRIPT_EXT or (data[:32].lstrip().lower().startswith((b"<hta", b"<html", b"var ", b"function "))):
        result["type"] = "script"; result["script"] = script_info(name, data, output_dir)
    elif data.startswith(b"MZ"):
        result["type"] = "pe"
        try: result["pe"] = pe_info(data)
        except Exception as exc: result["pe_error"] = f"{type(exc).__name__}: {exc}"
    elif depth < 4 and zipfile.is_zipfile(io.BytesIO(data)):
        result["type"] = "zip"
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                result["members"] = [analyze(info.filename, zf.read(info), output_dir, depth+1)
                                     for info in zf.infolist() if not info.is_dir()]
        except Exception as exc: result["parse_error"] = f"{type(exc).__name__}: {exc}"
    elif data.startswith(b"Rar!"):
        result["type"] = "rar"; result["note"] = "RAR inventory only; extraction requires a reviewed external extractor"
    else:
        result["type"] = "data"; result["iocs"] = iocs(extract_strings(data))
    return result

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--outer-zip", required=True, type=Path)
    ap.add_argument("--output-dir", required=True, type=Path)
    ap.add_argument("--password", default="infected")
    args = ap.parse_args()
    members = []
    with pyzipper.AESZipFile(args.outer_zip) as zf:
        zf.setpassword(args.password.encode())
        for info in zf.infolist():
            if not info.is_dir(): members.append(analyze(info.filename, zf.read(info), args.output_dir / "scripts"))
    result = {"schema_version": 1, "outer_zip": str(args.outer_zip),
              "outer_sha256": sha(args.outer_zip.read_bytes()), "members": members,
              "executed": False, "network_contacted": False}
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "family-triage.json").write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({"output": str(args.output_dir / 'family-triage.json'),
                      "types": [x["type"] for x in members]}, ensure_ascii=False))
    return 0

if __name__ == "__main__": raise SystemExit(main())
