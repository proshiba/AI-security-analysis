#!/usr/bin/env python3
from __future__ import annotations
import argparse
import base64
import re
from pathlib import Path
from malware_io import decode_text, read_single_aes_zip_member, safety_metadata, sha256_bytes, write_json

B64 = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{40,}={0,2}(?![A-Za-z0-9+/])")
URL = re.compile(r"https?://[^\s\"'<>]+", re.I)
DOMAIN = re.compile(r"(?<![\w.-])(?:[a-z0-9-]{1,63}\.)+[a-z]{2,24}(?::\d{1,5})?", re.I)

def main() -> int:
    parser = argparse.ArgumentParser(description="Extract textual Base64 layers without execution.")
    parser.add_argument("--outer-zip", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--password", default="infected")
    args = parser.parse_args()
    member = read_single_aes_zip_member(args.outer_zip, password=args.password)
    source = decode_text(member.data)[0]
    layers, seen = [], set()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    for index, match in enumerate(B64.finditer(source)):
        try:
            blob = base64.b64decode(match.group() + "=" * (-len(match.group()) % 4), validate=False)
        except Exception:
            continue
        digest = sha256_bytes(blob)
        if len(blob) < 16 or digest in seen:
            continue
        seen.add(digest)
        decoded, encoding = decode_text(blob)
        ratio = sum(char.isprintable() or char in "\r\n\t" for char in decoded) / max(1, len(decoded))
        item = {"index": index, "encoded_offset": match.start(), "decoded_size": len(blob), "decoded_sha256": digest, "magic": blob[:16].hex(), "encoding": encoding, "printable_ratio": round(ratio, 3), "urls": sorted(set(URL.findall(decoded))), "domains": sorted({value.lower() for value in DOMAIN.findall(decoded)})}
        if ratio > 0.75:
            name = f"layer-{index:03d}-{digest[:12]}.txt"
            (args.output_dir / name).write_text(decoded, encoding="utf-8", errors="replace")
            item["text_file"] = name
        layers.append(item)
    write_json(args.output_dir / "encoded-text.json", {"schema_version": 2, "member": member.name, "sha256": member.sha256, "layers": layers, **safety_metadata()})
    print({"member": member.name, "layers": len(layers), "text_layers": sum("text_file" in item for item in layers)})
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
