#!/usr/bin/env python3
"""Office/OLE/ZIP/PDF コンテナを実行せず、境界付きで棚卸しする。"""

from __future__ import annotations
import argparse
import hashlib
import io
import json
import zipfile
from pathlib import Path

MAX_MEMBER = 64 * 1024 * 1024
MAX_MEMBERS = 512
MAX_DEPTH = 3


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def identify(data: bytes) -> str:
    if data.startswith(b"PK\x03\x04"):
        return "zip"
    if data.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        return "ole"
    if data.startswith(b"%PDF-"):
        return "pdf"
    if data.startswith(b"\x01\x00\x00\x00") and b" EMF" in data[:128]:
        return "emf"
    return "binary"


def inspect_pdf(data: bytes) -> dict[str, object]:
    markers = {
        name: token in data
        for name, token in {
            "javascript": b"/JavaScript",
            "open_action": b"/OpenAction",
            "launch": b"/Launch",
            "embedded_file": b"/EmbeddedFile",
            "additional_action": b"/AA",
        }.items()
    }
    return {
        "type": "pdf",
        "size": len(data),
        "sha256": sha256(data),
        "active_markers": markers,
        "active_content_observed": any(markers.values()),
    }


def inspect_zip(data: bytes, depth: int) -> dict[str, object]:
    entries = []
    total_uncompressed = 0
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        infos = archive.infolist()
        if len(infos) > MAX_MEMBERS:
            raise ValueError("ZIP member 数が安全上限を超えています")
        for info in infos:
            total_uncompressed += info.file_size
            if info.file_size > MAX_MEMBER or total_uncompressed > MAX_MEMBER * 4:
                raise ValueError("ZIP 展開サイズが安全上限を超えています")
            if info.is_dir():
                entries.append({"name": info.filename, "directory": True})
                continue
            member = archive.read(info)
            item = {"name": info.filename, "size": len(member), "sha256": sha256(member), "type": identify(member)}
            if depth < MAX_DEPTH and item["type"] in {"zip", "ole", "pdf"}:
                item["inventory"] = analyze_bytes(member, depth + 1)
            entries.append(item)
    return {"type": "zip", "size": len(data), "sha256": sha256(data), "entries": entries}


def inspect_ole(data: bytes, depth: int) -> dict[str, object]:
    result: dict[str, object] = {
        "type": "ole",
        "size": len(data),
        "sha256": sha256(data),
        "streams": [],
        "ole_parser_available": False,
    }
    try:
        import olefile  # type: ignore
    except ImportError:
        result["limitations"] = ["olefile がないため stream 列挙を省略"]
        return result
    result["ole_parser_available"] = True
    with olefile.OleFileIO(io.BytesIO(data)) as ole:
        paths = ole.listdir(streams=True, storages=False)
        if len(paths) > MAX_MEMBERS:
            raise ValueError("OLE stream 数が安全上限を超えています")
        streams = []
        for path in paths:
            name = "/".join(path)
            size = ole.get_size(path)
            item: dict[str, object] = {"name": name, "size": size}
            if size <= MAX_MEMBER:
                content = ole.openstream(path).read(MAX_MEMBER + 1)
                if len(content) > MAX_MEMBER:
                    raise ValueError("OLE stream が安全上限を超えています")
                item.update({"sha256": sha256(content), "type": identify(content)})
                if depth < MAX_DEPTH and item["type"] in {"zip", "ole", "pdf"}:
                    item["inventory"] = analyze_bytes(content, depth + 1)
            streams.append(item)
        result["streams"] = streams
        result["macro_streams"] = [
            item["name"]
            for item in streams
            if any(token in str(item["name"]).lower() for token in ("vba", "macros", "_vba_project"))
        ]
    return result


def analyze_bytes(data: bytes, depth: int = 0) -> dict[str, object]:
    if not data or len(data) > MAX_MEMBER:
        raise ValueError("入力サイズが安全上限外です")
    if depth > MAX_DEPTH:
        raise ValueError("container 深度が安全上限外です")
    kind = identify(data)
    if kind == "zip":
        return inspect_zip(data, depth)
    if kind == "ole":
        return inspect_ole(data, depth)
    if kind == "pdf":
        return inspect_pdf(data)
    return {"type": kind, "size": len(data), "sha256": sha256(data)}


def analyze_file(path: Path) -> dict[str, object]:
    result = analyze_bytes(path.read_bytes())
    result["source_name"] = path.name
    result["safety"] = {
        "document_opened": False,
        "macro_executed": False,
        "javascript_executed": False,
        "embedded_file_launched": False,
        "network_contacted": False,
    }
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("sample", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    rendered = json.dumps(analyze_file(args.sample), ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
