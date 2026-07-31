#!/usr/bin/env python3
"""認証済みMalwareBazaar検体を再帰的かつ安全に静的トリアージする。"""

from __future__ import annotations

import argparse
import base64
import binascii
import ipaddress
import math
import re
import sys
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


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
repository_value = str(REPOSITORY_ROOT)
if repository_value not in sys.path:
    sys.path.insert(0, repository_value)

from unpackers.static_unpacker import detect_format  # noqa: E402

PRINTABLE = re.compile(rb"[\x20-\x7e]{4,}")
WIDE = re.compile(rb"(?:[\x20-\x7e]\x00){4,}")
URL = re.compile(r"https?://[^\s\"'<>]{4,400}", re.I)
IP = re.compile(r"(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?")
DOMAIN = re.compile(r"(?<![\w.-])(?:[a-z0-9-]{1,63}\.)+[a-z]{2,24}(?::\d{1,5})?", re.I)
GENERIC_MAX_MEMBER_SIZE = 64 * 1024 * 1024
GENERIC_MAX_MEMBERS = 256
GENERIC_MAX_TOTAL_SIZE = 256 * 1024 * 1024
GENERIC_MAX_COMPRESSION_RATIO = 100.0
MAX_BASE64_ENCODED_LENGTH = 1024 * 1024
DEFAULT_STRING_SCAN_LIMIT = 500_000
MAX_BASE64_CANDIDATES = 10_000
STATIC_LAYER_DELEGATED_FORMATS = {
    "7z",
    "apple-disk-image",
    "asar",
    "autoit-a3x",
    "cab",
    "java-class",
    "macho",
    "png",
    "rar",
    "xz",
}


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for value in data:
        counts[value] += 1
    return round(-sum((n / len(data)) * math.log2(n / len(data)) for n in counts if n), 4)


def extract_strings_with_coverage(data: bytes, limit: int = DEFAULT_STRING_SCAN_LIMIT) -> tuple[list[dict], dict]:
    """文字列を上限付きで抽出し、打切り有無を返す。"""

    if limit <= 0:
        raise ValueError("文字列抽出上限は正数で指定してください")
    ascii_values = []
    for match in PRINTABLE.finditer(data):
        ascii_values.append({"offset": match.start(), "encoding": "ascii", "value": match.group().decode("ascii")})
        if len(ascii_values) > limit:
            break
    wide_values = []
    for match in WIDE.finditer(data):
        wide_values.append(
            {
                "offset": match.start(),
                "encoding": "utf-16-le",
                "value": match.group()[::2].decode("ascii"),
            }
        )
        if len(wide_values) > limit:
            break
    strings = [*ascii_values, *wide_values]
    strings.sort(key=lambda item: item["offset"])
    truncated = len(strings) > limit or len(ascii_values) > limit or len(wide_values) > limit
    return strings[:limit], {
        "limit": limit,
        "returned": min(len(strings), limit),
        "truncated": truncated,
    }


def extract_strings(data: bytes, limit: int = 20_000) -> list[dict]:
    """後方互換用に、上限付き文字列一覧だけを返す。"""

    return extract_strings_with_coverage(data, limit)[0]


def _valid_ip_candidates(text: str) -> list[str]:
    values = set()
    for raw in IP.findall(text):
        host, separator, raw_port = raw.partition(":")
        try:
            ipaddress.ip_address(host)
        except ValueError:
            continue
        if separator and not 1 <= int(raw_port) <= 65_535:
            continue
        values.add(raw)
    return sorted(values)[:200]


def _valid_domain_candidates(text: str) -> list[str]:
    """範囲内portを持つdomain候補だけを返す。"""

    values = set()
    for raw in DOMAIN.findall(text):
        candidate = raw.lower().rstrip(".,;)")
        host, separator, raw_port = candidate.partition(":")
        if separator:
            try:
                if not 1 <= int(raw_port) <= 65_535:
                    continue
            except ValueError:
                continue
        values.add(f"{host}:{raw_port}" if separator else host)
    return sorted(values)[:500]


def extract_iocs(strings: list[dict]) -> dict:
    text = "\n".join(item["value"] for item in strings)
    return {
        "urls": sorted(set(URL.findall(text)))[:500],
        "ips": _valid_ip_candidates(text),
        "domains": _valid_domain_candidates(text),
    }


def script_info(
    name: str,
    data: bytes,
    output_dir: Path,
    *,
    persist_normalized_text: bool = True,
    string_scan_limit: int = DEFAULT_STRING_SCAN_LIMIT,
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
    oversized_base64 = 0
    for match in re.finditer(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{80,}={0,2}(?![A-Za-z0-9+/])", text):
        encoded_length = match.end() - match.start()
        if encoded_length > MAX_BASE64_ENCODED_LENGTH:
            oversized_base64 += 1
            continue
        try:
            blob = base64.b64decode(match.group(), validate=True)
        except (ValueError, binascii.Error):
            continue
        if len(blob) >= 32:
            base64_hits.append(
                {
                    "offset": match.start(),
                    "encoded_length": encoded_length,
                    "decoded_size": len(blob),
                    "decoded_sha256": sha256_bytes(blob),
                    "magic": blob[:16].hex(),
                }
            )
            if len(base64_hits) > MAX_BASE64_CANDIDATES:
                break
    filename = safe_output_name(name)
    normalized_text = None
    if persist_normalized_text:
        output_dir.mkdir(parents=True, exist_ok=True)
        (output_dir / f"{filename}.normalized.txt").write_text(text, encoding="utf-8", errors="replace")
        normalized_text = f"scripts/{filename}.normalized.txt"
    strings = []
    string_scan_truncated = False
    for match in re.finditer(r"[\x20-\x7e]{4,}", text):
        if len(strings) >= string_scan_limit:
            string_scan_truncated = True
            break
        strings.append({"offset": match.start(), "encoding": "text", "value": match.group()})
    return {
        "encoding": encoding,
        "line_count": text.count("\n") + 1,
        "indicators": indicators,
        "base64_candidates": base64_hits[:MAX_BASE64_CANDIDATES],
        "base64_scan": {
            "candidate_limit": MAX_BASE64_CANDIDATES,
            "encoded_length_limit": MAX_BASE64_ENCODED_LENGTH,
            "oversized_candidates": oversized_base64,
            "truncated": len(base64_hits) > MAX_BASE64_CANDIDATES or oversized_base64 > 0,
        },
        "iocs": extract_iocs(strings),
        "string_scan": {
            "limit": string_scan_limit,
            "returned": len(strings),
            "truncated": string_scan_truncated,
        },
        "normalized_text": normalized_text,
    }


def pe_info(data: bytes, *, string_scan_limit: int = DEFAULT_STRING_SCAN_LIMIT) -> dict:
    pe = pefile.PE(data=data, fast_load=False)
    imports = {
        entry.dll.decode(errors="replace"): [
            item.name.decode(errors="replace") if item.name else f"ordinal:{item.ordinal}" for item in entry.imports
        ]
        for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", [])
    }
    strings, string_scan = extract_strings_with_coverage(data, string_scan_limit)
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
        "string_scan": string_scan,
        "iocs": extract_iocs(strings),
        "behavior_strings": sorted(
            {
                item["value"]
                for item in strings
                if re.search(
                    r"(?i)(smtp|ftp|telegram|discord|password|credential|keylog|wallet|outlook|firefox|chrome|mutex|remcos|agent.?tesla|registry|schtasks|powershell)",
                    item["value"],
                )
            }
        )[:1000],
    }


def _coverage_issues(value: object, path: str = "root") -> list[str]:
    """汎用解析結果からparse失敗、上限到達、子層partialを収集する。"""

    issues = []
    if isinstance(value, dict):
        for key, item in value.items():
            lowered = str(key).casefold()
            child = f"{path}.{key}"
            if lowered == "parse_error" or lowered.endswith("_error"):
                issues.append(child)
            elif lowered in {"string_scan", "base64_scan"} and isinstance(item, dict):
                if item.get("truncated") is True:
                    issues.append(f"{child}:truncated")
            elif lowered == "analysis_coverage" and isinstance(item, dict):
                if item.get("status") != "complete":
                    issues.append(f"{child}:{item.get('status')}")
            else:
                issues.extend(_coverage_issues(item, child))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            issues.extend(_coverage_issues(item, f"{path}[{index}]"))
    return issues


def analyze(
    name: str,
    data: bytes,
    output_dir: Path,
    depth: int = 0,
    *,
    persist_normalized_text: bool = True,
    recurse_archives: bool = True,
    _archive_budget: dict[str, int] | None = None,
    string_scan_limit: int = DEFAULT_STRING_SCAN_LIMIT,
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
    detected_format = detect_format(data, name)
    if detected_format == "elf":
        result["type"] = "elf"
        try:
            layout = parse_elf_layout(data)
            strings, string_scan = extract_strings_with_coverage(data, string_scan_limit)
            result["elf"] = {
                "bits": layout.bits,
                "byte_order": layout.byte_order,
                "machine": layout.machine,
                "entry_point": hex(layout.entry_point),
                "load_segments": [
                    {
                        "offset": segment.offset,
                        "virtual_address": hex(segment.virtual_address),
                        "file_size": segment.file_size,
                        "memory_size": segment.memory_size,
                    }
                    for segment in layout.segments
                ],
                "string_scan": string_scan,
                "iocs": extract_iocs(strings),
            }
        except Exception as exc:
            result["elf_error"] = f"{type(exc).__name__}: {exc}"
    elif detected_format == "pe":
        result["type"] = "pe"
        try:
            result["pe"] = pe_info(data, string_scan_limit=string_scan_limit)
        except Exception as exc:
            result["pe_error"] = f"{type(exc).__name__}: {exc}"
    elif detected_format in STATIC_LAYER_DELEGATED_FORMATS and not recurse_archives:
        result.update(
            type=detected_format,
            format_specific_analysis="delegated_to_static_layer_pipeline",
        )
    elif detected_format == "zip":
        result["type"] = "zip"
        if not recurse_archives:
            result["archive_recursion"] = "delegated_to_static_layer_pipeline"
        elif depth >= 4:
            result["parse_error"] = "ValueError: 汎用ZIP解析の深度上限へ到達しました"
        else:
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
                        recurse_archives=recurse_archives,
                        string_scan_limit=string_scan_limit,
                        _archive_budget=_archive_budget,
                    )
                    for member in members
                ]
            except Exception as exc:
                result["parse_error"] = f"{type(exc).__name__}: {exc}"
    elif detected_format == "rar":
        result.update(type="rar", note="RARはinventoryだけを記録し、レビュー済み外部抽出器が必要です")
    elif detected_format == "script":
        result.update(
            type="script",
            script=script_info(
                name,
                data,
                output_dir,
                persist_normalized_text=persist_normalized_text,
                string_scan_limit=string_scan_limit,
            ),
        )
    elif detected_format != "data":
        strings, string_scan = extract_strings_with_coverage(data, string_scan_limit)
        result.update(
            type=detected_format,
            string_scan=string_scan,
            iocs=extract_iocs(strings),
            format_specific_analysis="not_implemented",
        )
    else:
        strings, string_scan = extract_strings_with_coverage(data, string_scan_limit)
        result.update(type="data", string_scan=string_scan, iocs=extract_iocs(strings))
    issues = _coverage_issues(result)
    if result.get("type") == "rar":
        issues.append("root:rar_inventory_only")
    if result.get("format_specific_analysis") == "not_implemented":
        issues.append(f"root:{detected_format}_format_analysis_not_implemented")
    result["analysis_coverage"] = {
        "status": "partial" if issues else "complete",
        "issues": sorted(set(issues)),
    }
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="認証済みMalwareBazaar ZIPを実行せず安全に静的トリアージします。")
    parser.add_argument("--outer-zip", required=True, type=Path, help="解析する外装ZIPのpath")
    parser.add_argument("--output-dir", required=True, type=Path, help="解析結果を保存するdirectory")
    parser.add_argument("--password", default="infected", help="外装ZIPのpassword（既定: infected）")
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
