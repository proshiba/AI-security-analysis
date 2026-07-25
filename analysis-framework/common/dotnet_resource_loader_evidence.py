"""`.NET resource loader`の静的適用証拠を共通化する。

検体や復元物を実行せず、PEのCLR data directory、マネージドAPI相関、
上限付きBitmap RGB復元結果だけを扱う。復元したbyte列は呼出元へ返さず、
SHA-256とサイズへ縮約する。
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from types import SimpleNamespace
import struct
import sys
from typing import Any

import dnfile


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from unpackers.managed_il_triage import _contain_parser_diagnostics  # noqa: E402
from unpackers.static_unpacker import (  # noqa: E402
    recover_dotnet_bitmap_payloads,
    valid_pe_extent,
)


BITMAP_MARKERS = (
    b"System.Drawing.Bitmap",
    b"GetPixel",
    b"GetExportedTypes",
    b"InvokeMember",
)
RGB_ACCESS_MARKERS = (b"get_R", b"get_G", b"get_B")
MAX_BITMAP_SCAN_INPUT_BYTES = 128 * 1024 * 1024
MAX_BITMAP_RESOURCE_COUNT = 64
MAX_BITMAP_ENTRY_COUNT = 256
MAX_BITMAP_RESOURCE_BYTES = 64 * 1024 * 1024
MAX_BITMAP_DIMENSION = 4096
MAX_BITMAP_PIXELS = 4 * 1024 * 1024
MAX_BITMAP_TOTAL_PIXELS = 8 * 1024 * 1024
MAX_BITMAP_TOTAL_RGB_BYTES = 24 * 1024 * 1024
MAX_BITMAP_TOTAL_OUTPUT_BYTES = 32 * 1024 * 1024
MAX_EMBEDDED_BITMAP_CANDIDATES = 64


def managed_pe_shape(data: bytes) -> dict[str, Any]:
    """PE optional headerのCLR data directoryを境界検証して返す。"""

    result: dict[str, Any] = {
        "mz_header": data.startswith(b"MZ"),
        "pe_signature": False,
        "optional_magic": None,
        "clr_rva": 0,
        "clr_size": 0,
        "is_managed_pe": False,
    }
    if len(data) < 0x40 or not result["mz_header"]:
        return result
    pe_offset = int.from_bytes(data[0x3C:0x40], "little")
    result["pe_offset"] = pe_offset
    if pe_offset < 0x40 or pe_offset + 24 > len(data):
        return result
    if data[pe_offset : pe_offset + 4] != b"PE\0\0":
        return result
    result["pe_signature"] = True
    optional_size = int.from_bytes(data[pe_offset + 20 : pe_offset + 22], "little")
    optional_offset = pe_offset + 24
    optional_end = optional_offset + optional_size
    if optional_size < 2 or optional_end > len(data):
        return result
    magic = int.from_bytes(data[optional_offset : optional_offset + 2], "little")
    result["optional_magic"] = f"0x{magic:x}"
    if magic == 0x10B:
        directory_count_offset = optional_offset + 92
        directory_offset = optional_offset + 96
    elif magic == 0x20B:
        directory_count_offset = optional_offset + 108
        directory_offset = optional_offset + 112
    else:
        return result
    if directory_count_offset + 4 > optional_end:
        return result
    directory_count = int.from_bytes(
        data[directory_count_offset : directory_count_offset + 4],
        "little",
    )
    result["data_directory_count"] = directory_count
    clr_offset = directory_offset + 14 * 8
    if directory_count <= 14 or clr_offset + 8 > optional_end:
        return result
    clr_rva, clr_size = struct.unpack_from("<II", data, clr_offset)
    result["clr_rva"] = clr_rva
    result["clr_size"] = clr_size
    result["is_managed_pe"] = bool(clr_rva and clr_size)
    return result


def _integer_field(value: object, name: str) -> int:
    try:
        return int(getattr(value, name, 0) or 0)
    except (TypeError, ValueError):
        return 0


def _declared_table_rows(tables: object, name: str) -> int:
    table = getattr(tables, name, None)
    try:
        return max(0, int(getattr(table, "num_rows", 0) or 0))
    except (TypeError, ValueError):
        return 0


def _managed_metadata_evidence_from_image(
    image: object,
    data: bytes,
    shape: dict[str, Any],
    extent: int,
) -> dict[str, Any] | None:
    """COR20、BSJB root、primary table streamの境界と実テーブル行を検証する。"""

    if not 0 < extent <= len(data) or shape["clr_size"] < 0x48:
        return None
    try:
        clr_offset = int(image.get_offset_from_rva(int(shape["clr_rva"])))
    except (AttributeError, TypeError, ValueError):
        return None
    if not 0 <= clr_offset <= extent - 0x48:
        return None
    net = getattr(image, "net", None)
    metadata = getattr(net, "metadata", None)
    if net is None or metadata is None or getattr(net, "mdtables", None) is None:
        return None
    net_struct = getattr(net, "struct", None)
    metadata_struct = getattr(metadata, "struct", None)
    if _integer_field(net_struct, "cb") < 0x48 or _integer_field(metadata_struct, "Signature") != 0x424A5342:
        return None
    metadata_rva = _integer_field(net_struct, "MetaDataRva")
    metadata_size = _integer_field(net_struct, "MetaDataSize")
    try:
        metadata_offset = int(image.get_offset_from_rva(metadata_rva))
    except (AttributeError, TypeError, ValueError):
        return None
    if (
        metadata_rva <= 0
        or metadata_size <= 0
        or metadata_offset < 0
        or metadata_offset + metadata_size > extent
    ):
        return None
    streams = getattr(metadata, "streams", None)
    if not isinstance(streams, dict):
        return None
    primary_name = b"#~"
    tables = streams.get(primary_name)
    if tables is None:
        primary_name = b"#-"
        tables = streams.get(primary_name)
    if tables is None:
        return None
    stream_struct = getattr(tables, "struct", None)
    stream_offset = _integer_field(stream_struct, "Offset")
    stream_size = _integer_field(stream_struct, "Size")
    if stream_offset < 0 or stream_size <= 0 or stream_offset + stream_size > metadata_size:
        return None
    module_rows = _declared_table_rows(tables, "Module")
    type_definition_rows = _declared_table_rows(tables, "TypeDef")
    if module_rows < 1 or type_definition_rows < 1:
        return None
    return {
        "clr_file_offset": clr_offset,
        "cor20_header_size": _integer_field(net_struct, "cb"),
        "metadata_rva": metadata_rva,
        "metadata_file_offset": metadata_offset,
        "metadata_size": metadata_size,
        "metadata_signature": "BSJB",
        "primary_table_stream": primary_name.decode("ascii"),
        "primary_table_stream_offset": stream_offset,
        "primary_table_stream_size": stream_size,
        "module_rows": module_rows,
        "type_definition_rows": type_definition_rows,
        "method_definition_rows": _declared_table_rows(tables, "MethodDef"),
        "manifest_resource_rows": _declared_table_rows(tables, "ManifestResource"),
    }


@_contain_parser_diagnostics
def _parse_managed_metadata_evidence(
    data: bytes,
    shape: dict[str, Any],
    extent: int,
) -> dict[str, Any] | None:
    """有効PE範囲だけをdnfileへ渡し、managed metadata証拠へ縮約する。"""

    if extent > MAX_BITMAP_SCAN_INPUT_BYTES:
        return None
    try:
        bounded = data if extent == len(data) else data[:extent]
        image = dnfile.dnPE(data=bounded)
        return _managed_metadata_evidence_from_image(image, bounded, shape, extent)
    except Exception:
        return None


def validated_managed_pe_shape(data: bytes) -> dict[str, Any]:
    """PE、COR20、metadata root、primary table streamをすべて検証する。"""

    result = managed_pe_shape(data)
    extent = valid_pe_extent(data, 0) if result["is_managed_pe"] else None
    metadata_evidence = (
        _parse_managed_metadata_evidence(data, result, int(extent)) if extent else None
    )
    result["validated_extent"] = extent
    result["metadata_evidence"] = metadata_evidence
    result["metadata_validated"] = metadata_evidence is not None
    result["boundary_validated"] = bool(extent and metadata_evidence)
    return result


def text_marker_hits(data: bytes, markers: tuple[str, ...]) -> list[str]:
    """ASCIIまたはUTF-16LEで実在するmarker名だけを返す。"""

    return [marker for marker in markers if marker.encode("ascii") in data or marker.encode("utf-16le") in data]


def _entry_bounds(resource_set: object, index: int) -> tuple[int, int]:
    entries = list(getattr(resource_set, "entries", []) or [])
    raw = getattr(resource_set, "_data", b"")
    header = getattr(resource_set, "struct", None)
    base = int(getattr(header, "DataSectionOffset", 0) or 0)
    if not isinstance(raw, (bytes, bytearray)) or not 0 <= index < len(entries):
        raise ValueError("ResourceSet entryを参照できません")
    start = base + int(getattr(getattr(entries[index], "struct", None), "DataOffset", 0) or 0)
    offsets = sorted(base + int(getattr(getattr(entry, "struct", None), "DataOffset", 0) or 0) for entry in entries)
    later = [offset for offset in offsets if offset > start]
    end = min(later) if later else len(raw)
    if not 0 <= start < end <= len(raw):
        raise ValueError("ResourceSet entry境界が不正です")
    return start, end


def _bitmap_header(raw: bytes, offset: int, end: int) -> dict[str, int]:
    if offset < 0 or offset + 54 > end or raw[offset : offset + 2] != b"BM":
        raise ValueError("BMP headerがありません")
    declared_size = struct.unpack_from("<I", raw, offset + 2)[0]
    pixel_offset = struct.unpack_from("<I", raw, offset + 10)[0]
    dib_size = struct.unpack_from("<I", raw, offset + 14)[0]
    width, height = struct.unpack_from("<ii", raw, offset + 18)
    planes, bits = struct.unpack_from("<HH", raw, offset + 26)
    compression = struct.unpack_from("<I", raw, offset + 30)[0]
    if (
        declared_size < 54
        or offset + declared_size > end
        or dib_size < 40
        or width <= 0
        or height == 0
        or planes != 1
        or bits not in {24, 32}
        or compression != 0
    ):
        raise ValueError("BMP構造が未対応または切断されています")
    absolute_height = abs(height)
    stride = ((width * bits + 31) // 32) * 4
    if pixel_offset < 54 or pixel_offset + stride * absolute_height > declared_size:
        raise ValueError("BMP pixel範囲が切断されています")
    return {
        "declared_size": declared_size,
        "width": width,
        "height": absolute_height,
        "pixels": width * absolute_height,
        "rgb_bytes": width * absolute_height * 3,
    }


def _managed_resource_range_evidence(
    image: object,
    data: bytes,
    extent: int,
    metadata_evidence: dict[str, Any] | None,
) -> dict[str, int] | None:
    """ManifestResource行とCLR resource directoryの物理範囲を検証する。"""

    if not metadata_evidence or metadata_evidence["manifest_resource_rows"] < 1:
        return None
    net_struct = getattr(getattr(image, "net", None), "struct", None)
    resource_rva = _integer_field(net_struct, "ResourcesRva")
    resource_size = _integer_field(net_struct, "ResourcesSize")
    if resource_rva <= 0 or not 0 < resource_size <= MAX_BITMAP_RESOURCE_BYTES:
        return None
    try:
        resource_offset = int(image.get_offset_from_rva(resource_rva))
    except (AttributeError, TypeError, ValueError):
        return None
    resource_end = resource_offset + resource_size
    if resource_offset < 0 or resource_end > extent or resource_end > len(data):
        return None
    return {
        "resource_rva": resource_rva,
        "resource_offset": resource_offset,
        "resource_size": resource_size,
        "resource_end": resource_end,
        "manifest_resource_rows": int(metadata_evidence["manifest_resource_rows"]),
    }


def _budget_report(
    diagnostics: list[str],
    *,
    counters: dict[str, int],
    inventory: list[dict[str, Any]] | None = None,
) -> tuple[dict[str, Any], list[tuple[str, bytes]]]:
    return (
        {
            "status": "budget_exceeded",
            "diagnostics": diagnostics,
            "counters": counters,
            "inventory": inventory or [],
            "managed_metadata_valid": False,
            "managed_metadata_evidence": None,
            "managed_resource_range": None,
            "embedded_bitmap_headers": [],
        },
        [],
    )


def _scan_embedded_bitmap_headers(
    data: bytes,
    counters: dict[str, int],
    *,
    start: int,
    end: int,
) -> tuple[list[dict[str, int]], str | None]:
    """CLR resource範囲内のBMPだけを候補数・画素総量上限付きで検証する。"""

    inventory: list[dict[str, int]] = []
    search_offset = start
    while True:
        offset = data.find(b"BM", search_offset, end)
        if offset < 0:
            return inventory, None
        search_offset = offset + 2
        counters["embedded_bitmap_candidates"] += 1
        if counters["embedded_bitmap_candidates"] > MAX_EMBEDDED_BITMAP_CANDIDATES:
            return [], "埋め込みBMP候補数が走査上限を超えています"
        try:
            header = _bitmap_header(data, offset, end)
        except ValueError:
            continue
        if (
            header["width"] > MAX_BITMAP_DIMENSION
            or header["height"] > MAX_BITMAP_DIMENSION
            or header["pixels"] > MAX_BITMAP_PIXELS
        ):
            return [], "埋め込みBitmap dimensionsまたはpixel数が上限を超えています"
        counters["bitmap_pixels"] += header["pixels"]
        counters["rgb_bytes"] += header["rgb_bytes"]
        if (
            counters["bitmap_pixels"] > MAX_BITMAP_TOTAL_PIXELS
            or counters["rgb_bytes"] > MAX_BITMAP_TOTAL_RGB_BYTES
        ):
            return [], "埋め込みBitmap pixelまたはRGB総量が上限を超えています"
        inventory.append(
            {
                "offset": offset,
                "bitmap_size": header["declared_size"],
                "width": header["width"],
                "height": header["height"],
                "pixel_count": header["pixels"],
            }
        )


@_contain_parser_diagnostics
def _recover_budgeted_bitmap_pes(
    data: bytes,
) -> tuple[dict[str, Any], list[tuple[str, bytes]]]:
    """Bitmap entryだけを総量上限付きで走査し、PE候補をメモリ上で返す。"""

    counters = {
        "input_bytes": len(data),
        "resource_count": 0,
        "entry_count": 0,
        "resource_bytes": 0,
        "bitmap_pixels": 0,
        "rgb_bytes": 0,
        "output_bytes": 0,
        "embedded_bitmap_candidates": 0,
    }
    diagnostics: list[str] = []
    inventory: list[dict[str, Any]] = []
    artifacts: list[tuple[str, bytes]] = []
    if len(data) > MAX_BITMAP_SCAN_INPUT_BYTES:
        diagnostics.append("入力サイズがBitmap走査上限を超えています")
        return _budget_report(diagnostics, counters=counters)
    try:
        image = dnfile.dnPE(data=data)
        net = getattr(image, "net", None)
        shape = managed_pe_shape(data)
        extent = valid_pe_extent(data, 0) if shape["is_managed_pe"] else None
        managed_metadata_evidence = (
            _managed_metadata_evidence_from_image(image, data, shape, int(extent))
            if extent
            else None
        )
        managed_metadata_valid = managed_metadata_evidence is not None
        managed_resource_range = (
            _managed_resource_range_evidence(
                image,
                data,
                int(extent),
                managed_metadata_evidence,
            )
            if extent
            else None
        )
        resources = list(getattr(net, "resources", []) or [])
    except Exception as exc:
        return (
            {
                "status": "parse_failed",
                "diagnostics": [f".NET resource解析失敗: {type(exc).__name__}"],
                "counters": counters,
                "inventory": [],
                "managed_metadata_valid": False,
                "managed_metadata_evidence": None,
                "managed_resource_range": None,
                "embedded_bitmap_headers": [],
            },
            [],
        )
    counters["resource_count"] = len(resources)
    if len(resources) > MAX_BITMAP_RESOURCE_COUNT:
        diagnostics.append("manifest resource数がBitmap走査上限を超えています")
        return _budget_report(diagnostics, counters=counters)

    bitmap_seen = False
    for resource in resources:
        resource_set = getattr(resource, "data", None)
        entries = list(getattr(resource_set, "entries", []) or [])
        raw_value = getattr(resource_set, "_data", b"")
        raw = bytes(raw_value) if isinstance(raw_value, (bytes, bytearray)) else b""
        counters["entry_count"] += len(entries)
        counters["resource_bytes"] += len(raw)
        if counters["entry_count"] > MAX_BITMAP_ENTRY_COUNT:
            diagnostics.append("ResourceSet entry総数がBitmap走査上限を超えています")
            return _budget_report(
                diagnostics,
                counters=counters,
                inventory=inventory,
            )
        if counters["resource_bytes"] > MAX_BITMAP_RESOURCE_BYTES:
            diagnostics.append("ResourceSet raw data総量がBitmap走査上限を超えています")
            return _budget_report(
                diagnostics,
                counters=counters,
                inventory=inventory,
            )
        resource_entries: list[dict[str, Any]] = []
        for index, entry in enumerate(entries):
            if "System.Drawing.Bitmap" not in str(getattr(entry, "type_name", "")):
                continue
            bitmap_seen = True
            item: dict[str, Any] = {"name": str(getattr(entry, "name", "unnamed"))}
            try:
                start, end = _entry_bounds(resource_set, index)
                bmp_offset = raw.find(b"BM", start, min(end, start + 4096))
                header = _bitmap_header(raw, bmp_offset, end)
            except ValueError as exc:
                item.update(status="unsupported_bitmap", diagnostic=str(exc))
                resource_entries.append(item)
                continue
            item.update(
                bitmap_size=header["declared_size"],
                width=header["width"],
                height=header["height"],
                pixel_count=header["pixels"],
            )
            if (
                header["width"] > MAX_BITMAP_DIMENSION
                or header["height"] > MAX_BITMAP_DIMENSION
                or header["pixels"] > MAX_BITMAP_PIXELS
            ):
                item["status"] = "budget_exceeded"
                resource_entries.append(item)
                inventory.append(
                    {
                        "name": str(getattr(resource, "name", "")),
                        "size": len(raw),
                        "bitmap_payloads": {
                            "status": "budget_exceeded",
                            "entries": resource_entries,
                        },
                    }
                )
                diagnostics.append("Bitmap dimensionsまたはpixel数が上限を超えています")
                return _budget_report(
                    diagnostics,
                    counters=counters,
                    inventory=inventory,
                )
            counters["bitmap_pixels"] += header["pixels"]
            counters["rgb_bytes"] += header["rgb_bytes"]
            if (
                counters["bitmap_pixels"] > MAX_BITMAP_TOTAL_PIXELS
                or counters["rgb_bytes"] > MAX_BITMAP_TOTAL_RGB_BYTES
            ):
                item["status"] = "budget_exceeded"
                resource_entries.append(item)
                inventory.append(
                    {
                        "name": str(getattr(resource, "name", "")),
                        "size": len(raw),
                        "bitmap_payloads": {
                            "status": "budget_exceeded",
                            "entries": resource_entries,
                        },
                    }
                )
                diagnostics.append("Bitmap pixelまたはRGB出力総量が上限を超えています")
                return _budget_report(
                    diagnostics,
                    counters=counters,
                    inventory=inventory,
                )
            proxy = SimpleNamespace(
                entries=[entry],
                _data=raw,
                struct=getattr(resource_set, "struct", None),
            )
            report, recovered = recover_dotnet_bitmap_payloads(proxy)
            report_entries = report.get("entries") or []
            recovered_item = (
                dict(report_entries[0])
                if report_entries and isinstance(report_entries[0], dict)
                else {"name": item["name"], "status": "no_result"}
            )
            recovered_item.update(
                width=header["width"],
                height=header["height"],
                pixel_count=header["pixels"],
            )
            resource_entries.append(recovered_item)
            for transform, payload in recovered:
                counters["output_bytes"] += len(payload)
                if counters["output_bytes"] > MAX_BITMAP_TOTAL_OUTPUT_BYTES:
                    diagnostics.append("復元PE総量がBitmap走査上限を超えています")
                    return _budget_report(
                        diagnostics,
                        counters=counters,
                        inventory=inventory,
                    )
                artifacts.append((transform, payload))
        if resource_entries:
            inventory.append(
                {
                    "name": str(getattr(resource, "name", "")),
                    "size": len(raw),
                    "sha256": hashlib.sha256(raw).hexdigest(),
                    "bitmap_payloads": {
                        "status": (
                            "pe_recovered"
                            if any(entry.get("status") == "pe_recovered" for entry in resource_entries)
                            else "bitmap_entries_processed"
                        ),
                        "entries": resource_entries,
                    },
                }
            )
    embedded_bitmap_headers: list[dict[str, int]] = []
    if not resources and managed_metadata_valid and managed_resource_range:
        embedded_bitmap_headers, embedded_error = _scan_embedded_bitmap_headers(
            data,
            counters,
            start=managed_resource_range["resource_offset"],
            end=managed_resource_range["resource_end"],
        )
        if embedded_error:
            diagnostics.append(embedded_error)
            return _budget_report(diagnostics, counters=counters, inventory=inventory)
    if artifacts:
        status = "bitmap_pe_recovered"
    elif bitmap_seen:
        status = "bitmap_entries_processed"
    elif resources:
        status = "no_bitmap_entries"
    elif embedded_bitmap_headers:
        status = "embedded_bitmap_validated"
    else:
        status = "no_manifest_resources"
    return (
        {
            "status": status,
            "diagnostics": diagnostics,
            "counters": counters,
            "inventory": inventory,
            "managed_metadata_valid": managed_metadata_valid,
            "managed_metadata_evidence": managed_metadata_evidence,
            "managed_resource_range": managed_resource_range,
            "embedded_bitmap_headers": embedded_bitmap_headers,
        },
        artifacts,
    )


def _bitmap_inventory(report: dict[str, Any]) -> list[dict[str, Any]]:
    """Bitmap専用走査報告をbyte列を含まない公開形へ縮約する。"""

    values: list[dict[str, Any]] = []
    inventory = report.get("inventory")
    if not isinstance(inventory, list):
        return values
    for resource in inventory:
        if not isinstance(resource, dict):
            continue
        bitmap = resource.get("bitmap_payloads")
        if not isinstance(bitmap, dict):
            continue
        entries = bitmap.get("entries")
        if not isinstance(entries, list):
            entries = []
        values.append(
            {
                "resource_name": str(resource.get("name") or ""),
                "resource_sha256": resource.get("sha256"),
                "status": bitmap.get("status"),
                "entries": [
                    {
                        key: entry.get(key)
                        for key in (
                            "name",
                            "status",
                            "diagnostic",
                            "bitmap_size",
                            "width",
                            "height",
                            "pixel_count",
                            "rgb_size",
                            "rgb_sha256",
                            "payload_size",
                            "payload_sha256",
                        )
                        if entry.get(key) is not None
                    }
                    for entry in entries
                    if isinstance(entry, dict)
                ],
            }
        )
    return values


def _embedded_bitmap_inventory(report: dict[str, Any]) -> list[dict[str, int]]:
    """検証済み埋め込みBMPヘッダーを公開用の整数情報へ限定する。"""

    values: list[dict[str, int]] = []
    headers = report.get("embedded_bitmap_headers")
    if not isinstance(headers, list):
        return values
    keys = ("offset", "bitmap_size", "width", "height", "pixel_count")
    for header in headers:
        if not isinstance(header, dict) or not all(isinstance(header.get(key), int) for key in keys):
            continue
        item = {key: int(header[key]) for key in keys}
        if (
            item["offset"] < 0
            or item["bitmap_size"] < 54
            or item["width"] <= 0
            or item["height"] <= 0
            or item["width"] > MAX_BITMAP_DIMENSION
            or item["height"] > MAX_BITMAP_DIMENSION
            or item["pixel_count"] != item["width"] * item["height"]
            or item["pixel_count"] > MAX_BITMAP_PIXELS
        ):
            continue
        values.append(item)
    return values


def bitmap_loader_evidence(data: bytes) -> dict[str, Any]:
    """Bitmap RGB子PEまたは強いGetPixel/reflection相関を静的に評価する。"""

    managed = managed_pe_shape(data)
    marker_hits = [marker.decode("ascii") for marker in (*BITMAP_MARKERS, *RGB_ACCESS_MARKERS) if marker in data]
    marker_correlation = bool(
        managed["is_managed_pe"]
        and all(marker in data for marker in BITMAP_MARKERS)
        and all(marker in data for marker in RGB_ACCESS_MARKERS)
    )
    recovered_children: list[dict[str, Any]] = []
    bitmap_inventory: list[dict[str, Any]] = []
    resource_status = "not_scanned"
    resource_diagnostics: list[str] = []
    resource_counters: dict[str, int] = {}
    managed_metadata_valid = False
    managed_metadata_evidence: dict[str, Any] | None = None
    managed_resource_range: dict[str, int] | None = None
    embedded_bitmap_headers: list[dict[str, int]] = []
    if managed["is_managed_pe"] and b"System.Drawing.Bitmap" in data and b"GetExportedTypes" in data:
        resource_report, artifacts = _recover_budgeted_bitmap_pes(data)
        resource_status = str(resource_report.get("status") or "unknown")
        bitmap_inventory = _bitmap_inventory(resource_report)
        managed_metadata_valid = resource_report.get("managed_metadata_valid") is True
        raw_metadata_evidence = resource_report.get("managed_metadata_evidence")
        managed_metadata_evidence = (
            dict(raw_metadata_evidence) if isinstance(raw_metadata_evidence, dict) else None
        )
        raw_resource_range = resource_report.get("managed_resource_range")
        managed_resource_range = (
            {
                str(key): int(value)
                for key, value in raw_resource_range.items()
                if isinstance(key, str) and isinstance(value, int)
            }
            if isinstance(raw_resource_range, dict)
            else None
        )
        embedded_bitmap_headers = _embedded_bitmap_inventory(resource_report)
        resource_diagnostics = [str(value) for value in resource_report.get("diagnostics", [])]
        resource_counters = {
            str(key): int(value)
            for key, value in (resource_report.get("counters") or {}).items()
            if isinstance(value, int)
        }
        if artifacts and not managed_metadata_valid:
            resource_diagnostics.append(
                "outerのCOR20・metadata root・primary table streamを検証できません"
            )
            artifacts = []
        seen: set[str] = set()
        for transform, payload in artifacts:
            if transform != "dotnet-bitmap-rgb-pe":
                continue
            child_shape = validated_managed_pe_shape(payload)
            if not child_shape["boundary_validated"] or not child_shape["is_managed_pe"]:
                resource_diagnostics.append("Bitmap RGB復元PEが境界検証済みmanaged PEではありません")
                continue
            extent = int(child_shape["validated_extent"])
            child = payload[:extent]
            digest = hashlib.sha256(child).hexdigest()
            if digest in seen:
                continue
            seen.add(digest)
            recovered_children.append(
                {
                    "role": "bitmap_rgb_managed_child",
                    "transform": transform,
                    "sha256": digest,
                    "size": len(child),
                    "format": "pe",
                    "format_evidence": child_shape,
                    "retained": False,
                    "executed": False,
                }
            )
    bitmap_resource_validated = bool(
        resource_status in {"bitmap_entries_processed", "bitmap_pe_recovered"}
        and managed_metadata_valid
        and bitmap_inventory
    )
    embedded_bitmap_validated = bool(
        resource_status == "embedded_bitmap_validated"
        and managed_metadata_valid
        and managed_resource_range
        and embedded_bitmap_headers
    )
    strong_reflection = bool(
        marker_correlation and (bitmap_resource_validated or embedded_bitmap_validated)
    )
    budget_exceeded = resource_status == "budget_exceeded"
    if budget_exceeded:
        recovered_children = []
        strong_reflection = False
    if recovered_children:
        variant = "bitmap_rgb_recovered_pe"
    elif strong_reflection:
        variant = "bitmap_getpixel_reflection"
    else:
        variant = None
    return {
        "managed_pe": managed,
        "matched": bool(recovered_children or strong_reflection),
        "variant": variant,
        "marker_hits": marker_hits,
        "strong_reflection_correlation": strong_reflection,
        "resource_status": resource_status,
        "resource_diagnostics": resource_diagnostics,
        "resource_counters": resource_counters,
        "bitmap_inventory": bitmap_inventory,
        "managed_metadata_valid": managed_metadata_valid,
        "managed_metadata_evidence": managed_metadata_evidence,
        "managed_resource_range": managed_resource_range,
        "embedded_bitmap_headers": embedded_bitmap_headers,
        "recovered_children": recovered_children,
        "sample_executed": False,
        "network_contacted": False,
    }
