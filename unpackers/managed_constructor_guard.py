"""dnfile constructor 前の raw PE/CLI/45table 宣言 guard。IO・row構築・callbackなし。"""
try:
    from . import clr_input_binding as binding
except ImportError:  # 単独CLIの通常相対探索
    import clr_input_binding as binding

MAX_INPUT_BYTES = 512 * 1024 * 1024
MAX_TABLE_ROWS = 20_000
MAX_TOTAL_ROWS = 80_000
SCOPE = "constructor_declarations_only"


def _integer(data, offset, width):
    return int.from_bytes(data[offset:offset + width], "little")


def _result(reason, limits, tables=0, rows=0):
    return {"status": "partial" if reason else "validated", "accepted": not bool(reason),
            "scope": SCOPE, "input_bound": not bool(reason),
            "counts": {"tables_declared": tables, "rows_declared": rows},
            "limits": limits, "reason_counts": {reason: 1} if reason else {}}


def preflight_clr_declarations(data, *, max_input_bytes=MAX_INPUT_BYTES,
                               max_table_rows=MAX_TABLE_ROWS, max_total_rows=MAX_TOTAL_ROWS):
    """元の exact bytes 宣言だけを検証し、parser constructor の可否を返す。"""
    limits = {"max_input_bytes": MAX_INPUT_BYTES, "max_table_rows": MAX_TABLE_ROWS,
              "max_total_rows": MAX_TOTAL_ROWS}
    values = (max_input_bytes, max_table_rows, max_total_rows)
    hard = (MAX_INPUT_BYTES, MAX_TABLE_ROWS, MAX_TOTAL_ROWS)
    if any(type(value) is not int or not 0 < value <= cap for value, cap in zip(values, hard)):
        return _result("preflight_budget_invalid", limits)
    limits = dict(zip(("max_input_bytes", "max_table_rows", "max_total_rows"), values))
    if type(data) is not bytes:
        return _result("preflight_input_type_invalid", limits)
    if len(data) > max_input_bytes:
        return _result("preflight_input_byte_budget", limits)
    if len(data) < 64 or data[:2] != b"MZ":
        return _result("preflight_pe_header_invalid", limits)
    nt = _integer(data, 60, 4)
    if nt < 64 or nt + 24 > len(data) or data[nt:nt + 4] != b"PE\0\0":
        return _result("preflight_pe_header_invalid", limits)
    section_count, optional_size = _integer(data, nt + 6, 2), _integer(data, nt + 20, 2)
    optional = nt + 24
    section_start = optional + optional_size
    if (not 1 <= section_count <= binding.MAX_SECTIONS
            or not 1 <= optional_size <= binding.MAX_OPTIONAL_HEADER_BYTES
            or section_start + 40 * section_count > len(data)):
        return _result("preflight_pe_header_invalid", limits)
    magic = _integer(data, optional, 2)
    directory_base, count_offset = ((96, 92) if magic == 0x10B else
                                    (112, 108) if magic == 0x20B else (None, None))
    if directory_base is None or optional_size < directory_base + 15 * 8:
        return _result("preflight_pe_header_invalid", limits)
    directory_count = _integer(data, optional + count_offset, 4)
    if not 15 <= directory_count <= 16 or optional_size < directory_base + directory_count * 8:
        return _result("preflight_pe_header_invalid", limits)
    section_alignment = _integer(data, optional + 32, 4)
    file_alignment = _integer(data, optional + 36, 4)
    headers_size = _integer(data, optional + 60, 4)
    # parserの切下げ補正やheader fallbackを推測せず、raw写像と同じcanonical配置だけを受理する。
    if (not 0x200 <= file_alignment <= 0x10000 or file_alignment & (file_alignment - 1)
            or section_alignment < 0x1000 or section_alignment & (section_alignment - 1)
            or section_alignment < file_alignment
            or not section_start + 40 * section_count <= headers_size <= len(data)
            or headers_size % file_alignment):
        return _result("preflight_pe_layout_unsupported", limits)
    minimum_rva = ((headers_size + section_alignment - 1) // section_alignment) * section_alignment
    sections, virtual_spans, raw_spans = [], [], []
    for index in range(section_count):
        position = section_start + 40 * index
        values = tuple(_integer(data, position + field, 4) for field in (12, 16, 20))
        rva, size, offset = values
        if rva + size > binding.UINT32_END or offset + size > len(data):
            return _result("preflight_section_layout_invalid", limits)
        virtual_size = _integer(data, position + 8, 4)
        virtual_extent = max(size, virtual_size)
        if (rva % section_alignment or rva + virtual_extent > binding.UINT32_END
                or data[position:position + 40] == bytes(40)
                or (virtual_extent and rva < minimum_rva)
                or (size and (offset < headers_size or offset % file_alignment))):
            return _result("preflight_section_layout_unsupported", limits)
        if virtual_extent:
            virtual_spans.append((rva, rva + virtual_extent))
        if size:
            raw_spans.append((offset, offset + size))
        sections.append(values)
    for spans in (virtual_spans, raw_spans):
        if any(max(start, other_start) < min(end, other_end)
               for index, (start, end) in enumerate(spans)
               for other_start, other_end in spans[index + 1:]):
            return _result("preflight_section_layout_unsupported", limits)
    sections = tuple(sections)
    directory = optional + directory_base + 14 * 8
    clr_rva, clr_size = _integer(data, directory, 4), _integer(data, directory + 4, 4)
    if not 72 <= clr_size <= binding.MAX_CLR_DIRECTORY_BYTES:
        return _result("preflight_cli_header_invalid", limits)
    clr = binding.unique_file_span(sections, clr_rva, clr_size)
    if clr is None or _integer(data, clr, 4) != 72:
        return _result("preflight_cli_header_invalid", limits)
    metadata_rva, metadata_size = _integer(data, clr + 8, 4), _integer(data, clr + 12, 4)
    metadata = binding.unique_file_span(sections, metadata_rva, metadata_size)
    if (metadata is None or metadata_size < 20 or data[metadata:metadata + 4] != b"BSJB"
            or data[metadata + 4:metadata + 8] != b"\x01\x00\x01\x00"
            or _integer(data, metadata + 8, 4) != 0):
        return _result("preflight_metadata_root_invalid", limits)
    if max(clr, metadata) < min(clr + clr_size, metadata + metadata_size):
        return _result("preflight_metadata_root_invalid", limits)
    version_length = _integer(data, metadata + 12, 4)
    if (version_length > 256 or version_length % 4 or 20 + version_length > metadata_size
            or _integer(data, metadata + 16 + version_length, 2) != 0):
        return _result("preflight_metadata_root_invalid", limits)
    stream_count = _integer(data, metadata + 18 + version_length, 2)
    entries = binding.canonical_metadata_streams(data, metadata, metadata_size, version_length, stream_count)
    if entries is None:
        return _result("preflight_metadata_streams_invalid", limits)
    streams = {name: (metadata + relative, length) for _, name, relative, length in entries}
    if (b"#~" not in streams or b"#Strings" not in streams or b"#-" in streams
            or any(name not in (b"#~", b"#Strings", b"#Blob", b"#GUID", b"#US") for name in streams)):
        return _result("preflight_metadata_layout_unsupported", limits)
    table_offset, table_size = streams[b"#~"]
    if table_size < 24:
        return _result("preflight_metadata_layout_unsupported", limits)
    mask = _integer(data, table_offset + 8, 8)
    numbers = tuple(number for number in range(64) if mask & 1 << number)
    if any(number not in binding._SCHEMA for number in numbers) or 24 + 4 * len(numbers) > table_size:
        return _result("preflight_metadata_layout_unsupported", limits)
    # payload が短くても、全宣言を上限と比較する前に row・parser を構築しない。
    declared = tuple(_integer(data, table_offset + 24 + 4 * index, 4) for index in range(len(numbers)))
    total = sum(declared)
    if any(value > max_table_rows for value in declared):
        return _result("preflight_metadata_table_row_budget", limits, len(numbers), total)
    if total > max_total_rows:
        return _result("preflight_metadata_total_row_budget", limits, len(numbers), total)
    canonical = binding.canonical_table_layout(data, table_offset, table_size)
    if canonical is None:
        return _result("preflight_metadata_layout_unsupported", limits, len(numbers), total)
    counts, layout, heaps = canonical
    if tuple(counts[number] for number in numbers) != declared:
        return _result("preflight_metadata_layout_unsupported", limits, len(numbers), total)
    resource_rva, resource_size = _integer(data, clr + 24, 4), _integer(data, clr + 28, 4)
    if bool(resource_rva) != bool(resource_size):
        return _result("preflight_cli_header_invalid", limits, len(numbers), total)
    if resource_size:
        resource = binding.unique_file_span(sections, resource_rva, resource_size)
        if resource is None or any(max(resource, start) < min(resource + resource_size, end)
                                   for start, end in ((clr, clr + clr_size), (metadata, metadata + metadata_size))):
            return _result("preflight_cli_header_invalid", limits, len(numbers), total)
    return _result(None, limits, len(numbers), total)
