"""元bytesからPE/CLR宣言と固定metadata table位置を独立照合する。IOやparser callbackなし。"""

MAX_SECTIONS = 96
MAX_OPTIONAL_HEADER_BYTES = 4096
MAX_CLR_DIRECTORY_BYTES = 4096
UINT32_END = 1 << 32


def _uint32(value):
    return type(value) is int and 0 <= value < UINT32_END


def _integer(data, offset, size):
    return int.from_bytes(data[offset:offset + size], "little")


def unique_file_span(sections, rva, size):
    if not _uint32(rva) or not _uint32(size) or not size or rva + size > UINT32_END:
        return None
    candidates = [(index, offset + rva - base) for index, (base, raw_size, offset) in enumerate(sections)
                  if 0 <= rva - base and rva - base + size <= raw_size]
    if len(candidates) != 1:
        return None
    selected, offset = candidates[0]
    if any(index != selected and (max(rva, base) < min(rva + size, base + raw_size)
           or max(offset, raw_offset) < min(offset + size, raw_offset + raw_size))
           for index, (base, raw_size, raw_offset) in enumerate(sections)):
        return None
    return offset


def verify_pe_clr_input(data, pe):
    """DOS→NT→directory14→raw section→COR20を照合する。最初一致APIを呼ばない。"""
    try:
        if type(data) is not bytes or len(data) < 64 or data[:2] != b"MZ":
            return False
        nt = _integer(data, 60, 4)
        if nt < 64 or nt + 24 > len(data) or data[nt:nt + 4] != b"PE\x00\x00":
            return False
        section_count = _integer(data, nt + 6, 2)
        optional_size = _integer(data, nt + 20, 2)
        if not 1 <= section_count <= MAX_SECTIONS or not 1 <= optional_size <= MAX_OPTIONAL_HEADER_BYTES:
            return False
        optional = nt + 24
        section_start = optional + optional_size
        if section_start + 40 * section_count > len(data):
            return False
        magic = _integer(data, optional, 2)
        directory_base, count_offset = (96, 92) if magic == 0x10B else (112, 108) if magic == 0x20B else (None, None)
        if directory_base is None or optional_size < directory_base + 15 * 8:
            return False
        directory_count = _integer(data, optional + count_offset, 4)
        if not 15 <= directory_count <= 16 or optional_size < directory_base + directory_count * 8:
            return False
        if (type(pe.FILE_HEADER.NumberOfSections) is not int or pe.FILE_HEADER.NumberOfSections != section_count
                or type(pe.FILE_HEADER.SizeOfOptionalHeader) is not int or pe.FILE_HEADER.SizeOfOptionalHeader != optional_size
                or type(pe.OPTIONAL_HEADER.Magic) is not int or pe.OPTIONAL_HEADER.Magic != magic
                or type(pe.OPTIONAL_HEADER.NumberOfRvaAndSizes) is not int or pe.OPTIONAL_HEADER.NumberOfRvaAndSizes != directory_count):
            return False
        parsed_sections = pe.sections
        if type(parsed_sections) not in (list, tuple) or len(parsed_sections) != section_count:
            return False
        sections = []
        for index in range(section_count):
            start = section_start + 40 * index
            values = tuple(_integer(data, start + offset, 4) for offset in (12, 16, 20))
            parsed = parsed_sections[index]
            observed = (parsed.VirtualAddress, parsed.SizeOfRawData, parsed.PointerToRawData)
            if any(not _uint32(value) for value in observed) or observed != values:
                return False
            rva, raw_size, offset = values
            if rva + raw_size > UINT32_END or offset + raw_size > len(data):
                return False
            sections.append(values)
        directory = optional + directory_base + 14 * 8
        clr_rva, clr_size = _integer(data, directory, 4), _integer(data, directory + 4, 4)
        parsed_directories = pe.OPTIONAL_HEADER.DATA_DIRECTORY
        if type(parsed_directories) not in (list, tuple) or len(parsed_directories) < 15:
            return False
        parsed_directory = parsed_directories[14]
        observed_directory = (parsed_directory.VirtualAddress, parsed_directory.Size)
        if any(not _uint32(value) for value in observed_directory) or observed_directory != (clr_rva, clr_size):
            return False
        if not 72 <= clr_size <= MAX_CLR_DIRECTORY_BYTES:
            return False
        clr = unique_file_span(tuple(sections), clr_rva, clr_size)
        if clr is None or clr + clr_size > len(data) or _integer(data, clr, 4) != 72:
            return False
        header = pe.net.struct
        if type(header.cb) is not int or header.cb != 72:
            return False
        for name, offset in (("MetaDataRva", 8), ("MetaDataSize", 12),
                             ("ResourcesRva", 24), ("ResourcesSize", 28)):
            observed = getattr(header, name)
            if not _uint32(observed) or observed != _integer(data, clr + offset, 4):
                return False
        return True
    except Exception:
        return False


def canonical_metadata_streams(data, offset, size, version_length, stream_count):
    """rootが宣言したstream header位置だけを返す。padding中のlookalikeは探索しない。"""
    if (type(data) is not bytes or not _uint32(offset) or not _uint32(size)
            or type(version_length) is not int or not 0 <= version_length <= 256
            or version_length % 4 or type(stream_count) is not int or not 1 <= stream_count <= 64
            or offset + size > len(data) or 20 + version_length > size):
        return None
    end = offset + size
    position = offset + 20 + version_length
    result, names = [], set()
    for _ in range(stream_count):
        if position + 9 > end:
            return None
        relative, length = _integer(data, position, 4), _integer(data, position + 4, 4)
        name_end = data.find(b"\x00", position + 8, min(position + 40, end))
        if name_end < 0:
            return None
        name = data[position + 8:name_end]
        next_position = position + 8 + ((len(name) + 1 + 3) // 4) * 4
        if not name or name in names or next_position > end or relative + length > size:
            return None
        result.append((position, name, relative, length))
        names.add(name)
        position = next_position
    if any(offset + relative < position for _, _, relative, _ in result):
        return None
    for index, (_, _, start, length) in enumerate(result):
        if any(max(start, other_start) < min(start + length, other_start + other_length)
               for _, _, other_start, other_length in result[index + 1:]):
            return None
    return tuple(result)


# 固定schemaのfield: 2/4は整数幅、s/g/bはheap、tupleは(tag幅,参照table番号)。
TDR = (2, (2, 1, 27))
HC = (2, (4, 8, 23))
HCA = (5, (6, 4, 1, 2, 8, 9, 10, 0, 14, 23, 20, 17, 26, 27, 32, 35, 38, 39, 40, 42, 44, 43))
HFM = (1, (4, 8))
HDS = (2, (2, 6, 32))
MRP = (3, (2, 1, 26, 6, 27))
HS = (1, (20, 23))
MDR = (1, (6, 10))
MF = (1, (4, 6))
IMPL = (2, (38, 35, 39))
CAT = (3, (6, 10))
RS = (2, (0, 26, 35, 1))
TMD = (1, (2, 6))
_SCHEMA = {
    0: (2, "s", "g", "g", "g"), 1: (RS, "s", "s"),
    2: (4, "s", "s", TDR, (0, (4,)), (0, (6,))), 3: ((0, (4,)),),
    4: (2, "s", "b"), 5: ((0, (6,)),), 6: (4, 2, 2, "s", "b", (0, (8,))),
    7: ((0, (8,)),), 8: (2, 2, "s"), 9: ((0, (2,)), TDR),
    10: (MRP, "s", "b"), 11: (2, HC, "b"), 12: (HCA, CAT, "b"),
    13: (HFM, "b"), 14: (2, HDS, "b"), 15: (2, 4, (0, (2,))),
    16: (4, (0, (4,))), 17: ("b",), 18: ((0, (2,)), (0, (20,))),
    19: ((0, (20,)),), 20: (2, "s", TDR), 21: ((0, (2,)), (0, (23,))),
    22: ((0, (23,)),), 23: (2, "s", "b"), 24: (2, (0, (6,)), HS),
    25: ((0, (2,)), MDR, MDR), 26: ("s",), 27: ("b",),
    28: (2, MF, "s", (0, (26,))), 29: (4, (0, (4,))), 30: (4, 4), 31: (4,),
    32: (4, 2, 2, 2, 2, 4, "b", "s", "s"), 33: (4,), 34: (4, 4, 4),
    35: (2, 2, 2, 2, 4, "b", "s", "s", "b"), 36: (4, (0, (35,))),
    37: (4, 4, 4, (0, (35,))), 38: (4, "s", "b"),
    39: (4, 4, "s", "s", IMPL), 40: (4, 4, "s", IMPL),
    41: ((0, (2,)), (0, (2,))), 42: (2, 2, TMD, "s"),
    43: (MDR, "b"), 44: ((0, (42,)), TDR),
}


def _row_size(number, counts, heaps):
    result = 0
    for field in _SCHEMA[number]:
        if type(field) is int:
            result += field
        elif type(field) is str:
            result += heaps[{"s": 0, "g": 1, "b": 2}[field]]
        else:
            tag_bits, targets = field
            result += 2 if max(counts[target] for target in targets) < 1 << (16 - tag_bits) else 4
    return result


def canonical_table_layout(data, offset, size):
    """#~ v2.0のraw宣言だけで全table位置を計算する。rowや未知callbackを評価しない。"""
    if type(data) is not bytes or not _uint32(offset) or not _uint32(size) or size < 24 or offset + size > len(data):
        return None
    header = data[offset:offset + 24]
    if header[:4] != bytes(4) or header[4:6] != b"\x02\x00" or header[7] != 1 or header[6] & ~0x47:
        return None
    mask = _integer(header, 8, 8)
    numbers = tuple(number for number in range(64) if mask & 1 << number)
    if any(number not in _SCHEMA for number in numbers):
        return None
    position = offset + 24
    if position + 4 * len(numbers) > offset + size:
        return None
    counts = [0] * 64
    for number in numbers:
        counts[number] = _integer(data, position, 4)
        position += 4
    if header[6] & 0x40:
        position += 4
    if position > offset + size:
        return None
    heaps = tuple(4 if header[6] & flag else 2 for flag in (1, 2, 4))
    layout = [None] * 64
    for number in numbers:
        row_size = _row_size(number, counts, heaps)
        end = position + row_size * counts[number]
        if end > offset + size:
            return None
        layout[number] = (position, row_size, counts[number])
        position = end
    return tuple(counts), tuple(layout), heaps
