"""dnfile 0.18.0の固定LazyList／MDTableだけを受理する静的resource adapter。"""

from __future__ import annotations

from types import CodeType, FunctionType, MethodType, SimpleNamespace
from typing import Any

try:
    from . import clr_input_binding
except ImportError:
    import clr_input_binding

try:
    import dnfile
    from dnfile import base, mdtable, stream, utils
except ImportError:
    dnfile = base = mdtable = stream = utils = None

REVIEWED_VERSION = "0.18.0"
MAX_ROW_BYTES = 128
MAX_STRING_UTF8_BYTES = 2048
MAX_PARSER_TABLES = 64
MAX_STRING_HEAP_BYTES = 16 << 20
MAX_METADATA_VERSION_BYTES = 256
REASONS = frozenset({
    "dnfile_lazy_dependency_unreviewed", "dnfile_lazy_table_provenance_invalid",
    "dnfile_lazy_callback_unreviewed", "dnfile_lazy_full_loader_unreviewed",
    "dnfile_lazy_state_invalid", "dnfile_lazy_table_data_invalid",
    "dnfile_lazy_source_changed", "dnfile_lazy_materialization_failed",
    "dnfile_lazy_row_invalid", "dnfile_resource_view_invalid",
    "dnfile_string_heap_provenance_invalid", "dnfile_string_heap_budget_exceeded",
    "dnfile_metadata_registry_incomplete",
    "dnfile_pe_clr_input_binding_invalid", "dnfile_eager_rows_unsupported",
    "dnfile_table_layout_unsupported", "dnfile_table_canonical_position_mismatch",
})

_PROFILE_READY = False
_LAZY_LIST = None
_METADATA_CANDIDATE_CLASS = None
_TABLE_CLASSES = _ROW_CLASSES = _STRUCT_CLASSES = {}
try:
    # 非対応versionやAPI形状からclass/codeを無条件取得せず、import成功と受理を分ける。
    _LAZY_LIST = utils.LazyList
    if type(_LAZY_LIST) is not type or not issubclass(_LAZY_LIST, list):
        raise TypeError("非対応LazyListです")
    # 非対応versionのordinary rowsも迂回受理しないための拒否用identity。受理証明には使わない。
    _METADATA_CANDIDATE_CLASS = stream.MetaDataTables
    if dnfile is None or type(dnfile.__version__) is not str or dnfile.__version__ != REVIEWED_VERSION:
        raise ValueError("非対応dependencyです")
    _PE_CLASS, _ROOT_METADATA_CLASS = dnfile.dnPE, dnfile.ClrMetaData
    _ROOT_STRUCT_CLASS, _STREAM_STRUCT_CLASS = dnfile.ClrMetaDataStruct, base.StreamStruct
    _METADATA_CLASS, _STRINGS_CLASS = stream.MetaDataTables, stream.StringsHeap
    _TABLE_CLASSES = {
        "TypeRef": mdtable.TypeRef, "TypeDef": mdtable.TypeDef, "Field": mdtable.Field,
        "MethodDef": mdtable.MethodDef, "MemberRef": mdtable.MemberRef,
        "StandAloneSig": mdtable.StandAloneSig, "ModuleRef": mdtable.ModuleRef,
        "TypeSpec": mdtable.TypeSpec, "MethodSpec": mdtable.MethodSpec,
        "AssemblyRef": mdtable.AssemblyRef, "File": mdtable.File,
        "ExportedType": mdtable.ExportedType, "ManifestResource": mdtable.ManifestResource,
    }
    _ROW_CLASSES = {name: cls._row_class for name, cls in _TABLE_CLASSES.items()}
    _STRUCT_CLASSES = {name: cls._struct_class for name, cls in _ROW_CLASSES.items()}
    _PARSE_ROWS = base.ClrMetaDataTable._lazy_parse_rows
    _PARSE_ROW = base.ClrMetaDataTable._lazy_parse_row
    _PARSE_ROWS_CODE, _PARSE_ROW_CODE = _PARSE_ROWS.__code__, _PARSE_ROW.__code__
    _LAZY_GETITEM, _LAZY_GETITEM_CODE = _LAZY_LIST.__getitem__, _LAZY_LIST.__getitem__.__code__
    _ROW_INIT, _ROW_SETUP, _ROW_SET_DATA = base.MDTableRow.__init__, base.MDTableRow.setup_lazy_load, base.MDTableRow.set_data
    _ROW_BASE_CODES = (_ROW_INIT.__code__, _ROW_SETUP.__code__, _ROW_SET_DATA.__code__)
    _ROW_CODES = {name: cls._row_class._compute_format.__code__ for name, cls in _TABLE_CLASSES.items()}
    _FULL_LOADER_CODE = next(code for code in stream.MetaDataTables.parse.__code__.co_consts
                             if type(code) is CodeType and code.co_name == "full_loader")
    _PROFILE_READY = True
except Exception:
    # 欠落API／codeを含む未レビューdependencyはpartialで扱い、import時に停止しない。
    _PROFILE_READY = False
    _TABLE_CLASSES = _ROW_CLASSES = _STRUCT_CLASSES = {}


def dependency_failure() -> str | None:
    try:
        supported = (_PROFILE_READY and dnfile is not None and type(dnfile.__version__) is str
                     and dnfile.__version__ == REVIEWED_VERSION)
    except Exception:
        supported = False
    if not supported:
        return "dnfile_lazy_dependency_unreviewed"
    return None


def is_exact_lazy_list(source: Any) -> bool:
    return _LAZY_LIST is not None and type(source) is _LAZY_LIST


def is_exact_metadata(metadata: Any) -> bool:
    return _PROFILE_READY and type(metadata) is _METADATA_CLASS


def is_dnfile_metadata_candidate(metadata: Any) -> bool:
    return _METADATA_CANDIDATE_CLASS is not None and type(metadata) is _METADATA_CANDIDATE_CLASS


def is_heap_binding(value: Any) -> bool:
    return type(value) is _HeapBinding


def verify_input_binding(data, pe):
    failure = dependency_failure()
    if failure:
        return failure
    if type(pe) is not _PE_CLASS or not clr_input_binding.verify_pe_clr_input(data, pe):
        return "dnfile_pe_clr_input_binding_invalid"
    return None


def container_count(source: Any) -> int | None:
    """callbackを呼ばず、ordinary containerかexact LazyListの長さだけを取得する。"""
    if type(source) in (list, tuple):
        return len(source)
    if is_exact_lazy_list(source):
        return list.__len__(source)
    return None


def _bound_method(value: Any, owner: Any, function: Any) -> bool:
    return type(value) is MethodType and value.__self__ is owner and value.__func__ is function


class _HeapBinding:
    """同一入力へ結び付けた内部heap参照。本文や名前をrepr／stateに出さない。"""

    __slots__ = ("data", "pe", "metadata", "root", "heap", "raw", "offset", "size", "row_counts", "table_layout", "heap_widths")

    def __init__(self, data, pe, metadata, root, heap, raw, offset, size, row_counts, table_layout, heap_widths):
        self.data, self.pe, self.metadata, self.root = data, pe, metadata, root
        self.heap, self.raw, self.offset, self.size = heap, raw, offset, size
        self.row_counts = row_counts
        self.table_layout, self.heap_widths = table_layout, heap_widths

    def __repr__(self):
        return "_HeapBinding(private_identity_omitted=True)"

    def __getstate__(self):
        return {"private_identity_omitted": True}


def _valid_counts(value):
    return (type(value) is tuple and len(value) == 64
            and all(type(count) is int and 0 <= count < 1 << 32 for count in value))


def _valid_layout(value):
    return (type(value) is tuple and len(value) == 64 and all(item is None or
            (type(item) is tuple and len(item) == 3 and all(type(number) is int and 0 <= number < 1 << 32 for number in item))
            for item in value))

def _uint32(value):
    return type(value) is int and 0 <= value < 1 << 32


def _unique_file_span(data, pe, rva, size):
    if not _uint32(rva) or not _uint32(size) or rva + size > 1 << 32:
        return None
    source, declared = pe.sections, pe.FILE_HEADER.NumberOfSections
    if type(source) not in (list, tuple) or type(declared) is not int or not 1 <= declared <= 96 or len(source) != declared:
        return None
    rows = []
    for section in source:
        base_rva, raw_size, offset = section.VirtualAddress, section.SizeOfRawData, section.PointerToRawData
        if (not all(_uint32(value) for value in (base_rva, raw_size, offset))
                or base_rva + raw_size > 1 << 32 or offset + raw_size > len(data)):
            return None
        rows.append((base_rva, raw_size, offset))
    candidates = [(index, offset + rva - base_rva) for index, (base_rva, raw_size, offset) in enumerate(rows)
                  if 0 <= rva - base_rva and rva - base_rva + size <= raw_size]
    if len(candidates) != 1:
        return None
    selected, offset = candidates[0]
    if any(index != selected and (max(rva, base_rva) < min(rva + size, base_rva + raw_size)
           or max(offset, raw_offset) < min(offset + size, raw_offset + raw_size))
           for index, (base_rva, raw_size, raw_offset) in enumerate(rows)):
        return None
    return offset


def bind_strings_heap(data: bytes, pe: Any, metadata: Any, previous: Any = None, *, max_heap_bytes: int = MAX_STRING_HEAP_BYTES):
    """同じ#Strings heapを一度だけ入力照合する。複数tableで同じ全heap比較を繰返さない。"""
    failure = dependency_failure()
    if failure:
        return None, failure, 0
    try:
        if type(data) is not bytes or type(pe) is not _PE_CLASS or type(metadata) is not _METADATA_CLASS:
            return None, "dnfile_string_heap_provenance_invalid", 0
        root, heap = pe.net.metadata, pe.net.strings
        if type(root) is not _ROOT_METADATA_CLASS or type(root.struct) is not _ROOT_STRUCT_CLASS or type(heap) is not _STRINGS_CLASS:
            return None, "dnfile_string_heap_provenance_invalid", 0
        registry, streams = root.streams, root.streams_list
        declared = root.struct.NumberOfStreams
        if (type(registry) is not dict or type(streams) is not list or type(declared) is not int
                or not 1 <= declared <= MAX_PARSER_TABLES or len(registry) != declared or len(streams) != declared
                or any(type(name) is not bytes or len(name) > 32 for name in registry)
                or registry.get(b"#Strings") is not heap or sum(item is heap for item in streams) != 1
                or sum(item is metadata for item in streams) != 1
                or sum(registry.get(name) is metadata for name in (b"#~", b"#-", b"#Schema")) != 1
                or any(type(name) is not bytes or len(name) > 32 or sum(item is value for item in streams) != 1
                       for name, value in registry.items())):
            return None, "dnfile_string_heap_provenance_invalid", 0
        metadata_rva, metadata_size = pe.net.struct.MetaDataRva, pe.net.struct.MetaDataSize
        metadata_offset = _unique_file_span(data, pe, metadata_rva, metadata_size)
        if metadata_offset is None or type(root.rva) is not int or root.rva != metadata_rva:
            return None, "dnfile_string_heap_provenance_invalid", 0
        header_offset = object.__getattribute__(root.struct, "__file_offset__")
        version_length = root.struct.VersionLength
        if (type(header_offset) is not int or header_offset != metadata_offset
                or type(version_length) is not int or not 0 <= version_length <= MAX_METADATA_VERSION_BYTES
                or 20 + version_length > metadata_size or data[header_offset:header_offset + 4] != b"BSJB"
                or int.from_bytes(data[header_offset + 12:header_offset + 16], "little") != version_length
                or int.from_bytes(data[header_offset + 18 + version_length:header_offset + 20 + version_length], "little") != declared):
            return None, "dnfile_string_heap_provenance_invalid", 0
        entries = clr_input_binding.canonical_metadata_streams(data, metadata_offset, metadata_size, version_length, declared)
        if (entries is None or {entry[1] for entry in entries} != set(registry)
                or any(registry[entry[1]] is not streams[index] for index, entry in enumerate(entries))):
            return None, "dnfile_string_heap_provenance_invalid", 0
        declared_entries = {entry[1]: entry for entry in entries}
        header = heap.struct
        if type(header) is not _STREAM_STRUCT_CLASS or type(header.Name) is not bytes or header.Name != b"#Strings":
            return None, "dnfile_string_heap_provenance_invalid", 0
        relative, size = header.Offset, header.Size
        if not _uint32(relative) or not _uint32(size) or relative + size > metadata_size:
            return None, "dnfile_string_heap_provenance_invalid", 0
        if type(max_heap_bytes) is not int or not 0 < max_heap_bytes <= MAX_STRING_HEAP_BYTES or size > max_heap_bytes:
            return None, "dnfile_string_heap_budget_exceeded", 0
        entry_offset = object.__getattribute__(header, "__file_offset__")
        offset, raw = heap.file_offset, object.__getattribute__(heap, "__data__")
        if (type(entry_offset) is not int or declared_entries[b"#Strings"] != (entry_offset, b"#Strings", relative, size)
                or not metadata_offset <= entry_offset <= metadata_offset + metadata_size - 16
                or int.from_bytes(data[entry_offset:entry_offset + 4], "little") != relative
                or int.from_bytes(data[entry_offset + 4:entry_offset + 8], "little") != size
                or data[entry_offset + 8:entry_offset + 17] != b"#Strings\x00"
                or type(offset) is not int or offset != metadata_offset + relative
                or type(heap.rva) is not int or heap.rva != metadata_rva + relative
                or _unique_file_span(data, pe, heap.rva, size) != offset
                or type(raw) is not bytes or len(raw) != size or type(heap._data_size) is not int or heap._data_size != size):
            return None, "dnfile_string_heap_provenance_invalid", 0
        if previous is not None and (type(previous) is not _HeapBinding or previous.data is not data
                or previous.pe is not pe or previous.metadata is not metadata or previous.root is not root
                or previous.heap is not heap or previous.raw is not raw or type(previous.offset) is not int
                or type(previous.size) is not int or previous.offset != offset or previous.size != size):
            return None, "dnfile_string_heap_provenance_invalid", 0
        # memoryviewは全heapの追加bytes copyを作らない。比較は共有hard上限内で一度だけ。
        if memoryview(data)[offset:offset + size] != raw:
            return None, "dnfile_string_heap_provenance_invalid", size
        if type(metadata.file_offset) is not int or metadata.file_offset < 0:
            return None, "dnfile_metadata_registry_incomplete", size
        header_raw = data[metadata.file_offset:metadata.file_offset + 24]
        table_header = metadata.struct
        table_entry = object.__getattribute__(table_header, "__file_offset__")
        if (type(table_header) is not _STREAM_STRUCT_CLASS or type(table_header.Name) is not bytes or table_header.Name != b"#~"
                or not _uint32(table_header.Offset) or not _uint32(table_header.Size)
                or table_header.Offset + table_header.Size > metadata_size or table_header.Size < 24
                or type(metadata.file_offset) is not int or metadata.file_offset != metadata_offset + table_header.Offset
                or type(metadata.rva) is not int or metadata.rva != metadata_rva + table_header.Offset
                or _unique_file_span(data, pe, metadata.rva, table_header.Size) != metadata.file_offset
                or type(table_entry) is not int or not metadata_offset <= table_entry <= metadata_offset + metadata_size - 8
                or declared_entries.get(b"#~") != (table_entry, b"#~", table_header.Offset, table_header.Size)
                or int.from_bytes(data[table_entry:table_entry + 4], "little") != table_header.Offset
                or int.from_bytes(data[table_entry + 4:table_entry + 8], "little") != table_header.Size
                or data[table_entry + 8:table_entry + 11] != b"#~\x00"
                or len(header_raw) != 24):
            return None, "dnfile_metadata_registry_incomplete", size
        mask = int.from_bytes(header_raw[8:16], "little")
        numbers = {number for number in range(MAX_PARSER_TABLES) if mask & 1 << number}
        if (type(metadata.tables) is not dict
                or any(type(number) is not int or not 0 <= number < MAX_PARSER_TABLES for number in metadata.tables)
                or set(metadata.tables) != numbers
                or type(metadata.tables_list) is not list or len(metadata.tables_list) != len(numbers)):
            return None, "dnfile_metadata_registry_incomplete", size
        canonical = clr_input_binding.canonical_table_layout(data, metadata.file_offset, table_header.Size)
        if canonical is None:
            return None, "dnfile_table_layout_unsupported", size
        row_counts, table_layout, heap_widths = canonical
        if previous is not None and (not _valid_counts(previous.row_counts) or not _valid_layout(previous.table_layout)
                or type(previous.heap_widths) is not tuple or len(previous.heap_widths) != 3
                or any(type(value) is not int or value not in (2, 4) for value in previous.heap_widths)
                or previous.row_counts != row_counts or previous.table_layout != table_layout or previous.heap_widths != heap_widths):
            return None, "dnfile_string_heap_provenance_invalid", size
        return _HeapBinding(data, pe, metadata, root, heap, raw, offset, size, row_counts, table_layout, heap_widths), None, size
    except Exception:
        return None, "dnfile_string_heap_provenance_invalid", 0


def _trusted_functions_intact(name: str) -> bool:
    row_class = _ROW_CLASSES[name]
    return (_TABLE_CLASSES[name]._row_class is row_class and row_class._struct_class is _STRUCT_CLASSES[name]
            and _LAZY_LIST.__getitem__ is _LAZY_GETITEM and _LAZY_GETITEM.__code__ is _LAZY_GETITEM_CODE
            and _PARSE_ROWS.__code__ is _PARSE_ROWS_CODE and _PARSE_ROW.__code__ is _PARSE_ROW_CODE
            and row_class.__init__ is _ROW_INIT and _ROW_INIT.__code__ is _ROW_BASE_CODES[0]
            and row_class.setup_lazy_load is _ROW_SETUP and _ROW_SETUP.__code__ is _ROW_BASE_CODES[1]
            and row_class.set_data is _ROW_SET_DATA and _ROW_SET_DATA.__code__ is _ROW_BASE_CODES[2]
            and row_class._compute_format.__code__ is _ROW_CODES[name]
            and row_class.__new__ is object.__new__
            and getattr(row_class, "__bool__", None) is None and getattr(row_class, "__len__", None) is None
            and row_class.__eq__ is object.__eq__ and row_class.__ne__ is object.__ne__)


def preflight_lazy_table(data: bytes, metadata: Any, name: str, table: Any, source: Any, heap_binding: Any = None) -> str | None:
    """全row budgetの事前成立後に、同一parserの固定実装とsource bytesを検証する。"""
    failure = dependency_failure()
    if failure:
        return failure
    try:
        expected = _TABLE_CLASSES.get(name)
        if (expected is None or type(metadata) is not _METADATA_CLASS or type(table) is not expected
                or not is_exact_lazy_list(source) or table.rows is not source
                or getattr(metadata, name, None) is not table or type(table.name) is not str or table.name != name
                or type(table.number) is not int or table.number != expected.number or table._row_class is not _ROW_CLASSES[name]):
            return "dnfile_lazy_table_provenance_invalid"
        registry, tables = metadata.tables, metadata.tables_list
        if (type(registry) is not dict or not 0 < len(registry) <= MAX_PARSER_TABLES
                or any(type(key) is not int or not 0 <= key < MAX_PARSER_TABLES for key in registry)
                or registry.get(expected.number) is not table or type(tables) is not list
                or not 0 < len(tables) <= MAX_PARSER_TABLES
                or sum(candidate is table for candidate in tables) != 1):
            return "dnfile_lazy_table_provenance_invalid"
        if (not _trusted_functions_intact(name)
                or not _bound_method(source.eval_func, table, _PARSE_ROWS)
                or not _bound_method(table._lazy_parse_row, table, _PARSE_ROW)
                or not _bound_method(table._lazy_parse_rows, table, _PARSE_ROWS)):
            return "dnfile_lazy_callback_unreviewed"
        loader = table._full_loader
        if (type(loader) is not FunctionType or loader.__code__ is not _FULL_LOADER_CODE
                or loader.__globals__ is not stream.__dict__ or loader.__closure__ is None
                or len(loader.__closure__) != 1 or loader.__closure__[0].cell_contents is not metadata):
            return "dnfile_lazy_full_loader_unreviewed"
        if type(table._loaded) is not base.LoadState or table._loaded not in (base.LoadState.LazyLoaded, base.LoadState.Loaded):
            return "dnfile_lazy_state_invalid"
        counts = table._tables_rowcounts
        if (type(counts) is not list or len(counts) != MAX_PARSER_TABLES
                or any(value is not None and (type(value) is not int or not 0 <= value < 1 << 32) for value in counts)
                or counts[expected.number] != table.num_rows
                or any(type(value) is not int or value not in (2, 4) for value in
                       (table._strings_offset_size, table._guid_offset_size, table._blob_offset_size))):
            return "dnfile_lazy_state_invalid"
        row_size, raw, offset = table.row_size, table._table_data, table.file_offset
        if (type(row_size) is not int or not 0 < row_size <= MAX_ROW_BYTES or type(raw) is not bytes
                or len(raw) != row_size * table.num_rows or type(offset) is not int or offset < 0
                or offset + len(raw) > len(data) or data[offset:offset + len(raw)] != raw):
            return "dnfile_lazy_table_data_invalid"
        if (type(heap_binding) is not _HeapBinding or heap_binding.data is not data or heap_binding.metadata is not metadata
                or table._strings_heap is not heap_binding.heap):
            return "dnfile_lazy_state_invalid"
        if (not _valid_layout(heap_binding.table_layout) or heap_binding.table_layout[expected.number] !=
                (table.file_offset, table.row_size, table.num_rows)
                or heap_binding.heap_widths != (table._strings_offset_size, table._guid_offset_size, table._blob_offset_size)):
            return "dnfile_table_canonical_position_mismatch"
        if (type(heap_binding.row_counts) is not tuple or len(heap_binding.row_counts) != MAX_PARSER_TABLES
                or any(type(value) is not int or not 0 <= value < 1 << 32 for value in heap_binding.row_counts)
                or tuple(0 if value is None else value for value in counts) != heap_binding.row_counts):
            return "dnfile_lazy_state_invalid"
    except Exception:
        return "dnfile_lazy_table_provenance_invalid"
    return None


def materialize_lazy_row(data: bytes, metadata: Any, name: str, table: Any, source: Any,
                         index: int, expected_count: int) -> tuple[Any | None, str | None]:
    """検証済み固定callbackで一行だけstatic struct化し、full-loaderは実行しない。"""
    try:
        if (table.rows is not source or container_count(source) != expected_count
                or table.num_rows != expected_count):
            return None, "dnfile_lazy_source_changed"
        # cached cellも固定row classかNoneだけ。任意__bool__/__eq__をcallbackへ渡さない。
        cached = list.__getitem__(source, index)
        expected_row = _ROW_CLASSES[name]
        if cached is not None:
            if type(cached) is not expected_row:
                return None, "dnfile_lazy_row_invalid"
            state = object.__getattribute__(cached, "_loaded")
            if type(state) is not base.LoadState or state not in (base.LoadState.Unloaded, base.LoadState.LazyLoaded, base.LoadState.Loaded):
                return None, "dnfile_lazy_row_invalid"
        if (not _trusted_functions_intact(name) or not _bound_method(source.eval_func, table, _PARSE_ROWS)
                or not _bound_method(table._lazy_parse_row, table, _PARSE_ROW)):
            return None, "dnfile_lazy_callback_unreviewed"
        row = source[index]
        if (table.rows is not source or container_count(source) != expected_count
                or table.num_rows != expected_count or not _bound_method(source.eval_func, table, _PARSE_ROWS)):
            return None, "dnfile_lazy_source_changed"
        if (type(row) is not expected_row or type(object.__getattribute__(row, "struct")) is not _STRUCT_CLASSES[name]
                or type(object.__getattribute__(row, "_data")) is not bytes
                or object.__getattribute__(row, "_data") != table._table_data[index * table.row_size:(index + 1) * table.row_size]
                or object.__getattribute__(row, "_tables_rowcnt") is not table._tables_rowcounts
                or object.__getattribute__(row, "_strings") is not table._strings_heap
                or object.__getattribute__(row, "_guids") is not table._guid_heap
                or object.__getattribute__(row, "_blobs") is not table._blob_heap
                or object.__getattribute__(row, "_full_loader") is not table._full_loader):
            return None, "dnfile_lazy_row_invalid"
        return row, None
    except Exception:
        return None, "dnfile_lazy_materialization_failed"


def project_manifest_row(row: Any, table: Any, metadata: Any, heap_binding: Any = None) -> tuple[Any | None, str | None]:
    """raw MR structとbounded UTF-8 heapだけを読む。row.Implementation属性は取得しない。"""
    try:
        if dnfile is None or type(row) is not _ROW_CLASSES["ManifestResource"] or type(table) is not _TABLE_CLASSES["ManifestResource"]:
            return None, "dnfile_resource_view_invalid"
        raw = object.__getattribute__(row, "struct")
        if type(raw) is not _STRUCT_CLASSES["ManifestResource"]:
            return None, "dnfile_resource_view_invalid"
        row_data = object.__getattribute__(row, "_data")
        name_width = table._strings_offset_size
        if type(row_data) is not bytes or type(name_width) is not int or name_width not in (2, 4):
            return None, "dnfile_resource_view_invalid"
        coded_width = len(row_data) - 8 - name_width
        if coded_width not in (2, 4):
            return None, "dnfile_resource_view_invalid"
        offset = int.from_bytes(row_data[:4], "little")
        string_index = int.from_bytes(row_data[8:8 + name_width], "little")
        coded = int.from_bytes(row_data[8 + name_width:], "little")
        values = (raw.Offset, raw.Name_StringIndex, raw.Implementation_CodedIndex)
        if any(type(value) is not int for value in values) or values != (offset, string_index, coded):
            return None, "dnfile_resource_view_invalid"
        heap = table._strings_heap
        if (type(heap_binding) is not _HeapBinding or heap_binding.metadata is not metadata or heap_binding.heap is not heap
                or heap_binding.raw is not object.__getattribute__(heap, "__data__")):
            return None, "dnfile_resource_view_invalid"
        heap_data = heap_binding.raw
        if type(heap_data) is not bytes or string_index >= len(heap_data):
            return None, "dnfile_resource_view_invalid"
        end = heap_data.find(b"\x00", string_index, min(len(heap_data), string_index + MAX_STRING_UTF8_BYTES + 1))
        if end < 0:
            return None, "dnfile_resource_view_invalid"
        name = heap_data[string_index:end].decode("utf-8")
        implementation = None
        if coded:
            scope = {0: "File", 1: "AssemblyRef", 2: "ExportedType"}.get(coded & 3)
            if scope is None:
                return None, "dnfile_resource_view_invalid"
            implementation = SimpleNamespace(table=getattr(metadata, scope, None), row_index=coded >> 2)
        return SimpleNamespace(Name=name, Offset=offset, Implementation=implementation), None
    except Exception:
        return None, "dnfile_resource_view_invalid"
