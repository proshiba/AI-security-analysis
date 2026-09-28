"""CLR resource宣言の有界な静的descriptor。本文・名前は公開coverageへ含めない。"""

from __future__ import annotations

from typing import Any

try:
    from . import dnfile_resource_adapter as _dnfile_adapter
except ImportError:
    import dnfile_resource_adapter as _dnfile_adapter

MAX_INPUT_BYTES = 512 << 20
MAX_RESOURCE_ROWS = 4096
MAX_TABLE_ROWS = 20_000
MAX_TOTAL_ROWS = 80_000
MAX_RESOURCE_BYTES = 64 << 20
MAX_SECTIONS = 96
MAX_NAME_CHARACTERS = 512
UINT32_END = 1 << 32
TABLE_NAMES = (
    "TypeRef", "TypeDef", "Field", "MethodDef", "MemberRef", "StandAloneSig",
    "ModuleRef", "TypeSpec", "MethodSpec", "AssemblyRef", "File", "ExportedType",
    "ManifestResource",
)
REASONS = frozenset({
    "input_type_invalid", "input_byte_budget_exceeded", "not_managed_pe",
    "metadata_access_failed", "metadata_declared_count_missing",
    "metadata_declared_count_invalid", "metadata_rows_container_unsupported",
    "metadata_row_count_mismatch", "metadata_table_row_budget_exceeded",
    "metadata_total_row_budget_exceeded", "metadata_snapshot_failed",
    "resource_count_budget_exceeded", "shared_snapshot_origin_mismatch",
    "shared_snapshot_limits_mismatch", "shared_snapshot_source_changed",
    "directory_fields_invalid", "directory_pair_inconsistent",
    "directory_rva_overflow", "manifest_table_absent_with_directory",
    "embedded_resource_without_directory", "section_count_invalid",
    "section_count_mismatch", "section_rows_unsupported", "section_fields_invalid",
    "section_file_bounds_invalid", "section_rva_overflow",
    "directory_not_uniquely_file_backed", "directory_file_alias",
    "resource_row_access_failed", "resource_name_invalid",
    "resource_name_ambiguity", "resource_offset_invalid",
    "resource_header_outside_directory", "resource_body_outside_directory",
    "resource_byte_budget_exceeded", "resource_total_byte_budget_exceeded",
    "resource_not_uniquely_file_backed", "resource_file_alias",
    "resource_span_mapping_inconsistent", "resource_range_overlap",
    "resource_range_alias", "linked_reference_invalid", "linked_reference_unsupported",
    "linked_reference_foreign_table", "linked_reference_rid_invalid",
    "complete_inventory_required_for_descriptors",
    "all_descriptors_discarded_incomplete_inventory",
}) | _dnfile_adapter.REASONS


def _is_uint32(value: Any) -> bool:
    return type(value) is int and 0 <= value < UINT32_END


def _limit(value: int, maximum: int) -> int:
    if type(value) is not int or not 0 < value <= maximum:
        raise ValueError("上限は非boolの正整数で、固定hard上限以下にしてください")
    return value


def _reason(counts: dict[str, int], reason: str) -> None:
    if reason not in REASONS:
        raise ValueError("未知の診断reasonです")
    counts[reason] = counts.get(reason, 0) + 1


class _RowSnapshot:
    """同一入力・PE・予算に結び付く内部row参照snapshot。row属性の不変性は保証しない。"""

    __slots__ = ("data", "pe", "limits", "rows", "tables", "sources", "states", "reasons", "reserved", "visited", "lazy_tables", "lazy_visited", "heap_binding", "heap_bytes_compared", "input_binding_verified")

    def __init__(self, data: bytes, pe: Any, limits: tuple[int, ...]) -> None:
        self.data, self.pe, self.limits = data, pe, limits
        self.rows: dict[str, tuple[Any, ...]] = {}
        self.tables: dict[str, Any] = {}
        self.sources: dict[str, Any] = {}
        self.states: dict[str, dict[str, Any]] = {}
        self.reasons: dict[str, int] = {}
        self.reserved = self.visited = 0
        self.lazy_tables = frozenset()
        self.lazy_visited = 0
        self.heap_binding = None
        self.heap_bytes_compared = 0
        self.input_binding_verified = False

    def __repr__(self) -> str:
        return "_RowSnapshot(private_snapshot_omitted=True)"

    def __getstate__(self) -> dict[str, Any]:
        return {"private_snapshot_omitted": True,
                "reservation_demand_capped": self.reserved if type(self.reserved) is int and 0 <= self.reserved <= MAX_TOTAL_ROWS + 1 else None,
                "complete": not self.reasons}


class _ResourceDescriptor:
    """consumer専用のdescriptor。repr／state projectionは名前やoffsetを返さない。"""

    __slots__ = ("row_index", "kind", "name", "body_offset", "body_size", "linked_scope")

    def __init__(self, row_index: int, kind: str, name: str, body_offset: int | None,
                 body_size: int | None, linked_scope: str | None = None) -> None:
        self.row_index, self.kind, self.name = row_index, kind, name
        self.body_offset, self.body_size, self.linked_scope = body_offset, body_size, linked_scope

    def __repr__(self) -> str:
        return "_ResourceDescriptor(private_identity_omitted=True)"

    def __getstate__(self) -> dict[str, Any]:
        return {"kind": self.kind if self.kind in {"embedded", "linked"} else None,
                "private_identity_omitted": True}


class _ResourceScan:
    """公開coverageと非公開descriptorを分離する結果。公開投影は独立したcopy。"""

    __slots__ = ("_descriptors", "_coverage", "_row_snapshot")

    def __init__(self, descriptors: tuple[_ResourceDescriptor, ...], coverage: dict[str, Any], snapshot: _RowSnapshot) -> None:
        self._descriptors, self._coverage, self._row_snapshot = descriptors, coverage, snapshot

    def coverage(self) -> dict[str, Any]:
        result = dict(self._coverage)
        for name in ("counts", "reason_counts", "budgets", "work"):
            result[name] = dict(self._coverage[name])
        result["tables"] = {name: dict(state) for name, state in self._coverage["tables"].items()}
        return result

    def __repr__(self) -> str:
        return f"_ResourceScan(status={self._coverage['status']!r}, descriptor_count={len(self._descriptors)})"

    def __getstate__(self) -> dict[str, Any]:
        return self.coverage()


def _snapshot_rows(data: bytes, pe: Any, *, max_table_rows: int = MAX_TABLE_ROWS,
                   max_total_rows: int = MAX_TOTAL_ROWS, max_resources: int = MAX_RESOURCE_ROWS,
                   max_string_heap_bytes: int = _dnfile_adapter.MAX_STRING_HEAP_BYTES) -> _RowSnapshot:
    """固定13tableを一度ずつ予約し、総80k以内でrow参照をsnapshot化する。"""
    limits = (_limit(max_table_rows, MAX_TABLE_ROWS), _limit(max_total_rows, MAX_TOTAL_ROWS),
              _limit(max_resources, MAX_RESOURCE_ROWS), _limit(max_string_heap_bytes, _dnfile_adapter.MAX_STRING_HEAP_BYTES))
    snapshot = _RowSnapshot(data, pe, limits)
    lazy_tables: set[str] = set()
    try:
        metadata = getattr(getattr(pe, "net", None), "mdtables", None)
        if metadata is None:
            _reason(snapshot.reasons, "not_managed_pe")
            return snapshot
        for name in TABLE_NAMES:
            table = getattr(metadata, name, None)
            snapshot.tables[name] = table
            state = {"present": table is not None, "declared_status": "absent",
                     "declared": None, "container_rows": 0, "row_count_mismatch": False}
            snapshot.states[name] = state
            if table is None:
                snapshot.sources[name], snapshot.rows[name] = None, ()
                continue
            declared = getattr(table, "num_rows", None)
            source = getattr(table, "rows", None)
            snapshot.sources[name] = source
            if declared is None:
                state["declared_status"] = "missing"
                _reason(snapshot.reasons, "metadata_declared_count_missing")
            elif type(declared) is not int or declared < 0:
                state["declared_status"] = "invalid"
                _reason(snapshot.reasons, "metadata_declared_count_invalid")
            else:
                state["declared_status"] = "valid"
                state["declared"] = min(declared, max_table_rows + 1)
                if declared > max_table_rows:
                    _reason(snapshot.reasons, "metadata_table_row_budget_exceeded")
            count = _dnfile_adapter.container_count(source)
            if count is None:
                _reason(snapshot.reasons, "metadata_rows_container_unsupported")
                continue
            if _dnfile_adapter.is_exact_lazy_list(source):
                lazy_tables.add(name)
            state["container_rows"] = min(count, max_table_rows + 1)
            if type(declared) is int and declared >= 0 and count != declared:
                state["row_count_mismatch"] = True
                _reason(snapshot.reasons, "metadata_row_count_mismatch")
            if count > max_table_rows:
                _reason(snapshot.reasons, "metadata_table_row_budget_exceeded")
            if name == "ManifestResource" and count > max_resources:
                _reason(snapshot.reasons, "resource_count_budget_exceeded")
            # AssemblyRefをlinked検証で使っても再加算しない。予約とCPU訪問数は別。
            snapshot.reserved = min(max_total_rows + 1, snapshot.reserved + count)
        if snapshot.reserved > max_total_rows:
            _reason(snapshot.reasons, "metadata_total_row_budget_exceeded")
        snapshot.lazy_tables = frozenset(lazy_tables)
        if not snapshot.reasons:
            if _dnfile_adapter.is_dnfile_metadata_candidate(metadata):
                failure = _dnfile_adapter.verify_input_binding(data, pe)
                if failure:
                    _reason(snapshot.reasons, failure)
                else:
                    snapshot.input_binding_verified = True
                if any(snapshot.states[name]["container_rows"] and name not in lazy_tables for name in TABLE_NAMES):
                    _reason(snapshot.reasons, "dnfile_eager_rows_unsupported")
        if not snapshot.reasons:
            if lazy_tables or _dnfile_adapter.is_dnfile_metadata_candidate(metadata):
                snapshot.heap_binding, failure, snapshot.heap_bytes_compared = _dnfile_adapter.bind_strings_heap(data, pe, metadata, max_heap_bytes=limits[3])
                if failure:
                    _reason(snapshot.reasons, failure)
        if not snapshot.reasons:
            # 全13tableの予約を完了してから、固定parser callbackの由来を調べる。
            for name in lazy_tables:
                failure = _dnfile_adapter.preflight_lazy_table(data, metadata, name, snapshot.tables[name], snapshot.sources[name], snapshot.heap_binding)
                if failure:
                    _reason(snapshot.reasons, failure)
        if not snapshot.reasons:
            for name in TABLE_NAMES:
                source = snapshot.sources[name]
                retained = []
                for index in range(snapshot.states[name]["container_rows"]):
                    snapshot.visited += 1
                    if name in lazy_tables:
                        snapshot.lazy_visited += 1
                        row, failure = _dnfile_adapter.materialize_lazy_row(
                            data, metadata, name, snapshot.tables[name], source, index,
                            snapshot.states[name]["container_rows"])
                        if failure:
                            _reason(snapshot.reasons, failure)
                            break
                    else:
                        row = source[index]
                    retained.append(row)
                rows = tuple(retained)
                if len(rows) != snapshot.states[name]["container_rows"]:
                    _reason(snapshot.reasons, "metadata_row_count_mismatch")
                snapshot.rows[name] = rows
                if snapshot.reasons:
                    break
    except Exception:
        _reason(snapshot.reasons, "metadata_snapshot_failed")
    if snapshot.reasons:
        snapshot.rows = {name: () for name in TABLE_NAMES}
    return snapshot


def _validated_sections(data: bytes, pe: Any, maximum: int, reasons: dict[str, int]) -> tuple[tuple[int, int, int], ...]:
    try:
        source = pe.sections
        declared = pe.FILE_HEADER.NumberOfSections
        if type(declared) is not int or not 1 <= declared <= maximum:
            _reason(reasons, "section_count_invalid")
            return ()
        if type(source) not in (list, tuple):
            _reason(reasons, "section_rows_unsupported")
            return ()
        if len(source) != declared:
            _reason(reasons, "section_count_mismatch")
            return ()
        sections = []
        for section in source:
            rva, size, offset = section.VirtualAddress, section.SizeOfRawData, section.PointerToRawData
            if not all(_is_uint32(value) for value in (rva, size, offset)):
                _reason(reasons, "section_fields_invalid")
            elif offset + size > len(data):
                _reason(reasons, "section_file_bounds_invalid")
            elif rva + size > UINT32_END:
                _reason(reasons, "section_rva_overflow")
            else:
                sections.append((rva, size, offset))
        return tuple(sections) if not reasons else ()
    except Exception:
        _reason(reasons, "section_fields_invalid")
        return ()


def _raw_span(sections: tuple[tuple[int, int, int], ...], rva: int, size: int) -> tuple[int, int] | None:
    matches = []
    for index, (base, raw_size, raw_offset) in enumerate(sections):
        delta = rva - base
        if 0 <= delta and delta + size <= raw_size and (size > 0 or delta < raw_size):
            matches.append((index, raw_offset + delta))
    if len(matches) != 1:
        return None
    selected = matches[0][0]
    # 部分交差する別sectionもRVAの曖昧さを生む。全包含候補数だけでは不十分。
    if any(index != selected and max(rva, base) < min(rva + size, base + raw_size)
           for index, (base, raw_size, _) in enumerate(sections)):
        return None
    return matches[0]


def _file_alias(sections: tuple[tuple[int, int, int], ...], selected: int, offset: int, size: int) -> bool:
    return any(index != selected and max(offset, raw_offset) < min(offset + size, raw_offset + raw_size)
               for index, (_, raw_size, raw_offset) in enumerate(sections))


def _private_name(row: Any) -> str | None:
    value = getattr(row, "Name", None)
    value = value if type(value) is str else getattr(value, "value", None)
    if (type(value) is not str or not 1 <= len(value) <= MAX_NAME_CHARACTERS
            or any(ord(character) < 32 or ord(character) == 127 for character in value)):
        return None
    return value


def _linked_scope(reference: Any, snapshot: _RowSnapshot, reasons: dict[str, int]) -> str | None:
    table = getattr(reference, "table", None)
    scope = next((name for name in ("File", "AssemblyRef", "ExportedType")
                  if table is not None and table is snapshot.tables.get(name)), None)
    if scope is None:
        _reason(reasons, "linked_reference_foreign_table")
        return None
    rid = getattr(reference, "row_index", None)
    if type(rid) is not int or not 1 <= rid <= len(snapshot.rows[scope]):
        _reason(reasons, "linked_reference_rid_invalid")
        return None
    if scope == "ExportedType":
        _reason(reasons, "linked_reference_unsupported")
        return None
    return scope


def _public_table_states(snapshot: _RowSnapshot, reasons: dict[str, int]) -> dict[str, dict[str, Any]]:
    result = {}
    for name in TABLE_NAMES:
        state = snapshot.states.get(name, {})
        clean = {"present": None, "declared_status": "unavailable", "declared": None,
                 "container_rows": 0, "row_count_mismatch": False}
        if type(state) is not dict:
            _reason(reasons, "shared_snapshot_source_changed")
        else:
            for key in ("present", "row_count_mismatch"):
                if type(state.get(key)) is bool:
                    clean[key] = state[key]
                elif key in state:
                    _reason(reasons, "shared_snapshot_source_changed")
            status = state.get("declared_status", "unavailable")
            if type(status) is str and status in {"absent", "valid", "missing", "invalid", "unavailable"}:
                clean["declared_status"] = status
            else:
                _reason(reasons, "shared_snapshot_source_changed")
            for key in ("declared", "container_rows"):
                value = state.get(key, clean[key])
                if key == "declared" and value is None:
                    continue
                if type(value) is int and 0 <= value <= MAX_TABLE_ROWS + 1:
                    clean[key] = value
                else:
                    _reason(reasons, "shared_snapshot_source_changed")
        result[name] = clean
    return result


def _shared_snapshot_budget_valid(snapshot: _RowSnapshot, limits: tuple[int, ...]) -> bool:
    if any(type(value) is not dict or len(value) != len(TABLE_NAMES)
           or any(type(key) is not str or key not in TABLE_NAMES for key in value) for value in
           (snapshot.rows, snapshot.tables, snapshot.sources, snapshot.states)):
        return False
    if (type(snapshot.reasons) is not dict or len(snapshot.reasons) > len(REASONS)
            or any(type(reason) is not str or reason not in REASONS or type(count) is not int
                   or not 0 < count <= MAX_TOTAL_ROWS for reason, count in snapshot.reasons.items())):
        return False
    if (type(snapshot.reserved) is not int or not 0 <= snapshot.reserved <= limits[1]
            or type(snapshot.visited) is not int or not 0 <= snapshot.visited <= limits[1]
            or type(snapshot.lazy_visited) is not int or not 0 <= snapshot.lazy_visited <= snapshot.visited
            or type(snapshot.lazy_tables) is not frozenset or len(snapshot.lazy_tables) > len(TABLE_NAMES)
            or any(type(name) is not str or name not in TABLE_NAMES for name in snapshot.lazy_tables)
            or type(snapshot.heap_bytes_compared) is not int or not 0 <= snapshot.heap_bytes_compared <= limits[3]
            or (snapshot.heap_binding is not None and not _dnfile_adapter.is_heap_binding(snapshot.heap_binding))
            or (snapshot.lazy_tables and snapshot.heap_binding is None)
            or type(snapshot.input_binding_verified) is not bool):
        return False
    total = 0
    for name in TABLE_NAMES:
        rows, source, state = snapshot.rows[name], snapshot.sources[name], snapshot.states[name]
        state_keys = ("present", "declared_status", "declared", "container_rows", "row_count_mismatch")
        if (type(rows) is not tuple or len(rows) > limits[0] or type(state) is not dict
                or len(state) != len(state_keys) or any(type(key) is not str or key not in state_keys for key in state)):
            return False
        if name == "ManifestResource" and len(rows) > limits[2]:
            return False
        if source is not None and _dnfile_adapter.container_count(source) is None:
            return False
        if (name in snapshot.lazy_tables) != _dnfile_adapter.is_exact_lazy_list(source):
            return False
        total += len(rows)
        if total > limits[1]:
            return False
        if (type(state.get("declared_status")) is not str or state["declared_status"] not in {"valid", "absent", "missing", "invalid", "unavailable"}
                or (state.get("declared") is not None and type(state["declared"]) is not int)
                or type(state.get("container_rows")) is not int):
            return False
        if not snapshot.reasons and (state.get("present") is not (snapshot.tables[name] is not None)
                or state.get("declared_status") != ("valid" if source is not None else "absent")
                or state.get("declared") != (len(rows) if source is not None else None)
                or state.get("container_rows") != len(rows) or state.get("row_count_mismatch") is not False):
            return False
    return bool(snapshot.reasons) or total == snapshot.reserved == snapshot.visited


def _check_shared_snapshot(snapshot: Any, data: bytes, pe: Any, limits: tuple[int, ...]) -> tuple[str | None, int, int, int]:
    visits = lazy_visits = heap_bytes = 0
    try:
        if type(snapshot) is not _RowSnapshot or snapshot.data is not data or snapshot.pe is not pe:
            return "shared_snapshot_origin_mismatch", visits, lazy_visits, heap_bytes
        if (type(snapshot.limits) is not tuple or len(snapshot.limits) != 4
                or any(type(value) is not int for value in snapshot.limits) or snapshot.limits != limits):
            return "shared_snapshot_limits_mismatch", visits, lazy_visits, heap_bytes
        if not _shared_snapshot_budget_valid(snapshot, limits):
            return "shared_snapshot_source_changed", visits, lazy_visits, heap_bytes
        metadata = pe.net.mdtables
        if _dnfile_adapter.is_dnfile_metadata_candidate(metadata) is not snapshot.input_binding_verified:
            return "shared_snapshot_source_changed", visits, lazy_visits, heap_bytes
        if snapshot.input_binding_verified:
            failure = _dnfile_adapter.verify_input_binding(data, pe)
            if failure:
                return failure, visits, lazy_visits, heap_bytes
        if snapshot.heap_binding is not None:
            _binding, failure, heap_bytes = _dnfile_adapter.bind_strings_heap(data, pe, metadata, snapshot.heap_binding, max_heap_bytes=limits[3])
            if failure:
                return failure, visits, lazy_visits, heap_bytes
        # 全containerの形状を先に検証し、未対応containerへのindexingを開始しない。
        for name in TABLE_NAMES:
            table = getattr(metadata, name, None)
            if table is not snapshot.tables[name]:
                return "shared_snapshot_source_changed", visits, lazy_visits, heap_bytes
            if table is not None and (_dnfile_adapter.container_count(getattr(table, "rows", None)) is None
                    or table.rows is not snapshot.sources[name]
                    or type(getattr(table, "num_rows", None)) is not int
                    or table.num_rows != len(snapshot.rows[name])
                    or _dnfile_adapter.container_count(table.rows) != len(snapshot.rows[name])):
                return "shared_snapshot_source_changed", visits, lazy_visits, heap_bytes
            if name in snapshot.lazy_tables:
                failure = _dnfile_adapter.preflight_lazy_table(data, metadata, name, table, table.rows, snapshot.heap_binding)
                if failure:
                    return failure, visits, lazy_visits, heap_bytes
        for name in TABLE_NAMES:
            source = snapshot.sources[name]
            for index, row in enumerate(snapshot.rows[name]):
                visits += 1
                if name in snapshot.lazy_tables:
                    lazy_visits += 1
                    actual, failure = _dnfile_adapter.materialize_lazy_row(
                        data, metadata, name, snapshot.tables[name], source, index,
                        len(snapshot.rows[name]))
                    if failure:
                        return failure, visits, lazy_visits, heap_bytes
                else:
                    actual = source[index]
                if actual is not row:
                    return "shared_snapshot_source_changed", visits, lazy_visits, heap_bytes
    except Exception:
        return "shared_snapshot_source_changed", visits, lazy_visits, heap_bytes
    return None, visits, lazy_visits, heap_bytes


def describe_clr_resources(data: bytes, pe: Any, *, max_resources: int = MAX_RESOURCE_ROWS,
                           max_resource_bytes: int = MAX_RESOURCE_BYTES,
                           max_total_bytes: int = MAX_RESOURCE_BYTES,
                           max_table_rows: int = MAX_TABLE_ROWS,
                           max_total_rows: int = MAX_TOTAL_ROWS,
                           max_sections: int = MAX_SECTIONS,
                           max_string_heap_bytes: int = _dnfile_adapter.MAX_STRING_HEAP_BYTES,
                           row_snapshot: _RowSnapshot | None = None) -> _ResourceScan:
    """静的resource inventoryだけを検証し、partialならdescriptor全体を破棄する。

    row_snapshotは同一data/PEの内部共有入口。公開coverageから逆構成して使わない。
    linked resource本文は取得せず、framework/runtime真正性も一切検証しない。
    """
    max_resources, max_resource_bytes = _limit(max_resources, MAX_RESOURCE_ROWS), _limit(max_resource_bytes, MAX_RESOURCE_BYTES)
    max_total_bytes, max_sections = _limit(max_total_bytes, MAX_RESOURCE_BYTES), _limit(max_sections, MAX_SECTIONS)
    limits = (_limit(max_table_rows, MAX_TABLE_ROWS), _limit(max_total_rows, MAX_TOTAL_ROWS), max_resources,
              _limit(max_string_heap_bytes, _dnfile_adapter.MAX_STRING_HEAP_BYTES))
    reasons: dict[str, int] = {}
    counts = {"declared_resources": 0, "rows_evaluated": 0, "embedded_resources": 0,
              "linked_resources": 0, "invalid_resources": 0, "validated_resource_bytes": 0,
              "rows_skipped": 0, "descriptors_retained": 0, "descriptors_discarded": 0}
    if type(data) is not bytes:
        _reason(reasons, "input_type_invalid")
    elif len(data) > MAX_INPUT_BYTES:
        _reason(reasons, "input_byte_budget_exceeded")
    reused = row_snapshot is not None
    accepted_shared_snapshot = False
    reuse_identity_visits = 0
    reuse_lazy_identity_visits = reuse_heap_bytes = 0
    snapshot = _RowSnapshot(data, pe, limits)
    if reused and not reasons:
        failure, reuse_identity_visits, reuse_lazy_identity_visits, reuse_heap_bytes = _check_shared_snapshot(row_snapshot, data, pe, limits)
        if failure:
            # 不正なmutable snapshotの.get/.itemsを後段で使わず、固定safe状態へ切替える。
            _reason(reasons, failure)
        else:
            snapshot = row_snapshot
            accepted_shared_snapshot = True
    elif not reasons:
        snapshot = _snapshot_rows(data, pe, max_table_rows=max_table_rows,
                                  max_total_rows=max_total_rows, max_resources=max_resources, max_string_heap_bytes=limits[3])
    for reason, count in snapshot.reasons.items():
        if reason not in REASONS or type(count) is not int or not 0 < count <= MAX_TOTAL_ROWS:
            _reason(reasons, "shared_snapshot_source_changed")
        else:
            reasons[reason] = reasons.get(reason, 0) + count
    descriptors: list[_ResourceDescriptor] = []
    resource_visits = linked_visits = 0
    sections: tuple[tuple[int, int, int], ...] = ()
    directory_rva = directory_size = 0
    if not reasons:
        try:
            directory_rva, directory_size = pe.net.struct.ResourcesRva, pe.net.struct.ResourcesSize
            if not _is_uint32(directory_rva) or not _is_uint32(directory_size):
                _reason(reasons, "directory_fields_invalid")
            elif bool(directory_rva) != bool(directory_size):
                _reason(reasons, "directory_pair_inconsistent")
            elif directory_rva + directory_size > UINT32_END:
                _reason(reasons, "directory_rva_overflow")
            elif directory_size:
                sections = _validated_sections(data, pe, max_sections, reasons)
                mapping = _raw_span(sections, directory_rva, directory_size)
                if mapping is None:
                    _reason(reasons, "directory_not_uniquely_file_backed")
                elif _file_alias(sections, mapping[0], mapping[1], directory_size):
                    _reason(reasons, "directory_file_alias")
            if snapshot.tables.get("ManifestResource") is None and directory_size:
                _reason(reasons, "manifest_table_absent_with_directory")
        except Exception:
            _reason(reasons, "directory_fields_invalid")
    intervals: list[tuple[int, int]] = []
    names: set[str] = set()
    rows = snapshot.rows.get("ManifestResource", ())
    if not reasons:
        for index, row in enumerate(rows, 1):
            resource_visits += 1
            counts["rows_evaluated"] += 1
            previous_reasons = sum(reasons.values())
            try:
                if "ManifestResource" in snapshot.lazy_tables:
                    row, failure = _dnfile_adapter.project_manifest_row(row, snapshot.tables["ManifestResource"], pe.net.mdtables, snapshot.heap_binding)
                    if failure:
                        _reason(reasons, failure)
                        counts["invalid_resources"] += 1
                        continue
                name = _private_name(row)
                if name is None:
                    _reason(reasons, "resource_name_invalid")
                elif name in names:
                    _reason(reasons, "resource_name_ambiguity")
                else:
                    names.add(name)
                offset = row.Offset
                if not _is_uint32(offset):
                    _reason(reasons, "resource_offset_invalid")
                implementation = getattr(row, "Implementation")
                if implementation is not None:
                    linked_visits += 1
                    scope = _linked_scope(implementation, snapshot, reasons)
                    if scope:
                        counts["linked_resources"] += 1
                        descriptors.append(_ResourceDescriptor(index, "linked", name or "", None, None, scope))
                else:
                    counts["embedded_resources"] += 1
                    if not _is_uint32(offset):
                        pass
                    elif not directory_size:
                        _reason(reasons, "embedded_resource_without_directory")
                    elif offset + 4 > directory_size:
                        _reason(reasons, "resource_header_outside_directory")
                    else:
                        header = _raw_span(sections, directory_rva + offset, 4)
                        if header is None:
                            _reason(reasons, "resource_not_uniquely_file_backed")
                        else:
                            length = int.from_bytes(data[header[1]:header[1] + 4], "little")
                            if offset + 4 + length > directory_size:
                                _reason(reasons, "resource_body_outside_directory")
                            elif length > max_resource_bytes:
                                _reason(reasons, "resource_byte_budget_exceeded")
                            elif counts["validated_resource_bytes"] + length > max_total_bytes:
                                _reason(reasons, "resource_total_byte_budget_exceeded")
                            else:
                                whole = _raw_span(sections, directory_rva + offset, 4 + length)
                                if whole is None:
                                    _reason(reasons, "resource_not_uniquely_file_backed")
                                elif whole != header:
                                    _reason(reasons, "resource_span_mapping_inconsistent")
                                elif _file_alias(sections, whole[0], whole[1], 4 + length):
                                    _reason(reasons, "resource_file_alias")
                                else:
                                    intervals.append((whole[1], whole[1] + 4 + length))
                                    counts["validated_resource_bytes"] += length
                                    descriptors.append(_ResourceDescriptor(index, "embedded", name or "", whole[1] + 4, length))
            except Exception:
                _reason(reasons, "resource_row_access_failed")
            if sum(reasons.values()) != previous_reasons:
                counts["invalid_resources"] += 1
    previous = None
    for interval in sorted(intervals):
        if previous is not None and interval[0] < previous[1]:
            _reason(reasons, "resource_range_alias" if interval == previous else "resource_range_overlap")
        previous = (interval[0], max(interval[1], previous[1])) if previous and interval[0] < previous[1] else interval
    table_states = _public_table_states(snapshot, reasons)
    manifest_state = table_states["ManifestResource"]
    counts["declared_resources"] = manifest_state["declared"] or 0
    counts["rows_skipped"] = max(0, manifest_state["container_rows"] - counts["rows_evaluated"])
    safe_reserved = snapshot.reserved if type(snapshot.reserved) is int and 0 <= snapshot.reserved <= MAX_TOTAL_ROWS + 1 else 0
    safe_visited = snapshot.visited if type(snapshot.visited) is int and 0 <= snapshot.visited <= MAX_TOTAL_ROWS else 0
    if safe_reserved != snapshot.reserved or safe_visited != snapshot.visited:
        _reason(reasons, "shared_snapshot_source_changed")
    if reasons:
        _reason(reasons, "complete_inventory_required_for_descriptors")
    if reasons and descriptors:
        counts["descriptors_discarded"] = len(descriptors)
        descriptors = []
        _reason(reasons, "all_descriptors_discarded_incomplete_inventory")
    counts["descriptors_retained"] = len(descriptors)
    complete = not reasons
    coverage = {
        "schema_version": 1, "scope": "manifest_resource_declarations_not_runtime_contents",
        "status": "complete" if complete else "partial", "inventory_complete": complete,
        "embedded_scan_complete": complete, "external_contents_resolved": False,
        "runtime_resource_resolution_verified": False, "resource_contents_interpreted": False,
        "literal_names_published": False, "resource_bodies_published": False,
        "input_binding_verified": snapshot.input_binding_verified,
        "parser_view_only": not snapshot.input_binding_verified,
        "executed": False, "emulated": False, "clr_loaded": False, "network_contacted": False,
        "counts": counts, "reason_counts": reasons,
        "budgets": {"max_resources": max_resources, "max_resource_bytes": max_resource_bytes,
                    "max_total_bytes": max_total_bytes, "max_table_rows": max_table_rows,
                    "max_total_rows": max_total_rows, "max_sections": max_sections,
                    "max_string_heap_bytes": limits[3]},
        "work": {"unique_rows_reserved": safe_reserved if not snapshot.reasons and not any(
                     reason.startswith("shared_snapshot_") for reason in reasons) else 0,
                 "reservation_demand_capped": safe_reserved,
                 "snapshot_row_visits_this_call": 0 if reused else safe_visited,
                 "dnfile_lazy_snapshot_row_visits_this_call": 0 if reused else snapshot.lazy_visited,
                 "dnfile_lazy_identity_visits_this_call": reuse_lazy_identity_visits,
                 "dnfile_string_heap_bytes_compared_this_call": reuse_heap_bytes if reused else snapshot.heap_bytes_compared,
                 "dnfile_lazy_table_count": len(snapshot.lazy_tables),
                 "shared_snapshot_identity_visits": reuse_identity_visits,
                 "resource_row_visits": resource_visits, "linked_reference_row_visits": linked_visits,
                 "shared_snapshot_requested": reused,
                 "shared_snapshot_reused": accepted_shared_snapshot},
        "tables": table_states,
    }
    return _ResourceScan(tuple(descriptors), coverage, snapshot)
