"""固定13table snapshotを既存resolverの内部stateへ接続する。"""

from __future__ import annotations

from typing import Any

try:
    from . import managed_resources as resources
    from .managed_metadata import MetadataResolver, TABLES, DEFAULT_MAX_ROWS, DEFAULT_MAX_TOTAL_ROWS
except ImportError:
    import managed_resources as resources
    from managed_metadata import MetadataResolver, TABLES, DEFAULT_MAX_ROWS, DEFAULT_MAX_TOTAL_ROWS


def _failure_tables():
    # 不明なsourceをabsent／validated-emptyへ変換しない。
    return {name: {"rows": [], "declared": None, "declared_status": "parse_error",
                   "present": True, "row_count_mismatch": False, "truncated": False,
                   "error": "SharedSnapshotUnavailable", "missing_rows": False}
            for name in TABLES.values()}


def shared_metadata_state(pe: Any, data: bytes, row_snapshot: Any, *,
                          max_rows: int = DEFAULT_MAX_ROWS,
                          max_total_rows: int = DEFAULT_MAX_TOTAL_ROWS):
    """同じ入力と13table予約を再照合し、10tableへrow参照だけを供給する。"""
    resources._limit(max_rows, DEFAULT_MAX_ROWS)
    resources._limit(max_total_rows, DEFAULT_MAX_TOTAL_ROWS)
    work = {"scope": "shared_13table_reservation_not_additional_resolver_reservation",
            "accepted": False, "unique_rows_reserved_this_resolver": 0,
            "group_unique_rows_reserved": 0, "shared_identity_visits": 0,
            "shared_lazy_identity_visits": 0, "string_heap_bytes_compared": 0,
            "resolver_row_reference_visits": 0, "reason": None}
    failure = "shared_snapshot_origin_mismatch"
    if type(row_snapshot) is resources._RowSnapshot and type(data) is bytes:
        limits = row_snapshot.limits
        maxima = (resources.MAX_TABLE_ROWS, resources.MAX_TOTAL_ROWS, resources.MAX_RESOURCE_ROWS,
                  resources._dnfile_adapter.MAX_STRING_HEAP_BYTES)
        if (type(limits) is tuple and len(limits) == 4
                and all(type(value) is int and 0 < value <= maximum for value, maximum in zip(limits, maxima))):
            if limits[:2] != (max_rows, max_total_rows):
                failure = "shared_snapshot_limits_mismatch"
            elif row_snapshot.input_binding_verified is not True:
                failure = "shared_snapshot_origin_mismatch"
            else:
                failure, visits, lazy_visits, heap_bytes = resources._check_shared_snapshot(row_snapshot, data, pe, limits)
                work.update(shared_identity_visits=visits, shared_lazy_identity_visits=lazy_visits,
                            string_heap_bytes_compared=heap_bytes)
            if not failure and row_snapshot.reasons:
                failure = "metadata_snapshot_failed"
            if not failure and row_snapshot.reserved > max_total_rows:
                failure = "metadata_total_row_budget_exceeded"
    if failure:
        work["reason"] = failure if failure in resources.REASONS else "shared_snapshot_source_changed"
        return _failure_tables(), {}, work
    rows_used = 0
    tables, table_objects = {}, {}
    for name in TABLES.values():
        table = row_snapshot.tables[name]
        if table is not None:
            table_objects[id(table)] = name
        source = row_snapshot.rows[name]
        limit = min(max_rows, max_total_rows - rows_used)
        retained = min(len(source), limit)
        rows = []
        for index in range(retained):
            rows.append(source[index])
            work["resolver_row_reference_visits"] += 1
        rows_used += retained
        state = row_snapshot.states[name]
        tables[name] = {"rows": rows, "declared": state["declared"],
                        "declared_status": state["declared_status"], "present": state["present"],
                        "row_count_mismatch": False, "truncated": len(source) > retained,
                        "error": None, "missing_rows": False}
    work.update(accepted=True, group_unique_rows_reserved=row_snapshot.reserved)
    return tables, table_objects, work


_REVIEWED_RESOLVER_CLASS = MetadataResolver


def resolver_from_resource_snapshot(pe, *, data, row_snapshot,
                                   max_rows=DEFAULT_MAX_ROWS, max_total_rows=DEFAULT_MAX_TOTAL_ROWS):
    """原入力証明済みstateだけを固定resolverへ供給する。元constructor/classは変更しない。"""
    if (MetadataResolver is not _REVIEWED_RESOLVER_CLASS or type(MetadataResolver) is not type
            or MetadataResolver.__bases__ != (object,)
            or MetadataResolver.__new__ is not object.__new__
            or MetadataResolver.__setattr__ is not object.__setattr__):
        raise ValueError("shared_resolver_class_identity_invalid")
    tables, table_objects, work = shared_metadata_state(
        pe, data, row_snapshot, max_rows=max_rows, max_total_rows=max_total_rows)
    # 固定class/固定属性だけを直接設定する。任意classやsetterを受け取る入口はない。
    resolver = object.__new__(MetadataResolver)
    resolver.tables = tables
    resolver._table_objects = table_objects
    resolver._cache = {}
    return resolver, work

def _incomplete_scan(scan, reason):
    coverage = scan.coverage()
    coverage.update(status="partial", inventory_complete=False, embedded_scan_complete=False)
    coverage["reason_counts"][reason] = coverage["reason_counts"].get(reason, 0) + 1
    coverage["counts"]["descriptors_discarded"] += len(scan._descriptors)
    coverage["counts"]["descriptors_retained"] = 0
    return resources._ResourceScan((), coverage, scan._row_snapshot)


def _descriptor_projection(descriptors):
    if type(descriptors) is not tuple or len(descriptors) > resources.MAX_RESOURCE_ROWS:
        raise ValueError("resource_consumer_scan_invalid")
    result = []
    for item in descriptors:
        if (type(item) is not resources._ResourceDescriptor or type(item.row_index) is not int
                or not 1 <= item.row_index <= resources.MAX_RESOURCE_ROWS
                or type(item.kind) is not str or item.kind not in {"embedded", "linked"}
                or type(item.name) is not str or not 0 < len(item.name) <= resources.MAX_NAME_CHARACTERS
                or any(value is not None and type(value) is not int for value in (item.body_offset, item.body_size))
                or item.linked_scope is not None and type(item.linked_scope) is not str):
            raise ValueError("resource_consumer_scan_invalid")
        result.append((item.row_index, item.kind, item.name, item.body_offset, item.body_size, item.linked_scope))
    return tuple(result)


def revalidated_resource_scan(data, scan):
    """同じbytes identityを要求し、毎消費時にsource/snapshot/descriptorを再照合する。"""
    if (type(data) is not bytes or type(scan) is not resources._ResourceScan
            or type(scan._row_snapshot) is not resources._RowSnapshot
            or scan._row_snapshot.data is not data
            or type(scan._coverage) is not dict or len(scan._coverage) > 64
            or any(type(key) is not str for key in scan._coverage)
            or type(scan._coverage.get("budgets")) is not dict):
        raise ValueError("resource_consumer_origin_mismatch")
    budgets = scan._coverage["budgets"]
    maxima = {"max_resources": resources.MAX_RESOURCE_ROWS, "max_resource_bytes": resources.MAX_RESOURCE_BYTES,
              "max_total_bytes": resources.MAX_RESOURCE_BYTES, "max_table_rows": resources.MAX_TABLE_ROWS,
              "max_total_rows": resources.MAX_TOTAL_ROWS, "max_sections": resources.MAX_SECTIONS,
              "max_string_heap_bytes": resources._dnfile_adapter.MAX_STRING_HEAP_BYTES}
    if (len(budgets) != len(maxima) or any(type(key) is not str or key not in maxima for key in budgets)
            or any(type(budgets[name]) is not int
            or not 0 < budgets[name] <= maximum for name, maximum in maxima.items())):
        raise ValueError("resource_consumer_budget_invalid")
    original = _descriptor_projection(scan._descriptors)
    fresh = resources.describe_clr_resources(data, scan._row_snapshot.pe,
                                          row_snapshot=scan._row_snapshot, **budgets)
    if fresh._row_snapshot.input_binding_verified is not True:
        return _incomplete_scan(fresh, "source_input_binding_required")
    # staleなsourceはhelperのpartialをそのまま伝播し、旧descriptorへ戻さない。
    if fresh.coverage()["inventory_complete"] and original != _descriptor_projection(fresh._descriptors):
        return _incomplete_scan(fresh, "resource_consumer_descriptor_changed")
    return fresh


def prepare_resource_snapshot(data, pe, *, max_resources=resources.MAX_RESOURCE_ROWS,
                              max_resource_bytes=resources.MAX_RESOURCE_BYTES,
                              max_rows=DEFAULT_MAX_ROWS, max_total_rows=DEFAULT_MAX_TOTAL_ROWS):
    """同じ13table予算を成立させ、固定resolverと作業量を返す専用factory。"""
    scan = resources.describe_clr_resources(
        data, pe, max_resources=max_resources, max_resource_bytes=max_resource_bytes,
        max_total_bytes=max_resource_bytes, max_table_rows=max_rows, max_total_rows=max_total_rows)
    if scan._row_snapshot.input_binding_verified is not True:
        scan = _incomplete_scan(scan, "source_input_binding_required")
    resolver, work = resolver_from_resource_snapshot(
        pe, data=data, row_snapshot=scan._row_snapshot, max_rows=max_rows, max_total_rows=max_total_rows)
    return scan, resolver, work
