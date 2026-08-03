#!/usr/bin/env python3
"""Windows Installerデータベースを実行せず、主要テーブルを読み取り専用で棚卸しする。"""

from __future__ import annotations

import argparse
import ctypes
from ctypes import wintypes
import hashlib
import json
import os
from pathlib import Path
from typing import Callable

ERROR_SUCCESS = 0
ERROR_MORE_DATA = 234
ERROR_NO_MORE_ITEMS = 259
MAX_ROWS_DEFAULT = 4096
MAX_MSI_SIZE_DEFAULT = 256 * 1024 * 1024

TABLE_QUERIES = {
    "File": (
        "SELECT `File`,`Component_`,`FileName`,`FileSize`,`Version`,`Language`,`Attributes`,`Sequence` FROM `File`",
        [
            "File",
            "Component_",
            "FileName",
            "FileSize",
            "Version",
            "Language",
            "Attributes",
            "Sequence",
        ],
    ),
    "CustomAction": (
        "SELECT `Action`,`Type`,`Source`,`Target` FROM `CustomAction`",
        ["Action", "Type", "Source", "Target"],
    ),
    "InstallExecuteSequence": (
        "SELECT `Action`,`Condition`,`Sequence` FROM `InstallExecuteSequence`",
        ["Action", "Condition", "Sequence"],
    ),
    "Media": (
        "SELECT `DiskId`,`LastSequence`,`DiskPrompt`,`Cabinet`,`VolumeLabel`,`Source` FROM `Media`",
        ["DiskId", "LastSequence", "DiskPrompt", "Cabinet", "VolumeLabel", "Source"],
    ),
}


class MsiInventoryError(RuntimeError):
    """MSI APIが読み取りに失敗したことを表す。"""


def _msi_api():
    if os.name != "nt":
        raise MsiInventoryError("MSIテーブル棚卸しはWindowsでのみ利用できます")
    api = ctypes.WinDLL("msi", use_last_error=True)
    api.MsiOpenDatabaseW.argtypes = [
        wintypes.LPCWSTR,
        ctypes.c_void_p,
        ctypes.POINTER(wintypes.UINT),
    ]
    api.MsiOpenDatabaseW.restype = wintypes.UINT
    api.MsiDatabaseOpenViewW.argtypes = [
        wintypes.UINT,
        wintypes.LPCWSTR,
        ctypes.POINTER(wintypes.UINT),
    ]
    api.MsiDatabaseOpenViewW.restype = wintypes.UINT
    api.MsiViewExecute.argtypes = [wintypes.UINT, wintypes.UINT]
    api.MsiViewExecute.restype = wintypes.UINT
    api.MsiViewFetch.argtypes = [wintypes.UINT, ctypes.POINTER(wintypes.UINT)]
    api.MsiViewFetch.restype = wintypes.UINT
    api.MsiRecordGetStringW.argtypes = [
        wintypes.UINT,
        wintypes.UINT,
        wintypes.LPWSTR,
        ctypes.POINTER(wintypes.DWORD),
    ]
    api.MsiRecordGetStringW.restype = wintypes.UINT
    api.MsiCloseHandle.argtypes = [wintypes.UINT]
    api.MsiCloseHandle.restype = wintypes.UINT
    return api


def _record_string(api, record: int, field: int) -> str | None:
    length = wintypes.DWORD(0)
    status = api.MsiRecordGetStringW(record, field, None, ctypes.byref(length))
    if status not in {ERROR_SUCCESS, ERROR_MORE_DATA}:
        raise MsiInventoryError(
            f"MsiRecordGetStringWの長さ取得に失敗しました: {status}"
        )
    if length.value == 0:
        return None
    buffer = ctypes.create_unicode_buffer(length.value + 1)
    capacity = wintypes.DWORD(length.value + 1)
    status = api.MsiRecordGetStringW(record, field, buffer, ctypes.byref(capacity))
    if status != ERROR_SUCCESS:
        raise MsiInventoryError(f"MsiRecordGetStringWに失敗しました: {status}")
    return buffer.value


def query_rows(
    msi_path: Path, query: str, fields: list[str], max_rows: int
) -> tuple[list[dict[str, str | None]], bool]:
    """1テーブルを読み取り専用で境界付き取得する。"""

    api = _msi_api()
    database = wintypes.UINT(0)
    status = api.MsiOpenDatabaseW(
        str(msi_path), ctypes.c_void_p(0), ctypes.byref(database)
    )
    if status != ERROR_SUCCESS:
        raise MsiInventoryError(f"MsiOpenDatabaseWに失敗しました: {status}")
    view = wintypes.UINT(0)
    try:
        status = api.MsiDatabaseOpenViewW(database.value, query, ctypes.byref(view))
        if status != ERROR_SUCCESS:
            raise MsiInventoryError(f"MsiDatabaseOpenViewWに失敗しました: {status}")
        status = api.MsiViewExecute(view.value, 0)
        if status != ERROR_SUCCESS:
            raise MsiInventoryError(f"MsiViewExecuteに失敗しました: {status}")
        rows: list[dict[str, str | None]] = []
        truncated = False
        while True:
            record = wintypes.UINT(0)
            status = api.MsiViewFetch(view.value, ctypes.byref(record))
            if status == ERROR_NO_MORE_ITEMS:
                break
            if status != ERROR_SUCCESS:
                raise MsiInventoryError(f"MsiViewFetchに失敗しました: {status}")
            try:
                if len(rows) >= max_rows:
                    truncated = True
                    break
                rows.append(
                    {
                        name: _record_string(api, record.value, index + 1)
                        for index, name in enumerate(fields)
                    }
                )
            finally:
                api.MsiCloseHandle(record.value)
        return rows, truncated
    finally:
        if view.value:
            api.MsiCloseHandle(view.value)
        api.MsiCloseHandle(database.value)


def collect_inventory(
    msi_path: Path,
    max_rows: int = MAX_ROWS_DEFAULT,
    query_function: Callable[
        [Path, str, list[str], int], tuple[list[dict[str, str | None]], bool]
    ] = query_rows,
    *,
    max_input_size: int = MAX_MSI_SIZE_DEFAULT,
) -> dict[str, object]:
    """主要テーブルとファイルID・カスタムアクションの対応を返す。"""

    if max_rows <= 0:
        raise ValueError("max_rowsは正数である必要があります")
    if max_input_size <= 0:
        raise ValueError("max_input_sizeは正数である必要があります")
    if not msi_path.is_file():
        raise MsiInventoryError("入力MSIが通常ファイルではありません")
    size = msi_path.stat().st_size
    if size > max_input_size:
        raise MsiInventoryError(
            f"入力MSIが上限を超えています: {size} > {max_input_size}"
        )
    digest = hashlib.sha256()
    with msi_path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    tables: dict[str, object] = {}
    for table, (query, fields) in TABLE_QUERIES.items():
        try:
            rows, truncated = query_function(msi_path, query, fields, max_rows)
            tables[table] = {
                "status": "ok",
                "rows": rows,
                "row_count": len(rows),
                "truncated": truncated,
            }
        except MsiInventoryError as exc:
            tables[table] = {
                "status": "unavailable",
                "reason": str(exc),
                "rows": [],
                "row_count": 0,
                "truncated": False,
            }

    file_rows = tables["File"]["rows"]
    file_map = {
        str(row.get("File")): row.get("FileName")
        for row in file_rows
        if row.get("File")
    }
    actions = []
    for row in tables["CustomAction"]["rows"]:
        source = row.get("Source")
        actions.append(
            {**row, "source_file_name": file_map.get(str(source)) if source else None}
        )
    sequence_map = {
        str(row.get("Action")): row.get("Sequence")
        for row in tables["InstallExecuteSequence"]["rows"]
        if row.get("Action")
    }
    for action in actions:
        action["execute_sequence"] = sequence_map.get(str(action.get("Action")))

    return {
        "schema_version": 1,
        "sample": {"name": msi_path.name, "size": size, "sha256": digest.hexdigest()},
        "tables": tables,
        "relationships": {"file_id_to_name": file_map, "custom_actions": actions},
        "safety": {
            "database_mode": "read_only",
            "installer_executed": False,
            "network_contacted": False,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="MSI主要テーブルを実行せず棚卸しします"
    )
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--max-rows", type=int, default=MAX_ROWS_DEFAULT)
    parser.add_argument("--max-input-size", type=int, default=MAX_MSI_SIZE_DEFAULT)
    args = parser.parse_args()
    report = collect_inventory(
        args.input.resolve(),
        args.max_rows,
        max_input_size=args.max_input_size,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(
        json.dumps(
            {"output": str(args.output), "sha256": report["sample"]["sha256"]},
            ensure_ascii=False,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
