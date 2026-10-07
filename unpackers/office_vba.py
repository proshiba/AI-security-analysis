#!/usr/bin/env python3
"""OLE内のVBA sourceを実行せず有界に復元する。

``oletools`` の静的parserだけを用い、VBA、p-code、Office application、
外部processを実行しない。入力、module数、module単体size、復元総量へ上限を
設け、上限違反時は復元物を一切後続へ渡さない。
"""

from __future__ import annotations

import hashlib

from oletools import olevba

OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
MAX_INPUT_SIZE = 32 * 1024 * 1024
MAX_MODULES = 128
MAX_MODULE_SIZE = 1024 * 1024
MAX_TOTAL_SOURCE_SIZE = 16 * 1024 * 1024


class OfficeVbaError(ValueError):
    """VBA静的復元の安全境界違反を表す。"""


def _bounded_positive_integer(value: int, maximum: int, label: str) -> int:
    """boolを除く正整数上限だけを受理する。"""

    if type(value) is not int or not 1 <= value <= maximum:
        raise OfficeVbaError(f"{label}が不正です")
    return value


def _source_bytes(value: bytes | str) -> bytes:
    """oletoolsの版差を吸収してVBA sourceをUTF-8 byte列へ正規化する。"""

    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return value.encode("utf-8", errors="replace")
    raise OfficeVbaError("VBA sourceの型が不正です")


def _name_digest(value: object) -> str | None:
    """parser由来の名称を公開せず、照合用digestだけを返す。"""

    if value is None:
        return None
    if isinstance(value, bytes):
        encoded = value
    elif isinstance(value, str):
        encoded = value.encode("utf-8", errors="replace")
    else:
        encoded = repr(type(value).__name__).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def recover_vba_modules(
    data: bytes,
    *,
    maximum_input_size: int = MAX_INPUT_SIZE,
    maximum_modules: int = MAX_MODULES,
    maximum_module_size: int = MAX_MODULE_SIZE,
    maximum_total_source_size: int = MAX_TOTAL_SOURCE_SIZE,
) -> tuple[dict[str, object], list[tuple[str, bytes]]]:
    """OLE containerからVBA source moduleだけをfail-closedで復元する。"""

    _bounded_positive_integer(maximum_input_size, MAX_INPUT_SIZE, "入力size上限")
    _bounded_positive_integer(maximum_modules, MAX_MODULES, "module数上限")
    _bounded_positive_integer(maximum_module_size, MAX_MODULE_SIZE, "module size上限")
    _bounded_positive_integer(
        maximum_total_source_size,
        MAX_TOTAL_SOURCE_SIZE,
        "復元総量上限",
    )
    if not data.startswith(OLE_MAGIC):
        return {"status": "not_ole_container"}, []
    if not 1 <= len(data) <= maximum_input_size:
        return {
            "status": "input_size_blocked",
            "input_size": len(data),
            "maximum_input_size": maximum_input_size,
            "executed": False,
            "network_contacted": False,
        }, []

    parser: olevba.VBA_Parser | None = None
    try:
        parser = olevba.VBA_Parser(
            filename="memory.ole",
            data=data,
            relaxed=False,
            disable_pcode=True,
        )
        if not parser.detect_vba_macros():
            return {
                "status": "vba_not_detected",
                "input_sha256": hashlib.sha256(data).hexdigest(),
                "pcode_processed": False,
                "executed": False,
                "network_contacted": False,
            }, []

        recovered: list[tuple[str, bytes]] = []
        modules: list[dict[str, object]] = []
        total_size = 0
        for index, (_filename, stream_path, module_name, source) in enumerate(
            parser.extract_macros(),
            start=1,
        ):
            if index > maximum_modules:
                raise OfficeVbaError("VBA module数が上限を超えています")
            source_bytes = _source_bytes(source)
            if len(source_bytes) > maximum_module_size:
                raise OfficeVbaError("VBA module sizeが上限を超えています")
            total_size += len(source_bytes)
            if total_size > maximum_total_source_size:
                raise OfficeVbaError("VBA source復元総量が上限を超えています")
            digest = hashlib.sha256(source_bytes).hexdigest()
            artifact_name = f"office-vba-module-{index:03d}.vba"
            recovered.append((artifact_name, source_bytes))
            modules.append(
                {
                    "index": index,
                    "size": len(source_bytes),
                    "sha256": digest,
                    "stream_path_sha256": _name_digest(stream_path),
                    "module_name_sha256": _name_digest(module_name),
                }
            )
        if not recovered:
            return {
                "status": "vba_detected_without_source",
                "input_sha256": hashlib.sha256(data).hexdigest(),
                "pcode_processed": False,
                "executed": False,
                "network_contacted": False,
            }, []
    except OfficeVbaError as exc:
        return {
            "status": "output_limit_blocked",
            "reason": str(exc),
            "pcode_processed": False,
            "executed": False,
            "network_contacted": False,
        }, []
    except (AttributeError, OSError, ValueError, olevba.OlevbaBaseException) as exc:
        return {
            "status": "parser_rejected",
            "error_type": type(exc).__name__,
            "pcode_processed": False,
            "executed": False,
            "network_contacted": False,
        }, []
    finally:
        if parser is not None:
            # oletoolsの版差や破損OLEによりclose側が例外を返しても、
            # 静的解析worker全体を停止させない。復元結果の判定は上の
            # parser処理だけで完結しており、close失敗を成功根拠には使わない。
            try:
                parser.close()
            except (
                AttributeError,
                OSError,
                ValueError,
                olevba.OlevbaBaseException,
            ):
                pass

    return {
        "status": "vba_source_recovered",
        "input_size": len(data),
        "input_sha256": hashlib.sha256(data).hexdigest(),
        "module_count": len(recovered),
        "total_source_size": total_size,
        "modules": modules,
        "pcode_processed": False,
        "executed": False,
        "network_contacted": False,
        "office_application_started": False,
    }, recovered
