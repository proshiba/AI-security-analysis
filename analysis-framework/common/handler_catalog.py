#!/usr/bin/env python3
"""既存の静的解析関数を棚卸しし、安全な共通インターフェースで実行する。"""

from __future__ import annotations

import ast
from dataclasses import asdict, dataclass
from functools import lru_cache
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys
from typing import Any, Callable
from urllib.parse import urlsplit, urlunsplit


FRAMEWORK_ROOT = Path(__file__).resolve().parents[1]
REPOSITORY_ROOT = FRAMEWORK_ROOT.parent
MALWARE_ROOT = FRAMEWORK_ROOT / "malware"
EXTRACTORS_ROOT = REPOSITORY_ROOT / "extractors"
PROFILE_PATH = EXTRACTORS_ROOT / "profiles" / "windows_family_profiles.json"
FAMILY_ID = re.compile(r"^[a-z0-9_-]+$")
EMAIL = re.compile(r"(?<![\w.+-])[\w.+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?![\w.-])")
SECRET_ASSIGNMENT = re.compile(
    r"(?i)\b(password|passwd|secret|token|api[_-]?key|auth[_-]?key)\b\s*[:=]\s*([^\s,;]+)"
)
SECRET_KEY = re.compile(
    r"(?i)^(?:password|passwd|secret|token|api[_-]?key|auth[_-]?key|username|email|credentials?)$"
)
MAX_DEPTH = 24
MAX_COLLECTION_ITEMS = 20_000
MAX_STRING_LENGTH = 65_536


@dataclass(frozen=True)
class HandlerSpec:
    """1つの既存静的解析関数に対する検証済み呼び出し仕様。"""

    id: str
    family: str
    relative_path: str
    callable_name: str
    invocation: str
    source: str
    automatic: bool
    campaign: str | None
    supported_interface: bool
    reason: str

    def public(self) -> dict[str, Any]:
        """機械可読な公開用メタデータへ変換する。"""

        return asdict(self)


class HandlerLoadError(RuntimeError):
    """解析ハンドラーの許可リスト検証または読み込みに失敗した。"""


def _function_shape(path: Path, callable_name: str) -> tuple[str, bool, str]:
    """ASTだけを読み、バイト列APIとして安全に呼べる関数か判定する。"""

    try:
        tree = ast.parse(path.read_text(encoding="utf-8-sig"), filename=str(path))
    except (OSError, SyntaxError, UnicodeError) as exc:
        return "unsupported", False, f"source_parse_error:{type(exc).__name__}"
    function = next(
        (
            node
            for node in tree.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name == callable_name
        ),
        None,
    )
    if function is None or isinstance(function, ast.AsyncFunctionDef):
        return "unsupported", False, "callable_missing_or_async"
    positional = [*function.args.posonlyargs, *function.args.args]
    if not positional:
        return "unsupported", False, "sample_parameter_missing"
    first = positional[0].arg
    if first == "text":
        invocation = "text"
    elif first in {"data", "blob", "resource_data", "plaintext"}:
        invocation = "bytes"
    else:
        return "unsupported", False, f"unsupported_first_parameter:{first}"
    required_positional = len(positional) - len(function.args.defaults)
    if required_positional > 1:
        if (
            invocation == "bytes"
            and required_positional == 2
            and positional[1].arg == "expected_sha256"
        ):
            invocation = "bytes_expected_sha256"
        else:
            return invocation, False, "additional_required_positional_parameter"
    required_keywords = [
        argument.arg
        for argument, default in zip(function.args.kwonlyargs, function.args.kw_defaults)
        if default is None
    ]
    if required_keywords:
        if invocation == "bytes" and required_keywords == ["timestamp"]:
            invocation = "bytes_pe_timestamp"
        else:
            return invocation, False, "additional_required_keyword_parameter"
    if (
        invocation == "bytes"
        and callable_name == "extract"
        and len(positional) >= 2
        and positional[1].arg in {"name", "source_name"}
    ):
        invocation = "bytes_name"
    return invocation, True, "bounded_static_callable"


def _handler_id(family: str, path: Path, callable_name: str) -> str:
    relative = path.resolve().relative_to(REPOSITORY_ROOT.resolve()).as_posix()
    stem = re.sub(r"[^a-z0-9]+", ".", relative.lower()).strip(".")
    return f"{family}:{stem}:{callable_name}"


def _malware_specs() -> list[HandlerSpec]:
    specs: list[HandlerSpec] = []
    for family_root in sorted(item for item in MALWARE_ROOT.iterdir() if item.is_dir()):
        family = family_root.name
        if FAMILY_ID.fullmatch(family) is None:
            continue
        for path in sorted(family_root.rglob("*.py")):
            if "tests" in path.parts or path.name.startswith("test_"):
                continue
            relative_family = path.relative_to(family_root)
            callables = []
            try:
                tree = ast.parse(path.read_text(encoding="utf-8-sig"), filename=str(path))
                names = {
                    node.name
                    for node in tree.body
                    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                }
                callables = [
                    name
                    for name in ("extract_config", "extract", "analyze", "extract_directory")
                    if name in names
                ]
            except (OSError, SyntaxError, UnicodeError):
                callables = []
            for callable_name in callables:
                invocation, supported, shape_reason = _function_shape(path, callable_name)
                campaign = None
                automatic = (
                    relative_family.parts == ("extract_config.py",)
                    and callable_name == "extract_config"
                )
                if len(relative_family.parts) >= 3 and relative_family.parts[0] == "campaigns":
                    campaign = relative_family.parts[1]
                    automatic = supported
                reason = shape_reason
                if supported and not automatic:
                    reason = "specialized_handler_requires_manual_or_campaign_selection"
                specs.append(
                    HandlerSpec(
                        id=_handler_id(family, path, callable_name),
                        family=family,
                        relative_path=path.resolve().relative_to(REPOSITORY_ROOT.resolve()).as_posix(),
                        callable_name=callable_name,
                        invocation=invocation,
                        source="malware_family_script",
                        automatic=automatic and supported,
                        campaign=campaign,
                        supported_interface=supported,
                        reason=reason,
                    )
                )
    return specs


def _extractor_specs() -> list[HandlerSpec]:
    specs: list[HandlerSpec] = []
    paths = sorted(EXTRACTORS_ROOT.glob("*/extractor.py"))
    nested = EXTRACTORS_ROOT / "unclassified" / "mx_go" / "extractor.py"
    if nested.is_file():
        paths.append(nested)
    for path in paths:
        family = "mx-go" if path.parent.name == "mx_go" else path.parent.name
        if FAMILY_ID.fullmatch(family) is None:
            continue
        invocation, supported, reason = _function_shape(path, "extract")
        specs.append(
            HandlerSpec(
                id=_handler_id(family, path, "extract"),
                family=family,
                relative_path=path.resolve().relative_to(REPOSITORY_ROOT.resolve()).as_posix(),
                callable_name="extract",
                invocation=invocation,
                source="shared_extractor",
                automatic=supported,
                campaign=None,
                supported_interface=supported,
                reason=reason,
            )
        )
    return specs


def _profiled_specs(existing_families: set[str]) -> list[HandlerSpec]:
    if not PROFILE_PATH.is_file():
        return []
    profiles = json.loads(PROFILE_PATH.read_text(encoding="utf-8-sig"))
    values = profiles.get("profiles", profiles.get("families", profiles))
    if not isinstance(values, dict):
        return []
    path = EXTRACTORS_ROOT / "profiled_family.py"
    specs = []
    for family in sorted(values):
        if family in existing_families or FAMILY_ID.fullmatch(family) is None:
            continue
        specs.append(
            HandlerSpec(
                id=f"{family}:extractors.profiled_family:extractor_for",
                family=family,
                relative_path=path.resolve().relative_to(REPOSITORY_ROOT.resolve()).as_posix(),
                callable_name="extractor_for",
                invocation="profiled_bytes_name",
                source="profiled_shared_extractor",
                automatic=True,
                campaign=None,
                supported_interface=True,
                reason="bounded_profiled_static_callable",
            )
        )
    return specs


def discover_handlers() -> list[HandlerSpec]:
    """信頼済みディレクトリから既存解析関数を決定的に棚卸しする。"""

    specs = [*_malware_specs(), *_extractor_specs()]
    automatic_families = {item.family for item in specs if item.automatic}
    specs.extend(_profiled_specs(automatic_families))
    unique = {item.id: item for item in specs}
    return [unique[key] for key in sorted(unique)]


def catalog_summary(specs: list[HandlerSpec]) -> dict[str, Any]:
    """解析器カタログの対応数と手動確認対象数を集計する。"""

    return {
        "handler_count": len(specs),
        "family_count": len({item.family for item in specs}),
        "automatic_handler_count": sum(item.automatic for item in specs),
        "supported_interface_count": sum(item.supported_interface for item in specs),
        "manual_or_unsupported_count": sum(not item.automatic for item in specs),
    }


def _resolve_handler_path(spec: HandlerSpec) -> Path:
    if FAMILY_ID.fullmatch(spec.family) is None:
        raise HandlerLoadError(f"invalid family id: {spec.family!r}")
    requested = Path(spec.relative_path)
    if requested.is_absolute() or ".." in requested.parts:
        raise HandlerLoadError(f"unsafe handler path: {spec.relative_path!r}")
    try:
        resolved = (REPOSITORY_ROOT / requested).resolve(strict=True)
    except (OSError, FileNotFoundError) as exc:
        raise HandlerLoadError(f"handler path does not exist: {spec.relative_path}") from exc
    allowed = (MALWARE_ROOT.resolve(), EXTRACTORS_ROOT.resolve())
    if not any(resolved == root or root in resolved.parents for root in allowed):
        raise HandlerLoadError(f"handler path is outside the allowlist: {resolved}")
    if not resolved.is_file() or resolved.suffix.lower() != ".py":
        raise HandlerLoadError(f"handler is not a Python source file: {resolved}")
    return resolved


@lru_cache(maxsize=None)
def load_handler(spec: HandlerSpec) -> tuple[Callable[..., Any], str]:
    """許可リスト検証後に既存静的解析関数を読み込む。"""

    if not spec.supported_interface:
        raise HandlerLoadError(f"unsupported handler interface: {spec.reason}")
    path = _resolve_handler_path(spec)
    for trusted in (REPOSITORY_ROOT, FRAMEWORK_ROOT, FRAMEWORK_ROOT / "common", path.parent):
        value = str(trusted)
        if value not in sys.path:
            sys.path.insert(0, value)
    module_name = f"one_shot_handler_{hashlib.sha256(str(path).encode()).hexdigest()[:16]}"
    module_spec = importlib.util.spec_from_file_location(module_name, path)
    if module_spec is None or module_spec.loader is None:
        raise HandlerLoadError(f"cannot load handler module: {path}")
    module = importlib.util.module_from_spec(module_spec)
    # dataclasses、typing、picklingなどは、クラス定義中に
    # sys.modules[cls.__module__] を参照する。動的moduleを登録せず
    # exec_moduleすると、正当なdataclass使用handlerまでpreflightで失敗する。
    previous_module = sys.modules.get(module_name)
    sys.modules[module_name] = module
    try:
        module_spec.loader.exec_module(module)
    except Exception:
        if previous_module is None:
            sys.modules.pop(module_name, None)
        else:
            sys.modules[module_name] = previous_module
        raise
    callable_value = getattr(module, spec.callable_name, None)
    if not callable(callable_value):
        raise HandlerLoadError(f"callable not found: {spec.callable_name}")
    if spec.invocation == "profiled_bytes_name":
        callable_value = callable_value(spec.family)
        if not callable(callable_value):
            raise HandlerLoadError(f"profile factory did not return a callable: {spec.family}")
        return callable_value, "bytes_name"
    return callable_value, spec.invocation


def _sanitize_url(value: str) -> str:
    try:
        parsed = urlsplit(value)
    except ValueError:
        return value
    if parsed.scheme.lower() not in {"http", "https", "ftp"} or not parsed.hostname:
        return value
    port = f":{parsed.port}" if parsed.port else ""
    path = parsed.path
    hostname = parsed.hostname.lower()
    if "api.telegram.org" in hostname and path not in {"", "/"}:
        path = "/<redacted>"
    if "discord" in hostname and "webhook" in path.lower():
        path = "/<redacted>"
    if "hooks.slack.com" == hostname and path not in {"", "/"}:
        path = "/<redacted>"
    return urlunsplit((parsed.scheme.lower(), f"{hostname}{port}", path, "", ""))


def sanitize_public_value(value: Any, *, key: str = "", depth: int = 0) -> Any:
    """資格情報とバイナリを除去し、JSONへ安全に保存できる値へ変換する。"""

    if depth > MAX_DEPTH:
        return {"truncated": True, "reason": "maximum_depth"}
    if SECRET_KEY.fullmatch(key) and not isinstance(value, (bool, int, float, type(None))):
        return "[REDACTED]"
    if isinstance(value, bytes):
        return {
            "type": "bytes",
            "size": len(value),
            "sha256": hashlib.sha256(value).hexdigest(),
            "content_exported": False,
        }
    if isinstance(value, Path):
        return value.name
    if isinstance(value, dict):
        result = {}
        for index, (item_key, item_value) in enumerate(value.items()):
            if index >= MAX_COLLECTION_ITEMS:
                result["_truncated"] = True
                break
            text_key = str(item_key)
            result[text_key] = sanitize_public_value(
                item_value, key=text_key, depth=depth + 1
            )
        return result
    if isinstance(value, (list, tuple, set)):
        items = list(value)
        sanitized = [
            sanitize_public_value(item, key=key, depth=depth + 1)
            for item in items[:MAX_COLLECTION_ITEMS]
        ]
        if len(items) > MAX_COLLECTION_ITEMS:
            sanitized.append({"truncated": True, "reason": "maximum_items"})
        return sanitized
    if isinstance(value, str):
        result = _sanitize_url(value) if value.lower().startswith(("http://", "https://", "ftp://")) else value
        result = EMAIL.sub("[REDACTED_EMAIL]", result)
        result = SECRET_ASSIGNMENT.sub(lambda match: f"{match.group(1)}=[REDACTED]", result)
        if len(result) > MAX_STRING_LENGTH:
            return result[:MAX_STRING_LENGTH] + "…[truncated]"
        return result
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return str(value)[:MAX_STRING_LENGTH]


def _pe_timestamp(data: bytes) -> int:
    """PEヘッダーからTimeDateStampをロードせず取得する。"""

    if len(data) < 0x40 or not data.startswith(b"MZ"):
        raise HandlerLoadError("PE timestampを取得できる入力ではありません")
    pe_offset = int.from_bytes(data[0x3C:0x40], "little")
    if pe_offset < 0x40 or pe_offset + 12 > len(data) or data[pe_offset:pe_offset + 4] != b"PE\0\0":
        raise HandlerLoadError("PEヘッダーが不正です")
    return int.from_bytes(data[pe_offset + 8:pe_offset + 12], "little")


def execute_handler(spec: HandlerSpec, data: bytes, source_name: str) -> dict[str, Any]:
    """1つの静的解析関数を実行し、秘密値とバイナリを除去して返す。"""

    handler, invocation = load_handler(spec)
    if invocation == "bytes_name":
        result = handler(data, source_name)
    elif invocation == "bytes":
        result = handler(data)
    elif invocation == "bytes_expected_sha256":
        result = handler(data, hashlib.sha256(data).hexdigest())
    elif invocation == "bytes_pe_timestamp":
        result = handler(data, timestamp=_pe_timestamp(data))
    elif invocation == "text":
        result = handler(data.decode("utf-8-sig", errors="replace"))
    else:
        raise HandlerLoadError(f"unsupported invocation: {invocation}")
    return {
        "handler": spec.public(),
        "result": sanitize_public_value(result),
        "executed_sample": False,
        "network_contacted": False,
    }
