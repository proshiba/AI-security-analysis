#!/usr/bin/env python3
"""既存の静的解析関数を棚卸しし、安全な共通インターフェースで実行する。"""

from __future__ import annotations

import ast
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
from functools import lru_cache
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys
from typing import Any, Callable
from urllib.parse import unquote, urlsplit, urlunsplit


FRAMEWORK_ROOT = Path(__file__).resolve().parents[1]
REPOSITORY_ROOT = FRAMEWORK_ROOT.parent
MALWARE_ROOT = FRAMEWORK_ROOT / "malware"
EXTRACTORS_ROOT = REPOSITORY_ROOT / "extractors"
PROFILE_PATH = EXTRACTORS_ROOT / "profiles" / "windows_family_profiles.json"
FAMILY_ID = re.compile(r"^[a-z0-9_-]+$")
EMAIL = re.compile(r"(?<![\w.+-])[\w.+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?![\w.-])")
SECRET_ASSIGNMENT = re.compile(
    r"(?i)(?P<prefix>[\"']?(?:password|passwd|secret|token|api[_-]?key|auth[_-]?key)"
    r"[\"']?\s*[:=]\s*)(?P<secret>\"[^\"]*\"|'[^']*'|[^\s,;}]+)"
)
BEARER_CREDENTIAL = re.compile(
    r"(?i)(\b(?:authorization\s*:\s*)?bearer\s+)([^\s,;\"']+)"
)
OPAQUE_CREDENTIAL = re.compile(
    r"(?i)\b(?:github_pat_[A-Za-z0-9_]{20,}|gh[pousr]_[A-Za-z0-9_]{20,}|"
    r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})\b"
)
SENSITIVE_URL_PATH = re.compile(
    r"(?i)/((?:access[_-]?)?token|api[_-]?key|auth(?:orization)?|"
    r"password|client[_-]?secret|secret)/[^/]+"
)
SECRET_KEY = re.compile(
    r"(?i)^(?:password|passwd|secret|token|api[_-]?key|auth[_-]?key|"
    r"auth(?:entication)?[_-]?token|access[_-]?token|refresh[_-]?token|bot[_-]?token|"
    r"authorization|bearer|cookies?|session[_-]?(?:id|token)|client[_-]?secret|"
    r"private[_-]?key|webhook[_-]?(?:secret|token)|username|email|credentials?)$"
)
MAX_DEPTH = 24
MAX_COLLECTION_ITEMS = 20_000
MAX_STRING_LENGTH = 65_536
HANDLER_CONTRACT_NAME = "HANDLER_CONTRACT"
DEFAULT_MAXIMUM_ASSESSMENT_LAYER_SIZE = 128 * 1024 * 1024
DEFAULT_MAXIMUM_ASSESSMENT_TOTAL_SIZE = 256 * 1024 * 1024
MAX_ASSESSMENT_CANDIDATES = 64
MAX_ASSESSMENT_LAYERS = 128
MAX_ASSESSMENT_ATTEMPTS = 2_048
KNOWN_INPUT_FORMATS = frozenset(
    {
        "any",
        "data",
        "pe",
        "elf",
        "macho",
        "zip",
        "7z",
        "xz",
        "png",
        "asar",
        "apple-disk-image",
        "cab",
        "rar",
        "autoit-a3x",
        "ole",
        "script",
        "java-class",
    }
)


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
    input_formats: tuple[str, ...]
    input_contract_source: str
    minimum_evidence_score: int

    def public(self) -> dict[str, Any]:
        """機械可読な公開用メタデータへ変換する。"""

        return asdict(self)


class HandlerLoadError(RuntimeError):
    """解析ハンドラーの許可リスト検証または読み込みに失敗した。"""


class HandlerNoEvidenceError(ValueError):
    """入力は解析できたが、対象variantの適用証拠がないことを表す。"""


@lru_cache(maxsize=None)
def _module_tree(path: Path) -> ast.Module:
    """同一ソースを繰り返し読まず、ASTをキャッシュして返す。"""

    return ast.parse(path.read_text(encoding="utf-8-sig"), filename=str(path))


def _function_node(path: Path, callable_name: str) -> ast.FunctionDef | None:
    """トップレベルの同期関数だけを返す。"""

    return next(
        (
            node
            for node in _module_tree(path).body
            if isinstance(node, ast.FunctionDef) and node.name == callable_name
        ),
        None,
    )


def _function_shape(path: Path, callable_name: str) -> tuple[str, bool, str]:
    """ASTだけを読み、バイト列APIとして安全に呼べる関数か判定する。"""

    try:
        tree = _module_tree(path)
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


def _flatten_bytes_literal(node: ast.AST) -> list[bytes]:
    """`startswith`引数から静的なbytes定数だけを取り出す。"""

    if isinstance(node, ast.Constant) and isinstance(node.value, bytes):
        return [node.value]
    if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
        values: list[bytes] = []
        for item in node.elts:
            values.extend(_flatten_bytes_literal(item))
        return values
    return []


def _prefix_format(prefix: bytes) -> str | None:
    """厳格な先頭magicを共通形式IDへ変換する。"""

    if prefix.startswith(b"MZ"):
        return "pe"
    if prefix.startswith(b"\x7fELF"):
        return "elf"
    if prefix.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if prefix.startswith(b"MSCF"):
        return "cab"
    if prefix.startswith(b"Rar!\x1a\x07"):
        return "rar"
    if prefix.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        return "ole"
    if prefix.lstrip().startswith(
        (b"#!", b"<hta", b"<html", b"function ", b"var ", b"let ", b"const ")
    ):
        return "script"
    return None


def _strict_guard_formats(path: Path, callable_name: str) -> tuple[str, ...]:
    """先頭の否定magic guardから、拒否条件が明確な形式だけを推定する。"""

    function = _function_node(path, callable_name)
    if function is None:
        return ()
    positional = [*function.args.posonlyargs, *function.args.args]
    if not positional:
        return ()
    first_parameter = positional[0].arg
    guard_formats: list[set[str]] = []
    for statement in function.body[:12]:
        if (
            not isinstance(statement, ast.If)
            or not statement.body
            or not isinstance(statement.body[-1], ast.Raise)
        ):
            continue
        test = statement.test
        if not isinstance(test, ast.UnaryOp) or not isinstance(test.op, ast.Not):
            continue
        call = test.operand
        if (
            not isinstance(call, ast.Call)
            or not isinstance(call.func, ast.Attribute)
            or call.func.attr != "startswith"
            or not isinstance(call.func.value, ast.Name)
            or call.func.value.id != first_parameter
            or len(call.args) != 1
        ):
            continue
        detected_formats = {
            detected
            for prefix in _flatten_bytes_literal(call.args[0])
            if (detected := _prefix_format(prefix)) is not None
        }
        if detected_formats:
            guard_formats.append(detected_formats)
    if not guard_formats:
        return ()
    required_formats = set.intersection(*guard_formats)
    return tuple(sorted(required_formats))


def _declared_handler_contract(path: Path) -> dict[str, Any] | None:
    """module定数の宣言だけを`literal_eval`で安全に読み取る。"""

    for node in _module_tree(path).body:
        value_node: ast.AST | None = None
        if isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == HANDLER_CONTRACT_NAME
            for target in node.targets
        ):
            value_node = node.value
        elif (
            isinstance(node, ast.AnnAssign)
            and isinstance(node.target, ast.Name)
            and node.target.id == HANDLER_CONTRACT_NAME
        ):
            value_node = node.value
        if value_node is None:
            continue
        value = ast.literal_eval(value_node)
        if not isinstance(value, dict):
            raise ValueError(f"{HANDLER_CONTRACT_NAME}はobjectで宣言してください")
        return value
    return None


def _handler_contract(
    path: Path,
    callable_name: str,
    invocation: str,
    source: str,
) -> tuple[tuple[str, ...], str, int]:
    """宣言、厳格guard、呼出adapterの順に入力契約を決定する。"""

    declared = _declared_handler_contract(path)
    if declared is not None:
        raw_formats = declared.get("input_formats")
        if (
            not isinstance(raw_formats, (list, tuple))
            or not raw_formats
            or any(
                not isinstance(item, str) or item not in KNOWN_INPUT_FORMATS
                for item in raw_formats
            )
        ):
            raise ValueError("HANDLER_CONTRACT.input_formatsが不正です")
        raw_score = declared.get("minimum_evidence_score", 1)
        if (
            not isinstance(raw_score, int)
            or isinstance(raw_score, bool)
            or not 0 <= raw_score <= 100_000
        ):
            raise ValueError("HANDLER_CONTRACT.minimum_evidence_scoreが不正です")
        return tuple(dict.fromkeys(raw_formats)), "module_declaration", raw_score
    guarded = _strict_guard_formats(path, callable_name)
    if guarded:
        return guarded, "strict_magic_guard", 1
    if invocation == "bytes_pe_timestamp" or source == "profiled_shared_extractor":
        return ("pe",), "invocation_adapter", 1
    if invocation == "text":
        return ("script", "data"), "invocation_adapter", 1
    if source == "shared_extractor" or (
        source == "malware_family_script" and callable_name == "extract_config"
    ):
        payload_formats = tuple(sorted(KNOWN_INPUT_FORMATS.difference({"any"})))
        return (
            payload_formats,
            "bounded_payload_adapter",
            1,
        )
    return ("any",), "legacy_unrestricted", 1


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
                tree = _module_tree(path)
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
                try:
                    input_formats, contract_source, evidence_score = _handler_contract(
                        path,
                        callable_name,
                        invocation,
                        "malware_family_script",
                    )
                except (SyntaxError, ValueError) as exc:
                    input_formats, contract_source, evidence_score = ("any",), "invalid", 1
                    supported = False
                    shape_reason = f"handler_contract_error:{type(exc).__name__}:{exc}"
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
                        input_formats=input_formats,
                        input_contract_source=contract_source,
                        minimum_evidence_score=evidence_score,
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
        try:
            input_formats, contract_source, evidence_score = _handler_contract(
                path, "extract", invocation, "shared_extractor"
            )
        except (SyntaxError, ValueError) as exc:
            input_formats, contract_source, evidence_score = ("any",), "invalid", 1
            supported = False
            reason = f"handler_contract_error:{type(exc).__name__}:{exc}"
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
                input_formats=input_formats,
                input_contract_source=contract_source,
                minimum_evidence_score=evidence_score,
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
                input_formats=("pe", "script", "data"),
                input_contract_source="profile_definition",
                minimum_evidence_score=1,
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
        "format_constrained_handler_count": sum("any" not in item.input_formats for item in specs),
        "legacy_unrestricted_automatic_count": sum(
            item.automatic and item.input_contract_source == "legacy_unrestricted"
            for item in specs
        ),
        "declared_contract_handler_count": sum(item.input_contract_source == "module_declaration" for item in specs),
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


def clear_handler_caches() -> None:
    """同一process内の次回batchが変更済みsourceを再読込できるようにする。"""

    _module_tree.cache_clear()
    load_handler.cache_clear()



def _sanitize_url(value: str) -> str:
    try:
        parsed = urlsplit(value)
    except ValueError:
        return "[REDACTED_INVALID_URL]"
    if parsed.scheme.lower() not in {"http", "https", "ftp"}:
        return value
    try:
        hostname = parsed.hostname
    except ValueError:
        return "[REDACTED_INVALID_URL]"
    if not hostname:
        return "[REDACTED_INVALID_URL]"
    try:
        parsed_port = parsed.port
    except ValueError:
        return "[REDACTED_INVALID_URL]"
    port = f":{parsed_port}" if parsed_port else ""
    original_path = parsed.path
    decoded_path = unquote(original_path, errors="replace")
    sanitized_path = SENSITIVE_URL_PATH.sub(r"/\1/[REDACTED]", decoded_path)
    path = sanitized_path if sanitized_path != decoded_path else original_path
    hostname = hostname.lower()
    if "api.telegram.org" in hostname and path not in {"", "/"}:
        path = "/<redacted>"
    if "discord" in hostname and "webhook" in path.lower():
        path = "/<redacted>"
    if "hooks.slack.com" == hostname and path not in {"", "/"}:
        path = "/<redacted>"
    rendered_host = f"[{hostname}]" if ":" in hostname else hostname
    return urlunsplit((parsed.scheme.lower(), f"{rendered_host}{port}", path, "", ""))


def sanitize_public_value(value: Any, *, key: str = "", depth: int = 0) -> Any:
    """資格情報とバイナリを除去し、JSONへ安全に保存できる値へ変換する。"""

    if depth > MAX_DEPTH:
        return {"truncated": True, "reason": "maximum_depth"}
    if SECRET_KEY.fullmatch(key) and value is not None:
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
        truncated = len(value) > MAX_STRING_LENGTH
        working = value[:MAX_STRING_LENGTH] if truncated else value
        stripped = working.strip()
        if not truncated and stripped.startswith(("{", "[")):
            try:
                parsed_json = json.loads(stripped)
            except (json.JSONDecodeError, RecursionError):
                parsed_json = None
            if isinstance(parsed_json, (dict, list)):
                return sanitize_public_value(parsed_json, key=key, depth=depth + 1)
        result = _sanitize_url(working) if working.lower().startswith(("http://", "https://", "ftp://")) else working
        result = EMAIL.sub("[REDACTED_EMAIL]", result)
        result = SECRET_ASSIGNMENT.sub(lambda match: f"{match.group('prefix')}[REDACTED]", result)
        result = BEARER_CREDENTIAL.sub(lambda match: f"{match.group(1)}[REDACTED]", result)
        result = OPAQUE_CREDENTIAL.sub("[REDACTED_CREDENTIAL]", result)
        return result + "…[truncated]" if truncated else result
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
    try:
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
    except HandlerNoEvidenceError as exc:
        result = {"status": "not_applicable", "reason": str(exc)}
    return {
        "handler": spec.public(),
        "result": sanitize_public_value(result),
        "executed_sample": False,
        "network_contacted": False,
    }

_DETECTOR_METADATA_KEYS = frozenset(
    {
        'attribution_basis',
        'campaign_confidence',
        'campaign_type',
        'classification_confidence',
        'confidence',
        'detector',
        'error',
        'executed_sample',
        'family',
        'label',
        'malware_type',
        'malware_type_confidence',
        'matched',
        'message',
        'name',
        'network_contacted',
        'note',
        'reason',
        'sample_executed',
        'schema_version',
        'sha256',
        'size',
        'source',
        'source_name',
        'status',
        'type',
    }
)
_FORBIDDEN_CALL_PREFIXES = (
    'boto3.',
    'ftplib.',
    'http.client.',
    'paramiko.',
    'requests.',
    'shutil.',
    'smtplib.',
    'socket.',
    'subprocess.',
    'tempfile.',
    'urllib.request.',
    'winreg.',
)
_FORBIDDEN_CALL_NAMES = frozenset(
    {
        '__import__',
        'builtins.open',
        'compile',
        'eval',
        'exec',
        'open',
        'os.mkdir',
        'os.makedirs',
        'os.popen',
        'os.remove',
        'os.rename',
        'os.replace',
        'os.rmdir',
        'os.spawnl',
        'os.spawnle',
        'os.spawnlp',
        'os.spawnlpe',
        'os.spawnv',
        'os.spawnve',
        'os.spawnvp',
        'os.spawnvpe',
        'os.startfile',
        'os.system',
        'os.unlink',
    }
)
_FORBIDDEN_METHOD_NAMES = frozenset(
    {
        'chmod',
        'chown',
        'connect',
        'mkdir',
        'rename',
        'rmdir',
        'send',
        'sendall',
        'touch',
        'unlink',
        'write_bytes',
        'write_text',
    }
)


def _ast_call_name(node: ast.AST) -> str | None:
    '''呼出式を静的なドット区切り名へ変換する。'''

    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _ast_call_name(node.value)
        return f'{parent}.{node.attr}' if parent else node.attr
    return None


def _import_aliases(tree: ast.Module) -> dict[str, str]:
    '''module内import aliasを副作用APIの完全名へ展開できる形にする。'''

    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for item in node.names:
                aliases[item.asname or item.name.split('.')[0]] = item.name
        elif isinstance(node, ast.ImportFrom) and node.module:
            for item in node.names:
                if item.name != '*':
                    aliases[item.asname or item.name] = f'{node.module}.{item.name}'
    return aliases


def _expanded_call_name(node: ast.Call, aliases: Mapping[str, str]) -> str | None:
    name = _ast_call_name(node.func)
    if not name:
        return None
    first, separator, remainder = name.partition('.')
    replacement = aliases.get(first)
    if not replacement:
        return name
    return replacement + (separator + remainder if separator else '')


def _open_call_writes(node: ast.Call) -> bool:
    '''open系呼出しが書込みmodeを明示するか返す。'''

    values: list[ast.AST] = []
    if len(node.args) >= 2:
        values.append(node.args[1])
    values.extend(item.value for item in node.keywords if item.arg == 'mode')
    for value in values:
        if isinstance(value, ast.Constant) and isinstance(value.value, str):
            if any(marker in value.value for marker in ('w', 'a', 'x', '+')):
                return True
    return False


def _forbidden_call_reason(node: ast.Call, aliases: Mapping[str, str]) -> str | None:
    name = _expanded_call_name(node, aliases)
    if not name:
        return None
    if name in _FORBIDDEN_CALL_NAMES or name.startswith(_FORBIDDEN_CALL_PREFIXES):
        return f'forbidden_call:{name}'
    if name.startswith(('ctypes.windll', 'ctypes.WinDLL', 'ctypes.CDLL', 'ctypes.PyDLL')):
        return f'forbidden_native_call:{name}'
    if name.rsplit('.', 1)[-1] in _FORBIDDEN_METHOD_NAMES:
        return f'forbidden_side_effect_method:{name}'
    if name.rsplit('.', 1)[-1] == 'open' and _open_call_writes(node):
        return f'forbidden_write_open:{name}'
    return None


def _reachable_handler_functions(tree: ast.Module, callable_name: str) -> list[ast.FunctionDef]:
    '''entryから名前で到達可能なmodule内関数を決定的に列挙する。'''

    functions = {
        node.name: node
        for node in tree.body
        if isinstance(node, ast.FunctionDef)
    }
    pending = [callable_name]
    visited: set[str] = set()
    result: list[ast.FunctionDef] = []
    while pending:
        name = pending.pop(0)
        if name in visited or name not in functions:
            continue
        visited.add(name)
        function = functions[name]
        result.append(function)
        local_calls = sorted(
            {
                node.func.id
                for node in ast.walk(function)
                if isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id in functions
            }
        )
        pending.extend(item for item in local_calls if item not in visited)
    return result


def _handler_side_effect_issues(path: Path, callable_name: str) -> list[str]:
    '''import時とhandler到達関数に外部副作用APIがないかASTだけで検査する。'''

    tree = _module_tree(path)
    aliases = _import_aliases(tree)
    issues: set[str] = set()
    for statement in tree.body:
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for node in ast.walk(statement):
            if isinstance(node, ast.Call):
                reason = _forbidden_call_reason(node, aliases)
                if reason:
                    issues.add(f'import_time:{reason}')
    for function in _reachable_handler_functions(tree, callable_name):
        for node in ast.walk(function):
            if not isinstance(node, ast.Call):
                continue
            reason = _forbidden_call_reason(node, aliases)
            if reason:
                issues.add(f'reachable:{function.name}:{reason}')
    return sorted(issues)


def preflight_handler_for_assessment(
    spec: HandlerSpec,
    *,
    actual_format: str,
    input_size: int,
    maximum_input_size: int = DEFAULT_MAXIMUM_ASSESSMENT_LAYER_SIZE,
) -> dict[str, Any]:
    '''候補試行前に契約、形式、容量、外部副作用をimportせず検証する。'''

    blockers: list[str] = []
    if not spec.automatic:
        blockers.append('handler_not_automatic')
    if not spec.supported_interface:
        blockers.append(f'unsupported_interface:{spec.reason}')
    if actual_format not in KNOWN_INPUT_FORMATS or actual_format == 'any':
        blockers.append(f'unknown_input_format:{actual_format}')
    if 'any' in spec.input_formats:
        blockers.append('unbounded_input_format_contract')
    elif actual_format not in spec.input_formats:
        blockers.append(f'incompatible_input_format:{actual_format}')
    if not isinstance(input_size, int) or isinstance(input_size, bool) or input_size <= 0:
        blockers.append('invalid_or_empty_input_size')
    if (
        not isinstance(maximum_input_size, int)
        or isinstance(maximum_input_size, bool)
        or maximum_input_size <= 0
        or maximum_input_size > DEFAULT_MAXIMUM_ASSESSMENT_LAYER_SIZE
    ):
        blockers.append('invalid_maximum_input_size')
    elif isinstance(input_size, int) and input_size > maximum_input_size:
        blockers.append('input_size_limit_exceeded')

    source_sha256 = None
    try:
        path = _resolve_handler_path(spec)
        source_sha256 = hashlib.sha256(path.read_bytes()).hexdigest()
        if spec.source == 'profiled_shared_extractor':
            expected_profiled_path = (EXTRACTORS_ROOT / 'profiled_family.py').resolve()
            if (
                path.resolve() != expected_profiled_path
                or spec.callable_name != 'extractor_for'
                or spec.invocation != 'profiled_bytes_name'
                or spec.input_contract_source != 'profile_definition'
            ):
                blockers.append('profiled_handler_contract_changed')
        else:
            invocation, supported, _reason = _function_shape(path, spec.callable_name)
            if not supported or invocation != spec.invocation:
                blockers.append('callable_contract_changed')
            formats, source, evidence_score = _handler_contract(
                path,
                spec.callable_name,
                invocation,
                spec.source,
            )
            if (
                formats != spec.input_formats
                or source != spec.input_contract_source
                or evidence_score != spec.minimum_evidence_score
            ):
                blockers.append('handler_contract_changed')
        blockers.extend(_handler_side_effect_issues(path, spec.callable_name))
    except Exception as exc:
        blockers.append(
            str(sanitize_public_value(f'preflight_error:{type(exc).__name__}:{exc}'))
        )
    return {
        'handler_id': spec.id,
        'eligible': not blockers,
        'blockers': sorted(set(blockers)),
        'actual_format': actual_format,
        'accepted_formats': list(spec.input_formats),
        'input_size': input_size,
        'maximum_input_size': maximum_input_size,
        'minimum_evidence_score': spec.minimum_evidence_score,
        'source_sha256': source_sha256,
        'sample_execution_allowed': False,
        'network_allowed': False,
        'filesystem_write_allowed': False,
    }


def _mapping_value(value: Any, key: str, default: Any = None) -> Any:
    if isinstance(value, Mapping):
        return value.get(key, default)
    return getattr(value, key, default)


def _normalized_assessment_layers(
    layers: Sequence[Any],
    *,
    maximum_layer_size: int,
    maximum_total_size: int,
) -> list[dict[str, Any]]:
    '''StaticLayerまたは同等mappingをhash検証済み内部recordへ変換する。'''

    if not isinstance(layers, Sequence) or isinstance(layers, (str, bytes, bytearray)):
        raise TypeError('layersはsequenceで指定してください')
    if not 1 <= len(layers) <= MAX_ASSESSMENT_LAYERS:
        raise ValueError(f'layer数が不正です: {len(layers)}')
    if (
        not isinstance(maximum_layer_size, int)
        or isinstance(maximum_layer_size, bool)
        or not 1 <= maximum_layer_size <= DEFAULT_MAXIMUM_ASSESSMENT_LAYER_SIZE
    ):
        raise ValueError('maximum_layer_sizeが不正です')
    if (
        not isinstance(maximum_total_size, int)
        or isinstance(maximum_total_size, bool)
        or not 1 <= maximum_total_size <= DEFAULT_MAXIMUM_ASSESSMENT_TOTAL_SIZE
    ):
        raise ValueError('maximum_total_sizeが不正です')

    from unpackers.static_unpacker import detect_format

    normalized: list[dict[str, Any]] = []
    seen: set[str] = set()
    total = 0
    for index, supplied in enumerate(layers):
        data = _mapping_value(supplied, 'data')
        name = _mapping_value(supplied, 'name')
        if not isinstance(data, bytes):
            raise TypeError(f'layer[{index}].dataはimmutable bytesで指定してください')
        if (
            not isinstance(name, str)
            or not name
            or len(name) > 4_096
            or any(ord(character) < 32 or ord(character) == 127 for character in name)
        ):
            raise ValueError(f'layer[{index}].nameが不正です')
        digest = hashlib.sha256(data).hexdigest()
        supplied_digest = _mapping_value(supplied, 'sha256', digest)
        if supplied_digest != digest:
            raise ValueError(f'layer[{index}]のSHA-256がdataと一致しません')
        if digest in seen:
            raise ValueError(f'layer SHA-256が重複しています: {digest}')
        seen.add(digest)
        total += len(data)
        if total > maximum_total_size:
            raise ValueError('layer総容量上限を超えています')
        detected_format = detect_format(data, name)
        supplied_format = _mapping_value(supplied, 'format')
        if supplied_format is not None and supplied_format != detected_format:
            raise ValueError(f'layer[{index}].formatがdataの識別結果と一致しません')
        actual_format = detected_format
        parent = _mapping_value(supplied, 'parent_sha256')
        if parent is not None and (
            not isinstance(parent, str) or re.fullmatch(r'[0-9a-f]{64}', parent) is None
        ):
            raise ValueError(f'layer[{index}].parent_sha256が不正です')
        depth = _mapping_value(supplied, 'depth', 0)
        transform = _mapping_value(supplied, 'transform', 'unknown')
        if not isinstance(depth, int) or isinstance(depth, bool) or not 0 <= depth <= 64:
            raise ValueError(f'layer[{index}].depthが不正です')
        if (
            not isinstance(transform, str)
            or not transform
            or len(transform) > 240
            or any(ord(character) < 32 or ord(character) == 127 for character in transform)
        ):
            raise ValueError(f'layer[{index}].transformが不正です')
        normalized.append(
            {
                'index': index,
                'name': name,
                'data': data,
                'sha256': digest,
                'parent_sha256': parent,
                'depth': depth,
                'transform': transform,
                'format': actual_format,
                'size': len(data),
            }
        )
    known_hashes = {str(layer['sha256']) for layer in normalized}
    for layer in normalized:
        parent = layer['parent_sha256']
        if parent is not None and parent not in known_hashes:
            raise ValueError(f'layerの親SHA-256が入力集合にありません: {parent}')
        current = str(layer['sha256'])
        visited: set[str] = set()
        while current:
            if current in visited:
                raise ValueError('layer親子関係に循環があります')
            visited.add(current)
            current = next(
                (
                    str(item['parent_sha256'])
                    for item in normalized
                    if item['sha256'] == current and item['parent_sha256'] is not None
                ),
                '',
            )
    return normalized


def _candidate_records(candidates: Sequence[Any]) -> list[dict[str, Any]]:
    '''候補familyを正規化し、同一familyのsourceだけを統合する。'''

    if not isinstance(candidates, Sequence) or isinstance(candidates, (str, bytes, bytearray)):
        raise TypeError('candidatesはsequenceで指定してください')
    if not 1 <= len(candidates) <= MAX_ASSESSMENT_CANDIDATES:
        raise ValueError(f'候補family数が不正です: {len(candidates)}')
    merged: dict[str, set[str]] = {}
    for index, supplied in enumerate(candidates):
        if isinstance(supplied, str):
            family = supplied
            sources = ['unspecified_candidate']
        elif isinstance(supplied, Mapping):
            family = supplied.get('family')
            raw_sources = supplied.get('sources', supplied.get('source', []))
            sources = [raw_sources] if isinstance(raw_sources, str) else list(raw_sources or [])
        else:
            raise TypeError(f'candidate[{index}]が不正です')
        if not isinstance(family, str) or FAMILY_ID.fullmatch(family) is None:
            raise ValueError(f'candidate[{index}].familyが不正です')
        if any(
            not isinstance(item, str)
            or not item
            or len(item) > 120
            or any(ord(character) < 32 or ord(character) == 127 for character in item)
            for item in sources
        ):
            raise ValueError(f'candidate[{index}].sourcesが不正です')
        merged.setdefault(family, set()).update(sources or ['unspecified_candidate'])
    return [
        {'family': family, 'sources': sorted(sources)}
        for family, sources in sorted(merged.items())
    ]


def _meaningful_detector_value(value: Any, *, key: str = '', depth: int = 0) -> bool:
    '''confidence等の自己申告を除き、detectorの独立した実値があるか返す。'''

    if depth > 20 or value is None or value is False:
        return False
    if isinstance(value, bool):
        return key.casefold() not in _DETECTOR_METADATA_KEYS
    if isinstance(value, str):
        return bool(value.strip()) and key.casefold() not in _DETECTOR_METADATA_KEYS
    if isinstance(value, (int, float)):
        return value != 0 and key.casefold() not in _DETECTOR_METADATA_KEYS
    if isinstance(value, Mapping):
        return any(
            str(item_key).casefold() not in _DETECTOR_METADATA_KEYS
            and _meaningful_detector_value(item, key=str(item_key), depth=depth + 1)
            for item_key, item in value.items()
        )
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return any(
            _meaningful_detector_value(item, key=key, depth=depth + 1)
            for item in value[:10_000]
        )
    return False


def detector_corroboration(value: Any) -> dict[str, Any]:
    '''classifier評価またはdetector戻り値から独立裏付けの有無を判定する。'''

    if not isinstance(value, Mapping):
        return {'corroborated': False, 'score': 0, 'basis': 'missing_detector_evidence'}
    if value.get('known_outer_sha256') is True:
        return {'corroborated': True, 'score': 30_000, 'basis': 'known_outer_sha256'}
    if value.get('known_inner_sha256') is True:
        return {'corroborated': True, 'score': 30_000, 'basis': 'known_inner_sha256'}
    detection = value.get('detection') if isinstance(value.get('detection'), Mapping) else value
    matched = (
        value.get('detector_matched') is True
        and detection.get('matched') is True
    ) or (
        'detector_matched' not in value and detection.get('matched') is True
    )
    if not matched:
        return {'corroborated': False, 'score': 0, 'basis': 'detector_not_matched'}
    payload = {
        key: item
        for key, item in detection.items()
        if str(key).casefold() not in _DETECTOR_METADATA_KEYS
    }
    if not _meaningful_detector_value(payload):
        return {
            'corroborated': False,
            'score': 0,
            'basis': 'matched_boolean_without_independent_evidence',
        }
    return {'corroborated': True, 'score': 20_000, 'basis': 'detector_structural_evidence'}


def collect_detector_evaluations(
    layer_classifications: Sequence[Any],
) -> dict[str, dict[str, dict[str, Any]]]:
    '''既存layer分類結果を候補試行API用のfamily・SHA-256索引へ変換する。'''

    result: dict[str, dict[str, dict[str, Any]]] = {}
    for index, record in enumerate(layer_classifications):
        layer = _mapping_value(record, 'layer')
        classification = _mapping_value(record, 'classification', {})
        digest = _mapping_value(layer, 'sha256')
        if not isinstance(digest, str) or re.fullmatch(r'[0-9a-f]{64}', digest) is None:
            raise ValueError(f'layer_classifications[{index}]のSHA-256が不正です')
        evaluations = classification.get('detector_evaluations', []) if isinstance(classification, Mapping) else []
        if not isinstance(evaluations, list):
            raise ValueError(f'layer_classifications[{index}].detector_evaluationsが不正です')
        for evaluation in evaluations:
            if not isinstance(evaluation, Mapping):
                continue
            family = evaluation.get('malware_type')
            if isinstance(family, str) and FAMILY_ID.fullmatch(family):
                result.setdefault(family, {})[digest] = dict(evaluation)
    return result


def _detector_evidence_by_layer(
    detector_evaluations: Mapping[str, Any] | None,
    family: str,
    layers: Sequence[Mapping[str, Any]],
) -> dict[str, dict[str, Any]]:
    supplied = detector_evaluations.get(family) if isinstance(detector_evaluations, Mapping) else None
    if supplied is None:
        return {}
    layer_hashes = {str(layer['sha256']) for layer in layers}
    if isinstance(supplied, Mapping) and any(
        key in supplied
        for key in ('matched', 'detector_matched', 'known_outer_sha256', 'known_inner_sha256')
    ):
        return {str(layers[0]['sha256']): detector_corroboration(supplied)}
    if not isinstance(supplied, Mapping):
        raise TypeError(f'detector_evaluations[{family}]が不正です')
    return {
        digest: detector_corroboration(value)
        for digest, value in supplied.items()
        if digest in layer_hashes
    }


def _lineage_distance(
    source_sha256: str,
    target_sha256: str,
    parents: Mapping[str, str | None],
) -> int | None:
    '''同一、祖先、子孫ならedge距離を返し、兄弟・無関係ならNoneを返す。'''

    if source_sha256 == target_sha256:
        return 0
    for start, goal in ((source_sha256, target_sha256), (target_sha256, source_sha256)):
        distance = 0
        current: str | None = start
        visited: set[str] = set()
        while current and current not in visited:
            visited.add(current)
            current = parents.get(current)
            distance += 1
            if current == goal:
                return distance
    return None


def _best_detector_for_layer(
    layer_sha256: str,
    evidence_by_layer: Mapping[str, Mapping[str, Any]],
    parents: Mapping[str, str | None],
) -> dict[str, Any]:
    candidates = []
    for digest, evidence in evidence_by_layer.items():
        if evidence.get('corroborated') is not True:
            continue
        distance = _lineage_distance(layer_sha256, digest, parents)
        if distance is None:
            continue
        candidates.append((int(evidence.get('score', 0)), -distance, digest, evidence))
    if not candidates:
        return {'corroborated': False, 'score': 0, 'basis': 'no_corroborated_detector_in_lineage'}
    _score, negative_distance, digest, selected = max(candidates)
    return {
        **selected,
        'layer_sha256': digest,
        'lineage_distance': -negative_distance,
    }


def assess_candidate_handlers(
    candidates: Sequence[Any],
    layers: Sequence[Any],
    *,
    detector_evaluations: Mapping[str, Any] | None = None,
    specs: Sequence[HandlerSpec] | None = None,
    maximum_layer_size: int = DEFAULT_MAXIMUM_ASSESSMENT_LAYER_SIZE,
    maximum_total_size: int = DEFAULT_MAXIMUM_ASSESSMENT_TOTAL_SIZE,
    maximum_attempts: int = MAX_ASSESSMENT_ATTEMPTS,
) -> dict[str, Any]:
    '''候補familyの自動handlerを全復元layerへ安全に試行し、裏付け結果を返す。'''

    if (
        not isinstance(maximum_attempts, int)
        or isinstance(maximum_attempts, bool)
        or not 1 <= maximum_attempts <= MAX_ASSESSMENT_ATTEMPTS
    ):
        raise ValueError('maximum_attemptsが不正です')
    normalized_layers = _normalized_assessment_layers(
        layers,
        maximum_layer_size=maximum_layer_size,
        maximum_total_size=maximum_total_size,
    )
    normalized_candidates = _candidate_records(candidates)
    catalog = list(specs) if specs is not None else discover_handlers()
    by_family = {
        candidate['family']: sorted(
            (
                spec
                for spec in catalog
                if spec.family == candidate['family'] and spec.automatic
            ),
            key=lambda item: item.id,
        )
        for candidate in normalized_candidates
    }
    planned_attempts = sum(
        len(by_family[candidate['family']]) * len(normalized_layers)
        for candidate in normalized_candidates
    )
    if planned_attempts > maximum_attempts:
        raise ValueError(
            f'候補試行数上限を超えています: {planned_attempts} > {maximum_attempts}'
        )

    from analysis_contract import handler_result_quality

    parents = {
        str(layer['sha256']): layer.get('parent_sha256')
        for layer in normalized_layers
    }
    family_results = []
    confirmed_families = []
    for candidate in normalized_candidates:
        family = str(candidate['family'])
        evidence_by_layer = _detector_evidence_by_layer(
            detector_evaluations,
            family,
            normalized_layers,
        )
        attempts = []
        for spec in by_family[family]:
            for layer in normalized_layers:
                public_layer = {
                    key: layer[key]
                    for key in (
                        'index',
                        'name',
                        'sha256',
                        'parent_sha256',
                        'depth',
                        'transform',
                        'format',
                        'size',
                    )
                }
                preflight = preflight_handler_for_assessment(
                    spec,
                    actual_format=str(layer['format']),
                    input_size=int(layer['size']),
                    maximum_input_size=maximum_layer_size,
                )
                attempt: dict[str, Any] = {
                    'handler_id': spec.id,
                    'family': family,
                    'layer': public_layer,
                    'preflight': preflight,
                }
                if not preflight['eligible']:
                    attempts.append({**attempt, 'status': 'preflight_blocked'})
                    continue
                current_source_sha256 = hashlib.sha256(
                    _resolve_handler_path(spec).read_bytes()
                ).hexdigest()
                if current_source_sha256 != preflight['source_sha256']:
                    attempts.append(
                        {
                            **attempt,
                            'status': 'preflight_blocked',
                            'preflight': {
                                **preflight,
                                'eligible': False,
                                'blockers': ['source_changed_after_preflight'],
                            },
                        }
                    )
                    continue
                try:
                    executed = execute_handler(spec, layer['data'], str(layer['name']))
                    quality = handler_result_quality(
                        executed.get('result'),
                        minimum_score=spec.minimum_evidence_score,
                    )
                except Exception as exc:
                    attempts.append(
                        {
                            **attempt,
                            'status': 'failed',
                            'error': sanitize_public_value(f'{type(exc).__name__}: {exc}'),
                        }
                    )
                    continue
                detector = _best_detector_for_layer(
                    str(layer['sha256']),
                    evidence_by_layer,
                    parents,
                )
                if not quality['sufficient']:
                    status = 'no_evidence'
                elif detector['corroborated']:
                    status = 'corroborated'
                else:
                    status = 'handler_evidence_without_detector'
                attempts.append(
                    {
                        **attempt,
                        'status': status,
                        'handler_evidence': quality,
                        'detector_corroboration': detector,
                        'result': executed,
                    }
                )
        statuses = {item['status'] for item in attempts}
        detector_available = any(
            item.get('corroborated') is True for item in evidence_by_layer.values()
        )
        if 'corroborated' in statuses:
            family_status = 'confirmed'
            confirmed_families.append(family)
        elif 'handler_evidence_without_detector' in statuses:
            family_status = 'handler_evidence_without_detector'
        elif detector_available:
            family_status = 'detector_only'
        elif 'failed' in statuses:
            family_status = 'handler_failed'
        elif attempts:
            family_status = 'no_evidence'
        else:
            family_status = 'no_automatic_handler'
        family_results.append(
            {
                **candidate,
                'status': family_status,
                'confirmed': family_status == 'confirmed',
                'detector_layers': {
                    digest: evidence
                    for digest, evidence in sorted(evidence_by_layer.items())
                },
                'attempts': attempts,
            }
        )
    return {
        'schema_version': 1,
        'status': 'confirmed' if confirmed_families else 'no_confirmed_family',
        'confirmed_families': sorted(confirmed_families),
        'candidate_count': len(normalized_candidates),
        'layer_count': len(normalized_layers),
        'planned_attempt_count': planned_attempts,
        'families': family_results,
        'metadata_hint_can_confirm': False,
        'confirmation_requirement': 'handler_evidence_and_detector_corroboration_in_same_lineage',
        'executed_sample': False,
        'network_contacted': False,
        'filesystem_written_by_handlers': False,
    }
