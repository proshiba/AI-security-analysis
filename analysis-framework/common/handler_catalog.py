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
