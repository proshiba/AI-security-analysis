#!/usr/bin/env python3
"""既存の静的解析関数を棚卸しし、安全な共通インターフェースで実行する。"""

from __future__ import annotations

import ast
import base64
import hashlib
import importlib.abc
import importlib.machinery
import importlib.util
import io
import json
import math
import os
import re
import stat
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable, Mapping, Sequence
from contextlib import contextmanager, redirect_stderr, redirect_stdout
from dataclasses import asdict, dataclass
from functools import cache
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit, urlunsplit

FRAMEWORK_ROOT = Path(__file__).resolve().parents[1]
REPOSITORY_ROOT = FRAMEWORK_ROOT.parent
MALWARE_ROOT = FRAMEWORK_ROOT / "malware"
EXTRACTORS_ROOT = REPOSITORY_ROOT / "extractors"
PROFILE_PATH = EXTRACTORS_ROOT / "profiles" / "windows_family_profiles.json"
FAMILY_ID = re.compile(r"^[a-z0-9_-]+$")
EMAIL = re.compile(r"(?<![\w.+-])[\w.+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?![\w.-])")
SECRET_ASSIGNMENT = re.compile(
    r"(?i)(?P<prefix>[\"']?(?:password|passwd|secret|token|api[_-]?key|auth[_-]?key|"
    r"client[_-]?secret|aws[_-]?(?:access[_-]?key[_-]?id|secret[_-]?access[_-]?key))"
    r"[\"']?\s*[:=]\s*)(?P<secret>\"[^\"]*\"|'[^']*'|[^\s,;}]+)"
)
BEARER_CREDENTIAL = re.compile(
    r"(?i)(\b(?:authorization\s*:\s*)?bearer\s+)([^\s,;\"']+)"
)
OPAQUE_CREDENTIAL = re.compile(
    r"(?i)\b(?:github_pat_[A-Za-z0-9_]{20,}|gh[pousr]_[A-Za-z0-9_]{20,}|"
    r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})\b"
)
AWS_ACCESS_KEY_ID = re.compile(
    r"(?<![A-Z0-9])(?:AKIA|ASIA|AIDA|AROA|AIPA|ANPA|ANVA|ASCA)[A-Z0-9]{16}(?![A-Z0-9])"
)
HIGH_CONFIDENCE_CREDENTIAL = re.compile(
    r"(?i)(?<![A-Za-z0-9_-])(?:"
    r"xox[baprs]-[A-Za-z0-9-]{10,}|"
    r"sk_live_[A-Za-z0-9]{16,}|rk_live_[A-Za-z0-9]{16,}|"
    r"AIza[A-Za-z0-9_-]{30,}|"
    r"npm_[A-Za-z0-9]{20,}|pypi-[A-Za-z0-9_-]{20,}"
    r")(?![A-Za-z0-9_-])"
)
PEM_PRIVATE_KEY = re.compile(
    r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----"
    r".*?-----END (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----",
    re.DOTALL,
)
SENSITIVE_URL_PATH = re.compile(
    r"(?i)/((?:access[_-]?)?token|api[_-]?key|auth(?:orization)?|"
    r"password|client[_-]?secret|secret)/[^/]+"
)
SENSITIVE_URL_ASSIGNMENT = re.compile(
    r'(?i)([/;])((?:access[_-]?)?token|api[_-]?key|auth(?:orization)?|'
    r'password|client[_-]?secret|secret)(?:=|:)[^/?#;]+'
)
SECRET_KEY = re.compile(
    r"(?i)^(?:password|passwd|secret|token|api[_-]?key|auth[_-]?key|"
    r"auth(?:entication)?[_-]?token|access[_-]?token|refresh[_-]?token|bot[_-]?token|"
    r"authorization|bearer|cookies?|session[_-]?(?:id|token)|client[_-]?secret|"
    r"private[_-]?key|webhook[_-]?(?:secret|token)|"
    r"aws[_-]?(?:access[_-]?key[_-]?id|secret[_-]?access[_-]?key|session[_-]?token)|"
    r"username|email|credentials?)$"
)
MAX_DEPTH = 24
MAX_COLLECTION_ITEMS = 20_000
MAX_STRING_LENGTH = 65_536
HANDLER_CONTRACT_NAME = "HANDLER_CONTRACT"
DEFAULT_MAXIMUM_ASSESSMENT_LAYER_SIZE = 128 * 1024 * 1024
DEFAULT_MAXIMUM_ASSESSMENT_TOTAL_SIZE = 256 * 1024 * 1024
MAX_ASSESSMENT_CANDIDATES = 64
MAX_ASSESSMENT_LAYERS = 128
MAX_ASSESSMENT_ATTEMPTS = 64
MAX_ASSESSMENT_WALL_SECONDS = 300.0
MAX_ASSESSMENT_TOTAL_RESPONSE_BYTES = 16 * 1024 * 1024
MAX_ASSESSMENT_RETAINED_ATTEMPT_DETAILS = 64
MAX_ASSESSMENT_VERIFIED_OUTPUTS = 4_096
MAX_ASSESSMENT_IMPORT_DEPTH = 12
MAX_ASSESSMENT_IMPORT_FILES = 96
MAX_ASSESSMENT_SOURCE_FILE_SIZE = 8 * 1024 * 1024
MAX_ASSESSMENT_SOURCE_TOTAL_SIZE = 32 * 1024 * 1024
DEFAULT_HANDLER_TIMEOUT_SECONDS = 30.0
MAX_HANDLER_TIMEOUT_SECONDS = 300.0
MAX_VERIFIED_BINARY_OUTPUTS = 64
MAX_VERIFIED_BINARY_TOTAL_SIZE = 256 * 1024 * 1024
MAX_HANDLER_WORKER_REQUEST_SIZE = 65_536
MAX_HANDLER_WORKER_OUTPUT_SIZE = 16 * 1024 * 1024
MAX_PUBLIC_RESULT_ENTRIES = 4_096
MAX_PUBLIC_RESULT_TOTAL_STRING_CHARS = 2 * 1024 * 1024
MAX_PUBLIC_RESULT_TOTAL_BINARY_BYTES = 256 * 1024 * 1024
VERIFIED_BINARY_KINDS = frozenset({'archive', 'binary', 'elf', 'macho', 'pe', 'script'})
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


@dataclass(frozen=True)
class _DependencySourceSnapshot:
    relative_path: str
    resolved_path: Path
    sha256: str
    source: bytes


@dataclass(frozen=True)
class _DependencyDataSnapshot:
    relative_path: str
    resolved_path: Path
    sha256: str
    data: bytes


@dataclass
class _PublicValueBudget:
    entries: int = 0
    string_characters: int = 0
    binary_bytes: int = 0
    truncated: bool = False
    reasons: set[str] | None = None

    def __post_init__(self) -> None:
        if self.reasons is None:
            self.reasons = set()

    def reject(self, reason: str) -> dict[str, Any]:
        self.truncated = True
        assert self.reasons is not None
        self.reasons.add(reason)
        return {"truncated": True, "reason": reason}


@dataclass(frozen=True)
class _VerifiedModuleBinding:
    fullname: str
    snapshot: _DependencySourceSnapshot
    is_package: bool


class HandlerLoadError(RuntimeError):
    """解析ハンドラーの許可リスト検証または読み込みに失敗した。"""


class HandlerNoEvidenceError(ValueError):
    """入力は解析できたが、対象variantの適用証拠がないことを表す。"""


@cache
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
        ) or (
            isinstance(node, ast.AnnAssign)
            and isinstance(node.target, ast.Name)
            and node.target.id == HANDLER_CONTRACT_NAME
        ):
            value_node = node.value
        if value_node is None:
            continue
        value = ast.literal_eval(value_node)
        if not isinstance(value, dict):
            raise TypeError(f"{HANDLER_CONTRACT_NAME}はobjectで宣言してください")
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
        from analysis_contract import ensure_no_reparse_components

        ensure_no_reparse_components(REPOSITORY_ROOT)
        ensure_no_reparse_components(REPOSITORY_ROOT / requested)
        resolved = (REPOSITORY_ROOT / requested).resolve(strict=True)
    except (OSError, FileNotFoundError) as exc:
        raise HandlerLoadError(f"handler path does not exist: {spec.relative_path}") from exc
    allowed = (MALWARE_ROOT.resolve(), EXTRACTORS_ROOT.resolve())
    if not any(resolved == root or root in resolved.parents for root in allowed):
        raise HandlerLoadError(f"handler path is outside the allowlist: {resolved}")
    if not resolved.is_file() or resolved.suffix.lower() != ".py":
        raise HandlerLoadError(f"handler is not a Python source file: {resolved}")
    return resolved


_LOADED_HANDLER_MODULE_NAMES: set[str] = set()


def _trusted_handler_import_paths(path: Path) -> tuple[Path, ...]:
    """handler import中だけ使用する信頼済み検索pathを重複なしで返す。"""

    dynamic_framework_root = REPOSITORY_ROOT / 'analysis-framework'
    values = (
        REPOSITORY_ROOT,
        dynamic_framework_root,
        dynamic_framework_root / 'common',
        path.parent,
    )
    result: list[Path] = []
    for value in values:
        resolved = value.resolve()
        if resolved not in result:
            result.append(resolved)
    return tuple(result)


def _module_is_repository_local(module: object) -> bool:
    source = getattr(module, '__file__', None)
    if not isinstance(source, str) or not source:
        return False
    try:
        resolved = Path(source).resolve(strict=True)
        root = REPOSITORY_ROOT.resolve(strict=True)
    except OSError:
        return False
    return resolved == root or root in resolved.parents


@contextmanager
def _handler_import_environment(path: Path, *, keep_modules: Sequence[str] = ()):
    """sys.pathとrepository-local moduleをhandler呼出し境界の外へ残さない。"""

    original_path = list(sys.path)
    original_modules = set(sys.modules)
    trusted = [str(item) for item in _trusted_handler_import_paths(path)]
    sys.path[:] = [*trusted, *[item for item in original_path if item not in trusted]]
    try:
        yield
    finally:
        sys.path[:] = original_path
        retained = set(keep_modules)
        for name in tuple(set(sys.modules).difference(original_modules)):
            module = sys.modules.get(name)
            if name not in retained and module is not None and _module_is_repository_local(module):
                sys.modules.pop(name, None)


@cache
def load_handler(spec: HandlerSpec) -> tuple[Callable[..., Any], str]:
    """許可リスト検証後に既存静的解析関数を読み込む。"""

    if not spec.supported_interface:
        raise HandlerLoadError(f"unsupported handler interface: {spec.reason}")
    path = _resolve_handler_path(spec)
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
        with _handler_import_environment(path, keep_modules=(module_name,)):
            module_spec.loader.exec_module(module)
    except Exception:
        if previous_module is None:
            sys.modules.pop(module_name, None)
        else:
            sys.modules[module_name] = previous_module
        raise
    _LOADED_HANDLER_MODULE_NAMES.add(module_name)
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
    _recursive_handler_side_effect_audit.cache_clear()
    _relative_audit_path.cache_clear()
    _resolve_local_module_path.cache_clear()
    load_handler.cache_clear()
    for module_name in tuple(_LOADED_HANDLER_MODULE_NAMES):
        sys.modules.pop(module_name, None)
    _LOADED_HANDLER_MODULE_NAMES.clear()



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
    sanitized_path = SENSITIVE_URL_ASSIGNMENT.sub(r'\1\2=[REDACTED]', sanitized_path)
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


def _sanitize_public_text(value: str) -> str:
    """自由文字列からURL資格情報、token、メールアドレスを除去する。"""

    stripped = value.strip()
    result = (
        _sanitize_url(stripped)
        if stripped.lower().startswith(('http://', 'https://', 'ftp://'))
        else value
    )
    result = EMAIL.sub('[REDACTED_EMAIL]', result)
    result = SECRET_ASSIGNMENT.sub(
        lambda match: f"{match.group('prefix')}[REDACTED]",
        result,
    )
    result = BEARER_CREDENTIAL.sub(
        lambda match: f"{match.group(1)}[REDACTED]",
        result,
    )
    result = PEM_PRIVATE_KEY.sub('[REDACTED_PRIVATE_KEY]', result)
    result = AWS_ACCESS_KEY_ID.sub('[REDACTED_AWS_ACCESS_KEY_ID]', result)
    result = HIGH_CONFIDENCE_CREDENTIAL.sub('[REDACTED_CREDENTIAL]', result)
    return OPAQUE_CREDENTIAL.sub('[REDACTED_CREDENTIAL]', result)


def _stable_public_sort_key(value: Any) -> str:
    """set公開値をprocess間で同じ順序に並べる比較keyを返す。"""

    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(',', ':'),
            default=str,
        )
    except (TypeError, ValueError, RecursionError):
        return f'{type(value).__module__}.{type(value).__qualname__}'


def sanitize_public_value(
    value: Any,
    *,
    key: str = "",
    depth: int = 0,
    _seen: set[int] | None = None,
    _budget: _PublicValueBudget | None = None,
) -> Any:
    """資格情報とバイナリを除去し、JSONへ安全に保存できる値へ変換する。"""

    budget = _budget if _budget is not None else _PublicValueBudget()
    budget.entries += 1
    if budget.entries > MAX_PUBLIC_RESULT_ENTRIES:
        return budget.reject("maximum_total_entries")

    if depth > MAX_DEPTH:
        return budget.reject("maximum_depth")
    if SECRET_KEY.fullmatch(key) and value is not None:
        return "[REDACTED]"
    if isinstance(value, (bytes, bytearray)):
        raw = bytes(value)
        if budget.binary_bytes + len(raw) > MAX_PUBLIC_RESULT_TOTAL_BINARY_BYTES:
            return budget.reject("maximum_total_binary_bytes")
        budget.binary_bytes += len(raw)
        return {
            "type": "bytes",
            "size": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest(),
            "content_exported": False,
        }
    if isinstance(value, Path):
        return _sanitize_public_text(value.name)
    seen = _seen if _seen is not None else set()
    if isinstance(value, dict):
        identity = id(value)
        if identity in seen:
            return {"truncated": True, "reason": "cycle_detected"}
        seen.add(identity)
        result = {}
        collisions: dict[str, int] = {}
        try:
            for index, (item_key, item_value) in enumerate(value.items()):
                if index >= MAX_COLLECTION_ITEMS:
                    result["_truncated"] = True
                    break
                raw_key = str(item_key)[:MAX_STRING_LENGTH]
                if (
                    budget.string_characters + len(raw_key)
                    > MAX_PUBLIC_RESULT_TOTAL_STRING_CHARS
                ):
                    result["_truncated"] = budget.reject(
                        "maximum_total_string_characters"
                    )
                    break
                budget.string_characters += len(raw_key)
                text_key = _sanitize_public_text(raw_key)
                collision_count = collisions.get(text_key, 0) + 1
                collisions[text_key] = collision_count
                output_key = (
                    text_key
                    if collision_count == 1
                    else f'{text_key}[duplicate-{collision_count}]'
                )
                result[output_key] = sanitize_public_value(
                    item_value,
                    key=text_key,
                    depth=depth + 1,
                    _budget=budget,
                    _seen=seen,
                )
            return result
        finally:
            seen.remove(identity)
    if isinstance(value, (list, tuple, set)):
        identity = id(value)
        if identity in seen:
            return [{"truncated": True, "reason": "cycle_detected"}]
        seen.add(identity)
        try:
            if isinstance(value, set) and (
                len(value) + budget.entries > MAX_PUBLIC_RESULT_ENTRIES
                or len(value) > MAX_COLLECTION_ITEMS
            ):
                return [budget.reject("maximum_total_entries")]
            sanitized = []
            truncated = False
            for index, item in enumerate(value):
                if index >= MAX_COLLECTION_ITEMS:
                    truncated = True
                    break
                sanitized.append(
                    sanitize_public_value(
                        item,
                        key=key,
                        depth=depth + 1,
                        _budget=budget,
                        _seen=seen,
                    )
                )
                if budget.truncated:
                    break
            if isinstance(value, set):
                sanitized.sort(key=_stable_public_sort_key)
            if truncated:
                sanitized.append({"truncated": True, "reason": "maximum_items"})
            return sanitized
        finally:
            seen.remove(identity)
    if isinstance(value, str):
        truncated = len(value) > MAX_STRING_LENGTH
        working = value[:MAX_STRING_LENGTH] if truncated else value
        if budget.string_characters + len(working) > MAX_PUBLIC_RESULT_TOTAL_STRING_CHARS:
            return budget.reject("maximum_total_string_characters")
        budget.string_characters += len(working)
        stripped = working.strip()
        if not truncated and stripped.startswith(("{", "[")):
            try:
                parsed_json = json.loads(stripped)
            except (json.JSONDecodeError, RecursionError):
                parsed_json = None
            if isinstance(parsed_json, (dict, list)):
                return sanitize_public_value(
                    parsed_json,
                    key=key,
                    depth=depth + 1,
                    _budget=budget,
                    _seen=seen,
                )
        result = _sanitize_public_text(working)
        return result + "…[truncated]" if truncated else result
    if isinstance(value, float) and not math.isfinite(value):
        return budget.reject("non_finite_number")
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return _sanitize_public_text(str(value)[:MAX_STRING_LENGTH])


def _pe_timestamp(data: bytes) -> int:
    """PEヘッダーからTimeDateStampをロードせず取得する。"""

    if len(data) < 0x40 or not data.startswith(b"MZ"):
        raise HandlerLoadError("PE timestampを取得できる入力ではありません")
    pe_offset = int.from_bytes(data[0x3C:0x40], "little")
    if pe_offset < 0x40 or pe_offset + 12 > len(data) or data[pe_offset:pe_offset + 4] != b"PE\0\0":
        raise HandlerLoadError("PEヘッダーが不正です")
    return int.from_bytes(data[pe_offset + 8:pe_offset + 12], "little")


def _verified_binary_kind(data: bytes) -> str:
    """wrapper自身がmagicを確認し、公開可能なbinary kindへ正規化する。"""

    if data.startswith(b'MZ'):
        return 'pe'
    if data.startswith(b'\x7fELF'):
        return 'elf'
    if data.startswith((b'PK\x03\x04', b'Rar!\x1a\x07', b'7z\xbc\xaf\x27\x1c')):
        return 'archive'
    if data[:4] in {
        b'\xfe\xed\xfa\xce',
        b'\xce\xfa\xed\xfe',
        b'\xfe\xed\xfa\xcf',
        b'\xcf\xfa\xed\xfe',
        b'\xca\xfe\xba\xbe',
    }:
        return 'macho'
    prefix = data[:4_096].lstrip().lower()
    if prefix.startswith((b'#!', b'<hta', b'<html', b'function ', b'var ', b'let ', b'const ')):
        return 'script'
    return 'binary'


def _verified_binary_role(path: Sequence[str], parent: Mapping[str, Any] | None) -> str | None:
    """raw resultの明示的なterminal/final役割だけを採用する。"""

    aliases = {
        'terminal_payload': 'terminal_payload',
        'terminal_payload_bytes': 'terminal_payload',
        'terminal_payload_data': 'terminal_payload',
        'final_payload': 'final_payload',
        'final_payload_bytes': 'final_payload',
        'final_payload_data': 'final_payload',
    }
    normalized_path = tuple(
        segment.strip().casefold().replace('-', '_') for segment in path
    )
    if len(normalized_path) == 1:
        return aliases.get(normalized_path[0])
    allowed_record_keys = {
        'role',
        'data',
        'bytes',
        'kind',
        'type',
        'name',
        'file_name',
        'path',
        'relative_path',
    }
    if parent is not None and set(parent).issubset(allowed_record_keys):
        leaf = normalized_path[-1] if normalized_path else ''
        supplied = parent.get('role')
        if (
            leaf in {'data', 'bytes'}
            and isinstance(supplied, str)
            and supplied in {'terminal_payload', 'final_payload'}
        ):
            return supplied
        if len(normalized_path) == 2 and leaf in {'data', 'bytes'}:
            return aliases.get(normalized_path[0])
    return None


def _safe_verified_binary_path(
    supplied: Any,
    *,
    role: str,
    kind: str,
    digest: str,
) -> str:
    """handler由来pathを安全な相対pathへ制限し、不正時は決定的pathへ置換する。"""

    extension = {
        'archive': 'archive',
        'binary': 'bin',
        'elf': 'elf',
        'macho': 'macho',
        'pe': 'exe',
        'script': 'txt',
    }[kind]
    fallback = f'handler-result/{role}/{digest}.{extension}'
    if not isinstance(supplied, (str, Path)):
        return fallback
    normalized = str(supplied).strip().replace('\\', '/')
    if (
        not normalized
        or len(normalized) > 4_096
        or normalized.startswith('/')
        or re.match(r'^[A-Za-z]:', normalized)
        or '\x00' in normalized
    ):
        return fallback
    parts = normalized.split('/')
    if any(part in {'', '.', '..'} for part in parts):
        return fallback
    sanitized = _sanitize_public_text(normalized)
    if '[REDACTED' in sanitized or sanitized != normalized:
        return fallback
    return normalized


def _stage_verified_binary(artifact_root: Path, digest: str, raw: bytes) -> None:
    """worker一時領域へdigest名でraw bytesを排他的に保存する。"""

    from analysis_contract import ensure_no_reparse_components

    ensure_no_reparse_components(artifact_root)
    resolved_root = artifact_root.resolve(strict=True)
    destination = resolved_root / f'{digest}.payload'
    ensure_no_reparse_components(destination)
    try:
        with destination.open('xb') as stream:
            stream.write(raw)
    except FileExistsError:
        # 同一digestが複数の役割で返る場合だけ既存stageを再利用する。
        with destination.open('rb') as stream:
            existing = stream.read(len(raw) + 1)
        if existing != raw:
            raise HandlerLoadError('worker artifact digest collision')


def _verified_binary_outputs(
    raw_result: Any,
    *,
    artifact_root: Path | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """raw handler resultを有界走査し、実体hash済みterminal/final payloadだけを返す。"""

    outputs: list[dict[str, Any]] = []
    output_keys: set[tuple[str, str, str]] = set()
    seen: set[int] = set()
    binary_values_seen = 0
    binary_bytes_seen = 0
    traversal_items = 0
    reasons: set[str] = set()

    def visit(
        value: Any,
        path: tuple[str, ...],
        parent: Mapping[str, Any] | None,
        depth: int,
    ) -> None:
        nonlocal binary_bytes_seen, binary_values_seen, traversal_items
        if depth > MAX_DEPTH:
            reasons.add('maximum_depth')
            return
        traversal_items += 1
        if traversal_items > MAX_COLLECTION_ITEMS:
            reasons.add('maximum_items')
            return
        if isinstance(value, (bytes, bytearray)):
            binary_values_seen += 1
            size = len(value)
            if size <= 0:
                reasons.add('empty_binary_value')
                return
            if binary_bytes_seen + size > MAX_VERIFIED_BINARY_TOTAL_SIZE:
                reasons.add('maximum_total_binary_size')
                return
            binary_bytes_seen += size
            role = _verified_binary_role(path, parent)
            if role is None:
                return
            if len(outputs) >= MAX_VERIFIED_BINARY_OUTPUTS:
                reasons.add('maximum_verified_outputs')
                return
            raw = bytes(value)
            digest = hashlib.sha256(raw).hexdigest()
            kind = _verified_binary_kind(raw)
            supplied_path = None
            if parent is not None:
                supplied_path = next(
                    (
                        parent.get(key)
                        for key in ('relative_path', 'path', 'name', 'file_name')
                        if parent.get(key) is not None
                    ),
                    None,
                )
            output_path = _safe_verified_binary_path(
                supplied_path,
                role=role,
                kind=kind,
                digest=digest,
            )
            identity = (role, output_path, digest)
            if identity in output_keys:
                return
            output_keys.add(identity)
            outputs.append(
                {
                    'role': role,
                    'kind': kind,
                    'path': output_path,
                    'sha256': digest,
                    'size': size,
                    'verification': {
                        'status': 'artifact_hash_verified',
                        'sha256_matches': True,
                        'size_matches': True,
                    },
                }
            )
            if artifact_root is not None:
                try:
                    _stage_verified_binary(artifact_root, digest, raw)
                except (OSError, ValueError, HandlerLoadError):
                    reasons.add('artifact_staging_failed')
            return
        if isinstance(value, Mapping):
            identity = id(value)
            if identity in seen:
                reasons.add('cycle_detected')
                return
            seen.add(identity)
            try:
                for index, (key, item) in enumerate(value.items()):
                    if index >= MAX_COLLECTION_ITEMS:
                        reasons.add('maximum_items')
                        break
                    visit(item, (*path, str(key)), value, depth + 1)
            finally:
                seen.remove(identity)
            return
        if isinstance(value, (list, tuple)):
            identity = id(value)
            if identity in seen:
                reasons.add('cycle_detected')
                return
            seen.add(identity)
            try:
                for index, item in enumerate(value):
                    if index >= MAX_COLLECTION_ITEMS:
                        reasons.add('maximum_items')
                        break
                    visit(item, (*path, f'item-{index}'), None, depth + 1)
            finally:
                seen.remove(identity)

    visit(raw_result, (), None, 0)
    outputs.sort(key=lambda item: (item['role'], item['path'], item['sha256']))
    return outputs, {
        'schema_version': 1,
        'maximum_outputs': MAX_VERIFIED_BINARY_OUTPUTS,
        'maximum_total_size': MAX_VERIFIED_BINARY_TOTAL_SIZE,
        'binary_values_seen': binary_values_seen,
        'binary_bytes_seen': binary_bytes_seen,
        'traversal_items': traversal_items,
        'observed_output_count': len(outputs),
        'retained_output_count': 0,
        'retained_for_follow_on_analysis': False,
        'follow_on_analysis_complete': False,
        'observation_scope': (
            'worker_staged_untrusted'
            if artifact_root is not None
            else 'wrapper_hash_metadata_only'
        ),
        'truncated': bool(reasons.intersection({
            'maximum_depth',
            'maximum_items',
            'maximum_total_binary_size',
            'maximum_verified_outputs',
        })),
        'reasons': sorted(reasons),
    }


def _invoke_loaded_handler(
    handler: Callable[..., Any],
    invocation: str,
    data: bytes,
    source_name: str,
) -> Any:
    """読み込み済みhandlerを宣言済みinvocationだけで呼び出す。"""

    if invocation == "bytes_name":
        return handler(data, source_name)
    if invocation == "bytes":
        return handler(data)
    if invocation == "bytes_expected_sha256":
        return handler(data, hashlib.sha256(data).hexdigest())
    if invocation == "bytes_pe_timestamp":
        return handler(data, timestamp=_pe_timestamp(data))
    if invocation == "text":
        return handler(data.decode("utf-8-sig", errors="replace"))
    raise HandlerLoadError(f"unsupported invocation: {invocation}")


def _invoke_handler(
    spec: HandlerSpec,
    data: bytes,
    source_name: str,
    *,
    dependency_source_manifest: Any = None,
    dependency_data_manifest: Any = None,
    dependency_module_manifest: Any = None,
) -> Any:
    """検証済みhandlerを現在processで呼び出し、raw resultを返す。"""

    if dependency_source_manifest is not None:
        return _invoke_handler_from_verified_snapshots(
            spec,
            data,
            source_name,
            dependency_source_manifest,
            dependency_data_manifest,
            dependency_module_manifest,
        )
    handler, invocation = load_handler(spec)
    path = _resolve_handler_path(spec)
    with _handler_import_environment(path, keep_modules=tuple(_LOADED_HANDLER_MODULE_NAMES)):
        return _invoke_loaded_handler(handler, invocation, data, source_name)


def execute_handler(
    spec: HandlerSpec,
    data: bytes,
    source_name: str,
    *,
    artifact_root: Path | None = None,
    dependency_source_manifest: Any = None,
    dependency_data_manifest: Any = None,
    dependency_module_manifest: Any = None,
) -> dict[str, Any]:
    """1つの静的解析関数を実行し、秘密値とバイナリを除去して返す。"""

    try:
        result = _invoke_handler(
            spec,
            data,
            source_name,
            dependency_source_manifest=dependency_source_manifest,
            dependency_data_manifest=dependency_data_manifest,
            dependency_module_manifest=dependency_module_manifest,
        )
    except HandlerNoEvidenceError as exc:
        result = {"status": "not_applicable", "reason": str(exc)}
    verified_outputs, verification_audit = _verified_binary_outputs(
        result,
        artifact_root=artifact_root,
    )
    public_budget = _PublicValueBudget()
    public_result = sanitize_public_value(result, _budget=public_budget)
    return {
        "handler": spec.public(),
        "result": public_result,
        "result_quota": {
            "maximum_entries": MAX_PUBLIC_RESULT_ENTRIES,
            "maximum_string_characters": MAX_PUBLIC_RESULT_TOTAL_STRING_CHARS,
            "maximum_binary_bytes": MAX_PUBLIC_RESULT_TOTAL_BINARY_BYTES,
            "entries_seen": public_budget.entries,
            "string_characters_seen": public_budget.string_characters,
            "binary_bytes_seen": public_budget.binary_bytes,
            "truncated": public_budget.truncated,
            "reasons": sorted(public_budget.reasons or ()),
        },
        "verified_binary_outputs": verified_outputs,
        "verified_binary_output_audit": verification_audit,
        "executed_sample": False,
        "network_contacted": False,
    }


class _DiscardHandlerText:
    """worker内handlerのstdout/stderrをmemoryへ蓄積せず破棄する。"""

    encoding = 'utf-8'

    def write(self, value: str) -> int:
        return len(value)

    def flush(self) -> None:
        return None


def _handler_spec_from_public(value: Mapping[str, Any]) -> HandlerSpec:
    """JSON化された公開specを型検証してimmutable HandlerSpecへ戻す。"""

    fields = {
        'id',
        'family',
        'relative_path',
        'callable_name',
        'invocation',
        'source',
        'automatic',
        'campaign',
        'supported_interface',
        'reason',
        'input_formats',
        'input_contract_source',
        'minimum_evidence_score',
    }
    if set(value) != fields:
        raise HandlerLoadError('worker handler spec fields are invalid')
    raw_formats = value.get('input_formats')
    if not isinstance(raw_formats, list) or any(not isinstance(item, str) for item in raw_formats):
        raise HandlerLoadError('worker handler input_formats are invalid')
    normalized = dict(value)
    normalized['input_formats'] = tuple(raw_formats)
    return HandlerSpec(**normalized)


def _worker_root(value: Any, *, name: str) -> Path:
    """workerに渡したrootをabsolute・非reparse pathへ限定する。"""

    if not isinstance(value, str) or not value or '\x00' in value:
        raise HandlerLoadError(f'worker {name} is invalid')
    path = Path(value)
    if not path.is_absolute():
        raise HandlerLoadError(f'worker {name} is not absolute')
    from analysis_contract import ensure_no_reparse_components

    ensure_no_reparse_components(path)
    return path.resolve(strict=True)


def _regular_file_snapshot(
    path: Path,
    *,
    maximum_size: int,
    description: str,
) -> tuple[bytes, str]:
    """通常単一linkファイルを1 handleで有界読込し、bytesとhashを固定する。"""

    if not isinstance(maximum_size, int) or isinstance(maximum_size, bool) or maximum_size < 1:
        raise ValueError('maximum_size is invalid')
    flags = os.O_RDONLY | getattr(os, 'O_BINARY', 0) | getattr(os, 'O_NOFOLLOW', 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise HandlerLoadError(f'{description} is unavailable') from exc
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or getattr(before, 'st_nlink', 1) != 1
            or before.st_size < 0
            or before.st_size > maximum_size
        ):
            raise HandlerLoadError(
                f'{description} is not a bounded regular single-link file'
            )
        digest = hashlib.sha256()
        chunks: list[bytes] = []
        bytes_seen = 0
        while True:
            chunk = os.read(
                descriptor,
                min(1024 * 1024, maximum_size + 1 - bytes_seen),
            )
            if not chunk:
                break
            bytes_seen += len(chunk)
            if bytes_seen > maximum_size:
                raise HandlerLoadError(f'{description} exceeds size limit')
            digest.update(chunk)
            chunks.append(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    identity_before = (
        before.st_dev,
        before.st_ino,
        before.st_size,
        getattr(before, 'st_mtime_ns', int(before.st_mtime * 1_000_000_000)),
        getattr(before, 'st_nlink', 1),
    )
    identity_after = (
        after.st_dev,
        after.st_ino,
        after.st_size,
        getattr(after, 'st_mtime_ns', int(after.st_mtime * 1_000_000_000)),
        getattr(after, 'st_nlink', 1),
    )
    if identity_before != identity_after or bytes_seen != before.st_size:
        raise HandlerLoadError(f'{description} changed while reading')
    return b''.join(chunks), digest.hexdigest()


def _dependency_source_snapshot(path: Path) -> tuple[bytes, str]:
    """依存source/dataを単一handleの検証済みbytes snapshotへ固定する。"""

    return _regular_file_snapshot(
        path,
        maximum_size=MAX_ASSESSMENT_SOURCE_FILE_SIZE,
        description='dependency source',
    )


def _strict_json_loads(raw: bytes, *, description: str) -> Any:
    """duplicate keyと非有限数を拒否してUTF-8 JSONをdecodeする。"""

    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f'{description} contains duplicate JSON key')
            result[key] = value
        return result

    def finite_float(value: str) -> float:
        parsed = float(value)
        if not math.isfinite(parsed):
            raise ValueError(f'{description} contains non-finite number')
        return parsed

    def reject_constant(value: str) -> None:
        raise ValueError(f'{description} contains invalid constant: {value}')

    try:
        return json.loads(
            raw.decode('utf-8'),
            object_pairs_hook=unique_object,
            parse_float=finite_float,
            parse_constant=reject_constant,
        )
    except (UnicodeError, json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise HandlerLoadError(f'{description} is invalid JSON') from exc


def _validated_dependency_source_snapshots(
    value: Any,
    *,
    repository: Path,
) -> tuple[_DependencySourceSnapshot, ...]:
    """manifestを現在のsource bytesへ結合したimmutable snapshot群へ変換する。"""

    if (
        not isinstance(value, list)
        or not value
        or len(value) > MAX_ASSESSMENT_IMPORT_FILES
    ):
        raise HandlerLoadError('dependency source manifest size is invalid')
    from analysis_contract import ensure_no_reparse_components

    ensure_no_reparse_components(repository)
    repository = repository.resolve(strict=True)
    if not repository.is_dir():
        raise HandlerLoadError('dependency source repository is invalid')
    snapshots: list[_DependencySourceSnapshot] = []
    seen: set[str] = set()
    total_size = 0
    for record in value:
        if not isinstance(record, Mapping) or set(record) != {'path', 'sha256'}:
            raise HandlerLoadError('dependency source manifest record is invalid')
        relative = record.get('path')
        expected = record.get('sha256')
        if (
            not isinstance(relative, str)
            or not relative
            or len(relative) > 4_096
            or '\\' in relative
            or '\x00' in relative
            or any(ord(character) < 32 or ord(character) == 127 for character in relative)
            or Path(relative).is_absolute()
            or any(part in {'', '.', '..'} for part in relative.split('/'))
            or not relative.endswith('.py')
            or not isinstance(expected, str)
            or re.fullmatch(r'[0-9a-f]{64}', expected) is None
            or relative in seen
        ):
            raise HandlerLoadError('dependency source manifest value is invalid')
        candidate = repository.joinpath(*relative.split('/'))
        try:
            ensure_no_reparse_components(candidate)
            resolved = candidate.resolve(strict=True)
            if repository not in resolved.parents:
                raise HandlerLoadError('dependency source is outside repository')
            source, actual = _dependency_source_snapshot(resolved)
        except (OSError, ValueError) as exc:
            raise HandlerLoadError('dependency source is unavailable or unsafe') from exc
        if actual != expected:
            raise HandlerLoadError('dependency source hash does not match manifest')
        total_size += len(source)
        if total_size > MAX_ASSESSMENT_SOURCE_TOTAL_SIZE:
            raise HandlerLoadError('dependency source snapshot total size is too large')
        seen.add(relative)
        snapshots.append(
            _DependencySourceSnapshot(
                relative_path=relative,
                resolved_path=resolved,
                sha256=expected,
                source=source,
            )
        )
    if list(snapshots) != sorted(snapshots, key=lambda item: item.relative_path):
        raise HandlerLoadError('dependency source manifest is not sorted')
    return tuple(snapshots)


def _validated_dependency_source_manifest(
    value: Any,
    *,
    repository: Path,
) -> list[dict[str, str]]:
    """監査済み依存source manifestを厳密検証し、現在のbytesへ再結合する。"""

    return [
        {'path': snapshot.relative_path, 'sha256': snapshot.sha256}
        for snapshot in _validated_dependency_source_snapshots(
            value,
            repository=repository,
        )
    ]


def _validated_dependency_data_snapshots(
    value: Any,
    *,
    repository: Path,
) -> tuple[_DependencyDataSnapshot, ...]:
    if not isinstance(value, list) or len(value) > MAX_ASSESSMENT_IMPORT_FILES:
        raise HandlerLoadError('dependency data manifest size is invalid')
    from analysis_contract import ensure_no_reparse_components

    ensure_no_reparse_components(repository)
    repository = repository.resolve(strict=True)
    snapshots: list[_DependencyDataSnapshot] = []
    seen: set[str] = set()
    total_size = 0
    for record in value:
        if not isinstance(record, Mapping) or set(record) != {'path', 'sha256', 'reason'}:
            raise HandlerLoadError('dependency data manifest record is invalid')
        relative = record.get('path')
        expected = record.get('sha256')
        reason = record.get('reason')
        if (
            not isinstance(relative, str)
            or not relative
            or len(relative) > 4_096
            or '\\' in relative
            or '\x00' in relative
            or Path(relative).is_absolute()
            or any(part in {'', '.', '..'} for part in relative.split('/'))
            or Path(relative).suffix.casefold() not in {'.json', '.yaml', '.yml'}
            or not isinstance(expected, str)
            or re.fullmatch(r'[0-9a-f]{64}', expected) is None
            or not isinstance(reason, str)
            or not reason
            or len(reason) > 512
            or relative in seen
        ):
            raise HandlerLoadError('dependency data manifest value is invalid')
        candidate = repository.joinpath(*relative.split('/'))
        try:
            ensure_no_reparse_components(candidate)
            resolved = candidate.resolve(strict=True)
            if repository not in resolved.parents:
                raise HandlerLoadError('dependency data is outside repository')
            data, actual = _dependency_source_snapshot(resolved)
        except (OSError, ValueError) as exc:
            raise HandlerLoadError('dependency data is unavailable or unsafe') from exc
        if actual != expected:
            raise HandlerLoadError('dependency data hash does not match manifest')
        total_size += len(data)
        if total_size > MAX_ASSESSMENT_SOURCE_TOTAL_SIZE:
            raise HandlerLoadError('dependency data snapshot total size is too large')
        seen.add(relative)
        snapshots.append(
            _DependencyDataSnapshot(
                relative_path=relative,
                resolved_path=resolved,
                sha256=expected,
                data=data,
            )
        )
    if list(snapshots) != sorted(snapshots, key=lambda item: item.relative_path):
        raise HandlerLoadError('dependency data manifest is not sorted')
    return tuple(snapshots)


def _validated_dependency_data_manifest(
    value: Any,
    *,
    repository: Path,
) -> list[dict[str, str]]:
    snapshots = _validated_dependency_data_snapshots(value, repository=repository)
    reasons = {
        str(record['path']): str(record['reason'])
        for record in value
        if isinstance(record, Mapping)
    }
    return [
        {
            'path': snapshot.relative_path,
            'sha256': snapshot.sha256,
            'reason': reasons[snapshot.relative_path],
        }
        for snapshot in snapshots
    ]


def _inferred_dependency_module_manifest(
    snapshots: tuple[_DependencySourceSnapshot, ...],
) -> list[dict[str, Any]]:
    imported_names: set[str] = set()
    for snapshot in snapshots:
        try:
            tree = ast.parse(
                snapshot.source.decode('utf-8-sig'),
                filename=str(snapshot.resolved_path),
            )
        except (SyntaxError, UnicodeError) as exc:
            raise HandlerLoadError('cannot infer dependency module binding') from exc
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported_names.update(item.name for item in node.names)
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                imported_names.add(node.module)
    expanded_names = {
        '.'.join(name.split('.')[:index])
        for name in imported_names
        for index in range(1, len(name.split('.')) + 1)
    }
    records: list[dict[str, Any]] = []
    for name in sorted(expanded_names):
        source_suffix = name.replace('.', '/') + '.py'
        package_suffix = name.replace('.', '/') + '/__init__.py'
        matches = [
            (snapshot, snapshot.relative_path.endswith(package_suffix))
            for snapshot in snapshots
            if (
                snapshot.relative_path == source_suffix
                or snapshot.relative_path.endswith('/' + source_suffix)
                or snapshot.relative_path == package_suffix
                or snapshot.relative_path.endswith('/' + package_suffix)
            )
        ]
        if len(matches) == 1:
            snapshot, is_package = matches[0]
            records.append(
                {
                    'name': name,
                    'path': snapshot.relative_path,
                    'is_package': is_package,
                }
            )
    return records


def _validated_dependency_module_bindings(
    value: Any,
    *,
    snapshots: tuple[_DependencySourceSnapshot, ...],
) -> tuple[_VerifiedModuleBinding, ...]:
    if (
        not isinstance(value, list)
        or len(value) > MAX_ASSESSMENT_IMPORT_FILES * 4
    ):
        raise HandlerLoadError('dependency module manifest size is invalid')
    by_path = {snapshot.relative_path: snapshot for snapshot in snapshots}
    bindings: list[_VerifiedModuleBinding] = []
    seen: set[str] = set()
    for record in value:
        if (
            not isinstance(record, Mapping)
            or set(record) != {'name', 'path', 'is_package'}
        ):
            raise HandlerLoadError('dependency module manifest record is invalid')
        name = record.get('name')
        relative = record.get('path')
        is_package = record.get('is_package')
        if (
            not isinstance(name, str)
            or not name
            or any(not part.isidentifier() for part in name.split('.'))
            or name in seen
            or not isinstance(relative, str)
            or relative not in by_path
            or not isinstance(is_package, bool)
            or is_package != relative.endswith('/__init__.py')
        ):
            raise HandlerLoadError('dependency module manifest value is invalid')
        seen.add(name)
        bindings.append(
            _VerifiedModuleBinding(
                fullname=name,
                snapshot=by_path[relative],
                is_package=is_package,
            )
        )
    if list(bindings) != sorted(bindings, key=lambda item: item.fullname):
        raise HandlerLoadError('dependency module manifest is not sorted')
    return tuple(bindings)


def _source_origin_key(path: str | Path) -> str:
    return os.path.normcase(os.path.abspath(os.fspath(path)))


class _VerifiedSnapshotLoader(importlib.abc.Loader):
    """検証済みbytesだけを元のorigin名でcompileするloader。"""

    def __init__(self, snapshot: _DependencySourceSnapshot):
        self.snapshot = snapshot

    def create_module(self, spec):
        return None

    def exec_module(self, module) -> None:
        module.__file__ = str(self.snapshot.resolved_path)
        module.__cached__ = None
        code = compile(
            self.snapshot.source,
            str(self.snapshot.resolved_path),
            'exec',
            dont_inherit=True,
        )
        exec(code, module.__dict__)  # noqa: S102 - 監査・hash検証済みsource snapshotのみ


class _VerifiedSnapshotFinder(importlib.abc.MetaPathFinder):
    """canonical fullnameを検証済みsource snapshotへ直接固定するfinder。"""

    def __init__(
        self,
        bindings: tuple[_VerifiedModuleBinding, ...],
        repository: Path,
    ):
        self.repository_key = _source_origin_key(repository)
        self.bindings = {binding.fullname: binding for binding in bindings}

    def find_spec(self, fullname, path=None, target=None):
        binding = self.bindings.get(fullname)
        if binding is not None:
            verified = importlib.util.spec_from_loader(
                fullname,
                _VerifiedSnapshotLoader(binding.snapshot),
                origin=str(binding.snapshot.resolved_path),
                is_package=binding.is_package,
            )
            if verified is None:
                raise HandlerLoadError('cannot create verified dependency module spec')
            verified.has_location = True
            if binding.is_package:
                verified.submodule_search_locations = [
                    str(binding.snapshot.resolved_path.parent)
                ]
            return verified
        original = importlib.machinery.PathFinder.find_spec(fullname, path, target)
        if original is None or not isinstance(original.origin, str):
            return None
        origin_key = _source_origin_key(original.origin)
        try:
            repository_local = os.path.commonpath(
                (origin_key, self.repository_key)
            ) == self.repository_key
        except ValueError:
            repository_local = False
        if repository_local:
            raise HandlerLoadError(
                'repository-local import is absent from dependency module manifest'
            )
        return None


@contextmanager
def _verified_snapshot_import_environment(
    snapshots: tuple[_DependencySourceSnapshot, ...],
    bindings: tuple[_VerifiedModuleBinding, ...],
):
    """bound fullnameをsys.modules衝突から隔離しsnapshot finderへ固定する。"""

    snapshot_keys = {
        _source_origin_key(snapshot.resolved_path) for snapshot in snapshots
    }
    bound_names = {binding.fullname for binding in bindings}
    displaced: dict[str, object] = {}
    for name, module in tuple(sys.modules.items()):
        origin = getattr(module, '__file__', None)
        if (
            name in bound_names
            or (
                isinstance(origin, str)
                and _source_origin_key(origin) in snapshot_keys
            )
        ):
            displaced[name] = module
            sys.modules.pop(name, None)
    finder = _VerifiedSnapshotFinder(
        bindings,
        REPOSITORY_ROOT.resolve(strict=True),
    )
    sys.meta_path.insert(0, finder)
    try:
        yield
    finally:
        sys.meta_path[:] = [item for item in sys.meta_path if item is not finder]
        for name, module in tuple(sys.modules.items()):
            if (
                name in bound_names
                or isinstance(getattr(module, '__loader__', None), _VerifiedSnapshotLoader)
            ):
                sys.modules.pop(name, None)
        sys.modules.update(displaced)


@contextmanager
def _verified_dynamic_source_environment(
    snapshots: tuple[_DependencySourceSnapshot, ...],
):
    """spec_from_file_locationも検証済みsource snapshotへ強制的に固定する。"""

    by_path = {
        _source_origin_key(snapshot.resolved_path): snapshot
        for snapshot in snapshots
    }
    original = importlib.util.spec_from_file_location

    def verified_spec_from_file_location(
        name: str,
        location: str | os.PathLike[str],
        *,
        loader: importlib.abc.Loader | None = None,
        submodule_search_locations: Sequence[str] | None = None,
    ):
        if (
            not isinstance(name, str)
            or not name
            or any(not part.isidentifier() for part in name.split('.'))
            or loader is not None
        ):
            raise HandlerLoadError('dynamic source module request is invalid')
        try:
            key = _source_origin_key(os.path.abspath(os.fspath(location)))
        except (TypeError, ValueError, OSError) as exc:
            raise HandlerLoadError('dynamic source location is invalid') from exc
        snapshot = by_path.get(key)
        if snapshot is None:
            raise HandlerLoadError(
                'dynamic source is absent from dependency source manifest'
            )
        is_package = snapshot.relative_path.endswith('/__init__.py')
        if submodule_search_locations not in (None, []) and not is_package:
            raise HandlerLoadError('dynamic non-package supplied package search path')
        verified = importlib.util.spec_from_loader(
            name,
            _VerifiedSnapshotLoader(snapshot),
            origin=str(snapshot.resolved_path),
            is_package=is_package,
        )
        if verified is None:
            raise HandlerLoadError('cannot create verified dynamic module spec')
        verified.has_location = True
        if is_package:
            verified.submodule_search_locations = [
                str(snapshot.resolved_path.parent)
            ]
        return verified

    importlib.util.spec_from_file_location = verified_spec_from_file_location
    try:
        yield
    finally:
        importlib.util.spec_from_file_location = original


@contextmanager
def _verified_data_read_environment(
    snapshots: tuple[_DependencyDataSnapshot, ...],
):
    """Path read APIをmanifest内の検証済みbytes snapshotだけへ固定する。"""

    by_path = {
        _source_origin_key(snapshot.resolved_path): snapshot.data
        for snapshot in snapshots
    }
    original_read_text = Path.read_text
    original_read_bytes = Path.read_bytes
    original_open = Path.open

    def snapshot_data(path: Path) -> bytes:
        key = _source_origin_key(path.absolute())
        try:
            return by_path[key]
        except KeyError as exc:
            raise HandlerLoadError(
                'filesystem read is absent from dependency data manifest'
            ) from exc

    def read_text(
        path: Path,
        encoding: str | None = None,
        errors: str | None = None,
    ) -> str:
        return snapshot_data(path).decode(
            encoding or 'utf-8',
            errors or 'strict',
        )

    def read_bytes(path: Path) -> bytes:
        return snapshot_data(path)

    def open_snapshot(
        path: Path,
        mode: str = 'r',
        buffering: int = -1,
        encoding: str | None = None,
        errors: str | None = None,
        newline: str | None = None,
    ):
        del buffering
        if mode not in {'r', 'rt', 'rb'}:
            raise HandlerLoadError('verified data loader is read-only')
        data = snapshot_data(path)
        if 'b' in mode:
            return io.BytesIO(data)
        stream = io.StringIO(
            data.decode(encoding or 'utf-8', errors or 'strict'),
            newline=newline,
        )
        return stream

    Path.read_text = read_text
    Path.read_bytes = read_bytes
    Path.open = open_snapshot
    try:
        yield
    finally:
        Path.read_text = original_read_text
        Path.read_bytes = original_read_bytes
        Path.open = original_open


def _invoke_handler_from_verified_snapshots(
    spec: HandlerSpec,
    data: bytes,
    source_name: str,
    dependency_source_manifest: Any,
    dependency_data_manifest: Any = None,
    dependency_module_manifest: Any = None,
) -> Any:
    """manifestへ結合したsource snapshotだけでhandlerとlocal dependencyを実行する。"""

    path = _resolve_handler_path(spec)
    repository = REPOSITORY_ROOT.resolve(strict=True)
    handler_relative_path = path.relative_to(repository).as_posix()
    snapshots = _validated_dependency_source_snapshots(
        dependency_source_manifest,
        repository=repository,
    )
    data_snapshots = _validated_dependency_data_snapshots(
        dependency_data_manifest if dependency_data_manifest is not None else [],
        repository=repository,
    )
    raw_module_manifest = (
        _inferred_dependency_module_manifest(snapshots)
        if dependency_module_manifest is None
        else dependency_module_manifest
    )
    module_bindings = _validated_dependency_module_bindings(
        raw_module_manifest, snapshots=snapshots
    )
    handler_snapshot = next(
        (
            snapshot
            for snapshot in snapshots
            if snapshot.relative_path == handler_relative_path
        ),
        None,
    )
    if handler_snapshot is None:
        raise HandlerLoadError('handler source is absent from dependency manifest')
    module_name = f"one_shot_handler_{hashlib.sha256(str(path).encode()).hexdigest()[:16]}"
    loader = _VerifiedSnapshotLoader(handler_snapshot)
    module_spec = importlib.util.spec_from_loader(
        module_name,
        loader,
        origin=str(handler_snapshot.resolved_path),
        is_package=False,
    )
    if module_spec is None:
        raise HandlerLoadError('cannot create verified handler module spec')
    module_spec.has_location = True
    module = importlib.util.module_from_spec(module_spec)
    previous_module = sys.modules.get(module_name)
    try:
        with (
            _handler_import_environment(path), _verified_snapshot_import_environment(snapshots, module_bindings),
            _verified_dynamic_source_environment(snapshots),
            _verified_data_read_environment(data_snapshots),
        ):
            sys.modules[module_name] = module
            loader.exec_module(module)
            callable_value = getattr(module, spec.callable_name, None)
            if not callable(callable_value):
                raise HandlerLoadError(f'callable not found: {spec.callable_name}')
            invocation = spec.invocation
            if invocation == 'profiled_bytes_name':
                callable_value = callable_value(spec.family)
                if not callable(callable_value):
                    raise HandlerLoadError(
                        f'profile factory did not return a callable: {spec.family}'
                    )
                invocation = 'bytes_name'
            return _invoke_loaded_handler(
                callable_value,
                invocation,
                data,
                source_name,
            )
    finally:
        if previous_module is None:
            sys.modules.pop(module_name, None)
        else:
            sys.modules[module_name] = previous_module


def _assessment_worker_main(encoded_request: str, output_path: str) -> int:
    """隔離Python process内で1 handler・1 layerだけを実行する内部entrypoint。"""

    global EXTRACTORS_ROOT, FRAMEWORK_ROOT, MALWARE_ROOT, PROFILE_PATH, REPOSITORY_ROOT
    worker_common = str(Path(__file__).resolve().parent)
    if worker_common not in sys.path:
        sys.path.insert(0, worker_common)
    worker_output = Path(output_path)
    if not worker_output.is_absolute() or worker_output.exists() or not worker_output.parent.is_dir():
        return 2
    worker_artifacts = worker_output.parent / 'artifacts'
    try:
        from analysis_contract import ensure_no_reparse_components

        ensure_no_reparse_components(worker_output.parent)
        ensure_no_reparse_components(worker_artifacts)
        if not worker_artifacts.is_dir():
            return 2
    except (OSError, ValueError):
        return 2
    try:
        if len(encoded_request) > MAX_HANDLER_WORKER_REQUEST_SIZE:
            raise HandlerLoadError('worker request is too large')
        padding = '=' * (-len(encoded_request) % 4)
        decoded = base64.urlsafe_b64decode((encoded_request + padding).encode('ascii'))
        request = _strict_json_loads(decoded, description='worker request')
        if not isinstance(request, dict):
            raise HandlerLoadError('worker request is not an object')
        if set(request) != {
            'dependency_source_manifest',
            'dependency_data_manifest',
            'dependency_module_manifest',
            'extractors_root',
            'framework_root',
            'malware_root',
            'repository_root',
            'source_name',
            'spec',
        }:
            raise HandlerLoadError('worker request fields are invalid')
        repository = _worker_root(request.get('repository_root'), name='repository_root')
        framework = _worker_root(request.get('framework_root'), name='framework_root')
        malware = _worker_root(request.get('malware_root'), name='malware_root')
        extractors = _worker_root(request.get('extractors_root'), name='extractors_root')
        if framework != repository / 'analysis-framework':
            raise HandlerLoadError('worker framework_root does not match repository')
        if malware != framework / 'malware' or extractors != repository / 'extractors':
            raise HandlerLoadError('worker handler roots do not match repository')
        source_name = request.get('source_name')
        if (
            not isinstance(source_name, str)
            or not source_name
            or len(source_name) > 512
            or any(ord(character) < 32 or ord(character) == 127 for character in source_name)
        ):
            raise HandlerLoadError('worker source_name is invalid')
        raw_spec = request.get('spec')
        if not isinstance(raw_spec, dict):
            raise HandlerLoadError('worker spec is invalid')

        REPOSITORY_ROOT = repository
        FRAMEWORK_ROOT = framework
        MALWARE_ROOT = malware
        EXTRACTORS_ROOT = extractors
        PROFILE_PATH = extractors / 'profiles' / 'windows_family_profiles.json'
        clear_handler_caches()
        spec = _handler_spec_from_public(raw_spec)
        data = sys.stdin.buffer.read(DEFAULT_MAXIMUM_ASSESSMENT_LAYER_SIZE + 1)
        if len(data) > DEFAULT_MAXIMUM_ASSESSMENT_LAYER_SIZE:
            raise HandlerLoadError('worker input exceeds maximum layer size')
        discarded = _DiscardHandlerText()
        with redirect_stdout(discarded), redirect_stderr(discarded):
            result = execute_handler(
                spec,
                data,
                source_name,
                artifact_root=worker_artifacts,
                dependency_source_manifest=request.get('dependency_source_manifest'),
                dependency_data_manifest=request.get('dependency_data_manifest'),
                dependency_module_manifest=request.get('dependency_module_manifest'),
            )
        response: dict[str, Any] = {'ok': True, 'result': result}
    except Exception as exc:  # noqa: BLE001 - worker境界では全障害を公開用に正規化する
        response = {
            'ok': False,
            'error': 'handler_worker_failed',
            'error_type': type(exc).__name__,
        }
    encoded = json.dumps(
        response,
        ensure_ascii=False,
        sort_keys=True,
        separators=(',', ':'),
        allow_nan=False,
    ).encode('utf-8')
    if len(encoded) > MAX_HANDLER_WORKER_OUTPUT_SIZE:
        encoded = (
            b'{"error":"worker_output_limit_exceeded",'
            b'"error_type":"HandlerLoadError","ok":false}'
        )
    try:
        with worker_output.open('xb') as stream:
            stream.write(encoded)
    except OSError:
        return 3
    return 0


def _bounded_handler_environment(
    *,
    temporary_root: Path | None = None,
) -> dict[str, str]:
    """API key等を子processへ渡さない最小環境変数を返す。"""

    allowed = ('SystemRoot', 'WINDIR') if os.name == 'nt' else ('LANG', 'LC_ALL')
    environment = {
        key: value
        for key in allowed
        if isinstance((value := os.environ.get(key)), str) and value
    }
    environment.update(
        {
            'PYTHONDONTWRITEBYTECODE': '1',
            'PYTHONIOENCODING': 'utf-8',
            'PYTHONNOUSERSITE': '1',
            'PYTHONUTF8': '1',
        }
    )
    if temporary_root is not None:
        from analysis_contract import ensure_no_reparse_components

        absolute = Path(os.path.abspath(os.fspath(temporary_root)))
        ensure_no_reparse_components(absolute)
        try:
            information = absolute.lstat()
        except OSError as exc:
            raise HandlerLoadError(
                'handler worker用一時directoryを安全に確認できません'
            ) from exc
        if not stat.S_ISDIR(information.st_mode) or bool(
            int(getattr(information, 'st_file_attributes', 0)) & 0x400
        ):
            raise HandlerLoadError(
                'handler worker用一時pathは通常directoryではありません'
            )
        private_temp = str(absolute.resolve(strict=True))
        environment.update(
            {
                'TEMP': private_temp,
                'TMP': private_temp,
                'TMPDIR': private_temp,
            }
        )
    return environment


def _validated_artifact_destination(
    artifact_directory: Path | None,
    artifact_path_prefix: str,
) -> tuple[Path, str] | None:
    """親processが所有する既存artifact directoryと公開相対prefixを検証する。"""

    if artifact_directory is None:
        return None
    from analysis_contract import ensure_no_reparse_components

    directory = Path(artifact_directory)
    if not directory.is_absolute():
        raise ValueError('artifact_directoryは絶対pathで指定してください')
    ensure_no_reparse_components(directory)
    resolved = directory.resolve(strict=True)
    if not resolved.is_dir():
        raise ValueError('artifact_directoryは既存directoryで指定してください')
    repository = REPOSITORY_ROOT.resolve(strict=True)
    if resolved == repository or repository in resolved.parents:
        raise ValueError('復号payloadはrepository配下へ保存できません')
    normalized = artifact_path_prefix.strip().replace(chr(92), '/')
    if (
        not normalized
        or len(normalized) > 256
        or normalized.startswith('/')
        or re.fullmatch(r'[A-Za-z0-9_./-]+', normalized) is None
        or any(part in {'', '.', '..'} for part in normalized.split('/'))
    ):
        raise ValueError('artifact_path_prefixが不正です')
    return resolved, normalized


def _read_verified_artifact(
    path: Path,
    *,
    expected_size: int,
    expected_sha256: str,
    deadline: float | None = None,
    monotonic: Callable[[], float] = time.monotonic,
) -> bytes:
    """通常fileを単一handleで有界読取りし、hardlink・変更・hash不一致を拒否する。"""

    from analysis_contract import ensure_no_reparse_components

    ensure_no_reparse_components(path)
    flags = os.O_RDONLY | getattr(os, 'O_BINARY', 0) | getattr(os, 'O_NOFOLLOW', 0)
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size != expected_size
            or expected_size > MAX_VERIFIED_BINARY_TOTAL_SIZE
        ):
            raise HandlerLoadError('artifact file metadata is invalid')
        chunks: list[bytes] = []
        remaining = expected_size + 1
        while remaining > 0:
            if deadline is not None and monotonic() >= deadline:
                raise TimeoutError('artifact read deadline exceeded')
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b''.join(chunks)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    identity_before = (
        before.st_dev,
        before.st_ino,
        before.st_size,
        getattr(before, 'st_mtime_ns', int(before.st_mtime * 1_000_000_000)),
    )
    identity_after = (
        after.st_dev,
        after.st_ino,
        after.st_size,
        getattr(after, 'st_mtime_ns', int(after.st_mtime * 1_000_000_000)),
    )
    if identity_before != identity_after or len(raw) != expected_size:
        raise HandlerLoadError('artifact changed while reading')
    if hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise HandlerLoadError('artifact hash does not match worker observation')
    return raw


def _retained_artifact_path(
    artifact_directory: Path,
    artifact_path_prefix: str,
    output: Mapping[str, Any],
) -> tuple[Path, str]:
    """検証済みmetadataから衝突しないcase内保存pathを決定する。"""

    extension = {
        'archive': 'archive',
        'binary': 'bin',
        'elf': 'elf',
        'macho': 'macho',
        'pe': 'exe',
        'script': 'txt',
    }[str(output['kind'])]
    digest = str(output['sha256'])
    from analysis_contract import ensure_no_reparse_components

    ensure_no_reparse_components(artifact_directory)
    destination = artifact_directory / f'{digest}.{extension}'
    return destination, f'{artifact_path_prefix}/{digest}.{extension}'


def _retain_worker_outputs(
    execution: dict[str, Any],
    *,
    worker_artifacts: Path,
    artifact_destination: tuple[Path, str] | None,
) -> dict[str, Any]:
    """worker観測metadataを親再検証済みcase artifactへfail-closedで昇格する。"""

    supplied = execution.get('verified_binary_outputs')
    observed = [item for item in supplied if isinstance(item, dict)] if isinstance(supplied, list) else []
    retained: list[dict[str, Any]] = []
    reasons = {
        str(item)
        for item in (execution.get('verified_binary_output_audit') or {}).get('reasons', [])
        if isinstance(item, str)
    }
    if artifact_destination is not None:
        artifact_directory, artifact_path_prefix = artifact_destination
        for output in observed[:MAX_VERIFIED_BINARY_OUTPUTS]:
            try:
                if set(output) != {'role', 'kind', 'path', 'sha256', 'size', 'verification'}:
                    raise HandlerLoadError('worker artifact metadata schema is invalid')
                role = output.get('role')
                kind = output.get('kind')
                digest = output.get('sha256')
                size = output.get('size')
                verification = output.get('verification')
                if (
                    role not in {'terminal_payload', 'final_payload'}
                    or kind not in VERIFIED_BINARY_KINDS
                    or not isinstance(digest, str)
                    or re.fullmatch(r'[0-9a-f]{64}', digest) is None
                    or not isinstance(size, int)
                    or isinstance(size, bool)
                    or not 0 < size <= MAX_VERIFIED_BINARY_TOTAL_SIZE
                    or not isinstance(verification, dict)
                    or verification != {
                        'status': 'artifact_hash_verified',
                        'sha256_matches': True,
                        'size_matches': True,
                    }
                ):
                    raise HandlerLoadError('worker artifact metadata is invalid')
                staged = worker_artifacts / f'{digest}.payload'
                raw = _read_verified_artifact(
                    staged,
                    expected_size=size,
                    expected_sha256=digest,
                )
                destination, public_path = _retained_artifact_path(
                    artifact_directory,
                    artifact_path_prefix,
                    output,
                )
                created = False
                try:
                    with destination.open('xb') as stream:
                        created = True
                        stream.write(raw)
                        stream.flush()
                        os.fsync(stream.fileno())
                except FileExistsError:
                    pass
                try:
                    _read_verified_artifact(
                        destination,
                        expected_size=size,
                        expected_sha256=digest,
                    )
                except Exception:
                    if created:
                        destination.unlink(missing_ok=True)
                    raise
                retained.append({**output, 'path': public_path})
            except (OSError, ValueError, HandlerLoadError):
                reasons.add('artifact_retention_failed')
    if len(observed) > MAX_VERIFIED_BINARY_OUTPUTS:
        reasons.add('maximum_verified_outputs')
    worker_audit = execution.get('verified_binary_output_audit')
    truncated = (
        isinstance(worker_audit, dict)
        and worker_audit.get('truncated') is True
    ) or bool(reasons.intersection({
        'maximum_depth',
        'maximum_items',
        'maximum_total_binary_size',
        'maximum_verified_outputs',
    }))
    execution['observed_binary_outputs'] = observed
    execution['verified_binary_outputs'] = retained
    execution['verified_binary_output_audit'] = {
        'schema_version': 1,
        'maximum_outputs': MAX_VERIFIED_BINARY_OUTPUTS,
        'maximum_total_size': MAX_VERIFIED_BINARY_TOTAL_SIZE,
        'binary_values_seen': (
            worker_audit.get('binary_values_seen', 0) if isinstance(worker_audit, dict) else 0
        ),
        'binary_bytes_seen': (
            worker_audit.get('binary_bytes_seen', 0) if isinstance(worker_audit, dict) else 0
        ),
        'traversal_items': (
            worker_audit.get('traversal_items', 0) if isinstance(worker_audit, dict) else 0
        ),
        'observed_output_count': len(observed),
        'retained_output_count': len(retained),
        'retained_for_follow_on_analysis': bool(retained),
        'follow_on_analysis_complete': False,
        'observation_scope': (
            'parent_rehashed_case_artifact'
            if retained
            else 'wrapper_hash_metadata_only'
        ),
        'truncated': truncated,
        'reasons': sorted(reasons),
    }
    return execution


def _execute_handler_bounded(
    spec: HandlerSpec,
    data: bytes,
    source_name: str,
    *,
    timeout_seconds: float,
    dependency_source_manifest: list[dict[str, str]],
    dependency_data_manifest: list[dict[str, str]],
    dependency_module_manifest: list[dict[str, Any]],
    artifact_destination: tuple[Path, str] | None = None,
) -> dict[str, Any]:
    """handlerをisolated subprocessで実行し、wall-clock上限とtree終了を保証する。"""

    request = {
        'repository_root': str(REPOSITORY_ROOT.resolve(strict=True)),
        'framework_root': str((REPOSITORY_ROOT / 'analysis-framework').resolve(strict=True)),
        'malware_root': str(MALWARE_ROOT.resolve(strict=True)),
        'extractors_root': str(EXTRACTORS_ROOT.resolve(strict=True)),
        'source_name': source_name,
        'spec': spec.public(),
        'dependency_source_manifest': dependency_source_manifest,
        'dependency_data_manifest': dependency_data_manifest,
        'dependency_module_manifest': dependency_module_manifest,
    }
    token = base64.urlsafe_b64encode(
        json.dumps(request, ensure_ascii=False, sort_keys=True).encode('utf-8')
    ).decode('ascii').rstrip('=')
    if len(token) > MAX_HANDLER_WORKER_REQUEST_SIZE:
        raise HandlerLoadError('handler worker request exceeds size limit')
    import bounded_process

    with tempfile.TemporaryDirectory(prefix='handler-assessment-') as temporary:
        output_path = Path(temporary) / 'response.json'
        worker_artifacts = Path(temporary) / 'artifacts'
        worker_artifacts.mkdir()
        worker_temp = Path(temporary) / 'worker-temp'
        worker_temp.mkdir(mode=0o700)
        os.chmod(worker_temp, 0o700)
        completed = bounded_process.run_bounded(
            [
                sys.executable,
                '-I',
                '-B',
                str(Path(__file__).resolve()),
                '--assessment-worker',
                token,
                str(output_path),
            ],
            timeout=timeout_seconds,
            check=False,
            shell=False,
            env=_bounded_handler_environment(temporary_root=worker_temp),
            cwd=REPOSITORY_ROOT,
            input=data,
            stdout=subprocess.DEVNULL,
            require_containment=True,
            maximum_active_processes=1,
            maximum_memory_bytes=bounded_process.DEFAULT_CONTAINED_MEMORY_BYTES,
            stderr=subprocess.DEVNULL,
            text=False,
        )
        if completed.returncode != 0:
            raise HandlerLoadError('handler worker failed')
        try:
            from analysis_contract import ensure_no_reparse_components

            ensure_no_reparse_components(output_path)
            output, _output_sha256 = _regular_file_snapshot(
                output_path,
                maximum_size=MAX_HANDLER_WORKER_OUTPUT_SIZE,
                description='handler worker output',
            )
        except (OSError, ValueError) as exc:
            raise HandlerLoadError('handler worker output is unavailable') from exc
        if not output:
            raise HandlerLoadError('handler worker output size is invalid')
        response = _strict_json_loads(output, description='handler worker output')
        if not isinstance(response, dict):
            raise HandlerLoadError('handler worker response is not an object')
        if response.get('ok') is False and set(response) == {'ok', 'error', 'error_type'}:
            raise HandlerLoadError(str(sanitize_public_value(response['error'])))
        if response.get('ok') is not True or set(response) != {'ok', 'result'}:
            raise HandlerLoadError('handler worker response schema is invalid')
        result = response.get('result')
        if not isinstance(result, dict):
            raise HandlerLoadError('handler worker result is invalid')
        return _retain_worker_outputs(
            result,
            worker_artifacts=worker_artifacts,
            artifact_destination=artifact_destination,
        )

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
        'functools.partial',
        'globals',
        'locals',
        'open',
        'operator.attrgetter',
        'operator.methodcaller',
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
        'vars',
    }
)
_FORBIDDEN_METHOD_NAMES = frozenset(
    {
        'chmod',
        'chown',
        'connect',
        'mkdir',
        'rename',
        'read_bytes',
        'read_text',
        'rmdir',
        'send',
        'sendall',
        'touch',
        'unlink',
        'write_bytes',
        'write_text',
    }
)
_DANGEROUS_REFLECTION_ATTRIBUTES = frozenset(
    {
        '__base__',
        '__bases__',
        '__builtins__',
        '__class__',
        '__closure__',
        '__code__',
        '__dict__',
        '__func__',
        '__getattribute__',
        '__globals__',
        '__mro__',
        '__self__',
        '__subclasses__',
    }
)
_APPROVED_EXTERNAL_MODULE_ROOTS = frozenset(
    {
        'Cryptodome',
        'cabarchive',
        'capstone',
        'cryptography',
        'dncil',
        'dnfile',
        'nrv2e',
        'numpy',
        'olefile',
        'pefile',
        'pyzipper',
        'refinery',
    }
)
_LEGACY_DYNAMIC_LOCAL_DEPENDENCIES: dict[
    str,
    tuple[tuple[str, tuple[str, ...], str], ...],
] = {
    'analysis-framework/malware/jackskid/extract_config.py': (
        (
            'analysis-framework/malware/linux_ens_sns_bot/profile.py',
            (),
            'literal_reviewed_profile_module',
        ),
    ),
    'analysis-framework/malware/purehvnc/extract_config.py': (
        (
            'analysis-framework/malware/purehvnc/detect.py',
            ('structural_summary',),
            'literal_sibling_detector_module',
        ),
    ),
    'extractors/remusstealer/extractor.py': (
        (
            'analysis-framework/common/remus_memory_config.py',
            ('extract_remus_memory_config',),
            'validated_common_module_loader',
        ),
        (
            'analysis-framework/common/remus_c2_profile.py',
            ('build_remus_c2_profile',),
            'validated_common_module_loader',
        ),
    ),
    'extractors/venomrat/integrated.py': (
        (
            'analysis-framework/common/dotnet_rat_config.py',
            ('recover',),
            'validated_common_module_loader',
        ),
    ),
}
_APPROVED_STATIC_SYS_PATH_SOURCES = frozenset(
    {
        'analysis-framework/malware/agenttesla/agenttesla_luajit_chain.py',
        'analysis-framework/malware/agenttesla/agenttesla_recover.py',
        'analysis-framework/malware/agenttesla/detect.py',
        'analysis-framework/malware/purehvnc/extract_config.py',
        'analysis-framework/common/dotnet_resource_loader_evidence.py',
        'analysis-framework/common/extract_dotnet_resources.py',
        'unpackers/static_unpacker.py',
    }
)
_SAFE_LOCAL_DATA_METHODS = frozenset(
    {'findall', 'finditer', 'fullmatch', 'get', 'items', 'keys', 'match', 'search', 'split', 'sub', 'subn', 'values'}
)
_APPROVED_EXTERNAL_CALLS = frozenset(
    {
        'Cryptodome.Cipher.AES.new',
        'ast.literal_eval',
        'base64.b64decode',
        'base64.b64encode',
        'base64.urlsafe_b64decode',
        'binascii.crc32',
        'codecs.decode',
        'collections.defaultdict',
        'contextlib.contextmanager',
        'contextlib.suppress',
        'copy.deepcopy',
        'cryptography.hazmat.primitives.ciphers.Cipher',
        'cryptography.hazmat.primitives.ciphers.aead.ChaCha20Poly1305',
        'cryptography.hazmat.primitives.ciphers.algorithms.AES',
        'cryptography.hazmat.primitives.ciphers.algorithms.TripleDES',
        'cryptography.hazmat.primitives.ciphers.modes.CBC',
        'cryptography.hazmat.primitives.padding.PKCS7',
        'cryptography.hazmat.primitives.serialization.pkcs12.load_key_and_certificates',
        'dataclasses.dataclass',
        'datetime.datetime.fromtimestamp',
        'dncil.cil.body.reader.read_method_body_from_bytes',
        'dnfile.dnPE',
        'functools.cache',
        'functools.lru_cache',
        'functools.reduce',
        'functools.wraps',
        'gzip.decompress',
        'hashlib.md5',
        'hashlib.pbkdf2_hmac',
        'hashlib.sha256',
        'hmac.compare_digest',
        'hmac.new',
        'importlib.util.module_from_spec',
        'importlib.util.spec_from_file_location',
        'io.BytesIO',
        'ipaddress.ip_address',
        'itertools.cycle',
        'itertools.islice',
        'itertools.pairwise',
        'json.JSONDecoder',
        'json.dumps',
        'json.loads',
        'sys.modules.get',
        'logging.Logger.manager.loggerDict.items',
        'logging.NullHandler',
        'logging.disable',
        'logging.getLogger',
        'math.log2',
        'warnings.catch_warnings',
        'warnings.simplefilter',
        'olefile.OleFileIO',
        'pathlib.Path',
        'pathlib.PurePosixPath',
        'pefile.PE',
        're.compile',
        're.escape',
        're.findall',
        're.finditer',
        're.fullmatch',
        're.match',
        're.search',
        're.sub',
        'refinery.lib.fast.aplib.aplib_decompress',
        'shlex.split',
        'struct.Struct',
        'struct.calcsize',
        'struct.pack',
        'struct.pack_into',
        'struct.unpack',
        'struct.unpack_from',
        'threading.RLock',
        'urllib.parse.urljoin',
        'urllib.parse.urlsplit',
        'urllib.parse.urlunsplit',
        'urllib.parse.urlparse',
        'zipfile.ZipFile',
        'zlib.compress',
        'zlib.crc32',
        'zlib.decompress',
        'zlib.decompressobj',
        'Cryptodome.Cipher.DES3.new',
        'ast.parse',
        'cryptography.hazmat.primitives.ciphers.algorithms.ChaCha20',
        'importlib.util.util.module_from_spec',
        'importlib.util.util.spec_from_file_location',
        'itertools.combinations',
        'itertools.product',
        'numpy.clip',
        'numpy.floor',
        'numpy.frombuffer',
        'numpy.maximum',
        'numpy.zeros',
        'os.fspath',
        'os.fstat',
        'os.path.abspath',
        'os.path.commonpath',
        'os.path.normcase',
        'os.path.normpath',
        'os.path.samestat',
        'stat.S_ISDIR',
        'stat.S_ISREG',
        'types.SimpleNamespace',
        'unicodedata.normalize',
        'urllib.parse.parse.urljoin',
        'urllib.parse.parse.urlsplit',
        'urllib.parse.parse.urlunsplit',
        'uuid.UUID',
        'xml.etree.ElementTree.fromstring',
    }
)
_APPROVED_BUILTIN_CALLS = frozenset(
    {
        'ImportError', 'KeyError', 'RuntimeError', 'TypeError', 'ValueError',
        'abs', 'all', 'any', 'bool', 'bytearray', 'bytes', 'float',
        'chr', 'dict', 'enumerate', 'frozenset', 'hasattr', 'hex',
        'int', 'isinstance', 'len', 'list', 'max', 'min', 'ord',
        'property', 'range', 'repr', 'reversed', 'round', 'set', 'staticmethod',
        'classmethod', 'str', 'sum',
        'memoryview', 'super', 'tuple', 'type', 'zip',
    }
)
_APPROVED_SAFE_METHOD_NAMES = frozenset(
    {
        '__init__', '__new__', 'absolute', 'add', 'append', 'as_posix',
        'astype', 'bit', 'casefold', 'clear', 'copy', 'count', 'decode',
        'decompress', 'decrypt', 'digest', 'encode', 'end', 'endswith',
        'decryptor', 'encryptor', 'extend', 'feed', 'fileno', 'finalize', 'find',
        'findall', 'finditer', 'from_bytes', 'fromhex', 'fromkeys',
        'flush', 'fullmatch', 'get', 'get_data', 'get_entropy',
        'get_file_offset', 'get_imphash', 'get_memory_mapped_image',
        'get_offset_from_rva', 'get_overlay_data_start_offset',
        'get_rva_from_offset', 'group', 'groups', 'handle_endtag',
        'handle_starttag', 'hexdigest', 'hex', 'index', 'infolist', 'insert',
        'intersection', 'is_absolute', 'is_dir', 'is_file', 'is_symlink',
        'isalnum', 'isalpha', 'isdigit', 'isprintable', 'isspace', 'issubset',
        'isoformat', 'items', 'iter', 'join', 'keys', 'listdir', 'lower',
        'lstat', 'lstrip', 'maketrans', 'match', 'partition',
        'pop', 'public', 'public_bytes', 'raw_decode', 'relative_to',
        'removesuffix', 'replace', 'reshape', 'resolve', 'rfc4514_string',
        'rfind', 'rpartition', 'rsplit', 'rstrip', 'search', 'sizeof', 'sort',
        'span', 'split', 'splitlines', 'start', 'startswith', 'strip', 'sub',
        'subn', 'tell', 'text', 'throw', 'to_bytes', 'tobytes', 'translate',
        'u16', 'u32', 'unpadder',
        'unpack_from', 'update', 'upper', 'values', 'virtual_to_offset',
        'with_name',
    }
)
_APPROVED_GETATTR_ATTRIBUTES = frozenset(
    {
        'CREATE_NEW_PROCESS_GROUP', 'Class', 'DATA_DIRECTORY', 'DIRECTORY_ENTRY_EXCEPTION',
        'DIRECTORY_ENTRY_EXPORT', 'DIRECTORY_ENTRY_IMPORT',
        'DIRECTORY_ENTRY_RESOURCE', 'DIRECTORY_ENTRY_TLS', 'DataOffset',
        'DataSectionOffset', 'FILE_ATTRIBUTE_REPARSE_POINT', 'FieldList',
        'FieldRva', 'FileInfo', 'Id', 'Implementation', 'Key',
        'ManifestResource', 'MethodDef', 'MethodList', 'Name', 'O_BINARY',
        'ProtocolProfileError', 'Rva', 'SIGKILL', 'TypeDef', 'TypeName', 'TypeNamespace',
        '__file__', '__version__', '_data', 'data', 'dll', 'entries',
        'file_offset', 'id', 'instructions', 'mdtables', 'metadata', 'name',
        'net', 'num_rows', 'opcode', 'operand', 'ordinal',
        'parse_data_directories', 'resolve_profile', 'resources', 'row',
        'row_index', 'rows', 'rva', 'scan_report', 'settings', 'size',
        'st_file_attributes', 'st_mtime_ns', 'st_nlink', 'status', 'streams',
        'struct', 'symbols', 'type_name', 'validation_method',
        'validation_note', 'value',
    }
)
_APPROVED_HIGHER_ORDER_CALLBACKS = frozenset(
    {
        'abs', 'dict', 'float', 'int', 'len', 'list', 'operator.xor', 'ord',
        're.escape', 'repr', 'set', 'str',
    }
)
_APPROVED_IN_MEMORY_READER_CONSTRUCTORS = frozenset(
    {'io.BytesIO', 'olefile.OleFileIO', 'zipfile.ZipFile'}
)
_REVIEWED_REPOSITORY_DATA_READS = {
    (
        'extractors/profiled_family.py',
        'reachable:_load_profiles_cached',
        'path.read_text',
    ): (
        'extractors/profiles/windows_family_profiles.json',
        '固定profile registryを検証済みbytes snapshotから読む',
    ),
    (
        'analysis-framework/common/pe_structural_profile.py',
        'reachable:_load_profiles_cached',
        'path.read_text',
    ): (
        'analysis-framework/registry/pe_structural_profiles.json',
        '固定PE structural profileを検証済みbytes snapshotから読む',
    ),
}
_REVIEWED_SOURCE_CALLS = {
    (
        'extractors/profiled_family.py',
        'reachable:load_profiles',
        'path.resolve',
    ): '固定profile pathの正規化のみ',
    (
        'extractors/profiled_family.py',
        'reachable:load_profiles',
        'resolved.stat',
    ): '固定profile snapshotのcache key生成のみ',
    (
        'analysis-framework/common/pe_structural_profile.py',
        'reachable:load_profiles',
        'path.resolve',
    ): '固定PE structural profile pathの正規化のみ',
    (
        'analysis-framework/common/pe_structural_profile.py',
        'reachable:load_profiles',
        'resolved.stat',
    ): '固定PE structural profile snapshotのcache key生成のみ',
    (
        'analysis-framework/malware/traffmonetizer_deployer/extract_config.py',
        'reachable:settings_summary',
        'path.read_text',
    ): 'bounded entryではsettings_path=None固定、runtime loaderもmanifest外readを拒否',
    (
        'analysis-framework/common/safe_private_output.py',
        'reachable:_read_bounded_json',
        'candidate.open',
    ): 'bounded entryではprivate pathなし、runtime loaderもmanifest外openを拒否',
    (
        'analysis-framework/common/extract_pyinstaller_archive.py',
        'reachable:_extract_selected_from_reader',
        'reader.extract',
    ): '入力bytesだけを保持するMemoryCArchiveReaderのsize制限付き展開',
    (
        'analysis-framework/malware/nanocore/extract_config.py',
        'reachable:_take',
        'stream.read',
    ): 'callerが入力bytes由来BytesIOへ固定するbounded read',
    (
        'extractors/acrstealer/extractor.py',
        'reachable:_recover_pumped_zip',
        'archive.open',
    ): '入力bytes由来ZipFile memberのread-only open',
    (
        'extractors/acrstealer/extractor.py',
        'reachable:_recover_pumped_zip',
        'stream.read',
    ): '入力bytes由来ZipExtFileのprefix上限付きread',
    (
        'extractors/remusstealer/extractor.py',
        'reachable:_terminal_memory_report',
        'module.extract_remus_memory_config',
    ): 'hash検証済みdynamic dependencyの監査済みsymbol',
    (
        'extractors/remusstealer/extractor.py',
        'reachable:_build_protocol_profile',
        'module.build_remus_c2_profile',
    ): 'hash検証済みdynamic dependencyの監査済みsymbol',
    (
        'extractors/venomrat/integrated.py',
        'reachable:_validated_recovery',
        'module.recover',
    ): 'hash検証済みdotnet_rat_configのHMAC検証済みVenom設定復元',
    (
        'analysis-framework/common/remus_profile_evidence.py',
        'reachable:_forbidden_identity',
        'absolute.stat',
    ): 'private evidenceのreparse/hardlink拒否用metadata確認',
    (
        'analysis-framework/common/remus_profile_evidence.py',
        'reachable:_read_bounded_json',
        'root.stat',
    ): 'private evidence root差替え拒否用metadata確認',
    (
        'analysis-framework/common/remus_profile_evidence.py',
        'reachable:_read_bounded_json',
        'candidate.stat',
    ): 'private evidence差替え拒否用metadata確認',
    (
        'analysis-framework/common/remus_profile_evidence.py',
        'reachable:_read_bounded_json',
        'candidate.open',
    ): 'bounded entryでpath未指定、runtime loaderもmanifest外openを拒否',
    (
        'analysis-framework/common/remus_profile_evidence.py',
        'reachable:_read_bounded_json',
        'stream.read',
    ): 'open成功時だけのsize上限付きread、bounded runtimeではmanifest外open拒否',
    (
        'analysis-framework/common/dotnet_resource_loader_evidence.py',
        'reachable:_integer_field',
        'getattr',
    ): '全callerが監査済み固定metadata field名を渡す',
    (
        'analysis-framework/common/dotnet_resource_loader_evidence.py',
        'reachable:_declared_table_rows',
        'getattr',
    ): '全callerが監査済み固定table名を渡す',
    (
        'analysis-framework/malware/valleyrat/campaigns/single_pe/analyze_dotnet_il.py',
        'reachable:token_name',
        'getattr',
    ): 'token table idを固定3名称へmapした後だけ参照する',
    (
        'unpackers/managed_il_triage.py',
        'reachable:_contained_parser_diagnostics',
        'logger.setLevel',
    ): '検証済みparser診断抑止scope内でのlogger level退避・復元',
}
_APPROVED_CALLBACK_PARAMETERS = frozenset(
    {
        ('unpackers/javascript_obfuscator.py', '_safe_arithmetic', 'parse_int'),
        ('unpackers/javascript_obfuscator.py', 'visit', 'parse_int'),
        ('unpackers/managed_il_triage.py', 'wrapper', 'function'),
    }
)

_REVIEWED_IMPORT_NAMESPACE_MUTATIONS = frozenset(
    {
        (
            'extractors/remusstealer/extractor.py',
            'reachable:_load_exact_module',
            'sys.modules[]',
        ),
        (
            'extractors/venomrat/integrated.py',
            'reachable:_load_dotnet_rat_config',
            'sys.modules[]',
        ),
    }
)


@dataclass(frozen=True)
class _ImportBinding:
    module: str
    symbol: str | None
    level: int
    imported_module: str


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
    for node in _nodes_in_lexical_scope(tree):
        if isinstance(node, ast.Import):
            for item in node.names:
                aliases[item.asname or item.name.split('.')[0]] = item.name
        elif isinstance(node, ast.ImportFrom) and node.module:
            for item in node.names:
                if item.name != '*':
                    aliases[item.asname or item.name] = f'{node.module}.{item.name}'
    return aliases


def _target_binding_paths(node: ast.AST) -> set[str]:
    """代入・削除targetが束縛または変更する静的な名前を返す。"""

    if isinstance(node, ast.Name):
        return {node.id}
    if isinstance(node, ast.Attribute):
        name = _ast_call_name(node)
        return {name} if name else set()
    if isinstance(node, ast.Subscript):
        name = _ast_call_name(node.value)
        return {f'{name}[]'} if name else set()
    if isinstance(node, ast.Starred):
        return _target_binding_paths(node.value)
    if isinstance(node, (ast.List, ast.Tuple)):
        return {
            name
            for item in node.elts
            for name in _target_binding_paths(item)
        }
    return set()


def _scope_non_import_bindings(scope: ast.AST) -> set[str]:
    """import自体を除き、scope内で上書きされる名前・属性を列挙する。"""

    result: set[str] = set()
    if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)):
        result.update(
            item.arg
            for item in (
                *scope.args.posonlyargs,
                *scope.args.args,
                *scope.args.kwonlyargs,
            )
        )
        if scope.args.vararg is not None:
            result.add(scope.args.vararg.arg)
        if scope.args.kwarg is not None:
            result.add(scope.args.kwarg.arg)
    for item in _nodes_in_lexical_scope(scope):
        targets: tuple[ast.AST, ...] = ()
        if isinstance(item, ast.Assign):
            targets = tuple(item.targets)
        elif isinstance(
            item,
            (
                ast.AnnAssign,
                ast.AugAssign,
                ast.NamedExpr,
                ast.For,
                ast.AsyncFor,
                ast.comprehension,
            ),
        ):
            targets = (item.target,)
        elif isinstance(item, (ast.With, ast.AsyncWith)):
            targets = tuple(
                entry.optional_vars
                for entry in item.items
                if entry.optional_vars is not None
            )
        elif isinstance(item, ast.Delete):
            targets = tuple(item.targets)
        for target in targets:
            result.update(_target_binding_paths(target))
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if item is not scope:
                result.add(item.name)
        elif isinstance(item, ast.ExceptHandler) and item.name:
            result.add(item.name)
    return result


def _expression_binding_is_intact(
    node: ast.AST,
    tree: ast.Module,
    scope: ast.AST,
) -> bool:
    """callback/callable名がimport後やbuiltin名から上書きされていないか確認する。"""

    name = _ast_call_name(node)
    if not name:
        return False
    root = name.split('.', 1)[0]
    active_scopes = (tree,) if scope is tree else (tree, scope)
    for active_scope in active_scopes:
        for bound in _scope_non_import_bindings(active_scope):
            if bound in {root, name} or name.startswith(f'{bound}.'):
                return False
    return True


def _import_namespace_mutations(
    scope: ast.AST,
    import_bindings: Mapping[str, _ImportBinding],
) -> tuple[str, ...]:
    """import済みmoduleの属性・mappingを書き換えるtargetを列挙する。"""

    mutated: set[str] = set()
    for item in _nodes_in_lexical_scope(scope):
        targets: tuple[ast.AST, ...] = ()
        if isinstance(item, ast.Assign):
            targets = tuple(item.targets)
        elif isinstance(item, (ast.AnnAssign, ast.AugAssign, ast.NamedExpr)):
            targets = (item.target,)
        elif isinstance(item, ast.Delete):
            targets = tuple(item.targets)
        for target in targets:
            for name in _target_binding_paths(target):
                root = name.split('.', 1)[0].removesuffix('[]')
                if root in import_bindings and name != root:
                    mutated.add(name)
    return tuple(sorted(mutated))



def _expanded_expression_name(
    node: ast.AST,
    aliases: Mapping[str, str],
) -> str | None:
    name = _ast_call_name(node)
    if not name:
        return None
    first, separator, remainder = name.partition('.')
    replacement = aliases.get(first)
    if not replacement:
        return name
    return replacement + (separator + remainder if separator else '')


def _expanded_call_name(node: ast.Call, aliases: Mapping[str, str]) -> str | None:
    return _expanded_expression_name(node.func, aliases)


def _safe_callback_expression(
    node: ast.AST,
    aliases: Mapping[str, str],
    *,
    allow_none: bool = False,
) -> bool:
    if isinstance(node, ast.Lambda):
        return True
    if allow_none and isinstance(node, ast.Constant) and node.value is None:
        return True
    name = _expanded_expression_name(node, aliases)
    return name in _APPROVED_HIGHER_ORDER_CALLBACKS


def _safe_replacement_expression(
    node: ast.AST,
    aliases: Mapping[str, str],
) -> bool:
    return isinstance(node, (ast.Constant, ast.JoinedStr, ast.Lambda)) or (
        _safe_callback_expression(node, aliases)
    )


def _approved_getattr_call(node: ast.Call) -> bool:
    return (
        len(node.args) in {2, 3}
        and not node.keywords
        and isinstance(node.args[1], ast.Constant)
        and isinstance(node.args[1].value, str)
        and node.args[1].value in _APPROVED_GETATTR_ATTRIBUTES
    )


def _approved_higher_order_builtin(
    node: ast.Call,
    name: str,
    aliases: Mapping[str, str],
) -> bool:
    if name == 'getattr':
        return _approved_getattr_call(node)
    if name == 'iter':
        return len(node.args) == 1 and not node.keywords
    if name == 'next':
        if not 1 <= len(node.args) <= 2 or node.keywords:
            return False
        source = node.args[0]
        if isinstance(source, (ast.GeneratorExp, ast.ListComp, ast.SetComp)):
            return True
        return (
            isinstance(source, ast.Call)
            and _expanded_call_name(source, aliases) == 'iter'
            and len(source.args) == 1
            and not source.keywords
        )
    if name in {'map', 'filter'}:
        return (
            len(node.args) >= 2
            and not node.keywords
            and _safe_callback_expression(
                node.args[0],
                aliases,
                allow_none=name == 'filter',
            )
        )
    if name in {'sorted', 'min', 'max'}:
        if not node.args or any(item.arg is None for item in node.keywords):
            return False
        key_values = [item.value for item in node.keywords if item.arg == 'key']
        if len(key_values) > 1:
            return False
        return not key_values or _safe_callback_expression(key_values[0], aliases)
    return False


def _approved_ole_container_expression(
    node: ast.AST,
    tree: ast.Module,
    scope: ast.AST,
    aliases: Mapping[str, str],
) -> bool:
    return (
        isinstance(node, ast.Call)
        and _expanded_call_name(node, aliases) == 'olefile.OleFileIO'
        and _expression_binding_is_intact(node.func, tree, scope)
        and _approved_external_call(node, 'olefile.OleFileIO', aliases)
    )


def _approved_ole_openstream(
    node: ast.AST,
    tree: ast.Module,
    scope: ast.AST,
    aliases: Mapping[str, str],
) -> bool:
    if (
        not isinstance(node, ast.Call)
        or not isinstance(node.func, ast.Attribute)
        or node.func.attr != 'openstream'
    ):
        return False
    receiver = node.func.value
    if _approved_ole_container_expression(receiver, tree, scope, aliases):
        return True
    if not isinstance(receiver, ast.Name):
        return False
    receiver_name = receiver.id
    if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)) and any(
        item.arg == receiver_name
        for item in (
            *scope.args.posonlyargs,
            *scope.args.args,
            *scope.args.kwonlyargs,
        )
    ):
        return False
    origins: list[ast.AST] = []
    unsafe_binding = False
    for item in _nodes_in_lexical_scope(scope):
        if isinstance(item, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
            targets = item.targets if isinstance(item, ast.Assign) else (item.target,)
            if any(isinstance(target, ast.Name) and target.id == receiver_name for target in targets):
                origins.append(item.value)
        elif isinstance(item, (ast.For, ast.AsyncFor, ast.comprehension)):
            if receiver_name in _target_binding_paths(item.target):
                unsafe_binding = True
        elif isinstance(item, (ast.With, ast.AsyncWith)):
            for with_item in item.items:
                if (
                    isinstance(with_item.optional_vars, ast.Name)
                    and with_item.optional_vars.id == receiver_name
                ):
                    origins.append(with_item.context_expr)
    return (
        not unsafe_binding
        and bool(origins)
        and all(
            _approved_ole_container_expression(item, tree, scope, aliases)
            for item in origins
        )
    )


def _safe_reader_expression(
    node: ast.AST,
    tree: ast.Module,
    scope: ast.AST,
    aliases: Mapping[str, str],
) -> bool:
    if not isinstance(node, ast.Call):
        return False
    name = _expanded_call_name(node, aliases)
    if name in _APPROVED_IN_MEMORY_READER_CONSTRUCTORS:
        return (
            _expression_binding_is_intact(node.func, tree, scope)
            and _approved_external_call(node, name, aliases)
        )
    return _approved_ole_openstream(node, tree, scope, aliases)


def _approved_in_memory_read(
    node: ast.Call,
    tree: ast.Module,
    scope: ast.AST,
    aliases: Mapping[str, str],
) -> bool:
    if not isinstance(node.func, ast.Attribute) or node.func.attr != 'read':
        return False
    receiver = node.func.value
    if _safe_reader_expression(receiver, tree, scope, aliases):
        return True
    if not isinstance(receiver, ast.Name):
        return False
    receiver_name = receiver.id
    if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)) and any(
        item.arg == receiver_name
        for item in (
            *scope.args.posonlyargs,
            *scope.args.args,
            *scope.args.kwonlyargs,
        )
    ):
        return False
    origins: list[ast.AST] = []
    unsafe_binding = False
    for item in _nodes_in_lexical_scope(scope):
        if isinstance(item, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
            targets = item.targets if isinstance(item, ast.Assign) else (item.target,)
            if any(isinstance(target, ast.Name) and target.id == receiver_name for target in targets):
                origins.append(item.value)
        elif isinstance(item, (ast.For, ast.AsyncFor)):
            if any(
                isinstance(target, ast.Name) and target.id == receiver_name
                for target in ast.walk(item.target)
            ):
                unsafe_binding = True
        elif isinstance(item, (ast.With, ast.AsyncWith)):
            for with_item in item.items:
                if (
                    isinstance(with_item.optional_vars, ast.Name)
                    and with_item.optional_vars.id == receiver_name
                ):
                    origins.append(with_item.context_expr)
    return (
        not unsafe_binding
        and bool(origins)
        and all(_safe_reader_expression(item, tree, scope, aliases) for item in origins)
    )


def _open_call_writes(node: ast.Call) -> bool:
    '''open系呼出しが書込みmodeを明示するか返す。'''

    values: list[ast.AST] = []
    if len(node.args) >= 2:
        values.append(node.args[1])
    values.extend(item.value for item in node.keywords if item.arg == 'mode')
    for value in values:
        if (
            isinstance(value, ast.Constant)
            and isinstance(value.value, str)
            and any(marker in value.value for marker in ('w', 'a', 'x', '+'))
        ):
            return True
    return False


def _approved_external_call(
    node: ast.Call,
    name: str,
    aliases: Mapping[str, str],
) -> bool:
    if name not in _APPROVED_EXTERNAL_CALLS:
        return False
    if name in {'pefile.PE', 'dnfile.dnPE'}:
        return any(item.arg == 'data' for item in node.keywords)
    if name in {'olefile.OleFileIO', 'zipfile.ZipFile'}:
        if not node.args or not isinstance(node.args[0], ast.Call):
            return False
        source_name = _expanded_call_name(node.args[0], aliases)
        if source_name != 'io.BytesIO':
            return False
        mode_nodes = [
            *(node.args[1:2]),
            *(item.value for item in node.keywords if item.arg == 'mode'),
        ]
        return all(
            isinstance(item, ast.Constant)
            and isinstance(item.value, str)
            and item.value in {'r', 'rb'}
            for item in mode_nodes
        )
    if name == 'functools.reduce':
        return (
            2 <= len(node.args) <= 3
            and not node.keywords
            and _safe_callback_expression(node.args[0], aliases)
        )
    if name == 'collections.defaultdict':
        return (
            len(node.args) <= 1
            and not node.keywords
            and (
                not node.args
                or _safe_callback_expression(
                    node.args[0],
                    aliases,
                    allow_none=True,
                )
            )
        )
    if name in {'re.sub', 're.subn'}:
        return (
            len(node.args) >= 3
            and _safe_replacement_expression(node.args[1], aliases)
        )
    if name in {'json.loads', 'json.JSONDecoder'}:
        callback_keywords = {
            'object_hook', 'object_pairs_hook', 'parse_constant',
            'parse_float', 'parse_int',
        }
        return not any(item.arg in callback_keywords for item in node.keywords)
    return True


def _forbidden_call_reason(node: ast.Call, aliases: Mapping[str, str]) -> str | None:
    name = _expanded_call_name(node, aliases)
    if not name:
        return None
    if name == 'numpy.fromfile':
        return 'forbidden_unverified_filesystem_read:numpy.fromfile'
    if name in {'pefile.PE', 'dnfile.dnPE'} and not any(
        item.arg == 'data' for item in node.keywords
    ):
        return f'forbidden_path_parser_input:{name}'
    if name in {'olefile.OleFileIO', 'zipfile.ZipFile'} and not _approved_external_call(
        node,
        name,
        aliases,
    ):
        return f'forbidden_path_parser_input:{name}'
    if name in _FORBIDDEN_CALL_NAMES or name.startswith(_FORBIDDEN_CALL_PREFIXES):
        return f'forbidden_call:{name}'
    if name.startswith(('ctypes.windll', 'ctypes.WinDLL', 'ctypes.CDLL', 'ctypes.PyDLL')):
        return f'forbidden_native_call:{name}'
    if name.rsplit('.', 1)[-1] in _FORBIDDEN_METHOD_NAMES:
        return f'forbidden_side_effect_method:{name}'
    if name.rsplit('.', 1)[-1] == 'open' and _open_call_writes(node):
        return f'forbidden_write_open:{name}'
    if name.rsplit('.', 1)[-1] == 'open':
        return f'forbidden_unverified_filesystem_open:{name}'
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


@cache
def _relative_audit_path(path: Path) -> str:
    """監査対象pathをrepository相対の公開値へ変換する。"""

    return path.resolve(strict=True).relative_to(REPOSITORY_ROOT.resolve(strict=True)).as_posix()


def _approved_external_module(module: str) -> bool:
    root = module.split('.', 1)[0]
    return (
        root == '__future__'
        or root in sys.stdlib_module_names
        or root in _APPROVED_EXTERNAL_MODULE_ROOTS
    )


def _local_import_roots(current_path: Path) -> tuple[Path, ...]:
    framework = REPOSITORY_ROOT / 'analysis-framework'
    values: tuple[Path, ...] = (
        current_path.parent,
        REPOSITORY_ROOT,
        framework,
        framework / 'common',
        REPOSITORY_ROOT / 'extractors',
    )
    try:
        malware_relative = current_path.resolve().relative_to(MALWARE_ROOT.resolve())
    except ValueError:
        pass
    else:
        if len(malware_relative.parts) > 1:
            values = (
                current_path.parent,
                MALWARE_ROOT / malware_relative.parts[0],
                *values[1:],
            )
    result: list[Path] = []
    for value in values:
        resolved = value.resolve()
        if resolved not in result:
            result.append(resolved)
    return tuple(result)


@cache
def _resolve_local_module_path(
    current_path: Path,
    module: str,
    *,
    level: int = 0,
) -> tuple[Path | None, str | None]:
    """Python import規則のrepository-local候補だけを安全に解決する。"""

    parts = tuple(item for item in module.split('.') if item)
    if level:
        base = current_path.parent
        for _index in range(level - 1):
            base = base.parent
        roots = (base,)
    else:
        roots = _local_import_roots(current_path)
    matches: list[Path] = []
    repository = REPOSITORY_ROOT.resolve(strict=True)
    from analysis_contract import ensure_no_reparse_components

    for root in roots:
        base = root.joinpath(*parts)
        for candidate in (base.with_suffix('.py'), base / '__init__.py'):
            if not candidate.exists():
                continue
            try:
                ensure_no_reparse_components(candidate)
                resolved = candidate.resolve(strict=True)
            except (OSError, ValueError) as exc:
                return None, f'unsafe_local_import:{type(exc).__name__}'
            if resolved != repository and repository not in resolved.parents:
                return None, 'local_import_outside_repository'
            if not resolved.is_file() or resolved.suffix.casefold() != '.py':
                return None, 'local_import_not_python_source'
            if resolved not in matches:
                matches.append(resolved)
    if len(matches) > 1:
        rendered = ','.join(sorted(_relative_audit_path(item) for item in matches))
        return None, f'ambiguous_local_import:{module}:{rendered}'
    if (
        not matches
        and level == 0
        and len(parts) == 1
        and not _approved_external_module(module)
    ):
        fallback_matches: list[Path] = []
        for candidate in repository.rglob(f'{parts[0]}.py'):
            relative_parts = candidate.relative_to(repository).parts
            if any(part in {'tests', '.git', '.venv', '__pycache__'} for part in relative_parts):
                continue
            try:
                ensure_no_reparse_components(candidate)
                resolved = candidate.resolve(strict=True)
            except (OSError, ValueError) as exc:
                return None, f'unsafe_local_import:{type(exc).__name__}'
            if resolved not in fallback_matches:
                fallback_matches.append(resolved)
            if len(fallback_matches) > 16:
                return None, f'ambiguous_local_import:{module}:too_many_matches'
        if len(fallback_matches) > 1:
            rendered = ','.join(sorted(_relative_audit_path(item) for item in fallback_matches))
            return None, f'ambiguous_local_import:{module}:{rendered}'
        if fallback_matches:
            return fallback_matches[0], None
    return (matches[0], None) if matches else (None, None)


def _function_definition_runtime_expressions(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> tuple[ast.AST, ...]:
    """関数定義時に評価され得る式を漏れなく列挙する。"""

    arguments = (
        *node.args.posonlyargs,
        *node.args.args,
        *node.args.kwonlyargs,
    )
    values: list[ast.AST | None] = [
        *node.decorator_list,
        *node.args.defaults,
        *node.args.kw_defaults,
        *(item.annotation for item in arguments),
        node.args.vararg.annotation if node.args.vararg is not None else None,
        node.args.kwarg.annotation if node.args.kwarg is not None else None,
        node.returns,
    ]
    for type_parameter in getattr(node, 'type_params', ()):
        values.extend(
            (
                getattr(type_parameter, 'bound', None),
                getattr(type_parameter, 'default_value', None),
            )
        )
    return tuple(value for value in values if isinstance(value, ast.AST))


def _nodes_in_lexical_scope(scope: ast.AST) -> tuple[ast.AST, ...]:
    """nested function/classへ越境せず現在のlexical scopeだけを列挙する。"""

    nodes: list[ast.AST] = []

    class Visitor(ast.NodeVisitor):
        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            nodes.append(node)
            for expression in _function_definition_runtime_expressions(node):
                self.visit(expression)
            if node is scope:
                for statement in node.body:
                    self.visit(statement)

        visit_AsyncFunctionDef = visit_FunctionDef

        def visit_ClassDef(self, node: ast.ClassDef) -> None:
            nodes.append(node)
            for expression in (
                *node.decorator_list,
                *node.bases,
                *(item.value for item in node.keywords),
            ):
                self.visit(expression)
            if node is scope:
                for statement in node.body:
                    self.visit(statement)

        def generic_visit(self, node: ast.AST) -> None:
            nodes.append(node)
            super().generic_visit(node)

    visitor = Visitor()
    if isinstance(scope, ast.Module):
        nodes.append(scope)
        for statement in scope.body:
            visitor.visit(statement)
    else:
        visitor.visit(scope)
    return tuple(nodes)


def _detailed_import_bindings(scope: ast.AST) -> dict[str, _ImportBinding]:
    bindings: dict[str, _ImportBinding] = {}
    for node in _nodes_in_lexical_scope(scope):
        if isinstance(node, ast.Import):
            for item in node.names:
                if item.asname:
                    alias = item.asname
                    bound_module = item.name
                else:
                    alias = item.name.split('.')[0]
                    bound_module = alias
                bindings[alias] = _ImportBinding(
                    module=bound_module,
                    symbol=None,
                    level=0,
                    imported_module=item.name,
                )
        elif isinstance(node, ast.ImportFrom):
            for item in node.names:
                if item.name == '*':
                    continue
                alias = item.asname or item.name
                bindings[alias] = _ImportBinding(
                    module=node.module or '',
                    symbol=item.name,
                    level=node.level,
                    imported_module=node.module or '',
                )
    return bindings


def _top_level_calls(tree: ast.Module) -> list[ast.Call]:
    """import時に評価される式のcallだけを列挙し、関数bodyとmain guardを除く。"""

    calls: list[ast.Call] = []

    class Visitor(ast.NodeVisitor):
        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            for expression in _function_definition_runtime_expressions(node):
                self.visit(expression)

        visit_AsyncFunctionDef = visit_FunctionDef

        def visit_Lambda(self, node: ast.Lambda) -> None:
            return None

        def visit_If(self, node: ast.If) -> None:
            is_main_guard = (
                isinstance(node.test, ast.Compare)
                and isinstance(node.test.left, ast.Name)
                and node.test.left.id == '__name__'
                and any(
                    isinstance(item, ast.Constant) and item.value == '__main__'
                    for item in node.test.comparators
                )
            )
            self.visit(node.test)
            if not is_main_guard:
                for statement in (*node.body, *node.orelse):
                    self.visit(statement)

        def visit_Call(self, node: ast.Call) -> None:
            calls.append(node)
            self.generic_visit(node)

    visitor = Visitor()
    for statement in tree.body:
        visitor.visit(statement)
    return calls


def _assigned_names(node: ast.AST) -> set[str]:
    names: set[str] = set()
    for item in _nodes_in_lexical_scope(node):
        if isinstance(item, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
            targets = item.targets if isinstance(item, ast.Assign) else (item.target,)
            for target in targets:
                for child in ast.walk(target):
                    if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Store):
                        names.add(child.id)
        elif isinstance(item, (ast.For, ast.AsyncFor)):
            for child in ast.walk(item.target):
                if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Store):
                    names.add(child.id)
    return names


def _static_path_expression(
    node: ast.AST,
    tree: ast.Module,
    visited_names: set[str] | None = None,
) -> tuple[bool, bool]:
    """path式が安全なliteralだけで構成され、__file__起点かを返す。"""

    visited = set() if visited_names is None else visited_names
    if isinstance(node, ast.Name):
        if node.id == '__file__':
            return True, True
        if node.id in visited:
            return False, False
        assignment = next(
            (
                item.value
                for item in tree.body
                if isinstance(item, (ast.Assign, ast.AnnAssign))
                and any(
                    isinstance(target, ast.Name) and target.id == node.id
                    for target in (
                        item.targets if isinstance(item, ast.Assign) else (item.target,)
                    )
                )
            ),
            None,
        )
        if assignment is None:
            loop_values = next(
                (
                    item.iter.elts
                    for item in tree.body
                    if isinstance(item, (ast.For, ast.AsyncFor))
                    and isinstance(item.target, ast.Name)
                    and item.target.id == node.id
                    and isinstance(item.iter, (ast.Tuple, ast.List))
                ),
                None,
            )
            if loop_values is None:
                return False, False
            evaluated = [
                _static_path_expression(item, tree, {*visited, node.id})
                for item in loop_values
            ]
            return all(valid for valid, _origin in evaluated), all(
                origin for _valid, origin in evaluated
            )
        return _static_path_expression(assignment, tree, {*visited, node.id})
    if isinstance(node, ast.Constant):
        if isinstance(node.value, int):
            return True, False
        if isinstance(node.value, str):
            value = node.value.replace('\\', '/')
            safe = '\x00' not in value and not value.startswith('/') and not re.match(r'^[A-Za-z]:', value) and '..' not in value.split('/')
            return safe, False
        return False, False
    if isinstance(node, ast.Call):
        if isinstance(node.func, ast.Name) and node.func.id in {'Path', 'str'} and len(node.args) == 1:
            return _static_path_expression(node.args[0], tree, visited)
        if isinstance(node.func, ast.Attribute) and node.func.attr == 'resolve' and not node.args:
            return _static_path_expression(node.func.value, tree, visited)
        return False, False
    if isinstance(node, ast.Attribute) and node.attr in {'parent', 'parents'}:
        return _static_path_expression(node.value, tree, visited)
    if isinstance(node, ast.Subscript):
        valid, origin = _static_path_expression(node.value, tree, visited)
        slice_valid, _slice_origin = _static_path_expression(node.slice, tree, visited)
        return valid and slice_valid, origin
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
        left_valid, left_origin = _static_path_expression(node.left, tree, visited)
        right_valid, right_origin = _static_path_expression(node.right, tree, visited)
        return left_valid and right_valid, left_origin or right_origin
    return False, False


def _safe_static_sys_path_insert(call: ast.Call, tree: ast.Module) -> bool:
    """sys.path先頭追加が当該sourceの__file__起点repository pathか確認する。"""

    if len(call.args) < 2 or not isinstance(call.args[0], ast.Constant) or call.args[0].value != 0:
        return False
    valid, file_origin = _static_path_expression(call.args[1], tree)
    return valid and file_origin


def _binding_local_call_target(
    path: Path,
    binding: _ImportBinding,
    remainder: Sequence[str],
) -> tuple[Path | None, str | None, str | None]:
    """import alias経由callをlocal module pathとsymbolへ解決する。"""

    if binding.symbol is not None:
        expanded_segments = [*binding.module.split('.'), binding.symbol, *remainder]
        minimum_module_parts = len(binding.module.split('.')) + 1
        for split_at in range(len(expanded_segments) - 1, minimum_module_parts - 1, -1):
            expanded_module = '.'.join(expanded_segments[:split_at])
            expanded_target, expanded_error = _resolve_local_module_path(
                path,
                expanded_module,
                level=binding.level,
            )
            if expanded_error:
                return None, None, expanded_error
            if expanded_target is not None:
                return expanded_target, '.'.join(expanded_segments[split_at:]) or None, None
        target, error = _resolve_local_module_path(
            path,
            binding.module,
            level=binding.level,
        )
        if error or target is not None:
            symbol = '.'.join((binding.symbol, *remainder))
            return target, symbol, error
        expanded_module = '.'.join(item for item in (binding.module, binding.symbol) if item)
        target, error = _resolve_local_module_path(path, expanded_module, level=binding.level)
        return target, remainder[-1] if target is not None and remainder else None, error

    segments = [*binding.module.split('.'), *remainder]
    for split_at in range(len(segments) - 1, 0, -1):
        module = '.'.join(segments[:split_at])
        target, error = _resolve_local_module_path(path, module, level=binding.level)
        if error:
            return None, None, error
        if target is not None:
            symbol = '.'.join(segments[split_at:]) or None
            return target, symbol, None
    target, error = _resolve_local_module_path(path, binding.module, level=binding.level)
    return target, '.'.join(remainder) or None, error


@cache
def _recursive_handler_side_effect_audit(path: Path, callable_name: str) -> dict[str, Any]:
    """reachable local helperをfile間で追跡し、importせず副作用callを監査する。"""

    issues: set[str] = set()
    files: dict[Path, str] = {}
    data_files: dict[Path, tuple[str, str]] = {}
    module_bindings: dict[str, tuple[Path, bool]] = {}
    visited_imports: set[Path] = set()
    visited_functions: set[tuple[Path, str]] = set()
    visited_definitions: set[tuple[Path, int, int, str]] = set()
    allowance_counts: dict[str, int] = {}
    allowance_examples: dict[str, set[str]] = {}
    calls_inspected = 0
    local_calls_followed = 0
    binding_cache: dict[ast.AST, dict[str, _ImportBinding]] = {}
    alias_cache: dict[ast.Module, dict[str, str]] = {}
    definition_cache: dict[ast.Module, dict[str, ast.AST]] = {}
    scope_symbol_cache: dict[ast.AST, tuple[set[str], set[str], set[str]]] = {}

    def bindings(scope: ast.AST) -> dict[str, _ImportBinding]:
        return binding_cache.setdefault(scope, _detailed_import_bindings(scope))

    def aliases(tree: ast.Module) -> dict[str, str]:
        return alias_cache.setdefault(tree, _import_aliases(tree))

    def definitions(tree: ast.Module) -> dict[str, ast.AST]:
        return definition_cache.setdefault(
            tree,
            {
                node.name: node
                for node in tree.body
                if isinstance(node, (ast.FunctionDef, ast.ClassDef))
            },
        )

    def scope_symbols(scope: ast.AST) -> tuple[set[str], set[str], set[str]]:
        cached = scope_symbol_cache.get(scope)
        if cached is not None:
            return cached
        nested = {
            node.name
            for node in _nodes_in_lexical_scope(scope)
            if isinstance(node, (ast.FunctionDef, ast.ClassDef)) and node is not scope
        }
        assigned = _assigned_names(scope)
        parameters = (
            {
                item.arg
                for item in (
                    *scope.args.posonlyargs,
                    *scope.args.args,
                    *scope.args.kwonlyargs,
                )
            }
            if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef))
            else set()
        )
        cached = (nested, assigned, parameters)
        scope_symbol_cache[scope] = cached
        return cached

    def allow(reason: str, call_name: str) -> None:
        allowance_counts[reason] = allowance_counts.get(reason, 0) + 1
        examples = allowance_examples.setdefault(reason, set())
        if len(examples) < 8:
            examples.add(call_name)

    def register_file(source: Path, depth: int) -> ast.Module | None:
        if depth > MAX_ASSESSMENT_IMPORT_DEPTH:
            issues.add(f'import_depth_limit:{_relative_audit_path(source)}')
            return None
        try:
            resolved = source.resolve(strict=True)
            relative = _relative_audit_path(resolved)
        except (OSError, ValueError) as exc:
            issues.add(f'unsafe_dependency_path:{type(exc).__name__}')
            return None
        if resolved not in files:
            if len(files) >= MAX_ASSESSMENT_IMPORT_FILES:
                issues.add('import_file_limit')
                return None
            try:
                content = resolved.read_bytes()
                tree = ast.parse(content.decode('utf-8-sig'), filename=str(resolved))
            except (OSError, SyntaxError, UnicodeError) as exc:
                issues.add(f'dependency_parse_error:{relative}:{type(exc).__name__}')
                return None
            files[resolved] = hashlib.sha256(content).hexdigest()
            return tree
        try:
            return _module_tree(resolved)
        except (OSError, SyntaxError, UnicodeError) as exc:
            issues.add(f'dependency_parse_error:{relative}:{type(exc).__name__}')
            return None

    def dynamic_call_allowed(source: Path, name: str) -> bool:
        relative = _relative_audit_path(source)
        if name == 'sys.path.insert':
            return relative in _APPROVED_STATIC_SYS_PATH_SOURCES
        if relative not in _LEGACY_DYNAMIC_LOCAL_DEPENDENCIES:
            return False
        return (
            name in {'importlib.util.spec_from_file_location', 'importlib.util.module_from_spec', 'sys.path.insert'}
            or name.endswith('.exec_module')
            or name.startswith('sys.modules.')
        )

    def register_module_binding(name: str, target: Path) -> None:
        if not name or any(not part.isidentifier() for part in name.split('.')):
            issues.add(f'invalid_local_module_binding:{name}')
            return
        resolved = target.resolve(strict=True)
        binding = (resolved, resolved.name == '__init__.py')
        previous = module_bindings.get(name)
        if previous is not None and previous != binding:
            issues.add(f'ambiguous_local_module_binding:{name}')
            return
        module_bindings[name] = binding

    def relative_module_name(
        source: Path,
        imported: str,
        level: int,
    ) -> str | None:
        source_names = [
            name
            for name, (target, _is_package) in module_bindings.items()
            if target == source.resolve(strict=True)
        ]
        if len(source_names) != 1:
            return None
        current = source_names[0].split('.')
        package = current if source.name == '__init__.py' else current[:-1]
        if level < 1 or level > len(package):
            return None
        base = package[: len(package) - (level - 1)]
        suffix = [item for item in imported.split('.') if item]
        result = '.'.join((*base, *suffix))
        return result or None

    def audit_imports(source: Path, tree: ast.Module, depth: int) -> None:
        bindings = _detailed_import_bindings(tree)
        for binding in bindings.values():
            imported = binding.imported_module
            target, error = _resolve_local_module_path(
                source,
                imported,
                level=binding.level,
            )
            if error:
                issues.add(f'import:{error}')
                continue
            if target is not None:
                if binding.level:
                    canonical = relative_module_name(
                        source,
                        imported,
                        binding.level,
                    )
                    if canonical is None:
                        issues.add(
                            f'relative_import_requires_canonical_binding:'
                            f'{imported or binding.symbol}'
                        )
                        continue
                    register_module_binding(canonical, target)
                    audit_module(target, depth + 1)
                    continue
                parts = imported.split('.')
                for index in range(1, len(parts) + 1):
                    module_name = '.'.join(parts[:index])
                    module_target, module_error = _resolve_local_module_path(
                        source,
                        module_name,
                    )
                    if module_error:
                        issues.add(f'import:{module_error}')
                        break
                    if module_target is not None:
                        register_module_binding(module_name, module_target)
                        audit_module(module_target, depth + 1)
                register_module_binding(imported, target)
                audit_module(target, depth + 1)
                continue
            if binding.level:
                issues.add(f'unresolved_local_import:{imported or binding.symbol}')
            elif _approved_external_module(imported):
                allow('approved_external_import', imported)
            else:
                issues.add(f'unresolved_local_or_unapproved_import:{imported}')

    def audit_target(source: Path, symbol: str | None, depth: int, context: str) -> None:
        nonlocal local_calls_followed
        tree = register_file(source, depth)
        if tree is None:
            return
        if symbol is None:
            return
        top_name = symbol.split('.', 1)[0]
        node = definitions(tree).get(top_name)
        if node is None:
            method = symbol.rsplit('.', 1)[-1]
            assignment = next(
                (
                    item
                    for item in tree.body
                    if isinstance(item, (ast.Assign, ast.AnnAssign))
                    and any(
                        isinstance(target, ast.Name) and target.id == top_name
                        for target in (
                            item.targets if isinstance(item, ast.Assign) else (item.target,)
                        )
                    )
                ),
                None,
            )
            if assignment is not None and method in _SAFE_LOCAL_DATA_METHODS:
                initializer = (
                    _expanded_call_name(assignment.value, aliases(tree))
                    if isinstance(assignment.value, ast.Call)
                    else None
                )
                static_container = isinstance(
                    assignment.value,
                    (ast.Dict, ast.DictComp, ast.List, ast.ListComp, ast.Set, ast.SetComp, ast.Tuple),
                )
                if static_container or (initializer and _approved_external_module(initializer)):
                    allow('reviewed_local_data_object_method', f'{top_name}.{method}')
                    return
            issues.add(f'{context}:unresolved_local_helper:{_relative_audit_path(source)}:{symbol}')
            return
        local_calls_followed += 1
        if isinstance(node, ast.ClassDef):
            audit_definition(source, tree, node, depth + 1, context)
        else:
            audit_function(source, tree, node.name, depth + 1, context)

    def audit_call(
        source: Path,
        tree: ast.Module,
        call: ast.Call,
        depth: int,
        context: str,
        scope: ast.AST,
    ) -> None:
        nonlocal calls_inspected
        calls_inspected += 1
        module_aliases = dict(aliases(tree))
        for alias, binding in bindings(scope).items():
            module_aliases[alias] = (
                f'{binding.module}.{binding.symbol}'
                if binding.symbol is not None
                else binding.imported_module
            )
        name = _expanded_call_name(call, module_aliases)
        relative = _relative_audit_path(source)

        def review_callback(
            expression: ast.AST,
            *,
            allow_none: bool = False,
        ) -> bool:
            if allow_none and isinstance(expression, ast.Constant) and expression.value is None:
                return True
            if isinstance(expression, ast.Lambda):
                audit_definition(source, tree, expression, depth + 1, context)
                return True
            if isinstance(expression, ast.Name):
                module_target = definitions(tree).get(expression.id)
                if isinstance(module_target, ast.FunctionDef):
                    audit_function(source, tree, expression.id, depth + 1, context)
                    return True
                nested_targets = [
                    item
                    for item in _nodes_in_lexical_scope(scope)
                    if isinstance(item, ast.FunctionDef)
                    and item is not scope
                    and item.name == expression.id
                ]
                if len(nested_targets) == 1:
                    audit_definition(source, tree, nested_targets[0], depth + 1, context)
                    return True
                active_scopes = (tree,) if scope is tree else (tree, scope)
                lambda_targets: list[ast.Lambda] = []
                other_bindings = False
                for active_scope in active_scopes:
                    for item in _nodes_in_lexical_scope(active_scope):
                        if not isinstance(item, (ast.Assign, ast.AnnAssign)):
                            continue
                        targets = item.targets if isinstance(item, ast.Assign) else (item.target,)
                        if not any(
                            isinstance(target, ast.Name) and target.id == expression.id
                            for target in targets
                        ):
                            continue
                        if isinstance(item.value, ast.Lambda):
                            lambda_targets.append(item.value)
                        else:
                            other_bindings = True
                if len(lambda_targets) == 1 and not other_bindings:
                    audit_definition(source, tree, lambda_targets[0], depth + 1, context)
                    return True
            return (
                _safe_callback_expression(expression, module_aliases)
                and _expression_binding_is_intact(expression, tree, scope)
            )

        def local_definition(name: str) -> ast.AST | None:
            nested = [
                item
                for item in _nodes_in_lexical_scope(scope)
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
                and item is not scope
                and item.name == name
            ]
            if len(nested) == 1:
                return nested[0]
            if nested:
                return None
            scope_line = int(getattr(scope, 'lineno', -1))
            enclosing_scopes = sorted(
                (
                    candidate
                    for candidate in ast.walk(tree)
                    if isinstance(
                        candidate,
                        (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef),
                    )
                    and candidate is not scope
                    and int(getattr(candidate, 'lineno', -2)) <= scope_line
                    <= int(getattr(candidate, 'end_lineno', -3))
                ),
                key=lambda candidate: (
                    int(getattr(candidate, 'end_lineno', 10**9))
                    - int(getattr(candidate, 'lineno', 0))
                ),
            )
            for enclosing in enclosing_scopes:
                candidates = [
                    item
                    for item in _nodes_in_lexical_scope(enclosing)
                    if isinstance(
                        item,
                        (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef),
                    )
                    and item is not enclosing
                    and item.name == name
                ]
                if len(candidates) == 1:
                    return candidates[0]
            return definitions(tree).get(name)

        def local_class_for_expression(
            expression: ast.AST,
            seen_names: frozenset[str] = frozenset(),
        ) -> ast.ClassDef | None:
            if isinstance(expression, ast.Call) and isinstance(expression.func, ast.Name):
                target = local_definition(expression.func.id)
                return target if isinstance(target, ast.ClassDef) else None
            if not isinstance(expression, ast.Name):
                return None
            if expression.id in seen_names:
                return None
            if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)):
                positional = (*scope.args.posonlyargs, *scope.args.args)
                if positional and positional[0].arg == expression.id:
                    enclosing = [
                        candidate
                        for candidate in ast.walk(tree)
                        if isinstance(candidate, ast.ClassDef)
                        and any(item is scope for item in candidate.body)
                    ]
                    if len(enclosing) == 1:
                        return enclosing[0]
            active_scopes = (tree,) if scope is tree else (tree, scope)
            origins: list[ast.AST] = []
            for active_scope in active_scopes:
                for item in _nodes_in_lexical_scope(active_scope):
                    if not isinstance(item, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
                        continue
                    targets = item.targets if isinstance(item, ast.Assign) else (item.target,)
                    if any(
                        isinstance(target, ast.Name) and target.id == expression.id
                        for target in targets
                    ):
                        origins.append(item.value)
            classes = [
                local_class_for_expression(origin, seen_names | {expression.id})
                for origin in origins
            ]
            if len(classes) == 1 and classes[0] is not None:
                return classes[0]
            return None

        def audit_local_class_capability(
            expression: ast.AST,
            method_names: Sequence[str],
            *,
            property_name: str | None = None,
        ) -> bool:
            class_definition = local_class_for_expression(expression)
            if class_definition is None:
                return False
            audit_definition(
                source,
                tree,
                class_definition,
                depth + 1,
                context,
            )
            selected: list[ast.AST] = [
                item
                for item in class_definition.body
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
                and item.name in method_names
            ]
            if property_name is not None:
                selected.extend(
                    item
                    for item in class_definition.body
                    if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
                    and item.name == property_name
                    and any(
                        _ast_call_name(decorator) == 'property'
                        for decorator in item.decorator_list
                    )
                )
            for selected_definition in selected:
                audit_definition(
                    source,
                    tree,
                    selected_definition,
                    depth + 1,
                    context,
                )
            return True


        reviewed_data = _REVIEWED_REPOSITORY_DATA_READS.get(
            (relative, context, name or '')
        )
        if reviewed_data is not None:
            data_relative, review_reason = reviewed_data
            candidate = REPOSITORY_ROOT.joinpath(*data_relative.split('/'))
            try:
                from analysis_contract import ensure_no_reparse_components

                ensure_no_reparse_components(candidate)
                resolved_data = candidate.resolve(strict=True)
                repository = REPOSITORY_ROOT.resolve(strict=True)
                if repository not in resolved_data.parents:
                    raise HandlerLoadError('reviewed data file is outside repository')
                content, digest = _dependency_source_snapshot(resolved_data)
            except (OSError, ValueError, HandlerLoadError) as exc:
                issues.add(
                    f'{context}:reviewed_data_unavailable:{data_relative}:'
                    f'{type(exc).__name__}'
                )
                return
            del content
            data_files[resolved_data] = (digest, review_reason)
            allow('reviewed_repository_data_snapshot', name or '')
            return
        reviewed_source_reason = _REVIEWED_SOURCE_CALLS.get(
            (relative, context, name or '')
        )
        if reviewed_source_reason is not None:
            allow('reviewed_source_scoped_call', f'{name}:{reviewed_source_reason}')
            return
        reason = _forbidden_call_reason(call, module_aliases)
        if reason:
            issues.add(f'{context}:{reason}')
            return
        if name in {'getattr', 'iter', 'next'}:
            if name == 'getattr' and call.args:
                attribute = (
                    call.args[1].value
                    if len(call.args) >= 2
                    and isinstance(call.args[1], ast.Constant)
                    and isinstance(call.args[1].value, str)
                    else None
                )
                audit_local_class_capability(
                    call.args[0],
                    ('__getattribute__', '__getattr__'),
                    property_name=attribute,
                )
            elif name == 'iter' and call.args:
                audit_local_class_capability(
                    call.args[0],
                    ('__iter__', '__next__'),
                )
            elif name == 'next' and call.args:
                audit_local_class_capability(
                    call.args[0],
                    ('__next__',),
                )
            if _approved_higher_order_builtin(call, name, module_aliases):
                allow('reviewed_higher_order_builtin', name)
            else:
                issues.add(f'{context}:unresolved_higher_order_call:{name}')
            return
        if name in {'map', 'filter'}:
            valid_arity = len(call.args) >= 2 if name == 'map' else len(call.args) == 2
            for iterable in call.args[1:]:
                audit_local_class_capability(
                    iterable,
                    ('__iter__', '__next__'),
                )
            if (
                valid_arity
                and not call.keywords
                and review_callback(call.args[0], allow_none=name == 'filter')
            ):
                allow('reviewed_higher_order_builtin', name)
            else:
                issues.add(f'{context}:unresolved_higher_order_call:{name}')
            return
        if name == 'hasattr':
            valid_attribute = (
                len(call.args) == 2
                and not call.keywords
                and isinstance(call.args[1], ast.Constant)
                and isinstance(call.args[1].value, str)
                and call.args[1].value not in _DANGEROUS_REFLECTION_ATTRIBUTES
            )
            if valid_attribute:
                audit_local_class_capability(
                    call.args[0],
                    ('__getattribute__', '__getattr__'),
                    property_name=call.args[1].value,
                )
                allow('reviewed_attribute_presence_check', name)
            else:
                issues.add(f'{context}:unresolved_attribute_presence_check:{name}')
            return
        if name in {'sorted', 'min', 'max'}:
            key_values = [item.value for item in call.keywords if item.arg == 'key']
            iterable_arguments = call.args[:1] if name == 'sorted' or len(call.args) == 1 else ()
            for iterable in iterable_arguments:
                audit_local_class_capability(
                    iterable,
                    ('__iter__', '__next__'),
                )
            valid = (
                bool(call.args)
                and not any(item.arg is None for item in call.keywords)
                and len(key_values) <= 1
                and (not key_values or review_callback(key_values[0]))
            )
            if valid:
                allow('reviewed_higher_order_builtin', name)
            else:
                issues.add(f'{context}:unresolved_higher_order_call:{name}')
            return
        if name == 'functools.reduce':
            if len(call.args) >= 2:
                audit_local_class_capability(
                    call.args[1],
                    ('__iter__', '__next__'),
                )
            if (
                2 <= len(call.args) <= 3
                and not call.keywords
                and review_callback(call.args[0])
            ):
                allow('approved_reduce_callback_capability', name)
            else:
                issues.add(f'{context}:unresolved_reduce_callback:{name}')
            return
        if name == 'collections.defaultdict':
            if (
                len(call.args) <= 1
                and not call.keywords
                and (
                    not call.args
                    or review_callback(call.args[0], allow_none=True)
                )
            ):
                allow('approved_default_factory_capability', name)
            else:
                issues.add(f'{context}:unresolved_default_factory:{name}')
            return
        if name in {'re.sub', 're.subn'}:
            if len(call.args) >= 3 and (
                isinstance(call.args[1], (ast.Constant, ast.JoinedStr))
                or review_callback(call.args[1])
            ):
                allow('approved_regex_replacement_capability', name)
            else:
                issues.add(f'{context}:unresolved_regex_callback:{name}')
            return
        if name in {'json.loads', 'json.JSONDecoder'}:
            callback_keywords = {
                'cls', 'object_hook', 'object_pairs_hook', 'parse_constant',
                'parse_float', 'parse_int',
            }
            callbacks = [
                item.value
                for item in call.keywords
                if item.arg in callback_keywords
            ]
            if all(review_callback(item) for item in callbacks):
                allow('approved_json_callback_capability', name)
            else:
                issues.add(f'{context}:unresolved_json_callback:{name}')
            return
        if name is None or not isinstance(call.func, (ast.Name, ast.Attribute)):
            static_lambda_dispatch = False
            dispatch_lambdas: list[ast.Lambda] = []
            if isinstance(call.func, ast.Subscript) and isinstance(
                call.func.value,
                ast.Name,
            ):
                dispatch_name = call.func.value.id
                scope_line = int(getattr(scope, 'lineno', -1))
                candidate_scopes: list[ast.AST] = [scope]
                if scope_line >= 0:
                    candidate_scopes.extend(
                        candidate
                        for candidate in ast.walk(tree)
                        if isinstance(
                            candidate,
                            (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef),
                        )
                        and candidate is not scope
                        and int(getattr(candidate, 'lineno', -2)) <= scope_line
                        <= int(getattr(candidate, 'end_lineno', -3))
                    )
                assignments = [
                    item
                    for candidate_scope in candidate_scopes
                    for item in _nodes_in_lexical_scope(candidate_scope)
                    if isinstance(item, ast.Assign)
                    and any(
                        isinstance(target, ast.Name)
                        and target.id == dispatch_name
                        for target in item.targets
                    )
                    and isinstance(item.value, ast.Dict)
                    and item.value.values
                    and all(
                        isinstance(value, ast.Lambda)
                        for value in item.value.values
                    )
                ]
                mutations = _scope_non_import_bindings(scope)
                static_lambda_dispatch = (
                    len(assignments) == 1
                    and not any(
                        value.startswith(
                            (f'{dispatch_name}.', f'{dispatch_name}[]')
                        )
                        for value in mutations
                    )
                )
                if static_lambda_dispatch:
                    dispatch_lambdas = list(assignments[0].value.values)
            if static_lambda_dispatch:
                for callback in dispatch_lambdas:
                    audit_definition(source, tree, callback, depth + 1, context)
                allow('static_lambda_dispatch_table', call.func.value.id)
            else:
                issues.add(f'{context}:unresolved_dynamic_call')
            return
        if name == 'sys.path.insert':
            if _safe_static_sys_path_insert(call, tree) or dynamic_call_allowed(source, name):
                allow('static_repository_sys_path_insert', name)
            else:
                issues.add(f'{context}:unapproved_dynamic_import:{name}')
            return
        if (
            name in {'importlib.util.spec_from_file_location', 'importlib.util.module_from_spec'}
            or name.endswith('.exec_module')
        ):
            if dynamic_call_allowed(source, name):
                allow('reviewed_dynamic_local_loader', name)
            else:
                issues.add(f'{context}:unapproved_dynamic_import:{name}')
            return

        call_bindings = dict(bindings(tree))
        call_bindings.update(bindings(scope))
        raw_name = _ast_call_name(call.func) or ''
        parts = raw_name.split('.')
        binding = call_bindings.get(parts[0]) if parts else None
        if binding is not None:
            if not _expression_binding_is_intact(call.func, tree, scope):
                issues.add(f'{context}:rebound_import_capability:{raw_name}')
                return
            target, symbol, error = _binding_local_call_target(source, binding, parts[1:])
            if error:
                issues.add(f'{context}:{error}')
                return
            if target is not None:
                audit_target(target, symbol, depth + 1, context)
                return
            if _approved_external_module(binding.imported_module):
                if _approved_external_call(call, name, module_aliases):
                    allow('approved_external_capability_call', name)
                    return
                issues.add(f'{context}:unapproved_external_call:{name}')
                return
            issues.add(f'{context}:unresolved_import_call:{name}')
            return

        module_definitions = definitions(tree)
        if isinstance(call.func, ast.Name) and call.func.id in module_definitions:
            target = module_definitions[call.func.id]
            if isinstance(target, ast.ClassDef):
                audit_local_class_capability(
                    call,
                    ('__new__', '__init__', '__post_init__'),
                )
            else:
                audit_function(source, tree, target.name, depth + 1, context)
            return
        nested_names, assigned_names, parameters = scope_symbols(scope)
        if isinstance(call.func, ast.Name) and call.func.id in nested_names:
            target = local_definition(call.func.id)
            if isinstance(target, ast.ClassDef):
                audit_local_class_capability(
                    call,
                    ('__new__', '__init__', '__post_init__'),
                )
                allow('reviewed_nested_local_class', call.func.id)
            elif isinstance(target, (ast.FunctionDef, ast.AsyncFunctionDef)):
                audit_definition(source, tree, target, depth + 1, context)
                allow('reviewed_nested_local_callable', call.func.id)
            else:
                issues.add(
                    f'{context}:ambiguous_nested_local_callable:{call.func.id}'
                )
            return
        if isinstance(call.func, ast.Name):
            enclosing_target = local_definition(call.func.id)
            if isinstance(enclosing_target, ast.ClassDef):
                audit_local_class_capability(
                    call,
                    ('__new__', '__init__', '__post_init__'),
                )
                allow('reviewed_enclosing_local_class', call.func.id)
                return
            if isinstance(
                enclosing_target,
                (ast.FunctionDef, ast.AsyncFunctionDef),
            ):
                audit_definition(
                    source, tree, enclosing_target, depth + 1, context
                )
                allow('reviewed_enclosing_local_callable', call.func.id)
                return
        if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if isinstance(call.func, ast.Name) and call.func.id in parameters:
                callback_key = (
                    _relative_audit_path(source),
                    scope.name,
                    call.func.id,
                )
                if callback_key in _APPROVED_CALLBACK_PARAMETERS:
                    allow('reviewed_bounded_callback_parameter', call.func.id)
                    return
                issues.add(f'{context}:unresolved_parameter_callable:{call.func.id}')
                return
            if isinstance(call.func, ast.Name) and call.func.id in assigned_names:
                factory_targets = {
                    item.value.func.id
                    for item in _nodes_in_lexical_scope(scope)
                    if isinstance(item, (ast.Assign, ast.AnnAssign))
                    and any(
                        isinstance(target, ast.Name) and target.id == call.func.id
                        for target in (
                            item.targets if isinstance(item, ast.Assign) else (item.target,)
                        )
                    )
                    and isinstance(item.value, ast.Call)
                    and isinstance(item.value.func, ast.Name)
                    and isinstance(module_definitions.get(item.value.func.id), ast.FunctionDef)
                }
                verified_factory_targets: set[str] = set()
                for factory_name in factory_targets:
                    factory = module_definitions[factory_name]
                    factory_nodes = _nodes_in_lexical_scope(factory)
                    returned_local_names = {
                        item.name
                        for item in factory_nodes
                        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
                        and item is not factory
                    }
                    returns = [
                        item.value
                        for item in factory_nodes
                        if isinstance(item, ast.Return) and item.value is not None
                    ]
                    if returns and all(
                        isinstance(value, ast.Lambda)
                        or isinstance(value, ast.Name)
                        and value.id in returned_local_names
                        for value in returns
                    ):
                        verified_factory_targets.add(factory_name)
                assigned_from_local_factory = (
                    bool(factory_targets)
                    and factory_targets == verified_factory_targets
                )
                tuple_local_targets: set[str] = set()
                for loop in _nodes_in_lexical_scope(scope):
                    if not (
                        isinstance(loop, (ast.For, ast.AsyncFor))
                        and isinstance(loop.target, ast.Name)
                        and loop.target.id == call.func.id
                        and isinstance(loop.iter, ast.Name)
                    ):
                        continue
                    for assignment in _nodes_in_lexical_scope(scope):
                        if not (
                            isinstance(assignment, ast.Assign)
                            and any(
                                isinstance(target, ast.Name)
                                and target.id == loop.iter.id
                                for target in assignment.targets
                            )
                            and isinstance(assignment.value, (ast.Tuple, ast.List))
                            and all(
                                isinstance(item, ast.Name)
                                and isinstance(
                                    module_definitions.get(item.id),
                                    ast.FunctionDef,
                                )
                                for item in assignment.value.elts
                            )
                        ):
                            continue
                        tuple_local_targets.update(
                            item.id for item in assignment.value.elts
                        )
                tuple_of_local_functions = bool(tuple_local_targets)
                local_choice_targets: set[str] = set()
                for assignment in _nodes_in_lexical_scope(scope):
                    if not isinstance(assignment, (ast.Assign, ast.AnnAssign)):
                        continue
                    targets = assignment.targets if isinstance(assignment, ast.Assign) else (assignment.target,)
                    if not any(isinstance(target, ast.Name) and target.id == call.func.id for target in targets):
                        continue
                    values = (
                        (assignment.value.body, assignment.value.orelse)
                        if isinstance(assignment.value, ast.IfExp)
                        else (assignment.value,)
                    )
                    names = {
                        value.id
                        for value in values
                        if isinstance(value, ast.Name) and value.id in module_definitions
                    }
                    if len(names) == len(values):
                        local_choice_targets.update(names)
                if assigned_from_local_factory or tuple_of_local_functions or local_choice_targets:
                    for factory_name in sorted(verified_factory_targets):
                        audit_function(source, tree, factory_name, depth + 1, context)
                    for target_name in sorted(tuple_local_targets):
                        audit_function(source, tree, target_name, depth + 1, context)
                    for target_name in sorted(local_choice_targets):
                        target = module_definitions[target_name]
                        if isinstance(target, ast.FunctionDef):
                            audit_function(source, tree, target_name, depth + 1, context)
                    allow('statically_bound_local_callable', call.func.id)
                    return
                issues.add(f'{context}:unresolved_dynamic_name_call:{call.func.id}')
                return
        if isinstance(call.func, ast.Name):
            callback_key = (
                _relative_audit_path(source),
                scope.name
                if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef))
                else '',
                call.func.id,
            )
            if callback_key in _APPROVED_CALLBACK_PARAMETERS:
                allow('reviewed_bounded_callback_or_closure', call.func.id)
                return
            if call.func.id in _APPROVED_BUILTIN_CALLS:
                implicit_methods = {
                    'all': ('__iter__', '__next__'),
                    'any': ('__iter__', '__next__'),
                    'bool': ('__bool__', '__len__'),
                    'bytearray': ('__bytes__', '__iter__', '__next__', '__index__'),
                    'bytes': ('__bytes__', '__iter__', '__next__', '__index__'),
                    'dict': ('keys', '__getitem__', '__iter__', '__next__'),
                    'enumerate': ('__iter__', '__next__'),
                    'frozenset': ('__iter__', '__next__'),
                    'len': ('__len__',),
                    'list': ('__iter__', '__next__'),
                    'memoryview': ('__buffer__',),
                    'repr': ('__repr__',),
                    'reversed': ('__reversed__', '__len__', '__getitem__'),
                    'set': ('__iter__', '__next__'),
                    'str': ('__str__',),
                    'sum': ('__iter__', '__next__'),
                    'tuple': ('__iter__', '__next__'),
                    'zip': ('__iter__', '__next__'),
                }
                methods = implicit_methods.get(call.func.id)
                protocol_arguments = call.args if call.func.id == 'zip' else call.args[:1]
                if methods:
                    for protocol_argument in protocol_arguments:
                        audit_local_class_capability(
                            protocol_argument,
                            methods,
                        )
                allow('python_builtin_call', call.func.id)
                return
            relative = _relative_audit_path(source)
            approved_symbols = {
                symbol
                for _target, symbols, _reason in _LEGACY_DYNAMIC_LOCAL_DEPENDENCIES.get(relative, ())
                for symbol in symbols
            }
            if call.func.id in approved_symbols:
                allow('reviewed_dynamic_local_symbol', call.func.id)
                return
            issues.add(f'{context}:unresolved_dynamic_name_call:{call.func.id}')
            return
        method = name.rsplit('.', 1)[-1]
        if method == 'openstream':
            if _approved_ole_openstream(call, tree, scope, module_aliases):
                allow('approved_ole_stream_capability', name)
            else:
                issues.add(f'{context}:unverified_ole_stream_capability:{name}')
            return
        if method == 'read':
            if _approved_in_memory_read(call, tree, scope, module_aliases):
                allow('approved_in_memory_reader_capability', name)
            else:
                issues.add(f'{context}:unverified_reader_capability:{name}')
            return
        if method == 'sort':
            key_values = [item.value for item in call.keywords if item.arg == 'key']
            if (
                not any(item.arg is None for item in call.keywords)
                and len(key_values) <= 1
                and (
                    not key_values
                    or review_callback(key_values[0])
                )
            ):
                allow('approved_in_memory_sort_capability', name)
            else:
                issues.add(f'{context}:unresolved_sort_callback:{name}')
            return
        if method in {'sub', 'subn'}:
            if call.args and (
                isinstance(call.args[0], (ast.Constant, ast.JoinedStr))
                or review_callback(call.args[0])
            ):
                allow('approved_regex_replacement_capability', name)
            else:
                issues.add(f'{context}:unresolved_regex_callback:{name}')
            return
        if (
            isinstance(call.func, ast.Attribute)
            and audit_local_class_capability(
                call.func.value,
                (method,),
            )
        ):
            allow('reviewed_local_class_method', name)
            return
        if method in _APPROVED_SAFE_METHOD_NAMES:
            allow('approved_in_memory_method', name)
            return
        issues.add(f'{context}:unapproved_object_method:{name}')

    def audit_definition(
        source: Path,
        tree: ast.Module,
        definition: ast.AST,
        depth: int,
        context: str,
    ) -> None:
        definition_key = (
            source.resolve(strict=True),
            int(getattr(definition, 'lineno', -1)),
            int(getattr(definition, 'col_offset', -1)),
            type(definition).__name__,
        )
        if definition_key in visited_definitions:
            return
        visited_definitions.add(definition_key)
        active_nodes = _nodes_in_lexical_scope(definition)
        for node in active_nodes:
            if (
                isinstance(node, ast.Attribute)
                and node.attr in _DANGEROUS_REFLECTION_ATTRIBUTES
            ):
                issues.add(
                    f'{context}:forbidden_reflection_attribute:{node.attr}'
                )
            elif isinstance(node, ast.Name) and node.id == '__builtins__':
                issues.add(f'{context}:forbidden_reflection_name:__builtins__')

        active_bindings = dict(bindings(tree))
        active_bindings.update(bindings(definition))
        for mutation in _import_namespace_mutations(definition, active_bindings):
            mutation_key = (
                _relative_audit_path(source),
                context,
                mutation,
            )
            if mutation_key in _REVIEWED_IMPORT_NAMESPACE_MUTATIONS:
                continue
            issues.add(f'{context}:forbidden_import_namespace_mutation:{mutation}')

        nested_definitions = [
            node
            for node in active_nodes
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
            and node is not definition
        ]
        for nested_definition in nested_definitions:
            if isinstance(nested_definition, ast.ClassDef):
                audit_definition(
                    source,
                    tree,
                    nested_definition,
                    depth + 1,
                    context,
                )

        nested_by_name = {
            node.name: node
            for node in nested_definitions
        }
        for node in active_nodes:
            if (
                isinstance(node, ast.Return)
                and isinstance(node.value, ast.Name)
                and node.value.id in nested_by_name
            ):
                audit_definition(
                    source,
                    tree,
                    nested_by_name[node.value.id],
                    depth + 1,
                    context,
                )

        decorated_definitions = [
            node
            for node in (definition, *nested_definitions)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
        ]
        for decorated in decorated_definitions:
            for decorator in decorated.decorator_list:
                if isinstance(decorator, ast.Call):
                    continue
                synthetic = ast.Call(func=decorator, args=[], keywords=[])
                audit_call(source, tree, synthetic, depth + 1, context, definition)

        for call in (node for node in active_nodes if isinstance(node, ast.Call)):
            audit_call(source, tree, call, depth, context, definition)

    def audit_function(
        source: Path,
        tree: ast.Module,
        function_name: str,
        depth: int,
        context: str,
    ) -> None:
        key = (source.resolve(strict=True), function_name)
        if key in visited_functions:
            return
        visited_functions.add(key)
        function = next(
            (
                node
                for node in tree.body
                if isinstance(node, ast.FunctionDef) and node.name == function_name
            ),
            None,
        )
        if function is None:
            issues.add(f'{context}:unresolved_local_function:{function_name}')
            return
        audit_definition(source, tree, function, depth, f'reachable:{function_name}')

    def audit_module(source: Path, depth: int) -> None:
        resolved = source.resolve(strict=True)
        if resolved in visited_imports:
            return
        tree = register_file(resolved, depth)
        if tree is None:
            return
        visited_imports.add(resolved)
        audit_imports(resolved, tree, depth)
        module_nodes = _nodes_in_lexical_scope(tree)
        for node in module_nodes:
            if (
                isinstance(node, ast.Attribute)
                and node.attr in _DANGEROUS_REFLECTION_ATTRIBUTES
            ):
                issues.add(
                    f'import_time:forbidden_reflection_attribute:{node.attr}'
                )
            elif isinstance(node, ast.Name) and node.id == '__builtins__':
                issues.add('import_time:forbidden_reflection_name:__builtins__')
        module_imports = bindings(tree)
        for mutation in _import_namespace_mutations(tree, module_imports):
            issues.add(
                f'import_time:forbidden_import_namespace_mutation:{mutation}'
            )
        for definition in tree.body:
            if isinstance(definition, ast.ClassDef):
                audit_definition(
                    resolved,
                    tree,
                    definition,
                    depth + 1,
                    'import_time',
                )
            if not isinstance(
                definition,
                (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef),
            ):
                continue
            for decorator in definition.decorator_list:
                if isinstance(decorator, ast.Call):
                    continue
                synthetic = ast.Call(func=decorator, args=[], keywords=[])
                audit_call(
                    resolved,
                    tree,
                    synthetic,
                    depth + 1,
                    'import_time',
                    tree,
                )
        for call in _top_level_calls(tree):
            audit_call(resolved, tree, call, depth, 'import_time', tree)

        relative = _relative_audit_path(resolved)
        for dependency, symbols, audit_reason in _LEGACY_DYNAMIC_LOCAL_DEPENDENCIES.get(relative, ()):
            target = REPOSITORY_ROOT / dependency
            target_tree = register_file(target, depth + 1)
            if target_tree is None:
                continue
            allow(audit_reason, dependency)
            audit_module(target, depth + 1)
            for symbol in symbols:
                audit_function(target, target_tree, symbol, depth + 1, 'reviewed_dynamic_local')

    root_tree = register_file(path, 0)
    if root_tree is not None:
        audit_module(path, 0)
        audit_function(path, root_tree, callable_name, 0, 'handler_entry')
    file_records = [
        {'path': _relative_audit_path(source), 'sha256': digest}
        for source, digest in sorted(files.items(), key=lambda item: _relative_audit_path(item[0]))
    ]
    data_file_records = [
        {
            'path': _relative_audit_path(source),
            'sha256': digest,
            'reason': reason,
        }
        for source, (digest, reason) in sorted(
            data_files.items(),
            key=lambda item: _relative_audit_path(item[0]),
        )
    ]
    module_binding_records = [
        {
            'name': name,
            'path': _relative_audit_path(target),
            'is_package': is_package,
        }
        for name, (target, is_package) in sorted(module_bindings.items())
    ]
    return {
        'issues': sorted(issues),
        'files': file_records,
        'files_inspected': len(file_records),
        'calls_inspected': calls_inspected,
        'data_files': data_file_records,
        'data_files_inspected': len(data_file_records),
        'module_bindings': module_binding_records,
        'module_bindings_inspected': len(module_binding_records),
        'local_calls_followed': local_calls_followed,
        'allowance_counts': dict(sorted(allowance_counts.items())),
        'allowance_examples': {
            reason: sorted(values)
            for reason, values in sorted(allowance_examples.items())
        },
        'maximum_import_depth': MAX_ASSESSMENT_IMPORT_DEPTH,
        'maximum_import_files': MAX_ASSESSMENT_IMPORT_FILES,
    }


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
    dependency_audit: dict[str, Any] = {
        'issues': [],
        'files': [],
        'data_files': [],
        'data_files_inspected': 0,
        'module_bindings': [],
        'module_bindings_inspected': 0,
        'files_inspected': 0,
        'calls_inspected': 0,
        'local_calls_followed': 0,
        'allowance_counts': {},
        'allowance_examples': {},
        'maximum_import_depth': MAX_ASSESSMENT_IMPORT_DEPTH,
        'maximum_import_files': MAX_ASSESSMENT_IMPORT_FILES,
    }
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
        dependency_audit = _recursive_handler_side_effect_audit(path, spec.callable_name)
        blockers.extend(dependency_audit['issues'])
    except Exception as exc:  # noqa: BLE001 - 解析不能もfail-closedにする
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
        'dependency_audit': dependency_audit,
        'sample_execution_allowed': False,
        'network_allowed': False,
        'filesystem_write_allowed': False,
    }


def _mapping_value(value: Any, key: str, default: Any = None) -> Any:
    if isinstance(value, Mapping):
        return value.get(key, default)
    return getattr(value, key, default)


def _preflight_dependency_source_manifest(
    preflight: Mapping[str, Any],
) -> list[dict[str, str]]:
    """preflight監査結果を現在のsource bytesへ再結合してworker用に返す。"""

    audit = preflight.get('dependency_audit')
    files = audit.get('files') if isinstance(audit, Mapping) else None
    return _validated_dependency_source_manifest(files, repository=REPOSITORY_ROOT)


def _preflight_dependency_data_manifest(
    preflight: Mapping[str, Any],
) -> list[dict[str, str]]:
    audit = preflight.get('dependency_audit')
    files = audit.get('data_files') if isinstance(audit, Mapping) else None
    return _validated_dependency_data_manifest(
        files if files is not None else [],
        repository=REPOSITORY_ROOT,
    )


def _preflight_dependency_module_manifest(
    preflight: Mapping[str, Any],
) -> list[dict[str, Any]]:
    audit = preflight.get('dependency_audit')
    if not isinstance(audit, Mapping):
        raise HandlerLoadError('dependency audit is unavailable')
    source_files = audit.get('files')
    records = audit.get('module_bindings')
    snapshots = _validated_dependency_source_snapshots(
        source_files,
        repository=REPOSITORY_ROOT,
    )
    bindings = _validated_dependency_module_bindings(
        records if records is not None else [],
        snapshots=snapshots,
    )
    return [
        {
            'name': binding.fullname,
            'path': binding.snapshot.relative_path,
            'is_package': binding.is_package,
        }
        for binding in bindings
    ]


def _preflight_dependency_sources_unchanged(preflight: Mapping[str, Any]) -> bool:
    """preflight後の全依存sourceを厳密に再検証する。"""

    try:
        _preflight_dependency_source_manifest(preflight)
        _preflight_dependency_data_manifest(preflight)
        _preflight_dependency_module_manifest(preflight)
    except (HandlerLoadError, OSError, ValueError):
        return False
    return True


def execute_handler_bounded_for_assessment(
    spec: HandlerSpec,
    data: bytes,
    source_name: str,
    *,
    actual_format: str,
    maximum_input_size: int = DEFAULT_MAXIMUM_ASSESSMENT_LAYER_SIZE,
    timeout_seconds: float = DEFAULT_HANDLER_TIMEOUT_SECONDS,
    artifact_directory: Path | None = None,
    artifact_path_prefix: str = 'recovered-payloads',
) -> dict[str, Any]:
    """事前検査済みhandlerを隔離processで実行し、安定した公開結果を返す。"""

    if not isinstance(data, bytes):
        raise TypeError('dataはbytesで指定してください')
    if not isinstance(source_name, str) or not source_name or len(source_name) > 512:
        raise ValueError('source_nameが不正です')
    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, (int, float))
        or not 0.1 <= float(timeout_seconds) <= MAX_HANDLER_TIMEOUT_SECONDS
    ):
        raise ValueError('timeout_secondsは0.1秒以上300秒以下で指定してください')

    preflight = preflight_handler_for_assessment(
        spec,
        actual_format=actual_format,
        input_size=len(data),
        maximum_input_size=maximum_input_size,
    )
    base = {
        'handler': spec.public(),
        'preflight': preflight,
        'handler_timeout_seconds': float(timeout_seconds),
    }
    artifact_destination = _validated_artifact_destination(
        artifact_directory,
        artifact_path_prefix,
    )
    if not preflight['eligible']:
        return {**base, 'status': 'preflight_blocked'}
    try:
        dependency_source_manifest = _preflight_dependency_source_manifest(preflight)
        dependency_module_manifest = _preflight_dependency_module_manifest(preflight)
        dependency_data_manifest = _preflight_dependency_data_manifest(preflight)
    except (HandlerLoadError, OSError, ValueError):
        return {
            **base,
            'status': 'preflight_blocked',
            'preflight': {
                **preflight,
                'eligible': False,
                'blockers': ['dependency_source_changed_after_preflight'],
            },
        }
    try:
        execution = _execute_handler_bounded(
            spec,
            data,
            source_name,
            timeout_seconds=float(timeout_seconds),
            dependency_source_manifest=dependency_source_manifest,
            dependency_module_manifest=dependency_module_manifest,
            artifact_destination=artifact_destination,
            dependency_data_manifest=dependency_data_manifest,
        )
    except subprocess.TimeoutExpired:
        return {
            **base,
            'status': 'timed_out',
            'error': 'handler_wall_clock_timeout',
        }
    except Exception as exc:  # noqa: BLE001 - worker障害を公開用に正規化する
        return {
            **base,
            'status': 'failed',
            'error': 'handler_worker_failed',
            'error_type': type(exc).__name__,
        }
    return {
        **base,
        'status': 'completed',
        'execution': execution,
    }


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
    allowed_modes = {'candidate_verification', 'selected_family_analysis'}
    merged: dict[str, dict[str, Any]] = {}
    for index, supplied in enumerate(candidates):
        if isinstance(supplied, str):
            family = supplied
            sources = ['explicit_caller_candidate']
            routing_eligible = True
            routing_mode = 'candidate_verification'
            caller_selected_string = True
            blocked_reasons: list[str] = []
        elif isinstance(supplied, Mapping):
            family = supplied.get('family')
            raw_sources = supplied.get('sources', supplied.get('source', []))
            sources = [raw_sources] if isinstance(raw_sources, str) else list(raw_sources or [])
            routing_eligible = supplied.get('routing_eligible') is True
            routing_mode = supplied.get('routing_mode')
            caller_selected_string = False
            blocked_reasons = []
            if not routing_eligible:
                blocked_reasons.append('routing_not_eligible')
            if routing_mode not in allowed_modes:
                blocked_reasons.append(f'routing_mode_not_executable:{routing_mode}')
            nested = supplied.get('routing_eligibility')
            if nested is not None:
                if not isinstance(nested, Mapping):
                    blocked_reasons.append('routing_eligibility_not_mapping')
                elif routing_mode in allowed_modes and nested.get(routing_mode) is not True:
                    blocked_reasons.append(f'routing_eligibility_mode_not_true:{routing_mode}')
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
        record = merged.setdefault(
            family,
            {
                'family': family,
                'sources': set(),
                'routing_modes': set(),
                'all_routing_eligible': True,
                'caller_selected_string': False,
                'blocked_reasons': set(),
            },
        )
        record['sources'].update(sources or ['unspecified_candidate'])
        record['routing_modes'].add(routing_mode)
        record['all_routing_eligible'] = (
            record['all_routing_eligible']
            and routing_eligible
            and routing_mode in allowed_modes
            and not blocked_reasons
        )
        record['caller_selected_string'] = (
            record['caller_selected_string'] or caller_selected_string
        )
        record['blocked_reasons'].update(blocked_reasons)

    normalized: list[dict[str, Any]] = []
    for family, record in sorted(merged.items()):
        modes = set(record['routing_modes'])
        if len(modes) != 1:
            record['blocked_reasons'].add('conflicting_duplicate_routing_modes')
            record['all_routing_eligible'] = False
        assessment_eligible = bool(record['all_routing_eligible'])
        routing_mode = next(iter(modes)) if len(modes) == 1 else 'blocked'
        normalized.append(
            {
                'family': family,
                'sources': sorted(record['sources']),
                'routing_eligible': assessment_eligible,
                'routing_mode': routing_mode,
                'caller_selected_string': bool(record['caller_selected_string']),
                'assessment_eligible': assessment_eligible,
                'blocked_reasons': sorted(record['blocked_reasons']),
            }
        )
    return normalized


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
            raise TypeError(f'layer_classifications[{index}].detector_evaluationsが不正です')
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
    maximum_wall_seconds: float = MAX_ASSESSMENT_WALL_SECONDS,
    maximum_response_bytes: int = MAX_ASSESSMENT_TOTAL_RESPONSE_BYTES,
    maximum_retained_attempt_details: int = MAX_ASSESSMENT_RETAINED_ATTEMPT_DETAILS,
    maximum_verified_outputs: int = MAX_ASSESSMENT_VERIFIED_OUTPUTS,
    handler_timeout_seconds: float = DEFAULT_HANDLER_TIMEOUT_SECONDS,
    artifact_directory: Path | None = None,
    artifact_path_prefix: str = 'recovered-payloads',
) -> dict[str, Any]:
    '''候補familyの自動handlerを全復元layerへ安全に試行し、裏付け結果を返す。'''

    if (
        not isinstance(maximum_attempts, int)
        or isinstance(maximum_attempts, bool)
        or not 1 <= maximum_attempts <= MAX_ASSESSMENT_ATTEMPTS
    ):
        raise ValueError('maximum_attemptsが不正です')
    if (
        isinstance(maximum_wall_seconds, bool)
        or not isinstance(maximum_wall_seconds, (int, float))
        or not 0.1 <= float(maximum_wall_seconds) <= MAX_ASSESSMENT_WALL_SECONDS
    ):
        raise ValueError('maximum_wall_seconds is invalid')
    for supplied, hard_limit, name in (
        (
            maximum_response_bytes,
            MAX_ASSESSMENT_TOTAL_RESPONSE_BYTES,
            'maximum_response_bytes',
        ),
        (
            maximum_retained_attempt_details,
            MAX_ASSESSMENT_RETAINED_ATTEMPT_DETAILS,
            'maximum_retained_attempt_details',
        ),
        (
            maximum_verified_outputs,
            MAX_ASSESSMENT_VERIFIED_OUTPUTS,
            'maximum_verified_outputs',
        ),
    ):
        if (
            isinstance(supplied, bool)
            or not isinstance(supplied, int)
            or not 1 <= supplied <= hard_limit
        ):
            raise ValueError(f'{name} is invalid')
    if (
        isinstance(handler_timeout_seconds, bool)
        or not isinstance(handler_timeout_seconds, (int, float))
        or not 0.1 <= float(handler_timeout_seconds) <= MAX_HANDLER_TIMEOUT_SECONDS
    ):
        raise ValueError('handler_timeout_secondsは0.1秒以上300秒以下で指定してください')
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
                if (
                    candidate['assessment_eligible']
                    and spec.family == candidate['family']
                    and spec.automatic
                )
            ),
            key=lambda item: item.id,
        )
        for candidate in normalized_candidates
    }
    planned_attempts = sum(
        len(by_family[candidate['family']]) * len(normalized_layers)
        for candidate in normalized_candidates
    )
    started = time.monotonic()
    actual_attempt_count = 0
    response_bytes = 0
    verified_output_count = 0
    budget_exhausted = False
    budget_blockers: set[str] = set()

    retained_attempt_details = 0

    def retain_attempt(target: list[dict[str, Any]], detail: dict[str, Any]) -> None:
        nonlocal budget_exhausted, retained_attempt_details
        if retained_attempt_details >= maximum_retained_attempt_details:
            budget_blockers.add('maximum_retained_attempt_details_exhausted')
            budget_exhausted = True
            return
        target.append(detail)
        retained_attempt_details += 1

    from analysis_contract import handler_result_quality

    parents = {
        str(layer['sha256']): layer.get('parent_sha256')
        for layer in normalized_layers
    }
    family_results = []
    confirmed_families = []
    for candidate in normalized_candidates:
        family = str(candidate['family'])
        if not candidate['assessment_eligible']:
            family_results.append(
                {
                    **candidate,
                    'status': 'blocked',
                    'confirmed': False,
                    'detector_layers': {},
                    'attempts': [],
                }
            )
            continue
        evidence_by_layer = _detector_evidence_by_layer(
            detector_evaluations,
            family,
            normalized_layers,
        )
        attempts: list[dict[str, Any]] = []
        for spec in by_family[family]:
            for layer in normalized_layers:
                if budget_exhausted:
                    break
                elapsed = time.monotonic() - started
                if elapsed >= float(maximum_wall_seconds):
                    budget_blockers.add('maximum_wall_seconds_exhausted')
                    budget_exhausted = True
                    break
                if actual_attempt_count >= maximum_attempts:
                    budget_blockers.add('maximum_attempts_exhausted')
                    budget_exhausted = True
                    break
                remaining_seconds = max(
                    0.1,
                    float(maximum_wall_seconds) - elapsed,
                )
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
                bounded = execute_handler_bounded_for_assessment(
                    spec,
                    layer['data'],
                    str(layer['name']),
                    actual_format=str(layer['format']),
                    maximum_input_size=maximum_layer_size,
                    timeout_seconds=min(
                        float(handler_timeout_seconds),
                        remaining_seconds,
                    ),
                    artifact_directory=artifact_directory,
                    artifact_path_prefix=artifact_path_prefix,
                )
                actual_attempt_count += 1
                if time.monotonic() - started >= float(maximum_wall_seconds):
                    budget_blockers.add('maximum_wall_seconds_exhausted')
                    budget_exhausted = True
                bounded_size = len(
                    json.dumps(
                        bounded,
                        ensure_ascii=False,
                        sort_keys=True,
                        separators=(',', ':'),
                    ).encode('utf-8')
                )
                if response_bytes + bounded_size > maximum_response_bytes:
                    budget_blockers.add('maximum_response_bytes_exhausted')
                    budget_exhausted = True
                    break
                response_bytes += bounded_size
                attempt: dict[str, Any] = {
                    'handler_id': spec.id,
                    'family': family,
                    'layer': public_layer,
                    'preflight': bounded['preflight'],
                }
                bounded_status = bounded['status']
                if bounded_status != 'completed':
                    retain_attempt(
                        attempts,
                        {
                            **attempt,
                            'status': bounded_status,
                            **(
                                {'error': bounded['error']}
                                if isinstance(bounded.get('error'), str)
                                else {}
                            ),
                            **(
                                {'error_type': bounded['error_type']}
                                if isinstance(bounded.get('error_type'), str)
                                else {}
                            ),
                        },
                    )
                    continue
                executed = bounded['execution']
                result_quota = executed.get('result_quota')
                if (
                    isinstance(result_quota, Mapping)
                    and result_quota.get('truncated') is True
                ):
                    budget_blockers.add('worker_result_structure_quota_exhausted')
                    budget_exhausted = True
                    retain_attempt(
                        attempts,
                        {
                            **attempt,
                            'status': 'partial_result_quota_exhausted',
                        },
                    )
                    break
                output_audit = executed.get('verified_binary_output_audit')
                observed_outputs = (
                    output_audit.get('observed_output_count', 0)
                    if isinstance(output_audit, Mapping)
                    else 0
                )
                if not isinstance(observed_outputs, int) or observed_outputs < 0:
                    observed_outputs = maximum_verified_outputs + 1
                if verified_output_count + observed_outputs > maximum_verified_outputs:
                    budget_blockers.add('maximum_verified_outputs_exhausted')
                    budget_exhausted = True
                    break
                verified_output_count += observed_outputs
                quality = handler_result_quality(
                    executed.get('result'),
                    minimum_score=spec.minimum_evidence_score,
                )
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
                retain_attempt(
                    attempts,
                    {
                        **attempt,
                        'status': status,
                        'handler_evidence': quality,
                        'detector_corroboration': detector,
                        'result': executed,
                    },
                )
            if budget_exhausted:
                break
        statuses = {item['status'] for item in attempts}
        detector_available = any(
            item.get('corroborated') is True for item in evidence_by_layer.values()
        )
        if 'corroborated' in statuses:
            family_status = 'confirmed'
            confirmed_families.append(family)
        elif budget_exhausted:
            family_status = 'partial_budget_exhausted'
        elif 'handler_evidence_without_detector' in statuses:
            family_status = 'handler_evidence_without_detector'
        elif detector_available:
            family_status = 'detector_only'
        elif 'timed_out' in statuses:
            family_status = 'handler_timed_out'
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
    elapsed_seconds = time.monotonic() - started
    if elapsed_seconds >= float(maximum_wall_seconds):
        budget_blockers.add('maximum_wall_seconds_exhausted')
        budget_exhausted = True
    return {
        'schema_version': 1,
        'status': (
            'partial'
            if budget_exhausted
            else 'confirmed'
            if confirmed_families
            else 'no_confirmed_family'
        ),
        'confirmed_families': sorted(confirmed_families),
        'candidate_count': len(normalized_candidates),
        'blocked_candidate_count': sum(
            not item['assessment_eligible'] for item in normalized_candidates
        ),
        'layer_count': len(normalized_layers),
        'planned_attempt_count': planned_attempts,
        'actual_attempt_count': actual_attempt_count,
        'retained_attempt_detail_count': retained_attempt_details,
        'omitted_attempt_detail_count': max(
            0,
            actual_attempt_count - retained_attempt_details,
        ),
        'unattempted_attempt_count': max(0, planned_attempts - actual_attempt_count),
        'handler_timeout_seconds': float(handler_timeout_seconds),
        'blockers': sorted(budget_blockers),
        'budget': {
            'maximum_attempts': maximum_attempts,
            'maximum_wall_seconds': float(maximum_wall_seconds),
            'maximum_response_bytes': maximum_response_bytes,
            'maximum_retained_attempt_details': maximum_retained_attempt_details,
            'maximum_verified_outputs': maximum_verified_outputs,
            'elapsed_seconds': elapsed_seconds,
            'response_bytes': response_bytes,
            'verified_output_count': verified_output_count,
            'exhausted': budget_exhausted,
        },
        'families': family_results,
        'metadata_hint_can_confirm': False,
        'confirmation_requirement': 'handler_evidence_and_detector_corroboration_in_same_lineage',
        'executed_sample': False,
        'network_contacted': False,
        'filesystem_written_by_handlers': False,
    }


if __name__ == '__main__':
    if len(sys.argv) == 4 and sys.argv[1] == '--assessment-worker':
        raise SystemExit(_assessment_worker_main(sys.argv[2], sys.argv[3]))
    raise SystemExit('このmoduleは--assessment-worker以外の直接実行に対応していません')
