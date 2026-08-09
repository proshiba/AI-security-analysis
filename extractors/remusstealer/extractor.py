"""Remus Stealerの設定候補とtoken/task protocol状態を静的に抽出する。"""

from __future__ import annotations

import importlib.util
import re
import sys
import threading
from functools import cache
from pathlib import Path
from types import ModuleType

from extractors.stealer_common import extract_stealer
from extractors.stealer_protocols import attach_protocol_guidance

_COMMON_MODULE_NAME = re.compile(r"[a-z][a-z0-9_]*")
_COMMON_IMPORT_LOCK = threading.RLock()
_COMMON_DEPENDENCIES = {
    "remus_c2_profile": ("safe_private_output",),
}


def _common_directory() -> Path:
    """repository外への差し替えを拒否し、commonの実体pathを返す。"""

    repository = Path(__file__).resolve().parents[2]
    common = (repository / "analysis-framework" / "common").resolve(strict=True)
    try:
        common.relative_to(repository)
    except ValueError as exc:
        raise ImportError("analysis-framework/commonがrepository外を指しています") from exc
    if not common.is_dir():
        raise ImportError("analysis-framework/commonがdirectoryではありません")
    return common


def _module_path(module_name: str) -> Path:
    if _COMMON_MODULE_NAME.fullmatch(module_name) is None:
        raise ImportError("common module名が許可形式ではありません")
    common = _common_directory()
    module_path = (common / f"{module_name}.py").resolve(strict=True)
    if module_path.parent != common or not module_path.is_file():
        raise ImportError(
            f"common moduleが許可directoryの直下にありません: {module_name}"
        )
    return module_path


def _module_has_expected_path(module: ModuleType, expected: Path) -> bool:
    source = getattr(module, "__file__", None)
    if not source:
        return False
    try:
        return Path(source).resolve(strict=True) == expected
    except OSError:
        return False


def _load_exact_module(module_name: str, *, public_name: bool = False) -> ModuleType:
    """検証済みの単一file moduleだけを読み込む。"""

    module_path = _module_path(module_name)
    import_name = module_name if public_name else f"_analysis_common_{module_name}"
    existing = sys.modules.get(import_name)
    if existing is not None:
        if not _module_has_expected_path(existing, module_path):
            raise ImportError(f"{import_name}が予期しないpathから読み込まれています")
        return existing

    spec = importlib.util.spec_from_file_location(import_name, module_path)
    if spec is None or spec.loader is None:
        raise ImportError(f"common moduleのload specを作成できません: {module_name}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[import_name] = module
    try:
        spec.loader.exec_module(module)
    except Exception:
        if sys.modules.get(import_name) is module:
            del sys.modules[import_name]
        raise
    return module


@cache
def _load_common_module(module_name: str) -> ModuleType:
    """明示したcommon moduleとその許可済み依存だけをlazy loadする。"""

    with _COMMON_IMPORT_LOCK:
        for dependency in _COMMON_DEPENDENCIES.get(module_name, ()):
            _load_exact_module(dependency, public_name=True)
        return _load_exact_module(module_name)


def _terminal_memory_report(data: bytes) -> dict | None:
    """Remusの完全一致構造だけを復元reportとして返す。"""

    try:
        module = _load_common_module("remus_memory_config")
    except (ImportError, OSError):
        return None
    try:
        report = module.extract_remus_memory_config(data)
    except module.RemusMemoryConfigError:
        return None

    if report.get("status") != "extracted":
        return None
    memory_config = report.get("config")
    if not isinstance(memory_config, dict):
        return None
    endpoints = memory_config.get("endpoints")
    selector = memory_config.get("selector")
    tag = memory_config.get("tag")
    if (
        not isinstance(endpoints, list)
        or not endpoints
        or not isinstance(selector, dict)
        or selector.get("status") != "recovered"
        or not isinstance(tag, dict)
        or tag.get("status") not in {"candidate", "recovered", "confirmed"}
    ):
        return None
    selected_index = selector.get("selected_index")
    if not any(
        isinstance(endpoint, dict)
        and endpoint.get("slot_index") == selected_index
        and endpoint.get("host") != "none"
        for endpoint in endpoints
    ):
        return None
    return report


def _build_protocol_profile(result: dict, report: dict) -> dict | None:
    """common builderで受動profileとfail-closedの能動判定を生成する。"""

    try:
        module = _load_common_module("remus_c2_profile")
    except (ImportError, OSError):
        return None
    memory_config = report["config"]
    try:
        return module.build_remus_c2_profile(
            endpoints=memory_config["endpoints"],
            selected_index=memory_config["selector"]["selected_index"],
            tag_candidate=memory_config["tag"],
            exp=memory_config.get("exp"),
            reviewed_http_host=None,
            parent_sha256=result["sample_sha256"],
            dump_sha256=None,
            recovered_pe_sha256=result["sample_sha256"],
            source_reference=None,
        )
    except module.RemusC2ProfileError:
        return None


def _attach_terminal_memory_config(result: dict, report: dict) -> dict:
    """復元済みendpointとprotocolを現行schemaへ統合する。"""

    profile_report = _build_protocol_profile(result, report)

    memory_config = report["config"]
    selected_index = memory_config["selector"]["selected_index"]
    endpoints = memory_config["endpoints"]
    endpoint_values = [f'{item["host"]}:{item["port"]}' for item in endpoints]
    endpoint_uris = [item["uri"] for item in endpoints]
    promoted_values = set(endpoint_values) | set(endpoint_uris)

    result["findings"] = [
        finding
        for finding in result["findings"]
        if finding.get("value") not in promoted_values
    ]
    result["findings"].extend(
        {
            "kind": "network.endpoint",
            "value": value,
            "role": (
                "selected_c2"
                if item["slot_index"] == selected_index
                else "fallback_c2"
            ),
            "confidence": "confirmed_static_config",
            "source": "remus_chacha20_config",
        }
        for item, value in zip(endpoints, endpoint_values, strict=True)
    )

    config = result["config"]
    config["urls"] = endpoint_uris
    config["endpoints"] = endpoint_values
    config["static_config_recovered"] = True
    config["candidate_infrastructure_recovered"] = True
    config["c2_liveness_confirmed"] = False
    config["memory_config_analysis"] = report

    protocol = config["protocol_analysis"]
    protocol["confirmed_c2"] = []
    protocol["static_confirmed_c2"] = endpoint_values
    protocol["candidate_infrastructure"] = [
        item
        for item in protocol["candidate_infrastructure"]
        if item not in promoted_values
    ]
    if profile_report is None:
        blocked_reason = {
            "code": "protocol_profile_generation_failed",
            "message_ja": "静的configは復元しましたが、protocol profileを安全に生成できませんでした",
        }
        active_generation = {
            "status": "blocked",
            "blocked_reasons": [blocked_reason],
            "profile": None,
        }
        protocol["terminal_protocol_recovered"] = False
        protocol["active_profile_generation"] = active_generation
        protocol["active_probe_blocked_reasons"] = active_generation[
            "blocked_reasons"
        ]
        result["limitations"].extend(
            [
                "静的C2設定は保持しましたが、protocol profile生成に失敗したため能動判定を許可しません。",
                "confirmed_static_configは復号済み設定を示し、C2の現在の稼働や所有を確認したものではありません。",
            ]
        )
        return result

    passive = profile_report["passive_profile"]
    active_generation = profile_report["active_profile_generation"]
    protocol["terminal_protocol_recovered"] = True
    protocol["protocol_sequence"] = passive["protocol_sequence"]
    protocol["response_envelope"] = passive["response_envelope"]
    protocol["passive_profile"] = passive
    protocol["active_profile_generation"] = active_generation
    protocol["active_probe_blocked_reasons"] = active_generation["blocked_reasons"]
    protocol["profile_generation_safety"] = profile_report["safety"]

    result["limitations"].extend(
        [
            "expは静的設定から復元できていないため、能動登録profileは生成しません。",
            "review済みHTTP Hostと単一のpinned IPが静的には得られず、他検体の値は継承しません。",
            "confirmed_static_configは復号済み設定を示し、C2の現在の稼働や所有を確認したものではありません。",
        ]
    )
    return result


def extract(data: bytes, name: str = "sample") -> dict:
    """Remusの収集機能、静的C2設定とprotocol境界を返す。"""
    result = extract_stealer(
        "remusstealer",
        data,
        name,
        ("Remus", "RemusStealer", "Stealer", "wallet.dat", "Login Data"),
        {
            "browser_collection": ("Login Data", "Local State", "Cookies", "Web Data"),
            "wallet_collection": ("wallet.dat", "Electrum", "Exodus", "MetaMask"),
            "go_runtime": ("Go build ID", "runtime.main", "godebug"),
            "archive_delivery": ("7-zip", "7z", "Wrong password"),
        },
        [
            "暗号化された内側の7z配布物にはcampaign passwordが必要で、password guessingは行いません。",
            "Remus帰属とインフラは、復元payload levelの相関が必要です。",
        ],
    )
    result = attach_protocol_guidance(result, "remusstealer")
    report = _terminal_memory_report(data)
    if report is None:
        return result
    return _attach_terminal_memory_config(result, report)
