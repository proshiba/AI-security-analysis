"""VenomRAT終端managed clientから認証済み設定を静的復元する。"""

from __future__ import annotations

import hashlib
import importlib.util
import re
import sys
from functools import cache
from pathlib import Path
from types import ModuleType
from urllib.parse import urlsplit, urlunsplit

from extractors.common import build_result, extract_strings, valid_host

HANDLER_CONTRACT = {
    "input_formats": ["pe"],
    "minimum_evidence_score": 20_000,
}

_COMMON_MODULE_NAME = "dotnet_rat_config"
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_VENOM_SETTINGS_FIELDS = frozenset(
    {
        "Key",
        "Por_ts",
        "Hos_ts",
        "Ver_sion",
        "In_stall",
        "Paste_bin",
        "An_ti",
        "Group",
        "Certifi_cate",
    }
)
_VENOM_CORE_FIELDS = frozenset(
    {"Por_ts", "Hos_ts", "Paste_bin", "Certifi_cate"}
)
_VENOM_PROTOCOL_FIELDS = frozenset({"Pac_ket", "Po_ng"})


def _common_directory() -> Path:
    """repository内の固定common directoryだけを解決する。"""

    repository = Path(__file__).resolve().parents[2]
    common = (repository / "analysis-framework" / "common").resolve(strict=True)
    try:
        common.relative_to(repository)
    except ValueError as exc:
        raise ImportError("analysis-framework/commonがrepository外を指しています") from exc
    if not common.is_dir():
        raise ImportError("analysis-framework/commonがdirectoryではありません")
    return common


def _module_has_expected_path(module: ModuleType, expected: Path) -> bool:
    source = getattr(module, "__file__", None)
    if not source:
        return False
    try:
        return Path(source).resolve(strict=True) == expected
    except OSError:
        return False


@cache
def _load_dotnet_rat_config() -> ModuleType:
    """検証済みの単一common moduleだけを遅延読込する。"""

    common = _common_directory()
    module_path = (common / f"{_COMMON_MODULE_NAME}.py").resolve(strict=True)
    if module_path.parent != common or not module_path.is_file():
        raise ImportError("dotnet_rat_configが許可directoryの直下にありません")
    import_name = f"_analysis_common_{_COMMON_MODULE_NAME}"
    existing = sys.modules.get(import_name)
    if existing is not None:
        if not _module_has_expected_path(existing, module_path):
            raise ImportError(f"{import_name}が予期しないpathから読み込まれています")
        return existing
    spec = importlib.util.spec_from_file_location(import_name, module_path)
    if spec is None or spec.loader is None:
        raise ImportError("dotnet_rat_configのload specを作成できません")
    module = importlib.util.module_from_spec(spec)
    sys.modules[import_name] = module
    try:
        spec.loader.exec_module(module)
    except Exception:
        if sys.modules.get(import_name) is module:
            del sys.modules[import_name]
        raise
    return module


def family_markers(strings: list[str]) -> list[str]:
    """後方互換用にQuasar派生の汎用markerを返す。"""

    text = "\n".join(strings).lower()
    return [
        marker
        for marker in (
            "quasar.client",
            "xclient.core",
            "reconnectdelay",
            "installname",
            "mutex",
        )
        if marker in text
    ]


def structural_evidence(data: bytes) -> dict[str, object]:
    """Venom固有field集合とCLR metadataの同時一致だけを強い構造証拠とする。"""

    strings = set(extract_strings(data, minimum=3))
    settings_fields = sorted(_VENOM_SETTINGS_FIELDS.intersection(strings))
    protocol_fields = sorted(_VENOM_PROTOCOL_FIELDS.intersection(strings))
    managed_pe = data.startswith(b"MZ") and b"BSJB" in data
    core_complete = _VENOM_CORE_FIELDS.issubset(settings_fields)
    supporting_count = len(
        {"Ver_sion", "In_stall", "An_ti", "Group"}.intersection(settings_fields)
    )
    matched = managed_pe and core_complete and supporting_count >= 2
    return {
        "matched": matched,
        "managed_pe": managed_pe,
        "settings_fields": settings_fields,
        "protocol_fields": protocol_fields,
        "core_fields_complete": core_complete,
        "supporting_field_count": supporting_count,
        "rule": "clr_metadata_and_venom_obfuscated_settings_v1",
    }


def _validated_dynamic_url(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or len(value) > 2_048:
        raise ValueError("動的設定URLの型または長さが不正です")
    parsed = urlsplit(value)
    if (
        parsed.scheme.casefold() not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or not valid_host(parsed.hostname)
    ):
        raise ValueError("動的設定URLが許可形式ではありません")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("動的設定URLのportが不正です") from exc
    if port is not None and not 1 <= port <= 65_535:
        raise ValueError("動的設定URLのportが範囲外です")
    host = parsed.hostname.casefold().rstrip(".")
    netloc = f"{host}:{port}" if port is not None else host
    return urlunsplit((parsed.scheme.casefold(), netloc, parsed.path, "", ""))


def _validated_recovery(data: bytes) -> dict[str, object]:
    module = _load_dotnet_rat_config()
    recovered = module.recover(data, "venomrat")
    if not isinstance(recovered, dict):
        raise ValueError("設定復元結果がobjectではありません")
    digest = hashlib.sha256(data).hexdigest()
    if (
        recovered.get("schema_version") != 1
        or recovered.get("family") != "venomrat"
        or recovered.get("sha256") != digest
        or recovered.get("terminal_managed_client") is not True
        or recovered.get("static_config_recovered") is not True
        or recovered.get("secret_fields_published") is not False
        or recovered.get("executed") is not False
        or recovered.get("network_contacted") is not False
    ):
        raise ValueError("設定復元結果の安全契約が一致しません")

    raw_endpoints = recovered.get("config_endpoints")
    if not isinstance(raw_endpoints, list) or len(raw_endpoints) > 64:
        raise ValueError("設定endpoint一覧が不正です")
    endpoints: list[dict[str, object]] = []
    for item in raw_endpoints:
        if not isinstance(item, dict):
            raise ValueError("設定endpointがobjectではありません")
        host = item.get("host")
        port = item.get("port")
        if (
            not isinstance(host, str)
            or not valid_host(host)
            or not isinstance(port, int)
            or isinstance(port, bool)
            or not 1 <= port <= 65_535
        ):
            raise ValueError("設定endpointのhostまたはportが不正です")
        endpoints.append({"host": host.casefold().rstrip("."), "port": port})
    endpoints = sorted(
        {f'{item["host"]}:{item["port"]}': item for item in endpoints}.values(),
        key=lambda item: (str(item["host"]), int(item["port"])),
    )

    certificate = recovered.get("certificate")
    if not isinstance(certificate, dict):
        raise ValueError("証明書情報がobjectではありません")
    certificate_sha256 = certificate.get("sha256")
    certificate_size = certificate.get("size")
    if certificate_sha256 is not None and (
        not isinstance(certificate_sha256, str)
        or _SHA256.fullmatch(certificate_sha256) is None
        or not isinstance(certificate_size, int)
        or isinstance(certificate_size, bool)
        or not 1 <= certificate_size <= 16 * 1024 * 1024
    ):
        raise ValueError("証明書hashまたはsizeが不正です")
    if certificate_sha256 is None and certificate_size is not None:
        raise ValueError("証明書hashなしでsizeだけが存在します")
    if certificate.get("certificate_mismatch_excludes_c2") is not False:
        raise ValueError("証明書不一致の判定契約が不正です")

    version = recovered.get("version")
    group = recovered.get("group")
    if version is not None and (not isinstance(version, str) or len(version) > 512):
        raise ValueError("versionが不正です")
    if group is not None and (not isinstance(group, str) or len(group) > 512):
        raise ValueError("groupが不正です")
    return {
        "version": version,
        "install": recovered.get("install"),
        "group": group,
        "anti_analysis": recovered.get("anti_analysis"),
        "endpoints": endpoints,
        "dynamic_config_url": _validated_dynamic_url(
            recovered.get("dynamic_config_url")
        ),
        "certificate": {
            "sha256": certificate_sha256,
            "size": certificate_size,
            "certificate_mismatch_excludes_c2": False,
        },
    }


def extract(data: bytes, name: str = "sample") -> dict:
    """強い構造一致後だけHMAC検証済み設定を公開結果へ統合する。"""

    strings = extract_strings(data)
    generic_markers = family_markers(strings)
    structural = structural_evidence(data)
    recovery: dict[str, object] | None = None
    recovery_status = "not_attempted_structural_mismatch"
    if structural["matched"] is True:
        try:
            recovery = _validated_recovery(data)
            recovery_status = "recovered_hmac_verified"
        except (ImportError, OSError, ValueError):
            recovery_status = "rejected_or_not_recovered"

    findings: list[dict[str, object]] = []
    if recovery is not None:
        findings.extend(
            {
                "kind": "network.endpoint",
                "value": f'{item["host"]}:{item["port"]}',
                "role": "configured_c2",
                "confidence": "confirmed_static_config",
                "source": "hmac_verified_dotnet_settings",
            }
            for item in recovery["endpoints"]
        )
        dynamic_url = recovery["dynamic_config_url"]
        if isinstance(dynamic_url, str):
            findings.append(
                {
                    "kind": "url",
                    "value": dynamic_url,
                    "role": "dynamic_config_resolver",
                    "confidence": "confirmed_static_config",
                    "source": "hmac_verified_dotnet_settings",
                }
            )
        certificate = recovery["certificate"]
        if isinstance(certificate, dict) and isinstance(
            certificate.get("sha256"), str
        ):
            findings.append(
                {
                    "kind": "certificate.sha256",
                    "value": certificate["sha256"],
                    "role": "tls_certificate_pin",
                    "confidence": "confirmed_static_config",
                    "source": "hmac_verified_dotnet_settings",
                }
            )

    config: dict[str, object] = {
        "source_name": name,
        "generic_markers": generic_markers,
        "structural_assessment": structural,
        "marker_hits": [structural] if structural["matched"] is True else [],
        "recovery_status": recovery_status,
        "terminal_managed_client": recovery is not None,
        "static_config_recovered": recovery is not None,
        "c2_liveness_confirmed": False,
    }
    if recovery is not None:
        config.update(recovery)
    else:
        config.update(
            {
                "version": None,
                "endpoints": [],
                "dynamic_config_url": None,
                "certificate": {
                    "sha256": None,
                    "size": None,
                    "certificate_mismatch_excludes_c2": False,
                },
            }
        )
    return build_result(
        "venomrat",
        data,
        config,
        findings,
        [
            "検体は実行せず、外部hostへ接続していません。",
            "CLR metadataとVenom固有の難読化field集合が一致しない入力では設定復元を試行しません。",
            "設定値はHMAC-SHA256を検証してからAES-256-CBCで復号し、認証失敗時は候補値を公開しません。",
            "dynamic_config_urlは時点付きで別取得し、復号設定と混同しないでください。",
            "証明書不一致だけでは非C2と判定しません。",
        ],
    )
