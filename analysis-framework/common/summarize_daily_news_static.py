#!/usr/bin/env python3
"""日次IOCから取得した検体の静的解析結果を公開可能な形へ要約する。"""

from __future__ import annotations

import argparse
import csv
import importlib
import io
import json
import os
import re
import stat
import sys
from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

COMMON_ROOT = Path(__file__).resolve().parent
if str(COMMON_ROOT) not in sys.path:
    sys.path.insert(0, str(COMMON_ROOT))
analysis_contract = importlib.import_module("analysis_contract")

CAPABILITY_APIS = {
    "network_client": {"connect", "socket", "wsastartup", "wsaeventselect", "winhttpopen", "internetopen", "curl_easy_init"},
    "host_discovery": {"getusernamea", "getusernamew", "getcomputernamea", "getcomputernamew", "getcomputernameexw", "getadaptersaddresses", "gettimezoneinformation"},
    "file_enumeration": {"findfirstfilea", "findfirstfilew", "findfirstfileexw", "findnextfilea", "findnextfilew", "createfilea", "createfilew", "readfile"},
    "process_execution": {"createprocessa", "createprocessw", "createprocessasuserw", "createprocesswithtokenw", "shellexecutea", "shellexecutew", "winexec"},
    "process_inspection": {"createtoolhelp32snapshot", "process32first", "process32next", "openprocess", "getprocessmemoryinfo"},
    "screen_capture": {"bitblt", "stretchblt", "getdibits", "createcompatiblebitmap", "createcompatibledc"},
    "registry_change": {"regcreatekeyexa", "regcreatekeyexw", "regsetvalueexa", "regsetvalueexw", "regdeletevaluea", "regdeletevaluew"},
    "anti_analysis_surface": {"isdebuggerpresent", "outputdebugstringa", "outputdebugstringw", "addvectoredexceptionhandler", "setunhandledexceptionfilter", "getthreadcontext", "setthreadcontext"},
    "certificate_store_access": {"certopenstore", "certenumcertificatesinstore", "certfreecertificatecontext"},
}

CAPABILITY_JA = {
    "network_client": "socket/HTTPクライアント相当の通信機能",
    "host_discovery": "利用者・端末・NIC・時間帯の収集",
    "file_enumeration": "ファイル列挙と読み取り",
    "process_execution": "子プロセスまたは別トークンでのプロセス起動",
    "process_inspection": "プロセス列挙・参照",
    "screen_capture": "GDIによる画面取得",
    "registry_change": "レジストリ作成・更新・削除",
    "anti_analysis_surface": "デバッガ・例外・スレッドコンテキストに関係する処理",
    "certificate_store_access": "Windows証明書ストアの列挙",
}

HASH_IOC_TYPES = {"file_hash_sha1", "file_hash_sha256"}
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
EMAIL_RE = re.compile(
    r"(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]+@"
    r"[A-Za-z0-9.-]+\.[A-Za-z]{2,63}(?![A-Za-z0-9._%+-])"
)
REDACTED_EMAIL = "[redacted-email]"
MAX_SUMMARY_CASES = 1_000
MAX_PUBLIC_SAMPLE_BYTES = 256 * 1024
MAX_PUBLIC_SAMPLES_TOTAL_BYTES = 32 * 1024 * 1024
MAX_STATIC_EVIDENCE_ITEMS = 10_000
MAX_STATIC_EVIDENCE_TEXT_BYTES = 2_048
MAX_REVIEWED_FUNCTIONS_PER_SAMPLE = 256
MAX_REVIEW_SOURCE_BYTES = 256
MAX_REVIEW_NAME_BYTES = 256
MAX_REVIEW_ROLE_BYTES = 512
MAX_REVIEW_EVIDENCE_BYTES = 2_048
FUNCTION_REVIEW_TYPE = "verified_static_evidence_supplement"
FUNCTION_REVIEW_DOCUMENT_KEYS = frozenset(
    {
        "schema_version",
        "review_type",
        "source_date",
        "safety",
        "sample_count",
        "samples",
    }
)
FUNCTION_REVIEW_SAMPLE_KEYS = frozenset(
    {"sha256", "source", "functions", "static_evidence"}
)
FUNCTION_REVIEW_FUNCTION_KEYS = frozenset(
    {"address", "name", "role", "evidence"}
)
FUNCTION_REVIEW_SAFETY = {
    "network_contacted": False,
    "online_revocation_checked": False,
    "raw_sample_published": False,
    "sample_executed": False,
}
REVIEW_SOURCE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$")
REVIEW_ADDRESS_RE = re.compile(r"^(?:0x)?[0-9A-Fa-f]{1,16}$")
REVIEW_FUNCTION_NAME_RE = re.compile(r"^[A-Za-z0-9_?$@:.<>~+\-]{1,256}$")
ABSOLUTE_PATH_RE = re.compile(
    r"(?:^|[\s\x60\"'])(?:[A-Za-z]:[\\/]|\\\\|/(?:Users|home|root|tmp|var|etc|opt|mnt|srv)/)",
    re.IGNORECASE,
)
RAW_DECOMPILATION_RE = re.compile(
    r"(?:/\*\s*(?:WARNING|Decompiler)|\b(?:undefined\d*|local_[0-9a-f]+|stack0x[0-9a-f]+)\b|"
    r"\b(?:void|int|char|long|short|bool|byte|dword|qword)\s+(?:FUN_|sub_)[0-9a-f]+\s*\(|"
    r"\b(?:if|while|for)\s*\([^\n]{0,512}\)\s*\{|\breturn\b[^\n]{0,512};)",
    re.IGNORECASE,
)

AUTHENTICODE_VERIFIED_STATUSES = frozenset({
    "ok",
    "valid",
    "verified",
    "verification_flags.ok",
})

# 製品名だけではなく、署名で保護されたOriginalFilenameと役割markerを
# 併用する。これらのmarkerは悪性判定ではなく正規コンポーネント内の役割確認用。
NETSUPPORT_COMPONENT_PROFILES: dict[str, dict[str, Any]] = {
    "audiocapturewvi.dll": {
        "id": "netsupport_audio_capture_module",
        "summary_ja": "NetSupportの音声キャプチャ用モジュール",
        "required_exports": frozenset({"iscapturing", "startcapturing", "stopcapturing"}),
        "required_imports": frozenset(),
        "required_modules": frozenset(),
    },
    "pcicapi.dll": {
        "id": "netsupport_capi_transport_module",
        "summary_ja": "NetSupportのISDN CAPIトランスポート用モジュール",
        "required_exports": frozenset({"capiopen", "capidial", "capisend", "capiread"}),
        "required_imports": frozenset(),
        "required_modules": frozenset(),
    },
    "client32.exe": {
        "id": "netsupport_remote_control_client_bootstrap",
        "summary_ja": "NetSupport Remote Controlクライアントの起動ラッパー",
        "required_exports": frozenset(),
        "required_imports": frozenset({"_nsmclient32@8"}),
        "required_modules": frozenset({"pcicl32.dll"}),
    },
    "remcmdstub.exe": {
        "id": "netsupport_remote_command_stub",
        "summary_ja": "NetSupport Remote Command Promptの子プロセス起動stub",
        "required_exports": frozenset(),
        "required_imports": frozenset({"createprocessa", "getcommandlinea"}),
        "required_modules": frozenset({"kernel32.dll"}),
    },
}


def _evidence_text(value: Any, label: str) -> str | None:
    """review supplementの文字列を公開可能な上限内へ固定する。"""

    if value is None:
        return None
    if not isinstance(value, str):
        raise TypeError(f"{label}が文字列ではありません")
    normalized = value.strip()
    if not normalized:
        return None
    if len(normalized.encode("utf-8")) > MAX_STATIC_EVIDENCE_TEXT_BYTES:
        raise ValueError(f"{label}が容量上限を超えています")
    return normalized


def _review_text(
    value: Any,
    label: str,
    *,
    maximum_bytes: int,
    reject_raw_decompilation: bool = False,
) -> str:
    """公開review文字列を単一行・非path・非raw本文へ限定する。"""

    if not isinstance(value, str):
        raise TypeError(f"{label}が文字列ではありません")
    normalized = value.strip()
    if not normalized:
        raise ValueError(f"{label}が空です")
    if len(normalized.encode("utf-8")) > maximum_bytes:
        raise ValueError(f"{label}が容量上限を超えています")
    if any(ord(character) < 32 or ord(character) == 127 for character in normalized):
        raise ValueError(f"{label}に制御文字が含まれています")
    if ABSOLUTE_PATH_RE.search(normalized):
        raise ValueError(f"{label}に絶対pathが含まれています")
    if reject_raw_decompilation and (
        "{" in normalized
        or "}" in normalized
        or RAW_DECOMPILATION_RE.search(normalized)
    ):
        raise ValueError(f"{label}に生の逆コンパイル本文が含まれています")
    return normalized


def _normalize_reviewed_functions(value: Any) -> list[dict[str, str]]:
    """検証済みGhidra reviewを公開用4 fieldへfail-closed正規化する。"""

    if not isinstance(value, list) or len(value) > MAX_REVIEWED_FUNCTIONS_PER_SAMPLE:
        raise ValueError("function reviewのfunctionsが上限内のlistではありません")
    normalized: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for item in value:
        if not isinstance(item, Mapping) or set(item) != FUNCTION_REVIEW_FUNCTION_KEYS:
            raise ValueError("function review関数のfield集合が不正です")
        address = _review_text(
            item.get("address"),
            "function review address",
            maximum_bytes=18,
        )
        if REVIEW_ADDRESS_RE.fullmatch(address) is None:
            raise ValueError("function review addressが16進addressではありません")
        name = _review_text(
            item.get("name"),
            "function review name",
            maximum_bytes=MAX_REVIEW_NAME_BYTES,
        )
        if REVIEW_FUNCTION_NAME_RE.fullmatch(name) is None:
            raise ValueError("function review nameが許可済み識別子ではありません")
        role = _review_text(
            item.get("role"),
            "function review role",
            maximum_bytes=MAX_REVIEW_ROLE_BYTES,
            reject_raw_decompilation=True,
        )
        evidence = _review_text(
            item.get("evidence"),
            "function review evidence",
            maximum_bytes=MAX_REVIEW_EVIDENCE_BYTES,
            reject_raw_decompilation=True,
        )
        key = (address.casefold().removeprefix("0x"), name.casefold())
        if key in seen:
            raise ValueError("function review関数が重複しています")
        seen.add(key)
        normalized.append(
            {"address": address, "name": name, "role": role, "evidence": evidence}
        )
    return normalized


def _function_reviews_document(
    payload: Mapping[str, Any] | None,
    *,
    expected_source_date: str | None = None,
) -> dict[str, dict[str, Any]]:
    """review supplementのschema/statusと全sampleを公開前に検証する。"""

    if payload is None:
        return {}
    if set(payload) != FUNCTION_REVIEW_DOCUMENT_KEYS:
        raise ValueError("function review文書のtop-level field集合が不正です")
    if payload.get("schema_version") != 1:
        raise ValueError("function review文書のschema versionが未対応です")
    if payload.get("review_type") != FUNCTION_REVIEW_TYPE:
        raise ValueError("function review文書のschema種別が未対応です")
    source_date = payload.get("source_date")
    if not isinstance(source_date, str) or re.fullmatch(
        r"20[0-9]{2}-[0-9]{2}-[0-9]{2}",
        source_date,
    ) is None:
        raise ValueError("function review文書のsource dateが不正です")
    if expected_source_date is not None and source_date != expected_source_date:
        raise ValueError("function review文書と日次要約のsource dateが一致しません")
    if payload.get("safety") != FUNCTION_REVIEW_SAFETY:
        raise ValueError("function review文書の安全statusが不正です")
    raw_reviews = payload.get("samples")
    sample_count = payload.get("sample_count")
    if (
        not isinstance(raw_reviews, list)
        or len(raw_reviews) > MAX_SUMMARY_CASES
        or isinstance(sample_count, bool)
        or not isinstance(sample_count, int)
        or sample_count != len(raw_reviews)
    ):
        raise ValueError("function review文書のsample件数が不正です")
    reviews: dict[str, dict[str, Any]] = {}
    for item in raw_reviews:
        if not isinstance(item, Mapping) or set(item) != FUNCTION_REVIEW_SAMPLE_KEYS:
            raise ValueError("function review sampleのfield集合が不正です")
        digest = str(item.get("sha256") or "").casefold()
        if SHA256_RE.fullmatch(digest) is None:
            raise ValueError("function review sampleのSHA-256が不正です")
        if digest in reviews:
            raise ValueError("function review sampleのSHA-256が重複しています")
        source = _review_text(
            item.get("source"),
            "function review source",
            maximum_bytes=MAX_REVIEW_SOURCE_BYTES,
        )
        if REVIEW_SOURCE_RE.fullmatch(source) is None:
            raise ValueError("function review sourceが許可済み識別子ではありません")
        static_evidence = item.get("static_evidence")
        if not isinstance(static_evidence, Mapping):
            raise TypeError("function review static_evidenceがobjectではありません")
        if (
            static_evidence.get("schema_version") != 1
            or static_evidence.get("status") != "verified"
        ):
            raise ValueError("function review sampleの検証statusが不正です")
        reviews[digest] = {
            "sha256": digest,
            "source": source,
            "functions": _normalize_reviewed_functions(item.get("functions")),
            "static_evidence": static_evidence,
        }
    return reviews


def _mapping_text(value: Mapping[str, Any], keys: tuple[str, ...], label: str) -> str | None:
    for key in keys:
        if key in value:
            return _evidence_text(value.get(key), label)
    return None


def _normalize_authenticode(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise TypeError("static_evidence.authenticodeがobjectではありません")
    for key in ("present", "verified", "online_revocation_checked"):
        if key in value and value[key] is not None and not isinstance(value[key], bool):
            raise TypeError(f"static_evidence.authenticode.{key}がbooleanではありません")
    verification_status = _mapping_text(
        value,
        ("verification_status", "status"),
        "Authenticode verification status",
    )
    status_verified = bool(
        verification_status
        and verification_status.casefold() in AUTHENTICODE_VERIFIED_STATUSES
    )
    verified = bool(
        value.get("present") is True
        and value.get("verified") is True
        and status_verified
    )
    signer_subject = _mapping_text(
        value,
        ("signer_subject", "subject"),
        "Authenticode signer subject",
    )
    if signer_subject is not None:
        signer_subject = EMAIL_RE.sub(REDACTED_EMAIL, signer_subject)
    return {
        "present": value.get("present") is True,
        "verified": verified,
        "verification_status": verification_status,
        "signer_subject": signer_subject,
        "verification_tool": _mapping_text(
            value,
            ("verification_tool", "tool"),
            "Authenticode verification tool",
        ),
        "verification_scope": _mapping_text(
            value,
            ("verification_scope", "scope"),
            "Authenticode verification scope",
        ),
        "online_revocation_checked": value.get("online_revocation_checked"),
    }


def _normalize_pe_version(value: Any) -> dict[str, str | None]:
    if not isinstance(value, Mapping):
        raise TypeError("static_evidence.pe_versionがobjectではありません")
    raw = value.get("values", value)
    if not isinstance(raw, Mapping):
        raise TypeError("static_evidence.pe_version.valuesがobjectではありません")
    return {
        "company_name": _mapping_text(raw, ("CompanyName", "company_name"), "PE CompanyName"),
        "product_name": _mapping_text(raw, ("ProductName", "product_name"), "PE ProductName"),
        "file_description": _mapping_text(
            raw,
            ("FileDescription", "file_description"),
            "PE FileDescription",
        ),
        "original_filename": _mapping_text(
            raw,
            ("OriginalFilename", "original_filename"),
            "PE OriginalFilename",
        ),
        "file_version": _mapping_text(
            raw,
            ("FileVersion", "file_version", "ProductVersion", "product_version"),
            "PE FileVersion",
        ),
    }


def _normalize_named_items(value: Any, label: str) -> list[str]:
    if value is None:
        return []
    if isinstance(value, Mapping):
        value = value.get("items")
    if not isinstance(value, list) or len(value) > MAX_STATIC_EVIDENCE_ITEMS:
        raise ValueError(f"{label}が上限内のlistではありません")
    output: dict[str, str] = {}
    for item in value:
        if isinstance(item, Mapping):
            name = _mapping_text(item, ("name",), f"{label} name")
        else:
            name = _evidence_text(item, label)
        if not name:
            continue
        # Ghidraの公開export表現 `name -> address` から識別子だけを保持する。
        canonical = re.split(r"\s+->\s+", name, maxsplit=1)[0].strip()
        if canonical:
            output.setdefault(canonical.casefold(), canonical)
    return [output[key] for key in sorted(output)]


def _normalize_import_evidence(value: Any, label: str) -> dict[str, list[str]]:
    """module/symbolを上限付きで正規化し、アドレス等は公開しない。"""

    if value is None:
        return {"modules": [], "symbols": []}
    rows: Any = None
    modules_value: Any = None
    if isinstance(value, Mapping):
        if "modules" in value:
            modules_value = value.get("modules")
        elif "items" in value:
            rows = value.get("items")
        else:
            modules_value = value
    elif isinstance(value, list):
        rows = value
    else:
        raise TypeError(f"{label}がobject/listではありません")

    modules: dict[str, str] = {}
    symbols: dict[str, str] = {}
    item_count = 0
    if modules_value is not None:
        if not isinstance(modules_value, Mapping) or len(modules_value) > 2_048:
            raise ValueError(f"{label}.modulesが上限内のobjectではありません")
        for module, raw_symbols in modules_value.items():
            module_name = _evidence_text(module, f"{label} module")
            if not module_name:
                continue
            if not isinstance(raw_symbols, list):
                raise TypeError(f"{label} import function listが不正です")
            item_count += len(raw_symbols)
            if item_count > MAX_STATIC_EVIDENCE_ITEMS:
                raise ValueError(f"{label}件数が上限を超えています")
            modules.setdefault(module_name.casefold(), module_name)
            for raw_symbol in raw_symbols:
                if isinstance(raw_symbol, Mapping):
                    symbol = _mapping_text(raw_symbol, ("name",), f"{label} symbol")
                else:
                    symbol = _evidence_text(raw_symbol, f"{label} symbol")
                if symbol:
                    symbols.setdefault(symbol.casefold(), symbol)
    else:
        if not isinstance(rows, list) or len(rows) > MAX_STATIC_EVIDENCE_ITEMS:
            raise ValueError(f"{label}.itemsが上限内のlistではありません")
        for row in rows:
            if isinstance(row, Mapping):
                symbol = _mapping_text(row, ("name", "symbol"), f"{label} symbol")
                module = _mapping_text(row, ("module", "library", "dll"), f"{label} module")
            else:
                raw = _evidence_text(row, f"{label} symbol")
                module, separator, symbol = raw.partition("!") if raw else ("", "", "")
                if not separator:
                    symbol = raw
                    module = None
            if symbol:
                symbols.setdefault(symbol.casefold(), symbol)
            if module:
                modules.setdefault(module.casefold(), module)
    return {
        "modules": [modules[key] for key in sorted(modules)],
        "symbols": [symbols[key] for key in sorted(symbols)],
    }


def _static_review_evidence(review: Mapping[str, Any]) -> dict[str, Any]:
    """明示的に検証済みとされたreview supplementだけを採用する。"""

    value = review.get("static_evidence")
    source = _evidence_text(review.get("source"), "function review source")
    if value is None:
        return {"usable": False, "reason": "verified_static_evidence_not_provided", "source": source}
    if not isinstance(value, Mapping):
        raise TypeError("function review static_evidenceがobjectではありません")
    schema_version = value.get("schema_version")
    status = _mapping_text(value, ("status",), "static_evidence status")
    if (
        isinstance(schema_version, bool)
        or schema_version != 1
        or status != "verified"
    ):
        return {"usable": False, "reason": "static_evidence_not_verified", "source": source}
    evidence_source = _mapping_text(value, ("source",), "static_evidence source") or source
    return {
        "usable": True,
        "reason": None,
        "source": evidence_source,
        "authenticode": _normalize_authenticode(value.get("authenticode")),
        "pe_version": _normalize_pe_version(value.get("pe_version")),
        "exports": _normalize_named_items(value.get("exports"), "static_evidence.exports"),
        "imports": _normalize_import_evidence(value.get("imports"), "static_evidence.imports"),
    }


def _imports(triage: dict[str, Any]) -> set[str]:
    output: set[str] = set()
    imports = (triage.get("pe") or {}).get("imports", {})
    if not isinstance(imports, Mapping) or len(imports) > 2_048:
        raise ValueError("import tableが上限内のobjectではありません")
    function_count = 0
    for functions in imports.values():
        if not isinstance(functions, list):
            raise TypeError("import function listが不正です")
        function_count += len(functions)
        if function_count > 10_000:
            raise ValueError("import function件数が上限を超えています")
        output.update(str(function).lower() for function in functions)
    return output


def _bounded_public_copy(value: Any, *, maximum_bytes: int) -> tuple[Any, int]:
    """選択済み公開fieldだけを容量内のdetached JSONへ変換する。"""

    encoded = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    if not 0 < len(encoded) <= maximum_bytes:
        raise ValueError("日次公開sample fieldが容量上限を超えています")
    return json.loads(encoded), len(encoded)


def infer_capabilities(triage: dict[str, Any]) -> list[dict[str, Any]]:
    imports = _imports(triage)
    results = []
    for name, candidates in CAPABILITY_APIS.items():
        evidence = sorted(imports & candidates)
        if evidence:
            results.append({
                "id": name,
                "summary_ja": CAPABILITY_JA[name],
                "evidence_imports": evidence,
                "confidence": "import_surface_only",
            })
    return results


def _campaign_source_text(source: Mapping[str, Any], key: str) -> str | None:
    return _evidence_text(source.get(key), f"IOC source {key}")


def _campaign_abuse_context(
    source: Mapping[str, Any],
    *,
    verified_dual_use_component: bool,
) -> dict[str, Any]:
    if not source:
        return {
            "status": "not_reported",
            "reported_label": None,
            "reported_type": None,
            "reference": None,
            "source_description": None,
            "relationship": "not_established",
            "assessment_ja": "この検体に対応するキャンペーン文脈はIOC入力に記録されていない。",
        }
    relationship = (
        "verified_dual_use_component_reported_in_campaign"
        if verified_dual_use_component
        else "osint_label_only"
    )
    assessment = (
        "IOC入力は当該正規dual-useコンポーネントをキャンペーン内の配置物として報告している。"
        "この配置文脈は悪用可能性を示すが、コンポーネント自体の悪性改変を意味しない。"
        if verified_dual_use_component
        else
        "IOC入力のラベルはキャンペーン上の手掛かりであり、検体本体の悪性またはC2役割を単独では確定しない。"
    )
    return {
        "status": "reported_campaign_context",
        "reported_label": _campaign_source_text(source, "malware"),
        "reported_type": _campaign_source_text(source, "malware_type"),
        "category": _campaign_source_text(source, "category"),
        "reference": _campaign_source_text(source, "reference"),
        "source_description": _campaign_source_text(source, "description"),
        "source_confidence": _campaign_source_text(source, "confidence"),
        "relationship": relationship,
        "assessment_ja": assessment,
    }


def _component_maliciousness(
    *,
    verified_dual_use_component: bool,
    campaign_context_present: bool,
) -> dict[str, Any]:
    if verified_dual_use_component:
        return {
            "status": "not_established_for_verified_dual_use_component",
            "direct_malicious_code_confirmed": False,
            "unknown_malware_body_confirmed": False,
            "standalone_c2_confirmed": False,
            "campaign_abuse_reported": campaign_context_present,
            "promotion_decision": "do_not_promote_as_unknown_malware_or_c2",
            "assessment_ja": (
                "検証済みAuthenticode、PE version情報、役割markerは署名済みNetSupportコンポーネントと整合する。"
                "直接の悪性改変または独立C2を示す静的根拠がないため、未知マルウェア本体やC2へ昇格しない。"
            ),
        }
    return {
        "status": "unresolved",
        "direct_malicious_code_confirmed": None,
        "unknown_malware_body_confirmed": None,
        "standalone_c2_confirmed": None,
        "campaign_abuse_reported": campaign_context_present,
        "promotion_decision": "withhold_pending_direct_static_evidence",
        "assessment_ja": (
            "このidentity gateではOSINTラベル、署名タグ、import表だけから悪性またはC2役割を確定しない。"
            "検証済みidentityと直接の関数・設定・通信根拠を別途評価するまで判定を保留する。"
        ),
    }


def _assess_software_component(
    triage: Mapping[str, Any],
    review: Mapping[str, Any],
    source: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]:
    """製品同一性、役割、悪用文脈、悪性を混同せずfail-closed評価する。"""

    evidence = _static_review_evidence(review)
    default_authenticode = {
        "present": None,
        "verified": False,
        "verification_status": None,
        "signer_subject": None,
        "verification_tool": None,
        "verification_scope": None,
        "online_revocation_checked": None,
    }
    authenticode = evidence.get("authenticode", default_authenticode)
    pe_version = evidence.get("pe_version", {})
    missing_identity: list[str] = []
    if not evidence["usable"]:
        missing_identity.append(str(evidence["reason"]))
    else:
        signer = str(authenticode.get("signer_subject") or "")
        company = str(pe_version.get("company_name") or "")
        product = str(pe_version.get("product_name") or "")
        original = str(pe_version.get("original_filename") or "")
        if authenticode.get("verified") is not True:
            missing_identity.append("verified_authenticode")
        if "netsupport" not in signer.casefold():
            missing_identity.append("netsupport_signer_subject")
        if "netsupport" not in company.casefold():
            missing_identity.append("netsupport_company_name")
        if "netsupport" not in product.casefold():
            missing_identity.append("netsupport_product_name")
        if not pe_version.get("file_version"):
            missing_identity.append("pe_file_version")
        if original.casefold() not in NETSUPPORT_COMPONENT_PROFILES:
            missing_identity.append("known_original_filename")

    identity_verified = not missing_identity
    software_identity = {
        "status": "verified_vendor_component" if identity_verified else "unresolved",
        "vendor": "NetSupport" if identity_verified else None,
        "product": pe_version.get("product_name") if identity_verified else None,
        "version": pe_version.get("file_version") if identity_verified else None,
        "original_filename": pe_version.get("original_filename") if identity_verified else None,
        "file_description": pe_version.get("file_description") if identity_verified else None,
        "authenticode": authenticode,
        "observed_pe_version": pe_version,
        "evidence_source": evidence.get("source"),
        "missing_evidence": sorted(missing_identity),
        "assessment_ja": (
            "Authenticodeの静的検証結果と署名対象のPE version情報からNetSupportコンポーネントと確認した。"
            if identity_verified
            else
            "検証済みreview supplementのAuthenticodeとPE version情報が全条件を満たさないため、製品同一性を確定しない。"
        ),
    }

    profile = None
    if identity_verified:
        profile = NETSUPPORT_COMPONENT_PROFILES[
            str(pe_version["original_filename"]).casefold()
        ]
    evidence_exports = list(evidence.get("exports", []))
    evidence_imports = evidence.get("imports", {"modules": [], "symbols": []})
    triage_imports = _normalize_import_evidence(
        (triage.get("pe") or {}).get("imports", {}),
        "generic_triage.pe.imports",
    )
    export_lookup = {item.casefold(): item for item in evidence_exports}
    import_lookup = {item.casefold(): item for item in evidence_imports["symbols"]}
    module_lookup = {item.casefold(): item for item in evidence_imports["modules"]}
    triage_import_keys = {item.casefold() for item in triage_imports["symbols"]}
    triage_module_keys = {item.casefold() for item in triage_imports["modules"]}
    missing_role: list[str] = []
    matched_exports: list[str] = []
    matched_imports: list[str] = []
    matched_modules: list[str] = []
    if profile is None:
        missing_role.append("verified_software_identity")
    else:
        for required in sorted(profile["required_exports"]):
            if required in export_lookup:
                matched_exports.append(export_lookup[required])
            else:
                missing_role.append(f"export:{required}")
        for required in sorted(profile["required_imports"]):
            if required in import_lookup and required in triage_import_keys:
                matched_imports.append(import_lookup[required])
            else:
                missing_role.append(f"verified_import:{required}")
        for required in sorted(profile["required_modules"]):
            if required in module_lookup and required in triage_module_keys:
                matched_modules.append(module_lookup[required])
            else:
                missing_role.append(f"verified_import_module:{required}")

    role_verified = profile is not None and not missing_role
    component_role = {
        "status": "verified" if role_verified else "unresolved",
        "id": profile["id"] if role_verified else None,
        "summary_ja": (
            profile["summary_ja"]
            if role_verified
            else "検証済み製品同一性と必要なexport/import markerが揃わないため、コンポーネント役割を確定しない。"
        ),
        "evidence_exports": matched_exports,
        "evidence_imports": matched_imports,
        "evidence_import_modules": matched_modules,
        "evidence_sources": [
            item
            for item in (
                evidence.get("source"),
                "generic_triage.pe.imports" if profile and profile["required_imports"] else None,
            )
            if item
        ],
        "missing_evidence": sorted(missing_role),
    }
    verified_dual_use_component = identity_verified and role_verified
    campaign_context = _campaign_abuse_context(
        source,
        verified_dual_use_component=verified_dual_use_component,
    )
    maliciousness = _component_maliciousness(
        verified_dual_use_component=verified_dual_use_component,
        campaign_context_present=bool(source),
    )
    return software_identity, component_role, campaign_context, maliciousness


def _labels_from_rows(rows: Iterable[Mapping[str, Any]]) -> dict[str, dict[str, str]]:
    return {
        str(row.get("ioc_value") or "").lower(): dict(row)
        for row in rows
        if row.get("ioc_type") in HASH_IOC_TYPES and row.get("ioc_value")
    }


def _read_labels(ioc_csv: Path) -> dict[str, dict[str, str]]:
    payload = analysis_contract._read_regular_file_snapshot(
        ioc_csv,
        max_bytes=8 * 1024 * 1024,
    )
    stream = io.StringIO(payload.decode("utf-8-sig", errors="strict"), newline="")
    return _labels_from_rows(csv.DictReader(stream))


def _provider_aliases_document(
    payload: Mapping[str, Any] | None,
    labels: dict[str, dict[str, str]],
) -> dict[str, dict[str, str]]:
    """親で検証済みのprovider文書からだけhash aliasを構築する。"""

    aliases: dict[str, dict[str, str]] = {}
    if payload is None:
        return aliases
    items = payload.get("items")
    if not isinstance(items, list) or len(items) > MAX_SUMMARY_CASES * 4:
        raise ValueError("provider文書のitemsが上限内のlistではありません")
    for item in items:
        if not isinstance(item, Mapping):
            raise TypeError("provider文書のitemがobjectではありません")
        metadata = item.get("metadata") or {}
        if not isinstance(metadata, Mapping):
            raise TypeError("provider metadataがobjectではありません")
        query = str(item.get("digest") or item.get("sha256") or item.get("sha1") or "").lower()
        source = labels.get(query, {})
        if not source and item.get("reported_malware"):
            source = {
                "malware": str(item["reported_malware"]),
                "malware_type": "provider_lookup",
                "ioc_value": query,
            }
        for value in (
            item.get("sha256"), item.get("sha1"),
            metadata.get("sha256_hash"), metadata.get("sha1_hash"),
        ):
            if value and source:
                aliases[str(value).lower()] = source
    return aliases


def _provider_aliases(path: Path | None, labels: dict[str, dict[str, str]]) -> dict[str, dict[str, str]]:
    if path is None or not os.path.lexists(path):
        return {}
    payload = analysis_contract.load_json_object_strict(path)
    return _provider_aliases_document(payload, labels)


def _architecture(triage: dict[str, Any]) -> dict[str, Any]:
    if triage.get("type") == "pe":
        pe = triage.get("pe") or {}
        return {"machine": pe.get("machine"), "entry_point": pe.get("entry_point_rva")}
    if triage.get("type") == "elf":
        elf = triage.get("elf") or {}
        return {
            "machine": elf.get("machine"),
            "bits": elf.get("bits"),
            "byte_order": elf.get("byte_order"),
            "entry_point": elf.get("entry_point"),
        }
    macho = triage.get("macho") or {}
    return {"machine": macho.get("cpu_type"), "entry_point": macho.get("entry_point")}


def _function_reviews(
    path: Path | None,
    source_date: str,
) -> dict[str, dict[str, Any]]:
    if path is None or not os.path.lexists(path):
        return {}
    payload = analysis_contract.load_json_object_strict(path)
    return _function_reviews_document(payload, expected_source_date=source_date)

def _build_summary_materialized(
    case_documents: Iterable[Mapping[str, Any]],
    *,
    labels: dict[str, dict[str, str]],
    aliases: dict[str, dict[str, str]],
    reviews: dict[str, dict[str, Any]],
    source_date: str,
    input_commitment: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    samples: list[dict[str, Any]] = []
    clusters: dict[str, list[str]] = defaultdict(list)
    retained_sample_bytes = 0

    observed: set[str] = set()
    previous_digest: str | None = None
    for document in case_documents:
        if len(observed) >= MAX_SUMMARY_CASES:
            raise ValueError("日次要約case件数が上限を超えています")
        if not isinstance(document, Mapping):
            raise TypeError("日次要約case documentがobjectではありません")
        digest = document.get("sha256")
        if (
            not isinstance(digest, str)
            or SHA256_RE.fullmatch(digest) is None
            or digest in observed
            or (previous_digest is not None and digest <= previous_digest)
        ):
            raise ValueError("日次要約case SHA-256が不正または重複しています")
        observed.add(digest)
        previous_digest = digest
        triage = document.get("generic_triage")
        static_logic = document.get("static_logic")
        if not isinstance(triage, Mapping) or not isinstance(static_logic, Mapping):
            raise TypeError("日次要約caseの静的JSONがobjectではありません")
        if str(triage.get("sha256") or digest).lower() != digest:
            raise ValueError("日次要約caseとgeneric triageのSHA-256が一致しません")
        source = labels.get(digest) or aliases.get(digest, {})
        review = reviews.get(digest, {})
        reviewed_functions = list(review.get("functions") or [])
        (
            software_identity,
            component_role,
            campaign_abuse_context,
            maliciousness,
        ) = _assess_software_component(triage, review, source)
        pe = triage.get("pe") or {}
        elf = triage.get("elf") or {}
        sample_type = str(triage.get("type") or "unknown")
        architecture = _architecture(triage)
        imphash = pe.get("imphash")
        telfhash = elf.get("telfhash")
        if imphash:
            cluster_key = f"imphash:{imphash}"
        elif telfhash:
            cluster_key = f"telfhash:{telfhash}"
        else:
            cluster_key = f"format:{sample_type}:{architecture.get('machine')}:{architecture.get('byte_order', '-') }"
        clusters[cluster_key].append(digest)

        sample: dict[str, Any] = {
            "sha256": digest,
            "reported_malware": source.get("malware") or "unknown",
            "reported_malware_type": source.get("malware_type") or "unknown",
            "source_hash": source.get("ioc_value"),
            "attribution_basis": "tech-memoのIOCラベルとプロバイダのハッシュ対応情報",
            "file_type": sample_type,
            "size": triage.get("size"),
            "entropy": triage.get("entropy"),
            "magic": triage.get("magic"),
            "architecture": architecture,
            "imphash": imphash,
            "telfhash": telfhash,
            "is_dotnet": pe.get("is_dotnet"),
            "capabilities": infer_capabilities(triage),
            "software_identity": software_identity,
            "component_role": component_role,
            "campaign_abuse_context": campaign_abuse_context,
            "maliciousness": maliciousness,
            "analysis_coverage": triage.get("analysis_coverage"),
            "static_logic_status": static_logic.get("status"),
            "function_count": max(static_logic.get("coverage", {}).get("function_count", 0), len(reviewed_functions)),
            "call_edge_count": static_logic.get("coverage", {}).get("call_edge_count", 0),
            "function_bodies_reviewed": bool(reviewed_functions) or static_logic.get("coverage", {}).get("function_bodies_reviewed", False),
            "reviewed_functions": reviewed_functions,
            "function_review_source": review.get("source"),
            "limitations": static_logic.get("limitations", []),
            "sample_executed": False,
            "network_contacted_by_sample": False,
        }
        if sample_type == "script":
            script = triage.get("script") or {}
            sample["script_indicators"] = script.get("indicators", {})
            sample["script_iocs"] = script.get("iocs", {})
            sample["functions"] = static_logic.get("functions", [])
            sample["call_edges"] = static_logic.get("call_edges", [])
        detached, encoded_size = _bounded_public_copy(
            sample,
            maximum_bytes=MAX_PUBLIC_SAMPLE_BYTES,
        )
        retained_sample_bytes += encoded_size
        if retained_sample_bytes > MAX_PUBLIC_SAMPLES_TOTAL_BYTES:
            raise ValueError("日次公開sample合計sizeが上限を超えています")
        samples.append(detached)

    format_counts = Counter(item["file_type"] for item in samples)
    cluster_rows = []
    for key, members in sorted(clusters.items()):
        member_set = set(members)
        family_counts = Counter(
            item["reported_malware"] for item in samples if item["sha256"] in member_set
        )
        cluster_rows.append({
            "cluster_key": key,
            "member_count": len(members),
            "members": sorted(members),
            "reported_malware": dict(sorted(family_counts.items())),
            "assessment": (
                "同一の構造指標は類似性の手掛かりだが、同一ファミリまたは同一キャンペーンを単独では確定しない。"
                if not key.startswith("format:")
                else "形式・アーキテクチャだけの集合であり、コード類似性の根拠には使用しない。"
            ),
        })

    summary = {
        "schema_version": 2,
        "source_date": source_date,
        "sample_count": len(samples),
        "counts": {
            "formats": dict(sorted(format_counts.items())),
            "pe": format_counts["pe"],
            "elf": format_counts["elf"],
            "macho": format_counts["macho"],
            "script": format_counts["script"],
            "function_analysis_complete": sum(bool(item["function_bodies_reviewed"]) for item in samples),
            "script_structure_recorded": sum(item["static_logic_status"] == "automated_script_structure" for item in samples),
            "function_analysis_required": sum(item["static_logic_status"] == "function_analysis_required" and not item["function_bodies_reviewed"] for item in samples),
        },
        "samples": samples,
        "clusters": cluster_rows,
        "safety": {
            "sample_executed": False,
            "network_contacted_by_sample": False,
            "raw_sample_published": False,
            "raw_decompilation_published": False,
        },
    }
    if input_commitment is not None:
        summary["input_commitment"] = dict(input_commitment)
    return summary


def build_summary_from_documents(
    case_documents: Iterable[Mapping[str, Any]],
    ioc_rows: Iterable[Mapping[str, Any]],
    source_date: str,
    *,
    provider_document: Mapping[str, Any] | None,
    input_commitment: Mapping[str, Any],
    function_review_document: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """検証済みin-memory文書だけから決定的な公開要約を作る。"""

    if provider_document is not None and provider_document.get("source_date") != source_date:
        raise ValueError("provider文書と日次要約のsource dateが一致しません")
    if input_commitment.get("source_date") != source_date:
        raise ValueError("日次要約input commitmentのsource dateが一致しません")
    labels = _labels_from_rows(ioc_rows)
    reviews = _function_reviews_document(
        function_review_document,
        expected_source_date=source_date,
    )
    return _build_summary_materialized(
        case_documents,
        labels=labels,
        aliases=_provider_aliases_document(provider_document, labels),
        reviews=reviews,
        source_date=source_date,
        input_commitment=input_commitment,
    )


def _bounded_case_entries(case_root: Path) -> list[os.DirEntry[str]]:
    """case rootを先に固定し、上限+1件目で列挙を打ち切る。"""

    absolute = Path(os.path.abspath(os.fspath(case_root)))
    try:
        analysis_contract.ensure_no_reparse_components(absolute)
        before = absolute.lstat()
        if (
            not stat.S_ISDIR(before.st_mode)
            or analysis_contract._stat_has_reparse_attribute(before)
        ):
            raise ValueError("case root type invalid")
        entries: list[os.DirEntry[str]] = []
        with os.scandir(absolute) as iterator:
            for entry in iterator:
                if len(entries) >= MAX_SUMMARY_CASES:
                    raise OverflowError
                entries.append(entry)
        after = absolute.lstat()
    except OverflowError as error:
        raise ValueError("日次要約case件数が上限を超えています") from error
    except (OSError, ValueError) as error:
        raise ValueError("日次要約case rootを安全に列挙できません") from error
    if (
        not stat.S_ISDIR(after.st_mode)
        or analysis_contract._stat_has_reparse_attribute(after)
        or not analysis_contract._same_file_identity(before, after)
        or before.st_mtime_ns != after.st_mtime_ns
        or before.st_ctime_ns != after.st_ctime_ns
    ):
        raise ValueError("日次要約case rootを安全に列挙できません")
    return sorted(entries, key=lambda entry: entry.name.casefold())


def build_summary(
    case_root: Path,
    ioc_csv: Path,
    source_date: str,
    provider_lookups: Path | None = None,
    function_reviews: Path | None = None,
) -> dict[str, Any]:
    """既存CLI互換のpath入力をmaterializeし、pure builderへ渡す。"""

    documents: list[dict[str, Any]] = []
    entries = _bounded_case_entries(case_root)
    for entry in entries:
        if not entry.is_dir(follow_symlinks=False):
            continue
        case = Path(entry.path)
        triage_path = case / "generic-triage.json"
        logic_path = case / "static-logic.json"
        if not os.path.lexists(triage_path) or not os.path.lexists(logic_path):
            continue
        documents.append(
            {
                "sha256": case.name.lower(),
                "generic_triage": analysis_contract.load_json_object_strict(triage_path),
                "static_logic": analysis_contract.load_json_object_strict(logic_path),
            }
        )
    labels = _read_labels(ioc_csv)
    return _build_summary_materialized(
        documents,
        labels=labels,
        aliases=_provider_aliases(provider_lookups, labels),
        reviews=_function_reviews(function_reviews, source_date),
        source_date=source_date,
    )


def _markdown_cell(value: Any) -> str:
    return str(value).replace("\r", " ").replace("\n", " ").replace("|", "\\|")


def render_markdown(summary: dict[str, Any]) -> str:
    counts = summary["counts"]
    verified_dual_use_components = sum(
        item["maliciousness"]["status"]
        == "not_established_for_verified_dual_use_component"
        for item in summary["samples"]
    )
    maliciousness_unresolved = sum(
        item["maliciousness"]["status"] == "unresolved"
        for item in summary["samples"]
    )
    format_text = "、".join(f"{name}: {count}件" for name, count in counts["formats"].items()) or "なし"
    lines = [
        f"# 取得検体の静的解析 — {summary['source_date']}", "",
        "## 解析範囲", "",
        f"- 取得・一次解析: {summary['sample_count']}件",
        f"- 形式別: {format_text}",
        f"- 関数本体レビュー済み: {counts['function_analysis_complete']}件",
        f"- 関数解析が必要: {counts['function_analysis_required']}件", "",
        f"- 検証済み署名dual-useコンポーネント: {verified_dual_use_components}件",
        f"- 直接の悪性判定を保留: {maliciousness_unresolved}件", "",
        (
            "検体は実行せず、汎用トリアージ、既存ファミリ抽出器、Ghidra等の静的解析結果を要約した。"
            "関数本体レビューが未完了の検体では、importや文字列だけから挙動成立を断定しない。"
        ), "",
        "## 検体一覧", "",
        "| SHA-256 | OSINTラベル | 形式 | アーキテクチャ | サイズ | entropy | 静的ロジック状態 |",
        "|---|---|---|---|---:|---:|---|",
    ]
    for item in summary["samples"]:
        arch = item["architecture"]
        arch_text = "/".join(str(value) for value in (arch.get("machine"), arch.get("bits"), arch.get("byte_order")) if value is not None) or "-"
        lines.append(
            f"| `{item['sha256']}` | {item['reported_malware']} | `{item['file_type']}` | "
            f"`{arch_text}` | {item['size']} | {item['entropy']} | `{item['static_logic_status']}` |"
        )
    lines.extend([
        "", "## ソフトウェア識別・役割・悪用文脈・悪性の分離", "",
        (
            "OSINT上のキャンペーンラベル、署名済みソフトウェアの同一性、コンポーネントの役割、"
            "検体自体の悪性は別々に評価する。署名済み正規コンポーネントが攻撃で配置された文脈だけを根拠に、"
            "そのコンポーネントを未知マルウェア本体または独立C2とは扱わない。"
        ), "",
        "| SHA-256 | ソフトウェア識別 | コンポーネント役割 | キャンペーン悪用文脈 | 悪性判定 |",
        "|---|---|---|---|---|",
    ])
    for item in summary["samples"]:
        identity = item["software_identity"]
        role = item["component_role"]
        context = item["campaign_abuse_context"]
        maliciousness = item["maliciousness"]
        if identity["status"] == "verified_vendor_component":
            identity_text = (
                f"{identity['vendor']} / {identity['product']} {identity['version']} / "
                f"{identity['original_filename']}（Authenticode静的検証済み）"
            )
        else:
            identity_text = "未確定（検証済みreview supplementの条件不足）"
        role_text = role["summary_ja"]
        if context["status"] == "reported_campaign_context":
            context_text = f"報告あり: {context.get('reported_label') or 'ラベルなし'}（配置文脈）"
        else:
            context_text = "対応するIOC文脈なし"
        maliciousness_text = maliciousness["assessment_ja"]
        lines.append(
            f"| `{item['sha256']}` | {_markdown_cell(identity_text)} | "
            f"{_markdown_cell(role_text)} | {_markdown_cell(context_text)} | "
            f"{_markdown_cell(maliciousness_text)} |"
        )
    lines.extend(["", "## 構造クラスタ", "", "| キー | 件数 | OSINTラベル内訳 | 評価 |", "|---|---:|---|---|"])
    for cluster in summary["clusters"]:
        labels = "、".join(f"{name}: {count}" for name, count in cluster["reported_malware"].items())
        lines.append(f"| `{cluster['cluster_key']}` | {cluster['member_count']} | {labels} | {cluster['assessment']} |")
    reviewed_samples = [item for item in summary["samples"] if item.get("reviewed_functions")]
    if reviewed_samples:
        lines.extend(["", "## 特徴関数レビュー", ""])
        for item in reviewed_samples:
            source = str(item.get("function_review_source") or "不明").replace("|", "\\|")
            lines.extend([
                f"### `{item['sha256']}`",
                "",
                f"- 解析元: `{source}`",
                f"- レビュー関数: {len(item['reviewed_functions'])}件",
                "",
                "| アドレス | 関数 | 役割 | 静的根拠 |",
                "|---|---|---|---|",
            ])
            for function in item["reviewed_functions"]:
                address = str(function.get("address") or "-").replace("|", "\\|")
                name = str(function.get("name") or "-").replace("|", "\\|")
                role = str(function.get("role") or "-").replace("|", "\\|")
                evidence = str(function.get("evidence") or "-").replace("|", "\\|")
                lines.append(f"| `{address}` | `{name}` | {role} | {evidence} |")
    lines.extend([
        "", "## 制約", "",
        "- 関数本体レビュー未完了のバイナリは、追加の逆コンパイルとコールグラフ整理が必要。",
        "- プロバイダのファミリ名は帰属の補助情報であり、独自に復元した設定・通信・コード類似性と分けて扱う。",
        "- Authenticodeの静的検証成功は署名対象の完全性を示すが、配置の正当性やオンライン失効確認を自動的には保証しない。",
        "- 検体の通信は発生させていない。公開結果には検体本体と逆コンパイル全文を含めない。", "",
    ])
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="日次取得検体の静的解析を公開用に要約する")
    parser.add_argument("--cases", type=Path, required=True)
    parser.add_argument("--ioc-csv", type=Path, required=True)
    parser.add_argument("--source-date", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--provider-lookups", type=Path)
    parser.add_argument("--function-reviews", type=Path)
    arguments = parser.parse_args()
    summary = build_summary(
        arguments.cases.resolve(),
        arguments.ioc_csv.resolve(),
        arguments.source_date,
        arguments.provider_lookups.resolve() if arguments.provider_lookups else None,
        arguments.function_reviews.resolve() if arguments.function_reviews else None,
    )
    output = arguments.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    (output / "sample-static-summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (output / "STATIC-ANALYSIS.md").write_text(render_markdown(summary), encoding="utf-8")
    print(json.dumps(summary["counts"], ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
