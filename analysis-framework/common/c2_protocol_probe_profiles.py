#!/usr/bin/env python3
"""完全一致のレビュー済みC2 protocol probe profileを検証・適用する。"""

from __future__ import annotations

import base64
import binascii
import hashlib
import importlib.util
import ipaddress
import json
import re
import sys
from copy import deepcopy
from functools import lru_cache
from pathlib import Path
from typing import Any

from darkcomet_profile_evidence import (
    DarkCometEvidenceError,
    validate_darkcomet_profile_evidence,
)
from remus_profile_evidence import (
    REVIEW_REGISTRY_SOURCE,
    RemusEvidenceError,
    _read_bounded_json,
    canonical_lf_json_sha256,
    load_remus_review_registry,
    validate_remus_profile_evidence,
)

DEFAULT_PROFILE_PATH = Path(__file__).with_name("c2_protocol_probe_profiles.json")
MAXIMUM_PROFILE_REGISTRY_BYTES = 256 * 1024
PROFILE_REGISTRY_SOURCE = "analysis-framework/common/c2_protocol_probe_profiles.json"
REDLINE_ACTIVE_PROFILE_REGISTRY_SOURCE = (
    "analysis-framework/malware/redlinestealer/active_profiles.json"
)
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
SHA1_RE = re.compile(r"^[0-9a-f]{40}$")
XLOADER_SYNTHETIC_TEMPLATE_ID = "xloader-v8-pkt2-synthetic-v1"
PROFILE_METHODS = {
    "valleyrat_winos_reviewed": ("winos", "winos_heartbeat"),
    "c2_detector_vvas": ("vvas", "vvas_checkin"),
    "c2_detector_n520_server_first": ("n520", "n520_server_first"),
    "agenttesla_ftp_authenticated": ("ftp", "ftp_authenticated"),
    "asyncrat_tls_messagepack": ("asyncrat", "asyncrat_tls_messagepack"),
    "venomrat_tls_messagepack": ("venomrat", "venomrat_tls_messagepack"),
    "stealc_v2_registration_task": ("stealc", "stealc_v2_registration_task"),
    "lumma_v6_registration_task": ("lummastealer", "lumma_v6_registration_task"),
    "remus_registration_task": ("remusstealer", "remus_registration_task"),
    "darkcomet_server_first_idtype": ("darkcomet", "darkcomet_server_first_idtype"),
    "redline_checkconnect_soap11": ("redlinestealer", "redline_checkconnect_soap11"),
    "xloader_v8_get_registration": (
        "xloader_http_get_pkt2",
        "xloader_v8_get_registration",
    ),
}


class ProtocolProfileError(ValueError):
    """profileが安全制約または完全一致条件を満たさない場合のエラー。"""


def _repository_root() -> Path:
    return Path(__file__).resolve().parents[2]


@lru_cache(maxsize=1)
def _load_redline_active_probe_module():
    """RedLine固有probeを名前衝突なしで読み込む。"""

    module_path = (
        _repository_root()
        / "analysis-framework"
        / "malware"
        / "redlinestealer"
        / "active_probe.py"
    )
    module_name = "_common_redline_active_probe"
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    if spec is None or spec.loader is None:
        raise ProtocolProfileError("RedLine active probe moduleを読み込めません")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    try:
        spec.loader.exec_module(module)
    except (ImportError, OSError, ValueError) as exc:
        raise ProtocolProfileError(
            f"RedLine active probe moduleを検証できません: {exc}"
        ) from exc
    return module


def redline_active_profile_registry_metadata(
    *,
    repository_root: Path | None = None,
) -> dict[str, str]:
    """RedLine固有review registryのsourceとraw bytes SHA-256を返す。"""

    root = (repository_root or _repository_root()).resolve()
    relative = Path(*REDLINE_ACTIVE_PROFILE_REGISTRY_SOURCE.split("/"))
    try:
        _payload, raw, _ = _read_bounded_json(
            root,
            relative,
            maximum_bytes=MAXIMUM_PROFILE_REGISTRY_BYTES,
            label="RedLine active profile registry",
        )
    except RemusEvidenceError as exc:
        raise ProtocolProfileError(
            f"RedLine active profile registryを読めません: {exc}"
        ) from exc
    return {
        "source": REDLINE_ACTIVE_PROFILE_REGISTRY_SOURCE,
        "sha256": hashlib.sha256(raw).hexdigest(),
    }


def validate_redline_profile_binding(
    profile: dict[str, Any],
    *,
    repository_root: Path | None = None,
) -> dict[str, Any]:
    """共通profileをRedLine固有profile、config、MVID、CILへ完全一致で固定する。"""

    root = (repository_root or _repository_root()).resolve()
    registry = redline_active_profile_registry_metadata(repository_root=root)
    if (
        profile.get("family_profile_registry_source") != registry["source"]
        or profile.get("family_profile_registry_sha256") != registry["sha256"]
    ):
        raise ProtocolProfileError("RedLine family profile registry pinが一致しません")
    module = _load_redline_active_probe_module()
    registry_path = root.joinpath(*registry["source"].split("/"))
    try:
        family_profiles = module.load_profiles(
            registry_path,
            expected_registry_sha256=registry["sha256"],
        )
        family_profile = family_profiles[profile["profile_id"]]
        binding = module.bind_profile_evidence(family_profile)
    except (KeyError, OSError, ValueError, json.JSONDecodeError) as exc:
        raise ProtocolProfileError(
            f"RedLine固有profile/config証拠を検証できません: {exc}"
        ) from exc
    exact_fields = (
        "status",
        "family",
        "protocol",
        "role",
        "variant",
        "handler",
        "method",
        "sample_sha256s",
        "config_review_id",
        "config_source",
        "config_artifact_review_sha256",
        "endpoint_json_pointer",
        "endpoint",
        "host",
        "port",
        "pinned_ips",
        "terminal_mvid",
        "terminal_cil_semantic_sha256",
        "http_method",
        "http_path",
        "content_type",
        "soap_version",
        "soap_action",
        "request_sha256",
        "request_budget",
        "maximum_request_bytes",
        "maximum_response_bytes",
        "timeout_seconds",
        "redirect_followed",
        "task_poll_allowed",
        "task_execution_allowed",
        "payload_download_allowed",
    )
    if any(profile.get(field) != family_profile.get(field) for field in exact_fields):
        raise ProtocolProfileError(
            "共通RedLine profileがfamily固有profileと一致しません"
        )
    binding_fields = (
        ("review_id", "config_review_id"),
        ("config_source", "config_source"),
        ("config_artifact_review_sha256", "config_artifact_review_sha256"),
        ("endpoint", "endpoint"),
        ("terminal_mvid", "terminal_mvid"),
        ("terminal_cil_semantic_sha256", "terminal_cil_semantic_sha256"),
    )
    if any(binding.get(left) != profile.get(right) for left, right in binding_fields):
        raise ProtocolProfileError(
            "RedLine config/MVID/CIL bindingが共通profileと一致しません"
        )
    return {
        "registry": registry,
        "binding": binding,
    }


def canonical_profile_object_sha256(profile: dict[str, Any]) -> str:
    """単一profile objectをXLoader family APIと同じ形式でhash化する。"""

    encoded = json.dumps(
        profile,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def validate_xloader_profile_evidence(
    profile: dict[str, Any],
    *,
    repository_root: Path | None = None,
    expected_sha256: str | None = None,
) -> dict[str, str]:
    """将来のXLoader実profileをreview証拠artifactへ固定する。"""

    root = (repository_root or _repository_root()).resolve()
    source = str(profile.get("review_evidence_source") or "")
    path_text = source.split(":", 1)[0]
    if (
        not path_text
        or "\\" in path_text
        or Path(path_text).is_absolute()
        or any(part in {"", ".", ".."} for part in path_text.split("/"))
    ):
        raise ProtocolProfileError("XLoader review evidence sourceが不正です")
    try:
        _payload, raw, _ = _read_bounded_json(
            root,
            Path(*path_text.split("/")),
            maximum_bytes=MAXIMUM_PROFILE_REGISTRY_BYTES,
            label="XLoader review evidence",
        )
    except RemusEvidenceError as exc:
        raise ProtocolProfileError(
            f"XLoader review evidence artifactを安全に読めません: {exc}"
        ) from exc
    digest = hashlib.sha256(raw).hexdigest()
    pinned = str(profile.get("review_evidence_sha256") or "")
    if digest != pinned or (expected_sha256 is not None and digest != expected_sha256):
        raise ProtocolProfileError(
            "XLoader review evidence SHA-256 pinが一致しません"
        )
    return {"source": source, "sha256": digest}


def _read_profile_registry(
    path: Path | None = None,
) -> tuple[dict[str, Any], str]:
    source = Path(path or DEFAULT_PROFILE_PATH).absolute()
    try:
        payload, raw, _ = _read_bounded_json(
            source.parent,
            Path(source.name),
            maximum_bytes=MAXIMUM_PROFILE_REGISTRY_BYTES,
            label="C2 protocol profile registry",
        )
    except RemusEvidenceError as exc:
        raise ProtocolProfileError(f"C2 protocol profile registry read failed: {exc}") from exc
    return payload, canonical_lf_json_sha256(raw, label="C2 protocol profile registry")


def profile_registry_metadata(path: Path | None = None) -> dict[str, str]:
    _, digest = _read_profile_registry(path)
    return {
        "source": PROFILE_REGISTRY_SOURCE,
        "sha256": digest,
    }


def remus_review_registry_metadata(
    *,
    repository_root: Path | None = None,
) -> dict[str, str]:
    try:
        value = load_remus_review_registry(repository_root=repository_root)
    except RemusEvidenceError as exc:
        raise ProtocolProfileError(f"Remus review registry read failed: {exc}") from exc
    return {
        "source": REVIEW_REGISTRY_SOURCE,
        "sha256": value["sha256"],
    }


def _is_canonical_global_ip(value: Any) -> bool:
    if type(value) is not str:
        return False
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return address.is_global and str(address) == value


def _is_canonical_global_host(value: Any) -> bool:
    if type(value) is not str or value != value.casefold() or value.endswith("."):
        return False
    if _is_canonical_global_ip(value):
        return True
    return (
        re.fullmatch(
            r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
            r"[a-z]{2,63}",
            value,
        )
        is not None
    )


def load_profiles(
    path: Path | None = None,
    *,
    expected_sha256: str | None = None,
) -> dict[str, dict[str, Any]]:
    """profile registryをfail-closedで読み込む。"""
    payload, digest = _read_profile_registry(path)
    if expected_sha256 is not None and digest != expected_sha256:
        raise ProtocolProfileError("C2 protocol profile registry SHA-256 pin mismatch")
    if not isinstance(payload, dict) or payload.get("schema_version") != 1:
        raise ProtocolProfileError("C2 protocol profileにはschema_version=1が必要です")
    values = payload.get("profiles")
    if not isinstance(values, list):
        raise ProtocolProfileError("C2 protocol profileのprofilesはlistである必要があります")
    profiles: dict[str, dict[str, Any]] = {}
    endpoints: set[tuple[str, int]] = set()
    for raw in values:
        if not isinstance(raw, dict):
            raise ProtocolProfileError("各C2 protocol profileはobjectである必要があります")
        profile = deepcopy(raw)
        profile_id = str(profile.get("profile_id") or "")
        host = str(profile.get("host") or "").casefold().rstrip(".")
        port = profile.get("port")
        handler = str(profile.get("handler") or "")
        expected = PROFILE_METHODS.get(handler)
        if not profile_id or profile_id in profiles:
            raise ProtocolProfileError(f"profile_idが空または重複しています: {profile_id}")
        if not host or not isinstance(port, int) or not 1 <= port <= 65535:
            raise ProtocolProfileError(f"profile endpointが不正です: {profile_id}")
        if (host, port) in endpoints:
            raise ProtocolProfileError(f"profile endpointが重複しています: {host}:{port}")
        samples = profile.get("sample_sha256s")
        if (
            not isinstance(samples, list)
            or not samples
            or any(type(value) is not str or not SHA256_RE.fullmatch(value) for value in samples)
            or len(set(samples)) != len(samples)
        ):
            raise ProtocolProfileError(f"sample_sha256sが不正です: {profile_id}")
        profile["sample_sha256s"] = sorted(samples)
        if expected != (profile.get("protocol"), profile.get("method")):
            raise ProtocolProfileError(f"handlerとprotocol/methodが一致しません: {profile_id}")
        timeout = float(profile.get("timeout_seconds", 3.0))
        maximum = int(profile.get("maximum_response_bytes", 64))
        registration_handlers = {
            "stealc_v2_registration_task",
            "lumma_v6_registration_task",
            "remus_registration_task",
        }
        maximum_limit = {
            "redline_checkconnect_soap11": 4096,
            "xloader_v8_get_registration": 8192,
        }.get(handler, 65536 if handler in registration_handlers else 1024)
        if not 0.1 <= timeout <= 5.0 or not 1 <= maximum <= maximum_limit:
            raise ProtocolProfileError(f"active probeの上限が不正です: {profile_id}")
        if handler == "valleyrat_winos_reviewed":
            pinned = profile.get("pinned_ips")
            if not isinstance(pinned, list) or len(pinned) != 1 or maximum != 64:
                raise ProtocolProfileError("Winos profileには単一pinned IPが必要です")
        elif handler == "c2_detector_vvas":
            if profile.get("send_hex") != "333200" or maximum != 64:
                raise ProtocolProfileError("vvaS check-inはレビュー済み333200だけを許可します")
            if profile.get("expected_stage_size") != 307214 or profile.get("expected_header_size") != 14:
                raise ProtocolProfileError("vvaS応答境界がレビュー済み値と一致しません")
        elif handler == "c2_detector_n520_server_first":
            if profile.get("sni") != "update.microsoft.com" or maximum != 44:
                raise ProtocolProfileError("N520 server-first profileのSNIまたは応答上限が不正です")
            if any(key in profile for key in ("send_hex", "checkin", "artifact_zip")):
                raise ProtocolProfileError("N520 profileではcheck-in送信を許可しません")
        elif handler == "agenttesla_ftp_authenticated":
            reference = str(profile.get("credential_reference") or "")
            if not reference.startswith("agenttesla:") or maximum != 1024:
                raise ProtocolProfileError("AgentTesla FTP profileの資格情報参照または応答上限が不正です")
        elif handler in {"asyncrat_tls_messagepack", "venomrat_tls_messagepack"}:
            expected_key = "Packet" if handler.startswith("asyncrat") else "Pac_ket"
            expected_reply = "pong" if handler.startswith("asyncrat") else "Po_ng"
            certificate = str(profile.get("expected_certificate_sha256") or "")
            if (
                profile.get("packet_key") != expected_key
                or profile.get("request_packet") != "Ping"
                or profile.get("expected_response_packets") != [expected_reply]
                or len(certificate) != 64
                or any(value not in "0123456789abcdef" for value in certificate.casefold())
                or int(profile.get("maximum_request_bytes", 0)) > 96
                or maximum != 64
            ):
                raise ProtocolProfileError("TLS MessagePack profileのreview済み境界が不正です")
        elif handler == "darkcomet_server_first_idtype":
            key = str(profile.get("network_rc4_key_base64") or "")
            try:
                decoded_key = base64.b64decode(key, validate=True)
            except (binascii.Error, ValueError):
                decoded_key = b""
            if (
                maximum != 12
                or not 1 <= len(decoded_key) <= 256
                or profile.get("expected_plaintext") != "IDTYPE"
                or profile.get("primary_wire_encoding") != "ascii_hex"
                or profile.get("wire_encodings") != ["raw", "ascii_hex"]
                or profile.get("key_derivation_status") != "static_verified"
                or not str(profile.get("key_derivation_evidence") or "").strip()
                or profile.get("password_concatenated") is not False
                or profile.get("config_resource_key_reused") is not False
                or any(field in profile for field in ("send_hex", "payload", "checkin", "request_packet"))
            ):
                raise ProtocolProfileError("DarkComet server-first profileのreview済み受信専用境界が不正です")
        elif handler == "redline_checkconnect_soap11":
            if (
                maximum != 4096
                or profile.get("request_budget") != 1
                or profile.get("maximum_request_bytes") != 357
                or profile.get("timeout_seconds") != 3.0
                or profile.get("status") != "approved"
                or profile.get("variant") != "wcf_soap11"
                or profile.get("http_method") != "POST"
                or profile.get("http_path") != "/"
                or profile.get("content_type") != "text/xml; charset=utf-8"
                or profile.get("soap_version") != "1.1"
                or profile.get("soap_action")
                != "http://tempuri.org/Endpoint/CheckConnect"
                or profile.get("redirect_followed") is not False
                or profile.get("task_poll_allowed") is not False
                or profile.get("task_execution_allowed") is not False
                or profile.get("payload_download_allowed") is not False
            ):
                raise ProtocolProfileError(
                    "RedLine CheckConnect profileのreview済み安全境界が不正です"
                )
            validate_redline_profile_binding(profile)
        elif handler == "xloader_v8_get_registration":
            pinned = profile.get("pinned_ips")
            digests = (
                "sample_sha256",
                "fully_recovered_image_sha256",
                "private_material_sha256",
                "selector_path_table_sha256",
                "review_evidence_sha256",
                "pkt2_inner_plaintext_sha256",
                "request_sha256",
            )
            if (
                profile.get("reviewed") is not True
                or profile.get("candidate_classification") != "reviewed_real_c2"
                or profile.get("response_contract_evidence")
                not in {
                    "current_sample_static",
                    "cross_version_v8_7_primary_research",
                }
                or any(
                    type(profile.get(field)) is not str
                    or not SHA256_RE.fullmatch(str(profile.get(field)))
                    for field in digests
                )
                or profile.get("sample_sha256s") != [profile.get("sample_sha256")]
                or profile.get("synthetic_template_id")
                != XLOADER_SYNTHETIC_TEMPLATE_ID
                or not isinstance(profile.get("review_id"), str)
                or not profile.get("review_id")
                or not isinstance(profile.get("private_material_reference"), str)
                or re.fullmatch(
                    r"xloader-private:[a-z0-9][a-z0-9._:-]{1,127}",
                    str(profile.get("private_material_reference")),
                )
                is None
                or not isinstance(profile.get("review_evidence_source"), str)
                or not profile.get("review_evidence_source")
                or str(profile.get("source") or "").split(":", 1)[0]
                != str(profile.get("review_evidence_source")).split(":", 1)[0]
                or not isinstance(pinned, list)
                or len(pinned) != 1
                or not _is_canonical_global_ip(pinned[0])
                or not _is_canonical_global_host(profile.get("host"))
                or profile.get("scheme") != "http"
                or profile.get("transport") != "raw_socket"
                or profile.get("http_method") != "GET"
                or re.fullmatch(r"/[A-Za-z0-9]{4}/", str(profile.get("http_path")))
                is None
                or type(profile.get("request_budget")) is not int
                or profile.get("request_budget") != 1
                or type(profile.get("maximum_request_count")) is not int
                or profile.get("maximum_request_count") != 1
                or type(profile.get("maximum_request_bytes")) is not int
                or profile.get("maximum_request_bytes") != 4096
                or type(profile.get("maximum_response_bytes")) is not int
                or maximum != 8192
                or type(profile.get("timeout_seconds")) is not float
                or profile.get("timeout_seconds") != 3.0
                or profile.get("redirect_followed") is not False
                or profile.get("task_execution_allowed") is not False
                or profile.get("payload_download_allowed") is not False
                or type(profile.get("candidate_index")) is not int
                or not 0 <= profile.get("candidate_index") <= 15
                or type(profile.get("selector")) is not int
                or not 1 <= profile.get("selector") <= 64
                or type(profile.get("record_sha1")) is not str
                or not SHA1_RE.fullmatch(profile.get("record_sha1"))
                or profile.get("data_parameter_position") not in {"first", "last"}
                or type(profile.get("data_parameter_name")) is not str
                or re.fullmatch(
                    r"[A-Za-z0-9]{2,16}",
                    profile.get("data_parameter_name"),
                )
                is None
                or type(profile.get("junk_parameter_name")) is not str
                or re.fullmatch(
                    r"[A-Za-z0-9]{2,16}",
                    profile.get("junk_parameter_name"),
                )
                is None
                or profile.get("data_parameter_name")
                == profile.get("junk_parameter_name")
                or type(profile.get("junk_value")) is not str
                or re.fullmatch(
                    r"[A-Za-z0-9]{1,64}",
                    profile.get("junk_value"),
                )
                is None
                or not isinstance(profile.get("user_agent"), str)
                or not profile.get("user_agent")
                or len(profile.get("user_agent")) > 256
                or "\r" in profile.get("user_agent")
                or "\n" in profile.get("user_agent")
            ):
                raise ProtocolProfileError(
                    "XLoader v8登録profileのreview済み安全境界または証拠pinが不正です"
                )
        elif handler in registration_handlers:
            pinned = profile.get("pinned_ips")
            if (
                not isinstance(pinned, list)
                or len(pinned) != 1
                or profile.get("http_path") != "/"
                or profile.get("request_budget") != 2
                or not 64 <= int(profile.get("maximum_request_bytes", 0)) <= 4096
                or not _is_canonical_global_ip(pinned[0])
            ):
                raise ProtocolProfileError("stealer登録profileの共通安全境界が不正です")
            if handler == "stealc_v2_registration_task":
                key = str(profile.get("network_rc4_key_base64") or "")
                build = str(profile.get("build") or "")
                try:
                    decoded_key = base64.b64decode(key, validate=True)
                except (binascii.Error, ValueError):
                    decoded_key = b""
                if (
                    maximum != 16384
                    or not 1 <= len(build) <= 64
                    or not 8 <= len(decoded_key) <= 64
                    or profile.get("http_host") != profile.get("host")
                ):
                    raise ProtocolProfileError("StealC v2登録profileがreview済み境界と一致しません")
            elif handler == "lumma_v6_registration_task":
                uid = str(profile.get("uid") or "")
                cid = profile.get("cid")
                if (
                    maximum != 65536
                    or not 32 <= len(uid) <= 64
                    or any(value not in "0123456789abcdef" for value in uid.casefold())
                    or not isinstance(cid, str)
                    or profile.get("http_host") != profile.get("host")
                ):
                    raise ProtocolProfileError("Lumma v6登録profileがreview済み境界と一致しません")
            elif (
                maximum != 8192
                or len(str(profile.get("tag") or "")) != 32
                or type(profile.get("exp")) is not int
                or not 946_684_800 <= profile.get("exp") <= 4_102_444_800
                or type(profile.get("request_budget")) is not int
                or profile.get("request_budget") != 2
                or type(profile.get("timeout_seconds")) is not float
                or profile.get("timeout_seconds") != 3.0
                or type(profile.get("maximum_request_bytes")) is not int
                or profile.get("maximum_request_bytes") != 4096
                or type(profile.get("maximum_response_bytes")) is not int
                or profile.get("maximum_response_bytes") != 8192
                or profile.get("http_host") != "microsoft.com"
            ):
                raise ProtocolProfileError("Remus登録profileがreview済み境界と一致しません")
        profile["host"] = host
        profiles[profile_id] = profile
        endpoints.add((host, port))
    return profiles


def resolve_profile(
    profile_id: str,
    host: str,
    port: int,
    *,
    expected_registry_sha256: str | None = None,
) -> dict[str, Any]:
    """IDと完全一致endpointの両方が一致したprofileだけを返す。"""
    profiles = load_profiles(expected_sha256=expected_registry_sha256)
    profile = profiles.get(profile_id)
    normalized_host = host.casefold().rstrip(".")
    if profile is None:
        raise ProtocolProfileError(f"未レビューのprotocol_profile_idです: {profile_id}")
    if profile["host"] != normalized_host or profile["port"] != port:
        raise ProtocolProfileError(f"protocol profileとendpointが一致しません: {profile_id} / {normalized_host}:{port}")
    return deepcopy(profile)


def apply_profiles(
    targets: list[dict[str, Any]],
    *,
    repository_root: Path | None = None,
    rejections: list[dict[str, str]] | None = None,
    expected_profile_registry_sha256: str | None = None,
    expected_remus_review_registry_sha256: str | None = None,
) -> tuple[list[dict[str, Any]], int]:
    """IOC対象へprofileをoverlayし、DarkCometは証拠内容とSHA-256も固定する。"""
    profiles = load_profiles(expected_sha256=expected_profile_registry_sha256)
    rejection_sink = rejections if rejections is not None else []
    available: dict[str, dict[str, Any]] = {}
    for profile_id, profile in profiles.items():
        if profile.get("handler") == "darkcomet_server_first_idtype":
            try:
                evidence = validate_darkcomet_profile_evidence(
                    profile,
                    repository_root=repository_root,
                )
            except DarkCometEvidenceError:
                continue
            profile = deepcopy(profile)
            profile["evidence_sha256"] = evidence["sha256"]
            profile["evidence_source"] = evidence["source"]
        elif profile.get("handler") == "remus_registration_task":
            try:
                evidence = validate_remus_profile_evidence(
                    profile,
                    repository_root=repository_root,
                    expected_registry_sha256=expected_remus_review_registry_sha256,
                )
            except RemusEvidenceError as exc:
                rejection_sink.append(
                    {
                        "profile_id": profile_id,
                        "reason_code": "remus_review_evidence_unavailable",
                        "reason": str(exc),
                    }
                )
                continue
            profile = deepcopy(profile)
            profile["evidence_sha256"] = evidence["sha256"]
            profile["evidence_source"] = evidence["source"]
            profile["review_id"] = evidence["review_id"]
            profile["review_registry_source"] = evidence["review_registry_source"]
            profile["review_registry_sha256"] = evidence["review_registry_sha256"]
            profile["flow_artifact_source"] = evidence["flow_artifact_source"]
            profile["flow_artifact_sha256"] = evidence["flow_artifact_sha256"]
        elif profile.get("handler") == "redline_checkconnect_soap11":
            try:
                redline = validate_redline_profile_binding(
                    profile,
                    repository_root=repository_root,
                )
            except ProtocolProfileError as exc:
                rejection_sink.append(
                    {
                        "profile_id": profile_id,
                        "reason_code": "redline_review_binding_unavailable",
                        "reason": str(exc),
                    }
                )
                continue
            profile = deepcopy(profile)
            profile["redline_registry_source"] = redline["registry"]["source"]
            profile["redline_registry_sha256"] = redline["registry"]["sha256"]
        elif profile.get("handler") == "xloader_v8_get_registration":
            try:
                evidence = validate_xloader_profile_evidence(
                    profile,
                    repository_root=repository_root,
                )
            except ProtocolProfileError as exc:
                rejection_sink.append(
                    {
                        "profile_id": profile_id,
                        "reason_code": "xloader_review_evidence_unavailable",
                        "reason": str(exc),
                    }
                )
                continue
            profile_object_sha256 = canonical_profile_object_sha256(profile)
            profile = deepcopy(profile)
            profile["evidence_source"] = evidence["source"]
            profile["evidence_sha256"] = evidence["sha256"]
            profile["profile_object_sha256"] = profile_object_sha256
        elif repository_root is not None and not (repository_root / str(profile["source"]).split(":", 1)[0]).is_file():
            continue
        available[profile_id] = profile
    profiles = available
    by_endpoint = {
        (str(target.get("host") or "").casefold().rstrip("."), int(target.get("port") or 0)): target
        for target in targets
    }
    added = 0
    for profile in profiles.values():
        key = (profile["host"], profile["port"])
        target = by_endpoint.get(key)
        profile_samples = sorted(profile.get("sample_sha256s") or [])
        if target is not None:
            target_samples = target.get("sample_sha256s")
            if not isinstance(target_samples, list) or sorted(target_samples) != profile_samples:
                target = None
        if target is None:
            target = {
                "target_id": f"reviewed-{profile['profile_id']}",
                "family": profile["family"],
                "host": profile["host"],
                "port": profile["port"],
                "transport": "direct",
                "sample_sha256s": profile_samples,
                "associated_case_count": len(profile_samples),
                "analyzed_dates": [],
                "sources": [profile["source"]],
                "roles": [profile["role"]],
                "selection_basis": "レビュー済みmalware固有C2 protocol profile",
            }
            targets.append(target)
            by_endpoint[key] = target
            added += 1
        target.update(
            {
                "protocol": profile["protocol"],
                "method": profile["method"],
                "protocol_profile_id": profile["profile_id"],
                "timeout_seconds": profile["timeout_seconds"],
                "maximum_request_bytes": profile.get("maximum_request_bytes"),
                "protocol_profile_registry_source": PROFILE_REGISTRY_SOURCE,
                "protocol_profile_registry_sha256": expected_profile_registry_sha256,
                "maximum_response_bytes": profile["maximum_response_bytes"],
            }
        )
        if profile.get("handler") == "darkcomet_server_first_idtype":
            target["protocol_profile_evidence_sha256"] = profile["evidence_sha256"]
            target["protocol_profile_evidence_source"] = profile["evidence_source"]
        if profile.get("handler") == "remus_registration_task":
            target["protocol_profile_evidence_sha256"] = profile["evidence_sha256"]
            target["protocol_profile_evidence_source"] = profile["evidence_source"]
            target["protocol_profile_review_id"] = profile["review_id"]
            target["protocol_profile_review_registry_source"] = profile["review_registry_source"]
            target["protocol_profile_review_registry_sha256"] = profile["review_registry_sha256"]
            target["protocol_profile_flow_artifact_source"] = profile["flow_artifact_source"]
            target["protocol_profile_flow_artifact_sha256"] = profile["flow_artifact_sha256"]
        if profile.get("handler") == "redline_checkconnect_soap11":
            target["http_path"] = profile["http_path"]
            target["protocol_profile_evidence_sha256"] = profile[
                "config_artifact_review_sha256"
            ]
            target["protocol_profile_evidence_source"] = profile["config_source"]
            target["protocol_profile_review_id"] = profile["config_review_id"]
            target["protocol_profile_endpoint_json_pointer"] = profile[
                "endpoint_json_pointer"
            ]
            target["protocol_profile_terminal_mvid"] = profile["terminal_mvid"]
            target["protocol_profile_terminal_cil_semantic_sha256"] = profile[
                "terminal_cil_semantic_sha256"
            ]
            target["protocol_profile_request_sha256"] = profile["request_sha256"]
            target["protocol_profile_family_registry_source"] = profile[
                "redline_registry_source"
            ]
            target["protocol_profile_family_registry_sha256"] = profile[
                "redline_registry_sha256"
            ]
        if profile.get("handler") == "xloader_v8_get_registration":
            target["http_path"] = profile["http_path"]
            target["protocol_profile_evidence_sha256"] = profile[
                "evidence_sha256"
            ]
            target["protocol_profile_evidence_source"] = profile[
                "evidence_source"
            ]
            target["protocol_profile_review_id"] = profile["review_id"]
            target["protocol_profile_payload_sha256"] = profile[
                "profile_object_sha256"
            ]
            target["protocol_profile_private_material_reference"] = profile[
                "private_material_reference"
            ]
            target["protocol_profile_private_material_sha256"] = profile[
                "private_material_sha256"
            ]
            target["protocol_profile_selector_path_table_sha256"] = profile[
                "selector_path_table_sha256"
            ]
            target["protocol_profile_synthetic_template_id"] = profile[
                "synthetic_template_id"
            ]
            target["protocol_profile_pkt2_inner_plaintext_sha256"] = profile[
                "pkt2_inner_plaintext_sha256"
            ]
            target["protocol_profile_request_sha256"] = profile[
                "request_sha256"
            ]
        target["family"] = profile["family"]
        target["sample_sha256s"] = profile_samples
        target["associated_case_count"] = len(profile_samples)
        target["sources"] = sorted(set(target.get("sources", [])) | {profile["source"]})
        target["roles"] = sorted(set(target.get("roles", [])) | {profile["role"]})
    return sorted(targets, key=lambda value: (value["host"], value["port"], value["protocol"])), added
