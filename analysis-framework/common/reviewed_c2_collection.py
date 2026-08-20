#!/usr/bin/env python3
"""複数検体のreview済みC2 profileを構築し、offline検出計画を生成する。"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from tls_messagepack_rat_host_emulator import (
    SessionLimits,
    TlsMessagePackHostError,
    decode_frame,
)

SCHEMA_VERSION = 1
BW_FAMILY = "bwrat_venomrat_protocol_lineage"
VVAS_FAMILY = "valleyrat_vvas"
SUPPORTED_FAMILIES = frozenset({BW_FAMILY, VVAS_FAMILY})
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
PROFILE_ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9-]{7,95}$")
DEFAULT_VVAS_CHECKIN_HEX = "333200"
DEFAULT_VVAS_STAGE_SIZE = 307214
DEFAULT_VVAS_HEADER_SIZE = 14
MAXIMUM_PROFILE_COUNT = 256
MAXIMUM_ENDPOINTS_PER_PROFILE = 8


class ReviewedC2CollectionError(ValueError):
    """profile packまたは観測値がreview済み境界に一致しないことを示す。"""


@dataclass(frozen=True)
class Endpoint:
    """数値IPへ固定した単一のC2候補。"""

    host: str
    port: int

    @property
    def display(self) -> str:
        return f"{self.host}:{self.port}"


@dataclass(frozen=True)
class ReviewedSampleProfile:
    """root検体とterminal payloadへ束縛した検出・模擬契約。"""

    profile_id: str
    profile_sha256: str
    source_member: str
    sample_sha256: str
    terminal_sha256: str
    family: str
    endpoints: tuple[Endpoint, ...]
    detector_method: str
    expected_certificate_sha256: str | None
    packet_key: str | None
    request_packet: str | None
    response_packet: str | None
    checkin_hex: str | None
    expected_stage_size: int | None
    expected_header_size: int | None


@dataclass(frozen=True)
class ReviewedC2Collection:
    """検体別profileの検証済みsnapshot。"""

    collection_id: str
    source_analysis_sha256: str
    source_path: str
    profiles: Mapping[str, ReviewedSampleProfile]


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for key, value in pairs:
        if key in output:
            raise ReviewedC2CollectionError(f"JSON keyが重複しています: {key}")
        output[key] = value
    return output


def _load_json(path: Path) -> Any:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise ReviewedC2CollectionError(f"JSONを読み取れません: {path}") from exc
    if b"\r" in raw.replace(b"\r\n", b""):
        raise ReviewedC2CollectionError("lone CRを含むJSONは拒否しました")
    try:
        return json.loads(
            raw.decode("utf-8-sig"),
            object_pairs_hook=_reject_duplicate_keys,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReviewedC2CollectionError(f"strict JSONではありません: {path}") from exc


def _canonical_json_sha256(value: Mapping[str, Any]) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _sha256(value: Any, label: str) -> str:
    text = str(value or "").casefold()
    if not SHA256_PATTERN.fullmatch(text):
        raise ReviewedC2CollectionError(f"{label}は64文字のSHA-256で指定してください")
    return text


def _strict_string(value: Any, label: str, *, maximum: int = 512) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise ReviewedC2CollectionError(f"{label}が不正です")
    if any(ord(character) < 0x20 for character in value):
        raise ReviewedC2CollectionError(f"{label}に制御文字があります")
    return value


def _strict_positive_int(value: Any, label: str, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= maximum:
        raise ReviewedC2CollectionError(f"{label}が範囲外です")
    return value


def _endpoint(value: Mapping[str, Any]) -> Endpoint:
    host = str(value.get("host") or "")
    try:
        address = ipaddress.ip_address(host)
    except ValueError as exc:
        raise ReviewedC2CollectionError("endpoint hostは数値IPへ固定してください") from exc
    if address.is_loopback or address.is_unspecified or address.is_multicast:
        raise ReviewedC2CollectionError("外部endpointへloopback等は登録できません")
    port = _strict_positive_int(value.get("port"), "endpoint port", 65535)
    expected = f"{address}:{port}"
    if value.get("endpoint") not in {None, expected}:
        raise ReviewedC2CollectionError("endpoint表示とhost／portが不一致です")
    return Endpoint(str(address), port)


def _profile_body(document: Mapping[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in document.items() if key != "profile_sha256"}


def _validate_profile(document: Mapping[str, Any]) -> ReviewedSampleProfile:
    if set(document) != {
        "profile_id",
        "profile_sha256",
        "source_member",
        "sample_sha256",
        "terminal_sha256",
        "family",
        "endpoints",
        "detector",
        "emulator",
        "safety",
    }:
        raise ReviewedC2CollectionError("profile key集合がreview済みschemaと不一致です")
    profile_id = str(document.get("profile_id") or "")
    if not PROFILE_ID_PATTERN.fullmatch(profile_id):
        raise ReviewedC2CollectionError("profile_idが不正です")
    expected_profile_sha = _canonical_json_sha256(_profile_body(document))
    profile_sha = _sha256(document.get("profile_sha256"), "profile_sha256")
    if profile_sha != expected_profile_sha:
        raise ReviewedC2CollectionError(f"profile_sha256が一致しません: {profile_id}")
    family = str(document.get("family") or "")
    if family not in SUPPORTED_FAMILIES:
        raise ReviewedC2CollectionError(f"未対応familyです: {family}")
    endpoint_values = document.get("endpoints")
    if not isinstance(endpoint_values, list) or len(endpoint_values) > MAXIMUM_ENDPOINTS_PER_PROFILE:
        raise ReviewedC2CollectionError("endpointsが不正です")
    endpoints = tuple(_endpoint(value) for value in endpoint_values if isinstance(value, Mapping))
    if len(endpoints) != len(endpoint_values) or len(set(endpoints)) != len(endpoints):
        raise ReviewedC2CollectionError("endpointが重複または不正です")
    detector = document.get("detector")
    emulator = document.get("emulator")
    safety = document.get("safety")
    if not all(isinstance(value, Mapping) for value in (detector, emulator, safety)):
        raise ReviewedC2CollectionError("detector／emulator／safetyがobjectではありません")
    if safety != {
        "sample_executed": False,
        "network_contacted_during_analysis": False,
        "task_transmission_allowed": False,
        "payload_or_stage_transmission_allowed": False,
        "loopback_emulation_only": True,
    }:
        raise ReviewedC2CollectionError("safety契約が不一致です")
    if family == BW_FAMILY:
        expected_detector = {
            "method": "venomrat_tls_messagepack",
            "nmap_script": "analysis-framework/nmap/scripts/dotnet-rat-c2.nse",
            "nmap_mode": "venomrat",
            "tls_version": "TLSv1.2",
            "packet_key": "Pac_ket",
            "request_packet": "Ping",
            "response_packet": "Po_ng",
            "maximum_request_bytes": 96,
            "maximum_response_bytes": 64,
        }
        for key, value in expected_detector.items():
            if detector.get(key) != value:
                raise ReviewedC2CollectionError(f"BwRAT detector契約が不一致です: {key}")
        certificate = _sha256(
            detector.get("expected_certificate_sha256"),
            "expected_certificate_sha256",
        )
        if emulator != {
            "kind": "tls_messagepack_heartbeat_loopback",
            "request_frames": 1,
            "response_frames": 1,
            "task_frames": 0,
            "certificate_private_key_available": False,
        }:
            raise ReviewedC2CollectionError("BwRAT emulator契約が不一致です")
        return ReviewedSampleProfile(
            profile_id=profile_id,
            profile_sha256=profile_sha,
            source_member=_strict_string(document.get("source_member"), "source_member"),
            sample_sha256=_sha256(document.get("sample_sha256"), "sample_sha256"),
            terminal_sha256=_sha256(document.get("terminal_sha256"), "terminal_sha256"),
            family=family,
            endpoints=endpoints,
            detector_method="venomrat_tls_messagepack",
            expected_certificate_sha256=certificate,
            packet_key="Pac_ket",
            request_packet="Ping",
            response_packet="Po_ng",
            checkin_hex=None,
            expected_stage_size=None,
            expected_header_size=None,
        )
    expected_detector = {
        "method": "vvas_checkin",
        "nmap_script": "analysis-framework/nmap/scripts/valleyrat-c2.nse",
        "nmap_mode": "vvas",
        "checkin_hex": DEFAULT_VVAS_CHECKIN_HEX,
        "expected_stage_size": DEFAULT_VVAS_STAGE_SIZE,
        "expected_header_size": DEFAULT_VVAS_HEADER_SIZE,
        "maximum_request_bytes": 3,
        "maximum_response_bytes": 64,
    }
    for key, value in expected_detector.items():
        if detector.get(key) != value:
            raise ReviewedC2CollectionError(f"vvaS detector契約が不一致です: {key}")
    if emulator != {
        "kind": "vvas_header_only_loopback",
        "request_frames": 1,
        "response_frames": 1,
        "stage_body_bytes": 0,
        "task_frames": 0,
    }:
        raise ReviewedC2CollectionError("vvaS emulator契約が不一致です")
    return ReviewedSampleProfile(
        profile_id=profile_id,
        profile_sha256=profile_sha,
        source_member=_strict_string(document.get("source_member"), "source_member"),
        sample_sha256=_sha256(document.get("sample_sha256"), "sample_sha256"),
        terminal_sha256=_sha256(document.get("terminal_sha256"), "terminal_sha256"),
        family=family,
        endpoints=endpoints,
        detector_method="vvas_checkin",
        expected_certificate_sha256=None,
        packet_key=None,
        request_packet=None,
        response_packet=None,
        checkin_hex=DEFAULT_VVAS_CHECKIN_HEX,
        expected_stage_size=DEFAULT_VVAS_STAGE_SIZE,
        expected_header_size=DEFAULT_VVAS_HEADER_SIZE,
    )


def load_collection(path: Path) -> ReviewedC2Collection:
    """検体別profile packを完全schema・profile hash付きで読み込む。"""

    document = _load_json(path)
    if not isinstance(document, Mapping) or set(document) != {
        "schema_version",
        "collection_id",
        "source_analysis_sha256",
        "source_path",
        "profiles",
    }:
        raise ReviewedC2CollectionError("collection schemaが不一致です")
    if document.get("schema_version") != SCHEMA_VERSION:
        raise ReviewedC2CollectionError("collection schema_versionが未対応です")
    values = document.get("profiles")
    if not isinstance(values, list) or not 1 <= len(values) <= MAXIMUM_PROFILE_COUNT:
        raise ReviewedC2CollectionError("profile件数が範囲外です")
    profiles: dict[str, ReviewedSampleProfile] = {}
    sample_hashes: set[str] = set()
    terminal_hashes: set[str] = set()
    for value in values:
        if not isinstance(value, Mapping):
            raise ReviewedC2CollectionError("profileはobjectで指定してください")
        profile = _validate_profile(value)
        if profile.profile_id in profiles or profile.sample_sha256 in sample_hashes:
            raise ReviewedC2CollectionError("profile IDまたはsample SHA-256が重複しています")
        profiles[profile.profile_id] = profile
        sample_hashes.add(profile.sample_sha256)
        terminal_hashes.add(profile.terminal_sha256)
    if len(terminal_hashes) != len(profiles):
        raise ReviewedC2CollectionError("terminal SHA-256が重複しています")
    return ReviewedC2Collection(
        collection_id=_strict_string(document.get("collection_id"), "collection_id", maximum=96),
        source_analysis_sha256=_sha256(
            document.get("source_analysis_sha256"),
            "source_analysis_sha256",
        ),
        source_path=_strict_string(document.get("source_path"), "source_path", maximum=1024),
        profiles=profiles,
    )


def _external_endpoints(config: Mapping[str, Any]) -> list[dict[str, Any]]:
    values = config.get("endpoints")
    if not isinstance(values, list):
        raise ReviewedC2CollectionError("analysis config.endpointsが不正です")
    output: list[dict[str, Any]] = []
    for value in values:
        if not isinstance(value, Mapping) or value.get("external") is not True:
            continue
        endpoint = _endpoint(value)
        output.append(
            {"endpoint": endpoint.display, "host": endpoint.host, "port": endpoint.port}
        )
    return output


def _build_profile(result: Mapping[str, Any], collection_id: str) -> dict[str, Any]:
    config = result.get("config")
    terminal = result.get("terminal")
    if not isinstance(config, Mapping) or not isinstance(terminal, Mapping):
        raise ReviewedC2CollectionError("analysis resultのconfig／terminalが不正です")
    family = str(config.get("family") or "")
    if family not in SUPPORTED_FAMILIES:
        raise ReviewedC2CollectionError(f"未対応analysis familyです: {family}")
    sample_sha = _sha256(result.get("root_sha256"), "root_sha256")
    terminal_sha = _sha256(terminal.get("sha256"), "terminal.sha256")
    suffix = "bwrat" if family == BW_FAMILY else "vvas"
    profile: dict[str, Any] = {
        "profile_id": f"{collection_id}-{sample_sha[:12]}-{suffix}",
        "source_member": _strict_string(result.get("source_member"), "source_member"),
        "sample_sha256": sample_sha,
        "terminal_sha256": terminal_sha,
        "family": family,
        "endpoints": _external_endpoints(config),
        "detector": {},
        "emulator": {},
        "safety": {
            "sample_executed": False,
            "network_contacted_during_analysis": False,
            "task_transmission_allowed": False,
            "payload_or_stage_transmission_allowed": False,
            "loopback_emulation_only": True,
        },
    }
    if result.get("sample_executed") is not False or result.get("network_contacted") is not False:
        raise ReviewedC2CollectionError("analysis safety flagがfalseではありません")
    if family == BW_FAMILY:
        certificate = config.get("certificate")
        if not isinstance(certificate, Mapping):
            raise ReviewedC2CollectionError("BwRAT certificate pinがありません")
        profile["detector"] = {
            "method": "venomrat_tls_messagepack",
            "nmap_script": "analysis-framework/nmap/scripts/dotnet-rat-c2.nse",
            "nmap_mode": "venomrat",
            "tls_version": "TLSv1.2",
            "packet_key": "Pac_ket",
            "request_packet": "Ping",
            "response_packet": "Po_ng",
            "expected_certificate_sha256": _sha256(certificate.get("sha256"), "certificate.sha256"),
            "maximum_request_bytes": 96,
            "maximum_response_bytes": 64,
        }
        profile["emulator"] = {
            "kind": "tls_messagepack_heartbeat_loopback",
            "request_frames": 1,
            "response_frames": 1,
            "task_frames": 0,
            "certificate_private_key_available": False,
        }
    else:
        profile["detector"] = {
            "method": "vvas_checkin",
            "nmap_script": "analysis-framework/nmap/scripts/valleyrat-c2.nse",
            "nmap_mode": "vvas",
            "checkin_hex": DEFAULT_VVAS_CHECKIN_HEX,
            "expected_stage_size": DEFAULT_VVAS_STAGE_SIZE,
            "expected_header_size": DEFAULT_VVAS_HEADER_SIZE,
            "maximum_request_bytes": 3,
            "maximum_response_bytes": 64,
        }
        profile["emulator"] = {
            "kind": "vvas_header_only_loopback",
            "request_frames": 1,
            "response_frames": 1,
            "stage_body_bytes": 0,
            "task_frames": 0,
        }
    profile["profile_sha256"] = _canonical_json_sha256(profile)
    return profile


def build_collection(
    analysis_path: Path,
    *,
    collection_id: str,
    source_path_label: str,
) -> dict[str, Any]:
    """静的解析JSONから秘密値を含まない検出・模擬profile packを構築する。"""

    if not PROFILE_ID_PATTERN.fullmatch(collection_id):
        raise ReviewedC2CollectionError("collection_idが不正です")
    raw = analysis_path.read_bytes()
    document = _load_json(analysis_path)
    if not isinstance(document, Mapping) or document.get("sample_executed") is not False:
        raise ReviewedC2CollectionError("analysis root safety flagが不正です")
    if document.get("network_contacted") is not False or document.get("raw_keys_published") is not False:
        raise ReviewedC2CollectionError("analysis root safety契約が不正です")
    results = document.get("results")
    if not isinstance(results, list) or not 1 <= len(results) <= MAXIMUM_PROFILE_COUNT:
        raise ReviewedC2CollectionError("analysis results件数が不正です")
    profiles = [_build_profile(result, collection_id) for result in results if isinstance(result, Mapping)]
    if len(profiles) != len(results):
        raise ReviewedC2CollectionError("analysis resultがobjectではありません")
    output = {
        "schema_version": SCHEMA_VERSION,
        "collection_id": collection_id,
        "source_analysis_sha256": hashlib.sha256(raw).hexdigest(),
        "source_path": source_path_label,
        "profiles": profiles,
    }
    if len({profile["profile_id"] for profile in profiles}) != len(profiles):
        raise ReviewedC2CollectionError("生成profile IDが重複しています")
    return output


def detector_plans(collection: ReviewedC2Collection) -> list[dict[str, Any]]:
    """全外部endpointに対するNmap NSE限定の実行計画を返す。"""

    plans: list[dict[str, Any]] = []
    for profile in collection.profiles.values():
        for endpoint in profile.endpoints:
            if profile.family == BW_FAMILY:
                script = "analysis-framework/nmap/scripts/dotnet-rat-c2.nse"
                script_args = (
                    "dotnet-rat.family=venomrat,"
                    f"dotnet-rat.expected-cert={profile.expected_certificate_sha256},"
                    "dotnet-rat.timeout=3000"
                )
            else:
                script = "analysis-framework/nmap/scripts/valleyrat-c2.nse"
                script_args = "valleyrat.mode=vvas,valleyrat.timeout=3000"
            plans.append(
                {
                    "profile_id": profile.profile_id,
                    "profile_sha256": profile.profile_sha256,
                    "sample_sha256": profile.sample_sha256,
                    "terminal_sha256": profile.terminal_sha256,
                    "family": profile.family,
                    "target": endpoint.display,
                    "execution_backend": "nmap_nse_only",
                    "script": script,
                    "script_args": script_args,
                    "argv": [
                        "nmap",
                        "-n",
                        "-sT",
                        "-Pn",
                        "--host-timeout",
                        "10s",
                        "--script-timeout",
                        "7s",
                        "-p",
                        str(endpoint.port),
                        "--script",
                        script,
                        "--script-args",
                        script_args,
                        endpoint.host,
                    ],
                    "network_contacted": False,
                    "requires_current_task_network_authorization": True,
                    "requires_profile_acknowledgement": profile.profile_sha256,
                }
            )
    return plans


def _messagepack_limits() -> SessionLimits:
    return SessionLimits(
        timeout_seconds=3.0,
        maximum_frame_bytes=64,
        maximum_decoded_bytes=1024,
        maximum_map_entries=4,
        maximum_string_bytes=256,
        maximum_binary_bytes=1,
        maximum_opcode_bytes=64,
        maximum_read_calls=8,
        maximum_send_bytes=96,
    )


def classify_bwrat_response(
    profile: ReviewedSampleProfile,
    frame: bytes,
    *,
    tls_version: str,
    certificate_sha256: str | None,
) -> dict[str, Any]:
    """BwRAT heartbeat responseをraw値を残さずoffline判定する。"""

    if profile.family != BW_FAMILY:
        raise ReviewedC2CollectionError("BwRAT profileではありません")
    try:
        decoded = decode_frame(frame, _messagepack_limits())
    except (TypeError, TlsMessagePackHostError) as exc:
        raise ReviewedC2CollectionError("TLS MessagePack response frameが不正です") from exc
    response_exact = decoded.values == {"Pac_ket": "Po_ng"}
    tls_exact = tls_version == "TLSv1.2"
    observed_certificate = (
        _sha256(certificate_sha256, "certificate_sha256")
        if certificate_sha256 is not None
        else None
    )
    certificate_exact = (
        observed_certificate == profile.expected_certificate_sha256
        if observed_certificate is not None
        else None
    )
    confirmed = response_exact and tls_exact
    status = (
        "confirmed_bwrat_venomrat_protocol_c2"
        if confirmed
        else "tls_version_mismatch"
        if not tls_exact
        else "messagepack_response_mismatch"
    )
    return {
        "profile_id": profile.profile_id,
        "family": profile.family,
        "status": status,
        "c2_confirmed": confirmed,
        "tls_version_exact": tls_exact,
        "response_exact": response_exact,
        "certificate_exact_match": certificate_exact,
        "certificate_mismatch_excludes_c2": False,
        "frame_size": decoded.frame_size,
        "frame_sha256": decoded.frame_sha256,
        "raw_response_retained": False,
        "victim_metadata_sent": False,
    }


def classify_vvas_response(
    profile: ReviewedSampleProfile,
    response: bytes,
) -> dict[str, Any]:
    """vvaS stage headerだけをoffline判定し、stage bodyを保持しない。"""

    if profile.family != VVAS_FAMILY:
        raise ReviewedC2CollectionError("vvaS profileではありません")
    if not isinstance(response, bytes) or len(response) > 64:
        raise ReviewedC2CollectionError("vvaS responseが64-byte上限外です")
    header = response[:DEFAULT_VVAS_HEADER_SIZE]
    expected = DEFAULT_VVAS_STAGE_SIZE.to_bytes(4, "little") + b"\x00" * 10
    exact = header == expected
    return {
        "profile_id": profile.profile_id,
        "family": profile.family,
        "status": "confirmed_vvas_c2" if exact else "vvas_header_mismatch",
        "c2_confirmed": exact,
        "received_bytes": len(response),
        "header_sha256": hashlib.sha256(header).hexdigest() if header else None,
        "stage_downloaded": False,
        "stage_body_retained": False,
        "victim_metadata_sent": False,
    }


def write_json_new(path: Path, document: Any) -> None:
    """既存fileを上書きせず機械可読結果をUTF-8 JSONで保存する。"""

    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8", newline="\n") as handle:
        json.dump(document, handle, ensure_ascii=False, indent=2, sort_keys=True)
        handle.write("\n")


def write_collection(path: Path, document: Mapping[str, Any]) -> None:
    """既存fileを上書きせずprofile packをUTF-8 JSONで保存する。"""

    write_json_new(path, document)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    build = subparsers.add_parser("build", help="静的解析JSONからprivate profile packを構築します")
    build.add_argument("--analysis", type=Path, required=True)
    build.add_argument("--collection-id", required=True)
    build.add_argument("--source-label", required=True)
    build.add_argument("--output", type=Path, required=True)
    inventory = subparsers.add_parser("inventory", help="profile件数と検出計画を表示します")
    inventory.add_argument("--profiles", type=Path, required=True)
    inventory.add_argument("--output", type=Path)
    plans = subparsers.add_parser("detector-plans", help="通信せずNmap NSE計画だけを表示します")
    plans.add_argument("--profiles", type=Path, required=True)
    plans.add_argument("--output", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "build":
        document = build_collection(
            args.analysis,
            collection_id=args.collection_id,
            source_path_label=args.source_label,
        )
        write_collection(args.output, document)
        result: Any = {
            "output": str(args.output),
            "profile_count": len(document["profiles"]),
            "network_contacted": False,
            "sample_executed": False,
        }
    else:
        collection = load_collection(args.profiles)
        plans = detector_plans(collection)
        result = plans if args.command == "detector-plans" else {
            "collection_id": collection.collection_id,
            "profile_count": len(collection.profiles),
            "external_target_count": len(plans),
            "families": sorted({profile.family for profile in collection.profiles.values()}),
            "network_contacted": False,
        }
        if args.output is not None:
            write_json_new(args.output, result)
    json.dump(result, sys.stdout, ensure_ascii=False, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
