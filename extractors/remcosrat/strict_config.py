"""RemcosのRCDATA/SETTINGSを実行せず厳格に検証・復号する共有実装。"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import re
import stat
import tempfile
from pathlib import Path
from typing import Any

import pefile

MAX_INPUT_BYTES = 64 * 1024 * 1024
MAX_SETTINGS_BYTES = 4 * 1024 * 1024
MAX_SETTINGS_LANGUAGE_LEAVES = 32
MAX_SETTINGS_RESOURCE_COPY_BYTES = 16 * 1024 * 1024
MAX_REPORT_BYTES = 2 * 1024 * 1024
MIN_SETTINGS_BYTES = 8
MIN_CONFIG_FIELDS = 16
MAX_CONFIG_FIELDS = 128
MAX_C2_RECORDS = 32
MAX_VERSION_CANDIDATES = 8
DELIMITERS = (b"\x7c\x1f\x1e\x1e\x7c", b"\x7c\x1e\x1e\x1f\x7c")
VERSION_RE = re.compile(rb"(?i)\b\d{1,3}\.\d{1,3}(?:\.\d{1,3})?\s+(?:pro|free)\b")
DNS_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
DOTTED_DECIMAL_RE = re.compile(r"^[0-9]+(?:\.[0-9]+)+$")
MODERN_FLAG_INDICES = (
    0x03,
    0x04,
    0x05,
    0x08,
    0x0C,
    0x12,
    0x13,
    0x14,
    0x16,
    0x1B,
    0x23,
    0x27,
    0x2B,
    0x2C,
    0x2E,
    0x32,
    0x35,
)
MODERN_PATH_INDICES = (0x09, 0x10, 0x19)
MODERN_MODE_LIMITS = ((0x0F, 2), (0x28, 2))
MODERN_FAMILY_SCHEMA_INDICES = tuple(
    sorted(
        {
            0x00,
            0x01,
            0x02,
            0x0E,
            0x29,
            *MODERN_FLAG_INDICES,
            *MODERN_PATH_INDICES,
            *(index for index, _maximum in MODERN_MODE_LIMITS),
        }
    )
)


class RemcosConfigError(ValueError):
    """推測や別layoutへの無条件fallbackを防ぐ型付き抽出失敗。"""

    def __init__(
        self,
        reason: str,
        message: str,
        *,
        stage: str,
        mapped_layout_retry_eligible: bool = False,
    ) -> None:
        super().__init__(message)
        self.reason = reason
        self.stage = stage
        self.mapped_layout_retry_eligible = mapped_layout_retry_eligible

    def public_reason(self) -> dict[str, object]:
        """秘密値や検体断片を含まない機械判定用理由を返す。"""

        return {
            "reason": self.reason,
            "stage": self.stage,
            "mapped_layout_retry_eligible": self.mapped_layout_retry_eligible,
        }


def _fail(
    reason: str,
    message: str,
    *,
    stage: str,
    mapped_layout_retry_eligible: bool = False,
) -> RemcosConfigError:
    return RemcosConfigError(
        reason,
        message,
        stage=stage,
        mapped_layout_retry_eligible=mapped_layout_retry_eligible,
    )


def rc4_crypt(data: bytes, key: bytes) -> bytes:
    """標準RC4を純粋なバイト変換として適用する。"""

    if not key:
        raise _fail("rc4_key_empty", "RC4キーが空です", stage="settings_blob")
    state = list(range(256))
    j = 0
    for i in range(256):
        j = (j + state[i] + key[i % len(key)]) & 0xFF
        state[i], state[j] = state[j], state[i]
    i = j = 0
    output = bytearray()
    for value in data:
        i = (i + 1) & 0xFF
        j = (j + state[i]) & 0xFF
        state[i], state[j] = state[j], state[i]
        output.append(value ^ state[(state[i] + state[j]) & 0xFF])
    return bytes(output)


def _settings_resource(data: bytes) -> bytes:
    """一意なRCDATA/SETTINGS language leafだけを返す。"""

    if (
        not data.startswith(b"MZ")
        or not MIN_SETTINGS_BYTES <= len(data) <= MAX_INPUT_BYTES
    ):
        raise _fail(
            "input_not_supported_pe",
            "許可範囲内のPE入力ではありません",
            stage="pe_input",
        )
    try:
        image = pefile.PE(data=data, fast_load=False)
    except pefile.PEFormatError as error:
        raise _fail(
            "pe_structure_invalid", "PE構造が不正です", stage="pe_input"
        ) from error

    resource_root = getattr(image, "DIRECTORY_ENTRY_RESOURCE", None)
    if resource_root is None:
        raise _fail(
            "settings_resource_unavailable_in_file_layout",
            "通常ファイル配置にRCDATA/SETTINGSリソースがありません",
            stage="resource_lookup",
            mapped_layout_retry_eligible=True,
        )

    resources: list[bytes] = []
    settings_leaf_count = 0
    copied_resource_bytes = 0
    try:
        for type_entry in resource_root.entries:
            if int(getattr(type_entry.struct, "Id", -1)) != 10:
                continue
            for name_entry in type_entry.directory.entries:
                name = str(name_entry.name or getattr(name_entry.struct, "Id", ""))
                if name.casefold() != "settings":
                    continue
                for language_entry in name_entry.directory.entries:
                    settings_leaf_count += 1
                    if settings_leaf_count > MAX_SETTINGS_LANGUAGE_LEAVES:
                        raise _fail(
                            "settings_resource_leaf_count_exceeded",
                            "SETTINGS language leaf数が許可上限を超えています",
                            stage="resource_bounds",
                        )
                    resource = language_entry.data.struct
                    size = int(resource.Size)
                    if not MIN_SETTINGS_BYTES <= size <= MAX_SETTINGS_BYTES:
                        raise _fail(
                            "settings_resource_size_out_of_bounds",
                            "SETTINGSリソースのサイズが許可範囲外です",
                            stage="resource_bounds",
                        )
                    copied_resource_bytes += size
                    if copied_resource_bytes > MAX_SETTINGS_RESOURCE_COPY_BYTES:
                        raise _fail(
                            "settings_resource_copy_bytes_exceeded",
                            "SETTINGS resourceの累積読込量が許可上限を超えています",
                            stage="resource_bounds",
                        )
                    offset = int(image.get_offset_from_rva(int(resource.OffsetToData)))
                    end = offset + size
                    if offset < 0 or end < offset or end > len(data):
                        raise _fail(
                            "settings_resource_bounds_invalid",
                            "SETTINGSリソースがPE境界外です",
                            stage="resource_bounds",
                        )
                    resources.append(data[offset:end])
    except RemcosConfigError:
        raise
    except (AttributeError, IndexError, TypeError, ValueError) as error:
        raise _fail(
            "resource_directory_structure_invalid",
            "PE resource directoryの構造が不正です",
            stage="resource_lookup",
        ) from error

    unique = {hashlib.sha256(item).digest(): item for item in resources}
    if not unique:
        raise _fail(
            "settings_resource_unavailable_in_file_layout",
            "通常ファイル配置にRCDATA/SETTINGSリソースがありません",
            stage="resource_lookup",
            mapped_layout_retry_eligible=True,
        )
    if len(unique) != 1:
        raise _fail(
            "settings_resource_leaf_ambiguous",
            "異なるRCDATA/SETTINGS language leafが複数あります",
            stage="resource_lookup",
        )
    return next(iter(unique.values()))


def decode_settings_blob(resource: bytes) -> tuple[bytes, bytes, int]:
    """先頭1バイトの鍵長、鍵、暗号文というRemcos形式を復号する。"""

    if not MIN_SETTINGS_BYTES <= len(resource) <= MAX_SETTINGS_BYTES:
        raise _fail(
            "settings_blob_size_out_of_bounds",
            "SETTINGSリソースのサイズが許可範囲外です",
            stage="settings_blob",
        )
    key_size = resource[0]
    if key_size == 0 or key_size + 2 > len(resource):
        raise _fail(
            "rc4_key_length_invalid",
            "SETTINGSのRC4鍵長が不正です",
            stage="settings_blob",
        )
    key = resource[1 : 1 + key_size]
    ciphertext = resource[1 + key_size :]
    if not ciphertext:
        raise _fail(
            "settings_ciphertext_missing",
            "SETTINGS暗号文がありません",
            stage="settings_blob",
        )
    clear = rc4_crypt(ciphertext, key)
    return clear, key, key_size


def _select_delimiter(clear: bytes) -> bytes:
    present = [delimiter for delimiter in DELIMITERS if delimiter in clear]
    if len(present) != 1:
        raise _fail(
            "settings_delimiter_ambiguous_or_missing",
            "Remcos設定delimiterを一意に特定できません",
            stage="config_schema",
        )
    return present[0]


def _decode_ascii(value: bytes, *, maximum: int) -> str | None:
    stripped = value.strip(b"\x00\t\r\n ")
    if not stripped or len(stripped) > maximum:
        return None
    try:
        text = stripped.decode("ascii")
    except UnicodeDecodeError:
        return None
    if any(ord(character) < 32 or ord(character) == 127 for character in text):
        return None
    return text


def _normalize_host(value: bytes) -> tuple[str, str, bool] | None:
    text = _decode_ascii(value, maximum=253)
    if text is None:
        return None
    host = text.casefold().rstrip(".")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        labels = host.split(".")
        # IPv4風の全decimal dotted表現をIP parse失敗後にDNSへ降格しない。
        # これを許すと、範囲外octet・先頭zero・不足octetを公開C2候補として
        # 誤ってmonitor対象へ昇格してしまう。
        if DOTTED_DECIMAL_RE.fullmatch(host):
            return None
        if len(labels) < 2 or not all(
            DNS_LABEL_RE.fullmatch(label) for label in labels
        ):
            return None
        return host, "dns", True
    if address.is_unspecified or address.is_multicast:
        return None
    return host, f"ipv{address.version}", bool(address.is_global)


def _parse_positive_int(value: bytes, *, maximum: int) -> int | None:
    text = _decode_ascii(value, maximum=16)
    if text is None or not text.isdigit():
        return None
    parsed = int(text)
    return parsed if 0 <= parsed <= maximum else None


def _is_boolean_field(value: bytes) -> bool:
    """版差で観測されるbinary／ASCII両形式のbooleanを厳格に判定する。"""

    return value in (b"\x00", b"\x01", b"0", b"1")


def _parse_c2_list(
    value: bytes, *, modern_schema: bool
) -> tuple[list[dict[str, Any]], bool]:
    """設定index 0だけを有界解析し、競合するendpoint表現を拒否する。"""

    stripped = value.strip(b"\x00")
    # 実際のRemcos SETTINGSでは0x1eがrecord間separatorであると同時に、
    # index 0全体の終端記号として1回だけ現れるprofileがある。終端1 byteは
    # recordに数えないが、先頭・内部・二重終端の空recordは引き続き拒否する。
    if stripped.endswith(b"\x1e"):
        stripped = stripped[:-1]
    raw_record_count = 0 if not stripped else stripped.count(b"\x1e") + 1
    if raw_record_count > MAX_C2_RECORDS:
        raise _fail(
            "c2_record_count_exceeded",
            "Remcos設定index 0のC2 record数が上限を超えています",
            stage="c2_schema",
        )

    records: list[dict[str, Any]] = []
    credential_or_unknown_field_present = False
    seen: dict[tuple[str, int], tuple[bool | None, str, bytes | None]] = {}
    for raw_record in stripped.split(b"\x1e") if stripped else ():
        if not raw_record:
            raise _fail(
                "c2_record_empty",
                "Remcos設定index 0のC2 record集合に空recordがあります",
                stage="c2_schema",
            )
        parts = raw_record.rsplit(b":", 2)
        if len(parts) == 2:
            raw_host, raw_port = parts
            raw_third = None
        elif len(parts) == 3:
            raw_host, raw_port, raw_third = parts
        else:
            raise _fail(
                "c2_record_structure_invalid",
                "Remcos設定index 0のC2 record区切り構造が不正です",
                stage="c2_schema",
            )
        normalized = _normalize_host(raw_host)
        port = _parse_positive_int(raw_port, maximum=65535)
        if normalized is None or port is None or port == 0:
            raise _fail(
                "c2_record_endpoint_invalid",
                "Remcos設定index 0のC2 recordに不正なhostまたはportがあります",
                stage="c2_schema",
            )
        host, host_kind, monitor_eligible = normalized
        tls_enabled: bool | None = None
        third_field_kind = "absent"
        if raw_third is not None:
            third = _decode_ascii(raw_third, maximum=512)
            if modern_schema and third in {"0", "1"}:
                tls_enabled = third == "1"
                third_field_kind = "tls_flag"
            else:
                credential_or_unknown_field_present = (
                    credential_or_unknown_field_present or bool(raw_third)
                )
                third_field_kind = "withheld_unknown_or_credential"
        identity = (host, port)
        third_fingerprint = (
            hashlib.sha256(raw_third).digest() if raw_third is not None else None
        )
        interpretation = (tls_enabled, third_field_kind, third_fingerprint)
        previous = seen.get(identity)
        if previous is not None:
            if previous != interpretation:
                raise _fail(
                    "c2_record_conflict",
                    "同一Remcos C2 endpointに競合する設定があります",
                    stage="c2_schema",
                )
            continue
        seen[identity] = interpretation
        endpoint = f"[{host}]:{port}" if host_kind == "ipv6" else f"{host}:{port}"
        records.append(
            {
                "endpoint": endpoint,
                "host": host,
                "host_kind": host_kind,
                "port": port,
                "tls_enabled": tls_enabled,
                "third_field_kind": third_field_kind,
                "monitor_eligible": monitor_eligible,
                "role": "interactive_c2",
                "confidence": "confirmed_static_configuration",
            }
        )
    return records, credential_or_unknown_field_present


def _validated_schema_fields(
    fields: list[bytes],
    *,
    modern_schema: bool,
) -> dict[str, Any]:
    """公開済みRemcos field schemaまたはlegacy mutex anchorを相関する。"""

    botnet = _decode_ascii(fields[1], maximum=128)
    connect_interval = _parse_positive_int(fields[2], maximum=86400)
    mutex = _decode_ascii(fields[0x0E], maximum=256)
    if botnet is None:
        raise _fail(
            "botnet_field_invalid",
            "Remcos botnet fieldの構造が不正です",
            stage="config_schema",
        )
    if connect_interval is None:
        raise _fail(
            "connect_interval_field_invalid",
            "Remcos接続間隔fieldの構造が不正です",
            stage="config_schema",
        )
    if mutex is None:
        raise _fail(
            "mutex_field_invalid",
            "Remcos mutex fieldの構造が不正です",
            stage="family_schema",
        )

    validated_indices = [0, 1, 2, 0x0E]
    connect_delay: int | None = None
    mutex_prefix_validated = mutex.casefold().startswith("rmc-")
    if modern_schema:
        connect_delay = _parse_positive_int(fields[0x29], maximum=86400)
        if connect_delay is None:
            raise _fail(
                "connect_delay_field_invalid",
                "modern Remcos接続遅延fieldの構造が不正です",
                stage="config_schema",
            )
        validated_indices.append(0x29)
        if any(not _is_boolean_field(fields[index]) for index in MODERN_FLAG_INDICES):
            raise _fail(
                "published_boolean_field_invalid",
                "modern Remcos boolean field集合の構造が不正です",
                stage="family_schema",
            )
        if any(
            _parse_positive_int(fields[index], maximum=8) is None
            for index in MODERN_PATH_INDICES
        ):
            raise _fail(
                "published_path_field_invalid",
                "modern Remcos path mapping field集合の構造が不正です",
                stage="family_schema",
            )
        if any(
            _parse_positive_int(fields[index], maximum=maximum) is None
            for index, maximum in MODERN_MODE_LIMITS
        ):
            raise _fail(
                "published_mode_field_invalid",
                "modern Remcos mode field集合の構造が不正です",
                stage="family_schema",
            )
        family_schema_indices = list(MODERN_FAMILY_SCHEMA_INDICES)
        family_anchor = "elastic_published_56_field_subset_v1"
    else:
        if not mutex_prefix_validated:
            raise _fail(
                "legacy_remcos_mutex_anchor_missing",
                "legacy Remcos profileのmutex prefixを確認できません",
                stage="family_schema",
            )
        family_schema_indices = list(validated_indices)
        family_anchor = "legacy_rmc_mutex_anchor_v1"
    return {
        "botnet": botnet,
        "connect_interval_seconds": connect_interval,
        "initial_connect_delay_seconds": connect_delay,
        "mutex": mutex,
        "validated_field_indices": validated_indices,
        "family_schema_field_indices": family_schema_indices,
        "family_schema_validation_profile": family_anchor,
        "family_specific_schema_validated": True,
        "family_specific_mutex_prefix_validated": mutex_prefix_validated,
        "known_mutex_prefix_observed": mutex_prefix_validated,
    }


def parse_decrypted_settings(clear: bytes) -> dict[str, Any]:
    """復号済み設定を既知field境界で検証し、公開可能な値だけ返す。"""

    if not clear or len(clear) > MAX_SETTINGS_BYTES:
        raise _fail(
            "decrypted_settings_size_out_of_bounds",
            "復号済みSETTINGSのサイズが許可範囲外です",
            stage="config_schema",
        )
    delimiter = _select_delimiter(clear)
    fields = clear.split(delimiter)
    if not MIN_CONFIG_FIELDS <= len(fields) <= MAX_CONFIG_FIELDS:
        raise _fail(
            "config_field_count_out_of_bounds",
            "Remcos設定field数が許可範囲外です",
            stage="config_schema",
        )
    modern_schema = len(fields) >= 0x39
    c2, withheld = _parse_c2_list(fields[0], modern_schema=modern_schema)
    if not c2:
        raise _fail(
            "configured_c2_not_recovered",
            "設定index 0から有効なC2を復元できません",
            stage="c2_schema",
        )

    schema_fields = _validated_schema_fields(fields, modern_schema=modern_schema)
    botnet = schema_fields["botnet"]
    connect_interval = schema_fields["connect_interval_seconds"]
    connect_delay = schema_fields["initial_connect_delay_seconds"]
    mutex = schema_fields["mutex"]
    tls_agent_certificate = fields[0x36] if len(fields) > 0x36 else b""
    tls_private_key = fields[0x37] if len(fields) > 0x37 else b""
    tls_peer_certificate = fields[0x38] if len(fields) > 0x38 else b""
    return {
        "delimiter_hex": delimiter.hex(),
        "field_count": len(fields),
        "schema_profile": "published_56_field_or_later"
        if modern_schema
        else "legacy_or_partial_field_set",
        "c2_record_count": len(c2),
        "maximum_c2_record_count": MAX_C2_RECORDS,
        "c2": c2,
        "validated_field_indices": schema_fields["validated_field_indices"],
        "family_schema_field_indices": schema_fields["family_schema_field_indices"],
        "family_schema_validation_profile": schema_fields[
            "family_schema_validation_profile"
        ],
        "family_specific_schema_validated": schema_fields[
            "family_specific_schema_validated"
        ],
        "complete_c2_record_set_validated": True,
        "family_specific_mutex_prefix_validated": schema_fields[
            "family_specific_mutex_prefix_validated"
        ],
        "known_mutex_prefix_observed": schema_fields["known_mutex_prefix_observed"],
        "botnet": botnet,
        "connect_interval_seconds": connect_interval,
        "initial_connect_delay_seconds": connect_delay,
        "mutex_sha256": hashlib.sha256(mutex.encode("ascii")).hexdigest()
        if mutex
        else None,
        "mutex_length": len(mutex) if mutex else 0,
        "credential_or_unknown_c2_field_present": withheld,
        "credential_value_published": False,
        "tls_material": {
            "agent_certificate_present": bool(tls_agent_certificate),
            "agent_certificate_sha256": (
                hashlib.sha256(tls_agent_certificate).hexdigest()
                if tls_agent_certificate
                else None
            ),
            "private_key_present": bool(tls_private_key),
            "private_key_published": False,
            "peer_certificate_present": bool(tls_peer_certificate),
            "peer_certificate_sha256": (
                hashlib.sha256(tls_peer_certificate).hexdigest()
                if tls_peer_certificate
                else None
            ),
        },
    }


def _version_evidence(data: bytes) -> tuple[list[str], dict[str, object]]:
    """PE全体のversion文字列を候補としてだけ記録し、競合時は選択しない。"""

    candidates: list[str] = []
    seen: set[str] = set()
    quota_exceeded = False
    for match in VERSION_RE.finditer(data):
        candidate = match.group(0).decode("ascii")
        if candidate in seen:
            continue
        seen.add(candidate)
        if len(candidates) >= MAX_VERSION_CANDIDATES:
            quota_exceeded = True
            break
        candidates.append(candidate)
    candidates.sort()

    if quota_exceeded:
        status = "candidate_quota_exceeded_withheld"
        reason = "version_candidate_quota_exceeded"
        published: list[str] = []
        observations: list[dict[str, object]] = []
    elif len(candidates) > 1:
        status = "conflicting_candidates_withheld"
        reason = "version_candidate_conflict"
        published = []
        observations = [
            {
                "value": candidate,
                "source": "pe_wide_printable_bytes",
                "scope": "entire_input_pe",
                "confidence": "unverified",
                "used_for_version_confirmation": False,
            }
            for candidate in candidates
        ]
    else:
        status = "single_candidate_not_confirmed" if candidates else "not_observed"
        reason = (
            "pe_wide_candidate_not_confirmed"
            if candidates
            else "version_candidate_not_observed"
        )
        published = candidates
        observations = [
            {
                "value": candidate,
                "source": "pe_wide_printable_bytes",
                "scope": "entire_input_pe",
                "confidence": "unverified",
                "used_for_version_confirmation": False,
            }
            for candidate in candidates
        ]
    return published, {
        "status": status,
        "reason": reason,
        "scope": "entire_input_pe",
        "source": "pe_wide_printable_bytes",
        "maximum_candidate_count": MAX_VERSION_CANDIDATES,
        "observed_unique_count": len(seen),
        "observed_unique_count_is_lower_bound": quota_exceeded,
        "candidate_set_complete": not quota_exceeded,
        "confirmed_version": None,
        "used_for_family_confirmation": False,
        "used_for_config_confirmation": False,
        "observations": observations,
    }


def extract_config(data: bytes) -> dict[str, object]:
    """C2と構造情報だけを返し、鍵・private key・認証値を公開しない。"""

    resource = _settings_resource(data)
    clear, key, key_size = decode_settings_blob(resource)
    parsed = parse_decrypted_settings(clear)
    c2 = [
        {
            **item,
            "evidence": {
                "kind": "rc4_decrypted_rcdata_settings",
                "resource_type": "RT_RCDATA",
                "resource_name": "SETTINGS",
                "config_field_index": 0,
                "all_expected_fields_validated": True,
                "validated_field_indices": parsed["validated_field_indices"],
                "complete_c2_record_set_validated": parsed[
                    "complete_c2_record_set_validated"
                ],
                "family_specific_schema_validated": parsed[
                    "family_specific_schema_validated"
                ],
                "family_specific_mutex_prefix_validated": parsed[
                    "family_specific_mutex_prefix_validated"
                ],
                "family_schema_validation_profile": parsed[
                    "family_schema_validation_profile"
                ],
            },
            "contacted": False,
            "liveness_confirmed": False,
        }
        for item in parsed.pop("c2")
    ]
    findings = [
        {
            "kind": "network.endpoint",
            "value": item["endpoint"],
            "role": "configured_c2",
            "confidence": "confirmed",
            "source": "rc4_decrypted_rcdata_settings_index_0",
        }
        for item in c2
    ]
    digest = hashlib.sha256(data).hexdigest()
    version_candidates, version_evidence = _version_evidence(data)
    return {
        "schema_version": 2,
        "family": "remcosrat",
        "classification_confidence": "confirmed_static_configuration",
        "family_attribution_confirmed": True,
        "sample_sha256": digest,
        "static_config_recovered": True,
        "decoded_config_recovered": True,
        "operational_c2_recovered": any(bool(item["monitor_eligible"]) for item in c2),
        "sample": {"sha256": digest, "size": len(data), "format": "pe"},
        "config": {
            **parsed,
            "static_config_recovered": True,
            "decoded_config_recovered": True,
            "family_attribution_confirmed": True,
            "endpoints": [item["endpoint"] for item in c2],
            "settings_resource_sha256": hashlib.sha256(resource).hexdigest(),
            "settings_resource_size": len(resource),
            "rc4_key_size": key_size,
            "rc4_key_sha256": hashlib.sha256(key).hexdigest(),
            "rc4_key_published": False,
            "decoded_settings_sha256": hashlib.sha256(clear).hexdigest(),
            "decoded_settings_published": False,
        },
        "version_candidates": version_candidates,
        "version_candidate_provenance": version_evidence,
        "c2": c2,
        "findings": findings,
        "credentials_published": False,
        "executed": False,
        "network_contacted": False,
        "safety": {
            "sample_executed": False,
            "network_contacted": False,
            "raw_config_published": False,
            "credentials_published": False,
            "private_key_published": False,
        },
        "limitations": [
            "設定内endpointは静的設定値であり、現在の稼働やRemcos protocol応答を確認したものではない",
            "TLS証明書hashは設定blob内の値であり、稼働中serverから観測した証明書ではない",
            "C2第3fieldは公開済み56-field schemaを満たす場合だけTLS flagとして解釈する",
            "PE全体のversion文字列は設定帰属がない候補であり、確定versionへ昇格しない",
        ],
    }


def _is_reparse_point(metadata: os.stat_result) -> bool:
    """Windows reparse属性を持つpath要素を識別する。"""

    flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return bool(int(getattr(metadata, "st_file_attributes", 0)) & flag)


def _ensure_no_reparse_components(path: Path) -> None:
    """既存path要素にsymlinkまたはjunctionがあれば停止する。"""

    absolute = path.absolute()
    if not absolute.parts:
        raise ValueError("pathが空です")
    current = Path(absolute.parts[0])
    for part in absolute.parts[1:]:
        current /= part
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            break
        except OSError as error:
            raise ValueError("path要素を安全に確認できません") from error
        if current.is_symlink() or _is_reparse_point(metadata):
            raise ValueError("symlinkまたはreparse pointを含むpathは使用できません")


def _file_identity(metadata: os.stat_result) -> tuple[int, ...]:
    """読取前後で比較する通常fileのidentityを返す。"""

    return (
        int(metadata.st_dev),
        int(metadata.st_ino),
        int(metadata.st_size),
        int(metadata.st_mtime_ns),
        int(metadata.st_nlink),
    )


def _read_bounded_regular_file(path: Path) -> bytes:
    """単一linkの通常fileを単一handleから上限付きで安定読込する。"""

    _ensure_no_reparse_components(path)
    try:
        before = path.lstat()
    except OSError as error:
        raise ValueError("入力fileを確認できません") from error
    if (
        path.is_symlink()
        or _is_reparse_point(before)
        or not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
    ):
        raise ValueError("入力はsingle-linkの通常fileである必要があります")
    if not 0 < before.st_size <= MAX_INPUT_BYTES:
        raise ValueError("入力fileのsizeが許可範囲外です")

    try:
        with path.open("rb") as stream:
            opened = os.fstat(stream.fileno())
            if (
                not stat.S_ISREG(opened.st_mode)
                or _is_reparse_point(opened)
                or opened.st_nlink != 1
                or _file_identity(before) != _file_identity(opened)
            ):
                raise ValueError("検証後に入力fileのidentityまたは属性が変化しました")
            data = stream.read(MAX_INPUT_BYTES + 1)
            after_handle = os.fstat(stream.fileno())
        after_path = path.lstat()
    except ValueError:
        raise
    except OSError as error:
        raise ValueError("入力fileを安全に読み込めません") from error

    _ensure_no_reparse_components(path)
    if (
        len(data) != before.st_size
        or len(data) > MAX_INPUT_BYTES
        or path.is_symlink()
        or _is_reparse_point(after_path)
        or not stat.S_ISREG(after_path.st_mode)
        or after_path.st_nlink != 1
        or _file_identity(before) != _file_identity(after_handle)
        or _file_identity(before) != _file_identity(after_path)
    ):
        raise ValueError("読込中に入力fileのidentity、属性、またはsizeが変化しました")
    return data


def _reject_input_output_alias(sample: Path, output: Path) -> None:
    """同一path、解決先、または既存hardlinkへの出力を拒否する。"""

    _ensure_no_reparse_components(sample)
    _ensure_no_reparse_components(output)
    if sample.resolve(strict=False) == output.resolve(strict=False):
        raise ValueError("inputとoutputは同じfileを参照できません")
    try:
        if sample.samefile(output):
            raise ValueError("inputとoutputは同じfileを参照できません")
    except FileNotFoundError:
        pass
    try:
        output_metadata = output.lstat()
    except FileNotFoundError:
        return
    except OSError as error:
        raise ValueError("outputを安全に確認できません") from error
    if (
        output.is_symlink()
        or _is_reparse_point(output_metadata)
        or not stat.S_ISREG(output_metadata.st_mode)
        or output_metadata.st_nlink != 1
    ):
        raise ValueError("既存outputはsingle-linkの通常fileである必要があります")


def _write_text_atomic(path: Path, text: str) -> None:
    """同一directory内のsingle-link一時fileからUTF-8 reportを置換する。"""

    encoded = text.encode("utf-8")
    if len(encoded) > MAX_REPORT_BYTES:
        raise ValueError("出力reportが許可sizeを超えています")
    _ensure_no_reparse_components(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    _ensure_no_reparse_components(path.parent)
    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent,
        prefix=f".{path.name}.",
        suffix=".tmp",
    )
    temporary = Path(temporary_name)
    try:
        temporary_metadata = temporary.lstat()
        if (
            temporary.is_symlink()
            or _is_reparse_point(temporary_metadata)
            or not stat.S_ISREG(temporary_metadata.st_mode)
            or temporary_metadata.st_nlink != 1
        ):
            raise ValueError("一時outputがsingle-linkの通常fileではありません")
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = -1
            opened = os.fstat(stream.fileno())
            if _file_identity(temporary_metadata) != _file_identity(opened):
                raise ValueError("一時outputのidentityが変化しました")
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        after = temporary.lstat()
        if (
            temporary.is_symlink()
            or _is_reparse_point(after)
            or not stat.S_ISREG(after.st_mode)
            or after.st_nlink != 1
            or after.st_size != len(encoded)
            or (after.st_dev, after.st_ino)
            != (temporary_metadata.st_dev, temporary_metadata.st_ino)
        ):
            raise ValueError("一時outputのidentity、属性、またはsizeが変化しました")
        _ensure_no_reparse_components(path)
        os.replace(temporary, path)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def main() -> int:
    """単一PEをoffline解析し、公開可能なJSONだけを出力する。"""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("sample", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.output:
        _reject_input_output_alias(args.sample, args.output)
    sample = _read_bounded_regular_file(args.sample)
    rendered = json.dumps(extract_config(sample), ensure_ascii=False, indent=2) + "\n"
    if args.output:
        _reject_input_output_alias(args.sample, args.output)
        _write_text_atomic(args.output, rendered)
    else:
        print(rendered, end="")
    return 0


__all__ = [
    "DELIMITERS",
    "MAX_C2_RECORDS",
    "MAX_CONFIG_FIELDS",
    "MAX_INPUT_BYTES",
    "MAX_SETTINGS_BYTES",
    "MAX_VERSION_CANDIDATES",
    "MIN_CONFIG_FIELDS",
    "RemcosConfigError",
    "decode_settings_blob",
    "extract_config",
    "parse_decrypted_settings",
    "rc4_crypt",
]


if __name__ == "__main__":
    raise SystemExit(main())
