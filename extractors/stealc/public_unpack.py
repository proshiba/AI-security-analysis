"""StealC の公開 unpack 結果から終端 config 証拠を検証して抽出する。

このモジュールはprovider JSONをmetadata証拠として扱い、親SHA-256、provider
result ID、raw JSON SHA-256、終端SHA-256、extractor名、設定内URLを相互検証
する。終端PE bytesの独立検証やC2接続を行ったものとは扱わない。
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import urllib.parse
from typing import Any

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
SAFE_BOTNET = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
SAFE_PROVIDER_ID = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")
MAX_RESULTS = 64
MAX_C2_ITEMS = 32
MAX_SETTINGS = 64
MAX_DECRYPTED_STRINGS = 4096
MAX_DECRYPTED_STRING_CHARS = 65536
MAX_STRING_OFFSET = (1 << 64) - 1


class PublicUnpackEvidenceError(ValueError):
    """公開unpack証拠が不正または相互に矛盾するときのエラー。"""


def _sha256(value: object, label: str) -> str:
    digest = str(value or "").lower()
    if not SHA256_RE.fullmatch(digest):
        raise PublicUnpackEvidenceError(f"{label} が正しい SHA-256 ではありません")
    return digest


def _dict(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise PublicUnpackEvidenceError(f"{label} が object ではありません")
    return value


def _list(value: object, label: str, maximum: int) -> list[Any]:
    if not isinstance(value, list) or len(value) > maximum:
        raise PublicUnpackEvidenceError(f"{label} が list ではないか上限を超えています")
    return value


def _http_base(value: object) -> str:
    if not isinstance(value, str):
        raise PublicUnpackEvidenceError("server_urlは文字列ではありません")
    text = value
    try:
        parsed = urllib.parse.urlsplit(text)
        port = parsed.port
    except ValueError as error:
        raise PublicUnpackEvidenceError("server_url を解析できません") from error
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
        or port == 0
    ):
        raise PublicUnpackEvidenceError("server_url の構造が許可範囲外です")
    host = parsed.hostname.lower().rstrip(".")
    if not host or any(ord(character) < 0x21 for character in host):
        raise PublicUnpackEvidenceError("server_url の host が不正です")
    authority = f"[{host}]" if ":" in host else host
    if port is not None:
        authority += f":{port}"
    return f"{parsed.scheme}://{authority}"


def _path(value: object, label: str, *, directory: bool = False) -> str:
    text = str(value or "")
    if (
        not text.startswith("/")
        or len(text) > 512
        or "?" in text
        or "#" in text
        or "\\" in text
        or any(part == ".." for part in text.split("/"))
        or any(ord(character) < 0x20 for character in text)
    ):
        raise PublicUnpackEvidenceError(f"{label} の構造が不正です")
    if directory and not text.endswith("/"):
        raise PublicUnpackEvidenceError(f"{label} は directory path ではありません")
    if not directory and not text.lower().endswith(".php"):
        raise PublicUnpackEvidenceError(f"{label} は PHP gate ではありません")
    return text


def _settings(config: dict[str, Any]) -> dict[str, str]:
    rows = _list(config.get("settings"), "settings", MAX_SETTINGS)
    result: dict[str, str] = {}
    for row in rows:
        item = _dict(row, "setting")
        name_value = item.get("name")
        value = item.get("value")
        if not isinstance(name_value, str):
            raise PublicUnpackEvidenceError("setting nameは文字列ではありません")
        name = name_value
        if name in {"server_url", "landing_path", "lib_path", "botnet_id"}:
            if not isinstance(value, str):
                raise PublicUnpackEvidenceError(f"{name}は文字列ではありません")
            if name in result and result[name] != value:
                raise PublicUnpackEvidenceError(f"{name} が競合しています")
            result[name] = value
    missing = {"server_url", "landing_path", "lib_path", "botnet_id"} - result.keys()
    if missing:
        raise PublicUnpackEvidenceError(f"必須 setting がありません: {sorted(missing)}")
    return result


def _config_c2_values(config: dict[str, Any]) -> tuple[set[str], set[str]]:
    urls: set[str] = set()
    ips: set[str] = set()
    for row in _list(config.get("c2s"), "c2s", MAX_C2_ITEMS):
        item = _dict(row, "c2 item")
        kind_value = item.get("type")
        value_value = item.get("value")
        if not isinstance(kind_value, str) or not isinstance(value_value, str):
            raise PublicUnpackEvidenceError("c2sのtype/valueは文字列ではありません")
        kind = kind_value.lower()
        value = value_value
        if kind == "url":
            urls.add(value)
        elif kind == "ip":
            try:
                ips.add(str(ipaddress.ip_address(value)))
            except ValueError as error:
                raise PublicUnpackEvidenceError("c2s の IP が不正です") from error
    return urls, ips


def _decrypted_string_evidence(config: dict[str, Any]) -> tuple[int, str]:
    rows = _list(
        config.get("decrypted_strings"),
        "decrypted_strings",
        MAX_DECRYPTED_STRINGS,
    )
    normalized: list[dict[str, int | str]] = []
    offsets: set[int] = set()
    for row in rows:
        item = _dict(row, "decrypted string")
        offset = item.get("offset")
        value = item.get("value")
        if (
            isinstance(offset, bool)
            or not isinstance(offset, int)
            or not 0 <= offset <= MAX_STRING_OFFSET
        ):
            raise PublicUnpackEvidenceError("decrypted string offset が不正です")
        if offset in offsets:
            raise PublicUnpackEvidenceError("decrypted string offset が重複しています")
        if (
            not isinstance(value, str)
            or not value.strip()
            or len(value) > MAX_DECRYPTED_STRING_CHARS
        ):
            raise PublicUnpackEvidenceError("decrypted string value が不正です")
        offsets.add(offset)
        normalized.append({"offset": offset, "value": value})
    normalized.sort(key=lambda item: int(item["offset"]))
    serialized = json.dumps(
        normalized,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return len(normalized), hashlib.sha256(serialized).hexdigest()


def _extract_terminal(
    result: dict[str, Any], parent_sha256: str
) -> dict[str, Any] | None:
    hashes = _dict(result.get("hashes"), "result.hashes")
    terminal_sha256 = _sha256(hashes.get("sha256"), "terminal sha256")
    if terminal_sha256 == parent_sha256:
        return None
    wrapper = result.get("config")
    if not isinstance(wrapper, dict):
        return None
    if str(wrapper.get("extractor_name") or "").lower() != "static_stealc":
        return None
    if _sha256(wrapper.get("sha256"), "config sha256") != terminal_sha256:
        raise PublicUnpackEvidenceError(
            "config と terminal result の SHA-256 が一致しません"
        )
    if str(wrapper.get("rule_name") or "").lower() != "stealc":
        raise PublicUnpackEvidenceError("StealC rule による config ではありません")
    config = _dict(wrapper.get("config"), "config.config")
    settings = _settings(config)
    server_url = _http_base(settings["server_url"])
    gate_path = _path(settings["landing_path"], "landing_path")
    library_path = _path(settings["lib_path"], "lib_path", directory=True)
    botnet_id = settings["botnet_id"]
    if not SAFE_BOTNET.fullmatch(botnet_id):
        raise PublicUnpackEvidenceError("botnet_id が許可範囲外です")
    c2_url = urllib.parse.urljoin(server_url + "/", gate_path.lstrip("/"))
    library_url = urllib.parse.urljoin(server_url + "/", library_path.lstrip("/"))
    configured_urls, configured_ips = _config_c2_values(config)
    if c2_url not in configured_urls:
        raise PublicUnpackEvidenceError("settings と c2s の C2 URL が一致しません")
    host = urllib.parse.urlsplit(server_url).hostname or ""
    try:
        host_ip = str(ipaddress.ip_address(host))
    except ValueError:
        host_ip = ""
    if host_ip and host_ip not in configured_ips:
        raise PublicUnpackEvidenceError("server_url と c2s の IP が一致しません")

    string_count, strings_sha256 = _decrypted_string_evidence(config)
    metadata = _dict(
        _dict(result.get("analysis"), "analysis").get("metadata"), "metadata"
    )
    terminal_size = metadata.get("Size")
    if isinstance(terminal_size, bool) or not isinstance(terminal_size, int):
        raise PublicUnpackEvidenceError("terminal sizeが整数ではありません")
    if not 1 <= terminal_size <= 512 * 1024 * 1024:
        raise PublicUnpackEvidenceError("terminal size が許可範囲外です")
    return {
        "sha256": terminal_sha256,
        "size": terminal_size,
        "bytes_available": False,
        "identity": "provider_unpacked_result_sha256",
        "config": {
            "generation": "StealC-v1",
            "server_url": server_url,
            "gate_path": gate_path,
            "c2_url": c2_url,
            "library_path": library_path,
            "library_url": library_url,
            "botnet_id": botnet_id,
            "decrypted_string_count": string_count,
            "decrypted_strings_normalized_sha256": strings_sha256,
        },
    }


def extract_public_unpack_evidence(
    payload: dict[str, Any],
    expected_parent_sha256: str,
    *,
    expected_provider_result_id: str,
    expected_provider_json_sha256: str,
    actual_provider_json_sha256: str,
) -> dict[str, Any]:
    """親hash・provider ID・raw JSON hashをbindしたStealC証拠を返す。"""
    parent_sha256 = _sha256(expected_parent_sha256, "expected parent sha256")
    expected_json_sha256 = _sha256(
        expected_provider_json_sha256, "expected provider JSON sha256"
    )
    actual_json_sha256 = _sha256(
        actual_provider_json_sha256, "actual provider JSON sha256"
    )
    if actual_json_sha256 != expected_json_sha256:
        raise PublicUnpackEvidenceError("provider JSON SHA-256が期待値と一致しません")
    if not SAFE_PROVIDER_ID.fullmatch(expected_provider_result_id):
        raise PublicUnpackEvidenceError("expected provider result IDが不正です")
    provider_result_id_value = payload.get("id")
    if not isinstance(provider_result_id_value, str):
        raise PublicUnpackEvidenceError("provider result IDが文字列ではありません")
    provider_result_id = provider_result_id_value
    if provider_result_id != expected_provider_result_id:
        raise PublicUnpackEvidenceError("provider result IDが期待値と一致しません")
    if _sha256(payload.get("sha256"), "provider parent sha256") != parent_sha256:
        raise PublicUnpackEvidenceError("公開結果が対象親 SHA-256 と一致しません")
    if str(payload.get("status") or "").lower() != "complete":
        raise PublicUnpackEvidenceError("公開 unpack 結果が complete ではありません")
    results = _list(payload.get("results"), "results", MAX_RESULTS)
    root_seen = False
    terminals: list[dict[str, Any]] = []
    for row in results:
        result = _dict(row, "result")
        hashes = _dict(result.get("hashes"), "result.hashes")
        digest = _sha256(hashes.get("sha256"), "result sha256")
        root_seen |= digest == parent_sha256
        terminal = _extract_terminal(result, parent_sha256)
        if terminal is not None:
            terminals.append(terminal)
    if not root_seen:
        raise PublicUnpackEvidenceError("results に対象親 SHA-256 がありません")
    if len(terminals) != 1:
        raise PublicUnpackEvidenceError("StealC terminal config が一意ではありません")
    terminal = terminals[0]
    return {
        "schema_version": 2,
        "family": "stealc",
        "parent_sha256": parent_sha256,
        "evidence_binding": {
            "provider_result_id": provider_result_id,
            "provider_json_sha256": actual_json_sha256,
            "immutable_snapshot_required": True,
        },
        "terminal_payload": terminal,
        "recovery": {
            "terminal_payload_identified": True,
            "terminal_payload_bytes_retrieved": False,
            "terminal_config_recovered": True,
            "source": "public_unpack_provider_result",
            "provider_result_id": provider_result_id,
        },
        "trust_boundary": {
            "provider_result_role": "metadata_and_static_config_evidence",
            "raw_json_hash_bound": True,
            "terminal_bytes_independently_verified": False,
            "function_analysis_completed": False,
        },
        "c2_assessment": {
            "static_config_confirmed": True,
            "endpoint": terminal["config"]["c2_url"],
            "protocol_profile": "stealc_v1_multipart_hwid_build",
            "active_probe_status": "protocol_profile_required",
            "reason": (
                "保存済み通信では登録拒否応答だけを確認しており、成功応答とtask schemaが不足するため、"
                "能動probe profileは生成しません。"
            ),
        },
        "limitations": [
            "終端payloadのSHA-256とconfigは公開unpack結果から復元しましたが、終端bytesは取得できていません。",
            "provider JSONは親・終端hashとconfigの相互一致を検証しましたが、終端PEの独立再解析ではありません。",
            "endpointへ接続しておらず、現在の稼働状態は未検証です。",
        ],
        "safety": {
            "sample_executed_locally": False,
            "endpoint_contacted": False,
            "credentials_published": False,
        },
    }


__all__ = [
    "PublicUnpackEvidenceError",
    "extract_public_unpack_evidence",
]
