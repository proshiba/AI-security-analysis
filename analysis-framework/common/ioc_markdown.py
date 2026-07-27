"""正規IOC JSONから、公開用Markdownを保守的かつ決定的に描画する。"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Iterable, Mapping

from handler_catalog import sanitize_public_value


IOC_HEADER = "| 種別 (Type) | 値 (Value) | 役割 (Role) | 確度 (Confidence) | 根拠 (Source) |"
IOC_SEPARATOR = "|---|---|---|---|---|"
CONFIRMED_STATIC_CONFIGURATION = "confirmed_static_configuration"
PUBLIC_C2_ENDPOINT_FIELDS = ("url", "host", "domain", "ip", "address", "endpoint")
PUBLIC_C2_FIELDS = (
    *PUBLIC_C2_ENDPOINT_FIELDS,
    "port",
    "transport",
    "protocol",
    "method",
    "path",
    "proxy",
    "reachability",
    "role",
    "confidence",
    "evidence",
)
SHA256_RE = re.compile(r"[0-9a-f]{64}")


@dataclass(frozen=True)
class CanonicalIocView:
    """描画可能と確認できた提出hashと静的network IOC。"""

    sha256: tuple[str, ...]
    network: tuple[dict[str, Any], ...]
    network_contacted: bool
    hash_source: str

    @property
    def entry_count(self) -> int:
        """Markdown表へ描画する行数を返す。"""

        return len(self.sha256) + len(self.network)


def is_canonical_case_ioc_document(document: object) -> bool:
    """publisher形式のcase IOC文書かを、誤昇格しない境界で判定する。"""

    if not isinstance(document, Mapping):
        return False
    hashes = document.get("sha256")
    network = document.get("network")
    hash_source = document.get("hash_source")
    return (
        document.get("schema_version") == 1
        and isinstance(hashes, (str, list))
        and isinstance(network, list)
        and document.get("sample_executed") is False
        and isinstance(document.get("network_contacted"), bool)
        and (
            hash_source is None
            or (isinstance(hash_source, str) and bool(hash_source.strip()))
        )
    )


def _normalize_sha256_values(value: object) -> tuple[str, ...]:
    supplied = [value] if isinstance(value, str) else value
    if not isinstance(supplied, list):
        raise ValueError("canonical iocs.jsonのsha256は文字列または配列で指定してください")
    unique: set[str] = set()
    for item in supplied:
        normalized = str(item).strip().lower() if isinstance(item, str) else ""
        if SHA256_RE.fullmatch(normalized) is None:
            raise ValueError("canonical iocs.jsonに不正なSHA-256があります")
        unique.add(normalized)
    if not unique:
        raise ValueError("canonical iocs.jsonにSHA-256がありません")
    return tuple(sorted(unique))


def normalize_confirmed_network_iocs(
    records: Iterable[object],
) -> list[dict[str, Any]]:
    """確認済み静的設定、role、source、evidenceを持つnetwork IOCだけを返す。"""

    unique: dict[str, dict[str, Any]] = {}
    for candidate in records:
        if not isinstance(candidate, Mapping):
            continue
        sanitized = sanitize_public_value(dict(candidate))
        if not isinstance(sanitized, dict):
            continue
        if sanitized.get("confidence") != CONFIRMED_STATIC_CONFIGURATION:
            continue
        role = sanitized.get("role")
        source = sanitized.get("source")
        evidence = sanitized.get("evidence")
        if not isinstance(role, str) or not role.strip():
            continue
        if not isinstance(source, str) or not source.strip():
            continue
        if not isinstance(evidence, dict) or not evidence:
            continue
        endpoint_present = any(
            isinstance(sanitized.get(key), str)
            and bool(str(sanitized.get(key)).strip())
            and not str(sanitized.get(key)).startswith("[REDACTED_")
            for key in PUBLIC_C2_ENDPOINT_FIELDS
        )
        if not endpoint_present:
            continue
        port = sanitized.get("port")
        if port is not None and (
            isinstance(port, bool)
            or not isinstance(port, int)
            or not 1 <= port <= 65535
        ):
            continue
        record = {key: sanitized[key] for key in PUBLIC_C2_FIELDS if key in sanitized}
        record["source"] = source.strip()
        identity = json.dumps(
            record,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        unique[identity] = record
    return [unique[key] for key in sorted(unique)]


def canonical_ioc_view(
    document: Mapping[str, Any],
    *,
    expected_sha256: str | None = None,
) -> CanonicalIocView:
    """canonical iocs.jsonを検証し、公開可能な行だけへ正規化する。"""

    if not is_canonical_case_ioc_document(document):
        raise ValueError("publisher形式のcanonical iocs.jsonではありません")
    hashes = _normalize_sha256_values(document.get("sha256"))
    if expected_sha256 is not None:
        normalized_expected = expected_sha256.strip().lower()
        if SHA256_RE.fullmatch(normalized_expected) is None:
            raise ValueError("期待するSHA-256が不正です")
        if normalized_expected not in hashes:
            raise ValueError("case directoryとcanonical iocs.jsonのSHA-256が一致しません")
    network = normalize_confirmed_network_iocs(document.get("network") or [])
    hash_source = str(document.get("hash_source") or "MalwareBazaar取得検体").strip()
    return CanonicalIocView(
        hashes,
        tuple(network),
        bool(document["network_contacted"]),
        hash_source,
    )


def _markdown_cell(value: object) -> str:
    return (
        str(value)
        .replace("|", "\\|")
        .replace("`", "\\`")
        .replace("\r", " ")
        .replace("\n", " ")
    )


def _network_ioc_display(record: Mapping[str, Any]) -> tuple[str, str]:
    for key, label in (
        ("url", "URL"),
        ("host", "Host"),
        ("domain", "Domain"),
        ("ip", "IP"),
        ("address", "Address"),
        ("endpoint", "Endpoint"),
    ):
        value = record.get(key)
        if isinstance(value, str) and value:
            if key != "url" and isinstance(record.get("port"), int):
                value = f"{value}:{record['port']}"
            return label, value
    raise ValueError("canonical network IOCに表示可能な接続先がありません")


def _evidence_source(record: Mapping[str, Any]) -> str:
    source = str(record.get("source") or "").strip()
    evidence = record.get("evidence")
    if isinstance(evidence, Mapping):
        evidence_source = str(evidence.get("source_file") or evidence.get("kind") or "").strip()
        if evidence_source:
            return f"{source}; {evidence_source}"
    return source


def render_canonical_ioc_document(
    document: Mapping[str, Any],
    *,
    expected_sha256: str | None = None,
) -> str:
    """canonical iocs.jsonと同じ意味を持つIOC-LIST.mdを描画する。"""

    view = canonical_ioc_view(document, expected_sha256=expected_sha256)
    lines = ["# IOC 一覧", "", IOC_HEADER, IOC_SEPARATOR]
    for digest in view.sha256:
        lines.append(f"| SHA-256 | {digest} | 提出検体 | 確認済み | {_markdown_cell(view.hash_source)} |")
    for record in view.network:
        indicator_type, value = _network_ioc_display(record)
        cells = (
            indicator_type,
            value,
            record["role"],
            record["confidence"],
            _evidence_source(record),
        )
        lines.append("| " + " | ".join(_markdown_cell(cell) for cell in cells) + " |")
    lines.extend(["", "汎用文字列走査だけで得たURL、domain、IPは誤検知を含み得るため、C2へ昇格していません。"])
    if view.network:
        if view.network_contacted:
            lines.append(
                "上記network IOCは、ファミリー固有handlerの静的設定構造で確認済みの値です。"
                "限定的な到達性確認の時刻・送受信範囲・制約はケースREADMEを参照してください。"
            )
        else:
            lines.append(
                "上記network IOCは、ファミリー固有handlerの静的設定構造で確認済みの値だけです。"
                "到達性は検証していません。"
            )
    else:
        lines.append("設定構造またはファミリー固有処理で裏付けられたC2は、本ケースの追加レビュー対象です。")
    lines.append("")
    return "\n".join(lines)


def render_submitted_iocs(
    digest: str,
    network_iocs: Iterable[object] = (),
) -> str:
    """提出hashと確認済み静的network IOCからcanonical Markdownを描画する。"""

    document = {
        "schema_version": 1,
        "sha256": [digest],
        "network": list(network_iocs),
        "sample_executed": False,
        "network_contacted": False,
    }
    return render_canonical_ioc_document(document, expected_sha256=digest)
