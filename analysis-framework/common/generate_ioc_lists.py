"""公開済み解析ごとに、決定的な IOC 専用 Markdown 一覧を生成する。"""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import urllib.parse
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

import yaml

from result_layout import resolve_catalog_case_path


IOC_HEADER = "| 種別 (Type) | 値 (Value) | 役割 (Role) | 確度 (Confidence) | 根拠 (Source) |"
IOC_SEPARATOR = "|---|---|---|---|---|"

HASH_RE = re.compile(r"(?i)(?<![0-9a-f])([0-9a-f]{64}|[0-9a-f]{40}|[0-9a-f]{32})(?![0-9a-f])")
URL_RE = re.compile(r"(?i)https?://[^\s<>\"'`|]+")
ENDPOINT_RE = re.compile(r"(?i)(?<![\w.-])((?:[a-z0-9-]+\.)+[a-z]{2,63}|(?:\d{1,3}\.){3}\d{1,3}):(\d{1,5})(?:/tcp)?")
IP_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
DOMAIN_RE = re.compile(r"(?i)^(?:[a-z0-9-]+\.)+[a-z]{2,63}$")
CASE_HASH_RE = re.compile(r"(?i)^[0-9a-f]{64}$")
RELEVANT_HEADING = re.compile(
    r"(?i)(ioc|c2|network|infrastructure|endpoint|config|通信|ネットワーク|インフラ|エンドポイント|設定|侵害指標)"
)
REFERENCE_HOSTS = {
    "tria.ge",
    "bazaar.abuse.ch",
    "github.com",
    "gitlab.com",
    "virustotal.com",
    "www.virustotal.com",
    "any.run",
    "app.any.run",
}
PUBLIC_RESOLVER_IPS = {"1.1.1.1", "8.8.4.4", "8.8.8.8", "9.9.9.9", "119.29.29.29"}
EXCLUSION_MARKERS = (
    "not an ioc",
    "not a standalone ioc",
    "not_c2",
    "context_only",
    "context only",
    "単独hashだけでは悪性判定不可",
    "単独ではioc",
    "iocとして扱わない",
    "signed host",
    "sideload host",
    "valid signature",
    "署名付きhost",
    "有効署名",
    "悪性iocではない",
    "c2から除外",
    "正規アプリ側",
    "block iocとしては低品質",
    "legitimate ",
    "shared edge",
    "cloudflare edge",
    "cloudflare-関連",
    "インフラ文脈のみ",
    "インフラ 文脈 のみ",
)
EMPTY_VALUES = {"", "none", "none recovered", "n/a", "not available", "unresolved", "unknown", "-"}
CONFIDENCE_ORDER = {"confirmed": 5, "high": 5, "medium": 4, "inferred": 3, "low": 2, "unverified": 1, "recorded": 3}
SOURCE_ORDER = {"directory": 6, "iocs.json": 5, "config.json": 5, "analysis_history": 4, "README": 2}
NON_IOC_ROLES = {
    "certificate_service",
    "documentation_reference",
    "host_discovery_service",
}
NON_IOC_MARKERS = {"context_only", "not_ioc", "not_c2", "dual-use"}
IOC_TYPE_LABELS = {
    "domain": "ドメイン",
    "endpoint": "接続先",
}
IOC_CONFIDENCE_LABELS = {
    "confirmed": "確認済み",
    "high": "高",
    "inferred": "推定",
    "low": "低",
    "medium": "中",
    "recorded": "記録済み",
    "unverified": "未検証",
}
IOC_ROLE_LABELS = {"delivery": "配布"}


@dataclass(frozen=True)
class Indicator:
    """根拠と確度を持つ、公開可能な単一の指標。"""

    type: str
    value: str
    role: str
    confidence: str
    source: str


def sanitize_url(value: str) -> str | None:
    """IOC のパスを維持しながら、認証情報、クエリ、フラグメントを除去する。"""
    try:
        parsed = urllib.parse.urlsplit(value.rstrip(".,;)]}"))
    except ValueError:
        return None
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        return None
    try:
        port = f":{parsed.port}" if parsed.port else ""
    except ValueError:
        return None
    host = parsed.hostname.lower()
    try:
        if ipaddress.ip_address(host).version == 6:
            host = f"[{host}]"
    except ValueError:
        pass
    return urllib.parse.urlunsplit((parsed.scheme.lower(), f"{host}{port}", parsed.path, "", ""))


def indicator_type(value: str) -> str | None:
    """正規化済みの値を、公開可能な IOC 種別へ分類する。"""
    lowered = value.lower().strip()
    if lowered in EMPTY_VALUES or "<redacted>" in lowered:
        return None
    if re.fullmatch(r"[0-9a-f]{64}", lowered):
        return "sha256"
    if re.fullmatch(r"[0-9a-f]{40}", lowered):
        return "sha1"
    if re.fullmatch(r"[0-9a-f]{32}", lowered):
        return "md5"
    if lowered.startswith(("http://", "https://")):
        return "url"
    match = ENDPOINT_RE.fullmatch(lowered)
    if match and 0 < int(match.group(2)) <= 65535:
        return "endpoint"
    try:
        return "ipv4" if ipaddress.ip_address(lowered).version == 4 else "ipv6"
    except ValueError:
        pass
    if re.match(r"(?i)^(?:[a-z]:\\|%[a-z_]+%\\|/)", value):
        return "file_path"
    if re.search(
        r"(?i)\.(?:exe|dll|sys|js|jse|vbs|ps1|bin|dat|ini|msi|hta|lnk|asp|php|zip|rar|7z|json|csv|ya?ml|md|txt)$",
        value,
    ):
        return "file_name"
    if lowered.startswith("sha256:") and re.fullmatch(r"sha256:[0-9a-f]{64}", lowered):
        return "container_digest"
    if DOMAIN_RE.fullmatch(lowered):
        return "domain"
    return None


def normalize_value(value: str) -> tuple[str, str] | None:
    """単一の候補を正規化し、種別と安全な値を返す。"""
    cleaned = value.strip().strip("`\"'").rstrip(".,;)]}")
    if cleaned.lower().endswith("/tcp") and ENDPOINT_RE.fullmatch(cleaned.lower()):
        cleaned = cleaned[:-4]
    if cleaned.lower().startswith(("http://", "https://")):
        cleaned = sanitize_url(cleaned) or ""
        if cleaned:
            hostname = urllib.parse.urlsplit(cleaned).hostname or ""
            if hostname.lower() in REFERENCE_HOSTS:
                return None
    if "@" in cleaned and not cleaned.lower().startswith(("http://", "https://")):
        return None
    kind = indicator_type(cleaned)
    if not kind:
        return None
    if kind == "ipv4" and cleaned in PUBLIC_RESOLVER_IPS:
        return None
    if kind == "endpoint":
        endpoint_host = cleaned.rsplit(":", 1)[0].lower()
        if endpoint_host in PUBLIC_RESOLVER_IPS or endpoint_host in REFERENCE_HOSTS:
            return None
    if kind == "domain" and cleaned.lower() in REFERENCE_HOSTS:
        return None
    return kind, cleaned.lower() if kind in {"domain", "endpoint", "ipv4", "ipv6"} else cleaned


def confidence_from_text(text: str, default: str = "recorded") -> str:
    """明示された確度表現を、短い正規化ラベルへ変換する。"""
    lowered = text.lower()
    if any(item in lowered for item in ("confirmed", "確定", "高", "confirmed_static", "confirmed_config")):
        return "confirmed"
    if any(item in lowered for item in ("inferred", "推定", "中")):
        return "inferred"
    if any(item in lowered for item in ("unverified", "未確認", "未検証", "低")):
        return "unverified"
    return default


def indicators_from_text(text: str, role: str, confidence: str, source: str) -> list[Indicator]:
    """明示的に関連する文章片からハッシュとネットワーク指標を抽出する。"""
    if any(marker in text.lower() for marker in EXCLUSION_MARKERS):
        return []
    values: list[str] = []
    text_without_urls = URL_RE.sub(" ", text)
    hash_context = f"{source} {text}".lower()
    allow_hash = role == "file_ioc" or any(
        marker in hash_context
        for marker in ("ioc", "侵害指標", "hash", "ハッシュ", "digest", "sha1", "sha-1", "sha256", "sha-256", "md5", "fingerprint", "指紋")
    )
    if allow_hash:
        values.extend(match.group(1) for match in HASH_RE.finditer(text_without_urls))
    values.extend(match.group(0) for match in URL_RE.finditer(text))
    values.extend(f"{match.group(1)}:{match.group(2)}" for match in ENDPOINT_RE.finditer(text))
    values.extend(IP_RE.findall(text))
    for value in re.findall(r"`([^`\n]+)`", text):
        if not re.search(r"\s", value) and not value.startswith(("ip:", "hostname:", "hash:")):
            values.append(value)
    output = []
    seen: set[tuple[str, str]] = set()
    for value in values:
        normalized = normalize_value(value)
        if not normalized:
            continue
        kind, safe_value = normalized
        if kind in {"file_name", "file_path"}:
            continue
        if kind in {"md5", "sha1", "sha256", "container_digest"} and not allow_hash:
            continue
        if kind == "domain" and safe_value.rsplit(".", 1)[-1] in {"client", "core"}:
            continue
        key = (kind, safe_value.lower())
        if key not in seen:
            output.append(Indicator(kind, safe_value, role, confidence, source))
            seen.add(key)
    return output


def _role_from_heading(heading: str) -> str:
    """英語または日本語の報告書見出しから、安定した IOC 役割を返す。"""
    lowered = heading.lower()
    if "c2" in lowered:
        return "c2_or_network_ioc"
    if "file" in lowered or "ファイル" in heading:
        return "file_ioc"
    if "infrastructure" in lowered or "インフラ" in heading:
        return "infrastructure_ioc"
    if "network" in lowered or "通信" in heading:
        return "network_ioc"
    if "config" in lowered or "設定" in heading:
        return "config_ioc"
    if "endpoint" in lowered:
        return "endpoint_ioc"
    return "recorded_ioc"


def read_relevant_markdown(path: Path) -> list[Indicator]:
    """明示的な IOC、C2、ネットワーク、設定の見出し配下だけから値を抽出する。"""
    if not path.exists():
        return []
    heading = ""
    active = False
    output: list[Indicator] = []
    for line in path.read_text(encoding="utf-8-sig", errors="replace").splitlines():
        match = re.match(r"^#{2,6}\s+(.+?)\s*$", line)
        if match:
            heading = match.group(1).strip()
            active = bool(RELEVANT_HEADING.search(heading)) and not re.search(
                r"(?i)(shodan|sigma|yara|detection|検知)", heading
            )
            continue
        if not active or not line.strip():
            continue
        confidence = confidence_from_text(line)
        role = _role_from_heading(heading)
        output.extend(indicators_from_text(line, role, confidence, f"README:{heading}"))
    return output


def indicators_from_ioc_json(path: Path) -> list[Indicator]:
    """ケース内の構造化 IOC 文書から、対応する指標を抽出する。"""
    if not path.exists():
        return []
    value = json.loads(path.read_text(encoding="utf-8-sig"))
    output: list[Indicator] = []

    def visit(node, role: str = "recorded_ioc", confidence: str = "recorded") -> None:
        if isinstance(node, dict):
            local_role = str(node.get("role", role))
            local_confidence = str(node.get("confidence", confidence))
            exclusion = f"{local_role} {local_confidence}".lower()
            if any(marker in exclusion for marker in ("context_only", "not_ioc", "not_c2", "dual-use")):
                return
            for key in ("sha256", "sha1", "sha1_thumbprint", "md5", "digest", "value"):
                if key in node and isinstance(node[key], str):
                    normalized = normalize_value(node[key])
                    if normalized:
                        kind, safe_value = normalized
                        output.append(Indicator(kind, safe_value, local_role, local_confidence, "iocs.json"))
            for key, child in node.items():
                if key not in {
                    "sha256",
                    "sha1",
                    "sha1_thumbprint",
                    "md5",
                    "digest",
                    "value",
                    "role",
                    "confidence",
                    "network_contacted",
                    "schema_version",
                }:
                    visit(child, key, local_confidence)
        elif isinstance(node, list):
            for child in node:
                visit(child, role, confidence)
        elif isinstance(node, str):
            for indicator in indicators_from_text(node, role, confidence, "iocs.json"):
                output.append(indicator)

    visit(value)
    return output


def indicators_from_config(path: Path) -> list[Indicator]:
    """設定 JSON 出力から、正規化済み抽出結果だけを読み取る。"""
    if not path.exists():
        return []
    value = json.loads(path.read_text(encoding="utf-8-sig"))
    output = []
    for finding in value.get("findings", []):
        role = str(finding.get("role", finding.get("kind", "config")))
        confidence = str(finding.get("confidence", "recorded"))
        exclusion = f"{role} {confidence}".lower()
        if any(marker in exclusion for marker in ("context_only", "not_ioc", "not_c2", "dual-use")):
            continue
        if not isinstance(finding, dict) or not isinstance(finding.get("value"), str):
            continue
        normalized = normalize_value(finding["value"])
        if not normalized:
            continue
        kind, safe_value = normalized
        output.append(
            Indicator(
                kind,
                safe_value,
                role,
                confidence,
                "config.json",
            )
        )
    return output


def load_history(path: Path) -> dict[str, dict]:
    """正規化した結果ディレクトリ別に、解析履歴の項目を索引化する。"""
    value = yaml.safe_load(path.read_text(encoding="utf-8-sig")) or {}
    return {str(item["result_path"]).replace("\\", "/").rstrip("/"): item for item in value.get("analyses", [])}


def analysis_directories(results_root: Path, history: dict[str, dict]) -> list[Path]:
    """固定レイアウトの case、campaign、research、collection source を列挙する。"""
    output: set[Path] = set()
    for readme in results_root.rglob("README.md"):
        relative = readme.relative_to(results_root)
        parts = relative.parts
        parent_parts = relative.parent.parts
        if "cases" in parts:
            index = parts.index("cases")
            if index + 2 == len(parts) - 1 and CASE_HASH_RE.fullmatch(parts[index + 1]):
                output.add(readme.parent)
        if "campaigns" in parent_parts:
            index = parent_parts.index("campaigns")
            if len(parent_parts) - index - 1 in {1, 2}:
                output.add(readme.parent)
        if (
            len(parent_parts) >= 3
            and parent_parts[0] == "research"
            and parent_parts[1] in {"supply-chain", "vulnerabilities", "news"}
        ):
            output.add(readme.parent)
        # 移行前の読取り互換。新規 writer は必ず research/ 以下へ出力する。
        if parts and parts[0] in {"supply-chain", "vulnerabilities", "news"} and len(parts) == 3:
            output.add(readme.parent)
    for manifest_path in results_root.rglob("manifest.json"):
        directory = manifest_path.parent
        if not (directory / "README.md").is_file():
            continue
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8-sig"))
        except (OSError, ValueError):
            continue
        relative = directory.relative_to(results_root).parts
        canonical_source = (
            len(relative) == 4
            and relative[0] == "collections"
            and relative[2] == "sources"
        )
        legacy_source = (directory / "cases").is_dir()
        if (
            manifest.get("source") == "MalwareBazaar exact signature query"
            and (canonical_source or legacy_source)
        ):
            output.add(directory)
    repository = results_root.parent
    for result_path in history:
        directory = repository / result_path
        if (directory / "README.md").exists():
            output.add(directory)
    return sorted(output, key=lambda item: item.as_posix().lower())


def history_indicators(directory: Path, repository: Path, history: dict[str, dict]) -> list[Indicator]:
    """解析履歴で確認済みの検体ハッシュと C2 項目を指標へ変換する。"""
    key = directory.relative_to(repository).as_posix().rstrip("/")
    item = history.get(key)
    if not item:
        return []
    output = []
    sample = normalize_value(str(item.get("sample_sha256", "")))
    if sample:
        output.append(Indicator(sample[0], sample[1], "submitted_sample", "confirmed", "analysis_history"))
    for value in item.get("c2", []) or []:
        output.extend(
            indicators_from_text(str(value), "c2_or_infrastructure_as_recorded", "recorded", "analysis_history")
        )
    return output


def directory_hash_indicator(directory: Path) -> list[Indicator]:
    """SHA-256 形式のケースディレクトリ名を、提出検体ハッシュとして扱う。"""
    if CASE_HASH_RE.fullmatch(directory.name):
        return [Indicator("sha256", directory.name.lower(), "submitted_sample", "confirmed", "directory")]
    return []


def merge_indicators(values: Iterable[Indicator]) -> list[Indicator]:
    """より強い根拠と確度を優先しながら、指標を重複排除する。"""
    selected: dict[tuple[str, str], Indicator] = {}
    for item in values:
        key = (item.type, item.value.lower())
        current = selected.get(key)
        if current is None:
            selected[key] = item
            continue
        current_score = (
            SOURCE_ORDER.get(current.source.split(":", 1)[0], 1),
            CONFIDENCE_ORDER.get(current.confidence.lower(), 2),
        )
        new_score = (
            SOURCE_ORDER.get(item.source.split(":", 1)[0], 1),
            CONFIDENCE_ORDER.get(item.confidence.lower(), 2),
        )
        if new_score > current_score:
            selected[key] = item
    return sorted(selected.values(), key=lambda item: (item.type, item.value.lower(), item.role.lower()))


def indicators_from_reviewed_findings(hashes: Iterable[str], findings: Iterable[dict]) -> list[Indicator]:
    """横断報告用に、確認済みハッシュと構造化所見を正規化する。"""
    unique: dict[tuple[str, str], Indicator] = {}
    for value in hashes:
        normalized = normalize_value(str(value))
        if not normalized or normalized[0] != "sha256":
            continue
        kind, safe_value = normalized
        indicator = Indicator(kind, safe_value, "submitted_sample", "confirmed", "manifest")
        unique.setdefault((kind, safe_value.lower()), indicator)
    for item in findings:
        role = str(item.get("role") or "candidate_infrastructure")
        confidence = str(item.get("confidence") or "candidate")
        exclusion = f"{role} {confidence}".lower()
        if role.lower() in NON_IOC_ROLES or any(marker in exclusion for marker in NON_IOC_MARKERS):
            continue
        normalized = normalize_value(str(item.get("value") or ""))
        if not normalized:
            continue
        kind, safe_value = normalized
        indicator = Indicator(
            kind,
            safe_value,
            role,
            confidence,
            str(item.get("source") or "static_analysis"),
        )
        unique.setdefault((kind, safe_value.lower()), indicator)
    return sorted(unique.values(), key=lambda item: (item.type, item.value.lower(), item.role.lower()))


def _profile_run_indicators(directory: Path, results_root: Path) -> list[Indicator] | None:
    """検体アーカイブに触れず、公開済みファミリ別実行結果を一件読み込む。"""
    manifest_path = directory / "manifest.json"
    if not manifest_path.is_file():
        return None
    manifest = json.loads(manifest_path.read_text(encoding="utf-8-sig"))
    if manifest.get("source") != "MalwareBazaar exact signature query":
        return None
    family = str(manifest.get("family") or "")
    hashes = [str(item.get("sha256") or "").lower() for item in manifest.get("items") or []]
    findings: list[dict] = []
    for digest in hashes:
        normalized = normalize_value(digest)
        if not normalized or normalized[0] != "sha256":
            raise ValueError(f"invalid aggregate manifest hash: {manifest_path}")
        indicator_path = (
            resolve_catalog_case_path(results_root, digest, family=family)
            / "indicators.json"
        )
        if not indicator_path.is_file():
            raise ValueError(f"missing aggregate case indicators: {indicator_path}")
        case = json.loads(indicator_path.read_text(encoding="utf-8-sig"))
        if str((case.get("source") or {}).get("sha256") or "").lower() != digest:
            raise ValueError(f"aggregate case hash mismatch: {indicator_path}")
        findings.extend((case.get("static_analysis") or {}).get("findings") or [])
    return indicators_from_reviewed_findings(hashes, findings)


def collect_indicators(directory: Path, repository: Path, history: dict[str, dict]) -> list[Indicator]:
    """単一解析について、保守的かつ公開可能な指標をすべて収集する。"""
    aggregate = _profile_run_indicators(directory, repository / "analysis-results")
    if aggregate is not None:
        return aggregate
    values: list[Indicator] = []
    values.extend(directory_hash_indicator(directory))
    values.extend(history_indicators(directory, repository, history))
    values.extend(indicators_from_ioc_json(directory / "iocs.json"))
    values.extend(indicators_from_config(directory / "config.json"))
    values.extend(read_relevant_markdown(directory / "README.md"))
    return merge_indicators(values)


def render_ioc_list(values: list[Indicator]) -> str:
    """挙動説明を混在させず、日本語見出しの IOC 表を描画する。"""
    lines = [
        "# IOC 一覧",
        "",
        IOC_HEADER,
        IOC_SEPARATOR,
    ]
    for item in values:
        cells = [
            IOC_TYPE_LABELS.get(item.type, item.type),
            item.value,
            IOC_ROLE_LABELS.get(item.role, item.role),
            IOC_CONFIDENCE_LABELS.get(item.confidence, item.confidence),
            item.source,
        ]
        lines.append("| " + " | ".join(cell.replace("|", "\\|").replace("`", "\\`") for cell in cells) + " |")
    return "\n".join(lines) + "\n"


def render_index(results_root: Path, reports: list[tuple[Path, int]]) -> str:
    """解析単位の IOC 一覧を横断する日本語索引を描画する。"""
    lines = [
        "# IOC 一覧索引",
        "",
        "| 解析 (Analysis) | IOC 一覧 | 件数 (Entries) |",
        "|---|---|---:|",
    ]
    for directory, count in reports:
        relative = directory.relative_to(results_root).as_posix()
        lines.append(f"| `{relative}` | [IOC-LIST.md]({relative}/IOC-LIST.md) | {count} |")
    return "\n".join(lines) + "\n"


def generate(repository: Path, check: bool = False) -> dict:
    """解析単位の IOC 一覧と横断索引を、すべて生成または検証する。"""
    results_root = repository / "analysis-results"
    history = load_history(repository / "analysis_history.yaml")
    directories = analysis_directories(results_root, history)
    mismatches = []
    reports = []
    for directory in directories:
        values = collect_indicators(directory, repository, history)
        content = render_ioc_list(values)
        target = directory / "IOC-LIST.md"
        reports.append((directory, len(values)))
        if check:
            if not target.exists() or target.read_text(encoding="utf-8-sig") != content:
                mismatches.append(str(target.relative_to(repository)))
        else:
            target.write_text(content, encoding="utf-8", newline="\n")
    index_content = render_index(results_root, reports)
    index_target = results_root / "IOC-INDEX.md"
    if check:
        if not index_target.exists() or index_target.read_text(encoding="utf-8-sig") != index_content:
            mismatches.append(str(index_target.relative_to(repository)))
    else:
        index_target.write_text(index_content, encoding="utf-8", newline="\n")
    if check and mismatches:
        raise ValueError("outdated IOC lists: " + ", ".join(mismatches[:20]))
    return {"analyses": len(reports), "indicators": sum(count for _, count in reports), "mismatches": mismatches}


def build_parser() -> argparse.ArgumentParser:
    """決定的な IOC 一覧生成用 CLI を構築する。"""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, default=Path.cwd())
    parser.add_argument("--check", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    """IOC 一覧を生成し、検証時に保存済み出力が古ければ失敗する。"""
    args = build_parser().parse_args(argv)
    result = generate(args.repository.resolve(), check=args.check)
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
