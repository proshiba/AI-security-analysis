"""Generate deterministic IOC-only Markdown lists for every published analysis."""

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

HASH_RE = re.compile(r"(?i)(?<![0-9a-f])([0-9a-f]{64}|[0-9a-f]{40}|[0-9a-f]{32})(?![0-9a-f])")
URL_RE = re.compile(r"(?i)https?://[^\s<>\"'`|]+")
ENDPOINT_RE = re.compile(r"(?i)(?<![\w.-])((?:[a-z0-9-]+\.)+[a-z]{2,63}|(?:\d{1,3}\.){3}\d{1,3}):(\d{1,5})(?:/tcp)?")
IP_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
DOMAIN_RE = re.compile(r"(?i)^(?:[a-z0-9-]+\.)+[a-z]{2,63}$")
CASE_HASH_RE = re.compile(r"(?i)^[0-9a-f]{64}$")
RELEVANT_HEADING = re.compile(r"(?i)(ioc|c2|network|infrastructure|endpoint|config|通信|インフラ)")
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
)
EMPTY_VALUES = {"", "none", "none recovered", "n/a", "not available", "unresolved", "unknown", "-"}
CONFIDENCE_ORDER = {"confirmed": 5, "high": 5, "medium": 4, "inferred": 3, "low": 2, "unverified": 1, "recorded": 3}
SOURCE_ORDER = {"directory": 6, "iocs.json": 5, "config.json": 5, "analysis_history": 4, "README": 2}


@dataclass(frozen=True)
class Indicator:
    """One publish-safe indicator with provenance and confidence."""

    type: str
    value: str
    role: str
    confidence: str
    source: str


def sanitize_url(value: str) -> str | None:
    """Remove credentials, query data, and fragments while preserving IOC paths."""
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
    return urllib.parse.urlunsplit((parsed.scheme.lower(), f"{parsed.hostname.lower()}{port}", parsed.path, "", ""))


def indicator_type(value: str) -> str | None:
    """Classify a normalized value as a publishable IOC type."""
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
    if re.search(r"(?i)\.(?:exe|dll|sys|js|jse|vbs|ps1|bin|dat|ini|msi|hta|lnk|asp|php|zip|rar|7z)$", value):
        return "file_name"
    if lowered.startswith("sha256:") and re.fullmatch(r"sha256:[0-9a-f]{64}", lowered):
        return "container_digest"
    if DOMAIN_RE.fullmatch(lowered):
        return "domain"
    return None


def normalize_value(value: str) -> tuple[str, str] | None:
    """Normalize one candidate and return its type and safe value."""
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
    """Map explicit confidence wording to a compact normalized label."""
    lowered = text.lower()
    if any(item in lowered for item in ("confirmed", "確定", "高", "confirmed_static", "confirmed_config")):
        return "confirmed"
    if any(item in lowered for item in ("inferred", "推定", "中")):
        return "inferred"
    if any(item in lowered for item in ("unverified", "未確認", "未検証", "低")):
        return "unverified"
    return default


def indicators_from_text(text: str, role: str, confidence: str, source: str) -> list[Indicator]:
    """Extract hashes and network indicators from an explicitly relevant text fragment."""
    if any(marker in text.lower() for marker in EXCLUSION_MARKERS):
        return []
    values: list[str] = []
    text_without_urls = URL_RE.sub(" ", text)
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
        if kind == "file_name" and role not in {"file_ioc", "config_ioc"}:
            continue
        if (
            kind == "domain"
            and safe_value.rsplit(".", 1)[-1] in {"client", "core"}
            and any(character.isupper() for character in value)
        ):
            continue
        key = (kind, safe_value.lower())
        if key not in seen:
            output.append(Indicator(kind, safe_value, role, confidence, source))
            seen.add(key)
    return output


def _role_from_heading(heading: str) -> str:
    """Return a stable IOC role for an English or Japanese report heading."""
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
    """Extract only values under explicit IOC, C2, network, or config headings."""
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
    """Extract supported indicators from a case-local structured IOC document."""
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
    """Read only normalized extractor findings from a config JSON output."""
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
    """Index analysis-history entries by normalized result directory."""
    value = yaml.safe_load(path.read_text(encoding="utf-8-sig")) or {}
    return {str(item["result_path"]).replace("\\", "/").rstrip("/"): item for item in value.get("analyses", [])}


def analysis_directories(results_root: Path, history: dict[str, dict]) -> list[Path]:
    """Discover individual cases, campaigns, and explicitly indexed incident analyses."""
    output: set[Path] = set()
    for readme in results_root.rglob("README.md"):
        relative = readme.relative_to(results_root)
        parts = relative.parts
        if "cases" in parts:
            index = parts.index("cases")
            if index + 2 == len(parts) - 1 and CASE_HASH_RE.fullmatch(parts[index + 1]):
                output.add(readme.parent)
        if "campaigns" in parts:
            index = parts.index("campaigns")
            if index + 2 == len(parts) - 1:
                output.add(readme.parent)
        if parts and parts[0] in {"supply-chain", "vulnerabilities"} and len(parts) == 3:
            output.add(readme.parent)
    repository = results_root.parent
    for result_path in history:
        directory = repository / result_path
        if (directory / "README.md").exists():
            output.add(directory)
    return sorted(output, key=lambda item: item.as_posix().lower())


def history_indicators(directory: Path, repository: Path, history: dict[str, dict]) -> list[Indicator]:
    """Convert reviewed sample hashes and C2 entries from analysis history."""
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
    """Treat a SHA-256 case-directory name as the submitted sample hash."""
    if CASE_HASH_RE.fullmatch(directory.name):
        return [Indicator("sha256", directory.name.lower(), "submitted_sample", "confirmed", "directory")]
    return []


def merge_indicators(values: Iterable[Indicator]) -> list[Indicator]:
    """Deduplicate indicators while preferring stronger provenance and confidence."""
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


def collect_indicators(directory: Path, repository: Path, history: dict[str, dict]) -> list[Indicator]:
    """Collect all conservative, publish-safe indicators for one analysis."""
    values: list[Indicator] = []
    values.extend(directory_hash_indicator(directory))
    values.extend(history_indicators(directory, repository, history))
    values.extend(indicators_from_ioc_json(directory / "iocs.json"))
    values.extend(indicators_from_config(directory / "config.json"))
    values.extend(read_relevant_markdown(directory / "README.md"))
    return merge_indicators(values)


def render_ioc_list(values: list[Indicator]) -> str:
    """Render one IOC-only Markdown table without behavioral narrative."""
    lines = [
        "# IOC list",
        "",
        "| Type | Value | Role | Confidence | Source |",
        "|---|---|---|---|---|",
    ]
    for item in values:
        cells = [item.type, item.value, item.role, item.confidence, item.source]
        lines.append("| " + " | ".join(cell.replace("|", "\\|").replace("`", "\\`") for cell in cells) + " |")
    return "\n".join(lines) + "\n"


def render_index(results_root: Path, reports: list[tuple[Path, int]]) -> str:
    """Render the repository-wide index of per-analysis IOC lists."""
    lines = ["# IOC list index", "", "| Analysis | IOC list | Entries |", "|---|---|---:|"]
    for directory, count in reports:
        relative = directory.relative_to(results_root).as_posix()
        lines.append(f"| `{relative}` | [IOC-LIST.md]({relative}/IOC-LIST.md) | {count} |")
    return "\n".join(lines) + "\n"


def generate(repository: Path, check: bool = False) -> dict:
    """Generate or verify every per-analysis IOC list and the aggregate index."""
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
    """Build the deterministic IOC-list generator CLI."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, default=Path.cwd())
    parser.add_argument("--check", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    """Generate IOC lists or fail when committed outputs are stale."""
    args = build_parser().parse_args(argv)
    result = generate(args.repository.resolve(), check=args.check)
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
