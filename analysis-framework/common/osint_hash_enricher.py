#!/usr/bin/env python3
"""Enrich low-confidence malware cases with auditable hash-only OSINT.

The collector never uploads a sample and never contacts infrastructure found
inside a sample. Raw API responses are restricted to an ignored private cache;
repository output contains only normalized provider evidence, source status,
references, and a conservative combined attribution.
"""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import time
from typing import Any, Iterable
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit, urlunsplit
from urllib.request import Request, urlopen

import yaml

SHA256 = re.compile(r"^[0-9a-f]{64}$")
OSINT_START = "<!-- hash-osint:start -->"
OSINT_END = "<!-- hash-osint:end -->"
GENERIC_LABELS = {
    "adware", "backdoor", "banker", "dropper", "generic", "hacktool",
    "infostealer", "keylogger", "loader", "malicious", "malware", "rat",
    "ransomware", "riskware", "spyware", "suspicious", "trojan", "unknown",
    "worm",
}
FAMILY_ALIASES = {
    "acrstealer": "acrstealer", "acr stealer": "acrstealer",
    "agenttesla": "agenttesla", "agent tesla": "agenttesla",
    "amadey": "amadey", "amos": "amosstealer", "amosstealer": "amosstealer",
    "atomic stealer": "amosstealer", "atomicstealer": "amosstealer",
    "beavertail": "beavertail", "blankgrabber": "blankgrabber",
    "doenerium": "doenerium", "formbook": "formbook",
    "genesis stealer": "genesisstealer", "genesisstealer": "genesisstealer",
    "invisible ferret": "invisibleferret", "invisibleferret": "invisibleferret",
    "irahook": "irahook", "latrodectus": "latrodectus",
    "exastealer": "exastealer", "exa stealer": "exastealer",
    "lumma": "lummastealer", "lummastealer": "lummastealer",
    "medusastealer": "medusastealer", "nyxstealer": "nyxstealer",
    "pysilon": "pysilon", "redline": "redlinestealer",
    "ottercookie": "ottercookie", "otter cookie": "ottercookie",
    "remcos": "remcosrat", "remcosrat": "remcosrat",
    "remus": "remusstealer", "remusstealer": "remusstealer",
    "rhadamanthys": "rhadamanthys", "salatstealer": "salatstealer",
    "stealc": "stealc", "tinba": "tinba", "twizgrabber": "twizstealer",
    "twizstealer": "twizstealer", "valleyrat": "valleyrat",
    "venomrat": "venomrat", "vidar": "vidar", "wasp stealer": "waspstealer",
    "waspstealer": "waspstealer", "xloader": "formbook", "xworm": "xworm",
}


def validate_sha256(value: str) -> str:
    """Return a normalized SHA-256 or raise ``ValueError``."""
    normalized = str(value or "").strip().lower()
    if not SHA256.fullmatch(normalized):
        raise ValueError(f"invalid SHA-256: {value}")
    return normalized


def load_source_registry(path: Path) -> dict:
    """Load and minimally validate the hash-OSINT source registry."""
    registry = yaml.safe_load(path.read_text(encoding="utf-8-sig"))
    if not isinstance(registry, dict) or registry.get("schema_version") != 1:
        raise ValueError("unsupported OSINT source registry")
    if not isinstance(registry.get("sources"), dict) or not registry["sources"]:
        raise ValueError("OSINT source registry has no sources")
    policy = registry.get("policy") or {}
    if policy.get("sample_submission") != "prohibited":
        raise ValueError("source registry must prohibit sample submission")
    return registry


def load_curated_evidence(path: Path | None) -> dict[str, dict]:
    """Load analyst-reviewed, hash-keyed research evidence for offline replay."""
    if path is None:
        return {}
    document = yaml.safe_load(path.read_text(encoding="utf-8-sig"))
    if not isinstance(document, dict) or document.get("schema_version") != 1:
        raise ValueError("unsupported curated evidence document")
    policy = document.get("policy") or {}
    if policy.get("sample_submission") != "prohibited":
        raise ValueError("curated evidence must prohibit sample submission")
    records = document.get("records") or {}
    if not isinstance(records, dict):
        raise ValueError("curated evidence records must be a mapping")
    return {validate_sha256(digest): record for digest, record in records.items() if isinstance(record, dict)}


def select_targets(summary: dict) -> list[dict]:
    """Return low-confidence or unknown cases in their existing order."""
    return [
        case for case in summary.get("cases") or []
        if "error" not in case and (
            (case.get("attribution") or {}).get("confidence") == "low"
            or (case.get("attribution") or {}).get("family") == "unknown"
        )
    ]


def sanitize_reference(value: str | None) -> str | None:
    """Remove URL user information, query strings, and fragments from references."""
    if not value:
        return None
    try:
        parsed = urlsplit(str(value))
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            return None
        netloc = parsed.hostname.lower()
        if parsed.port:
            netloc += f":{parsed.port}"
        return urlunsplit((parsed.scheme.lower(), netloc, parsed.path or "/", "", ""))
    except ValueError:
        return None


def sanitize_label(value: str) -> str:
    """Return a bounded public label with URLs, emails, and long tokens redacted."""
    label = re.sub(r"https?://\S+", "[URL]", str(value or ""), flags=re.I)
    label = re.sub(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", "[EMAIL]", label, flags=re.I)
    label = re.sub(r"\b[A-Za-z0-9_-]{40,}\b", "[REDACTED]", label)
    return re.sub(r"\s+", " ", label).strip()[:240]




def public_failure_reason(status: str, reason: str | None = None) -> str | None:
    """Return a bounded public reason without API-key names or backend details."""
    if status == "unavailable":
        return "required API credential is not configured"
    if status == "not_queried":
        return "network collection disabled"
    if status == "error":
        return "hash lookup failed"
    return sanitize_label(reason or "") or None
def family_from_label(value: str) -> str | None:
    """Map reviewed family tokens while rejecting generic vendor terminology."""
    lowered = re.sub(r"[_./:-]+", " ", str(value or "").lower())
    compact = re.sub(r"[^a-z0-9]", "", lowered)
    if compact in GENERIC_LABELS:
        return None
    for alias, family in sorted(FAMILY_ALIASES.items(), key=lambda item: len(item[0]), reverse=True):
        alias_compact = re.sub(r"[^a-z0-9]", "", alias)
        if re.search(rf"(?<![a-z0-9]){re.escape(alias)}(?![a-z0-9])", lowered):
            return family
        if len(alias_compact) >= 5 and alias_compact in compact:
            return family
    return None


def fetch_json(
    url: str,
    *,
    headers: dict[str, str] | None = None,
    fields: dict[str, str] | None = None,
    timeout: float = 30.0,
) -> tuple[int, Any]:
    """Fetch one JSON resource and return its HTTP status and decoded body."""
    data = urlencode(fields).encode("ascii") if fields is not None else None
    request = Request(url, data=data, headers={"Accept": "application/json", **(headers or {})})
    try:
        with urlopen(request, timeout=timeout) as response:  # noqa: S310 - registry limits URLs
            body = response.read(8 * 1024 * 1024)
            return int(response.status), json.loads(body.decode("utf-8"))
    except HTTPError as exc:
        body = exc.read(1024 * 1024)
        try:
            payload = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            payload = {"error": f"HTTP {exc.code}"}
        return int(exc.code), payload
    except (URLError, TimeoutError) as exc:
        raise RuntimeError(f"OSINT request failed for {urlsplit(url).hostname}: {exc.reason if isinstance(exc, URLError) else exc}") from exc


def collect_network_source(
    source_id: str,
    sha256: str,
    config: dict,
    *,
    timeout: float = 30.0,
) -> dict:
    """Perform a hash-only lookup for one configured network source."""
    digest = validate_sha256(sha256)
    endpoint = str(config["endpoint"]).format(sha256=digest)
    headers: dict[str, str] = {}
    auth_env = config.get("auth_env")
    api_key = os.environ.get(str(auth_env), "") if auth_env else ""
    if auth_env and not api_key and not config.get("auth_optional"):
        return {"status": "unavailable", "reason": f"{auth_env} is not set", "reference": sanitize_reference(endpoint)}
    if source_id == "virustotal" and api_key:
        headers["x-apikey"] = api_key
    elif source_id == "otx" and api_key:
        headers["X-OTX-API-KEY"] = api_key
    status, payload = fetch_json(endpoint, headers=headers, timeout=timeout)
    if status == 404:
        return {"status": "not_found", "http_status": status, "reference": sanitize_reference(endpoint)}
    if status != 200:
        return {"status": "error", "http_status": status, "reference": sanitize_reference(endpoint)}
    return {"status": "ok", "http_status": status, "reference": sanitize_reference(endpoint), "response": payload}


def _evidence(provider: str, transport: str, label: str, reference: str | None, strength: int = 2) -> dict | None:
    family = family_from_label(label)
    if not family:
        return None
    public_label = sanitize_label(label)
    return {
        "provider": provider.lower().replace(" ", "_"),
        "transport": transport,
        "family": family,
        "label": public_label,
        "strength": strength,
        "reference": sanitize_reference(reference),
    }


def normalize_malwarebazaar(metadata: dict) -> dict:
    """Normalize MalwareBazaar catalog, YARA, and named-provider evidence."""
    evidence: list[dict] = []
    providers: list[dict] = []
    for tag in metadata.get("tags") or []:
        item = _evidence("malwarebazaar_catalog", "malwarebazaar", str(tag), None, 1)
        if item:
            evidence.append(item)
    for rule in metadata.get("yara_rules") or []:
        label = str((rule or {}).get("rule_name") or "")
        item = _evidence("malwarebazaar_yara", "malwarebazaar", label, (rule or {}).get("reference"), 2)
        if item:
            evidence.append(item)

    vendors = metadata.get("vendor_intel") or {}
    field_map = {
        "ANY.RUN": ("malware_family",), "CAPE": ("detection",),
        "CERT-PL_MWDB": ("detection",), "Intezer": ("family_name",),
        "ReversingLabs": ("threat_name",), "Triage": ("malware_family",),
        "VMRay": ("malware_family",), "YOROI_YOMI": ("detection",),
    }
    link_fields = ("link", "report_link", "analysis_url", "report_url")
    family_fields = (
        "malware_family", "family_name", "detection", "threat_name", "threat", "classification", "label",
    )
    for vendor_name, raw in vendors.items():
        records = raw if isinstance(raw, list) else [raw]
        provider_labels: list[str] = []
        reference = None
        assessment = "unknown"
        for record in records:
            if not isinstance(record, dict):
                continue
            reference = reference or next((record.get(key) for key in link_fields if record.get(key)), None)
            verdict = str(record.get("verdict") or record.get("status") or "").lower()
            if "malicious" in verdict or verdict == "malware":
                assessment = "malicious"
            elif "suspicious" in verdict or "likely" in verdict:
                assessment = "suspicious"
            elif verdict in {"known", "clean", "clean1", "clean2", "nothreats", "no_threat"}:
                assessment = "no_threat_observed"
            for field in field_map.get(vendor_name, ()):
                value = record.get(field)
                if value:
                    provider_labels.append(str(value))
            for field in family_fields:
                value = record.get(field)
                if isinstance(value, str) and value:
                    provider_labels.append(value)
                elif isinstance(value, list):
                    provider_labels.extend(str(item) for item in value if isinstance(item, (str, int, float)))
            if vendor_name == "UnpacMe":
                provider_labels.extend(str(value) for value in record.get("detections") or [])
            if vendor_name == "Kaspersky":
                provider_labels.extend(str(value) for value in record.get("detections") or [])
            provider_labels.extend(str(value) for value in record.get("tags") or [])
        providers.append({
            "provider": vendor_name,
            "assessment": assessment,
            "reference": sanitize_reference(reference),
        })
        for label in provider_labels:
            item = _evidence(vendor_name, "malwarebazaar", label, reference, 3)
            if item:
                evidence.append(item)
    return {"providers": providers, "evidence": deduplicate_evidence(evidence)}


def normalize_otx(payload: dict, reference: str | None = None) -> dict:
    """Normalize OTX pulse names and tags as one community-provider vote."""
    evidence: list[dict] = []
    pulses = ((payload or {}).get("pulse_info") or {}).get("pulses") or []
    labels: list[str] = []
    for pulse in pulses:
        if not isinstance(pulse, dict):
            continue
        labels.append(str(pulse.get("name") or ""))
        labels.extend(str(value) for value in pulse.get("tags") or [])
    for label in labels:
        item = _evidence("otx", "otx", label, reference, 2)
        if item:
            evidence.append(item)
    return {"pulse_count": len(pulses), "evidence": deduplicate_evidence(evidence)}


def normalize_virustotal(payload: dict, reference: str | None = None) -> dict:
    """Normalize VirusTotal popular and sandbox family labels without raw AV output."""
    attributes = (((payload or {}).get("data") or {}).get("attributes") or {})
    evidence: list[dict] = []
    popular = attributes.get("popular_threat_classification") or {}
    labels = [str(popular.get("suggested_threat_label") or "")]
    labels.extend(str(item.get("value") or "") for item in popular.get("popular_threat_name") or [] if isinstance(item, dict))
    for label in labels:
        item = _evidence("virustotal_consensus", "virustotal", label, reference, 2)
        if item:
            evidence.append(item)
    for sandbox_name, verdict in (attributes.get("sandbox_verdicts") or {}).items():
        if not isinstance(verdict, dict):
            continue
        for label in verdict.get("malware_names") or []:
            item = _evidence(f"virustotal_{sandbox_name}", "virustotal", str(label), reference, 3)
            if item:
                evidence.append(item)
    return {"evidence": deduplicate_evidence(evidence)}


def normalize_circl(payload: dict) -> dict:
    """Return bounded known-file context from a CIRCL hashlookup match."""
    product = payload.get("ProductCode") if isinstance(payload.get("ProductCode"), dict) else {}
    return {
        "known_file_match": True,
        "trust": payload.get("hashlookup:trust"),
        "source": payload.get("source") or payload.get("db"),
        "file_name": str(payload.get("FileName") or "")[:240] or None,
        "product_name": str(product.get("ProductName") or "")[:240] or None,
    }


def deduplicate_evidence(items: Iterable[dict]) -> list[dict]:
    """De-duplicate normalized evidence while preserving deterministic order."""
    unique: dict[tuple[str, str, str], dict] = {}
    for item in items:
        key = (str(item.get("provider")), str(item.get("family")), str(item.get("label")))
        unique.setdefault(key, item)
    return sorted(unique.values(), key=lambda item: (item["family"], item["provider"], item["label"]))


def normalize_curated_evidence(payload: dict) -> dict:
    """Normalize reviewed research and local-static correlations."""
    if payload.get("reviewed") is not True:
        return {"evidence": [], "context_references": []}
    evidence: list[dict] = []
    for raw in payload.get("evidence") or []:
        if not isinstance(raw, dict):
            continue
        provider = re.sub(r"[^a-z0-9_.-]+", "_", str(raw.get("provider") or "").lower()).strip("_")
        family = family_from_label(str(raw.get("family") or ""))
        label = sanitize_label(str(raw.get("label") or raw.get("family") or ""))
        if not provider or not family or not label:
            continue
        evidence.append({
            "provider": provider,
            "transport": str(raw.get("transport") or "curated_research")[:80],
            "family": family,
            "label": label,
            "strength": min(4, max(1, int(raw.get("strength") or 2))),
            "reference": sanitize_reference(raw.get("reference")),
        })
    references = [
        value for value in (sanitize_reference(item) for item in payload.get("context_references") or []) if value
    ]
    return {"evidence": deduplicate_evidence(evidence), "context_references": sorted(set(references))}


def combine_attribution(static: dict, evidence: Iterable[dict]) -> dict:
    """Combine independent provider votes without double-counting transport layers."""
    items = deduplicate_evidence(evidence)
    providers: dict[str, set[str]] = defaultdict(set)
    strengths: Counter[str] = Counter()
    for item in items:
        providers[item["family"]].add(item["provider"])
        strengths[item["family"]] += int(item.get("strength") or 1)
    static_family = str(static.get("family") or "unknown")
    internal = any(str(item.get("source") or "").startswith("internal_") for item in static.get("evidence") or [])
    if static_family != "unknown" and internal:
        providers[static_family].add("local_static")
        strengths[static_family] += 4
    if not providers:
        return {"family": "unknown", "confidence": "low", "status": "unverified", "provider_count": 0, "providers": [], "conflicts": []}
    ranked = sorted(providers, key=lambda family: (len(providers[family]), strengths[family], family), reverse=True)
    winner = ranked[0]
    conflicts = [family for family in ranked[1:] if providers[family]]
    tied = len(ranked) > 1 and len(providers[ranked[1]]) == len(providers[winner])
    count = len(providers[winner])
    if tied:
        return {"family": "unknown", "confidence": "low", "status": "conflicting", "provider_count": count, "providers": sorted(providers[winner]), "conflicts": ranked}
    confidence = "medium" if count >= 2 and strengths[winner] >= 4 else "low"
    if internal and count >= 3 and confidence == "medium":
        confidence = "high"
    if conflicts:
        confidence = "low"
    return {
        "family": winner,
        "confidence": confidence,
        "status": "inferred" if confidence in {"medium", "high"} else "unverified",
        "provider_count": count,
        "providers": sorted(providers[winner]),
        "conflicts": conflicts,
    }


def build_public_evidence(sha256: str, static: dict, collected: dict, collected_at: str) -> dict:
    """Normalize private source responses into a publish-safe evidence record."""
    digest = validate_sha256(sha256)
    evidence: list[dict] = []
    sources: dict[str, dict] = {}
    known_file_context = None
    for source_id, source in collected.items():
        status = str(source.get("status") or "error")
        public_source = {key: source.get(key) for key in ("status", "http_status", "reference") if source.get(key) is not None}
        public_reason = public_failure_reason(status, source.get("reason"))
        if public_reason:
            public_source["reason"] = public_reason
        if "reference" in public_source:
            public_source["reference"] = sanitize_reference(public_source["reference"])
        response = source.get("response")
        if status == "ok" and source_id == "malwarebazaar":
            normalized = normalize_malwarebazaar(response or {})
            evidence.extend(normalized["evidence"])
            public_source["providers"] = normalized["providers"]
        elif status == "ok" and source_id == "otx":
            normalized = normalize_otx(response or {}, source.get("reference"))
            evidence.extend(normalized["evidence"])
            public_source["pulse_count"] = normalized["pulse_count"]
        elif status == "ok" and source_id == "virustotal":
            normalized = normalize_virustotal(response or {}, source.get("reference"))
            evidence.extend(normalized["evidence"])
        elif status == "ok" and source_id == "circl_hashlookup":
            known_file_context = normalize_circl(response or {})
            public_source.update(known_file_context)
        elif status == "ok" and source_id == "curated_research":
            normalized = normalize_curated_evidence(response or {})
            evidence.extend(normalized["evidence"])
            public_source["evidence_count"] = len(normalized["evidence"])
            public_source["context_references"] = normalized["context_references"]
        sources[source_id] = public_source
    evidence = deduplicate_evidence(evidence)
    return {
        "schema_version": 1,
        "sha256": digest,
        "collected_at": collected_at,
        "query_scope": "hash_metadata_only",
        "sources": sources,
        "family_evidence": evidence,
        "combined_attribution": combine_attribution(static, evidence),
        "known_file_context": known_file_context,
        "sample_submitted": False,
        "sample_executed": False,
        "infrastructure_contacted": False,
    }


def collect_case(
    sha256: str,
    registry: dict,
    *,
    offline_metadata: dict | None = None,
    enabled_sources: set[str] | None = None,
    network: bool = True,
    timeout: float = 30.0,
) -> dict:
    """Collect raw hash evidence for one case without sample submission."""
    digest = validate_sha256(sha256)
    selected = enabled_sources or set(registry["sources"])
    collected: dict[str, dict] = {}
    for source_id, config in registry["sources"].items():
        if source_id not in selected or not config.get("enabled", True):
            continue
        if source_id == "malwarebazaar" and offline_metadata is not None:
            collected[source_id] = {
                "status": "ok", "reference": f"https://bazaar.abuse.ch/sample/{digest}/",
                "response": offline_metadata,
            }
            continue
        if not network:
            collected[source_id] = {"status": "not_queried", "reason": "network collection disabled"}
            continue
        if source_id == "malwarebazaar":
            auth_env = str(config.get("auth_env") or "")
            api_key = os.environ.get(auth_env, "")
            if not api_key:
                collected[source_id] = {"status": "unavailable", "reason": f"{auth_env} is not set"}
                continue
            status, payload = fetch_json(config["endpoint"], headers={"Auth-Key": api_key}, fields={"query": "get_info", "hash": digest}, timeout=timeout)
            if status == 200 and payload.get("query_status") == "ok" and payload.get("data"):
                collected[source_id] = {"status": "ok", "http_status": status, "reference": f"https://bazaar.abuse.ch/sample/{digest}/", "response": payload["data"][0]}
            else:
                collected[source_id] = {"status": "not_found" if payload.get("query_status") == "hash_not_found" else "error", "http_status": status}
        else:
            try:
                collected[source_id] = collect_network_source(source_id, digest, config, timeout=timeout)
            except RuntimeError as exc:
                collected[source_id] = {"status": "error", "reason": f"{type(exc).__name__} during hash lookup"}
    return collected


def render_case_osint(record: dict) -> str:
    """Render one auditable case-level OSINT section."""
    attribution = record["combined_attribution"]
    lines = [
        OSINT_START, "## Hash OSINT enrichment", "",
        f"- Combined family: `{attribution['family']}`",
        f"- Confidence/status: `{attribution['confidence']}` / `{attribution['status']}`",
        f"- Independent agreeing providers: {attribution['provider_count']}",
        f"- Collected at: `{record['collected_at']}`",
        "- Scope: hash metadata only; no sample submission, execution, or infrastructure contact.", "",
        "### Family evidence", "",
    ]
    if record["family_evidence"]:
        for item in record["family_evidence"]:
            reference = f" ([report]({item['reference']}))" if item.get("reference") else ""
            lines.append(f"- `{item['provider']}` -> `{item['family']}` from `{item['label']}`{reference}")
    else:
        lines.append("- No family-specific public label was recovered.")
    if attribution["conflicts"]:
        lines.extend(["", f"- Conflicting family leads retained: `{', '.join(attribution['conflicts'])}`"])
    lines.extend(["", "### Source status", "", "| Source | Status |", "|---|---|"])
    for source_id, source in record["sources"].items():
        lines.append(f"| {source_id} | {source.get('status', 'error')} |")
    lines.extend(["", OSINT_END])
    return "\n".join(lines)


def upsert_marked_section(text: str, section: str) -> str:
    """Insert or replace a hash-OSINT Markdown section idempotently."""
    pattern = re.compile(rf"\n?{re.escape(OSINT_START)}.*?{re.escape(OSINT_END)}\n?", re.S)
    base = pattern.sub("\n", text).rstrip()
    return base + "\n\n" + section.strip() + "\n"


def render_osint_summary(records: list[dict]) -> str:
    """Render aggregate enrichment coverage, upgrades, and remaining unknowns."""
    family_counts = Counter((item["combined_attribution"]["family"], item["combined_attribution"]["confidence"]) for item in records)
    source_counts: dict[str, Counter] = defaultdict(Counter)
    for item in records:
        for source, value in item["sources"].items():
            source_counts[source][value.get("status", "error")] += 1
    identified = sum(item["combined_attribution"]["family"] != "unknown" for item in records)
    supported = sum(item["combined_attribution"]["confidence"] in {"medium", "high"} for item in records)
    unresolved = sum(item["combined_attribution"]["family"] == "unknown" or bool(item["combined_attribution"]["conflicts"]) for item in records)
    lines = [
        "# Hash OSINT enrichment", "",
        "Low-confidence and unidentified cases were correlated using hash-only public intelligence. Family attribution is promoted to medium only when at least two independent providers agree. Aggregator transports do not count as an extra vote.", "",
        "## Outcome", "",
        f"- Targeted cases: {len(records)}", f"- Family lead recovered: {identified}",
        f"- Supported at medium/high confidence: {supported}", f"- Remaining unknown/conflicting: {unresolved}", "",
        "## Family distribution", "", "| Family | Confidence | Count |", "|---|---|---:|",
    ]
    for (family, confidence), count in sorted(family_counts.items()):
        lines.append(f"| {family} | {confidence} | {count} |")
    lines.extend(["", "## Source coverage", "", "| Source | Status | Count |", "|---|---|---:|"])
    for source, counts in sorted(source_counts.items()):
        for status, count in sorted(counts.items()):
            lines.append(f"| {source} | {status} | {count} |")
    lines.extend(["", "## Cases", "", "| SHA-256 | Family | Confidence | Providers |", "|---|---|---|---:|"])
    for item in records:
        attr = item["combined_attribution"]
        lines.append(f"| [{item['sha256']}](cases/{item['sha256']}/README.md) | {attr['family']} | {attr['confidence']} | {attr['provider_count']} |")
    lines.extend(["", "## Interpretation", "", "A missing public label does not make a file benign. CIRCL known-file context is recorded separately and never supplies a malware-family vote. OTX pulse names remain community evidence. A keyed service is marked unavailable when its required credential is absent; no file is uploaded as a fallback."])
    return "\n".join(lines) + "\n"


def update_history_from_enrichment(history_path: Path, records: Iterable[dict]) -> int:
    """Update existing case history blocks with conservative combined attribution."""
    text = history_path.read_text(encoding="utf-8-sig")
    updated = 0
    for record in records:
        digest = record["sha256"]
        pattern = re.compile(rf"(?ms)^  - malware_type:.*?^    sample_sha256: {digest}$.*?(?=^  - malware_type:|\Z)")
        match = pattern.search(text)
        if not match:
            continue
        block = match.group(0)
        attr = record["combined_attribution"]
        supported = attr["family"] != "unknown" and attr["confidence"] in {"medium", "high"}
        malware_type = attr["family"] if supported else "Unclassified"
        note = (
            f"Hash-only OSINT enrichment: {attr['family']} at {attr['confidence']} confidence from "
            f"{attr['provider_count']} independent provider(s); static attribution is retained separately. "
            "No sample submission, execution, or infrastructure contact."
        )
        block = re.sub(r'^  - malware_type:.*$', f"  - malware_type: {json.dumps(malware_type)}", block, count=1, flags=re.M)
        block = re.sub(r'^    analysis_level:.*$', "    analysis_level: static_plus_hash_osint", block, count=1, flags=re.M)
        block = re.sub(r'^      - "family:.*?"$', f"      - {json.dumps('family:' + attr['family'])}", block, count=1, flags=re.M)
        block = re.sub(r'^      - "confidence:.*?"$', f"      - {json.dumps('confidence:' + attr['confidence'])}", block, count=1, flags=re.M)
        block = re.sub(r'^    notes:.*$', f"    notes: {json.dumps(note)}", block, count=1, flags=re.M)
        text = text[:match.start()] + block + text[match.end():]
        updated += 1
    history_path.write_text(text, encoding="utf-8")
    return updated


def enrich_batch(
    summary_path: Path,
    output_root: Path,
    registry_path: Path,
    cache_root: Path,
    *,
    private_manifest: Path | None = None,
    enabled_sources: set[str] | None = None,
    network: bool = True,
    refresh: bool = False,
    delay: float = 0.0,
    history_path: Path | None = None,
    curated_evidence_path: Path | None = None,
) -> dict:
    """Collect, normalize, publish, and summarize one low-confidence batch."""
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    registry = load_source_registry(registry_path)
    offline: dict[str, dict] = {}
    if private_manifest:
        manifest = json.loads(private_manifest.read_text(encoding="utf-8"))
        offline = {str(item.get("sha256")): item.get("detail_metadata") or {} for item in manifest.get("items") or []}
    cache_root.mkdir(parents=True, exist_ok=True)
    collected_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    records: list[dict] = []
    target_hashes = {case["sha256"] for case in select_targets(summary)}
    curated = load_curated_evidence(curated_evidence_path)
    for index, case in enumerate(select_targets(summary), 1):
        digest = validate_sha256(case["sha256"])
        cache_path = cache_root / f"{digest}.json"
        prior_cache = json.loads(cache_path.read_text(encoding="utf-8")) if cache_path.is_file() else {}
        if cache_path.is_file() and not refresh:
            collected = prior_cache["sources"]
            observed_at = prior_cache.get("collected_at") or collected_at
        else:
            refreshed = collect_case(digest, registry, offline_metadata=offline.get(digest), enabled_sources=enabled_sources, network=network)
            collected = dict(prior_cache.get("sources") or {})
            collected.update(refreshed)
            observed_at = collected_at
            cache_path.write_text(json.dumps({"schema_version": 1, "sha256": digest, "collected_at": observed_at, "sources": collected}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
            if delay:
                time.sleep(delay)
        public_collected = dict(collected)
        if digest in curated:
            public_collected["curated_research"] = {"status": "ok", "response": curated[digest]}
        record = build_public_evidence(digest, case.get("attribution") or {}, public_collected, observed_at)
        records.append(record)
        case_dir = output_root / "cases" / digest
        case_dir.mkdir(parents=True, exist_ok=True)
        (case_dir / "osint-evidence.json").write_text(json.dumps(record, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        case_json = case_dir / "case.json"
        if case_json.is_file():
            value = json.loads(case_json.read_text(encoding="utf-8"))
            value["combined_attribution"] = record["combined_attribution"]
            value["hash_osint"] = {"collected_at": record["collected_at"], "evidence_file": "osint-evidence.json", "query_scope": "hash_metadata_only"}
            case_json.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        readme = case_dir / "README.md"
        if readme.is_file():
            readme.write_text(upsert_marked_section(readme.read_text(encoding="utf-8"), render_case_osint(record)), encoding="utf-8")
        print(f"[{index:03d}/{len(target_hashes):03d}] {digest} {record['combined_attribution']['family']} {record['combined_attribution']['confidence']}", flush=True)
    by_hash = {item["sha256"]: item for item in records}
    for case in summary.get("cases") or []:
        if case.get("sha256") in by_hash:
            case["combined_attribution"] = by_hash[case["sha256"]]["combined_attribution"]
            case["hash_osint"] = {"collected_at": by_hash[case["sha256"]]["collected_at"], "evidence_file": f"cases/{case['sha256']}/osint-evidence.json"}
    counts = {
        "targeted": len(records),
        "identified": sum(item["combined_attribution"]["family"] != "unknown" for item in records),
        "supported": sum(item["combined_attribution"]["confidence"] in {"medium", "high"} for item in records),
        "unknown": sum(item["combined_attribution"]["family"] == "unknown" for item in records),
        "conflicting": sum(bool(item["combined_attribution"]["conflicts"]) for item in records),
    }
    counts["unresolved_or_conflicting"] = sum(item["combined_attribution"]["family"] == "unknown" or bool(item["combined_attribution"]["conflicts"]) for item in records)
    osint_summary = {"schema_version": 1, "collected_at": collected_at, "counts": counts, "records": records, "sample_submitted": False, "sample_executed": False, "infrastructure_contacted": False}
    summary["hash_osint_enrichment"] = {"collected_at": collected_at, "counts": counts, "summary_file": "osint-summary.json"}
    summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (output_root / "osint-summary.json").write_text(json.dumps(osint_summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    osint_markdown = render_osint_summary(records)
    (output_root / "OSINT.md").write_text(osint_markdown, encoding="utf-8")
    root_readme = output_root / "README.md"
    if root_readme.is_file():
        root_section = OSINT_START + "\n## Hash OSINT enrichment\n\n" + f"- Targeted: {counts['targeted']}\n- Family lead recovered: {counts['identified']}\n- Medium/high support: {counts['supported']}\n- Remaining unknown/conflicting: {counts['unresolved_or_conflicting']}\n- Details: [OSINT.md](OSINT.md)\n" + OSINT_END
        root_readme.write_text(upsert_marked_section(root_readme.read_text(encoding="utf-8"), root_section), encoding="utf-8")
    history_updated = update_history_from_enrichment(history_path, records) if history_path else 0
    return {**counts, "history_updated": history_updated}


def build_parser() -> argparse.ArgumentParser:
    """Build the hash-only OSINT enrichment command-line parser."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--summary", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--registry", required=True, type=Path)
    parser.add_argument("--cache", required=True, type=Path)
    parser.add_argument("--private-manifest", type=Path)
    parser.add_argument("--history", type=Path)
    parser.add_argument("--source", action="append", dest="sources")
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--refresh", action="store_true")
    parser.add_argument("--curated-evidence", type=Path)
    parser.add_argument("--delay", type=float, default=0.2)
    return parser


def main(argv: list[str] | None = None) -> int:
    """Run hash-only OSINT enrichment and print aggregate counts."""
    args = build_parser().parse_args(argv)
    counts = enrich_batch(
        args.summary, args.output, args.registry, args.cache,
        private_manifest=args.private_manifest,
        enabled_sources=set(args.sources) if args.sources else None,
        network=not args.offline,
        refresh=args.refresh,
        delay=max(0.0, args.delay),
        history_path=args.history,
        curated_evidence_path=args.curated_evidence,
    )
    print(json.dumps(counts, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
