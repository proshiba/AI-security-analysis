#!/usr/bin/env python3
"""Statically classify a newest-first MalwareBazaar unknown/stealer batch."""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import hashlib
import ipaddress
import importlib.util
import json
from pathlib import Path
import re
import sys
from urllib.parse import urlsplit, urlunsplit

REPO = Path(__file__).parents[2]
SRC = REPO / "analysis-framework" / "src"
COMMON = REPO / "analysis-framework" / "common"
for location in (REPO, SRC, COMMON):
    if str(location) not in sys.path:
        sys.path.insert(0, str(location))

import yara  # noqa: E402

from asa.discovery import infer_family  # noqa: E402
from extractors.config_extractor import EXTRACTORS  # noqa: E402
from malware_io import read_single_aes_zip_member, write_json  # noqa: E402
from unpackers.asar_unpacker import recover_asar  # noqa: E402
from unpackers.electron_nsis_unpacker import recover_electron_asars  # noqa: E402
from unpackers.javascript_obfuscator import (  # noqa: E402
    deobfuscate_plain_string_array,
    deobfuscate_string_array,
)
from unpackers.static_unpacker import detect_format, unpack_bytes  # noqa: E402

ASCII = re.compile(rb"[\x20-\x7e]{5,}")
WIDE = re.compile(rb"(?:[\x20-\x7e]\x00){5,}")
URL = re.compile(r"https?://[^\s\"'`<>]{4,512}", re.I)
IP = re.compile(r"(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?")
GENERIC_LABELS = {
    "unknown", "malware", "generic", "stealer", "infostealer", "loader",
    "dropper", "rat", "trojan", "spyware", "exe", "dll", "js", "jar",
    "python", "electron", "signed", "psw",
}
FAMILY_ALIASES = {
    "agenttesla": "agenttesla", "agent tesla": "agenttesla",
    "amadey": "amadey", "amos": "amosstealer", "amosstealer": "amosstealer",
    "atomicstealer": "amosstealer", "atomic stealer": "amosstealer",
    "beavertail": "beavertail", "blankgrabber": "blankgrabber",
    "blank grabber": "blankgrabber", "doenerium": "doenerium",
    "formbook": "formbook", "xloader": "formbook",
    "genesisstealer": "genesisstealer", "genesis stealer": "genesisstealer",
    "irahook": "irahook", "latrodectus": "latrodectus",
    "lumma": "lummastealer", "lummastealer": "lummastealer",
    "medusastealer": "medusastealer", "nyxstealer": "nyxstealer",
    "pysilon": "pysilon", "remcos": "remcosrat", "remcosrat": "remcosrat",
    "remus": "remusstealer", "remusstealer": "remusstealer",
    "salatstealer": "salatstealer", "stealc": "stealc",
    "twizgrabber": "twizstealer", "twizstealer": "twizstealer",
    "valleyrat": "valleyrat", "venomrat": "venomrat", "vidar": "vidar",
    "wasp stealer": "waspstealer", "waspstealer": "waspstealer",
    "xworm": "xworm",
    "asyncrat": "asyncrat", "async rat": "asyncrat",
    "quasarrat": "quasarrat", "quasar rat": "quasarrat",
    "njrat": "njrat", "bladabindi": "njrat",
    "darkcomet": "darkcomet", "dark comet": "darkcomet",
    "dcrat": "dcrat", "darkcrystalrat": "dcrat",
    "redlinestealer": "redlinestealer", "redline stealer": "redlinestealer",
    "snakekeylogger": "snakekeylogger", "snake keylogger": "snakekeylogger",
    "guloader": "guloader", "gu loader": "guloader",
    "hijackloader": "hijackloader", "hijack loader": "hijackloader",
}
SOURCE_WEIGHT = {
    "internal_detector": 4,
    "internal_inference": 4,
    "internal_yara": 4,
    "internal_shape": 3,
    "external_yara": 3,
    "external_sandbox": 2,
    "source_tag": 1,
}
MAX_LAYER_SIZE = 64 * 1024 * 1024
MAX_LAYERS = 48
ROOT_FULL_SCAN_LIMIT = 32 * 1024 * 1024
STRICT_INTERNAL_FORMATS = {
    "agenttesla": {"pe"}, "stealc": {"pe"},
}
BENIGN_URL_HOSTS = {
    "api.ipify.org", "archiverjs.com", "axios-http.com", "blog.caustik.com",
    "blog.izs.me", "caolan.github.io", "christalkington.com", "code.google.com",
    "developer.mozilla.org", "dom.spec.whatwg.org", "editorconfig.org",
    "en.wikipedia.org", "github.com", "invisible-island.net", "ipinfo.io",
    "luajit.org", "narwhaljs.org", "nodejs.org", "oneocsp.microsoft.com",
    "schemas.microsoft.com", "wiki.commonjs.org", "www.3waylabs.com",
    "www.digicert.com", "www.ecma-international.org", "www.example.com",
    "www.google.com", "www.midnight-commander.org", "www.unicode.org", "www.w3.org",
}
BENIGN_HOST_PREFIXES = (
    "cacerts.digicert.com", "crl.comodoca.com", "crl.sectigo.com", "crl.usertrust.com",
    "crl3.digicert.com", "crl4.digicert.com", "crt.sectigo.com", "ocsp.comodoca.com",
    "ocsp.digicert.com", "ocsp.sectigo.com", "ocsp.usertrust.com", "www.microsoft.com",
)
BENIGN_URL_HOSTS.update({
    "android.googlesource.com",
    "connalle.blogspot.com", "fastcopy.jp", "api.fastcopy.jp", "fengmk2.com",
    "gcc.gnu.org", "groups.google.com", "jrsoftware.org", "learn.microsoft.com",
    "mathiasbynens.be", "medium.com", "mths.be", "mxr.mozilla.org",
    "pubs.opengroup.org", "registry.npmjs.org", "sectigo.com", "server.net",
    "sindresorhus.com", "tc39.es", "tools.ietf.org", "www.archiverjs.com",
    "www.npmjs.com", "www.python.org",
})


def sha256_bytes(data: bytes) -> str:
    """Return the lowercase SHA-256 digest for bytes."""
    return hashlib.sha256(data).hexdigest()


def extract_strings(data: bytes, limit: int = 50_000) -> list[str]:
    """Extract bounded ASCII and UTF-16LE strings without interpreting content."""
    strings: list[str] = []
    for match in ASCII.finditer(data):
        strings.append(match.group().decode("ascii"))
        if len(strings) >= limit:
            return strings
    for match in WIDE.finditer(data):
        strings.append(match.group()[::2].decode("ascii"))
        if len(strings) >= limit:
            break
    return strings


def sanitize_url(value: str) -> str | None:
    """Remove credentials, query, and fragment from an HTTP(S) IOC candidate."""
    try:
        parsed = urlsplit(value.rstrip(".,;)]}"))
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            return None
        host = parsed.hostname.lower()
        netloc = f"[{host}]" if ":" in host and not host.startswith("[") else host
        if parsed.port:
            netloc += f":{parsed.port}"
        path = parsed.path or "/"
        lowered = path.lower()
        if host in {"discord.com", "discordapp.com"} and "/api/webhooks/" in lowered:
            parts = path.split("/")
            webhook = next((index for index, part in enumerate(parts) if part.lower() == "webhooks"), None)
            if webhook is not None and len(parts) > webhook + 2:
                path = "/".join(parts[: webhook + 2])
        if host == "hooks.slack.com" and path.lower().startswith("/services/"):
            parts = path.split("/")
            if len(parts) > 4:
                path = "/".join(parts[:4])
        if host == "api.telegram.org":
            path = re.sub(r"/bot[^/]{8,}", "/bot[REDACTED]", path, flags=re.I)
        if "{" in path or "}" in path:
            return None
        return urlunsplit((parsed.scheme.lower(), netloc, path, "", ""))
    except ValueError:
        return None


def ioc_worthy_url(value: str) -> bool:
    """Exclude local, example, certificate, and documentation URLs from IOC output."""
    try:
        parsed = urlsplit(value)
    except ValueError:
        return False
    host = (parsed.hostname or "").lower()
    ip_host = bool(re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", host))
    if not host or host == "localhost" or ("." not in host and not ip_host):
        return False
    if host in BENIGN_URL_HOSTS or any(
        host == prefix or host.endswith("." + prefix) or host.startswith(prefix)
        for prefix in BENIGN_HOST_PREFIXES
    ):
        return False
    if host == "hooks.slack.com" and any(part in {"TXXX", "XX"} for part in parsed.path.split("/")):
        return False
    if host == "discord.com" and "/api/webhooks/" not in parsed.path.lower():
        return False
    if host == "camo.githubusercontent.com":
        return False
    return True


def sanitize_ip_candidate(value: str) -> str | None:
    """Validate a public IPv4 candidate and preserve an optional TCP port."""
    host, separator, port = value.partition(":")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return None
    if address.version != 4 or not address.is_global or int(address) & 0xFFFF == 0:
        return None
    if separator:
        if not port.isdigit() or not 0 < int(port) <= 65535:
            return None
        return f"{address}:{int(port)}"
    return str(address)


def extract_iocs(strings: list[str]) -> dict:
    """Return sanitized, bounded URL and IP candidates from static strings."""
    text = "\n".join(strings)
    urls = sorted({
        item for raw in URL.findall(text)
        if (item := sanitize_url(raw)) and ioc_worthy_url(item)
    })
    ips = sorted({item for raw in IP.findall(text) if (item := sanitize_ip_candidate(raw))})
    return {"urls": urls[:256], "ips": ips[:128]}


def family_from_text(value: str) -> str | None:
    """Map only reviewed family tokens to normalized family identifiers."""
    lowered = re.sub(r"[_./-]+", " ", value.lower()).strip()
    compact = re.sub(r"[^a-z0-9]", "", lowered)
    for alias, family in sorted(FAMILY_ALIASES.items(), key=lambda item: len(item[0]), reverse=True):
        alias_compact = re.sub(r"[^a-z0-9]", "", alias)
        if alias in lowered or (len(alias_compact) >= 5 and alias_compact in compact):
            return family
    return None


def external_evidence(metadata: dict) -> list[dict]:
    """Extract family leads from source tags, public YARA, and sandbox metadata."""
    evidence: list[dict] = []
    for tag in metadata.get("tags") or []:
        family = family_from_text(str(tag))
        if family and str(tag).lower() not in GENERIC_LABELS:
            evidence.append({"family": family, "source": "source_tag", "detail": str(tag)})
    for rule in metadata.get("yara_rules") or []:
        name = str(rule.get("rule_name") or "")
        family = family_from_text(name)
        if family:
            evidence.append({"family": family, "source": "external_yara", "detail": name})
    vendors = metadata.get("vendor_intel") or {}
    triage_family = str((vendors.get("Triage") or {}).get("malware_family") or "")
    if family := family_from_text(triage_family):
        evidence.append({"family": family, "source": "external_sandbox", "detail": triage_family})
    for vendor in ("CAPE", "UnpacMe"):
        raw = vendors.get(vendor) or {}
        records = raw if isinstance(raw, list) else [raw]
        for record in records:
            if not isinstance(record, dict):
                continue
            detection = str(record.get("detection") or "")
            if family := family_from_text(detection):
                evidence.append({"family": family, "source": "external_sandbox", "detail": detection})
    return evidence


def load_detectors(registry_path: Path) -> dict[str, object]:
    """Load registered in-memory malware detectors once for a batch."""
    registry = json.loads(registry_path.read_text(encoding="utf-8-sig"))["malware_types"]
    detectors = {}
    framework = registry_path.parents[1]
    for family, metadata in registry.items():
        path = framework / metadata["detector"]
        spec = importlib.util.spec_from_file_location(f"unknown_batch_{family}", path)
        if spec is None or spec.loader is None:
            continue
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        detectors[family] = module.detect
    return detectors


def compile_yara_rules(repository: Path):
    """Compile all repository YARA files into isolated namespaces."""
    paths = sorted(repository.rglob("*.yar"))
    if not paths:
        return None
    return yara.compile(
        filepaths={f"rule_{index:04d}": str(path) for index, path in enumerate(paths)}
    )


def scan_yara(data: bytes, rules) -> list[str]:
    """Return bounded repository YARA rule names for one in-memory layer."""
    if rules is None:
        return []
    try:
        return sorted({match.rule for match in rules.match(data=data, timeout=10)})[:128]
    except yara.Error:
        return []


def internal_family_compatible(family: str, data_format: str) -> bool:
    """Return whether format-sensitive internal evidence is applicable."""
    allowed = STRICT_INTERNAL_FORMATS.get(family)
    return allowed is None or data_format in allowed


def internal_evidence(
    data: bytes,
    name: str,
    detectors: dict[str, object],
    rules,
) -> tuple[list[dict], dict]:
    """Run registered detectors, distinctive markers, and repository YARA."""
    strings = extract_strings(data)
    lowered = [value.lower() for value in strings]
    evidence: list[dict] = []
    data_format = detect_format(data, name)
    errors = {}
    inferred = infer_family(lowered)
    if inferred and internal_family_compatible(inferred, data_format):
        evidence.append({"family": inferred, "source": "internal_inference", "detail": "distinctive static markers"})
    if len(data) <= 32 * 1024 * 1024:
        for family, detector in detectors.items():
            try:
                result = detector(data, Path(name))
                if result.get("matched"):
                    evidence.append({"family": family, "source": "internal_detector", "detail": "registered detector matched"})
            except Exception as exc:
                errors[family] = type(exc).__name__
        yara_matches = scan_yara(data, rules)
    else:
        errors["batch_size_gate"] = "detectors_and_repository_yara_skipped_over_32_mib"
        yara_matches = []
    for rule_name in yara_matches:
        if family := family_from_text(rule_name):
            if internal_family_compatible(family, data_format):
                evidence.append({"family": family, "source": "internal_yara", "detail": rule_name})
    return evidence, {"strings": strings, "yara_matches": yara_matches, "detector_errors": errors}


def genesis_shape(strings: list[str], has_asar: bool) -> bool:
    """Recognize the reviewed Electron loader shape without naming it alone."""
    text = "\n".join(value.lower() for value in strings)
    markers = ("blocked_names", "gpu_brands", "resourcename", "spawnpowershell", "runpowershell", "spawnhidden")
    return has_asar and sum(marker in text for marker in markers) >= 3


def irahook_shape(strings: list[str], root_format: str) -> bool:
    """Recognize the reviewed IRAHook Minecraft-mod package shape."""
    if root_format != "zip":
        return False
    text = "\n".join(value.lower().replace(".", "/") for value in strings)
    return "ira/m/easysleep" in text and "fabric/mod/json" in text and (
        "qprotect" in text or "modclass" in text
    )



def resolve_attribution(evidence: list[dict]) -> dict:
    """Select a family candidate and calibrated confidence from independent evidence."""
    unique = []
    seen = set()
    for item in evidence:
        key = item["family"], item["source"], item["detail"]
        if key not in seen:
            seen.add(key)
            unique.append(item)
    scores: dict[str, int] = defaultdict(int)
    sources: dict[str, set[str]] = defaultdict(set)
    for item in unique:
        scores[item["family"]] += SOURCE_WEIGHT[item["source"]]
        sources[item["family"]].add(item["source"])
    if not scores:
        return {"family": "unknown", "confidence": "low", "status": "unverified", "score": 0, "evidence": unique}
    ordered = sorted(scores, key=lambda family: (-scores[family], family))
    selected = ordered[0]
    if len(ordered) > 1 and scores[ordered[0]] == scores[ordered[1]]:
        return {"family": "unknown", "confidence": "low", "status": "conflicting", "score": scores[selected], "evidence": unique}
    internal = any(source.startswith("internal_") for source in sources[selected])
    independent = len(sources[selected]) >= 2
    if internal and independent and scores[selected] >= 7:
        confidence = "high"
    elif internal or ("external_yara" in sources[selected] and independent):
        confidence = "medium"
    else:
        confidence = "low"
    return {"family": selected, "confidence": confidence, "status": "inferred", "score": scores[selected], "evidence": unique}


def _public_recovered(items: list[dict] | None, limit: int = 64) -> list[dict]:
    """Return a bounded metadata-only recovered-artifact inventory."""
    allowed = {"kind", "name", "path", "format", "size", "sha256", "status"}
    preferred, other = [], []
    for raw in items or []:
        if not isinstance(raw, dict):
            continue
        item = {key: raw[key] for key in allowed if key in raw}
        label = str(item.get("name") or item.get("path") or item.get("kind") or "").lower()
        target = preferred if (
            label.endswith((".js", ".json", ".node", ".exe", ".dll", ".ps1"))
            or any(marker in label for marker in ("payload", "loader", "resource", "main", "index", "config"))
        ) else other
        target.append(item)
    return (preferred + other)[:limit]


def _recovered_count(items: list[dict] | None) -> int:
    """Return a defensive count for a recovered-artifact inventory."""
    return len(items) if isinstance(items, list) else 0


def public_unpack_summary(report: dict) -> dict:
    """Reduce an unpack report to non-binary structural evidence."""
    pe = report.get("pe") or {}
    return {
        "format": report.get("format"),
        "entropy": report.get("entropy"),
        "unpack_status": report.get("unpack_status"),
        "recovered_total": _recovered_count(report.get("recovered")),
        "recovered": _public_recovered(report.get("recovered")),
        "packing_classification": pe.get("classification"),
        "packing_suspected": pe.get("packing_suspected", False),
        "packer_markers": pe.get("packer_markers") or [],
        "imphash": pe.get("imphash"),
        "large_file_mode": report.get("large_file_mode"),
        "full_file_detectors_skipped": bool(report.get("full_file_detectors_skipped")),
        "control_flow_triage": pe.get("control_flow_triage"),
    }


def _public_asar_summary(report: dict | None) -> dict | None:
    """Reduce an ASAR inventory to stable bounded structural metadata."""
    if not report:
        return None
    inventory = report.get("inventory") or []
    interesting = []
    for item in inventory:
        name = str(item.get("name") or item.get("path") or "")
        lowered = name.lower()
        if name and (lowered.endswith((".js", ".json", ".node")) or any(
            marker in lowered for marker in ("payload", "resource", "loader", "main", "index")
        )):
            interesting.append(name)
        if len(interesting) >= 64:
            break
    return {
        "status": report.get("status"),
        "data_offset": report.get("data_offset"),
        "member_count": report.get("member_count", len(inventory)),
        "interesting_paths": interesting,
    }


def _public_electron_summary(report: dict | None) -> dict | None:
    """Reduce targeted 7-Zip listings while retaining recovered ASAR facts."""
    if not report:
        return None
    outer = report.get("outer_listing") or {}
    return {
        "status": report.get("status"),
        "outer_listing": {"status": outer.get("status"), "types": outer.get("types") or [], "total_members": outer.get("total_members")},
        "nested": [
            {"nested_member": item.get("nested_member"), "status": item.get("status"), "total_members": (item.get("nested_listing") or {}).get("total_members"), "asars": item.get("asars") or []}
            for item in (report.get("nested") or [])[:16]
        ],
        "sample_executed": False,
    }


def recursive_layers(
    root_data: bytes,
    root_name: str,
    sevenzip: Path | None,
    electron_expected: bool,
) -> tuple[dict, list[dict], list[tuple[str, bytes]], list[str]]:
    """Recover bounded priority layers while skipping oversized runtime binaries."""
    targeted_report = None
    queue: list[tuple[str, bytes, int]] = []
    if electron_expected and sevenzip:
        targeted_report, targeted = recover_electron_asars(root_data, sevenzip)
        queue.extend((kind, blob, 1) for kind, blob in targeted)
        root_report = {
            "format": detect_format(root_data, root_name),
            "entropy": None,
            "unpack_status": "targeted_electron_asar",
            "recovered": [
                {"kind": kind, "size": len(blob), "sha256": sha256_bytes(blob)}
                for kind, blob in targeted
            ],
            "pe": {
                "classification": "self_extracting_container",
                "packing_suspected": False,
                "packer_markers": ["Nullsoft/NSIS"],
            },
        }
        artifacts = []
    else:
        root_kind = detect_format(root_data, root_name)
        large_pe = len(root_data) > ROOT_FULL_SCAN_LIMIT and root_kind == "pe"
        if len(root_data) > ROOT_FULL_SCAN_LIMIT and not large_pe:
            root_report = {
                "format": root_kind,
                "entropy": None,
                "unpack_status": "root_size_gate_over_32_mib",
                "recovered": [],
                "pe": {"classification": "bounded_static_triage", "packing_suspected": None, "packer_markers": []},
            }
            artifacts = []
        else:
            root_report, artifacts = unpack_bytes(root_data, root_name)
            if large_pe:
                root_report["large_file_mode"] = "bounded_pe_structural_and_reachable_cfg"
                root_report["full_file_detectors_skipped"] = True
        kind = root_report.get("format")
        needs_external = sevenzip and (
            kind in {"7z", "rar", "cab", "apple-disk-image"}
            or bool((root_report.get("pe") or {}).get("containerized"))
        )
        if needs_external and len(root_data) <= ROOT_FULL_SCAN_LIMIT:
            root_report, artifacts = unpack_bytes(root_data, root_name, sevenzip=sevenzip)
        queue.extend((kind_name, blob, 1) for kind_name, blob in artifacts)
    seen = {sha256_bytes(root_data)}
    layers: list[dict] = []
    retained: list[tuple[str, bytes]] = []
    all_strings: list[str] = []
    while queue and len(layers) < MAX_LAYERS:
        kind, blob, depth = queue.pop(0)
        digest = sha256_bytes(blob)
        if digest in seen:
            continue
        seen.add(digest)
        fmt = detect_format(blob, f"{kind}.bin")
        if len(blob) > MAX_LAYER_SIZE and fmt not in {"asar", "script"}:
            layers.append({"depth": depth, "kind": kind, "sha256": digest, "size": len(blob), "format": fmt, "status": "oversized_runtime_skipped"})
            continue
        report, children = unpack_bytes(blob, f"{kind}.bin", sevenzip=sevenzip if fmt in {"7z", "rar", "cab"} else None)
        strings = extract_strings(blob)
        transformed = []
        if fmt in {"script", "data"} and len(blob) <= 2 * 1024 * 1024:
            for decoder in (deobfuscate_plain_string_array, deobfuscate_string_array):
                decode_report, output = decoder(blob)
                if output:
                    strings.extend(extract_strings(output))
                    transformed.append(decode_report)
        all_strings.extend(strings)
        layers.append({
            "depth": depth,
            "kind": kind,
            "sha256": digest,
            "size": len(blob),
            "format": report.get("format"),
            "unpack_status": report.get("unpack_status"),
            "recovered_total": _recovered_count(report.get("recovered")),
            "recovered": _public_recovered(report.get("recovered")),
            "deobfuscation": transformed,
            "asar": _public_asar_summary(report.get("asar")),
        })
        retained.append((kind, blob))
        if depth < 4:
            for child_kind, child in children:
                child_format = detect_format(child, f"{child_kind}.bin")
                if child_format in {"asar", "script", "zip", "7z", "cab", "rar"} or len(child) <= 20 * 1024 * 1024:
                    queue.append((child_kind, child, depth + 1))
    root_public = public_unpack_summary(root_report)
    if targeted_report:
        root_public["electron_targeted"] = _public_electron_summary(targeted_report)
    return root_public, layers, retained, all_strings


def safe_config_findings(family: str, blobs: list[tuple[str, bytes]]) -> list[dict]:
    """Run a supported extractor and retain only sanitized network IOC findings."""
    if family not in EXTRACTORS:
        return []
    output, seen = [], set()
    for name, blob in blobs[:32]:
        try:
            result = EXTRACTORS[family](blob, f"{name}.bin")
        except Exception:
            continue
        for item in result.get("findings") or []:
            kind, value = str(item.get("kind") or ""), str(item.get("value") or "")
            if kind == "url":
                value = sanitize_url(value) or ""
            if kind not in {"url", "domain", "ip", "endpoint"} or not value:
                continue
            key = kind, value
            if key not in seen:
                seen.add(key)
                output.append({"kind": kind, "value": value, "role": item.get("role", "config_candidate")})
    return output[:256]


def analyze_item(item: dict, detectors: dict[str, object], rules, sevenzip: Path | None) -> dict:
    """Analyze one encrypted MalwareBazaar archive entirely through static parsing."""
    member = read_single_aes_zip_member(Path(item["zip_path"]))
    digest = sha256_bytes(member.data)
    if digest != item["sha256"]:
        raise ValueError(f"inner hash mismatch: {item['sha256']}")
    metadata = item.get("detail_metadata") or item.get("metadata") or {}
    tags = [str(value).lower() for value in metadata.get("tags") or []]
    rule_names = [str(value.get("rule_name") or "").lower() for value in metadata.get("yara_rules") or []]
    electron_expected = "electron" in tags or any("genesisstealer_installer_nsis" in name for name in rule_names)
    root_unpack, layers, retained, layer_strings = recursive_layers(member.data, member.name, sevenzip, electron_expected)
    evidence = external_evidence(metadata)
    internal, root_observations = internal_evidence(member.data, member.name, detectors, rules)
    evidence.extend(internal)
    internal_strings = root_observations["strings"] + layer_strings
    has_asar = any(layer.get("format") == "asar" for layer in layers)
    if genesis_shape(internal_strings, has_asar) and any(item["family"] == "genesisstealer" for item in evidence):
        evidence.append({"family": "genesisstealer", "source": "internal_shape", "detail": "NSIS/Electron ASAR loader markers"})
    for kind, blob in retained:
        layer_evidence, _ = internal_evidence(blob, f"{kind}.bin", detectors, rules)
    if irahook_shape(internal_strings, root_unpack.get("format")) and any(
        item["family"] == "irahook" for item in evidence
    ):
        evidence.append({"family": "irahook", "source": "internal_shape", "detail": "IRAHook Fabric mod package and EasySleep class markers"})
        evidence.extend(layer_evidence)
    attribution = resolve_attribution(evidence)
    strings = internal_strings[:100_000]
    iocs = extract_iocs(strings)
    config_findings = safe_config_findings(
        attribution["family"], [(member.name, member.data), *retained]
    ) if attribution["confidence"] in {"high", "medium"} else []
    for finding in config_findings:
        if finding["kind"] == "url":
            iocs["urls"] = sorted(set(iocs["urls"] + [finding["value"]]))
        elif finding["kind"] == "ip":
            iocs["ips"] = sorted(set(iocs["ips"] + [finding["value"]]))
    if str(metadata.get("file_type") or "").lower() in {"exe", "dll", "macho", "jar"}:
        url_hosts = {
            urlsplit(value).hostname
            for value in iocs["urls"]
            if urlsplit(value).hostname
        }
        config_ips = {finding["value"].split(":", 1)[0] for finding in config_findings if finding["kind"] in {"ip", "endpoint"}}
        iocs["ips"] = [
            value for value in iocs["ips"]
            if ":" in value or value.split(":", 1)[0] in url_hosts or value.split(":", 1)[0] in config_ips
        ]
    source = {
        "first_seen": metadata.get("first_seen"),
        "file_name": metadata.get("file_name") or member.name,
        "file_size": metadata.get("file_size") or len(member.data),
        "file_type": metadata.get("file_type"),
        "tags": metadata.get("tags") or [],
        "imphash": metadata.get("imphash"),
        "tlsh": metadata.get("tlsh"),
        "ssdeep": metadata.get("ssdeep"),
        "source_yara_rules": [value.get("rule_name") for value in metadata.get("yara_rules") or []],
    }
    return {
        "schema_version": 1,
        "sha256": digest,
        "source": source,
        "attribution": attribution,
        "root_unpack": root_unpack,
        "layers": layers,
        "repository_yara_matches": root_observations["yara_matches"],
        "iocs": iocs,
        "config_findings": config_findings,
        "sample_executed": False,
        "network_contacted": False,
        "limitations": [
            "Static-only attribution; low-confidence labels remain provisional.",
            "General string URLs are candidates, not confirmed C2 endpoints.",
            "Oversized Electron runtime binaries are inventoried but not recursively parsed.",
        ],
    }


def cluster_cases(cases: list[dict]) -> dict[str, list[str]]:
    """Group unresolved cases by exact ASAR, imphash, or source-type features."""
    groups: dict[str, list[str]] = defaultdict(list)
    for case in cases:
        if "error" in case:
            groups["errors"].append(case["sha256"])
            continue
        family = case["attribution"]["family"]
        if family != "unknown":
            key = f"family:{family}:{case['attribution']['confidence']}"
        else:
            asars = [layer["sha256"] for layer in case["layers"] if layer.get("format") == "asar"]
            imphash = case["source"].get("imphash")
            if asars:
                key = f"asar:{asars[0]}"
            elif imphash:
                key = f"imphash:{imphash}"
            else:
                key = f"format:{case['source'].get('file_type') or case['root_unpack'].get('format')}"
        groups[key].append(case["sha256"])
    return dict(sorted(groups.items()))


def render_case_readme(case: dict) -> str:
    """Render one publish-safe case report with attribution and detection material."""
    source, attribution = case["source"], case["attribution"]
    lines = [
        f"# {case['sha256']}", "",
        "## Overview", "",
        f"- MalwareBazaar first seen: `{source.get('first_seen')}`",
        f"- Submitted filename: `{source.get('file_name')}`",
        f"- Format / size: `{source.get('file_type')}` / `{source.get('file_size')}` bytes",
        f"- Identified family: `{attribution['family']}`",
        f"- Attribution confidence: `{attribution['confidence']}` (`{attribution['status']}`, score {attribution['score']})",
        "- Execution/network: not performed", "",
        "## Attribution evidence", "",
    ]
    if attribution["evidence"]:
        lines.extend(
            f"- `{item['source']}`: `{item['family']}` - {item['detail']}"
            for item in attribution["evidence"]
        )
    else:
        lines.append("- No defensible family-specific evidence; retained as unknown.")
    lines.extend(["", "## Static chain", "", f"- Root: `{case['root_unpack'].get('format')}` / `{case['root_unpack'].get('packing_classification')}`"])
    for layer in case["layers"]:
        lines.append(f"- Depth {layer['depth']}: `{layer['format']}` `{layer['sha256']}` ({layer['size']} bytes, {layer.get('status') or layer.get('unpack_status')})")
    lines.extend(["", "## Network indicators", ""])
    if case["iocs"]["urls"]:
        lines.extend(f"- URL candidate: `{value}`" for value in case["iocs"]["urls"])
    if case["iocs"]["ips"]:
        lines.extend(f"- IP candidate: `{value}`" for value in case["iocs"]["ips"])
    if not case["iocs"]["urls"] and not case["iocs"]["ips"]:
        lines.append("- None recovered from static evidence.")
    lines.extend([
        "", "## Detection considerations", "",
        f"- High confidence / low false-positive risk: exact submitted SHA-256 `{case['sha256']}`.",
        "- Medium confidence / medium false-positive risk: require two independent family-specific static observations or a reviewed structural signature.",
        "- Low confidence / high false-positive risk: filename, generic Electron/NSIS/PyInstaller tags, imphash, or a URL alone.",
        "- Sigma should combine process ancestry, extraction path, and script/runtime behavior; no process behavior was asserted from static data alone.",
        "", "## Limitations", "",
    ])
    lines.extend(f"- {value}" for value in case["limitations"])
    return "\n".join(lines) + "\n"


def write_case(case: dict, output: Path) -> None:
    """Write one JSON/Markdown case and machine-readable IOC source file."""
    output.mkdir(parents=True, exist_ok=True)
    write_json(output / "case.json", case)
    (output / "README.md").write_text(render_case_readme(case), encoding="utf-8")
    network = [
        {"value": value, "role": "static_url_candidate", "confidence": "inferred"}
        for value in case["iocs"]["urls"]
    ] + [
        {"value": value, "role": "static_ip_candidate", "confidence": "inferred"}
        for value in case["iocs"]["ips"]
    ]
    write_json(output / "iocs.json", {
        "schema_version": 1,
        "files": [{"sha256": case["sha256"], "role": "submitted_sample", "confidence": "confirmed"}],
        "network": network,
        "network_contacted": False,
    })


def normalize_case_iocs(case: dict) -> dict:
    """Re-sanitize cached case URLs after IOC policy or parser updates."""
    raw_urls = (case.get("iocs") or {}).get("urls") or []
    urls = sorted({
        item for raw in raw_urls
        if (item := sanitize_url(str(raw))) and ioc_worthy_url(item)
    })
    case.setdefault("iocs", {})["urls"] = urls[:256]
    raw_ips = case["iocs"].get("ips") or []
    ips = sorted({item for raw in raw_ips if (item := sanitize_ip_candidate(str(raw)))})
    if str((case.get("source") or {}).get("file_type") or "").lower() in {"exe", "dll", "macho", "jar"}:
        url_hosts = {urlsplit(value).hostname for value in urls if urlsplit(value).hostname}
        config_ips = {
            str(finding.get("value") or "").split(":", 1)[0]
            for finding in case.get("config_findings") or []
            if finding.get("kind") in {"ip", "endpoint"}
        }
        ips = [
            value for value in ips
            if ":" in value or value.split(":", 1)[0] in url_hosts or value.split(":", 1)[0] in config_ips
        ]
    case["iocs"]["ips"] = ips[:128]
    return case


def normalize_case_structure(case: dict) -> dict:
    """Bound verbose cached ASAR, Electron, and artifact inventories."""
    for layer in case.get("layers") or []:
        if layer.get("asar"):
            layer["asar"] = _public_asar_summary(layer["asar"])
        layer["recovered_total"] = max(int(layer.get("recovered_total") or 0), _recovered_count(layer.get("recovered")))
        layer["recovered"] = _public_recovered(layer.get("recovered"))
    root = case.get("root_unpack") or {}
    root["recovered_total"] = max(int(root.get("recovered_total") or 0), _recovered_count(root.get("recovered")))
    root["recovered"] = _public_recovered(root.get("recovered"))
    if root.get("electron_targeted"):
        root["electron_targeted"] = _public_electron_summary(root["electron_targeted"])
    return case


def render_summary(summary: dict) -> str:
    """Render the aggregate newest-first collection and family distribution."""
    lines = [
        "# MalwareBazaar unknown/stealer static classification", "",
        "This batch contains the newest 100 MalwareBazaar entries whose family signature was empty and whose tags included `unknown`, `stealer`, or `infostealer`. Samples were parsed statically; no sample or recovered payload was executed, and no extracted infrastructure was contacted.", "",
        "## Collection", "",
        f"- Samples: {summary['counts']['total']}",
        f"- First-seen range: `{summary['newest_first_seen']}` to `{summary['oldest_first_seen']}`",
        f"- Analysis errors: {summary['counts']['errors']}",
        f"- Identified (including provisional low confidence): {summary['counts']['identified']}",
        f"- Supported at medium/high confidence: {summary['counts']['supported']}",
        f"- Provisional external-only/low-confidence leads: {summary['counts']['provisional']}",
        f"- Remaining unknown: {summary['counts']['unknown']}", "",
        "## Attribution distribution", "",
        "| Family | Confidence | Count |", "|---|---|---:|",
    ]
    for key, count in summary["attribution_counts"].items():
        family, confidence = key.split("|", 1)
        lines.append(f"| {family} | {confidence} | {count} |")
    supported = [
        case for case in summary["cases"]
        if "error" not in case and case["attribution"]["family"] != "unknown"
        and case["attribution"]["confidence"] in {"medium", "high"}
    ]
    lines.extend(["", "## Supported family attributions", "", "| SHA-256 | Family | Confidence | Internal support |", "|---|---|---|---|"])
    for case in supported:
        support = ", ".join(sorted({
            item["source"] for item in case["attribution"]["evidence"]
            if item["source"].startswith("internal_")
        })) or "none"
        lines.append(f"| [{case['sha256']}](cases/{case['sha256']}/README.md) | {case['attribution']['family']} | {case['attribution']['confidence']} | {support} |")
    lines.extend([
        "", "## Detection rules", "",
        "- [IRAHook Fabric mod structure](rules/yara/irahook_fabric_mod_2026.yar): medium confidence, low expected false-positive risk after the full package-path conjunction.",
        "- [Electron credential-loader ASAR structure](rules/yara/electron_credential_loader_asar_2026.yar): medium confidence, medium expected false-positive risk; apply to a recovered ASAR or loader script.",
        "- No Sigma rule is asserted from this static-only batch because no process or event telemetry was collected.",
    ])
    network = sorted({
        value
        for case in summary["cases"] if "error" not in case
        for value in ((case.get("iocs") or {}).get("ips") or []) + ((case.get("iocs") or {}).get("urls") or [])
    })
    lines.extend(["", "## Static network candidates", "", "These values were recovered from static strings or configuration-like data. They were not contacted and are not confirmed C2 endpoints.", ""])
    if network:
        lines.extend(f"- `{value}`" for value in network)
    else:
        lines.append("- None recovered.")
    lines.extend(["", "## Case index", "", "| First seen | SHA-256 | Family | Confidence |", "|---|---|---|---|"])
    for case in summary["cases"]:
        if "error" in case:
            lines.append(f"| {case.get('first_seen')} | [{case['sha256']}](cases/{case['sha256']}/README.md) | error | low |")
        else:
            lines.append(f"| {case['source'].get('first_seen')} | [{case['sha256']}](cases/{case['sha256']}/README.md) | {case['attribution']['family']} | {case['attribution']['confidence']} |")
    lines.extend(["", "## Interpretation", "", "Family names based only on a source tag or external public rule remain provisional. A medium/high result requires internal detector/YARA/structure evidence. `unknown` or `conflicting` cases are intentionally not force-labeled. Network values are static candidates, not confirmed C2 infrastructure."])
    return "\n".join(lines) + "\n"


def analyze_manifest(manifest_path: Path, output: Path, registry: Path, sevenzip: Path | None, *, force: bool = False, force_hashes: set[str] | None = None) -> dict:
    """Analyze all manifest items in listed newest-first order and write reports."""
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    forced = {value.lower() for value in (force_hashes or set())}
    detectors = load_detectors(registry)
    rules = compile_yara_rules(REPO)
    cases = []
    for index, item in enumerate(manifest["items"], 1):
        case_path = output / "cases" / item["sha256"] / "case.json"
        try:
            if case_path.is_file() and not force and item["sha256"].lower() not in forced:
                case = json.loads(case_path.read_text(encoding="utf-8"))
            else:
                case = analyze_item(item, detectors, rules, sevenzip)
            case = normalize_case_iocs(case)
            case = normalize_case_structure(case)
            write_case(case, output / "cases" / case["sha256"])
        except Exception as exc:
            metadata = item.get("detail_metadata") or item.get("metadata") or {}
            case = {
                "sha256": item["sha256"],
                "first_seen": metadata.get("first_seen"),
                "error": type(exc).__name__,
                "sample_executed": False,
                "network_contacted": False,
            }
        cases.append(case)
        print(f"[{index:03d}/{len(manifest['items']):03d}] {case['sha256']} {case.get('attribution', {}).get('family', case.get('error'))}", flush=True)
    valid = [case for case in cases if "error" not in case]
    attribution_counts = Counter(
        f"{case['attribution']['family']}|{case['attribution']['confidence']}" for case in valid
    )
    first_seen = [case["source"].get("first_seen") for case in valid if case["source"].get("first_seen")]
    summary = {
        "schema_version": 1,
        "source": "MalwareBazaar Community API",
        "selection": "empty family signature; unknown/stealer/infostealer tags; newest first",
        "newest_first_seen": max(first_seen) if first_seen else None,
        "oldest_first_seen": min(first_seen) if first_seen else None,
        "counts": {
            "total": len(cases),
            "errors": len(cases) - len(valid),
            "identified": sum(case["attribution"]["family"] != "unknown" for case in valid),
            "unknown": sum(case["attribution"]["family"] == "unknown" for case in valid),
            "supported": sum(case["attribution"]["family"] != "unknown" and case["attribution"]["confidence"] in {"medium", "high"} for case in valid),
            "provisional": sum(case["attribution"]["family"] != "unknown" and case["attribution"]["confidence"] == "low" for case in valid),
        },
        "attribution_counts": dict(sorted(attribution_counts.items())),
        "clusters": cluster_cases(cases),
        "cases": cases,
        "sample_executed": False,
        "network_contacted": False,
    }
    output.mkdir(parents=True, exist_ok=True)
    write_json(output / "summary.json", summary)
    (output / "README.md").write_text(render_summary(summary), encoding="utf-8")
    return summary


def build_parser() -> argparse.ArgumentParser:
    """Build the offline unknown-batch analysis command-line parser."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--registry", required=True, type=Path)
    parser.add_argument("--sevenzip", type=Path)
    parser.add_argument("--force", action="store_true", help="ignore cached case JSON")
    parser.add_argument("--force-hash", action="append", default=[], help="reanalyze only this cached SHA-256")
    return parser


def main(argv: list[str] | None = None) -> int:
    """Run the newest-first batch and print aggregate counts."""
    args = build_parser().parse_args(argv)
    summary = analyze_manifest(args.manifest, args.output, args.registry, args.sevenzip, force=args.force, force_hashes=set(args.force_hash))
    print(json.dumps(summary["counts"], indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
