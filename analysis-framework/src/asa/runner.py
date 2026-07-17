"""Offline-only execution of compiled allowlisted analysis steps."""

from __future__ import annotations

import hashlib
import json
import re
import shutil
from pathlib import Path
from typing import Any

import pefile

from extractors.common import endpoint_candidates, extract_strings, url_candidates
from extractors.config_extractor import get_extractor
from unpackers.static_unpacker import unpack_bytes

from .catalog import parse_step_reference
from .compiler import compile_plan
from .discovery import discover
from .loader import index_definitions, load_definition_tree
from .models import MalwareDefinition, PipelineDefinition, PolicyDefinition


def write_json(path: Path, value: Any) -> None:
    """Write deterministic UTF-8 JSON and create parent directories."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def step_intake(context: dict) -> dict:
    """Record immutable input identity without persisting sample bytes."""
    data = context["data"]
    return {
        "name": context["facts"]["submission"]["name"],
        "sha256": hashlib.sha256(data).hexdigest(),
        "size": len(data),
    }


def step_inventory(context: dict) -> dict:
    """Return bounded format and magic observations."""
    data = context["data"]
    kind = (
        "pe"
        if data.startswith(b"MZ")
        else "script"
        if any(token in data[:4096].lower() for token in (b"function", b"powershell", b"wscript"))
        else "data"
    )
    return {"type": kind, "magic": data[:16].hex()}


def step_strings(context: dict) -> dict:
    """Extract bounded strings for downstream static steps."""
    values = extract_strings(context["data"])[:20000]
    context["strings"] = values
    return {"count": len(values), "values": values}


def step_iocs(context: dict) -> dict:
    """Extract unconfirmed static network candidates."""
    values = context.get("strings") or extract_strings(context["data"])
    return {"endpoints": endpoint_candidates(values), "urls": url_candidates(values), "confidence": "unverified"}


def step_pe(context: dict) -> dict:
    """Inspect PE headers and imports without loading the image."""
    try:
        pe = pefile.PE(data=context["data"], fast_load=True)
    except pefile.PEFormatError as exc:
        raise ValueError(f"not a PE: {exc}") from exc
    clr = pe.OPTIONAL_HEADER.DATA_DIRECTORY[14]
    return {
        "machine": hex(pe.FILE_HEADER.Machine),
        "is_dotnet": bool(clr.VirtualAddress and clr.Size),
        "sections": len(pe.sections),
    }


def step_dotnet(context: dict) -> dict:
    """Report CLR presence from the PE step or raw header inspection."""
    pe_result = context["results"].get("pe", {})
    return {"is_dotnet": bool(pe_result.get("is_dotnet"))}


def step_go(context: dict) -> dict:
    """Extract Go version and retained module markers."""
    data = context["data"]
    versions = sorted({item.decode() for item in re.findall(rb"go1\.[0-9]+(?:\.[0-9]+)?", data)})
    modules = sorted(
        {item.decode(errors="replace") for item in re.findall(rb"mx-go/internal/[A-Za-z0-9_./+-]{3,120}", data)}
    )
    return {"version": versions[-1] if versions else None, "modules": modules}


def _public_layer(layer: dict) -> dict:
    """Return publish-safe layer metadata without retained sample bytes."""
    return {
        key: layer[key]
        for key in ("sha256", "size", "name", "kind", "transform", "parent_sha256", "depth")
        if key in layer
    }


def _ensure_root_layer(context: dict) -> dict:
    """Initialize the in-memory layer ledger and return the root layer."""
    data = context["data"]
    digest = hashlib.sha256(data).hexdigest()
    layers = context.setdefault("layers", [])
    retained = context.setdefault("_layer_bytes", {})
    retained.setdefault(digest, data)
    if not layers:
        layers.append(
            {
                "sha256": digest,
                "size": len(data),
                "name": context["facts"]["submission"]["name"],
                "kind": "submission",
                "transform": "submission",
                "parent_sha256": None,
                "depth": 0,
            }
        )
    context.setdefault("selected_layer_sha256", digest)
    return layers[0]


def _layer_candidates(context: dict) -> list[tuple[dict, bytes]]:
    """Return authenticated retained layers in deterministic ledger order."""
    _ensure_root_layer(context)
    retained = context["_layer_bytes"]
    candidates = []
    for layer in context["layers"]:
        digest = layer["sha256"]
        if digest not in retained:
            continue
        data = retained[digest]
        if hashlib.sha256(data).hexdigest() != digest:
            raise ValueError(f"retained layer hash mismatch: {digest}")
        candidates.append((layer, data))
    return candidates


def step_unpack(context: dict) -> dict:
    """Run bounded unpacking and retain authenticated child layers in memory."""
    root = _ensure_root_layer(context)
    selected_sha256 = context["selected_layer_sha256"]
    parent = next((item for item in context["layers"] if item["sha256"] == selected_sha256), root)
    parent_data = context["_layer_bytes"][parent["sha256"]]
    report, artifacts = unpack_bytes(parent_data, parent["name"])
    known = {item["sha256"] for item in context["layers"]}
    retained_layers = []
    for artifact_kind, blob in artifacts:
        digest = hashlib.sha256(blob).hexdigest()
        if digest in known:
            continue
        layer = {
            "sha256": digest,
            "size": len(blob),
            "name": f"{parent['name']}::{artifact_kind}",
            "kind": artifact_kind,
            "transform": artifact_kind,
            "parent_sha256": parent["sha256"],
            "depth": parent["depth"] + 1,
        }
        context["layers"].append(layer)
        context["_layer_bytes"][digest] = blob
        known.add(digest)
        retained_layers.append(layer)
    report["input_layer"] = _public_layer(parent)
    report["retained_layers"] = [_public_layer(item) for item in retained_layers]
    return report


def step_scripts(context: dict) -> dict:
    """Summarize common script-loader features without interpretation or execution."""
    text = "\n".join(context.get("strings") or extract_strings(context["data"])).lower()
    return {key: key in text for key in ("powershell", "wscript.shell", "fromcharcode", "eval(", "adodb.stream")}


def step_iso(context: dict) -> dict:
    """Identify an ISO9660 primary volume descriptor without mounting it."""
    data = context["data"]
    return {"iso9660": len(data) >= 0x8006 and data[0x8001:0x8006] == b"CD001"}


def step_tool(context: dict, tool: str) -> dict:
    """Preflight an optional external static tool without invoking it."""
    names = {"floss": ["floss.exe", "floss"], "ghidra_mcp": ["ghidra-mcp"]}[tool]
    found = next((shutil.which(name) for name in names if shutil.which(name)), None)
    return {
        "tool": tool,
        "available": bool(found),
        "path": found,
        "invoked": False,
        "status": "preflight_only",
    }


def _config_evidence_score(result: dict) -> int:
    """Score explicit recovered config above unverified outer-layer literals."""
    config = result.get("config", {})
    score = 0
    if isinstance(config, dict):
        for key in ("static_config_recovered", "decoded_config_recovered"):
            if config.get(key) is True:
                score += 1000
        variant = str(config.get("variant", "")).strip().lower()
        if variant and variant not in {"unknown", "unrecognized", "unresolved"}:
            score += 500
    confidence = {
        "confirmed": 100,
        "high": 80,
        "inferred": 60,
        "probable": 50,
        "medium": 40,
        "candidate": 20,
        "low": 10,
        "unverified": 0,
    }
    finding_scores = []
    findings = result.get("findings", [])
    if not isinstance(findings, list):
        return score
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        value = confidence.get(str(finding.get("confidence", "")).lower(), 1)
        role = str(finding.get("role", "")).lower()
        source = str(finding.get("source", "")).lower()
        if role == "c2" or "configured_c2" in role:
            value += 60
        elif "c2" in role:
            value += 20
        if any(token in source for token in ("decoded", "static_config", "recovered_terminal")):
            value += 40
        finding_scores.append(value)
    if finding_scores:
        score += max(finding_scores) * 10 + min(len(finding_scores), 10)
    return score


def step_config(context: dict, family: str) -> dict:
    """Run a family extractor across retained layers and select best evidence."""
    extractor = get_extractor(family)
    attempts = []
    successful = []
    first_error: Exception | None = None
    for order, (layer, data) in enumerate(_layer_candidates(context)):
        try:
            result = extractor(data, layer["name"])
        except Exception as exc:
            first_error = first_error or exc
            attempts.append({**_public_layer(layer), "status": "extractor_error", "error": type(exc).__name__})
            continue
        findings = result.get("findings", [])
        finding_count = len(findings) if isinstance(findings, list) else 0
        evidence_score = _config_evidence_score(result)
        attempts.append(
            {
                **_public_layer(layer),
                "status": "analyzed",
                "finding_count": finding_count,
                "evidence_score": evidence_score,
            }
        )
        # Preserve root selection on an evidence tie; only a child with stronger
        # static findings supersedes it.
        successful.append((evidence_score, -order, layer, result))
    if not successful:
        if first_error is not None:
            raise first_error
        raise ValueError("no retained layer was available for config extraction")
    _, _, selected, result = max(successful, key=lambda item: (item[0], item[1]))
    context["selected_layer_sha256"] = selected["sha256"]
    result["input_layer"] = _public_layer(selected)
    result["layer_selection"] = {
        "strategy": "strongest_static_config_evidence_then_root_order",
        "candidate_count": len(attempts),
        "attempts": attempts,
    }
    return result


def step_donut_layers(context: dict) -> dict:
    """Recover strict Donut children before recording delivery-layer evidence."""
    unpack = step_unpack(context)
    result = step_config(context, "donutloader")
    result["unpack"] = unpack
    return result


def step_report(context: dict) -> dict:
    """Build a publish-safe summary of step statuses and config findings."""
    config = next(
        (value for key, value in context["results"].items() if key in {"config", "terminal"}),
        None,
    )
    return {
        "family": context["plan"]["family"],
        "campaign": context["plan"]["campaign"],
        "step_ids": list(context["results"]),
        "config_findings": [] if not config else config.get("findings", []),
        "executed": False,
        "network_contacted": False,
    }


def execute_step(reference: str, context: dict) -> dict:
    """Dispatch one allowlisted step reference to its offline implementation."""
    step_id, _ = parse_step_reference(reference)
    simple = {
        "intake.submission": step_intake,
        "containers.inventory": step_inventory,
        "static.strings.extract": step_strings,
        "static.ioc.extract": step_iocs,
        "static.pe.inspect": step_pe,
        "static.dotnet.inspect": step_dotnet,
        "static.go.inspect": step_go,
        "static.unpack.inspect": step_unpack,
        "scripts.layers": step_scripts,
        "containers.iso": step_iso,
        "reporting.case_report": step_report,
    }
    if step_id in simple:
        return simple[step_id](context)
    if step_id == "external.floss.analyze":
        return step_tool(context, "floss")
    if step_id == "external.ghidra_mcp.import_analyze":
        return step_tool(context, "ghidra_mcp")
    if step_id == "family.donutloader.layers":
        return step_donut_layers(context)
    family = {"family.mx_go.config": "mx-go"}.get(step_id)
    if step_id.startswith("family."):
        family = family or step_id.split(".")[1]
        return step_config(context, family)
    raise ValueError(f"no offline implementation for step: {step_id}")


def run_analysis(
    sample: Path,
    definitions_root: Path,
    output: Path,
    policy_id: str = "offline-default",
    password: str = "infected",
    family_hint: str | None = None,
    campaign_hint: str | None = None,
    unwrap_archive: bool = True,
) -> dict:
    """Discover, compile, and execute one offline analysis plan."""
    data, facts = discover(sample, password, family_hint, campaign_hint, unwrap_archive)
    definitions = load_definition_tree(definitions_root)
    malware = list(index_definitions(definitions, MalwareDefinition).values())
    pipelines = index_definitions(definitions, PipelineDefinition)
    policies = index_definitions(definitions, PolicyDefinition)
    if policy_id not in policies:
        raise ValueError(f"unknown policy: {policy_id}")
    plan_model = compile_plan(malware, pipelines, policies[policy_id], facts)
    plan = plan_model.model_dump(mode="json")
    write_json(output / "facts.json", facts)
    write_json(output / "plan.json", plan)
    context = {"data": data, "facts": facts, "plan": plan, "results": {}}
    states = []
    if plan["status"] != "blocked":
        for step in plan["steps"]:
            try:
                result = execute_step(step["uses"], context)
                context["results"][step["id"]] = result
                write_json(output / "steps" / step["id"] / "result.json", result)
                status = "not_invoked" if result.get("invoked") is False else "succeeded"
                states.append({"id": step["id"], "status": status})
            except Exception as exc:
                state = "partial" if step["on_error"] == "partial" else "failed"
                states.append({"id": step["id"], "status": state, "error": f"{type(exc).__name__}: {exc}"})
                if state == "failed":
                    break
    summary = {
        "schema_version": 1,
        "family": plan["family"],
        "campaign": plan["campaign"],
        "plan_status": plan["status"],
        "steps": states,
        "executed": False,
        "network_contacted": False,
    }
    write_json(output / "run.json", summary)
    return summary
