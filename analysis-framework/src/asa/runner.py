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


def step_unpack(context: dict) -> dict:
    """Run bounded static unpacking metadata without persisting recovered bytes."""
    report, _ = unpack_bytes(context["data"], context["facts"]["submission"]["name"])
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
    return {"tool": tool, "available": bool(found), "path": found, "invoked": False}


def step_config(context: dict, family: str) -> dict:
    """Run the root family config extractor against retained bytes."""
    return get_extractor(family)(context["data"], context["facts"]["submission"]["name"])


def step_report(context: dict) -> dict:
    """Build a publish-safe summary of step statuses and config findings."""
    config = next((value for key, value in context["results"].items() if key == "config"), None)
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
    if plan["status"] != "blocked" and plan["family"] != "unknown":
        for step in plan["steps"]:
            try:
                result = execute_step(step["uses"], context)
                context["results"][step["id"]] = result
                write_json(output / "steps" / step["id"] / "result.json", result)
                states.append({"id": step["id"], "status": "succeeded"})
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
