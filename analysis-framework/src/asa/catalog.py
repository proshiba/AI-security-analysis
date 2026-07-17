"""Allowlisted analysis-step catalog."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class StepSpec:
    """Static metadata for a callable analysis step."""

    id: str
    version: int
    capabilities: tuple[str, ...] = ()


PROFILED_FAMILIES = (
    "asyncrat",
    "darkcomet",
    "dcrat",
    "guloader",
    "hijackloader",
    "njrat",
    "quasarrat",
    "redlinestealer",
    "snakekeylogger",
    "xworm",
)

_STEPS = {
    item.id: item
    for item in (
        StepSpec("intake.submission", 1, ("filesystem.sample.read",)),
        StepSpec("containers.inventory", 1),
        StepSpec("static.strings.extract", 1),
        StepSpec("static.ioc.extract", 1),
        StepSpec("static.pe.inspect", 1),
        StepSpec("static.dotnet.inspect", 1),
        StepSpec("static.go.inspect", 1),
        StepSpec("static.unpack.inspect", 1),
        StepSpec("scripts.layers", 1),
        StepSpec("containers.iso", 1),
        StepSpec("external.floss.analyze", 1, ("external.floss",)),
        StepSpec("external.ghidra_mcp.import_analyze", 1, ("external.ghidra_mcp",)),
        StepSpec("family.valleyrat.config", 1),
        StepSpec("family.agenttesla.config", 1),
        StepSpec("family.atlascross.config", 1),
        StepSpec("family.amadey.config", 1),
        StepSpec("family.npm_supply_chain.config", 1),
        StepSpec("family.amosstealer.config", 1),
        StepSpec("family.formbook.config", 1),
        StepSpec("family.latrodectus.config", 1),
        StepSpec("family.lummastealer.config", 1),
        StepSpec("family.donutloader.layers", 1),
        StepSpec("family.purehvnc.config", 1),
        StepSpec("family.remcosrat.config", 1),
        StepSpec("family.remusstealer.config", 1),
        StepSpec("family.spyglace.config", 1),
        StepSpec("family.venomrat.config", 1),
        StepSpec("family.stealc.config", 1),
        StepSpec("family.vidar.config", 1),
        StepSpec("family.mx_go.config", 1),
        StepSpec("reporting.case_report", 1),
        *(StepSpec(f"family.{family}.config", 1) for family in PROFILED_FAMILIES),
    )
}


def parse_step_reference(reference: str) -> tuple[str, int]:
    """Parse `step.id@^N` and reject arbitrary paths or commands."""
    if "@^" not in reference:
        raise ValueError(f"step reference must use @^major: {reference}")
    step_id, version = reference.rsplit("@^", 1)
    if not step_id or any(token in step_id for token in ("/", "\\", " ", ";")):
        raise ValueError(f"unsafe step ID: {step_id}")
    return step_id, int(version)


def get_step(reference: str) -> StepSpec:
    """Resolve an allowlisted step reference and compatible major version."""
    step_id, version = parse_step_reference(reference)
    spec = _STEPS.get(step_id)
    if spec is None or spec.version != version:
        raise ValueError(f"unknown or incompatible step: {reference}")
    return spec


def list_steps() -> list[StepSpec]:
    """Return the catalog in deterministic order."""
    return [_STEPS[key] for key in sorted(_STEPS)]
