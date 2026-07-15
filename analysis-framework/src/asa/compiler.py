"""Compile facts and declarative definitions into a safe dry-run plan."""

from __future__ import annotations

from .catalog import get_step
from .conditions import score_rules
from .models import AnalysisPlan, Candidate, CompiledStep, MalwareDefinition, PipelineDefinition, PolicyDefinition


def rank_families(definitions: list[MalwareDefinition], facts: dict) -> list[Candidate]:
    """Score every malware definition using the same discovery facts."""
    values = []
    for definition in definitions:
        score, matched = score_rules(definition.classification.family.rules, facts)
        values.append(Candidate(id=definition.metadata.id, score=score, matched_rules=matched))
    return sorted(values, key=lambda item: (-item.score, item.id))


def select_family(
    definitions: list[MalwareDefinition], facts: dict
) -> tuple[MalwareDefinition | None, list[Candidate]]:
    """Select one above-threshold family, returning unknown on a top-score tie."""
    candidates = rank_families(definitions, facts)
    if not candidates:
        return None, []
    by_id = {item.metadata.id: item for item in definitions}
    top = candidates[0]
    selected = by_id[top.id]
    if top.score < selected.classification.family.threshold:
        return None, candidates
    if len(candidates) > 1 and candidates[1].score == top.score:
        return None, candidates
    return selected, candidates


def select_campaign(definition: MalwareDefinition, facts: dict) -> tuple[str, str, list[Candidate]]:
    """Select an above-threshold campaign or the family fallback pipeline."""
    candidates = []
    campaigns = {item.id: item for item in definition.classification.campaigns}
    for campaign in definition.classification.campaigns:
        score, matched = score_rules(campaign.rules, facts)
        candidates.append(Candidate(id=campaign.id, score=score, matched_rules=matched))
    candidates.sort(key=lambda item: (-item.score, item.id))
    if not candidates:
        return "unknown", definition.fallback_pipeline, []
    top = candidates[0]
    target = campaigns[top.id]
    tied = len(candidates) > 1 and candidates[1].score == top.score
    if top.score < target.threshold or tied:
        return "unknown", definition.fallback_pipeline, candidates
    return target.id, target.pipeline, candidates


def topological_steps(pipeline: PipelineDefinition) -> list[CompiledStep]:
    """Validate dependencies and return deterministic topological step order."""
    steps = {step.id: step for step in pipeline.steps}
    if len(steps) != len(pipeline.steps):
        raise ValueError(f"duplicate step ID in {pipeline.metadata.id}")
    for step in pipeline.steps:
        get_step(step.uses)
        missing = set(step.needs) - set(steps)
        if missing:
            raise ValueError(f"step {step.id} has missing dependencies: {sorted(missing)}")
    pending, done, ordered = set(steps), set(), []
    while pending:
        ready = sorted(item for item in pending if set(steps[item].needs) <= done)
        if not ready:
            raise ValueError(f"cycle in pipeline {pipeline.metadata.id}")
        for item in ready:
            step = steps[item]
            ordered.append(CompiledStep(id=step.id, uses=step.uses, needs=step.needs, on_error=step.on_error))
            pending.remove(item)
            done.add(item)
    return ordered


def compile_plan(
    malware: list[MalwareDefinition], pipelines: dict[str, PipelineDefinition], policy: PolicyDefinition, facts: dict
) -> AnalysisPlan:
    """Compile a non-executing plan and enforce the policy capability ceiling."""
    family, family_candidates = select_family(malware, facts)
    if family is None:
        return AnalysisPlan(
            family="unknown",
            campaign="unknown",
            pipeline="unknown.family_static",
            policy=policy.metadata.id,
            status="needs_review",
            reasons=["no unique family exceeded its threshold"],
            family_candidates=family_candidates,
        )
    campaign, pipeline_id, campaign_candidates = select_campaign(family, facts)
    if pipeline_id not in pipelines:
        raise ValueError(f"missing pipeline: {pipeline_id}")
    pipeline = pipelines[pipeline_id]
    required = set(pipeline.capabilities)
    for step in pipeline.steps:
        required.update(get_step(step.uses).capabilities)
    blocked = sorted((required & set(policy.deny)) | (required - set(policy.allow)))
    status = "blocked" if blocked else ("needs_review" if campaign == "unknown" else "ready")
    reasons = [f"capability not allowed: {item}" for item in blocked]
    if campaign == "unknown":
        reasons.append("no unique campaign exceeded its threshold")
    return AnalysisPlan(
        family=family.metadata.id,
        campaign=campaign,
        pipeline=pipeline_id,
        policy=policy.metadata.id,
        status=status,
        reasons=reasons,
        family_candidates=family_candidates,
        campaign_candidates=campaign_candidates,
        required_capabilities=sorted(required),
        steps=topological_steps(pipeline),
    )
