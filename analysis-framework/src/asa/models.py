"""Typed models for declarative analysis definitions and compiled plans."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class StrictModel(BaseModel):
    """Base model that rejects unknown definition fields."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True)


class Metadata(StrictModel):
    """Stable identity and version metadata for a definition."""

    id: str
    display_name: str | None = None
    version: str = "1.0.0"


class Condition(StrictModel):
    """A safe structural condition with no executable expression strings."""

    fact: str | None = None
    exists: bool | None = None
    equals: Any | None = None
    contains: Any | None = None
    contains_any: list[Any] | None = None
    contains_all: list[Any] | None = None
    in_values: list[Any] | None = Field(default=None, alias="in")
    matches: str | None = None
    gte: float | None = None
    lte: float | None = None
    all_of: list[Condition] | None = Field(default=None, alias="all")
    any_of: list[Condition] | None = Field(default=None, alias="any")
    not_: Condition | None = Field(default=None, alias="not")

    @model_validator(mode="after")
    def validate_shape(self) -> "Condition":
        """Require exactly one composite or one fact operator."""
        composites = [self.all_of is not None, self.any_of is not None, self.not_ is not None]
        operators = [
            self.exists is not None,
            self.equals is not None,
            self.contains is not None,
            self.contains_any is not None,
            self.contains_all is not None,
            self.in_values is not None,
            self.matches is not None,
            self.gte is not None,
            self.lte is not None,
        ]
        if sum(composites) == 1 and not any(operators) and self.fact is None:
            return self
        if not any(composites) and self.fact and sum(operators) == 1:
            return self
        raise ValueError("condition must contain one composite or one fact operator")


class Rule(StrictModel):
    """A weighted classification rule."""

    id: str
    weight: int
    when: Condition


class FamilyClassifier(StrictModel):
    """Family-level scoring rules."""

    threshold: int = 70
    tie_policy: Literal["unknown"] = "unknown"
    rules: list[Rule]


class CampaignDefinition(StrictModel):
    """Campaign scoring rules and selected pipeline."""

    id: str
    threshold: int = 70
    rules: list[Rule]
    pipeline: str


class ClassificationDefinition(StrictModel):
    """Two-stage family and campaign classification."""

    family: FamilyClassifier
    campaigns: list[CampaignDefinition]


class MalwareDefinition(StrictModel):
    """A complete malware-family declarative definition."""

    api_version: Literal["asa/v1alpha1"]
    kind: Literal["MalwareAnalysisDefinition"]
    metadata: Metadata
    classification: ClassificationDefinition
    fallback_pipeline: str


class PipelineStep(StrictModel):
    """One allowlisted step in an analysis DAG."""

    id: str
    uses: str
    needs: list[str] = Field(default_factory=list)
    when: Condition | None = None
    on_error: Literal["fail", "partial", "block"] = "fail"


class PipelineDefinition(StrictModel):
    """Declarative analysis DAG and capability requirements."""

    api_version: Literal["asa/v1alpha1"]
    kind: Literal["AnalysisPipeline"]
    metadata: Metadata
    capabilities: list[str] = Field(default_factory=list)
    steps: list[PipelineStep]


class PolicyDefinition(StrictModel):
    """Execution capability ceiling."""

    api_version: Literal["asa/v1alpha1"]
    kind: Literal["ExecutionPolicy"]
    metadata: Metadata
    allow: list[str] = Field(default_factory=list)
    deny: list[str] = Field(default_factory=list)


class Candidate(StrictModel):
    """One scored family or campaign candidate."""

    id: str
    score: int
    matched_rules: list[str]


class CompiledStep(StrictModel):
    """A validated step in topological execution order."""

    id: str
    uses: str
    needs: list[str]
    on_error: str


class AnalysisPlan(StrictModel):
    """Dry-run output describing exactly what the engine would execute."""

    schema_version: int = 1
    family: str
    campaign: str
    pipeline: str
    policy: str
    status: Literal["ready", "needs_review", "blocked"]
    reasons: list[str] = Field(default_factory=list)
    family_candidates: list[Candidate] = Field(default_factory=list)
    campaign_candidates: list[Candidate] = Field(default_factory=list)
    required_capabilities: list[str] = Field(default_factory=list)
    steps: list[CompiledStep] = Field(default_factory=list)
    executed: bool = False
    network_contacted: bool = False
