"""Load and validate versioned YAML definitions."""

from __future__ import annotations

from pathlib import Path
from typing import TypeVar

import yaml
from pydantic import BaseModel

from .models import MalwareDefinition, PipelineDefinition, PolicyDefinition

Definition = MalwareDefinition | PipelineDefinition | PolicyDefinition
T = TypeVar("T", bound=BaseModel)


def load_yaml(path: Path) -> dict:
    """Load one YAML mapping with strict model validation downstream."""
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"definition must be a mapping: {path}")
    return value


def parse_definition(value: dict) -> Definition:
    """Dispatch a raw mapping to its strict typed model."""
    models = {
        "MalwareAnalysisDefinition": MalwareDefinition,
        "AnalysisPipeline": PipelineDefinition,
        "ExecutionPolicy": PolicyDefinition,
    }
    kind = value.get("kind")
    if kind not in models:
        raise ValueError(f"unsupported definition kind: {kind}")
    return models[kind].model_validate(value)


def load_definition_tree(root: Path) -> list[Definition]:
    """Load every YAML definition below a directory in deterministic order."""
    return [parse_definition(load_yaml(path)) for path in sorted(root.rglob("*.yaml"))]


def index_definitions(definitions: list[Definition], model: type[T]) -> dict[str, T]:
    """Index one definition kind by metadata ID and reject duplicates."""
    result: dict[str, T] = {}
    for item in definitions:
        if isinstance(item, model):
            if item.metadata.id in result:
                raise ValueError(f"duplicate definition ID: {item.metadata.id}")
            result[item.metadata.id] = item
    return result
