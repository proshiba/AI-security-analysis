"""Evaluation helpers for the non-executable condition DSL."""

from __future__ import annotations

import re
from typing import Any

from .models import Condition, Rule


def resolve_fact(facts: dict[str, Any], path: str) -> tuple[bool, Any]:
    """Resolve a dotted path without evaluating code."""
    value: Any = facts
    for part in path.split("."):
        if not isinstance(value, dict) or part not in value:
            return False, None
        value = value[part]
    return True, value


def evaluate_condition(condition: Condition, facts: dict[str, Any]) -> bool:
    """Evaluate one validated condition against discovery facts."""
    if condition.all_of is not None:
        return all(evaluate_condition(item, facts) for item in condition.all_of)
    if condition.any_of is not None:
        return any(evaluate_condition(item, facts) for item in condition.any_of)
    if condition.not_ is not None:
        return not evaluate_condition(condition.not_, facts)
    found, value = resolve_fact(facts, condition.fact or "")
    if condition.exists is not None:
        return found is condition.exists
    if not found:
        return False
    if condition.equals is not None:
        return value == condition.equals
    if condition.contains is not None:
        return condition.contains in value
    if condition.contains_any is not None:
        return any(item in value for item in condition.contains_any)
    if condition.contains_all is not None:
        return all(item in value for item in condition.contains_all)
    if condition.in_values is not None:
        return value in condition.in_values
    if condition.matches is not None:
        if len(condition.matches) > 256:
            raise ValueError("regex exceeds 256 characters")
        return re.search(condition.matches, str(value)) is not None
    if condition.gte is not None:
        return float(value) >= condition.gte
    if condition.lte is not None:
        return float(value) <= condition.lte
    return False


def score_rules(rules: list[Rule], facts: dict[str, Any]) -> tuple[int, list[str]]:
    """Return the total score and matched rule IDs."""
    matched = [rule.id for rule in rules if evaluate_condition(rule.when, facts)]
    weights = {rule.id: rule.weight for rule in rules}
    return sum(weights[item] for item in matched), matched
