"""Unit tests for every function in the declarative planning engine."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from asa import cli
from asa.catalog import get_step, list_steps, parse_step_reference
from asa.compiler import compile_plan, rank_families, select_campaign, select_family, topological_steps
from asa.conditions import evaluate_condition, resolve_fact, score_rules
from asa.loader import index_definitions, load_definition_tree, load_yaml, parse_definition
from asa.models import Condition, MalwareDefinition, PipelineDefinition, PolicyDefinition, Rule

DEFINITIONS = Path(__file__).parents[1] / "definitions"


def test_condition_model_and_all_operators() -> None:
    facts = {"x": {"value": 5, "items": ["a", "b"], "text": "hello-123"}}
    assert resolve_fact(facts, "x.value") == (True, 5)
    assert resolve_fact(facts, "x.missing") == (False, None)
    conditions = [
        Condition(fact="x.value", exists=True),
        Condition(fact="x.value", equals=5),
        Condition(fact="x.items", contains="a"),
        Condition(fact="x.items", contains_any=["z", "a"]),
        Condition(fact="x.items", contains_all=["a", "b"]),
        Condition.model_validate({"fact": "x.value", "in": [4, 5]}),
        Condition(fact="x.text", matches=r"hello-\d+"),
        Condition(fact="x.value", gte=5),
        Condition(fact="x.value", lte=5),
        Condition.model_validate({"all": [{"fact": "x.value", "equals": 5}]}),
        Condition.model_validate({"any": [{"fact": "x.value", "equals": 5}]}),
        Condition.model_validate({"not": {"fact": "x.value", "equals": 6}}),
    ]
    assert all(evaluate_condition(item, facts) for item in conditions)
    assert not evaluate_condition(Condition(fact="x.missing", equals=1), facts)
    with pytest.raises(ValueError, match="regex"):
        evaluate_condition(Condition(fact="x.text", matches="x" * 257), facts)
    with pytest.raises(ValidationError):
        Condition(fact="x.value", equals=5, gte=1)


def test_score_rules() -> None:
    rules = [
        Rule(id="yes", weight=10, when=Condition(fact="a", equals=1)),
        Rule(id="no", weight=20, when=Condition(fact="a", equals=2)),
    ]
    assert score_rules(rules, {"a": 1}) == (10, ["yes"])


def test_loader_functions_and_indexes(tmp_path: Path) -> None:
    source = DEFINITIONS / "policies" / "offline-default.yaml"
    value = load_yaml(source)
    assert isinstance(parse_definition(value), PolicyDefinition)
    bad = tmp_path / "bad.yaml"
    bad.write_text("- not-a-mapping\n", encoding="utf-8")
    with pytest.raises(ValueError, match="mapping"):
        load_yaml(bad)
    with pytest.raises(ValueError, match="unsupported"):
        parse_definition({"kind": "Other"})
    definitions = load_definition_tree(DEFINITIONS)
    malware = index_definitions(definitions, MalwareDefinition)
    assert set(malware) == {
        "agenttesla",
        "amosstealer",
        "formbook",
        "lummastealer",
        "donutloader",
        "purehvnc",
        "mx-go",
        "remcosrat",
        "remusstealer",
        "spyglace",
        "valleyrat",
        "venomrat",
        "vidar",
    }
    with pytest.raises(ValueError, match="duplicate"):
        index_definitions([malware["agenttesla"], malware["agenttesla"]], MalwareDefinition)


def test_catalog_functions() -> None:
    assert parse_step_reference("static.pe.inspect@^1") == ("static.pe.inspect", 1)
    assert get_step("static.pe.inspect@^1").id == "static.pe.inspect"
    assert list_steps() == sorted(list_steps(), key=lambda item: item.id)
    for value in ("static.pe.inspect", "bad/path@^1", "unknown@^1", "static.pe.inspect@^2"):
        with pytest.raises((ValueError, TypeError)):
            get_step(value)


def test_compiler_functions_and_policy() -> None:
    definitions = load_definition_tree(DEFINITIONS)
    malware = list(index_definitions(definitions, MalwareDefinition).values())
    pipelines = index_definitions(definitions, PipelineDefinition)
    policy = index_definitions(definitions, PolicyDefinition)["offline-default"]
    facts = {
        "classification": {"family_hint": "agenttesla", "campaign_hint": "javascript_aes_inmemory_dotnet"},
        "static": {"strings_ci": []},
    }
    ranked = rank_families(malware, facts)
    assert ranked[0].id == "agenttesla"
    family, _ = select_family(malware, facts)
    assert family and family.metadata.id == "agenttesla"
    campaign, pipeline, _ = select_campaign(family, facts)
    assert (campaign, pipeline) == ("javascript_aes_inmemory_dotnet", "agenttesla.config")
    order = topological_steps(pipelines[pipeline])
    assert order[0].id == "intake" and order[-1].id == "report"
    plan = compile_plan(malware, pipelines, policy, facts)
    assert plan.status == "ready" and not plan.executed and not plan.network_contacted
    unknown = compile_plan(malware, pipelines, policy, {})
    assert unknown.status == "needs_review"
    blocked_policy = policy.model_copy(update={"deny": [*policy.deny, "filesystem.sample.read"]})
    assert compile_plan(malware, pipelines, blocked_policy, facts).status == "blocked"


def test_topology_errors() -> None:
    base = {"api_version": "asa/v1alpha1", "kind": "AnalysisPipeline", "metadata": {"id": "bad"}, "steps": []}
    duplicate = PipelineDefinition.model_validate(
        {**base, "steps": [{"id": "x", "uses": "static.pe.inspect@^1"}, {"id": "x", "uses": "static.pe.inspect@^1"}]}
    )
    with pytest.raises(ValueError, match="duplicate"):
        topological_steps(duplicate)
    missing = PipelineDefinition.model_validate(
        {**base, "steps": [{"id": "x", "uses": "static.pe.inspect@^1", "needs": ["y"]}]}
    )
    with pytest.raises(ValueError, match="missing"):
        topological_steps(missing)
    cycle = PipelineDefinition.model_validate(
        {
            **base,
            "steps": [
                {"id": "x", "uses": "static.pe.inspect@^1", "needs": ["y"]},
                {"id": "y", "uses": "static.pe.inspect@^1", "needs": ["x"]},
            ],
        }
    )
    with pytest.raises(ValueError, match="cycle"):
        topological_steps(cycle)


def test_cli_functions(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.build_parser().parse_args(["validate", "--definitions", str(DEFINITIONS)]).command == "validate"
    assert cli.validate_definitions(DEFINITIONS) == {"malware": 13, "pipelines": 15, "policies": 1}
    facts = tmp_path / "facts.json"
    facts.write_text(
        json.dumps(
            {
                "classification": {"family_hint": "mx-go", "campaign_hint": "remotely_controlled_bulk_email_spam_bot"},
                "static": {"strings_ci": []},
            }
        ),
        encoding="utf-8",
    )
    assert cli.create_plan(DEFINITIONS, facts, "offline-default").family == "mx-go"
    with pytest.raises(ValueError, match="unknown policy"):
        cli.create_plan(DEFINITIONS, facts, "missing")
    assert cli.main(["validate", "--definitions", str(DEFINITIONS)]) == 0
    assert '"malware": 13' in capsys.readouterr().out
    output = tmp_path / "plan.json"
    assert cli.main(["plan", "--definitions", str(DEFINITIONS), "--facts", str(facts), "--output", str(output)]) == 0
    assert output.exists()
