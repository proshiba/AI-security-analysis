"""HijackLoaderの汎用ClickFix誤検知に対する回帰試験。"""

from pathlib import Path

from asa.compiler import rank_families, select_family
from asa.loader import index_definitions, load_definition_tree
from asa.models import MalwareDefinition


DEFINITIONS = Path(__file__).parents[1] / "definitions"


def test_clickfix_url_module_alone_is_not_hijackloader() -> None:
    malware = list(
        index_definitions(load_definition_tree(DEFINITIONS), MalwareDefinition).values()
    )
    facts = {
        "classification": {"family_hint": None},
        "static": {"strings_ci": ["clickfix", "url", "module"]},
    }
    family, _candidates = select_family(malware, facts)
    scores = {candidate.id: candidate.score for candidate in rank_families(malware, facts)}
    assert family is None or family.metadata.id != "hijackloader"
    assert scores["hijackloader"] == 0
