"""HijackLoaderの汎用ClickFix誤検知に対する回帰試験。"""

from pathlib import Path

from asa.compiler import rank_families, select_family
from asa.loader import index_definitions, load_definition_tree
from asa.models import MalwareDefinition


DEFINITIONS = Path(__file__).parents[1] / "definitions"


def test_clickfix_url_module_alone_is_not_hijackloader() -> None:
    malware = list(index_definitions(load_definition_tree(DEFINITIONS), MalwareDefinition).values())
    facts = {
        "classification": {"family_hint": None},
        "static": {"strings_ci": ["clickfix", "url", "module"]},
    }
    family, _candidates = select_family(malware, facts)
    scores = {candidate.id: candidate.score for candidate in rank_families(malware, facts)}
    assert family is None or family.metadata.id != "hijackloader"
    assert scores["hijackloader"] == 0


def test_short_idat_esal_strings_are_not_hijackloader() -> None:
    """短いIDAT・ESALと汎用設定語だけではHijackLoaderにしない。"""

    malware = list(index_definitions(load_definition_tree(DEFINITIONS), MalwareDefinition).values())
    facts = {
        "classification": {"family_hint": None},
        "static": {"strings_ci": ["idat", "esal", "url", "module"]},
    }
    family, _candidates = select_family(malware, facts)
    scores = {candidate.id: candidate.score for candidate in rank_families(malware, facts)}
    assert family is None or family.metadata.id != "hijackloader"
    assert scores["hijackloader"] == 0


def test_high_specificity_hijackloader_literals_reach_threshold() -> None:
    """固有phraseが独立して揃う場合は宣言型判定の閾値へ達する。"""

    malware = list(index_definitions(load_definition_tree(DEFINITIONS), MalwareDefinition).values())
    facts = {
        "classification": {"family_hint": None},
        "static": {"strings_ci": ["hijackloader", "module stomping", "url"]},
    }
    family, _candidates = select_family(malware, facts)
    scores = {candidate.id: candidate.score for candidate in rank_families(malware, facts)}
    assert family is not None
    assert family.metadata.id == "hijackloader"
    assert scores["hijackloader"] >= 70
