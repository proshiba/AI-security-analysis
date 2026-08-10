'''既知family候補の安全なhandler試行と誤昇格防止を検証する。'''

from __future__ import annotations

import hashlib
from pathlib import Path
import sys

import pytest


COMMON_ROOT = Path(__file__).resolve().parents[1] / 'common'
if str(COMMON_ROOT) not in sys.path:
    sys.path.insert(0, str(COMMON_ROOT))

import handler_catalog as catalog  # noqa: E402


@pytest.fixture
def isolated_catalog(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    '''一時allowlist内だけをhandler catalogとして使用する。'''

    repository = tmp_path / 'repository'
    malware_root = repository / 'analysis-framework' / 'malware'
    extractors_root = repository / 'extractors'
    malware_root.mkdir(parents=True)
    extractors_root.mkdir(parents=True)
    monkeypatch.setattr(catalog, 'REPOSITORY_ROOT', repository)
    monkeypatch.setattr(catalog, 'MALWARE_ROOT', malware_root)
    monkeypatch.setattr(catalog, 'EXTRACTORS_ROOT', extractors_root)
    catalog.clear_handler_caches()
    yield repository, malware_root
    catalog.clear_handler_caches()


def _handler_spec(
    repository: Path,
    malware_root: Path,
    family: str,
    source: str,
    *,
    input_formats: tuple[str, ...] = ('data',),
) -> catalog.HandlerSpec:
    family_root = malware_root / family
    family_root.mkdir(parents=True, exist_ok=True)
    path = family_root / 'extract_config.py'
    path.write_text(source, encoding='utf-8')
    return catalog.HandlerSpec(
        id=f'{family}:fixture:extract_config',
        family=family,
        relative_path=path.relative_to(repository).as_posix(),
        callable_name='extract_config',
        invocation='bytes',
        source='malware_family_script',
        automatic=True,
        campaign=None,
        supported_interface=True,
        reason='bounded_static_callable',
        input_formats=input_formats,
        input_contract_source='module_declaration',
        minimum_evidence_score=1,
    )


def _source(result_expression: str, formats: tuple[str, ...] = ('data',)) -> str:
    return (
        f'HANDLER_CONTRACT = {{"input_formats": {list(formats)!r}, '
        '"minimum_evidence_score": 1}\n'
        'def extract_config(data):\n'
        f'    return {result_expression}\n'
    )


def _layer(data: bytes, name: str, parent: str | None = None) -> dict:
    return {
        'name': name,
        'data': data,
        'sha256': hashlib.sha256(data).hexdigest(),
        'parent_sha256': parent,
        'depth': 0 if parent is None else 1,
        'transform': 'root' if parent is None else 'fixture_extract',
    }


def _structural_detector() -> dict:
    return {
        'detector_matched': True,
        'detection': {
            'matched': True,
            'confidence': 'high',
            'observations': {'marker_hits': ['independent-family-marker']},
        },
    }


def test_multiple_candidates_try_every_layer_and_confirm_only_correlated_family(
    isolated_catalog,
) -> None:
    repository, malware_root = isolated_catalog
    family_a = _handler_spec(
        repository,
        malware_root,
        'family_a',
        _source("{'marker_hits': ['family-a-config-marker']}"),
    )
    family_b = _handler_spec(
        repository,
        malware_root,
        'family_b',
        _source("{'confidence': 'high', 'family': 'family_b'}"),
    )
    root = _layer(b'MZ-root-container', 'root.exe')
    child = _layer(b'family-a-inner-data', 'inner.bin', root['sha256'])

    result = catalog.assess_candidate_handlers(
        [
            {'family': 'family_a', 'source': 'metadata_hint'},
            {'family': 'family_b', 'source': 'metadata_hint'},
        ],
        [root, child],
        specs=[family_a, family_b],
        detector_evaluations={
            'family_a': {root['sha256']: _structural_detector()},
            'family_b': {root['sha256']: {'matched': True, 'confidence': 'high'}},
        },
    )

    assert result['confirmed_families'] == ['family_a']
    assert result['planned_attempt_count'] == 4
    by_family = {item['family']: item for item in result['families']}
    assert by_family['family_a']['status'] == 'confirmed'
    assert [item['status'] for item in by_family['family_a']['attempts']] == [
        'preflight_blocked',
        'corroborated',
    ]
    assert by_family['family_a']['attempts'][1]['detector_corroboration']['lineage_distance'] == 1
    assert by_family['family_b']['status'] == 'no_evidence'
    assert by_family['family_b']['attempts'][1]['status'] == 'no_evidence'
    assert result['metadata_hint_can_confirm'] is False


def test_handler_evidence_without_detector_is_not_confirmed(isolated_catalog) -> None:
    repository, malware_root = isolated_catalog
    spec = _handler_spec(
        repository,
        malware_root,
        'candidate_family',
        _source("{'marker_hits': ['strong-handler-marker']}"),
    )
    layer = _layer(b'candidate payload', 'payload.bin')

    result = catalog.assess_candidate_handlers(
        [{'family': 'candidate_family', 'source': 'metadata_hint'}],
        [layer],
        specs=[spec],
        detector_evaluations={
            'candidate_family': {
                layer['sha256']: {'matched': True, 'confidence': 'high'}
            }
        },
    )

    family = result['families'][0]
    assert result['confirmed_families'] == []
    assert family['status'] == 'handler_evidence_without_detector'
    assert family['attempts'][0]['detector_corroboration']['basis'] == (
        'no_corroborated_detector_in_lineage'
    )


@pytest.mark.parametrize(
    'result_expression',
    [
        '{}',
        "{'confidence': 'confirmed', 'family': 'candidate_family', 'matched': True}",
    ],
    ids=['empty_result', 'self_reported_confidence'],
)
def test_empty_or_self_reported_result_is_not_evidence(
    isolated_catalog,
    result_expression: str,
) -> None:
    repository, malware_root = isolated_catalog
    spec = _handler_spec(
        repository,
        malware_root,
        'candidate_family',
        _source(result_expression),
    )
    layer = _layer(b'candidate payload', 'payload.bin')
    result = catalog.assess_candidate_handlers(
        ['candidate_family'],
        [layer],
        specs=[spec],
        detector_evaluations={
            'candidate_family': {layer['sha256']: _structural_detector()}
        },
    )

    attempt = result['families'][0]['attempts'][0]
    assert attempt['status'] == 'no_evidence'
    assert attempt['handler_evidence']['tier_name'] == 'no_evidence'
    assert result['confirmed_families'] == []


@pytest.mark.parametrize('location', ['import_time', 'reachable'])
def test_side_effect_is_blocked_before_handler_import(
    isolated_catalog,
    location: str,
) -> None:
    repository, malware_root = isolated_catalog
    touched = malware_root / 'candidate_family' / 'touched.txt'
    contract = (
        'HANDLER_CONTRACT = {"input_formats": ["data"], '
        '"minimum_evidence_score": 1}\n'
    )
    if location == 'import_time':
        source = (
            'from pathlib import Path\n'
            f'Path({str(touched)!r}).write_text("bad", encoding="utf-8")\n'
            + contract
            + 'def extract_config(data):\n'
            "    return {'marker_hits': ['marker']}\n"
        )
    else:
        source = (
            'from pathlib import Path\n'
            + contract
            + 'def write_result(data):\n'
            f'    Path({str(touched)!r}).write_text("bad", encoding="utf-8")\n'
            "    return {'marker_hits': ['marker']}\n"
            + 'def extract_config(data):\n'
            '    return write_result(data)\n'
        )
    spec = _handler_spec(repository, malware_root, 'candidate_family', source)
    layer = _layer(b'candidate payload', 'payload.bin')

    result = catalog.assess_candidate_handlers(
        ['candidate_family'],
        [layer],
        specs=[spec],
        detector_evaluations={
            'candidate_family': {layer['sha256']: _structural_detector()}
        },
    )

    attempt = result['families'][0]['attempts'][0]
    assert attempt['status'] == 'preflight_blocked'
    assert any(location in blocker for blocker in attempt['preflight']['blockers'])
    assert not touched.exists()


def test_unreachable_cli_writer_does_not_block_pure_handler(isolated_catalog) -> None:
    repository, malware_root = isolated_catalog
    source = (
        'from pathlib import Path\n'
        'HANDLER_CONTRACT = {"input_formats": ["data"], '
        '"minimum_evidence_score": 1}\n'
        'def extract_config(data):\n'
        "    return {'marker_hits': ['marker']}\n"
        'def main():\n'
        '    Path("cli-output.json").write_text("cli", encoding="utf-8")\n'
    )
    spec = _handler_spec(repository, malware_root, 'candidate_family', source)
    preflight = catalog.preflight_handler_for_assessment(
        spec,
        actual_format='data',
        input_size=10,
    )
    assert preflight['eligible'] is True


def test_size_and_unbounded_format_contracts_fail_closed(isolated_catalog) -> None:
    repository, malware_root = isolated_catalog
    bounded = _handler_spec(
        repository,
        malware_root,
        'bounded_family',
        _source("{'marker_hits': ['marker']}"),
    )
    unbounded = _handler_spec(
        repository,
        malware_root,
        'unbounded_family',
        _source("{'marker_hits': ['marker']}", ('any',)),
        input_formats=('any',),
    )
    assert catalog.preflight_handler_for_assessment(
        bounded,
        actual_format='data',
        input_size=5,
        maximum_input_size=4,
    )['blockers'] == ['input_size_limit_exceeded']
    assert 'unbounded_input_format_contract' in catalog.preflight_handler_for_assessment(
        unbounded,
        actual_format='data',
        input_size=5,
    )['blockers']


def test_sibling_layer_detector_does_not_corroborate_handler(isolated_catalog) -> None:
    repository, malware_root = isolated_catalog
    spec = _handler_spec(
        repository,
        malware_root,
        'candidate_family',
        _source("{'marker_hits': ['marker']}"),
    )
    root = _layer(b'MZ-root', 'root.exe')
    detector_child = _layer(b'detector-child', 'detector.bin', root['sha256'])
    handler_child = _layer(b'handler-child', 'handler.bin', root['sha256'])
    result = catalog.assess_candidate_handlers(
        ['candidate_family'],
        [root, detector_child, handler_child],
        specs=[spec],
        detector_evaluations={
            'candidate_family': {
                detector_child['sha256']: _structural_detector()
            }
        },
    )

    attempts = result['families'][0]['attempts']
    handler_attempt = next(item for item in attempts if item['layer']['sha256'] == handler_child['sha256'])
    assert handler_attempt['status'] == 'handler_evidence_without_detector'


def test_attempt_limit_is_checked_before_handler_import(isolated_catalog) -> None:
    repository, malware_root = isolated_catalog
    spec = _handler_spec(
        repository,
        malware_root,
        'candidate_family',
        _source("{'marker_hits': ['marker']}"),
    )
    layers = [_layer(b'layer-one', 'one.bin'), _layer(b'layer-two', 'two.bin')]
    with pytest.raises(ValueError, match='候補試行数上限'):
        catalog.assess_candidate_handlers(
            ['candidate_family'],
            layers,
            specs=[spec],
            maximum_attempts=1,
        )


def test_claimed_layer_format_cannot_override_static_detection(isolated_catalog) -> None:
    repository, malware_root = isolated_catalog
    spec = _handler_spec(
        repository,
        malware_root,
        'candidate_family',
        _source("{'marker_hits': ['marker']}"),
    )
    layer = _layer(b'plain data', 'payload.bin')
    layer['format'] = 'pe'
    with pytest.raises(ValueError, match='formatがdataの識別結果と一致しません'):
        catalog.assess_candidate_handlers(
            ['candidate_family'],
            [layer],
            specs=[spec],
        )


def test_layer_parent_must_exist_and_dag_must_be_acyclic(isolated_catalog) -> None:
    repository, malware_root = isolated_catalog
    spec = _handler_spec(
        repository,
        malware_root,
        'candidate_family',
        _source("{'marker_hits': ['marker']}"),
    )
    missing_parent = _layer(b'child', 'child.bin', 'a' * 64)
    with pytest.raises(ValueError, match='親SHA-256が入力集合にありません'):
        catalog.assess_candidate_handlers(
            ['candidate_family'],
            [missing_parent],
            specs=[spec],
        )

    first = _layer(b'first', 'first.bin')
    second = _layer(b'second', 'second.bin', first['sha256'])
    first['parent_sha256'] = second['sha256']
    with pytest.raises(ValueError, match='親子関係に循環'):
        catalog.assess_candidate_handlers(
            ['candidate_family'],
            [first, second],
            specs=[spec],
        )


def test_all_discovered_automatic_handlers_pass_assessment_preflight() -> None:
    '''現行automatic handlerを候補試行へ接続できる状態に保つ。'''

    blocked = {}
    automatic = [item for item in catalog.discover_handlers() if item.automatic]
    for spec in automatic:
        actual_format = next(
            (item for item in spec.input_formats if item != 'any'),
            'data',
        )
        preflight = catalog.preflight_handler_for_assessment(
            spec,
            actual_format=actual_format,
            input_size=4_096,
        )
        if not preflight['eligible']:
            blocked[spec.id] = preflight['blockers']
    assert len(automatic) >= 90
    assert blocked == {}
