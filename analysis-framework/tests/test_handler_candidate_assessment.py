'''既知family候補の安全なhandler試行と誤昇格防止を検証する。'''

from __future__ import annotations

import base64
import hashlib
import json
import os
import sys
import types
from pathlib import Path

import pytest

COMMON_ROOT = Path(__file__).resolve().parents[1] / 'common'
if str(COMMON_ROOT) not in sys.path:
    sys.path.insert(0, str(COMMON_ROOT))

import bounded_process  # noqa: E402
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


def _candidate(family: str, source: str = 'metadata_hint') -> dict:
    return {
        'family': family,
        'source': source,
        'routing_eligible': True,
        'routing_mode': 'candidate_verification',
        'routing_eligibility': {'candidate_verification': True},
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
            _candidate('family_a'),
            _candidate('family_b'),
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
        [_candidate('candidate_family')],
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
    'candidate',
    [
        {
            'family': 'candidate_family',
            'source': 'metadata_hint',
            'routing_eligible': False,
            'routing_mode': 'blocked',
        },
        {'family': 'candidate_family', 'source': 'metadata_hint'},
        {
            'family': 'candidate_family',
            'source': 'metadata_hint',
            'routing_eligible': True,
            'routing_mode': 'candidate_verification',
            'routing_eligibility': {'candidate_verification': False},
        },
    ],
)
def test_mapping_candidate_without_complete_routing_authorization_is_blocked(
    isolated_catalog,
    monkeypatch: pytest.MonkeyPatch,
    candidate: dict,
) -> None:
    """routing許可が欠けるmapping候補はpreflightもworkerも起動しない。"""

    repository, malware_root = isolated_catalog
    spec = _handler_spec(
        repository,
        malware_root,
        'candidate_family',
        _source("{'marker_hits': ['marker']}"),
    )
    called = []
    monkeypatch.setattr(
        catalog,
        '_execute_handler_bounded',
        lambda *_args, **_kwargs: called.append(True),
    )
    result = catalog.assess_candidate_handlers(
        [candidate],
        [_layer(b'candidate payload', 'payload.bin')],
        specs=[spec],
    )

    family = result['families'][0]
    assert family['status'] == 'blocked'
    assert family['attempts'] == []
    assert result['planned_attempt_count'] == 0
    assert result['blocked_candidate_count'] == 1
    assert called == []


def test_string_candidate_is_explicit_caller_selected_compatibility(isolated_catalog) -> None:
    """文字列候補は後方互換としてcaller明示選択のverification候補に限定する。"""

    repository, malware_root = isolated_catalog
    spec = _handler_spec(
        repository,
        malware_root,
        'candidate_family',
        _source('{}'),
    )
    result = catalog.assess_candidate_handlers(
        ['candidate_family'],
        [_layer(b'candidate payload', 'payload.bin')],
        specs=[spec],
    )
    family = result['families'][0]
    assert family['routing_eligible'] is True
    assert family['routing_mode'] == 'candidate_verification'
    assert family['caller_selected_string'] is True
    assert family['sources'] == ['explicit_caller_candidate']


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


@pytest.mark.parametrize('location', ['import_time', 'reachable'])
def test_repository_local_import_alias_side_effect_is_blocked_recursively(
    isolated_catalog,
    location: str,
) -> None:
    """alias付きlocal helperのimport時・到達関数副作用をfile間で検出する。"""

    repository, malware_root = isolated_catalog
    family_root = malware_root / 'candidate_family'
    family_root.mkdir(parents=True, exist_ok=True)
    touched = family_root / 'touched.txt'
    if location == 'import_time':
        helper = (
            'from pathlib import Path\n'
            f'Path({str(touched)!r}).write_text("bad", encoding="utf-8")\n'
            'def exfiltrate(data):\n'
            "    return {'marker_hits': ['marker']}\n"
        )
    else:
        helper = (
            'from pathlib import Path\n'
            'def exfiltrate(data):\n'
            f'    Path({str(touched)!r}).write_text("bad", encoding="utf-8")\n'
            "    return {'marker_hits': ['marker']}\n"
        )
    (family_root / 'helper_module.py').write_text(helper, encoding='utf-8')
    source = (
        'from helper_module import exfiltrate as helper\n'
        'HANDLER_CONTRACT = {"input_formats": ["data"], "minimum_evidence_score": 1}\n'
        'def extract_config(data):\n'
        '    return helper(data)\n'
    )
    spec = _handler_spec(repository, malware_root, 'candidate_family', source)
    preflight = catalog.preflight_handler_for_assessment(
        spec,
        actual_format='data',
        input_size=10,
    )
    assert preflight['eligible'] is False
    assert any(location in blocker for blocker in preflight['blockers'])
    assert preflight['dependency_audit']['files_inspected'] == 2
    assert not touched.exists()


def test_dependency_source_manifest_rejects_forged_records(
    isolated_catalog,
) -> None:
    """workerへ渡す依存manifestはexact schema・安全path・現在hashへ結合する。"""

    repository, malware_root = isolated_catalog
    spec = _handler_spec(
        repository,
        malware_root,
        'candidate_family',
        _source("{'marker_hits': ['marker']}"),
    )
    source = repository / spec.relative_path
    relative = source.relative_to(repository).as_posix()
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    valid = [{'path': relative, 'sha256': digest}]

    assert catalog._validated_dependency_source_manifest(
        valid,
        repository=repository,
    ) == valid
    forged_values = [
        [{**valid[0], 'extra': True}],
        [valid[0], valid[0]],
        [{'path': '../escape.py', 'sha256': digest}],
        [{'path': relative.replace('/', '\\'), 'sha256': digest}],
        [{'path': relative, 'sha256': '0' * 64}],
    ]
    for forged in forged_values:
        with pytest.raises(catalog.HandlerLoadError):
            catalog._validated_dependency_source_manifest(
                forged,
                repository=repository,
            )

    directory = source.parent / 'directory.py'
    directory.mkdir()
    with pytest.raises(catalog.HandlerLoadError):
        catalog._validated_dependency_source_manifest(
            [
                {
                    'path': directory.relative_to(repository).as_posix(),
                    'sha256': '0' * 64,
                }
            ],
            repository=repository,
        )


def test_worker_request_rejects_unknown_fields(tmp_path: Path) -> None:
    """isolated workerのrequestは未知fieldを受理しない。"""

    worker_root = tmp_path / 'worker'
    worker_root.mkdir()
    (worker_root / 'artifacts').mkdir()
    output = worker_root / 'response.json'
    encoded = base64.urlsafe_b64encode(
        json.dumps({'unexpected': True}).encode('utf-8')
    ).decode('ascii').rstrip('=')

    assert catalog._assessment_worker_main(encoded, str(output)) == 0
    response = json.loads(output.read_text(encoding='utf-8'))
    assert response == {
        'ok': False,
        'error': 'handler_worker_failed',
        'error_type': 'HandlerLoadError',
    }


def test_unresolved_dynamic_callable_fails_closed(isolated_catalog) -> None:
    """getattrで生成した未解決callableは候補handlerとして許可しない。"""

    repository, malware_root = isolated_catalog
    source = (
        'HANDLER_CONTRACT = {"input_formats": ["data"], "minimum_evidence_score": 1}\n'
        'def extract_config(data):\n'
        '    callback = getattr(data, "decode")\n'
        '    return callback()\n'
    )
    spec = _handler_spec(repository, malware_root, 'candidate_family', source)
    preflight = catalog.preflight_handler_for_assessment(
        spec,
        actual_format='data',
        input_size=10,
    )
    assert preflight['eligible'] is False
    assert any('unresolved_higher_order_call:getattr' in item for item in preflight['blockers'])


def test_execute_handler_verifies_raw_terminal_binary_and_separates_self_report(
    isolated_catalog,
) -> None:
    """handler自己申告hashではなくraw bytesをwrapperがhashして公開する。"""

    repository, malware_root = isolated_catalog
    payload = b'MZ' + b'A' * 30
    source = (
        'HANDLER_CONTRACT = {"input_formats": ["data"], "minimum_evidence_score": 1}\n'
        'def extract_config(data):\n'
        '    return {\n'
        '        "verified_binary_outputs": [{"sha256": "0" * 64, "size": 999}],\n'
        f'        "terminal_payload": {{"name": "stage.exe", "data": {payload!r}}},\n'
        '    }\n'
    )
    spec = _handler_spec(repository, malware_root, 'candidate_family', source)
    result = catalog.execute_handler(spec, b'input', 'sample.bin')
    verified = result['verified_binary_outputs']
    assert verified == [
        {
            'role': 'terminal_payload',
            'kind': 'pe',
            'path': 'stage.exe',
            'sha256': hashlib.sha256(payload).hexdigest(),
            'size': len(payload),
            'verification': {
                'status': 'artifact_hash_verified',
                'sha256_matches': True,
                'size_matches': True,
            },
        }
    ]
    assert result['result']['verified_binary_outputs'][0]['sha256'] == '0' * 64
    assert result['result']['terminal_payload']['data']['content_exported'] is False


def test_bounded_handler_retains_raw_payload_only_after_parent_rehash(
    isolated_catalog,
    tmp_path: Path,
) -> None:
    """隔離workerのraw bytesは親再検証後だけrepo外artifactへ保持する。"""

    repository, malware_root = isolated_catalog
    payload = b'MZ' + b'B' * 62
    source = (
        'HANDLER_CONTRACT = {"input_formats": ["data"], "minimum_evidence_score": 1}\n'
        'def extract_config(data):\n'
        f'    return {{"terminal_payload": {{"name": "stage.exe", "data": {payload!r}}}}}\n'
    )
    spec = _handler_spec(repository, malware_root, 'candidate_family', source)
    artifact_directory = tmp_path / 'retained'
    artifact_directory.mkdir()

    bounded = catalog.execute_handler_bounded_for_assessment(
        spec,
        b'input',
        'sample.bin',
        actual_format='data',
        artifact_directory=artifact_directory,
        artifact_path_prefix='recovered-payloads',
    )

    assert bounded['status'] == 'completed'
    execution = bounded['execution']
    digest = hashlib.sha256(payload).hexdigest()
    retained = artifact_directory / f'{digest}.exe'
    assert retained.read_bytes() == payload
    assert execution['verified_binary_outputs'][0]['path'] == (
        f'recovered-payloads/{digest}.exe'
    )
    assert execution['verified_binary_output_audit']['retained_for_follow_on_analysis'] is True
    assert execution['verified_binary_output_audit']['follow_on_analysis_complete'] is False
    assert execution['verified_binary_output_audit']['observation_scope'] == (
        'parent_rehashed_case_artifact'
    )


def test_bounded_handler_without_destination_is_observed_only(
    isolated_catalog,
) -> None:
    """保存先なしのraw bytesはhash観測だけを残しterminal完了へ昇格しない。"""

    repository, malware_root = isolated_catalog
    source = (
        'HANDLER_CONTRACT = {"input_formats": ["data"], "minimum_evidence_score": 1}\n'
        'def extract_config(data):\n'
        '    return {"terminal_payload": b"MZ-observed"}\n'
    )
    spec = _handler_spec(repository, malware_root, 'candidate_family', source)
    bounded = catalog.execute_handler_bounded_for_assessment(
        spec,
        b'input',
        'sample.bin',
        actual_format='data',
    )

    execution = bounded['execution']
    assert execution['verified_binary_outputs'] == []
    assert len(execution['observed_binary_outputs']) == 1
    assert execution['verified_binary_output_audit']['retained_for_follow_on_analysis'] is False
    assert execution['verified_binary_output_audit']['follow_on_analysis_complete'] is False


def test_retention_rejects_repository_destination(
    isolated_catalog,
) -> None:
    """復号payloadをGit repository配下へ保存する指定は拒否する。"""

    repository, malware_root = isolated_catalog
    source = (
        'HANDLER_CONTRACT = {"input_formats": ["data"], "minimum_evidence_score": 1}\n'
        'def extract_config(data):\n'
        '    return {"terminal_payload": b"MZ-repository"}\n'
    )
    spec = _handler_spec(repository, malware_root, 'candidate_family', source)
    forbidden = repository / 'analysis-output'
    forbidden.mkdir()

    with pytest.raises(ValueError, match='repository'):
        catalog.execute_handler_bounded_for_assessment(
            spec,
            b'input',
            'sample.bin',
            actual_format='data',
            artifact_directory=forbidden,
        )


def test_verified_binary_scan_is_bounded_and_cycle_safe(monkeypatch: pytest.MonkeyPatch) -> None:
    """raw result走査はcycleと総byte上限で停止する。"""

    cyclic: dict = {}
    cyclic['terminal_payload'] = cyclic
    outputs, audit = catalog._verified_binary_outputs(cyclic)
    assert outputs == []
    assert 'cycle_detected' in audit['reasons']

    monkeypatch.setattr(catalog, 'MAX_VERIFIED_BINARY_TOTAL_SIZE', 4)
    outputs, audit = catalog._verified_binary_outputs({'terminal_payload': b'MZ123'})
    assert outputs == []
    assert 'maximum_total_binary_size' in audit['reasons']
    assert audit['truncated'] is True


def test_truncated_raw_payload_is_not_staged(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """total-size上限を超えたraw bytesは一時artifactも生成しない。"""

    artifact_root = tmp_path / 'worker-artifacts'
    artifact_root.mkdir()
    monkeypatch.setattr(catalog, 'MAX_VERIFIED_BINARY_TOTAL_SIZE', 4)
    outputs, audit = catalog._verified_binary_outputs(
        {'terminal_payload': b'MZ123'},
        artifact_root=artifact_root,
    )

    assert outputs == []
    assert list(artifact_root.iterdir()) == []
    assert audit['retained_for_follow_on_analysis'] is False
    assert audit['truncated'] is True


def test_public_sanitizer_covers_keys_leading_url_and_set_order() -> None:
    """dict keyと先頭空白URLを秘匿し、setを決定順序で公開する。"""

    secret_key = 'github_pat_' + 'A' * 40
    sanitized = catalog.sanitize_public_value({secret_key: 'value'})
    rendered_key = next(iter(sanitized))
    assert secret_key not in rendered_key
    assert '[REDACTED' in rendered_key
    assert catalog.sanitize_public_value(
        '  https://user:pass@example.test/token/secret?api_key=value  '
    ) == 'https://example.test/token/[REDACTED]'
    assert catalog.sanitize_public_value({'z', 'a', 'm'}) == ['a', 'm', 'z']


def test_load_handler_restores_sys_path(isolated_catalog) -> None:
    """handler importが変更したsys.pathを呼出し元processへ残さない。"""

    repository, malware_root = isolated_catalog
    marker = str(repository / 'poisoned-import-path')
    source = (
        'import sys\n'
        f'sys.path.insert(0, {marker!r})\n'
        'HANDLER_CONTRACT = {"input_formats": ["data"], "minimum_evidence_score": 1}\n'
        'def extract_config(data):\n'
        '    return {}\n'
    )
    spec = _handler_spec(repository, malware_root, 'candidate_family', source)
    original = list(sys.path)
    catalog.load_handler(spec)
    assert sys.path == original
    assert marker not in sys.path


def test_candidate_handler_wall_clock_timeout(isolated_catalog) -> None:
    """停止しないhandlerは別process treeごとtimeoutし、jobを継続可能にする。"""

    repository, malware_root = isolated_catalog
    source = (
        'HANDLER_CONTRACT = {"input_formats": ["data"], "minimum_evidence_score": 1}\n'
        'def extract_config(data):\n'
        '    while True:\n'
        '        pass\n'
    )
    spec = _handler_spec(repository, malware_root, 'candidate_family', source)
    result = catalog.assess_candidate_handlers(
        ['candidate_family'],
        [_layer(b'candidate payload', 'payload.bin')],
        specs=[spec],
        handler_timeout_seconds=0.2,
    )
    assert result['families'][0]['status'] == 'handler_timed_out'
    assert result['families'][0]['attempts'][0]['status'] == 'timed_out'


def test_public_bounded_assessment_api_returns_stable_execution_shape(
    isolated_catalog,
) -> None:
    """selected/candidate共通の公開境界が事前検査と隔離実行結果を返す。"""

    repository, malware_root = isolated_catalog
    spec = _handler_spec(
        repository,
        malware_root,
        'candidate_family',
        _source("{'marker_hits': ['bounded-public-api']}"),
    )
    result = catalog.execute_handler_bounded_for_assessment(
        spec,
        b'candidate payload',
        'payload.bin',
        actual_format='data',
        timeout_seconds=2.0,
    )
    assert result['status'] == 'completed'
    assert result['preflight']['eligible'] is True
    assert result['handler_timeout_seconds'] == 2.0
    assert result['execution']['result']['marker_hits'] == ['bounded-public-api']


def test_worker_rechecks_dependency_manifest_immediately_before_import(
    isolated_catalog,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """親検証後にlocal dependencyを差し替えてもworkerはimportせずfail closedにする。"""

    repository, malware_root = isolated_catalog
    family_root = malware_root / 'candidate_family'
    family_root.mkdir(parents=True, exist_ok=True)
    helper = family_root / 'helper_module.py'
    helper.write_text(
        'def transform(data):\n'
        "    return {'marker_hits': ['safe-helper']}\n",
        encoding='utf-8',
    )
    spec = _handler_spec(
        repository,
        malware_root,
        'candidate_family',
        'from helper_module import transform\n'
        'HANDLER_CONTRACT = {"input_formats": ["data"], '
        '"minimum_evidence_score": 1}\n'
        'def extract_config(data):\n'
        '    return transform(data)\n',
    )
    touched = family_root / 'worker-imported-mutated-helper.txt'
    original_run_bounded = bounded_process.run_bounded
    captured_request: dict = {}

    def mutate_after_parent_check(*args, **kwargs):
        command = args[0]
        token = command[-2]
        padding = '=' * (-len(token) % 4)
        captured_request.update(
            json.loads(
                base64.urlsafe_b64decode((token + padding).encode('ascii')).decode('utf-8')
            )
        )
        helper.write_text(
            'from pathlib import Path\n'
            f'Path({str(touched)!r}).write_text("imported", encoding="utf-8")\n'
            'def transform(data):\n'
            "    return {'marker_hits': ['mutated-helper']}\n",
            encoding='utf-8',
        )
        return original_run_bounded(*args, **kwargs)

    monkeypatch.setattr(bounded_process, 'run_bounded', mutate_after_parent_check)
    result = catalog.execute_handler_bounded_for_assessment(
        spec,
        b'candidate payload',
        'payload.bin',
        actual_format='data',
        timeout_seconds=5.0,
    )

    assert set(captured_request) == {
        'dependency_data_manifest',
        'dependency_module_manifest',
        'dependency_source_manifest',
        'extractors_root',
        'framework_root',
        'malware_root',
        'repository_root',
        'source_name',
        'spec',
    }
    assert [item['path'] for item in captured_request['dependency_source_manifest']] == [
        spec.relative_path,
        helper.relative_to(repository).as_posix(),
    ]
    assert result['status'] == 'failed'
    assert result['error_type'] == 'HandlerLoadError'
    assert not touched.exists()


def test_verified_source_snapshots_ignore_post_verification_path_replacement(
    isolated_catalog,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """検証完了後にpathを差し替えてもmain/helperとも検証済みbytesだけを実行する。"""

    repository, malware_root = isolated_catalog
    family_root = malware_root / 'candidate_family'
    family_root.mkdir(parents=True, exist_ok=True)
    helper = family_root / 'helper_module.py'
    helper.write_text(
        'def transform(data):\n'
        "    return {'marker_hits': ['verified-helper']}\n",
        encoding='utf-8',
    )
    spec = _handler_spec(
        repository,
        malware_root,
        'candidate_family',
        'from helper_module import transform\n'
        'HANDLER_CONTRACT = {"input_formats": ["data"], '
        '"minimum_evidence_score": 1}\n'
        'def extract_config(data):\n'
        '    return transform(data)\n',
    )
    preflight = catalog.preflight_handler_for_assessment(
        spec,
        actual_format='data',
        input_size=7,
    )
    manifest = preflight['dependency_audit']['files']
    original_snapshot = catalog._validated_dependency_source_snapshots
    touched_main = family_root / 'mutated-main-imported.txt'
    touched_helper = family_root / 'mutated-helper-imported.txt'

    def snapshot_then_replace(value, *, repository):
        snapshots = original_snapshot(value, repository=repository)
        (repository / spec.relative_path).write_text(
            'from pathlib import Path\n'
            f'Path({str(touched_main)!r}).write_text("bad", encoding="utf-8")\n'
            'HANDLER_CONTRACT = {"input_formats": ["data"], '
            '"minimum_evidence_score": 1}\n'
            'def extract_config(data):\n'
            "    return {'marker_hits': ['mutated-main']}\n",
            encoding='utf-8',
        )
        helper.write_text(
            'from pathlib import Path\n'
            f'Path({str(touched_helper)!r}).write_text("bad", encoding="utf-8")\n'
            'def transform(data):\n'
            "    return {'marker_hits': ['mutated-helper']}\n",
            encoding='utf-8',
        )
        return snapshots

    monkeypatch.setattr(
        catalog,
        '_validated_dependency_source_snapshots',
        snapshot_then_replace,
    )
    result = catalog._invoke_handler_from_verified_snapshots(
        spec,
        b'payload',
        'payload.bin',
        manifest,
    )

    assert result == {'marker_hits': ['verified-helper']}
    assert not touched_main.exists()
    assert not touched_helper.exists()


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


def test_attempt_limit_returns_partial_without_extra_handler_import(isolated_catalog) -> None:
    repository, malware_root = isolated_catalog
    spec = _handler_spec(
        repository,
        malware_root,
        'candidate_family',
        _source("{'marker_hits': ['marker']}"),
    )
    layers = [_layer(b'layer-one', 'one.bin'), _layer(b'layer-two', 'two.bin')]
    result = catalog.assess_candidate_handlers(
        ['candidate_family'],
        layers,
        specs=[spec],
        maximum_attempts=1,
    )

    assert result['status'] == 'partial'
    assert result['actual_attempt_count'] == 1
    assert result['unattempted_attempt_count'] == 1
    assert result['blockers'] == ['maximum_attempts_exhausted']

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

@pytest.mark.parametrize(
    ('source', 'blocker'),
    [
        (
            'from pathlib import Path\n'
            + _source("{'value': Path('secret.txt').read_text(encoding='utf-8')}"),
            'forbidden_side_effect_method',
        ),
        (
            'import numpy\n' + _source("{'value': numpy.fromfile('secret.bin')}"),
            'forbidden_unverified_filesystem_read:numpy.fromfile',
        ),
        (
            'import pefile\n' + _source("{'value': pefile.PE('secret.exe')}"),
            'forbidden_path_parser_input:pefile.PE',
        ),
    ],
    ids=['path_read_text', 'numpy_fromfile', 'pefile_path'],
)
def test_ast_audit_blocks_unverified_path_readers(
    isolated_catalog,
    source: str,
    blocker: str,
) -> None:
    repository, malware_root = isolated_catalog
    spec = _handler_spec(repository, malware_root, 'candidate_family', source)

    preflight = catalog.preflight_handler_for_assessment(
        spec,
        actual_format='data',
        input_size=16,
    )

    assert preflight['eligible'] is False
    assert any(blocker in item for item in preflight['blockers'])


def test_ast_audit_blocks_higher_order_open_reader_bypass(isolated_catalog) -> None:
    """getattr→map→next→readの高階関数連鎖でもfilesystem readを許可しない。"""

    repository, malware_root = isolated_catalog
    source = (
        'import builtins\n'
        'HANDLER_CONTRACT = {"input_formats": ["data"], "minimum_evidence_score": 1}\n'
        'def extract_config(data):\n'
        '    reader = getattr(builtins, "open")\n'
        '    handle = next(map(reader, ["secret.txt"]))\n'
        '    return {"value": handle.read()}\n'
    )
    spec = _handler_spec(repository, malware_root, 'candidate_family', source)

    preflight = catalog.preflight_handler_for_assessment(
        spec,
        actual_format='data',
        input_size=16,
    )

    assert preflight['eligible'] is False
    rendered = '\n'.join(preflight['blockers'])
    assert 'unresolved_higher_order_call:getattr' in rendered
    assert 'unresolved_higher_order_call:map' in rendered
    assert 'unverified_reader_capability' in rendered


def test_public_sanitizer_redacts_value_based_credentials_and_private_keys() -> None:
    aws_id = 'AKIA' + 'A' * 16
    aws_secret = 's' * 40
    slack_token = 'xoxb-' + 'B' * 30
    jwt = '.'.join(('eyJ' + 'C' * 16, 'D' * 16, 'E' * 16))
    private_key = (
        '-----BEGIN PRIVATE KEY-----\n'
        + 'F' * 64
        + '\n-----END PRIVATE KEY-----'
    )
    value = {
        'note': (
            f'aws_access_key_id={aws_id} '
            f'aws_secret_access_key={aws_secret} '
            f'token={slack_token} jwt={jwt}\n{private_key}'
        ),
        'AWS_SECRET_ACCESS_KEY': aws_secret,
    }

    rendered = json.dumps(
        catalog.sanitize_public_value(value),
        ensure_ascii=False,
        sort_keys=True,
    )

    for secret in (aws_id, aws_secret, slack_token, jwt, private_key):
        assert secret not in rendered
    assert '[REDACTED' in rendered


def test_public_result_quota_blocks_oversized_and_deep_values(
    isolated_catalog,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, malware_root = isolated_catalog
    spec = _handler_spec(repository, malware_root, 'candidate_family', _source('{}'))

    monkeypatch.setattr(catalog, '_invoke_handler', lambda *_args, **_kwargs: list(range(5_000)))
    oversized = catalog.execute_handler(spec, b'input', 'sample.bin')
    assert oversized['result_quota']['truncated'] is True
    assert 'maximum_total_entries' in oversized['result_quota']['reasons']
    assert len(json.dumps(oversized, ensure_ascii=False)) < 2_000_000

    deep: dict[str, object] = {'leaf': 'value'}
    for _index in range(catalog.MAX_DEPTH + 4):
        deep = {'nested': deep}
    monkeypatch.setattr(catalog, '_invoke_handler', lambda *_args, **_kwargs: deep)
    nested = catalog.execute_handler(spec, b'input', 'sample.bin')
    assert nested['result_quota']['truncated'] is True
    assert 'maximum_depth' in nested['result_quota']['reasons']

    non_finite = catalog.sanitize_public_value(float('nan'))
    assert non_finite == {'truncated': True, 'reason': 'non_finite_number'}


def test_raw_binary_materialization_requires_exact_terminal_schema() -> None:
    payload = b'MZ' + b'P' * 14
    nested, _nested_audit = catalog._verified_binary_outputs(
        {'terminal_payload': {'nested': {'data': payload}}}
    )
    extra, _extra_audit = catalog._verified_binary_outputs(
        {
            'record': {
                'role': 'terminal_payload',
                'data': payload,
                'unexpected': True,
            }
        }
    )
    valid, _valid_audit = catalog._verified_binary_outputs(
        {'record': {'role': 'terminal_payload', 'data': payload}}
    )

    assert nested == []
    assert extra == []
    assert len(valid) == 1
    assert valid[0]['sha256'] == hashlib.sha256(payload).hexdigest()


def _mock_completed_handler_result() -> dict:
    return {
        'status': 'completed',
        'preflight': {'eligible': True, 'blockers': []},
        'execution': {
            'result': {},
            'result_quota': {'truncated': False},
            'verified_binary_output_audit': {'observed_output_count': 0},
        },
    }


def test_2048_planned_attempts_stop_at_global_hard_cap(
    isolated_catalog,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, malware_root = isolated_catalog
    base = _handler_spec(
        repository,
        malware_root,
        'candidate_family',
        _source('{}'),
    )
    specs = [
        catalog.HandlerSpec(**{**base.public(), 'id': f'candidate_family:fixture:{index:02d}'})
        for index in range(32)
    ]
    layers = [_layer(f'layer-{index:02d}'.encode(), f'{index:02d}.bin') for index in range(64)]
    monkeypatch.setattr(
        catalog,
        'execute_handler_bounded_for_assessment',
        lambda *_args, **_kwargs: _mock_completed_handler_result(),
    )

    result = catalog.assess_candidate_handlers(
        [_candidate('candidate_family')],
        layers,
        specs=specs,
    )

    assert result['planned_attempt_count'] == 2_048
    assert result['actual_attempt_count'] == catalog.MAX_ASSESSMENT_ATTEMPTS == 64
    assert result['unattempted_attempt_count'] == 1_984
    assert result['status'] == 'partial'
    assert result['blockers'] == ['maximum_attempts_exhausted']


def test_attempt_detail_and_verified_output_budgets_return_partial(
    isolated_catalog,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, malware_root = isolated_catalog
    spec = _handler_spec(repository, malware_root, 'candidate_family', _source('{}'))
    layers = [_layer(f'layer-{index}'.encode(), f'{index}.bin') for index in range(10)]
    monkeypatch.setattr(
        catalog,
        'execute_handler_bounded_for_assessment',
        lambda *_args, **_kwargs: _mock_completed_handler_result(),
    )

    details = catalog.assess_candidate_handlers(
        [_candidate('candidate_family')],
        layers,
        specs=[spec],
        maximum_retained_attempt_details=4,
    )
    assert details['status'] == 'partial'
    assert details['actual_attempt_count'] == 5
    assert details['retained_attempt_detail_count'] == 4
    assert details['omitted_attempt_detail_count'] == 1
    assert details['blockers'] == ['maximum_retained_attempt_details_exhausted']

    oversized_output = _mock_completed_handler_result()
    oversized_output['execution']['verified_binary_output_audit'] = {
        'observed_output_count': catalog.MAX_ASSESSMENT_VERIFIED_OUTPUTS + 1
    }
    monkeypatch.setattr(
        catalog,
        'execute_handler_bounded_for_assessment',
        lambda *_args, **_kwargs: oversized_output,
    )
    outputs = catalog.assess_candidate_handlers(
        [_candidate('candidate_family')],
        layers[:1],
        specs=[spec],
    )
    assert outputs['status'] == 'partial'
    assert outputs['blockers'] == ['maximum_verified_outputs_exhausted']


@pytest.mark.parametrize(
    'raw',
    [
        b'{"ok":true,"ok":false}',
        b'{"value":NaN}',
        b'{"value":Infinity}',
        b'{"value":1e9999}',
    ],
    ids=['duplicate_key', 'nan', 'infinity', 'overflow_float'],
)
def test_strict_json_loader_rejects_ambiguous_or_nonfinite_values(raw: bytes) -> None:
    with pytest.raises(catalog.HandlerLoadError, match='invalid JSON'):
        catalog._strict_json_loads(raw, description='fixture')


def test_regular_file_snapshot_rejects_hardlinks(tmp_path: Path) -> None:
    original = tmp_path / 'original.json'
    linked = tmp_path / 'linked.json'
    original.write_bytes(b'{}')
    try:
        os.link(original, linked)
    except OSError as exc:
        pytest.skip(f'hardlinkを作成できない環境です: {exc}')

    with pytest.raises(catalog.HandlerLoadError, match='single-link'):
        catalog._regular_file_snapshot(
            linked,
            maximum_size=1024,
            description='fixture',
        )


def test_bounded_worker_requires_process_and_memory_containment(
    isolated_catalog,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, malware_root = isolated_catalog
    spec = _handler_spec(repository, malware_root, 'candidate_family', _source('{}'))
    captured: dict = {}

    def fake_run(command, **kwargs):
        captured.update(kwargs)
        Path(command[-1]).write_text(
            json.dumps({'ok': True, 'result': {}}),
            encoding='utf-8',
        )
        return types.SimpleNamespace(returncode=0)

    monkeypatch.setattr(bounded_process, 'run_bounded', fake_run)
    result = catalog._execute_handler_bounded(
        spec,
        b'input',
        'sample.bin',
        timeout_seconds=1.0,
        dependency_source_manifest=[],
        dependency_data_manifest=[],
        dependency_module_manifest=[],
    )

    assert result['verified_binary_outputs'] == []
    assert captured['require_containment'] is True
    assert captured['maximum_active_processes'] == 1
    assert captured['maximum_memory_bytes'] == bounded_process.DEFAULT_CONTAINED_MEMORY_BYTES
    temporary_paths = {
        Path(captured['env'][name]) for name in ('TEMP', 'TMP', 'TMPDIR')
    }
    assert len(temporary_paths) == 1
    child_temp = temporary_paths.pop()
    assert child_temp.name == 'worker-temp'
    assert not child_temp.exists()


def test_windows_family_profile_data_is_read_from_verified_snapshot(
    isolated_catalog,
) -> None:
    repository, _malware_root = isolated_catalog
    profile = repository / 'extractors' / 'profiles' / 'windows_family_profiles.json'
    profile.parent.mkdir(parents=True)
    original = '{"safe":true}\n'
    replacement = '{"evil":true}\n'
    assert len(original.encode()) == len(replacement.encode())
    profile.write_bytes(original.encode())
    metadata = profile.stat()
    relative = profile.relative_to(repository).as_posix()
    manifest = [
        {
            'path': relative,
            'sha256': hashlib.sha256(original.encode()).hexdigest(),
            'reason': 'fixture profile snapshot',
        }
    ]
    snapshots = catalog._validated_dependency_data_snapshots(
        manifest,
        repository=repository,
    )
    profile.write_bytes(replacement.encode())
    os.utime(profile, ns=(metadata.st_atime_ns, metadata.st_mtime_ns))
    external = repository / 'external.json'
    external.write_text('{"secret":true}', encoding='utf-8')

    with catalog._verified_data_read_environment(snapshots):
        assert profile.read_text(encoding='utf-8') == original
        with pytest.raises(catalog.HandlerLoadError, match='absent'):
            external.read_text(encoding='utf-8')


def test_preloaded_same_name_module_cannot_override_verified_snapshot(
    isolated_catalog,
) -> None:
    repository, malware_root = isolated_catalog
    family_root = malware_root / 'candidate_family'
    family_root.mkdir(parents=True, exist_ok=True)
    helper = family_root / 'helper_module.py'
    helper.write_text(
        'def transform(data):\n'
        "    return {'marker_hits': ['verified-helper']}\n",
        encoding='utf-8',
    )
    spec = _handler_spec(
        repository,
        malware_root,
        'candidate_family',
        'from helper_module import transform\n'
        'HANDLER_CONTRACT = {"input_formats": ["data"], "minimum_evidence_score": 1}\n'
        'def extract_config(data):\n'
        '    return transform(data)\n',
    )
    preflight = catalog.preflight_handler_for_assessment(
        spec,
        actual_format='data',
        input_size=7,
    )
    poisoned = types.ModuleType('helper_module')
    poisoned.transform = lambda _data: {'marker_hits': ['poisoned-module']}
    previous = sys.modules.get('helper_module')
    sys.modules['helper_module'] = poisoned
    try:
        result = catalog._invoke_handler_from_verified_snapshots(
            spec,
            b'payload',
            'payload.bin',
            preflight['dependency_audit']['files'],
            preflight['dependency_audit']['data_files'],
            preflight['dependency_audit']['module_bindings'],
        )
        assert result == {'marker_hits': ['verified-helper']}
        assert sys.modules['helper_module'] is poisoned
    finally:
        if previous is None:
            sys.modules.pop('helper_module', None)
        else:
            sys.modules['helper_module'] = previous


def test_same_name_site_module_is_not_fallback_after_snapshot(
    isolated_catalog,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    repository, malware_root = isolated_catalog
    family_root = malware_root / 'candidate_family'
    family_root.mkdir(parents=True, exist_ok=True)
    helper = family_root / 'helper_module.py'
    helper.write_text(
        'def transform(data):\n'
        "    return {'marker_hits': ['verified-helper']}\n",
        encoding='utf-8',
    )
    site = tmp_path / 'site-packages'
    site.mkdir()
    (site / 'helper_module.py').write_text(
        'def transform(data):\n'
        "    return {'marker_hits': ['site-fallback']}\n",
        encoding='utf-8',
    )
    monkeypatch.syspath_prepend(str(site))
    spec = _handler_spec(
        repository,
        malware_root,
        'candidate_family',
        'from helper_module import transform\n'
        'HANDLER_CONTRACT = {"input_formats": ["data"], "minimum_evidence_score": 1}\n'
        'def extract_config(data):\n'
        '    return transform(data)\n',
    )
    preflight = catalog.preflight_handler_for_assessment(
        spec,
        actual_format='data',
        input_size=7,
    )
    original = catalog._validated_dependency_source_snapshots

    def snapshot_then_delete(value, *, repository):
        snapshots = original(value, repository=repository)
        helper.unlink()
        return snapshots

    monkeypatch.setattr(
        catalog,
        '_validated_dependency_source_snapshots',
        snapshot_then_delete,
    )
    result = catalog._invoke_handler_from_verified_snapshots(
        spec,
        b'payload',
        'payload.bin',
        preflight['dependency_audit']['files'],
        preflight['dependency_audit']['data_files'],
        preflight['dependency_audit']['module_bindings'],
    )

    assert result == {'marker_hits': ['verified-helper']}


def test_verified_package_and_submodule_bindings_load_from_snapshots(
    isolated_catalog,
) -> None:
    repository, malware_root = isolated_catalog
    family_root = malware_root / 'candidate_family'
    package = family_root / 'verified_pkg'
    package.mkdir(parents=True)
    (package / '__init__.py').write_text(
        'PACKAGE_MARKER = "verified-package"\n',
        encoding='utf-8',
    )
    (package / 'helper.py').write_text(
        'from verified_pkg import PACKAGE_MARKER\n'
        'def transform(data):\n'
        '    return {"marker_hits": [PACKAGE_MARKER]}\n',
        encoding='utf-8',
    )
    spec = _handler_spec(
        repository,
        malware_root,
        'candidate_family',
        'from verified_pkg.helper import transform\n'
        'HANDLER_CONTRACT = {"input_formats": ["data"], "minimum_evidence_score": 1}\n'
        'def extract_config(data):\n'
        '    return transform(data)\n',
    )
    preflight = catalog.preflight_handler_for_assessment(
        spec,
        actual_format='data',
        input_size=7,
    )

    assert preflight['eligible'] is True
    assert {item['name'] for item in preflight['dependency_audit']['module_bindings']} >= {
        'verified_pkg',
        'verified_pkg.helper',
    }
    result = catalog._invoke_handler_from_verified_snapshots(
        spec,
        b'payload',
        'payload.bin',
        preflight['dependency_audit']['files'],
        preflight['dependency_audit']['data_files'],
        preflight['dependency_audit']['module_bindings'],
    )
    assert result == {'marker_hits': ['verified-package']}


def test_dynamic_file_loader_uses_snapshot_after_live_replacement(
    isolated_catalog,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, malware_root = isolated_catalog
    family_root = malware_root / 'candidate_family'
    family_root.mkdir(parents=True, exist_ok=True)
    helper = family_root / 'dynamic_helper.py'
    helper.write_text(
        'def transform(data):\n'
        "    return {'marker_hits': ['verified-dynamic']}\n",
        encoding='utf-8',
    )
    spec = _handler_spec(
        repository,
        malware_root,
        'candidate_family',
        'import importlib.util\n'
        'from pathlib import Path\n'
        '_path = Path(__file__).resolve().parent / "dynamic_helper.py"\n'
        '_spec = importlib.util.spec_from_file_location("dynamic_fixture", _path)\n'
        'assert _spec and _spec.loader\n'
        '_module = importlib.util.module_from_spec(_spec)\n'
        '_spec.loader.exec_module(_module)\n'
        'HANDLER_CONTRACT = {"input_formats": ["data"], "minimum_evidence_score": 1}\n'
        'def extract_config(data):\n'
        '    return _module.transform(data)\n',
    )
    source_paths = [repository / spec.relative_path, helper]
    manifest = [
        {
            'path': path.relative_to(repository).as_posix(),
            'sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
        }
        for path in sorted(source_paths, key=lambda item: item.relative_to(repository).as_posix())
    ]
    original = catalog._validated_dependency_source_snapshots

    def snapshot_then_replace(value, *, repository):
        snapshots = original(value, repository=repository)
        helper.write_text(
            'def transform(data):\n'
            "    return {'marker_hits': ['mutated-dynamic']}\n",
            encoding='utf-8',
        )
        return snapshots

    monkeypatch.setattr(
        catalog,
        '_validated_dependency_source_snapshots',
        snapshot_then_replace,
    )
    result = catalog._invoke_handler_from_verified_snapshots(
        spec,
        b'payload',
        'payload.bin',
        manifest,
        [],
        [],
    )

    assert result == {'marker_hits': ['verified-dynamic']}


def test_repository_reparse_import_is_rejected_before_snapshot(
    isolated_catalog,
    tmp_path: Path,
) -> None:
    repository, malware_root = isolated_catalog
    outside = tmp_path / 'outside-package'
    outside.mkdir()
    (outside / '__init__.py').write_text('', encoding='utf-8')
    (outside / 'helper.py').write_text(
        'def transform(data):\n    return {}\n',
        encoding='utf-8',
    )
    family_root = malware_root / 'candidate_family'
    family_root.mkdir(parents=True, exist_ok=True)
    linked = family_root / 'linked_pkg'
    try:
        os.symlink(outside, linked, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f'directory reparse pointを作成できない環境です: {exc}')
    spec = _handler_spec(
        repository,
        malware_root,
        'candidate_family',
        'from linked_pkg.helper import transform\n'
        'HANDLER_CONTRACT = {"input_formats": ["data"], "minimum_evidence_score": 1}\n'
        'def extract_config(data):\n'
        '    return transform(data)\n',
    )

    preflight = catalog.preflight_handler_for_assessment(
        spec,
        actual_format='data',
        input_size=7,
    )

    assert preflight['eligible'] is False
    assert any('unsafe_local_import' in item for item in preflight['blockers'])


@pytest.mark.parametrize(
    'source',
    [
        (
            'import builtins\n'
            'HANDLER_CONTRACT = {"input_formats": ["data"], "minimum_evidence_score": 1}\n'
            'def extract_config(data):\n'
            '    return {"value": vars(builtins)["open"]("secret.txt").read()}\n'
        ),
        (
            'import builtins\n'
            'HANDLER_CONTRACT = {"input_formats": ["data"], "minimum_evidence_score": 1}\n'
            'def extract_config(data):\n'
            '    return {"value": builtins.__dict__["open"]("secret.txt").read()}\n'
        ),
        (
            'import functools\n'
            'HANDLER_CONTRACT = {"input_formats": ["data"], "minimum_evidence_score": 1}\n'
            'def extract_config(data):\n'
            '    callback = functools.partial(open, "secret.txt")\n'
            '    return {"value": callback().read()}\n'
        ),
        (
            'import operator\n'
            'from pathlib import Path\n'
            'HANDLER_CONTRACT = {"input_formats": ["data"], "minimum_evidence_score": 1}\n'
            'def extract_config(data):\n'
            '    callback = operator.methodcaller("read_text")\n'
            '    return {"value": callback(Path("secret.txt"))}\n'
        ),
    ],
    ids=['vars-builtins', 'builtins-dict', 'partial-open', 'methodcaller-reader'],
)
def test_ast_audit_blocks_indirect_capability_construction(
    isolated_catalog,
    source: str,
) -> None:
    repository, malware_root = isolated_catalog
    spec = _handler_spec(repository, malware_root, 'candidate_family', source)

    preflight = catalog.preflight_handler_for_assessment(
        spec,
        actual_format='data',
        input_size=16,
    )

    assert preflight['eligible'] is False
    assert preflight['blockers']


@pytest.mark.parametrize(
    'source',
    [
        (
            'from pathlib import Path\n'
            'def len(value):\n'
            '    return Path(value).read_text(encoding="utf-8")\n'
            'HANDLER_CONTRACT = {"input_formats": ["data"], "minimum_evidence_score": 1}\n'
            'def extract_config(data):\n'
            '    return {"value": list(map(len, ["secret.txt"]))}\n'
        ),
        (
            'import re\n'
            're.search = open\n'
            'HANDLER_CONTRACT = {"input_formats": ["data"], "minimum_evidence_score": 1}\n'
            'def extract_config(data):\n'
            '    return {"value": bool(re.search("secret.txt"))}\n'
        ),
        (
            'from re import search\n'
            'search = open\n'
            'HANDLER_CONTRACT = {"input_formats": ["data"], "minimum_evidence_score": 1}\n'
            'def extract_config(data):\n'
            '    return {"value": bool(search("secret.txt"))}\n'
        ),
    ],
    ids=['shadowed-builtin-callback', 'mutated-module-alias', 'mutated-import-symbol'],
)
def test_ast_audit_blocks_shadowed_or_mutated_safe_names(
    isolated_catalog,
    source: str,
) -> None:
    repository, malware_root = isolated_catalog
    spec = _handler_spec(repository, malware_root, 'candidate_family', source)

    preflight = catalog.preflight_handler_for_assessment(
        spec,
        actual_format='data',
        input_size=16,
    )

    assert preflight['eligible'] is False
    assert preflight['blockers']


@pytest.mark.parametrize(
    'source',
    [
        (
            'HANDLER_CONTRACT = {"input_formats": ["data"], "minimum_evidence_score": 1}\n'
            'def extract_config(data):\n'
            '    def nested():\n'
            '        return open("secret.txt").read()\n'
            '    return {"value": nested()}\n'
        ),
        (
            'HANDLER_CONTRACT = {"input_formats": ["data"], "minimum_evidence_score": 1}\n'
            'def extract_config(data):\n'
            '    class Nested:\n'
            '        leaked = open("secret.txt").read()\n'
            '    return {}\n'
        ),
        (
            'from pathlib import Path\n'
            'def decorator(function):\n'
            '    Path("marker.txt").write_text("x", encoding="utf-8")\n'
            '    return function\n'
            '@decorator\n'
            'def extract_config(data):\n'
            '    return {}\n'
            'HANDLER_CONTRACT = {"input_formats": ["data"], "minimum_evidence_score": 1}\n'
        ),
        (
            'HANDLER_CONTRACT = {"input_formats": ["data"], "minimum_evidence_score": 1}\n'
            'def extract_config(data=open("secret.txt").read()):\n'
            '    return {}\n'
        ),
        (
            'HANDLER_CONTRACT = {"input_formats": ["data"], "minimum_evidence_score": 1}\n'
            'def extract_config(data: open("secret.txt").read()):\n'
            '    return {}\n'
        ),
    ],
    ids=['nested-function', 'nested-class-body', 'local-decorator', 'default-value', 'annotation'],
)
def test_ast_audit_blocks_nested_and_definition_time_side_effects(
    isolated_catalog,
    source: str,
) -> None:
    repository, malware_root = isolated_catalog
    spec = _handler_spec(repository, malware_root, 'candidate_family', source)

    preflight = catalog.preflight_handler_for_assessment(
        spec,
        actual_format='data',
        input_size=16,
    )

    assert preflight['eligible'] is False
    assert preflight['blockers']


@pytest.mark.parametrize(
    'source',
    [
        (
            'from pathlib import Path\n'
            'class Evil:\n'
            '    def get(self):\n'
            '        return Path("secret.txt").read_text(encoding="utf-8")\n'
            + _source('{"value": Evil().get()}')
        ),
        (
            'class Evil:\n'
            '    def openstream(self, name):\n'
            '        return open(name)\n'
            + _source('{"value": Evil().openstream("secret.txt").read()}')
        ),
        (
            'class Evil:\n'
            '    def __iter__(self):\n'
            '        return iter(open("secret.txt"))\n'
            + _source('{"value": list(Evil())}')
        ),
        (
            'class Evil:\n'
            '    def __getattribute__(self, name):\n'
            '        return open("secret.txt").read\n'
            + _source('{"value": hasattr(Evil(), "value")}')
        ),
        (
            'HANDLER_CONTRACT = {"input_formats": ["data"], "minimum_evidence_score": 1}\n'
            'def extract_config(data):\n'
            '    callback = type.__subclasses__\n'
            '    return {"value": list(map(callback, [object]))}\n'
        ),
    ],
    ids=['local-get', 'fake-openstream', 'iter-protocol', 'getattribute-protocol', 'dunder-laundering'],
)
def test_ast_audit_blocks_local_object_and_reflection_capabilities(
    isolated_catalog,
    source: str,
) -> None:
    repository, malware_root = isolated_catalog
    spec = _handler_spec(repository, malware_root, 'candidate_family', source)

    preflight = catalog.preflight_handler_for_assessment(
        spec,
        actual_format='data',
        input_size=16,
    )

    assert preflight['eligible'] is False
    assert preflight['blockers']


def test_ast_audit_allows_safe_local_callback(isolated_catalog) -> None:
    repository, malware_root = isolated_catalog
    source = (
        'def normalize(value):\n'
        '    return str(value)\n'
        'HANDLER_CONTRACT = {"input_formats": ["data"], "minimum_evidence_score": 1}\n'
        'def extract_config(data):\n'
        '    return {"values": list(map(normalize, [1, 2]))}\n'
    )
    spec = _handler_spec(repository, malware_root, 'candidate_family', source)

    preflight = catalog.preflight_handler_for_assessment(
        spec,
        actual_format='data',
        input_size=16,
    )

    assert preflight['eligible'] is True
    assert preflight['blockers'] == []
