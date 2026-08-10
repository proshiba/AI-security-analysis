'''保持payload fixed-pointのfail-closed境界を検証する。'''

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest


FRAMEWORK_ROOT = Path(__file__).resolve().parents[1]
COMMON_ROOT = FRAMEWORK_ROOT / 'common'
REPOSITORY_ROOT = FRAMEWORK_ROOT.parent
for trusted in (REPOSITORY_ROOT, FRAMEWORK_ROOT, COMMON_ROOT):
    value = str(trusted)
    if value not in sys.path:
        sys.path.insert(0, value)

import analyze_sample as one_shot  # noqa: E402
import bounded_process  # noqa: E402


REGISTRY = FRAMEWORK_ROOT / 'registry' / 'malware_types.json'


@pytest.mark.parametrize(
    ('raw', 'message'),
    [
        (b'{"value":1e999}', '非finite'),
        (b'{"value":-1e999}', '非finite'),
        (b'\xef\xbb\xbf{"value":1}', '解釈できません'),
    ],
)
def test_strict_follow_on_json_rejects_noncanonical_numbers_and_bom(
    raw: bytes,
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        one_shot._strict_json_object_bytes(raw, label='fixture')


def test_follow_on_json_encoder_refuses_non_finite_output() -> None:
    with pytest.raises(ValueError):
        one_shot._encoded_json_document({'value': float('nan')})


def test_strict_follow_on_json_rejects_excessive_nesting() -> None:
    raw = b'{"value":' + (b'[' * 2_000) + b'0' + (b']' * 2_000) + b'}'
    with pytest.raises(ValueError, match='入れ子が深すぎます'):
        one_shot._strict_json_object_bytes(raw, label='fixture')


def test_strict_follow_on_json_rejects_excessive_integer_digits() -> None:
    raw = b'{"value":' + (b'9' * 500) + b'}'
    with pytest.raises(ValueError, match='整数桁数'):
        one_shot._strict_json_object_bytes(raw, label='fixture')


def _audit(count: int, **overrides: object) -> dict[str, object]:
    value: dict[str, object] = {
        'schema_version': 1,
        'maximum_outputs': 64,
        'maximum_total_size': 256 * 1024 * 1024,
        'binary_values_seen': count,
        'binary_bytes_seen': count,
        'traversal_items': count,
        'observed_output_count': count,
        'retained_output_count': count,
        'retained_for_follow_on_analysis': True,
        'follow_on_analysis_complete': False,
        'observation_scope': 'parent_rehashed_case_artifact',
        'truncated': False,
        'reasons': [],
    }
    value.update(overrides)
    return value


def _wrapper(data: bytes, path: str = 'p/payload.bin') -> dict[str, object]:
    return {
        'verified_binary_outputs': [
            {
                'role': 'terminal_payload',
                'kind': 'pe',
                'path': path,
                'sha256': hashlib.sha256(data).hexdigest(),
                'size': len(data),
                'verification': {
                    'status': 'artifact_hash_verified',
                    'sha256_matches': True,
                    'size_matches': True,
                },
            }
        ],
        'verified_binary_output_audit': _audit(1),
    }


@pytest.mark.parametrize(
    ('change',),
    [
        ({'observed_output_count': 2},),
        ({'truncated': True},),
        ({'reasons': ['maximum_items']},),
    ],
)
def test_promotion_eligibility_requires_every_observed_output(change: dict[str, object]) -> None:
    wrapper = _wrapper(b'MZ child')
    wrapper['verified_binary_output_audit'].update(change)

    assert one_shot._wrapper_follow_on_promotion_eligible(wrapper) is False


def test_wrapper_promotion_requires_matching_strict_child_proof() -> None:
    data = b'MZ child proof'
    digest = hashlib.sha256(data).hexdigest()
    wrapper = _wrapper(data)

    assert one_shot._promote_wrapper_follow_on_audit(wrapper, proofs={}) is False
    assert wrapper['verified_binary_output_audit']['follow_on_analysis_complete'] is False

    changed = one_shot._promote_wrapper_follow_on_audit(
        wrapper,
        proofs={
            digest: {
                'sha256': digest,
                'analysis_contract_sha256': 'a' * 64,
                'report_semantic_sha256': 'b' * 64,
            }
        },
    )

    assert changed is True
    assert wrapper['verified_binary_output_audit']['follow_on_analysis_complete'] is True
    assert wrapper['follow_on_analysis_proof']['children'][0]['sha256'] == digest


def test_parent_promotion_validation_failure_does_not_write(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """一部の子だけcompleteでも検証失敗前に親成果物を書き換えない。"""

    parent = 'a' * 64
    first_data = b'first complete child'
    second_data = b'second incomplete child'
    first_digest = hashlib.sha256(first_data).hexdigest()
    first_wrapper = _wrapper(first_data, 'p/first.bin')
    second_wrapper = _wrapper(second_data, 'p/second.bin')
    candidate: dict[str, object] = {'families': []}
    report = {
        'handler_executions': [
            {'handler_id': 'first', 'result': 'first-wrapper.json'},
            {'handler_id': 'second', 'result': 'second-wrapper.json'},
        ],
        'case_state': {
            'status': 'partial',
            'complete': False,
            'resumable': False,
            'blockers': ['orchestration:terminal_payload'],
        },
        'artifact_sha256': {
            'first-wrapper.json': '0' * 64,
            'second-wrapper.json': '1' * 64,
            'candidate-handler-assessment.json': '2' * 64,
            'orchestration.json': '3' * 64,
        },
    }
    outcome = {
        'status': 'partial',
        'family_resolution': {'status': 'resolved', 'family': 'synthetic'},
        'quality_gates': {
            'terminal_payload': {
                'required': True,
                'satisfied': False,
                'status': 'required_missing',
            }
        },
        'blockers': ['terminal_payload'],
        'next_actions_ja': ['terminal payloadを確認してください。'],
    }
    case_dir = tmp_path / 'cases' / parent
    case_dir.mkdir(parents=True)
    paths = {
        name: case_dir / name
        for name in (
            'report.json',
            'first-wrapper.json',
            'second-wrapper.json',
            'candidate-handler-assessment.json',
            'orchestration.json',
        )
    }
    for path in paths.values():
        path.write_text('{}', encoding='utf-8')

    snapshots = {
        'report': json.dumps(report, sort_keys=True),
        'outcome': json.dumps(outcome, sort_keys=True),
        'first': json.dumps(first_wrapper, sort_keys=True),
        'second': json.dumps(second_wrapper, sort_keys=True),
    }
    monkeypatch.setattr(one_shot, '_follow_on_case_directory', lambda *_args: case_dir)
    monkeypatch.setattr(one_shot, 'case_integrity_errors', lambda *_args, **_kwargs: [])
    monkeypatch.setattr(
        one_shot,
        '_case_wrapper_documents',
        lambda *_args: (
            [
                (paths['first-wrapper.json'], first_wrapper),
                (paths['second-wrapper.json'], second_wrapper),
            ],
            paths['candidate-handler-assessment.json'],
            candidate,
        ),
    )

    def load_document(path: Path):
        if path.name == 'report.json':
            return report
        if path.name == 'orchestration.json':
            return outcome
        raise AssertionError(f'予期しない読取りです: {path}')

    monkeypatch.setattr(one_shot, 'load_json_object_strict', load_document)
    monkeypatch.setattr(
        one_shot,
        '_completed_follow_on_child_proof',
        lambda _output, digest, **_kwargs: {
            'sha256': digest,
            'analysis_contract_sha256': 'c' * 64,
            'report_semantic_sha256': 'd' * 64,
        },
    )

    def legacy_records(_case_dir, _executions, _specs, *, wrapper_overrides):
        return [
            {'family': 'synthetic', 'result': wrapper}
            for _path, wrapper in sorted(
                wrapper_overrides.items(),
                key=lambda item: str(item[0]),
            )
        ]

    monkeypatch.setattr(one_shot, '_legacy_outcome_handler_records', legacy_records)

    def summarize(records, *, verified_only=True, family_filter=None):
        del verified_only, family_filter
        retained = sorted(
            {
                output['sha256']
                for record in records
                for output in record['result']['verified_binary_outputs']
            }
        )
        promoted = sorted(
            {
                output['sha256']
                for record in records
                if record['result']['verified_binary_output_audit'].get(
                    'follow_on_analysis_complete'
                )
                for output in record['result']['verified_binary_outputs']
            }
        )
        return {
            'retained_terminal_payload_sha256': retained,
            'terminal_payload_sha256': promoted,
        }

    monkeypatch.setattr(
        one_shot.orchestration_outcome,
        'summarize_handler_outputs',
        summarize,
    )
    monkeypatch.setattr(
        one_shot,
        'artifact_hashes',
        lambda *_args, **_kwargs: pytest.fail('論理検証失敗後にhashしてはならない'),
    )
    writes: list[Path] = []
    monkeypatch.setattr(
        one_shot,
        '_atomic_replace_json',
        lambda path, _value: writes.append(path),
    )

    with pytest.raises(ValueError, match='親別proof'):
        one_shot._promote_parent_case_from_follow_on(
            tmp_path,
            parent,
            parent_contract={'sha256': 'b' * 64},
            child_contract={'sha256': 'c' * 64},
            specs=[],
            complete_child_digests={first_digest},
        )

    assert writes == []
    assert json.dumps(report, sort_keys=True) == snapshots['report']
    assert json.dumps(outcome, sort_keys=True) == snapshots['outcome']
    assert json.dumps(first_wrapper, sort_keys=True) == snapshots['first']
    assert json.dumps(second_wrapper, sort_keys=True) == snapshots['second']


def test_worker_command_does_not_expose_archive_password(tmp_path: Path, monkeypatch) -> None:
    output = tmp_path / 'jobs'
    output.mkdir()
    secret = 'password-that-must-not-enter-process-list'
    captured: dict[str, object] = {}

    def fake_run(command, **kwargs):
        captured['command'] = command
        captured['kwargs'] = kwargs
        request_path = Path(command[-4])
        assert request_path.is_file()
        assert secret in request_path.read_text(encoding='utf-8')
        one_shot._write_private_regular_file(
            Path(command[-1]),
            json.dumps({'ok': True, 'result': {}}).encode('utf-8'),
            maximum_size=one_shot.MAX_FOLLOW_ON_WORKER_RESPONSE,
        )
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(bounded_process, 'run_bounded', fake_run)
    payload = b'MZ retained child'
    result = one_shot._execute_follow_on_child(
        payload=payload,
        digest=hashlib.sha256(payload).hexdigest(),
        parent_sha256='a' * 64,
        depth=1,
        output=output,
        registry=REGISTRY,
        minimum_confidence='medium',
        upx=None,
        sevenzip=None,
        diec=None,
        force_container_probe=False,
        max_static_layers=8,
        retry_max_static_layers=None,
        archive_password=secret,
        string_scan_limit=1000,
        analysis_contract={},
        timeout_seconds=1,
    )

    assert result == {}
    assert secret not in ' '.join(str(item) for item in captured['command'])
    worker_options = captured['kwargs']
    assert isinstance(worker_options, dict)
    assert worker_options['timeout'] == 1
    assert worker_options['require_containment'] is True
    assert (
        worker_options['maximum_active_processes']
        == one_shot.MAX_FOLLOW_ON_WORKER_ACTIVE_PROCESSES
    )
    assert (
        worker_options['maximum_memory_bytes']
        == one_shot.MAX_FOLLOW_ON_WORKER_MEMORY_BYTES
    )
    temporary_paths = {
        Path(worker_options['env'][name]) for name in ('TEMP', 'TMP', 'TMPDIR')
    }
    assert len(temporary_paths) == 1
    child_temp = temporary_paths.pop()
    assert child_temp.name == 'worker-temp'
    assert not child_temp.exists()


def test_worker_cli_dispatch_accepts_request_file_contract(tmp_path: Path) -> None:
    request = tmp_path / 'request.json'
    response = tmp_path / 'response.json'
    raw = b'{}'
    one_shot._write_private_regular_file(
        request,
        raw,
        maximum_size=one_shot.MAX_FOLLOW_ON_WORKER_REQUEST,
    )
    completed = subprocess.run(
        [
            sys.executable,
            '-B',
            str(Path(one_shot.__file__).resolve()),
            '--follow-on-worker',
            str(request),
            str(len(raw)),
            hashlib.sha256(raw).hexdigest(),
            str(response),
        ],
        input=b'',
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
        timeout=30,
    )

    assert completed.returncode == 0
    value = json.loads(response.read_text(encoding='utf-8'))
    assert value['ok'] is False
    assert value['error'] == 'follow_on_worker_failed'


def test_isolated_runtime_preflight_discovers_automatic_handlers() -> None:
    completed = subprocess.run(
        [
            sys.executable,
            '-I',
            '-B',
            str(Path(one_shot.__file__).resolve()),
            '--runtime-preflight',
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
        timeout=60,
    )

    if completed.returncode != 0:
        pytest.skip('isolated runtimeのsystem／venv依存がありません')
    assert completed.returncode == 0


def test_real_worker_recomputes_and_seals_child_contract(tmp_path: Path) -> None:
    """隔離workerが親の自己申告ではなく現在のraw child契約を検証する。"""

    runtime_probe = subprocess.run(
        [sys.executable, '-B', str(Path(one_shot.__file__).resolve()), '--help'],
        cwd=REPOSITORY_ROOT,
        env=one_shot._bounded_handler_environment(),
        shell=False,
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=30,
    )
    if runtime_probe.returncode != 0:
        pytest.skip('このinterpreterはsanitized follow-on worker依存を満たしません')

    output = tmp_path / 'jobs'
    output.mkdir()
    specs = one_shot.discover_handlers()
    contract = one_shot._build_follow_on_analysis_contract(
        registry=REGISTRY,
        specs=specs,
        minimum_confidence='medium',
        upx=None,
        sevenzip=None,
        diec=None,
        force_container_probe=False,
        max_static_layers=8,
        retry_max_static_layers=None,
        archive_password='infected',
        string_scan_limit=1000,
    )
    payload = b'synthetic offline follow-on fixture'
    digest = hashlib.sha256(payload).hexdigest()

    result = one_shot._execute_follow_on_child(
        payload=payload,
        digest=digest,
        parent_sha256='a' * 64,
        depth=1,
        output=output,
        registry=REGISTRY,
        minimum_confidence='medium',
        upx=None,
        sevenzip=None,
        diec=None,
        force_container_probe=False,
        max_static_layers=8,
        retry_max_static_layers=None,
        archive_password='infected',
        string_scan_limit=1000,
        analysis_contract=contract,
        timeout_seconds=60,
    )

    assert result['sha256'] == digest
    report = json.loads(
        (output / 'cases' / digest / 'report.json').read_text(encoding='utf-8')
    )
    assert report['analysis_contract'] == contract
    assert report['follow_on_lineage']['parent_sha256'] == 'a' * 64

    with pytest.raises(RuntimeError):
        one_shot._execute_follow_on_child(
            payload=b'different child',
            digest=hashlib.sha256(b'different child').hexdigest(),
            parent_sha256='a' * 64,
            depth=1,
            output=output,
            registry=REGISTRY,
            minimum_confidence='medium',
            upx=None,
            sevenzip=None,
            diec=None,
            force_container_probe=False,
            max_static_layers=8,
            retry_max_static_layers=None,
            archive_password='infected',
            string_scan_limit=1000,
            analysis_contract={},
            timeout_seconds=60,
        )


def test_retained_payload_scan_applies_record_budget_before_reads(tmp_path: Path, monkeypatch) -> None:
    digest = 'a' * 64
    case_dir = tmp_path / 'cases' / digest
    (case_dir / 'p').mkdir(parents=True)
    (case_dir / 'report.json').write_text('{}', encoding='utf-8')
    first = b'first'
    second = b'second'
    wrapper = _wrapper(first, 'p/first.bin')
    second_wrapper = _wrapper(second, 'p/second.bin')
    wrapper['verified_binary_outputs'].extend(second_wrapper['verified_binary_outputs'])
    wrapper['verified_binary_output_audit'] = _audit(2)
    (case_dir / 'p' / 'first.bin').write_bytes(first)
    (case_dir / 'p' / 'second.bin').write_bytes(second)
    monkeypatch.setattr(
        one_shot,
        '_case_wrapper_documents',
        lambda *_args: ([(case_dir / 'wrapper.json', wrapper)], case_dir / 'candidate.json', {}),
    )
    reads: list[int] = []

    def fake_read(_path: Path, *, expected_size: int, expected_sha256: str) -> bytes:
        reads.append(expected_size)
        data = first if expected_size == len(first) else second
        assert hashlib.sha256(data).hexdigest() == expected_sha256
        return data

    monkeypatch.setattr(one_shot, '_read_verified_artifact', fake_read)
    records, errors, read_count, read_bytes = one_shot._case_retained_payloads(
        tmp_path,
        digest,
        maximum_records=1,
        maximum_read_bytes=100,
    )

    assert len(records) == 1
    assert errors == ['verified_output_edge_limit']
    assert read_count == 1
    assert read_bytes == len(first)
    assert reads == [len(first)]


def test_retained_payload_scan_reports_exact_omitted_metadata(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """edge予算外の全metadataを、artifactを読まずに証明へ残す。"""

    digest = 'a' * 64
    case_dir = tmp_path / 'cases' / digest
    (case_dir / 'p').mkdir(parents=True)
    (case_dir / 'report.json').write_text('{}', encoding='utf-8')
    first = b'first'
    second = b'second'
    wrapper = _wrapper(first, 'p/first.bin')
    wrapper['verified_binary_outputs'].extend(
        _wrapper(second, 'p/second.bin')['verified_binary_outputs']
    )
    wrapper['verified_binary_output_audit'] = _audit(2)
    (case_dir / 'p' / 'first.bin').write_bytes(first)
    (case_dir / 'p' / 'second.bin').write_bytes(second)
    monkeypatch.setattr(
        one_shot,
        '_case_wrapper_documents',
        lambda *_args: (
            [(case_dir / 'wrapper.json', wrapper)],
            case_dir / 'candidate.json',
            {},
        ),
    )
    reads: list[str] = []

    def fake_read(path: Path, *, expected_size: int, expected_sha256: str) -> bytes:
        del expected_size
        reads.append(path.name)
        assert expected_sha256 == hashlib.sha256(first).hexdigest()
        return first

    monkeypatch.setattr(one_shot, '_read_verified_artifact', fake_read)
    records, errors, read_count, read_bytes, omitted = (
        one_shot._case_retained_payloads(
            tmp_path,
            digest,
            maximum_records=1,
            maximum_read_bytes=100,
            include_omitted_metadata=True,
        )
    )

    assert len(records) == 1
    assert errors == ['verified_output_edge_limit']
    assert read_count == 1
    assert read_bytes == len(first)
    assert reads == ['first.bin']
    assert omitted == [
        {
            'sha256': hashlib.sha256(second).hexdigest(),
            'size': len(second),
            'path': 'p/second.bin',
            'role': 'terminal_payload',
            'kind': 'pe',
            'reason': 'verified_output_edge_limit',
        }
    ]


def test_retained_payload_scan_stops_before_read_after_deadline(
    tmp_path: Path,
    monkeypatch,
) -> None:
    digest = 'a' * 64
    case_dir = tmp_path / 'cases' / digest
    case_dir.mkdir(parents=True)
    (case_dir / 'report.json').write_text('{}', encoding='utf-8')
    wrapper = _wrapper(b'payload')
    monkeypatch.setattr(
        one_shot,
        '_case_wrapper_documents',
        lambda *_args: ([(case_dir / 'wrapper.json', wrapper)], case_dir / 'candidate.json', {}),
    )
    monkeypatch.setattr(
        one_shot,
        '_read_verified_artifact',
        lambda *_args, **_kwargs: pytest.fail('deadline後にartifactを読んではならない'),
    )

    records, errors, read_count, read_bytes = one_shot._case_retained_payloads(
        tmp_path,
        digest,
        maximum_records=1,
        maximum_read_bytes=100,
        deadline=1.0,
        monotonic=lambda: 1.0,
    )

    assert records == []
    assert errors == ['verified_output_read_wall_clock_limit']
    assert read_count == 0
    assert read_bytes == 0


def _run_fixed_point(
    tmp_path: Path,
    monkeypatch,
    retained,
    *,
    strict_complete=None,
    monotonic=None,
    root_digests=None,
):
    root = 'a' * 64
    tmp_path.mkdir(exist_ok=True)
    monkeypatch.setattr(one_shot, '_case_retained_payloads', retained)
    monkeypatch.setattr(
        one_shot,
        '_case_result_from_disk',
        lambda *_args, **_kwargs: {'case_state': 'complete'},
    )
    monkeypatch.setattr(
        one_shot,
        '_case_strict_complete',
        strict_complete or (lambda *_args, **_kwargs: True),
    )
    monkeypatch.setattr(
        one_shot,
        '_case_has_follow_on_promotion',
        lambda *_args, **_kwargs: False,
    )
    calls: list[str] = []

    def execute(**kwargs):
        calls.append(kwargs['digest'])
        return {}

    optional_arguments = {}
    if monotonic is not None:
        optional_arguments['monotonic'] = monotonic
    result = one_shot._run_follow_on_fixed_point(
        root_digests=root_digests or [root],
        output=tmp_path,
        registry=REGISTRY,
        specs=[],
        requirements_policy={},
        minimum_confidence='medium',
        upx=None,
        sevenzip=None,
        diec=None,
        force_container_probe=False,
        max_static_layers=8,
        retry_max_static_layers=None,
        archive_password='infected',
        string_scan_limit=1000,
        analysis_contract={},
        root_analysis_contract={},
        resume=False,
        execute_child=execute,
        **optional_arguments,
    )
    return result, calls


def test_fixed_point_completes_child_graph_with_parent_promotion_enabled(
    tmp_path: Path,
    monkeypatch,
) -> None:
    child_data = b'MZ child payload'
    child = hashlib.sha256(child_data).hexdigest()

    def retained(_output: Path, digest: str, **_kwargs):
        if digest == 'a' * 64:
            return ([{
                'sha256': child,
                'size': len(child_data),
                'path': 'p/child.bin',
                'role': 'terminal_payload',
                'kind': 'pe',
                'data': child_data,
            }], [], 1, len(child_data))
        return [], [], 0, 0

    result, calls = _run_fixed_point(tmp_path, monkeypatch, retained)

    assert calls == [child]
    assert result['status'] == 'complete'
    assert result['parent_promotion_enabled'] is True
    assert result['edges'][0]['status'] == 'child_complete'
    assert result['errors'] == []


def test_fixed_point_omitted_metadata_forces_partial(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """全edgeがcompleteでも省略metadataがあればcompleteへ昇格しない。"""

    root = 'a' * 64
    child_data = b'bounded child'
    child = hashlib.sha256(child_data).hexdigest()
    omitted_data = b'omitted child'
    omitted_digest = hashlib.sha256(omitted_data).hexdigest()

    def retained(_output: Path, digest: str, **_kwargs):
        if digest != root:
            return [], [], 0, 0, []
        return (
            [
                {
                    'sha256': child,
                    'size': len(child_data),
                    'path': 'p/child.bin',
                    'role': 'terminal_payload',
                    'kind': 'data',
                    'data': child_data,
                }
            ],
            ['verified_output_edge_limit'],
            1,
            len(child_data),
            [
                {
                    'sha256': omitted_digest,
                    'size': len(omitted_data),
                    'path': 'p/omitted.bin',
                    'role': 'terminal_payload',
                    'kind': 'data',
                    'reason': 'verified_output_edge_limit',
                }
            ],
        )

    result, calls = _run_fixed_point(tmp_path, monkeypatch, retained)

    assert calls == [child]
    assert result['status'] == 'partial'
    assert result['edges'][0]['status'] == 'child_complete'
    assert result['omitted_metadata'] == [
        {
            'parent_sha256': root,
            'sha256': omitted_digest,
            'size': len(omitted_data),
            'path': 'p/omitted.bin',
            'role': 'terminal_payload',
            'kind': 'data',
            'reason': 'verified_output_edge_limit',
        }
    ]
    assert result['errors'] == [f'{root}:verified_output_edge_limit']


def test_fixed_point_promotes_parent_after_child_is_strict_complete(
    tmp_path: Path,
    monkeypatch,
) -> None:
    root = 'a' * 64
    child_data = b'child for parent promotion'
    child = hashlib.sha256(child_data).hexdigest()

    def retained(_output: Path, digest: str, **_kwargs):
        if digest == root:
            return ([{
                'sha256': child,
                'size': len(child_data),
                'path': 'p/child.bin',
                'role': 'terminal_payload',
                'kind': 'data',
                'data': child_data,
            }], [], 1, len(child_data))
        return [], [], 0, 0

    promoted: list[str] = []

    def promote(_output: Path, digest: str, **_kwargs) -> bool:
        promoted.append(digest)
        return digest == root

    monkeypatch.setattr(one_shot, '_promote_parent_case_from_follow_on', promote)
    result, calls = _run_fixed_point(
        tmp_path,
        monkeypatch,
        retained,
        strict_complete=lambda _output, digest, **_kwargs: digest == child,
    )

    assert calls == [child]
    assert promoted == [root]
    assert result['promoted_parent_sha256'] == [root]
    assert result['status'] == 'complete'


def test_fixed_point_rejects_cycle_without_executing_child(tmp_path: Path, monkeypatch) -> None:
    root = 'a' * 64
    data = b'cycle'

    def retained(_output: Path, _digest: str, **_kwargs):
        return ([{
            'sha256': root,
            'size': len(data),
            'path': 'p/cycle.bin',
            'role': 'terminal_payload',
            'kind': 'data',
            'data': data,
        }], [], 1, len(data))

    result, calls = _run_fixed_point(tmp_path, monkeypatch, retained)

    assert calls == []
    assert result['status'] == 'partial'
    assert result['edges'][0]['status'] == 'cycle_excluded'


def test_fixed_point_reaches_two_stage_payload_chain(tmp_path: Path, monkeypatch) -> None:
    """子が保持する孫payloadまで同じ有界queueで解析する。"""

    root = 'a' * 64
    child_data = b'child-stage'
    grandchild_data = b'grandchild-stage'
    child = hashlib.sha256(child_data).hexdigest()
    grandchild = hashlib.sha256(grandchild_data).hexdigest()

    def retained(_output: Path, digest: str, **_kwargs):
        values = {
            root: (child, child_data),
            child: (grandchild, grandchild_data),
        }
        if digest not in values:
            return [], [], 0, 0
        next_digest, data = values[digest]
        return ([{
            'sha256': next_digest,
            'size': len(data),
            'path': f'p/{next_digest}.bin',
            'role': 'terminal_payload',
            'kind': 'data',
            'data': data,
        }], [], 1, len(data))

    result, calls = _run_fixed_point(tmp_path, monkeypatch, retained)

    assert calls == [child, grandchild]
    assert result['status'] == 'complete'
    assert sorted(edge['depth'] for edge in result['edges']) == [1, 2]
    assert all(
        edge['status'] == 'child_complete'
        for edge in result['edges']
    )


def test_fixed_point_reuses_shared_payload_without_second_analysis(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """同一payloadを複数wrapperが返しても1回だけ解析し、graphをpartialにしない。"""

    child_data = b'shared-child'
    child = hashlib.sha256(child_data).hexdigest()

    def retained(_output: Path, digest: str, **_kwargs):
        if digest != 'a' * 64:
            return [], [], 0, 0
        records = [
            {
                'sha256': child,
                'size': len(child_data),
                'path': f'p/shared-{index}.bin',
                'role': 'terminal_payload',
                'kind': 'data',
                'data': child_data,
            }
            for index in range(2)
        ]
        return records, [], 2, len(child_data)

    result, calls = _run_fixed_point(tmp_path, monkeypatch, retained)

    assert calls == [child]
    assert result['status'] == 'complete'
    assert sorted(edge['status'] for edge in result['edges']) == [
        'child_complete',
        'shared_sha256_reused_complete',
    ]


def test_fixed_point_reuses_other_root_without_duplicate_child_node(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """保持payloadが別rootと同一SHAでもroot nodeを再利用し入力順序へ依存しない。"""

    first_root = 'a' * 64
    root_payload = b'other root bytes'
    other_root = hashlib.sha256(root_payload).hexdigest()

    def retained(_output: Path, digest: str, **_kwargs):
        if digest != first_root:
            return [], [], 0, 0
        return ([{
            'sha256': other_root,
            'size': len(root_payload),
            'path': 'p/other-root.bin',
            'role': 'terminal_payload',
            'kind': 'data',
            'data': root_payload,
        }], [], 1, len(root_payload))

    result, calls = _run_fixed_point(
        tmp_path,
        monkeypatch,
        retained,
        strict_complete=lambda _output, digest, **_kwargs: digest == other_root,
        root_digests=[other_root, first_root],
    )

    assert calls == []
    assert result['status'] == 'complete'
    assert result['edges'] == [
        {
            'parent_sha256': first_root,
            'child_sha256': other_root,
            'depth': 1,
            'path': 'p/other-root.bin',
            'role': 'terminal_payload',
            'kind': 'data',
            'size': len(root_payload),
            'status': 'shared_sha256_reused_complete',
        }
    ]
    assert {
        (node['sha256'], node['depth'], node['state']) for node in result['nodes']
    } == {
        (first_root, 0, 'root'),
        (other_root, 0, 'root'),
    }


def test_parent_complete_children_exclude_limits_cycles_and_root_reuse() -> None:
    parent = 'a' * 64
    normal = 'b' * 64
    shared = 'c' * 64
    limited = 'd' * 64
    root_reuse = 'e' * 64
    edges = [
        {'child_sha256': normal, 'status': 'queued'},
        {'child_sha256': shared, 'status': 'shared_sha256_reference'},
        {'child_sha256': limited, 'status': 'depth_limit'},
        {'child_sha256': root_reuse, 'status': 'shared_sha256_reference'},
    ]

    observed = one_shot._parent_complete_child_digests(
        parent,
        outbound={parent: [0, 1, 2, 3]},
        edges=edges,
        depths={normal: 1, shared: 2, limited: 4, root_reuse: 0},
        strict_complete_digests={normal, shared, limited, root_reuse},
    )

    assert observed == {normal, shared}


def test_scan_error_without_edges_is_partial(tmp_path: Path, monkeypatch) -> None:
    """保持artifact検証失敗をno payloadと誤認しない。"""

    def retained(_output: Path, _digest: str, **_kwargs):
        return [], ['artifact_verification_failed'], 0, 0

    result, calls = _run_fixed_point(tmp_path, monkeypatch, retained)

    assert calls == []
    assert result['status'] == 'partial'
    assert result['errors'] == [
        f"{'a' * 64}:artifact_verification_failed"
    ]


def test_fixed_point_recomputes_remaining_time_before_child(tmp_path: Path, monkeypatch) -> None:
    """resume確認で時間を消費しても古いremainingを子timeoutへ渡さない。"""

    child_data = b'child near wall deadline'
    child = hashlib.sha256(child_data).hexdigest()

    def retained(_output: Path, digest: str, **_kwargs):
        if digest != 'a' * 64:
            return [], [], 0, 0
        return ([{
            'sha256': child,
            'size': len(child_data),
            'path': 'p/child.bin',
            'role': 'terminal_payload',
            'kind': 'data',
            'data': child_data,
        }], [], 1, len(child_data))

    values = iter([0.0, 0.0, 0.0, 0.0, 299.5, 300.1])
    last = 300.1

    def monotonic() -> float:
        nonlocal last
        try:
            last = next(values)
        except StopIteration:
            pass
        return last

    result, calls = _run_fixed_point(
        tmp_path,
        monkeypatch,
        retained,
        strict_complete=lambda *_args, **_kwargs: False,
        monotonic=monotonic,
    )

    assert calls == []
    assert result['wall_clock_exhausted'] is True
    assert next(node for node in result['nodes'] if node['sha256'] == child)['state'] == (
        'wall_clock_limit'
    )


def test_run_batch_never_publishes_timeout_child_case(tmp_path: Path, monkeypatch) -> None:
    """timeout直前にcaseが残ってもderived_casesへ再読込しない。"""

    sample = tmp_path / 'sample.bin'
    sample.write_bytes(b'root sample')
    output = tmp_path / 'output'
    root = hashlib.sha256(b'root sample').hexdigest()
    child = 'b' * 64
    root_result = {
        'sha256': root,
        'source_name': sample.name,
        'family': 'unknown',
        'selected_family': None,
        'selected_families': [],
        'automation_family': None,
        'automation_state': 'unknown',
        'candidate_handler_attempts': 0,
        'ai_used': False,
        'campaign': 'unknown',
        'handler_succeeded': 0,
        'handler_failed': 0,
        'handler_no_evidence': 0,
        'handler_ambiguous': 0,
        'handler_incompatible': 0,
        'analysis_stage_failed': False,
        'analysis_stage_partial': False,
        'case_state': 'complete',
        'report': f'cases/{root}/report.json',
        'resumed': False,
    }
    monkeypatch.setattr(one_shot, 'discover_handlers', lambda: [])
    monkeypatch.setattr(one_shot, '_registered_families', lambda _registry: set())
    monkeypatch.setattr(one_shot, '_load_family_analysis_requirements', lambda: {})
    monkeypatch.setattr(
        one_shot,
        '_build_analysis_contract',
        lambda **_kwargs: {'schema_version': 1, 'sha256': 'c' * 64},
    )
    monkeypatch.setattr(
        one_shot,
        '_build_follow_on_analysis_contract',
        lambda **_kwargs: {'schema_version': 1, 'sha256': 'd' * 64},
    )
    monkeypatch.setattr(one_shot, 'analyze_unit', lambda *_args, **_kwargs: root_result)
    monkeypatch.setattr(
        one_shot,
        '_run_follow_on_fixed_point',
        lambda **_kwargs: {
            'schema_version': 1,
            'status': 'partial',
            'roots': [root],
            'nodes': [
                {'sha256': root, 'depth': 0, 'state': 'root'},
                {'sha256': child, 'depth': 1, 'state': 'timeout', 'size': 10},
            ],
            'edges': [
                {
                    'parent_sha256': root,
                    'child_sha256': child,
                    'depth': 1,
                    'path': 'p/child.bin',
                    'role': 'terminal_payload',
                    'kind': 'data',
                    'size': 10,
                    'status': 'child_incomplete',
                }
            ],
            'errors': [],
            'executed_sample': False,
            'network_contacted': False,
            'ai_used': False,
        },
    )
    loaded: list[str] = []

    def case_result(_output: Path, digest: str, **_kwargs):
        loaded.append(digest)
        if digest == child:
            raise AssertionError('timeout child must not be loaded')
        return root_result

    monkeypatch.setattr(one_shot, '_case_result_from_disk', case_result)

    summary = one_shot.run_batch(
        [sample],
        output,
        archive_mode='raw',
        max_file_size=1024,
    )

    assert loaded == [root]
    assert summary['derived_cases'] == []
    assert summary['derived_counts']['analyzed'] == 0
    assert summary['follow_on_analysis']['status'] == 'partial'


def test_follow_on_contract_describes_actual_raw_child_settings() -> None:
    """rootのforced familyやhintをchild契約へ虚偽継承しない。"""

    contract = one_shot._build_follow_on_analysis_contract(
        registry=REGISTRY,
        specs=[],
        minimum_confidence='medium',
        upx=None,
        sevenzip=None,
        diec=None,
        force_container_probe=False,
        max_static_layers=8,
        retry_max_static_layers=None,
        archive_password='infected',
        string_scan_limit=1000,
    )

    settings = contract['settings']
    assert settings['archive_mode'] == 'raw'
    assert settings['forced_family'] is None
    assert settings['family_hint_manifest'] is None
    assert settings['max_file_size'] == one_shot.MAX_FOLLOW_ON_PAYLOAD_SIZE
    assert settings['follow_on_fixed_point']['maximum_edges'] == one_shot.MAX_FOLLOW_ON_EDGES


def test_main_returns_partial_when_follow_on_is_incomplete(tmp_path: Path, monkeypatch) -> None:
    """rootがcompleteでも後段graph partialならWebUIへexit 20を返す。"""

    monkeypatch.setattr(one_shot, '_interpreter_is_isolated', lambda: True)
    monkeypatch.setattr(one_shot, '_runtime_preflight_main', lambda: 0)
    monkeypatch.setattr(
        one_shot,
        'run_batch',
        lambda *_args, **_kwargs: {
            'counts': {'errors': 0, 'partial': 0, 'failed': 0},
            'follow_on_analysis': {'status': 'partial'},
        },
    )

    assert one_shot.main(
        ['--input', str(tmp_path / 'sample.bin'), '--output', str(tmp_path / 'out')]
    ) == 20
