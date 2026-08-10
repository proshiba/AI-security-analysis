from __future__ import annotations

import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest


COMMON = Path(__file__).resolve().parents[1] / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

import analyze_sample as analyzer  # noqa: E402
import bounded_process  # noqa: E402
import runtime_contract  # noqa: E402
import analysis_job_runner as runner  # noqa: E402


def test_required_runtime_modules_cover_the_fixed_analysis_dependencies() -> None:
    assert runtime_contract.REQUIRED_RUNTIME_MODULES == tuple(
        sorted(runtime_contract.REQUIRED_RUNTIME_MODULES, key=str.casefold)
    )
    assert {
        "Cryptodome",
        "cabarchive",
        "capstone",
        "cryptography",
        "dncil",
        "dnfile",
        "olefile",
        "pefile",
        "pydantic",
        "pyzipper",
        "yaml",
        "yara",
    } == set(runtime_contract.REQUIRED_RUNTIME_MODULES)


def test_import_required_runtime_modules_is_exact_and_fail_closed() -> None:
    imported: list[str] = []

    def importer(name: str) -> ModuleType:
        imported.append(name)
        if name == "dnfile":
            raise ImportError("missing")
        return ModuleType(name)

    with pytest.raises(ImportError, match="missing"):
        runtime_contract.import_required_runtime_modules(importer=importer)

    expected_prefix = list(runtime_contract.REQUIRED_RUNTIME_MODULES)
    assert imported == expected_prefix[: expected_prefix.index("dnfile") + 1]


def test_isolated_import_probe_contains_only_the_fixed_module_manifest() -> None:
    source = runtime_contract.isolated_import_probe_source()

    assert "importlib.import_module" in source
    assert "os.environ" not in source
    for name in runtime_contract.REQUIRED_RUNTIME_MODULES:
        assert name in source


def test_runner_uses_the_central_runtime_import_probe() -> None:
    assert runner.RUNTIME_IMPORT_PROBE == runtime_contract.isolated_import_probe_source()


def test_analyzer_runtime_preflight_imports_fixed_dependencies(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []
    monkeypatch.setattr(
        runtime_contract,
        'import_required_runtime_modules',
        lambda: calls.append('runtime_dependencies'),
    )
    monkeypatch.setattr(analyzer, 'clear_handler_caches', lambda: calls.append('clear'))
    monkeypatch.setattr(
        analyzer,
        'discover_handlers',
        lambda: [
            SimpleNamespace(
                automatic=True,
                supported_interface=True,
                input_formats=('pe',),
                id='fixture:handler',
            )
        ],
    )

    assert analyzer._runtime_preflight_main() == 0
    assert calls == ['runtime_dependencies', 'clear']


def test_analyzer_runtime_preflight_fails_closed_on_missing_dependency(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def missing_dependency() -> None:
        raise ModuleNotFoundError('user-site-only dependency is unavailable')

    monkeypatch.setattr(
        runtime_contract,
        'import_required_runtime_modules',
        missing_dependency,
    )
    monkeypatch.setattr(
        analyzer,
        'clear_handler_caches',
        lambda: pytest.fail('dependency失敗後にcatalogへ進んではならない'),
    )

    assert analyzer._runtime_preflight_main() == 2


def test_direct_cli_reexecutes_full_analysis_in_same_isolated_python(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[list[str], dict]] = []

    def fake_run(command, **kwargs):
        calls.append((command, kwargs))
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(analyzer, '_interpreter_is_isolated', lambda: False)
    monkeypatch.setattr(bounded_process, 'run_bounded', fake_run)
    monkeypatch.setenv('VT_API_KEY', 'must-not-be-inherited')
    monkeypatch.setenv('TRIAGE_API_KEY', 'must-not-be-inherited')

    arguments = ['--input', 'sample.bin', '--output', 'result']
    assert analyzer._run_isolated_cli(arguments) == 0
    assert len(calls) == 1
    command, kwargs = calls[0]
    assert Path(command[0]).resolve() == Path(sys.executable).resolve()
    assert command[1:] == [
        '-I',
        '-B',
        str(Path(analyzer.__file__).resolve()),
        *arguments,
    ]
    assert kwargs['cwd'] == analyzer.REPOSITORY_ROOT
    assert kwargs['shell'] is False
    assert kwargs['check'] is False
    assert kwargs['stdout'] is sys.stdout
    assert kwargs['stderr'] is sys.stderr
    assert kwargs['timeout'] == analyzer.MAX_DIRECT_CLI_SECONDS
    assert kwargs['require_containment'] is True
    assert kwargs['maximum_active_processes'] == analyzer.MAX_DIRECT_CLI_ACTIVE_PROCESSES
    assert kwargs['maximum_memory_bytes'] == analyzer.MAX_DIRECT_CLI_MEMORY_BYTES
    assert kwargs['env']['PYTHONNOUSERSITE'] == '1'
    assert 'VT_API_KEY' not in kwargs['env']
    assert 'TRIAGE_API_KEY' not in kwargs['env']


def test_direct_cli_does_not_fallback_after_isolated_analysis_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[list[str]] = []

    def failed_run(command, **_kwargs):
        calls.append(command)
        return SimpleNamespace(returncode=1)

    monkeypatch.setattr(analyzer, '_interpreter_is_isolated', lambda: False)
    monkeypatch.setattr(bounded_process, 'run_bounded', failed_run)

    assert analyzer._run_isolated_cli(['--help']) == 1
    assert len(calls) == 1
    assert '-I' in calls[0]


def test_direct_cli_fails_closed_when_containment_cannot_be_created(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(analyzer, '_interpreter_is_isolated', lambda: False)
    monkeypatch.setattr(
        bounded_process,
        'run_bounded',
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            RuntimeError('containment unavailable')
        ),
    )

    assert analyzer._run_isolated_cli(['--help']) == 2


def test_isolated_main_stays_in_process_without_recursion(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(analyzer, '_interpreter_is_isolated', lambda: True)
    monkeypatch.setattr(analyzer, 'build_parser', lambda: pytest.fail('preflight失敗後に解析してはならない'))
    monkeypatch.setattr(analyzer, '_runtime_preflight_main', lambda: 2)
    monkeypatch.setattr(
        bounded_process,
        'run_bounded',
        lambda *_args, **_kwargs: pytest.fail('isolated processは子processを再帰起動しない'),
    )

    assert analyzer.main([]) == 2
