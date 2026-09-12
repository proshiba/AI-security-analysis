from __future__ import annotations

import io
import json
import subprocess
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest

COMMON = Path(__file__).resolve().parents[1] / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

import analysis_job_runner as runner  # noqa: E402
import analyze_sample as analyzer  # noqa: E402
import bounded_process  # noqa: E402
import runtime_contract  # noqa: E402


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
        "refinery.lib.cab",
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
        "import_required_runtime_modules",
        lambda: calls.append("runtime_dependencies"),
    )
    monkeypatch.setattr(analyzer, "clear_handler_caches", lambda: calls.append("clear"))
    monkeypatch.setattr(
        analyzer,
        "discover_handlers",
        lambda: [
            SimpleNamespace(
                automatic=True,
                supported_interface=True,
                input_formats=("pe",),
                id="fixture:handler",
            )
        ],
    )

    monkeypatch.setattr(
        analyzer,
        "_validate_runtime_handler_catalog",
        lambda _specs: calls.append("validate"),
    )

    assert analyzer._runtime_preflight_main() == 0
    assert calls == ["runtime_dependencies", "clear", "validate"]


def test_analyzer_runtime_preflight_fails_closed_on_missing_dependency(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def missing_dependency() -> None:
        raise ModuleNotFoundError("user-site-only dependency is unavailable")

    monkeypatch.setattr(
        runtime_contract,
        "import_required_runtime_modules",
        missing_dependency,
    )
    monkeypatch.setattr(
        analyzer,
        "clear_handler_caches",
        lambda: pytest.fail("dependency失敗後にcatalogへ進んではならない"),
    )

    assert analyzer._runtime_preflight_main() == 2


def test_normal_cli_dependency_preflight_does_not_discover_catalog(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """通常CLI前段は固定依存だけを確認し、catalog発見を二重実行しない。"""

    calls: list[str] = []
    monkeypatch.setattr(
        runtime_contract,
        "import_required_runtime_modules",
        lambda: calls.append("runtime_dependencies"),
    )
    monkeypatch.setattr(
        analyzer,
        "clear_handler_caches",
        lambda: pytest.fail("catalog cacheを通常CLI前段で操作してはならない"),
    )
    monkeypatch.setattr(
        analyzer,
        "discover_handlers",
        lambda: pytest.fail("catalogはrun_batch内だけで発見する"),
    )

    assert analyzer._runtime_dependency_preflight_main() == 0
    assert calls == ["runtime_dependencies"]


@pytest.mark.parametrize(
    "specs",
    [
        [],
        [
            SimpleNamespace(
                automatic=True,
                supported_interface=True,
                input_formats=("any",),
                id="fixture:unbounded",
            )
        ],
        [
            SimpleNamespace(
                automatic=True,
                supported_interface=True,
                input_formats=("pe",),
                id=f"fixture:{index}",
            )
            for index in range(257)
        ],
    ],
    ids=["empty", "unbounded-format", "handler-count-limit"],
)
def test_runtime_catalog_validator_fails_closed(specs: list[object]) -> None:
    """空・無界・件数超過catalogを通常解析へ渡さない。"""

    with pytest.raises(ValueError):
        analyzer._validate_runtime_handler_catalog(specs)


def test_run_batch_validates_fresh_catalog_before_component_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """batchはfresh catalogへvalidatorを適用してからfingerprintを取得する。"""

    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"offline synthetic fixture")
    calls: list[object] = []
    fresh_specs = [object()]

    monkeypatch.setattr(
        analyzer,
        "clear_handler_caches",
        lambda: calls.append("clear"),
    )
    monkeypatch.setattr(
        analyzer,
        "discover_handlers",
        lambda: calls.append("discover") or fresh_specs,
    )
    monkeypatch.setattr(
        analyzer,
        "_validate_runtime_handler_catalog",
        lambda specs: calls.append(("validate", specs)),
    )

    class SnapshotBoundaryReached(RuntimeError):
        pass

    def capture(_registry, specs):
        calls.append(("capture", specs))
        raise SnapshotBoundaryReached

    monkeypatch.setattr(
        analyzer._AnalysisComponentSnapshot,
        "capture",
        capture,
    )

    with pytest.raises(SnapshotBoundaryReached):
        analyzer.run_batch(
            [sample],
            tmp_path / "output",
            archive_mode="raw",
        )

    assert calls[-4:] == [
        "clear",
        "discover",
        ("validate", fresh_specs),
        ("capture", fresh_specs),
    ]


def test_isolated_main_avoids_full_catalog_preflight_before_run_batch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """通常CLIは依存確認後にrun_batchだけでcatalogを構築する。"""

    calls: list[str] = []
    monkeypatch.setattr(analyzer, "_interpreter_is_isolated", lambda: True)
    monkeypatch.setattr(
        analyzer,
        "_runtime_dependency_preflight_main",
        lambda: calls.append("dependencies") or 0,
    )
    monkeypatch.setattr(
        analyzer,
        "_runtime_preflight_main",
        lambda: pytest.fail("通常CLIでfull catalog preflightを重複実行してはならない"),
    )
    monkeypatch.setattr(
        analyzer,
        "run_batch",
        lambda *_args, **_kwargs: calls.append("batch")
        or {
            "counts": {
                "errors": 0,
                "triaged_unknown": 0,
                "partial": 0,
                "failed": 0,
            },
            "derived_counts": {"triaged_unknown": 0},
            "follow_on_analysis": {"status": "no_retained_payloads"},
        },
    )

    assert (
        analyzer.main(
            [
                "--input",
                str(tmp_path / "sample.bin"),
                "--output",
                str(tmp_path / "output"),
            ]
        )
        == 0
    )
    assert calls == ["dependencies", "batch"]


def test_direct_cli_reexecutes_full_analysis_in_same_isolated_python(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    calls: list[tuple[list[str], dict]] = []
    requests: list[dict[str, object]] = []

    def fake_run(command, **kwargs):
        calls.append((command, kwargs))
        request_raw = kwargs["input"]
        requests.append(json.loads(request_raw))
        worker_temp = Path(kwargs["env"]["TEMP"])
        assert not (worker_temp.parent / "request.json").exists()
        (Path(kwargs["cwd"]) / "response.json").write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "exit_code": 20,
                    "counts": {"analyzed": 1, "errors": 0},
                }
            ),
            encoding="utf-8",
        )
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(analyzer, "_interpreter_is_isolated", lambda: False)
    monkeypatch.setattr(bounded_process, "run_bounded", fake_run)
    monkeypatch.setenv("VT_API_KEY", "must-not-be-inherited")
    monkeypatch.setenv("TRIAGE_API_KEY", "must-not-be-inherited")

    arguments = [
        "--input",
        "sample.bin",
        "--output",
        "result",
    ]
    assert analyzer._run_isolated_cli(arguments) == 20
    assert len(calls) == 1
    command, kwargs = calls[0]
    assert Path(command[0]).resolve() == Path(sys.executable).resolve()
    assert command[1:] == [
        "-I",
        "-B",
        str(Path(analyzer.__file__).resolve()),
        "--direct-cli-worker",
    ]
    assert requests == [
        {
            "arguments": arguments,
            "archive_password": None,
            "inno_password": None,
            "schema_version": 1,
        }
    ]
    assert kwargs["input"]
    assert Path(kwargs["cwd"]).name.startswith("direct-cli-analysis-")
    assert kwargs["shell"] is False
    assert kwargs["check"] is False
    assert kwargs["stdout"] is subprocess.DEVNULL
    assert kwargs["stderr"] is subprocess.DEVNULL
    assert kwargs["timeout"] == analyzer.MAX_DIRECT_CLI_SECONDS
    assert kwargs["require_containment"] is True
    assert kwargs["maximum_active_processes"] == analyzer.MAX_DIRECT_CLI_ACTIVE_PROCESSES
    assert kwargs["maximum_memory_bytes"] == analyzer.MAX_DIRECT_CLI_MEMORY_BYTES
    assert kwargs["env"]["PYTHONNOUSERSITE"] == "1"
    assert "VT_API_KEY" not in kwargs["env"]
    assert "TRIAGE_API_KEY" not in kwargs["env"]
    assert json.loads(capsys.readouterr().out) == {"analyzed": 1, "errors": 0}


def test_direct_cli_worker_rejects_nonexact_request_schema(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """private requestは未知keyを含むschemaを解析前に拒否する。"""

    request = {
        "schema_version": 1,
        "arguments": ["--help"],
        "archive_password": None,
        "inno_password": None,
        "unexpected": "must-be-rejected",
    }
    raw = json.dumps(request).encode("utf-8")
    monkeypatch.setattr(analyzer, "_interpreter_is_isolated", lambda: True)
    monkeypatch.setattr(
        analyzer,
        "_execute_cli",
        lambda _arguments: pytest.fail("不正requestを実行してはならない"),
    )
    monkeypatch.setattr(analyzer.sys, "stdin", SimpleNamespace(buffer=io.BytesIO(raw)))

    assert analyzer._direct_cli_worker_main() == 2


def test_direct_cli_worker_accepts_valid_bounded_request(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """検証済みrequestだけを元の順序でisolated mainへ渡す。"""

    arguments = ["--input", "sample.bin", "--output", "result"]
    archive_secret = "archive-secret-in-private-request"
    inno_secret = "inno-secret-in-private-request"
    raw = json.dumps(
        {
            "schema_version": 1,
            "arguments": arguments,
            "archive_password": archive_secret,
            "inno_password": inno_secret,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    observed: list[tuple[list[str], dict[str, object]]] = []
    monkeypatch.setattr(analyzer, "_interpreter_is_isolated", lambda: True)
    monkeypatch.setattr(
        analyzer,
        "_execute_cli",
        lambda values, **kwargs: (
            observed.append((values, kwargs)) or 20,
            {"analyzed": 1},
        ),
    )
    monkeypatch.setattr(analyzer.sys, "stdin", SimpleNamespace(buffer=io.BytesIO(raw)))
    monkeypatch.chdir(tmp_path)

    assert analyzer._direct_cli_worker_main() == 0
    assert observed == [
        (
            arguments,
            {
                "archive_password_override": archive_secret,
                "inno_password_override": inno_secret,
            },
        )
    ]
    assert archive_secret not in arguments
    assert inno_secret not in arguments
    response = json.loads((tmp_path / "response.json").read_text(encoding="utf-8"))
    assert response == {
        "counts": {"analyzed": 1},
        "exit_code": 20,
        "schema_version": 1,
    }


def test_direct_cli_worker_suppresses_exception_after_private_request_load(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """解析本体の例外にprivate pathが含まれても親stdioへ公開しない。"""

    private_path = str((tmp_path / "private-source.bin").resolve())
    secret = "inno-secret-that-must-not-reach-stdio"
    arguments = ["--input", private_path, "--output", "result"]
    raw = json.dumps(
        {
            "schema_version": 1,
            "arguments": arguments,
            "archive_password": None,
            "inno_password": secret,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    monkeypatch.setattr(analyzer, "_interpreter_is_isolated", lambda: True)

    def fail_after_load(
        _arguments: list[str], **_kwargs
    ) -> tuple[int, dict[str, int]]:
        raise RuntimeError(f"failed for {private_path} using {secret}")

    monkeypatch.setattr(analyzer, "_execute_cli", fail_after_load)
    monkeypatch.setattr(analyzer.sys, "stdin", SimpleNamespace(buffer=io.BytesIO(raw)))
    monkeypatch.chdir(tmp_path)

    assert analyzer._direct_cli_worker_main() == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == ""


def test_direct_cli_worker_rejects_nonisolated_invocation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """内部worker flagを通常interpreterから直接利用できない。"""

    raw = (
        b'{"archive_password":null,"arguments":[],"inno_password":null,'
        b'"schema_version":1}'
    )
    monkeypatch.setattr(analyzer, "_interpreter_is_isolated", lambda: False)
    monkeypatch.setattr(
        analyzer,
        "_execute_cli",
        lambda _arguments: pytest.fail("非隔離workerを実行してはならない"),
    )
    monkeypatch.setattr(analyzer.sys, "stdin", SimpleNamespace(buffer=io.BytesIO(raw)))

    assert analyzer._direct_cli_worker_main() == 2


@pytest.mark.parametrize(
    "raw",
    [
        b'{"arguments":["--help"],"schema_version":',
        b"x" * (analyzer.MAX_DIRECT_CLI_REQUEST + 1),
    ],
    ids=("truncated", "oversized"),
)
def test_direct_cli_worker_rejects_truncated_or_oversized_stdin(
    raw: bytes,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """切れたJSONと上限超過stdinをmain実行前に拒否する。"""

    monkeypatch.setattr(analyzer, "_interpreter_is_isolated", lambda: True)
    monkeypatch.setattr(analyzer.sys, "stdin", SimpleNamespace(buffer=io.BytesIO(raw)))
    monkeypatch.setattr(
        analyzer,
        "_execute_cli",
        lambda _arguments: pytest.fail("不正stdinでmainを実行してはならない"),
    )

    assert analyzer._direct_cli_worker_main() == 2


def test_direct_cli_request_size_limit_blocks_before_process_start(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """上限超過argvはprivate file作成・子process開始より前に拒否する。"""

    monkeypatch.setattr(analyzer, "_interpreter_is_isolated", lambda: False)
    monkeypatch.setattr(
        bounded_process,
        "run_bounded",
        lambda *_args, **_kwargs: pytest.fail("上限超過requestでprocessを開始してはならない"),
    )

    oversized = "x" * (analyzer.MAX_DIRECT_CLI_ARGUMENT_CHARACTERS + 1)
    assert analyzer._run_isolated_cli([oversized]) == 2


@pytest.mark.parametrize(
    ("option", "request_field"),
    (
        ("--password-stdin", "archive_password"),
        ("--inno-password-stdin", "inno_password"),
    ),
)
def test_direct_cli_password_stdin_moves_secret_only_into_private_pipe(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    option: str,
    request_field: str,
) -> None:
    secret = "stdin-secret-not-for-process-list"
    captured: dict[str, object] = {}

    def fake_run(command, **kwargs):
        captured["command"] = command
        captured["kwargs"] = kwargs
        (Path(kwargs["cwd"]) / "response.json").write_text(
            json.dumps({"schema_version": 1, "exit_code": 0, "counts": {"analyzed": 1}}),
            encoding="utf-8",
        )
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(analyzer, "_interpreter_is_isolated", lambda: False)
    monkeypatch.setattr(analyzer.sys, "stdin", SimpleNamespace(buffer=io.BytesIO(secret.encode())))
    monkeypatch.setattr(bounded_process, "run_bounded", fake_run)

    assert analyzer._run_isolated_cli(
        ["--input", "sample.bin", "--output", "result", option]
    ) == 0
    command = captured["command"]
    kwargs = captured["kwargs"]
    assert secret not in command
    assert secret not in repr(kwargs["env"])
    assert secret not in str(kwargs["cwd"])
    request = json.loads(kwargs["input"])
    assert option not in request["arguments"]
    assert "--password" not in request["arguments"]
    assert "--inno-password" not in request["arguments"]
    assert request[request_field] == secret
    other_field = "inno_password" if request_field == "archive_password" else "archive_password"
    assert request[other_field] is None
    captured_stdio = capsys.readouterr()
    assert secret not in captured_stdio.out
    assert secret not in captured_stdio.err


@pytest.mark.parametrize(
    "arguments",
    (["--help"], ["--input", "sample.bin", "--help"], ["--input", "x", "-h"]),
)
def test_direct_cli_help_is_rendered_locally_without_starting_worker(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    arguments: list[str],
) -> None:
    monkeypatch.setattr(analyzer, "_interpreter_is_isolated", lambda: False)
    monkeypatch.setattr(
        bounded_process,
        "run_bounded",
        lambda *_args, **_kwargs: pytest.fail("helpでworkerを起動してはならない"),
    )

    assert analyzer._run_isolated_cli(arguments) == 0
    help_text = capsys.readouterr().out
    assert "使用法:" in help_text
    option_strings = {
        option
        for action in analyzer.build_parser()._actions
        for option in action.option_strings
    }
    assert "--password-stdin" in option_strings
    assert "--inno-password-stdin" in option_strings
    assert "--password" not in option_strings
    assert "--inno-password" not in option_strings


@pytest.mark.parametrize("raw_option", ("--password", "--inno-password"))
def test_direct_cli_raw_password_option_is_rejected_before_worker_without_echo(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    raw_option: str,
) -> None:
    private_path = "C:/private/sample.bin"
    secret = "must-not-reach-stdio"

    monkeypatch.setattr(analyzer, "_interpreter_is_isolated", lambda: False)
    monkeypatch.setattr(
        bounded_process,
        "run_bounded",
        lambda *_args, **_kwargs: pytest.fail("raw credentialでworkerを起動してはならない"),
    )

    assert analyzer._run_isolated_cli(
        ["--input", private_path, "--output", "result", raw_option, secret]
    ) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == ""


def test_execute_cli_uses_internal_default_infected_password(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: dict[str, object] = {}

    def fake_batch(*_args, **kwargs):
        observed.update(kwargs)
        return {
            "counts": {"errors": 0},
            "derived_counts": {},
            "follow_on_analysis": {"status": "complete"},
        }

    monkeypatch.setattr(analyzer, "_runtime_dependency_preflight_main", lambda: 0)
    monkeypatch.setattr(analyzer, "run_batch", fake_batch)

    exit_code, _counts = analyzer._execute_cli(
        ["--input", str(tmp_path / "sample.bin"), "--output", str(tmp_path / "out")]
    )

    assert exit_code == 0
    assert observed["password"] == "infected"
    assert observed["inno_password"] == ""


def test_direct_cli_fails_closed_when_containment_cannot_be_created(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(analyzer, "_interpreter_is_isolated", lambda: False)
    monkeypatch.setattr(
        bounded_process,
        "run_bounded",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("containment unavailable")),
    )

    assert analyzer._run_isolated_cli(
        ["--input", "sample.bin", "--output", "result"]
    ) == 2


def test_isolated_main_stays_in_process_without_recursion(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(analyzer, "_interpreter_is_isolated", lambda: True)
    monkeypatch.setattr(analyzer, "build_parser", lambda: pytest.fail("preflight失敗後に解析してはならない"))
    monkeypatch.setattr(analyzer, "_runtime_dependency_preflight_main", lambda: 2)
    monkeypatch.setattr(
        analyzer,
        "_runtime_preflight_main",
        lambda: pytest.fail("通常CLIでfull catalog preflightを実行してはならない"),
    )
    monkeypatch.setattr(
        bounded_process,
        "run_bounded",
        lambda *_args, **_kwargs: pytest.fail("isolated processは子processを再帰起動しない"),
    )

    assert analyzer.main([]) == 2
