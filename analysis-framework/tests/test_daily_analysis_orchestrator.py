from __future__ import annotations

import hashlib
import json
import os
import platform
import shutil
import sys
from collections import defaultdict
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

COMMON = Path(__file__).resolve().parents[1] / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

import archive_analysis_datastore as datastore_archive
import daily_analysis_orchestrator as target
import daily_news_malware_intake as news_intake


def test_reused_archive_is_reverified_with_remote_head(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """verified_reusedでもS3 size・SSE・hash metadataを再照合する。"""

    archive_sha256 = "a" * 64
    manifest_sha256 = "b" * 64
    target_name = "daily-fixture-case"
    report = {
        "object_uri": "s3://malware-analysis-datastore-720232834682/analysis-data/case.zip",
        "archive_size": 123,
        "archive_sha256": archive_sha256,
        "manifest_sha256": manifest_sha256,
    }
    response = {
        "ContentLength": 123,
        "ServerSideEncryption": "AES256",
        "Metadata": {
            "archive-sha256": archive_sha256,
            "manifest-sha256": manifest_sha256,
            "analysis-target": target_name,
        },
    }
    monkeypatch.setattr(datastore_archive, "find_aws_cli", lambda _value: Path("aws"))
    monkeypatch.setattr(datastore_archive, "_run_aws", lambda *_args, **_kwargs: response)

    target._reverify_archive_head(report, target=target_name)

    response["ContentLength"] = 122
    with pytest.raises(
        target.DailyOrchestrationError,
        match="HeadObject",
    ) as caught:
        target._reverify_archive_head(report, target=target_name)
    assert caught.value.code == "archive_remote_reverification_failed"


def test_daily_static_layer_retry_covers_multi_component_installers() -> None:
    """通常検体は軽量に保ち、上限到達時だけ十分な件数へ広げる。"""

    assert target.DAILY_INITIAL_STATIC_LAYERS == 6
    assert target.DAILY_RETRY_STATIC_LAYERS == target.analysis_job_runner.MAX_RETRY_STATIC_LAYERS
    assert target.DAILY_RETRY_STATIC_LAYERS > 14


def request_document(
    *,
    stages: dict[str, bool] | None = None,
    network: dict[str, bool] | None = None,
) -> dict:
    return {
        "schema_version": 2,
        "run_id": "daily-20260829",
        "analysis_date": "2026-08-29",
        "news_source_date": "2026-08-29",
        "source_manifest_sha256": "a" * 64,
        "malwarebazaar_count": 50,
        "tech_memo": "tech-memo",
        "stages": stages or {name: True for name in target.STAGES},
        "network": network
        or {
            "provider_lookups": False,
            "sample_download": False,
            "c2_monitoring": False,
            "datastore_upload": False,
        },
        "limits": {
            "query_limit": 200,
            "static_timeout_seconds": 3600,
            "ghidra_minimum_free_bytes": 8 * 1024 * 1024 * 1024,
            "ghidra_max_new_programs": 4,
        },
    }


def context(
    tmp_path: Path,
    document: dict | None = None,
    *,
    trusted_tool_configuration: target.analysis_job_runner.TrustedToolConfiguration | None = None,
) -> target.DailyContext:
    repository = tmp_path / "repository"
    repository.mkdir()
    news = repository / "tech-memo" / "daily-news" / "news" / "fixture"
    iocs = repository / "tech-memo" / "daily-news" / "iocs" / "fixture"
    news.mkdir(parents=True)
    iocs.mkdir(parents=True)
    (news / "20260829.md").write_text("news\n", encoding="utf-8")
    (iocs / "20260829.csv").write_text("type,value\n", encoding="utf-8")
    (iocs / "20260829.md").write_text("log\n", encoding="utf-8")
    raw_request = json.loads(json.dumps(document or request_document()))
    raw_request["source_manifest_sha256"] = target.verify_news_source_date(
        repository / "tech-memo",
        raw_request["news_source_date"],
    )["source_manifest_sha256"]
    request = target.validate_request_object(raw_request)
    return target._validate_context(
        request,
        repository=repository,
        intelligence_root=repository,
        private_root=tmp_path / "private",
        work_root=tmp_path / "work",
        ghidra_project_store=tmp_path / "ghidra-projects",
        allow_live_c2=False,
        create_roots=True,
        trusted_tool_configuration=trusted_tool_configuration,
    )


def trusted_tool_configuration(
    tmp_path: Path,
) -> tuple[target.analysis_job_runner.TrustedToolConfiguration, Path, Path]:
    """repository・input・job root外のoperator固定7zz fixtureを作る。"""

    tool_root = tmp_path / "operator-tools"
    tool_root.mkdir()
    sevenzip = tool_root / "7zz.exe"
    sevenzip.write_bytes(b"synthetic-static-sevenzip-tool")
    manifest = tool_root / "trusted-tools.json"
    manifest.write_text(
        json.dumps(
            {
                "schema_version": target.analysis_job_runner.SCHEMA_VERSION,
                "profile_id": "daily-test-tools",
                "platform": {
                    "sys_platform": sys.platform,
                    "machine": platform.machine().casefold(),
                },
                "tools": {
                    "upx": None,
                    "sevenzip": {
                        "path": str(sevenzip.resolve()),
                        "size": sevenzip.stat().st_size,
                        "sha256": hashlib.sha256(sevenzip.read_bytes()).hexdigest(),
                    },
                },
            },
            ensure_ascii=False,
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    configuration = target.analysis_job_runner.TrustedToolConfiguration(
        manifest_path=manifest,
        manifest_sha256=hashlib.sha256(manifest.read_bytes()).hexdigest(),
    )
    return configuration, manifest, sevenzip


def test_trusted_tool_cli_pair_is_operator_only_and_fail_closed() -> None:
    manifest = Path("C:/operator/trusted-tools.json")
    digest = "b" * 64
    complete = target._trusted_tool_configuration_from_args(
        SimpleNamespace(
            trusted_tools_manifest=manifest,
            trusted_tools_manifest_sha256=digest,
        )
    )
    assert complete == target.analysis_job_runner.TrustedToolConfiguration(
        manifest_path=manifest,
        manifest_sha256=digest,
    )
    for incomplete in (
        SimpleNamespace(
            trusted_tools_manifest=manifest,
            trusted_tools_manifest_sha256=None,
        ),
        SimpleNamespace(
            trusted_tools_manifest=None,
            trusted_tools_manifest_sha256=digest,
        ),
    ):
        with pytest.raises(target.DailyOrchestrationError) as captured:
            target._trusted_tool_configuration_from_args(incomplete)
        assert captured.value.code == "trusted_tool_configuration_incomplete"
    with pytest.raises(target.DailyOrchestrationError) as captured:
        target._trusted_tool_configuration_from_args(
            SimpleNamespace(
                trusted_tools_manifest=manifest,
                trusted_tools_manifest_sha256=digest.upper(),
            )
        )
    assert captured.value.code == "trusted_tool_manifest_pin_invalid"
    with pytest.raises(target.DailyOrchestrationError) as captured:
        target._trusted_tool_configuration_from_args(
            SimpleNamespace(
                trusted_tools_manifest=Path("trusted-tools.json"),
                trusted_tools_manifest_sha256=digest,
            )
        )
    assert captured.value.code == "trusted_tool_manifest_path_invalid"

    request_with_tool_path = request_document()
    request_with_tool_path["trusted_tools_manifest"] = str(manifest)
    with pytest.raises(target.DailyOrchestrationError):
        target.validate_request_object(request_with_tool_path)


@pytest.mark.parametrize(
    "command",
    ["plan", "preflight", "run", "resume", "drive", "verify"],
)
def test_operator_commands_accept_trusted_tool_pair(command: str) -> None:
    arguments = [
        command,
        "--request",
        "request.json",
        "--repository",
        "repository",
        "--intelligence-root",
        "intelligence",
        "--private-root",
        "private",
        "--work-root",
        "work",
        "--ghidra-project-store",
        "ghidra",
        "--trusted-tools-manifest",
        "C:/operator/tools.json",
        "--trusted-tools-manifest-sha256",
        "c" * 64,
    ]
    parsed = target.build_parser().parse_args(arguments)
    assert parsed.trusted_tools_manifest == Path("C:/operator/tools.json")
    assert parsed.trusted_tools_manifest_sha256 == "c" * 64


def test_trusted_tool_preflight_validates_pin_without_disclosing_paths(
    tmp_path: Path,
) -> None:
    configuration, manifest, sevenzip = trusted_tool_configuration(tmp_path)
    daily_context = context(
        tmp_path,
        trusted_tool_configuration=configuration,
    )

    report = target.build_preflight_report(daily_context)

    tools = report["trusted_static_tools"]
    assert tools["configured"] is True
    assert tools["ready"] is True
    assert tools["automatic_path_discovery"] is False
    assert tools["job_private_snapshot_deferred"] is True
    assert tools["operator_manifest_sha256"] == configuration.manifest_sha256
    assert tools["tools"]["sevenzip"]["name"] == sevenzip.name
    serialized = json.dumps(report, ensure_ascii=False)
    assert str(manifest.resolve()) not in serialized
    assert str(sevenzip.resolve()) not in serialized
    assert "trusted_tools_manifest" not in daily_context.request.public()


def test_trusted_tool_context_rejects_raw_manifest_pin_mismatch(
    tmp_path: Path,
) -> None:
    _configuration, manifest, _sevenzip = trusted_tool_configuration(tmp_path)
    mismatch = target.analysis_job_runner.TrustedToolConfiguration(
        manifest_path=manifest,
        manifest_sha256="0" * 64,
    )

    with pytest.raises(target.DailyOrchestrationError) as captured:
        context(tmp_path, trusted_tool_configuration=mismatch)

    assert captured.value.code == "trusted_tool_manifest_pin_mismatch"


def test_trusted_tool_context_rejects_nonregular_manifest(tmp_path: Path) -> None:
    manifest_directory = tmp_path / "operator-manifest-directory"
    manifest_directory.mkdir()
    configuration = target.analysis_job_runner.TrustedToolConfiguration(
        manifest_path=manifest_directory,
        manifest_sha256="0" * 64,
    )

    with pytest.raises(target.DailyOrchestrationError):
        context(tmp_path, trusted_tool_configuration=configuration)


def test_trusted_tool_context_rejects_reparse_manifest(tmp_path: Path) -> None:
    configuration, manifest, _sevenzip = trusted_tool_configuration(tmp_path)
    link = tmp_path / "trusted-tools-link.json"
    try:
        link.symlink_to(manifest)
    except OSError:
        pytest.skip("このhostではsymlink fixtureを作成できません")
    linked = target.analysis_job_runner.TrustedToolConfiguration(
        manifest_path=link,
        manifest_sha256=configuration.manifest_sha256,
    )

    with pytest.raises(target.DailyOrchestrationError):
        context(tmp_path, trusted_tool_configuration=linked)


def test_static_stage_forwards_trusted_tools_to_validate_run_and_result(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    configuration, _manifest, _sevenzip = trusted_tool_configuration(tmp_path)
    daily_context = context(
        tmp_path,
        trusted_tool_configuration=configuration,
    )
    request = SimpleNamespace(job_id="daily-trusted-tool-fixture")
    identity = SimpleNamespace(
        input_snapshot_manifest_sha256="1" * 64,
        family_hint_manifest_sha256="2" * 64,
        cache_key_sha256="3" * 64,
    )
    policy = target._load_context_trusted_tool_policy(daily_context)
    assert policy is not None
    snapshot_digest = "4" * 64
    provenance = {
        "profile_id": policy.profile_id,
        "operator_manifest_sha256": policy.operator_manifest_sha256,
        "snapshot_manifest_sha256": snapshot_digest,
        "tools": target._expected_static_snapshot_tool_identities(policy),
    }
    observed: dict[str, object] = {}

    monkeypatch.setattr(
        target,
        "_static_request",
        lambda _context: (request, identity),
    )

    def validate_job(_request, **kwargs):
        observed["validate_configuration"] = kwargs["trusted_tool_configuration"]
        return {
            "trusted_static_tools": {
                "profile_id": policy.profile_id,
                "operator_manifest_sha256": policy.operator_manifest_sha256,
                "tools": policy.identities(),
            }
        }

    def run_job(_request, **kwargs):
        observed["run_configuration"] = kwargs["trusted_tool_configuration"]
        job_dir = kwargs["jobs_root"] / request.job_id
        job_dir.mkdir()
        (job_dir / "result.json").write_text(
            json.dumps(
                {
                    "analysis_state": "complete",
                    "trusted_static_tools": provenance,
                    "artifacts": {
                        "trusted_static_tools_manifest": ("contract-inputs/trusted-static-tools.json"),
                        "trusted_static_tools_manifest_sha256": snapshot_digest,
                    },
                }
            ),
            encoding="utf-8",
        )
        return 0

    monkeypatch.setattr(target.analysis_job_runner, "validate_job", validate_job)
    monkeypatch.setattr(target.analysis_job_runner, "run_job", run_job)

    outcome = target._production_static_analysis(daily_context)

    assert outcome.status == "complete"
    assert observed == {
        "validate_configuration": configuration,
        "run_configuration": configuration,
    }
    assert outcome.result["trusted_tool_operator_manifest_sha256"] == configuration.manifest_sha256
    assert outcome.result["implementation_cache_key_sha256"] == (
        target._static_execution_cache_key(daily_context, identity.cache_key_sha256)
    )
    serialized = json.dumps(outcome.result, ensure_ascii=False)
    assert str(configuration.manifest_path.resolve()) not in serialized


def test_static_result_accepts_job_private_launcher_name(
    tmp_path: Path,
) -> None:
    configuration, _manifest, sevenzip = trusted_tool_configuration(tmp_path)
    daily_context = context(
        tmp_path,
        trusted_tool_configuration=configuration,
    )
    policy = target._load_context_trusted_tool_policy(daily_context)
    assert policy is not None
    assert sevenzip.name == "7zz.exe"
    snapshot_digest = "4" * 64
    job_id = "daily-trusted-tool-renamed-snapshot"
    job_dir = daily_context.jobs_root / job_id
    job_dir.mkdir(parents=True)
    snapshot_identities = target._expected_static_snapshot_tool_identities(policy)
    expected_launcher_name = "sevenzip.exe" if os.name == "nt" else "sevenzip"
    assert snapshot_identities["sevenzip"]["name"] == expected_launcher_name
    (job_dir / "result.json").write_text(
        json.dumps(
            {
                "analysis_state": "complete",
                "trusted_static_tools": {
                    "profile_id": policy.profile_id,
                    "operator_manifest_sha256": policy.operator_manifest_sha256,
                    "snapshot_manifest_sha256": snapshot_digest,
                    "tools": snapshot_identities,
                },
                "artifacts": {
                    "trusted_static_tools_manifest": ("contract-inputs/trusted-static-tools.json"),
                    "trusted_static_tools_manifest_sha256": snapshot_digest,
                },
            }
        ),
        encoding="utf-8",
    )

    observed = target._static_job_result_for_id(daily_context, job_id)

    assert observed["trusted_static_tools"]["tools"] == snapshot_identities


def test_static_result_rejects_different_operator_manifest_pin(
    tmp_path: Path,
) -> None:
    configuration, _manifest, _sevenzip = trusted_tool_configuration(tmp_path)
    daily_context = context(
        tmp_path,
        trusted_tool_configuration=configuration,
    )
    policy = target._load_context_trusted_tool_policy(daily_context)
    assert policy is not None
    job_id = "daily-trusted-tool-mismatch"
    job_dir = daily_context.jobs_root / job_id
    job_dir.mkdir(parents=True)
    (job_dir / "result.json").write_text(
        json.dumps(
            {
                "analysis_state": "complete",
                "trusted_static_tools": {
                    "profile_id": policy.profile_id,
                    "operator_manifest_sha256": "f" * 64,
                    "snapshot_manifest_sha256": "e" * 64,
                    "tools": policy.identities(),
                },
                "artifacts": {
                    "trusted_static_tools_manifest": ("contract-inputs/trusted-static-tools.json"),
                    "trusted_static_tools_manifest_sha256": "e" * 64,
                },
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(target.DailyOrchestrationError) as captured:
        target._static_job_result_for_id(daily_context, job_id)

    assert captured.value.code == "static_trusted_tool_mismatch"


def actions(
    overrides: dict[str, object] | None = None,
) -> tuple[target.DailyActions, defaultdict[str, int]]:
    calls: defaultdict[str, int] = defaultdict(int)
    supplied = overrides or {}

    def adapter(name: str):
        def invoke(_context: target.DailyContext) -> target.StageOutcome:
            calls[name] += 1
            value = supplied.get(name)
            if callable(value):
                return value(calls[name])
            if isinstance(value, target.StageOutcome):
                return value
            return target.StageOutcome("complete", {"stage": name})

        return invoke

    return (
        target.DailyActions(**{name: adapter(name) for name in target.STAGES}),
        calls,
    )


def ready_capacity(
    _context: target.DailyContext,
    _state,
) -> dict:
    return {
        "ready": True,
        "filesystems": [],
        "required_recovery_bytes": 0,
    }


def test_request_schema_is_exact_and_blocks_unbound_network() -> None:
    valid = request_document()
    parsed = target.validate_request_object(valid)
    assert parsed.malwarebazaar_count == 50
    assert set(target.request_json_schema()["required"]) == target.REQUEST_KEYS

    unknown = {**valid, "command": "anything"}
    with pytest.raises(target.DailyOrchestrationError, match="field集合"):
        target.validate_request_object(unknown)

    invalid_network = request_document()
    invalid_network["network"]["c2_monitoring"] = True
    invalid_network["stages"]["c2_monitoring"] = False
    with pytest.raises(target.DailyOrchestrationError, match="c2_monitoring"):
        target.validate_request_object(invalid_network)

    invalid_dependency = request_document()
    invalid_dependency["stages"]["malwarebazaar_acquisition"] = False
    with pytest.raises(target.DailyOrchestrationError, match="static_analysis"):
        target.validate_request_object(invalid_dependency)


def test_plan_declares_fixed_safety_and_network_boundaries() -> None:
    document = request_document()
    document["network"]["provider_lookups"] = True
    request = target.validate_request_object(document)
    plan = target.build_plan(request)

    assert plan["execution"] == {
        "mode": "sequential_checkpointed",
        "maximum_parallel_stages": 1,
        "continue_after_partial": True,
        "preflight_before_network": True,
        "bounded_drive_supported": True,
        "automatic_source_deletion": False,
        "sample_execution": False,
        "arbitrary_command_execution": False,
    }
    stages = {item["name"]: item for item in plan["stages"]}
    assert stages["news_intake"]["network_enabled"] is True
    assert stages["ghidra"]["network_enabled"] is False


def test_sample_download_limits_fit_provider_and_static_analyzer_bounds() -> None:
    """大容量候補を許可してもprovider・batch合計・後段上限を超えない。"""

    import daily_news_malware_intake
    import malwarebazaar_batch

    assert target.SAMPLE_DOWNLOAD_MAX_BYTES == 256 * target.MIB
    assert target.SAMPLE_DOWNLOAD_MAX_BYTES == daily_news_malware_intake.DAILY_SAMPLE_DOWNLOAD_MAX_BYTES
    assert target.SAMPLE_DOWNLOAD_MAX_BYTES <= malwarebazaar_batch.MAX_API_RESPONSE_BYTES
    assert target.SAMPLE_DOWNLOAD_MAX_BYTES <= target.analysis_job_runner.MAX_FILE_SIZE
    assert target.PREFLIGHT_SAMPLE_ARCHIVE_BYTES == 40 * target.MIB
    assert 50 * target.PREFLIGHT_SAMPLE_ARCHIVE_BYTES <= target.analysis_job_runner.MAX_TOTAL_INPUT_BYTES


def test_live_c2_requires_request_and_current_invocation(tmp_path: Path) -> None:
    document = request_document()
    document["network"]["c2_monitoring"] = True
    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / "tech-memo").write_text("fixture\n", encoding="utf-8")
    request = target.validate_request_object(document)

    with pytest.raises(target.DailyOrchestrationError, match="--allow-live-c2"):
        target._validate_context(
            request,
            repository=repository,
            intelligence_root=repository,
            private_root=tmp_path / "private",
            work_root=tmp_path / "work",
            ghidra_project_store=tmp_path / "ghidra",
            allow_live_c2=False,
            create_roots=True,
        )


def test_ghidra_project_store_must_be_separate(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / "tech-memo").write_text("fixture\n", encoding="utf-8")
    request = target.validate_request_object(request_document())

    with pytest.raises(target.DailyOrchestrationError, match="相互に分離"):
        target._validate_context(
            request,
            repository=repository,
            intelligence_root=repository,
            private_root=tmp_path / "private",
            work_root=tmp_path / "work",
            ghidra_project_store=tmp_path / "private" / "ghidra",
            allow_live_c2=False,
            create_roots=False,
        )


def test_production_ghidra_separates_prepared_inputs_from_source(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Ghidra復元cacheは取得済みarchiveの不変rootへ書き込まない。"""

    import ghidra_function_batch

    daily_context = context(tmp_path)
    captured = {}

    def fake_run(arguments):
        captured["arguments"] = arguments
        return {
            "status": "complete",
            "unique_pe_programs": 1,
            "complete_programs": 1,
            "pending_programs": [],
        }

    monkeypatch.setattr(ghidra_function_batch, "run", fake_run)

    outcome = target._production_ghidra(daily_context)

    arguments = captured["arguments"]
    assert outcome.status == "complete"
    assert arguments.sample_root == daily_context.source_root
    assert arguments.prepared_input_root == daily_context.ghidra_sample_root
    assert daily_context.ghidra_sample_root == (daily_context.work_root / "gi" / daily_context.request.run_id)
    assert daily_context.ghidra_sample_root.is_dir()
    assert daily_context.ghidra_sample_root != daily_context.source_root


def test_production_ghidra_generates_static_followup_plan(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Ghidra後の公開caseから未完了静的解析queueを自動更新する。"""

    import collection_followup_planner
    import ghidra_function_batch
    import sync_collection_publication

    daily_context = context(tmp_path)
    collection = daily_context.repository / "analysis-results" / "collections" / daily_context.collection_id
    collection.mkdir(parents=True)
    captured = {}
    call_order = []

    monkeypatch.setattr(
        ghidra_function_batch,
        "run",
        lambda _arguments: {
            "status": "complete",
            "unique_pe_programs": 1,
            "complete_programs": 1,
            "pending_programs": [],
        },
    )

    def fake_sync(repository, observed_collection, *, input_root, write):
        call_order.append("followup")
        captured.update(
            {
                "repository": repository,
                "collection": observed_collection,
                "input_root": input_root,
                "write": write,
            }
        )
        return {
            "planned_case_count": 3,
            "plan_sha256": "a" * 64,
        }

    def fake_projection(repository, observed_collection, *, write):
        call_order.append("projection")
        assert repository == daily_context.repository
        assert observed_collection == collection
        assert write is True
        return {
            "status": "updated",
            "stale_files": ["manifest.json", "publication-summary.json"],
            "case_count": 50,
            "write_performed": True,
            "check_passed": True,
        }

    monkeypatch.setattr(sync_collection_publication, "synchronize_collection_projection", fake_projection)
    monkeypatch.setattr(collection_followup_planner, "sync_plan", fake_sync)

    outcome = target._production_ghidra(daily_context)

    assert captured == {
        "repository": daily_context.repository,
        "collection": collection,
        "input_root": daily_context.source_root,
        "write": True,
    }
    assert call_order == ["projection", "followup"]
    assert outcome.result["collection_publication_projection"] == {
        "status": "updated",
        "stale_files": ["manifest.json", "publication-summary.json"],
        "case_count": 50,
        "write_performed": True,
        "check_passed": True,
    }
    assert outcome.result["static_followup_plan"] == {
        "status": "generated",
        "planned_case_count": 3,
        "plan_sha256": "a" * 64,
    }

    monkeypatch.setattr(
        ghidra_function_batch,
        "run",
        lambda _arguments: {
            "status": "ghidra_chunk_pending",
            "unique_pe_programs": 2,
            "complete_programs": 1,
            "pending_programs": ["b" * 64],
        },
    )
    captured.clear()
    call_order.clear()
    pending = target._production_ghidra(daily_context)
    assert pending.status == "partial"
    assert captured["input_root"] is None
    assert call_order == ["projection", "followup"]


def test_production_ghidra_stops_before_followup_when_projection_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """公開集計同期に失敗した状態からstaleなfollow-up計画を生成しない。"""

    import collection_followup_planner
    import ghidra_function_batch
    import sync_collection_publication

    daily_context = context(tmp_path)
    collection = daily_context.repository / "analysis-results" / "collections" / daily_context.collection_id
    collection.mkdir(parents=True)
    monkeypatch.setattr(
        ghidra_function_batch,
        "run",
        lambda _arguments: {"status": "complete", "pending_programs": []},
    )
    monkeypatch.setattr(
        sync_collection_publication,
        "synchronize_collection_projection",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(sync_collection_publication.ProjectionError("broken")),
    )
    followup_called = False

    def unexpected_followup(*_args, **_kwargs):
        nonlocal followup_called
        followup_called = True

    monkeypatch.setattr(collection_followup_planner, "sync_plan", unexpected_followup)
    with pytest.raises(target.DailyOrchestrationError) as observed:
        target._production_ghidra(daily_context)
    assert observed.value.code == "collection_publication_projection_failed"
    assert followup_called is False


def test_run_and_resume_retries_only_retryable_partial_stages(tmp_path: Path) -> None:
    daily_context = context(tmp_path)

    def ghidra(attempt: int) -> target.StageOutcome:
        if attempt == 1:
            return target.StageOutcome(
                "partial",
                {
                    "stop_reason": "minimum_free_space_not_met",
                    "disk_space": {
                        "minimum_free_bytes": 1024,
                        "filesystems": [{"free_bytes": 256}],
                    },
                },
                retryable=True,
            )
        return target.StageOutcome("complete", {"status": "complete"})

    def validation(attempt: int) -> target.StageOutcome:
        return (
            target.StageOutcome("partial", {"complete": False}, retryable=True)
            if attempt == 1
            else target.StageOutcome("complete", {"complete": True})
        )

    fake_actions, calls = actions({"ghidra": ghidra, "validation": validation})
    first = target.run_daily(
        daily_context,
        actions=fake_actions,
        capacity_probe=ready_capacity,
    )
    assert first["status"] == "partial"
    assert first["capacity_remediation"]["required_recovery_bytes"] == 768
    assert first["capacity_remediation"]["automatic_source_deletion"] is False
    assert first["safety"]["automatic_source_deletion"] is False

    resumed = target.resume_daily(
        daily_context,
        actions=fake_actions,
        capacity_probe=ready_capacity,
    )
    assert resumed["status"] == "complete"
    assert calls["ghidra"] == 2
    assert calls["validation"] == 2
    assert calls["publication"] == 1
    assert calls["private_archive"] == 1


def test_resume_marks_daily_state_running_before_stage_reloads_it(tmp_path: Path) -> None:
    daily_context = context(tmp_path)

    def private_archive(attempt: int) -> target.StageOutcome:
        if attempt == 1:
            raise target.DailyOrchestrationError("fixture_failure", "fixture")
        reloaded = target._load_state(daily_context)
        assert reloaded["status"] == "running"
        # load時は中断されたrunning stageを再開可能なpendingへ正規化する。
        assert reloaded["stages"]["private_archive"]["status"] == "pending"
        return target.StageOutcome("complete", {"status": "verified"})

    fake_actions, calls = actions({"private_archive": private_archive})
    first = target.run_daily(
        daily_context,
        actions=fake_actions,
        capacity_probe=ready_capacity,
    )
    assert first["status"] == "failed"

    resumed = target.resume_daily(
        daily_context,
        actions=fake_actions,
        capacity_probe=ready_capacity,
    )

    assert resumed["status"] == "complete"
    assert calls["private_archive"] == 2


def test_non_retryable_partial_is_not_reexecuted(tmp_path: Path) -> None:
    daily_context = context(tmp_path)
    fake_actions, calls = actions(
        {
            "static_analysis": target.StageOutcome(
                "partial",
                {"analysis_state": "partial"},
                retryable=False,
            )
        }
    )
    assert (
        target.run_daily(
            daily_context,
            actions=fake_actions,
            capacity_probe=ready_capacity,
        )["status"]
        == "partial"
    )
    assert (
        target.resume_daily(
            daily_context,
            actions=fake_actions,
            capacity_probe=ready_capacity,
        )["status"]
        == "partial"
    )
    assert calls["static_analysis"] == 1


def test_ghidra_chunks_can_make_progress_beyond_default_attempt_limit(tmp_path: Path) -> None:
    daily_context = context(tmp_path)

    def ghidra(attempt: int) -> target.StageOutcome:
        if attempt <= target.MAX_ATTEMPTS:
            return target.StageOutcome(
                "partial",
                {
                    "status": "ghidra_chunk_pending",
                    "stop_reason": "max_new_programs_reached",
                    "complete_programs": attempt * 4,
                },
                retryable=True,
            )
        return target.StageOutcome("complete", {"status": "complete"})

    fake_actions, calls = actions({"ghidra": ghidra})
    state = target.run_daily(
        daily_context,
        actions=fake_actions,
        capacity_probe=ready_capacity,
    )
    for _ in range(target.MAX_ATTEMPTS):
        state = target.resume_daily(
            daily_context,
            actions=fake_actions,
            capacity_probe=ready_capacity,
        )
    assert state["status"] == "complete"
    assert calls["ghidra"] == target.MAX_ATTEMPTS + 1


def test_resume_rejects_implementation_contract_change(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    daily_context = context(tmp_path)
    fake_actions, _calls = actions()
    target.run_daily(
        daily_context,
        actions=fake_actions,
        capacity_probe=ready_capacity,
    )
    monkeypatch.setattr(target, "_implementation_sha256", lambda: "0" * 64)
    with pytest.raises(target.DailyOrchestrationError, match="実装契約"):
        target.resume_daily(
            daily_context,
            actions=fake_actions,
            capacity_probe=ready_capacity,
        )


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda state: state["safety"].update({"automatic_source_deletion": True}), "安全値"),
        (lambda state: state.update({"status": "complete"}), "全体とstage"),
        (lambda state: state["stages"]["news_intake"].update({"retryable": True}), "完了stage"),
    ],
)
def test_resume_rejects_tampered_state(
    tmp_path: Path,
    mutation,
    message: str,
) -> None:
    daily_context = context(tmp_path)
    fake_actions, _calls = actions(
        {
            "ghidra": target.StageOutcome(
                "partial",
                {"stop_reason": "max_new_programs_reached"},
                retryable=True,
            )
        }
    )
    target.run_daily(
        daily_context,
        actions=fake_actions,
        capacity_probe=ready_capacity,
    )
    state_path = daily_context.state_root / "state.json"
    state = json.loads(state_path.read_text(encoding="utf-8"))
    mutation(state)
    state_path.write_text(json.dumps(state), encoding="utf-8")
    with pytest.raises(target.DailyOrchestrationError, match=message):
        target.resume_daily(
            daily_context,
            actions=fake_actions,
            capacity_probe=ready_capacity,
        )


def test_resume_rejects_saved_request_change(tmp_path: Path) -> None:
    daily_context = context(tmp_path)
    fake_actions, _calls = actions()
    target.run_daily(
        daily_context,
        actions=fake_actions,
        capacity_probe=ready_capacity,
    )
    request_path = daily_context.state_root / "request.json"
    saved = json.loads(request_path.read_text(encoding="utf-8"))
    saved["malwarebazaar_count"] = 49
    request_path.write_text(json.dumps(saved), encoding="utf-8")
    with pytest.raises(target.DailyOrchestrationError, match="保存済み日次request"):
        target.resume_daily(
            daily_context,
            actions=fake_actions,
            capacity_probe=ready_capacity,
        )


def test_resume_recovers_running_state_after_last_stage_checkpoint(tmp_path: Path) -> None:
    daily_context = context(tmp_path)
    fake_actions, calls = actions()
    completed = target.run_daily(
        daily_context,
        actions=fake_actions,
        capacity_probe=ready_capacity,
    )
    state_path = daily_context.state_root / "state.json"
    completed["status"] = "running"
    state_path.write_text(json.dumps(completed), encoding="utf-8")

    resumed = target.resume_daily(
        daily_context,
        actions=fake_actions,
        capacity_probe=ready_capacity,
    )
    assert resumed["status"] == "complete"
    assert all(calls[name] == 1 for name in target.STAGES)


def test_archive_report_requires_remote_verification_and_source_retention(tmp_path: Path) -> None:
    report = {
        "status": "verified",
        "target": "daily-source",
        "archive_sha256": "a" * 64,
        "manifest_sha256": "b" * 64,
        "local_source_deleted": False,
        "s3_verification": {"server_side_encryption": "AES256"},
    }
    path = tmp_path / "report.json"
    path.write_text(json.dumps(report), encoding="utf-8")
    assert target._verified_archive_report(path, "daily-source") == report

    report["local_source_deleted"] = True
    path.write_text(json.dumps(report), encoding="utf-8")
    with pytest.raises(target.DailyOrchestrationError, match="source保持"):
        target._verified_archive_report(path, "daily-source")


def test_status_rejects_tampered_capacity_deletion_flags(tmp_path: Path) -> None:
    daily_context = context(tmp_path)
    fake_actions, _calls = actions(
        {
            "ghidra": target.StageOutcome(
                "partial",
                {
                    "stop_reason": "minimum_free_space_not_met",
                    "disk_space": {
                        "minimum_free_bytes": 1024,
                        "filesystems": [{"free_bytes": 256}],
                    },
                },
                retryable=True,
            )
        }
    )
    target.run_daily(
        daily_context,
        actions=fake_actions,
        capacity_probe=ready_capacity,
    )
    state_path = daily_context.state_root / "state.json"
    state = json.loads(state_path.read_text(encoding="utf-8"))
    state["capacity_remediation"]["automatic_source_deletion"] = True
    state_path.write_text(json.dumps(state), encoding="utf-8")

    with pytest.raises(target.DailyOrchestrationError, match="境界"):
        target.read_status(daily_context.work_root, daily_context.request.run_id)


def test_tree_size_rejects_hardlinks(tmp_path: Path) -> None:
    root = tmp_path / "source"
    root.mkdir()
    source = root / "one.bin"
    source.write_bytes(b"fixture")
    os.link(source, root / "two.bin")
    with pytest.raises(target.DailyOrchestrationError, match="通常file"):
        target._tree_size(root)


@pytest.mark.skipif(os.name != "nt", reason="Windows長パス固有の回帰テスト")
def test_tree_size_handles_extended_length_paths(tmp_path: Path) -> None:
    root = tmp_path / "source"
    current = target.analysis_job_runner._extended_length_path(root)
    current.mkdir()
    depth = 0
    while len(str(current / "payload.bin")) < 270:
        depth += 1
        current = current / f"segment-{depth:02d}-{'x' * 32}"
        current.mkdir()
    payload = current / "payload.bin"
    payload.write_bytes(b"fixture")

    assert len(str(payload)) >= 270
    assert target._tree_size(root) == len(b"fixture")


def test_latest_complete_source_discovery_and_request_draft(tmp_path: Path) -> None:
    memo = tmp_path / "tech-memo"
    news = memo / "daily-news" / "news" / "2026_07-09"
    iocs = memo / "daily-news" / "iocs" / "2026_07-09"
    news.mkdir(parents=True)
    iocs.mkdir(parents=True)
    (news / "20260829.md").write_text("news\n", encoding="utf-8")
    (iocs / "20260829.csv").write_text("type,value\n", encoding="utf-8")
    (iocs / "20260829.md").write_text("log\n", encoding="utf-8")
    (news / "20260830.md").write_text("incomplete\n", encoding="utf-8")

    discovered = target.discover_latest_news_source(memo)
    assert discovered["source_date"] == "2026-08-29"
    assert discovered["network_contacted"] is False

    request = target.draft_request_document(
        intelligence_root=tmp_path,
        tech_memo="tech-memo",
        analysis_date="2026-08-30",
        run_id=None,
        malwarebazaar_count=50,
    )
    assert request["run_id"] == "daily-20260830"
    assert request["news_source_date"] == "2026-08-29"
    assert request["source_manifest_sha256"] == discovered["source_manifest_sha256"]
    assert all(request["stages"].values())
    assert all(request["network"].values())


def test_capacity_preflight_groups_roles_without_disclosing_paths(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    daily_context = context(tmp_path)
    monkeypatch.setattr(
        target.shutil,
        "disk_usage",
        lambda _path: SimpleNamespace(free=1),
    )

    report = target.build_capacity_preflight(daily_context)
    assert report["ready"] is False
    assert report["required_recovery_bytes"] > 0
    assert report["network_contacted"] is False
    assert report["automatic_source_deletion"] is False
    serialized = json.dumps(report, ensure_ascii=False)
    assert str(tmp_path) not in serialized
    assert "ghidra_project_reserve" in serialized
    assert "archive_staging" in serialized


def test_run_capacity_preflight_stops_before_any_stage(tmp_path: Path) -> None:
    daily_context = context(tmp_path)
    fake_actions, calls = actions()

    def blocked(_context, _state):
        return {
            "ready": False,
            "required_recovery_bytes": 900,
            "filesystems": [
                {
                    "filesystem": "filesystem-1",
                    "roles": ["ghidra_project_reserve"],
                    "required_free_bytes": 1000,
                    "free_bytes": 100,
                    "shortfall_bytes": 900,
                }
            ],
        }

    state = target.run_daily(
        daily_context,
        actions=fake_actions,
        capacity_probe=blocked,
    )
    assert state["status"] == "partial"
    assert state["capacity_remediation"]["reason"] == "preflight_capacity_insufficient"
    assert state["capacity_remediation"]["required_recovery_bytes"] == 900
    assert all(record["attempts"] == 0 for record in state["stages"].values())
    assert not calls


def test_run_rejects_changed_source_before_checkpoint(tmp_path: Path) -> None:
    daily_context = context(tmp_path)
    source = next((daily_context.intelligence_root / "tech-memo").rglob("20260829.csv"))
    source.unlink()
    fake_actions, calls = actions()

    with pytest.raises(target.DailyOrchestrationError, match="一意に存在"):
        target.run_daily(
            daily_context,
            actions=fake_actions,
            capacity_probe=ready_capacity,
        )
    assert not daily_context.state_root.exists()
    assert not calls


def test_drive_repeats_retryable_chunks_until_complete(tmp_path: Path) -> None:
    daily_context = context(tmp_path)

    def ghidra(attempt: int) -> target.StageOutcome:
        if attempt < 3:
            return target.StageOutcome(
                "partial",
                {
                    "status": "ghidra_chunk_pending",
                    "stop_reason": "max_new_programs_reached",
                    "complete_programs": attempt * 4,
                },
                retryable=True,
            )
        return target.StageOutcome("complete", {"status": "complete"})

    fake_actions, calls = actions({"ghidra": ghidra})
    state = target.drive_daily(
        daily_context,
        actions=fake_actions,
        max_cycles=8,
        capacity_probe=ready_capacity,
    )
    assert state["status"] == "complete"
    assert calls["ghidra"] == 3
    assert calls["publication"] == 1
    assert calls["c2_monitoring"] == 1


def test_drive_stops_when_retryable_partial_has_no_semantic_progress(
    tmp_path: Path,
) -> None:
    daily_context = context(tmp_path)
    unchanged = target.StageOutcome(
        "partial",
        {
            "status": "ghidra_chunk_pending",
            "stop_reason": "max_new_programs_reached",
            "complete_programs": 4,
        },
        retryable=True,
    )
    fake_actions, calls = actions({"ghidra": unchanged})

    state = target.drive_daily(
        daily_context,
        actions=fake_actions,
        max_cycles=100,
        capacity_probe=ready_capacity,
    )
    assert state["status"] == "partial"
    assert calls["ghidra"] == 2


def test_private_archive_attempt_budget_covers_ghidra_chunks() -> None:
    assert target.MAX_STAGE_ATTEMPTS["private_archive"] == target.MAX_STAGE_ATTEMPTS["ghidra"]


def test_archive_capacity_partial_becomes_resume_remediation() -> None:
    remediation = target._capacity_remediation(
        target.StageOutcome(
            "partial",
            {
                "status": "archive_staging_capacity_insufficient",
                "required_staging_bytes": 100,
                "minimum_reserve_bytes": 50,
                "observed_free_bytes": 20,
            },
            retryable=True,
        )
    )
    assert remediation is not None
    assert remediation["reason"] == "archive_staging_capacity_insufficient"
    assert remediation["required_recovery_bytes"] == 130
    assert remediation["automatic_source_deletion"] is False


def test_windows_drive_relative_tech_memo_is_rejected() -> None:
    document = request_document()
    document["tech_memo"] = "D:evil"
    with pytest.raises(target.DailyOrchestrationError, match="POSIX相対path"):
        target.validate_request_object(document)


def test_run_rejects_source_content_replacement_before_checkpoint(
    tmp_path: Path,
) -> None:
    daily_context = context(tmp_path)
    source = next((daily_context.intelligence_root / "tech-memo").rglob("20260829.csv"))
    source.write_text("type,value\nchanged,value\n", encoding="utf-8")
    fake_actions, calls = actions()

    with pytest.raises(target.DailyOrchestrationError) as captured:
        target.run_daily(
            daily_context,
            actions=fake_actions,
            capacity_probe=ready_capacity,
        )
    assert captured.value.code == "news_source_changed"
    assert not daily_context.state_root.exists()
    assert not calls


def test_source_discovery_has_global_entry_and_depth_limits(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "sources"
    root.mkdir()
    for index in range(3):
        (root / f"{index}.txt").write_text("fixture\n", encoding="utf-8")
    monkeypatch.setattr(target, "MAX_SOURCE_DISCOVERY_FILES", 2)
    with pytest.raises(target.DailyOrchestrationError) as captured:
        target._bounded_tree_files(root)
    assert captured.value.code == "news_source_discovery_limit"

    monkeypatch.setattr(target, "MAX_SOURCE_DISCOVERY_FILES", 100)
    monkeypatch.setattr(target, "MAX_SOURCE_DISCOVERY_DEPTH", 1)
    nested = root / "one" / "two"
    nested.mkdir(parents=True)
    with pytest.raises(target.DailyOrchestrationError) as captured:
        target._bounded_tree_files(root)
    assert captured.value.code == "news_source_discovery_depth"


def test_repository_lock_conflicts_across_different_work_roots(
    tmp_path: Path,
) -> None:
    first = context(tmp_path)
    second = target._validate_context(
        first.request,
        repository=first.repository,
        intelligence_root=first.intelligence_root,
        private_root=tmp_path / "private-second",
        work_root=tmp_path / "work-second",
        ghidra_project_store=tmp_path / "ghidra-second",
        allow_live_c2=False,
        create_roots=True,
    )
    with target._run_lock(first), pytest.raises(target.DailyOrchestrationError) as captured:
        with target._run_lock(second):
            pass
    assert captured.value.code == "run_locked"


def test_collection_binding_tamper_cannot_be_adopted(tmp_path: Path) -> None:
    daily_context = context(tmp_path)
    target._ensure_collection_binding(daily_context, create=True)
    binding_path = daily_context.collection_root / "collection-binding.json"
    binding = json.loads(binding_path.read_text(encoding="utf-8"))
    binding["run_id"] = "other-run"
    binding_path.write_text(json.dumps(binding), encoding="utf-8")

    with pytest.raises(target.DailyOrchestrationError) as captured:
        target._ensure_collection_binding(daily_context, create=False)
    assert captured.value.code == "collection_owned_by_other_run"


def test_acquisition_tree_rejects_unbound_entry_and_child_reparse(
    tmp_path: Path,
) -> None:
    daily_context = context(tmp_path)
    daily_context.source_root.mkdir(parents=True)
    (daily_context.source_root / "unbound.zip").write_bytes(b"fixture")
    with pytest.raises(target.DailyOrchestrationError) as captured:
        target._validate_acquisition_tree_layout(
            daily_context,
            selected_hashes=None,
        )
    assert captured.value.code == "acquisition_tree_unbound_entry"

    (daily_context.source_root / "unbound.zip").unlink()
    external = tmp_path / "external"
    external.mkdir()
    try:
        os.symlink(
            external,
            daily_context.source_root / ("a" * 64),
            target_is_directory=True,
        )
    except OSError:
        pytest.skip("このWindows環境ではdirectory symlinkを作成できません")
    with pytest.raises(target.DailyOrchestrationError) as captured:
        target._validate_acquisition_tree_layout(
            daily_context,
            selected_hashes=["a" * 64],
        )
    assert captured.value.code == "acquisition_tree_reparse_forbidden"


def test_acquisition_tree_uses_fresh_path_stat_after_atomic_replace(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    daily_context = context(tmp_path)
    daily_context.source_root.mkdir(parents=True)
    (daily_context.source_root / "manifest.json").write_text("{}\n", encoding="utf-8")
    (daily_context.source_root / "family-hints.json").write_text(
        "{}\n",
        encoding="utf-8",
    )
    real_scandir = target.os.scandir

    class EntryProxy:
        def __init__(self, entry: os.DirEntry[str]) -> None:
            self._entry = entry

        def __getattr__(self, name: str) -> object:
            return getattr(self._entry, name)

        def stat(self, *, follow_symlinks: bool = True) -> os.stat_result:
            del follow_symlinks
            raise AssertionError("stale DirEntry.stat must not be used")

    class ScandirProxy:
        def __init__(self, path: os.PathLike[str] | str) -> None:
            self._iterator = real_scandir(path)

        def __enter__(self) -> ScandirProxy:
            return self

        def __exit__(self, *args: object) -> None:
            self._iterator.close()

        def __iter__(self) -> ScandirProxy:
            return self

        def __next__(self) -> EntryProxy:
            return EntryProxy(next(self._iterator))

    monkeypatch.setattr(target.os, "scandir", ScandirProxy)

    target._validate_acquisition_tree_layout(
        daily_context,
        selected_hashes=None,
    )


def test_ghidra_capacity_remediation_includes_planned_write() -> None:
    remediation = target._capacity_remediation(
        target.StageOutcome(
            "partial",
            {
                "stop_reason": "minimum_free_space_not_met",
                "disk_space": {
                    "minimum_free_bytes": 1_000,
                    "planned_write_bytes": 500,
                    "filesystems": [{"free_bytes": 1_200, "planned_write_bytes": 500}],
                },
            },
            retryable=True,
        )
    )
    assert remediation is not None
    assert remediation["required_recovery_bytes"] == 300
    assert remediation["planned_write_bytes"] == 500


def test_ghidra_capacity_remediation_applies_planned_write_per_filesystem() -> None:
    remediation = target._capacity_remediation(
        target.StageOutcome(
            "partial",
            {
                "stop_reason": "minimum_free_space_not_met",
                "disk_space": {
                    "minimum_free_bytes": 1_000,
                    "planned_write_bytes": 500,
                    "filesystems": [
                        {"free_bytes": 1_200, "planned_write_bytes": 500},
                        {"free_bytes": 900},
                    ],
                },
            },
            retryable=True,
        )
    )
    assert remediation is not None
    assert remediation["required_recovery_bytes"] == 400


def test_private_archive_keeps_news_and_generation_bound_ghidra_checkpoint(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    document = request_document()
    document["network"]["datastore_upload"] = True
    daily_context = context(tmp_path, document)
    daily_context.source_root.mkdir(parents=True)
    (daily_context.source_root / "source.bin").write_bytes(b"source")
    job = daily_context.jobs_root / "job-fixture"
    job.mkdir(parents=True)
    (job / "result.json").write_text("{}\n", encoding="utf-8")
    news = daily_context.daily_news_private_output / daily_context.request.news_source_date
    news.mkdir(parents=True)
    (news / "normalized-iocs.json").write_text("{}\n", encoding="utf-8")
    static_job = daily_context.daily_news_private_output / "static-analysis-jobs" / "fixture"
    static_job.mkdir(parents=True)
    (static_job / "summary.json").write_text("{}\n", encoding="utf-8")
    daily_context.ghidra_private_output.mkdir(parents=True)
    (daily_context.ghidra_private_output / "run-progress.json").write_text(
        json.dumps({"status": "ghidra_chunk_pending"}),
        encoding="utf-8",
    )
    (daily_context.ghidra_private_output / "functions.json").write_text(
        "{}\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(
        target,
        "_static_request",
        lambda _context: (SimpleNamespace(job_id="job-fixture"), object()),
    )
    monkeypatch.setattr(
        target.shutil,
        "disk_usage",
        lambda _path: SimpleNamespace(free=10**12),
    )
    observed: list[tuple[str, Path, str]] = []

    def archive_one(
        _context: target.DailyContext,
        *,
        role: str,
        source: Path,
        target: str,
    ) -> dict[str, str]:
        observed.append((role, source, target))
        return {"source_role": role, "target": target, "status": "verified"}

    monkeypatch.setattr(target, "_archive_one", archive_one)
    outcome = target._production_private_archive(daily_context)

    assert outcome.status == "partial"
    assert outcome.result["ghidra_checkpoint_archived"] is True
    roles = {role for role, _source, _target in observed}
    assert roles == {"daily_news", "ghidra_checkpoint"}
    assert "source" not in roles
    assert "one_shot_job" not in roles
    assert "ghidra_static_results" not in roles
    targets = [archive_target for _role, _source, archive_target in observed]
    assert len(targets) == len(set(targets))
    assert any("ghidra-checkpoint-" in value for value in targets)
    news_sources = [source for role, source, _target in observed if role == "daily_news"]
    assert news_sources == [daily_context.daily_news_private_output]


def test_private_archive_routes_complete_collection_to_case_archives(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    document = request_document()
    document["network"]["datastore_upload"] = True
    document["stages"]["news_intake"] = False
    daily_context = context(tmp_path, document)
    daily_context.source_root.mkdir(parents=True)
    one_shot = daily_context.jobs_root / "job-fixture" / "analysis"
    one_shot.mkdir(parents=True)
    daily_context.ghidra_private_output.mkdir(parents=True)
    (daily_context.ghidra_private_output / "run-progress.json").write_text(
        json.dumps({"status": "complete"}),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        target,
        "_static_request",
        lambda _context: (SimpleNamespace(job_id="job-fixture"), object()),
    )
    observed: list[Path] = []

    def archive_cases(
        _context: target.DailyContext,
        *,
        one_shot_root: Path,
    ) -> list[dict[str, object]]:
        observed.append(one_shot_root)
        return [
            {"source_role": "analysis_case", "target": "case-a"},
            {"source_role": "analysis_case", "target": "case-b"},
        ]

    monkeypatch.setattr(target, "_archive_analysis_cases", archive_cases)
    monkeypatch.setattr(
        target,
        "_archive_one",
        lambda *_args, **_kwargs: pytest.fail("bulk archiveを呼び出しました"),
    )

    outcome = target._production_private_archive(daily_context)

    assert outcome.status == "complete"
    assert outcome.result["case_archive_count"] == 2
    assert outcome.result["ghidra_checkpoint_archived"] is False
    assert observed == [one_shot]
    assert {item["source_role"] for item in outcome.result["verified_targets"]} == {"analysis_case"}


def test_private_archive_routes_collection_when_ghidra_is_disabled(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    document = request_document()
    document["network"]["datastore_upload"] = True
    document["stages"]["news_intake"] = False
    document["stages"]["ghidra"] = False
    daily_context = context(tmp_path, document)
    daily_context.source_root.mkdir(parents=True)
    one_shot = daily_context.jobs_root / "job-fixture" / "analysis"
    one_shot.mkdir(parents=True)
    monkeypatch.setattr(
        target,
        "_static_request",
        lambda _context: (SimpleNamespace(job_id="job-fixture"), object()),
    )
    observed: list[Path] = []

    def archive_cases(
        _context: target.DailyContext,
        *,
        one_shot_root: Path,
    ) -> list[dict[str, object]]:
        observed.append(one_shot_root)
        return [{"source_role": "analysis_case", "target": "case-a"}]

    monkeypatch.setattr(target, "_archive_analysis_cases", archive_cases)
    monkeypatch.setattr(
        target,
        "_archive_one",
        lambda *_args, **_kwargs: pytest.fail("bulk archiveを呼び出しました"),
    )

    outcome = target._production_private_archive(daily_context)

    assert outcome.status == "complete"
    assert outcome.result["case_archive_count"] == 1
    assert outcome.result["ghidra_checkpoint_archived"] is False
    assert observed == [one_shot]


def test_archive_analysis_cases_stages_and_cleans_one_case_at_a_time(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import stage_case_analysis_datastore

    daily_context = context(tmp_path)
    cases = [f"{index:064x}" for index in range(1, 51)]
    monkeypatch.setattr(
        target,
        "_load_acquisition_manifest",
        lambda _context: {"selected_hashes": list(reversed(cases))},
    )
    staged_calls: list[tuple[str, ...]] = []
    archived_calls: list[tuple[str, Path, str]] = []
    cleanup_calls: list[str] = []

    def stage_cases(**kwargs: object) -> dict[str, object]:
        selected = tuple(kwargs["case_sha256s"])
        staged_calls.append(selected)
        digest = selected[0]
        archive_target = f"{daily_context.collection_id}-{digest}"
        source = daily_context.state_root / "case-datastore-staging" / archive_target
        return {
            "case_count": 1,
            "cases": [
                {
                    "case_sha256": digest,
                    "target": archive_target,
                    "source_path": str(source),
                }
            ],
        }

    def archive_one(
        _context: target.DailyContext,
        *,
        role: str,
        source: Path,
        target: str,
        expected_source: object = None,
    ) -> dict[str, object]:
        assert expected_source is not None
        archived_calls.append((role, source, target))
        return {
            "source_role": role,
            "target": target,
            "status": "verified",
            "archive_sha256": "a" * 64,
            "manifest_sha256": "b" * 64,
        }

    def cleanup(**kwargs: object) -> dict[str, object]:
        cleanup_calls.append(str(kwargs["case_sha256"]))
        return {"removed": True}

    monkeypatch.setattr(stage_case_analysis_datastore, "stage_cases", stage_cases)
    monkeypatch.setattr(
        stage_case_analysis_datastore,
        "remove_case_staging_after_verified_archive",
        cleanup,
    )
    monkeypatch.setattr(target, "_archive_one", archive_one)

    archived = target._archive_analysis_cases(
        daily_context,
        one_shot_root=tmp_path / "one-shot-analysis",
    )

    assert staged_calls == [(digest,) for digest in sorted(cases)]
    assert len(archived_calls) == 50
    assert all(role == "analysis_case" for role, _source, _target in archived_calls)
    assert cleanup_calls == sorted(cases)
    assert len(archived) == 50
    assert all(item["case_separated"] is True for item in archived)
    assert all(item["owned_staging_removed"] is True for item in archived)


def test_archive_analysis_cases_stops_at_failing_case(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import stage_case_analysis_datastore

    daily_context = context(tmp_path)
    cases = [f"{index:064x}" for index in range(1, 51)]
    ordered = sorted(cases)
    monkeypatch.setattr(
        target,
        "_load_acquisition_manifest",
        lambda _context: {"selected_hashes": cases},
    )
    staged_calls: list[str] = []
    archived_calls: list[str] = []

    def stage_cases(**kwargs: object) -> dict[str, object]:
        digest = list(kwargs["case_sha256s"])[0]
        staged_calls.append(digest)
        if digest == ordered[2]:
            raise stage_case_analysis_datastore.CaseStagingError("fixture failure")
        archive_target = f"{daily_context.collection_id}-{digest}"
        return {
            "case_count": 1,
            "cases": [
                {
                    "case_sha256": digest,
                    "target": archive_target,
                    "source_path": str(daily_context.state_root / "case-datastore-staging" / archive_target),
                }
            ],
        }

    def archive_one(
        _context: target.DailyContext,
        *,
        role: str,
        source: Path,
        target: str,
        expected_source: object = None,
    ) -> dict[str, object]:
        assert expected_source is not None
        del role, source
        archived_calls.append(target)
        return {
            "target": target,
            "status": "verified",
            "archive_sha256": "a" * 64,
            "manifest_sha256": "b" * 64,
        }

    monkeypatch.setattr(stage_case_analysis_datastore, "stage_cases", stage_cases)
    monkeypatch.setattr(
        stage_case_analysis_datastore,
        "remove_case_staging_after_verified_archive",
        lambda **_kwargs: {"removed": True},
    )
    monkeypatch.setattr(target, "_archive_one", archive_one)

    with pytest.raises(target.DailyOrchestrationError) as captured:
        target._archive_analysis_cases(
            daily_context,
            one_shot_root=tmp_path / "one-shot-analysis",
        )

    assert captured.value.code == "case_archive_staging_failed"
    assert staged_calls == ordered[:3]
    assert len(archived_calls) == 2


def test_archive_analysis_cases_reuses_retained_staging_after_upload_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """一時upload失敗後は保持stagingを再検証経路で再利用して完走する。"""

    import stage_case_analysis_datastore

    daily_context = context(tmp_path)
    short_state = tmp_path.parent / ("s-" + hashlib.sha256(str(tmp_path).encode("utf-8")).hexdigest()[:8])
    short_state.mkdir()
    daily_context = replace(daily_context, state_root=short_state)
    cases = [f"{index:064x}" for index in range(1, 51)]
    ordered = sorted(cases)
    first = ordered[0]
    monkeypatch.setattr(
        target,
        "_load_acquisition_manifest",
        lambda _context: {"selected_hashes": cases},
    )
    stage_calls: list[str] = []
    reuse_calls: list[str] = []
    fail_first_upload = True

    def handoff(digest: str) -> dict[str, object]:
        archive_target = f"{daily_context.collection_id}-{digest}"
        source = daily_context.state_root / "case-datastore-staging" / archive_target
        return {
            "case_count": 1,
            "cases": [
                {
                    "case_sha256": digest,
                    "target": archive_target,
                    "source_path": str(source),
                }
            ],
        }

    def stage_cases(**kwargs: object) -> dict[str, object]:
        digest = list(kwargs["case_sha256s"])[0]
        stage_calls.append(digest)
        source = Path(handoff(digest)["cases"][0]["source_path"])
        source.mkdir(parents=True)
        (source / "inventory.bin").write_bytes(b"trusted")
        return handoff(digest)

    def reuse_case_staging(**kwargs: object) -> dict[str, object]:
        digest = str(kwargs["case_sha256"])
        reuse_calls.append(digest)
        source = Path(handoff(digest)["cases"][0]["source_path"])
        assert (source / "inventory.bin").read_bytes() == b"trusted"
        return handoff(digest)

    def archive_one(
        _context: target.DailyContext,
        *,
        role: str,
        source: Path,
        target: str,
        expected_source: object = None,
    ) -> dict[str, object]:
        nonlocal fail_first_upload
        assert expected_source is not None
        del role
        if target.endswith(first) and fail_first_upload:
            fail_first_upload = False
            raise target_module_error(
                "fixture_upload_failed",
                "一時upload失敗",
            )
        return {
            "target": target,
            "status": "verified",
            "archive_sha256": "a" * 64,
            "manifest_sha256": "b" * 64,
            "source_path": str(source),
        }

    def cleanup(**kwargs: object) -> dict[str, object]:
        shutil.rmtree(Path(kwargs["source_path"]))
        return {"removed": True}

    target_module_error = target.DailyOrchestrationError
    monkeypatch.setattr(stage_case_analysis_datastore, "stage_cases", stage_cases)
    monkeypatch.setattr(
        stage_case_analysis_datastore,
        "reuse_case_staging",
        reuse_case_staging,
    )
    monkeypatch.setattr(
        stage_case_analysis_datastore,
        "remove_case_staging_after_verified_archive",
        cleanup,
    )
    monkeypatch.setattr(target, "_archive_one", archive_one)

    with pytest.raises(target.DailyOrchestrationError) as captured:
        target._archive_analysis_cases(
            daily_context,
            one_shot_root=tmp_path / "one-shot-analysis",
        )
    assert captured.value.code == "fixture_upload_failed"
    retained = daily_context.state_root / "case-datastore-staging" / f"{daily_context.collection_id}-{first}"
    assert retained.is_dir()

    archived = target._archive_analysis_cases(
        daily_context,
        one_shot_root=tmp_path / "one-shot-analysis",
    )

    assert reuse_calls == [first]
    assert stage_calls.count(first) == 1
    assert sorted(stage_calls) == ordered
    assert len(archived) == 50
    assert not retained.exists()


def test_archive_analysis_cases_rejects_tampered_retained_staging(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """upload失敗後の保持stagingが変化した場合は再開をfail-closedにする。"""

    import stage_case_analysis_datastore

    daily_context = context(tmp_path)
    short_state = tmp_path.parent / ("s-" + hashlib.sha256(str(tmp_path).encode("utf-8")).hexdigest()[:8])
    short_state.mkdir()
    daily_context = replace(daily_context, state_root=short_state)
    cases = [f"{index:064x}" for index in range(1, 51)]
    first = sorted(cases)[0]
    monkeypatch.setattr(
        target,
        "_load_acquisition_manifest",
        lambda _context: {"selected_hashes": cases},
    )
    archive_target = f"{daily_context.collection_id}-{first}"
    source = daily_context.state_root / "case-datastore-staging" / archive_target

    def stage_cases(**_kwargs: object) -> dict[str, object]:
        source.mkdir(parents=True)
        (source / "inventory.bin").write_bytes(b"trusted")
        return {
            "case_count": 1,
            "cases": [
                {
                    "case_sha256": first,
                    "target": archive_target,
                    "source_path": str(source),
                }
            ],
        }

    def reject_tampered(**_kwargs: object) -> dict[str, object]:
        if (source / "inventory.bin").read_bytes() != b"trusted":
            raise stage_case_analysis_datastore.CaseStagingError("既存case staging inventoryのSHA-256が一致しません")
        pytest.fail("tamperが存在しません")

    upload_attempt = 0

    def archive_one(*_args: object, **_kwargs: object) -> dict[str, object]:
        nonlocal upload_attempt
        upload_attempt += 1
        raise target.DailyOrchestrationError(
            "fixture_upload_failed",
            "一時upload失敗",
        )

    monkeypatch.setattr(stage_case_analysis_datastore, "stage_cases", stage_cases)
    monkeypatch.setattr(
        stage_case_analysis_datastore,
        "reuse_case_staging",
        reject_tampered,
    )
    monkeypatch.setattr(target, "_archive_one", archive_one)

    with pytest.raises(target.DailyOrchestrationError):
        target._archive_analysis_cases(
            daily_context,
            one_shot_root=tmp_path / "one-shot-analysis",
        )
    (source / "inventory.bin").write_bytes(b"tampered")

    with pytest.raises(target.DailyOrchestrationError) as captured:
        target._archive_analysis_cases(
            daily_context,
            one_shot_root=tmp_path / "one-shot-analysis",
        )

    assert captured.value.code == "case_archive_staging_failed"
    assert upload_attempt == 1
    assert source.is_dir()


def test_source_commitment_matches_news_consumer_for_nested_layout(tmp_path: Path) -> None:
    memo = tmp_path / "tech-memo"
    news = memo / "daily-news" / "news" / "nested" / "quarter"
    iocs = memo / "daily-news" / "iocs" / "nested" / "quarter"
    news.mkdir(parents=True)
    iocs.mkdir(parents=True)
    (news / "20260829.md").write_text("news\n", encoding="utf-8")
    (iocs / "20260829.csv").write_text("ioc_type,ioc_value\n", encoding="utf-8")
    (iocs / "20260829.md").write_text("log\n", encoding="utf-8")

    verified = target.verify_news_source_date(memo, "2026-08-29")
    source = news_intake.select_source(memo, "2026-08-29")
    commitment, _csv = news_intake._daily_source_snapshot(source, memo)
    assert commitment == verified["source_manifest_sha256"]

    duplicate = memo / "daily-news" / "news" / "duplicate" / "20260829.md"
    duplicate.parent.mkdir(parents=True)
    duplicate.write_text("duplicate\n", encoding="utf-8")
    with pytest.raises(target.DailyOrchestrationError, match="一意に存在"):
        target.verify_news_source_date(memo, "2026-08-29")
    with pytest.raises(RuntimeError, match="複数存在"):
        news_intake.select_source(memo, "2026-08-29")


def test_news_adapter_converts_system_exit_to_checkpointable_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    daily_context = context(tmp_path)
    monkeypatch.setattr(
        news_intake,
        "main",
        lambda _arguments: (_ for _ in ()).throw(SystemExit(2)),
    )
    with pytest.raises(target.DailyOrchestrationError) as captured:
        target._production_news_intake(daily_context)
    assert captured.value.code == "news_intake_failed"


def test_news_source_change_does_not_promote_staged_public_results(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    daily_context = context(tmp_path)

    def mutate_source(arguments: list[str]) -> int:
        public_base = Path(arguments[arguments.index("--public-output") + 1])
        staging = public_base / daily_context.request.news_source_date
        staging.mkdir(parents=True)
        for name in target.NEWS_PUBLIC_FILES:
            (staging / name).write_text("staged\n", encoding="utf-8")
        source = next((daily_context.intelligence_root / "tech-memo").rglob("20260829.md"))
        source.write_text("changed\n", encoding="utf-8")
        return 0

    monkeypatch.setattr(news_intake, "main", mutate_source)
    with pytest.raises(target.DailyOrchestrationError, match="commitment"):
        target._production_news_intake(daily_context)
    final = (
        daily_context.repository
        / "analysis-results"
        / "research"
        / "daily-news-malware"
        / daily_context.request.news_source_date
    )
    assert not final.exists()


def test_failed_stage_continues_only_to_authorized_private_checkpoint(
    tmp_path: Path,
) -> None:
    document = request_document()
    document["network"]["datastore_upload"] = True
    daily_context = context(tmp_path, document)

    def fail_news(_attempt: int) -> target.StageOutcome:
        raise target.DailyOrchestrationError("fixture_failure", "fixture")

    fake_actions, calls = actions(
        {
            "news_intake": fail_news,
            "private_archive": target.StageOutcome(
                "complete",
                {"status": "checkpointed"},
            ),
        }
    )
    state = target.run_daily(
        daily_context,
        actions=fake_actions,
        capacity_probe=ready_capacity,
    )
    assert state["status"] == "failed"
    assert calls["news_intake"] == 1
    assert calls["private_archive"] == 1
    assert all(calls[name] == 0 for name in target.STAGES if name not in {"news_intake", "private_archive"})


def test_datastore_target_is_deterministically_bounded() -> None:
    original = "a" * 64 + "-ghidra-checkpoint-" + "b" * 64
    bounded = target._bounded_datastore_target(original)
    assert len(bounded) <= target.MAX_DATASTORE_TARGET_LENGTH
    assert bounded == target._bounded_datastore_target(original)
    assert bounded != original


def test_acquisition_selection_binding_is_immutable(tmp_path: Path) -> None:
    daily_context = context(tmp_path)
    selected_hashes = [f"{index:064x}" for index in range(50)]
    first = {
        "selection_commitment_sha256": "a" * 64,
        "selected_hashes": selected_hashes,
    }
    target._bind_acquisition_selection(daily_context, first)
    target._bind_acquisition_selection(daily_context, first)
    with pytest.raises(target.DailyOrchestrationError) as captured:
        target._bind_acquisition_selection(
            daily_context,
            {
                "selection_commitment_sha256": "b" * 64,
                "selected_hashes": selected_hashes,
            },
        )
    assert captured.value.code == "acquisition_selection_changed"


def test_acquisition_stage_reports_full_selection_commitment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    daily_context = context(tmp_path)
    daily_context.source_root.mkdir(parents=True)
    (daily_context.source_root / "manifest.json").write_text(
        "{}\n",
        encoding="utf-8",
    )
    manifest = {
        "selection_commitment_sha256": "c" * 64,
        "selected_hashes": ["a" * 64],
        "downloaded": 1,
        "pending": 0,
    }
    monkeypatch.setattr(
        target,
        "_validate_acquisition_tree_layout",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        target,
        "_load_acquisition_manifest",
        lambda *_args, **_kwargs: manifest,
    )
    monkeypatch.setattr(
        target,
        "_bind_acquisition_selection",
        lambda *_args, **_kwargs: None,
    )
    import malwarebazaar_batch

    monkeypatch.setattr(
        malwarebazaar_batch,
        "write_verification_family_hints",
        lambda _path: {"schema_version": 1},
    )

    outcome = target._production_malwarebazaar_acquisition(daily_context)

    assert outcome.result["selection_commitment_sha256"] == manifest["selection_commitment_sha256"]


def test_fixed_python_uses_bounded_pipe_capture(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    daily_context = context(tmp_path)
    observed: dict[str, object] = {}

    def bounded(command, **options):
        observed["command"] = command
        observed.update(options)
        return SimpleNamespace(
            returncode=0,
            stdout=b"stdout\n",
            stderr=b"stderr\n",
            stdout_observed_bytes=7,
            stderr_observed_bytes=7,
        )

    monkeypatch.setattr(
        target.analysis_job_runner,
        "_run_process_with_bounded_output",
        bounded,
    )
    target._run_fixed_python(
        daily_context,
        stage="fixture",
        arguments=["fixed.py", "--safe"],
        timeout_seconds=10,
    )
    assert observed["shell"] is False
    assert observed["stdout"] == target.subprocess.PIPE
    assert observed["stderr"] == target.subprocess.PIPE
    logs = daily_context.state_root / "process-logs"
    assert (logs / "fixture.stdout.log").read_bytes() == b"stdout\n"
    assert (logs / "fixture.stderr.log").read_bytes() == b"stderr\n"


def test_news_public_staging_promotes_only_fixed_file_set(tmp_path: Path) -> None:
    daily_context = context(tmp_path)
    staging_base = daily_context.state_root / "news-public-staging"
    staging = staging_base / daily_context.request.news_source_date
    staging.mkdir(parents=True)
    for name in target.NEWS_PUBLIC_FILES:
        (staging / name).write_text(f"{name}\n", encoding="utf-8")
    result = target._promote_news_public_staging(daily_context, staging_base)
    final = (
        daily_context.repository
        / "analysis-results"
        / "research"
        / "daily-news-malware"
        / daily_context.request.news_source_date
    )
    assert result["file_count"] == len(target.NEWS_PUBLIC_FILES)
    assert result["staging_retained"] is True
    assert {path.name for path in final.iterdir()} == target.NEWS_PUBLIC_FILES


def test_archive_preflight_uses_largest_sequential_candidate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    daily_context = context(tmp_path)
    values = iter((100, 200, 300, 400))
    monkeypatch.setattr(
        target,
        "_archive_preflight_source_bytes",
        lambda *_args, **_kwargs: next(values),
    )
    required = target._projected_archive_staging_bytes(
        daily_context,
        tuple(target.STAGES),
    )
    assert required == target.PREFLIGHT_ARCHIVE_STAGING_BYTES + 400


def test_preflight_rejects_missing_download_credential_before_network(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    document = request_document()
    document["network"]["provider_lookups"] = True
    document["network"]["sample_download"] = True
    daily_context = context(tmp_path, document)
    monkeypatch.delenv("MALWAREBAZAAR_AUTH_KEY", raising=False)
    monkeypatch.delenv("VT_API_KEY", raising=False)
    monkeypatch.setattr(
        target,
        "build_capacity_preflight",
        lambda _context, _state=None: {
            "ready": True,
            "network_contacted": False,
            "filesystems": [],
            "required_recovery_bytes": 0,
        },
    )
    blocked = target.build_preflight_report(daily_context)
    assert blocked["ready"] is False
    assert blocked["authorization"]["provider_credential_ready"] is False
    assert blocked["authorization"]["sample_download_credential_ready"] is False

    monkeypatch.setenv("MALWAREBAZAAR_AUTH_KEY", "fixture-key")
    ready = target.build_preflight_report(daily_context)
    assert ready["ready"] is True
