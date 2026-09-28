"""公開保留は私有検証を弱めず、未完了checkpointだけを残すことを確認する。"""

import hashlib
import json
from types import SimpleNamespace

import pytest

import ghidra_function_batch as target


@pytest.fixture
def prepared_run(monkeypatch, tmp_path):
    """実検体もMCPも使わず、合成metadataだけのbatchを構築する。"""
    digest = "a" * 64
    repository = tmp_path / "repository"
    collection = repository / "analysis-results" / "collections" / "synthetic"
    sample_root = tmp_path / "samples"
    private_output = tmp_path / "private"
    collection.mkdir(parents=True)
    sample_root.mkdir()
    private_output.mkdir()
    item = target.ProgramObject(sha256=digest, input_path=sample_root / (digest + ".quarantine.bin"), size=1)
    inventory = {"schema_version": target.SCHEMA_VERSION, "collection_id": "synthetic",
                 "relationships": [{"case_sha256": digest, "layer_sha256": digest, "is_pe": True, "size": 1}],
                 "unique_pe_objects": 1, "static_tools": {}, "sample_executed": False,
                 "network_contacted": False}
    inventory_path = private_output / "input-relationships.json"
    target._json_dump(inventory_path, inventory)
    inventory_sha = hashlib.sha256(inventory_path.read_bytes()).hexdigest()
    cache = {"status": "complete", "mcp_responses_valid": True, "sha256": digest, "functions": []}
    target.ensure_characteristic_selection(cache)
    cache_path = private_output / "objects" / digest / "program-result.json"
    target._json_dump(cache_path, cache)
    events = []
    monkeypatch.delenv("GHIDRA_MCP_ALLOW_SCRIPTS", raising=False)
    monkeypatch.setattr(target, "prepare_inputs", lambda *a, **kw: ({digest: item}, {}))
    monkeypatch.setattr(target, "load_prepared_inputs", lambda *a, **kw: ({digest: item}, {}))
    monkeypatch.setattr(target, "validate_prepared_scope", lambda *a, **kw: events.append("prepared_scope"))
    monkeypatch.setattr(target, "GhidraMcpClient", lambda *a, **kw: object())
    monkeypatch.setattr(target, "_storage_budget_observation", lambda *a, **kw: {
        "phase": kw["phase"], "minimum_free_bytes": kw["minimum_free_bytes"], "sufficient": True, "filesystems": []})
    monkeypatch.setattr(target, "_analyze_with_inventory_refresh", lambda *a, **kw: pytest.fail("完了cacheを再解析しない"))

    def refresh(client, results, private):
        events.append("private_refresh")
        return {"programs": len(results)}

    def private_validation(results, private, **kwargs):
        events.append("private_validation")
        assert kwargs["expected_program_count"] == 1
        assert len(results) == 1
        assert results[digest]["mcp_responses_valid"] is True
        return {"complete": True, "valid_programs": 1, "invalid_programs": [], "totals": {}}

    monkeypatch.setattr(target, "refresh_complete_program_artifacts", refresh)
    monkeypatch.setattr(target, "augment_private_call_graphs", lambda *a, **kw: {})
    monkeypatch.setattr(target, "validate_private_artifacts", private_validation)
    monkeypatch.setattr(target, "publish_cases", lambda *a, **kw: events.append("publish_cases") or {})
    monkeypatch.setattr(target, "validate_collection", lambda *a, **kw: events.append("validate_collection") or {
        "complete": True, "valid_cases": 1, "invalid_cases": []})
    monkeypatch.setattr(target, "finalize_collection_publication", lambda *a, **kw: events.append("finalize_collection") or {})
    args = target.build_parser().parse_args([
        "--repository", str(repository), "--collection", str(collection), "--sample-root", str(sample_root),
        "--private-output", str(private_output), "--defer-publication"])
    return SimpleNamespace(args=args, digest=digest, private=private_output, collection=collection, cache=cache,
                           cache_path=cache_path, inventory_path=inventory_path, inventory_sha=inventory_sha, events=events)


def checkpoint(case, stop_reason="postprocessing_in_progress"):
    """厳格な既存schemaで後処理checkpointを作る。"""
    value = target._run_progress_document(
        collection_id="synthetic", status="ghidra_chunk_pending", stop_reason=stop_reason, retryable=True,
        inventory_prepared=True, prepared_inventory_sha256=case.inventory_sha, unique_pe_programs=1,
        complete_programs=1, cached_programs=1, newly_analyzed_programs=0, pending_programs=[],
        postprocessing_pending=True, prepared_inputs_reused=True, resume_mode="postprocessing_only", disk_space={})
    target._write_run_progress(case.private, value)
    return value


def assert_no_publication(case):
    """公開系3関数を呼ばず、公開directoryへ何も書かない。"""
    assert not {"publish_cases", "validate_collection", "finalize_collection"}.intersection(case.events)
    assert list(case.collection.iterdir()) == []


def test_all_programs_verified_but_deferred(prepared_run):
    """全program完了もcollection completeへ昇格させず私有checkpointだけを残す。"""
    case = prepared_run
    original = case.cache_path.read_bytes()
    result = target.run(case.args)
    assert result["status"] == "ghidra_chunk_pending"
    assert result["stop_reason"] == "publication_deferred"
    assert result["postprocessing_pending"] is True
    assert result["resume_mode"] == "postprocessing_only"
    assert result["complete_programs"] == result["cached_programs"] == result["unique_pe_programs"] == 1
    assert result["pending_programs"] == []
    assert result["retryable"] is True
    assert case.cache_path.read_bytes() == original
    assert case.events == ["prepared_scope", "private_refresh", "private_validation"]
    assert not (case.private / "run-summary.json").exists()
    assert_no_publication(case)
    assert target._load_resume_checkpoint(case.private, collection_id="synthetic") == result


def test_new_program_finishes_privately_without_publication(prepared_run, monkeypatch):
    """新規program解析をmockで終えても公開は保留し、次回は認証済みcacheを使う。"""
    case = prepared_run
    case.cache_path.unlink()

    def analyze(*args, **kwargs):
        case.events.append("analyze_program")
        target._json_dump(case.cache_path, case.cache)
        return dict(case.cache)

    monkeypatch.setattr(target, "_analyze_with_inventory_refresh", analyze)
    result = target.run(case.args)
    assert result["stop_reason"] == "publication_deferred"
    assert result["newly_analyzed_programs"] == 1
    assert result["cached_programs"] == 0
    assert result["complete_programs"] == 1
    assert case.events == ["prepared_scope", "analyze_program", "private_refresh", "private_validation"]
    assert_no_publication(case)
    monkeypatch.setattr(target, "_analyze_with_inventory_refresh", lambda *a, **kw: pytest.fail("再開時はcacheを使う"))
    repeated = target.run(case.args)
    assert repeated["cached_programs"] == 1
    assert repeated["newly_analyzed_programs"] == 0
    assert repeated["stop_reason"] == "publication_deferred"
    assert_no_publication(case)


@pytest.mark.parametrize("prior_reason", ["postprocessing_in_progress", "minimum_free_space_not_met", "publication_deferred"])
def test_existing_postprocessing_resume_remains_deferred(prepared_run, monkeypatch, prior_reason):
    """既存／新checkpointから同じflagで再開しても公開へ進まない。"""
    case = prepared_run
    checkpoint(case, prior_reason)
    monkeypatch.setattr(target, "prepare_inputs", lambda *a, **kw: pytest.fail("inputを再準備しない"))
    first = target.run(case.args)
    assert first["stop_reason"] == "publication_deferred"
    assert first["prepared_inputs_reused"] is True
    assert first["cached_programs"] == 1
    second = target.run(case.args)
    assert second == first
    assert_no_publication(case)


@pytest.mark.parametrize("legacy_namespace", [False, True])
def test_flag_omitted_keeps_original_publication_path(prepared_run, legacy_namespace):
    """flag省略のCLIと旧namespace APIは従来の公開検証経路を保つ。"""
    case = prepared_run
    if legacy_namespace:
        del case.args.defer_publication
    else:
        case.args.defer_publication = False
    result = target.run(case.args)
    assert result["status"] == "complete"
    assert case.events == ["prepared_scope", "private_refresh", "private_validation", "publish_cases",
                           "validate_collection", "finalize_collection"]
    assert json.loads((case.private / "run-progress.json").read_text(encoding="utf-8"))["status"] == "complete"


def test_deferred_resume_without_flag_uses_existing_publication_path(prepared_run):
    """公開を別途許可してflagを省略すれば、元の全検証を通った後にだけ公開へ進む。"""
    case = prepared_run
    checkpoint(case, "publication_deferred")
    case.args.defer_publication = False
    result = target.run(case.args)
    assert result["status"] == "complete"
    assert "private_validation" in case.events
    assert case.events[-3:] == ["publish_cases", "validate_collection", "finalize_collection"]


def test_missing_cache_keeps_fresh_program_pending(prepared_run):
    """cacheがないprogramは全件完了とせず、既存chunk pendingへ残す。"""
    case = prepared_run
    case.cache_path.unlink()
    case.args.max_new_programs = 0
    result = target.run(case.args)
    assert result["status"] == "ghidra_chunk_pending"
    assert result["stop_reason"] == "max_new_programs_reached"
    assert result["complete_programs"] == 0
    assert result["pending_programs"] == [case.digest]
    assert result["postprocessing_pending"] is False
    assert_no_publication(case)


def test_missing_cache_does_not_bypass_strict_postprocessing_resume(prepared_run):
    """後処理checkpointのcache欠落は既存どおり拒否し、pending原本を完了にしない。"""
    case = prepared_run
    prior = checkpoint(case, "publication_deferred")
    case.cache_path.unlink()
    progress_raw = (case.private / "run-progress.json").read_bytes()
    with pytest.raises(ValueError, match="検証不能なprogram cache"):
        target.run(case.args)
    assert (case.private / "run-progress.json").read_bytes() == progress_raw
    assert prior["status"] == "ghidra_chunk_pending"
    assert_no_publication(case)


@pytest.mark.parametrize("phase", ["before_input_preparation", "before_postprocessing"])
def test_low_capacity_still_precedes_publication_deferred(prepared_run, monkeypatch, phase):
    """空き不足はflagとは独立に優先し、公開保留理由で隠さない。"""
    case = prepared_run
    monkeypatch.setattr(target, "_storage_budget_observation", lambda *a, **kw: {
        "phase": kw["phase"], "minimum_free_bytes": kw["minimum_free_bytes"],
        "sufficient": kw["phase"] != phase, "filesystems": []})
    result = target.run(case.args)
    assert result["stop_reason"] == "minimum_free_space_not_met"
    assert result["status"] == "ghidra_chunk_pending"
    assert "private_refresh" not in case.events
    assert_no_publication(case)


def test_incomplete_private_artifacts_are_not_deferred_as_verified(prepared_run, monkeypatch):
    """欠落artifactは既存どおり拒否し、公開保留を検証免除に使わない。"""
    case = prepared_run
    monkeypatch.setattr(target, "validate_private_artifacts", lambda *a, **kw: {
        "complete": False, "invalid_programs": [case.digest]})
    with pytest.raises(RuntimeError, match="生の静的解析成果物に欠落"):
        target.run(case.args)
    result = json.loads((case.private / "run-progress.json").read_text(encoding="utf-8"))
    assert result["stop_reason"] == "postprocessing_in_progress"
    assert result["status"] == "ghidra_chunk_pending"
    assert_no_publication(case)


def test_partial_refresh_remains_program_pending(prepared_run, monkeypatch):
    """更新中に見つかったpartialをflagで検証済み扱いへ変えない。"""
    case = prepared_run

    def partial(client, results, private):
        results[case.digest]["status"] = "partial"
        return {"programs": 1}

    monkeypatch.setattr(target, "refresh_complete_program_artifacts", partial)
    result = target.run(case.args)
    assert result["stop_reason"] == "program_analysis_incomplete"
    assert result["retryable"] is False
    assert result["postprocessing_pending"] is False
    assert result["complete_programs"] == 0
    assert result["pending_programs"] == [case.digest]
    assert_no_publication(case)


def test_resume_inventory_hash_authentication_remains_required(prepared_run):
    """公開保留でもinventory hash差替えを拒否する。"""
    case = prepared_run
    checkpoint(case, "publication_deferred")
    changed = json.loads(case.inventory_path.read_text(encoding="utf-8"))
    changed["unauthorized_mutation"] = True
    target._json_dump(case.inventory_path, changed)
    with pytest.raises(ValueError):
        target.run(case.args)
    assert_no_publication(case)


@pytest.mark.parametrize("field,value", [("postprocessing_pending", False), ("complete_programs", 0),
                                         ("resume_mode", "prepared_inputs"), ("retryable", False)])
def test_publication_deferred_progress_rejects_malformed_state(prepared_run, field, value):
    """新停止理由を未完了programや不正な後処理状態へ付与できない。"""
    case = prepared_run
    args = dict(collection_id="synthetic", status="ghidra_chunk_pending", stop_reason="publication_deferred",
                retryable=True, inventory_prepared=True, prepared_inventory_sha256=case.inventory_sha,
                unique_pe_programs=1, complete_programs=1, cached_programs=1, newly_analyzed_programs=0,
                pending_programs=[], postprocessing_pending=True, prepared_inputs_reused=True,
                resume_mode="postprocessing_only", disk_space={})
    args[field] = value
    with pytest.raises(ValueError):
        target._run_progress_document(**args)


def test_defer_flag_does_not_allow_non_boolean_api_value(prepared_run):
    """非booleanをtruthyとして受け取らず、API境界で拒否する。"""
    prepared_run.args.defer_publication = "false"
    with pytest.raises(ValueError, match="defer_publicationはboolean"):
        target.run(prepared_run.args)
    assert prepared_run.events == []


def test_defer_does_not_allow_arbitrary_ghidra_scripts(prepared_run, monkeypatch):
    """私有保留flagでも既存の任意script禁止は維持する。"""
    monkeypatch.setenv("GHIDRA_MCP_ALLOW_SCRIPTS", "true")
    with pytest.raises(RuntimeError, match="任意Ghidra script実行"):
        target.run(prepared_run.args)
    assert prepared_run.events == []


def test_cli_keeps_retryable_incomplete_exit_code(prepared_run, capsys):
    """公開保留は正常完了のexit 0ではなく、既存の未完了exit 20を返す。"""
    case = prepared_run
    exit_code = target.main([
        "--repository", str(case.args.repository), "--collection", str(case.args.collection),
        "--sample-root", str(case.args.sample_root), "--private-output", str(case.private),
        "--defer-publication"])
    assert exit_code == target.RETRYABLE_INCOMPLETE_EXIT_CODE == 20
    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "ghidra_chunk_pending"
    assert result["stop_reason"] == "publication_deferred"
    assert_no_publication(case)
