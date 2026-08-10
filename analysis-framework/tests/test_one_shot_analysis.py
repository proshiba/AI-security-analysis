"""適用可否判定から一括静的解析までの共通入口を検証する。"""

from __future__ import annotations

import json
from pathlib import Path
import sys

import pytest
import pyzipper


FRAMEWORK_ROOT = Path(__file__).resolve().parents[1]
COMMON_ROOT = FRAMEWORK_ROOT / "common"
CLASSIFIERS_ROOT = FRAMEWORK_ROOT / "classifiers"
REPOSITORY_ROOT = FRAMEWORK_ROOT.parent
for trusted in (REPOSITORY_ROOT, FRAMEWORK_ROOT, COMMON_ROOT, CLASSIFIERS_ROOT):
    value = str(trusted)
    if value not in sys.path:
        sys.path.insert(0, value)

import analyze_sample as one_shot  # noqa: E402
import classify_sample  # noqa: E402
from analysis_contract import handler_result_quality  # noqa: E402
from handler_catalog import (  # noqa: E402
    _strict_guard_formats,
    catalog_summary,
    discover_handlers,
    load_handler,
    sanitize_public_value,
)


REGISTRY = FRAMEWORK_ROOT / "registry" / "malware_types.json"


def test_cli_help_is_japanese() -> None:
    """人が読む新CLIのhelp見出しと説明を日本語へ統一する。"""

    rendered = one_shot.build_parser().format_help()
    assert "使用法:" in rendered
    assert "オプション:" in rendered
    assert "このヘルプを表示して終了します" in rendered
    assert "show this help message" not in rendered


def test_cli_string_scan_limit_is_positive_and_defaults_compatibly() -> None:
    """文字列走査上限の既定値を維持し、CLIでは正の整数だけを受け入れる。"""

    parser = one_shot.build_parser()
    required = ["--input", "sample.bin", "--output", "out"]
    default_args = parser.parse_args(required)
    explicit_args = parser.parse_args([*required, "--string-scan-limit", "100000"])

    assert one_shot.DEFAULT_STRING_SCAN_LIMIT == 1_000_000
    assert default_args.string_scan_limit == one_shot.DEFAULT_STRING_SCAN_LIMIT
    assert explicit_args.string_scan_limit == 100_000
    with pytest.raises(SystemExit):
        parser.parse_args([*required, "--string-scan-limit", "0"])


def test_catalog_covers_legacy_scripts_and_marks_nonstandard_interfaces() -> None:
    """既存解析関数を広く棚卸しし、特殊引数を自動実行しない。"""

    specs = discover_handlers()
    assert len(specs) >= 100
    assert len({item.family for item in specs}) >= 75
    assert any(
        item.family == "agenttesla" and item.automatic and item.callable_name == "extract"
        for item in specs
    )
    suomi = [
        item
        for item in specs
        if item.family == "suomi_agent" and item.relative_path.endswith("extract_config.py")
    ]
    assert suomi and suomi[0].automatic
    assert suomi[0].invocation == "bytes_pe_timestamp"
    assert any(
        item.family == "valleyrat"
        and item.campaign == "single_pe"
        and item.invocation == "bytes_expected_sha256"
        and item.supported_interface
        for item in specs
    )
    assert any(
        item.family == "tor_openssh_backdoor" and not item.supported_interface
        for item in specs
    )
    assert any(
        item.family == "efimer"
        and item.callable_name == "extract_directory"
        and not item.supported_interface
        and "encrypted_dir" in item.reason
        for item in specs
    )


def test_dynamic_handler_loader_supports_dataclasses() -> None:
    """dataclassを持つ許可済み解析器もプリフライトで読み込める。"""

    spec = next(item for item in discover_handlers() if item.family == "acrstealer")
    handler, invocation = load_handler(spec)
    assert callable(handler)
    assert invocation == "bytes_name"


def test_registered_detector_paths_are_all_allowlisted() -> None:
    """全レジストリ項目がfamily直下のdetect.pyへ解決できる。"""

    registry = json.loads(REGISTRY.read_text(encoding="utf-8-sig"))["malware_types"]
    for family, metadata in registry.items():
        detector = classify_sample.load_detector(
            FRAMEWORK_ROOT,
            metadata["detector"],
            family,
        )
        assert callable(detector), family


def test_family_coverage_exposes_automatic_and_manual_only_families() -> None:
    """登録済みファミリーの解析器未実装・手動限定状態を隠さない。"""

    registered = set(
        json.loads(REGISTRY.read_text(encoding="utf-8-sig"))["malware_types"]
    )
    coverage = {
        item["family"]: item
        for item in one_shot.summarize_family_coverage(
            discover_handlers(), registered
        )
    }
    assert set(registered) <= set(coverage)
    assert coverage["freepbx_k_php"]["status"] == "automatic_handler_available"
    assert coverage["efimer"]["status"] == "automatic_handler_available"
    assert coverage["efimer"]["automatic_handlers"]
    assert coverage["efimer"]["manual_or_unsupported_handlers"]


def test_freepbx_detector_requires_correlated_structure() -> None:
    """一般的なBash断片では一致せず、FreePBX侵害構造の相関で一致する。"""

    detector = classify_sample.load_detector(
        FRAMEWORK_ROOT,
        "malware/freepbx_k_php/detect.py",
        "freepbx_k_php",
    )
    assert not detector(b"#!/bin/bash\necho base64", Path("benign.sh"))["matched"]
    sample = (
        b"#!/bin/bash\nampusers /etc/asterisk crontab base64 '<?php' "
        b"https://example.invalid/hima_data/index.php"
    )
    result = detector(sample, Path("k.php"))
    assert result["matched"]
    assert result["campaigns"][0]["campaign_type"] == "freepbx_k_php_post_exploitation"


def test_public_sanitizer_removes_credentials_and_binary_content() -> None:
    """資格情報、メール、URL秘密部、復元バイナリを公開値へ残さない。"""

    raw = {
        "password": "secret-value",
        "contact": "operator@example.test",
        "url": "https://user:pass@example.test/gate?token=x#frag",
        "payload": b"MZpayload",
    }
    value = sanitize_public_value(raw)
    assert value["password"] == "[REDACTED]"
    assert value["contact"] == "[REDACTED_EMAIL]"
    assert value["url"] == "https://example.test/gate"
    assert value["payload"]["content_exported"] is False
    assert "MZpayload" not in json.dumps(value)


def test_forced_family_runs_only_automatic_handlers(tmp_path: Path) -> None:
    """明示ファミリーでは標準抽出器を実行し、特殊派生解析器を強制しない。"""

    sample = tmp_path / "sample.sh"
    sample.write_bytes(
        b"#!/bin/bash\nampusers /etc/asterisk crontab base64 '<?php' "
        b"https://example.invalid/hima_data/index.php"
    )
    output = tmp_path / "out"
    summary = one_shot.run_batch(
        [sample],
        output,
        registry=REGISTRY,
        forced_family="freepbx_k_php",
    )
    assert summary["counts"]["analyzed"] == 1
    assert summary["counts"]["handler_successes"] == 1
    case = summary["cases"][0]
    report = json.loads((output / case["report"]).read_text(encoding="utf-8"))
    assert report["classification"]["selected_family"] == "freepbx_k_php"
    assert report["executed_sample"] is False
    assert report["network_contacted"] is False
    generic = json.loads(
        (output / "cases" / case["sha256"] / "generic-triage.json").read_text(
            encoding="utf-8"
        )
    )
    assert generic["script"]["normalized_text"] is None
    case_dir = output / "cases" / case["sha256"]
    features = json.loads((case_dir / "features.json").read_text(encoding="utf-8"))
    labels = json.loads((case_dir / "campaign-labels.json").read_text(encoding="utf-8"))
    logic = json.loads((case_dir / "static-logic.json").read_text(encoding="utf-8"))
    assert features["sha256"] == case["sha256"]
    assert features["analysis_assessment"]["status"] in {
        "complete",
        "partial",
        "insufficient",
    }
    assert (case_dir / "FEATURES.md").read_text(encoding="utf-8").startswith(
        "# 挙動・検体特徴"
    )
    assert labels["status"] in {"matched", "no_strong_match"}
    assert labels["safety"]["network_contacted"] is False
    assert logic["status"] == "automated_script_structure"
    assert logic["coverage"]["function_count"] >= 1
    assert logic["safety"]["raw_pseudocode_exported"] is False
    assert (case_dir / "STATIC-LOGIC.md").is_file()
    assert not (case_dir / "scripts").exists()


def test_auto_unwraps_only_encrypted_single_member_zip(tmp_path: Path) -> None:
    """autoモードは暗号化単一メンバーだけをメモリ内展開する。"""

    archive = tmp_path / "sample.zip"
    with pyzipper.AESZipFile(
        archive,
        "w",
        compression=pyzipper.ZIP_DEFLATED,
        encryption=pyzipper.WZ_AES,
    ) as handle:
        handle.setpassword(b"infected")
        handle.writestr("inner.bin", b"one-shot-fixture")
    unit = one_shot.read_input_unit(
        archive,
        password="infected",
        archive_mode="auto",
        max_file_size=1024 * 1024,
    )
    assert unit.input_kind == "authenticated_single_member_zip"
    assert unit.source_name == "inner.bin"
    assert unit.data == b"one-shot-fixture"


def test_malwarebazaar_directory_ignores_acquisition_manifests(tmp_path: Path) -> None:
    """MalwareBazaar取得rootでは暗号化ZIPだけを検体入力にする。"""

    archive = tmp_path / "sample.zip"
    with pyzipper.AESZipFile(
        archive,
        "w",
        compression=pyzipper.ZIP_DEFLATED,
        encryption=pyzipper.WZ_AES,
    ) as handle:
        handle.setpassword(b"infected")
        handle.writestr("inner.bin", b"malwarebazaar-directory-fixture")
    (tmp_path / "manifest.json").write_text(
        '{"schema_version": 1}\n',
        encoding="utf-8",
    )
    summary = one_shot.run_batch(
        [tmp_path],
        tmp_path / "out",
        registry=REGISTRY,
        archive_mode="malwarebazaar",
        assessment_only=True,
    )
    assert summary["counts"]["input_files"] == 1
    assert summary["counts"]["analyzed"] == 1
    assert summary["counts"]["errors"] == 0


def test_recovered_layer_is_classified_and_selected_for_extraction(
    tmp_path: Path, monkeypatch
) -> None:
    """復元子層も分類し、証拠を抽出できた層の結果を採用する。"""

    wrapper = b"bounded-static-wrapper"
    recovered = (
        b"#!/bin/bash\nampusers /etc/asterisk crontab */3 base64 '<?php' "
        b"https://example.invalid/hima_data/index.php"
    )

    def fake_unpack(data: bytes, source_name: str, **_kwargs):
        if data == wrapper:
            return (
                {"source_name": source_name, "method": "test_static_decoder"},
                [("decoded_script", recovered)],
            )
        return ({"source_name": source_name, "method": "none"}, [])

    monkeypatch.setattr(one_shot, "unpack_bytes", fake_unpack)
    sample = tmp_path / "wrapper.bin"
    sample.write_bytes(wrapper)
    output = tmp_path / "out"
    summary = one_shot.run_batch([sample], output, registry=REGISTRY)

    assert summary["counts"]["analyzed"] == 1
    assert summary["counts"]["identified"] == 1
    assert summary["counts"]["handler_successes"] == 1
    case = summary["cases"][0]
    assert case["selected_family"] is None
    assert case["selected_families"] == ["freepbx_k_php"]
    case_dir = output / "cases" / case["sha256"]
    layer_report = json.loads((case_dir / "static-layers.json").read_text(encoding="utf-8"))
    assert layer_report["counts"]["recovered_layers"] == 1
    classification = json.loads(
        (case_dir / "classification.json").read_text(encoding="utf-8")
    )
    assert classification["selected_families"] == ["freepbx_k_php"]
    report = json.loads((case_dir / "report.json").read_text(encoding="utf-8"))
    execution = report["handler_executions"][0]
    handler = json.loads((case_dir / execution["result"]).read_text(encoding="utf-8"))
    assert handler["selected_layer"]["depth"] == 1
    assert handler["selected_layer"]["sha256"] == one_shot.sha256_bytes(recovered)
    assert [item["status"] for item in handler["attempts"]] == [
        "succeeded",
        "skipped_incompatible_format",
    ]
    assert handler["attempts"][0]["routing_role"] == "selected_family_layer"
    assert handler["executed_sample"] is False
    assert handler["network_contacted"] is False


def test_batch_deduplicates_and_isolates_input_errors(tmp_path: Path) -> None:
    """同一SHA-256を一度だけ解析し、壊れた外装の失敗を全体へ波及させない。"""

    first = tmp_path / "a.bin"
    second = tmp_path / "b.bin"
    first.write_bytes(b"duplicate-static-fixture")
    second.write_bytes(first.read_bytes())
    broken = tmp_path / "broken.zip"
    with pyzipper.AESZipFile(
        broken,
        "w",
        compression=pyzipper.ZIP_DEFLATED,
        encryption=pyzipper.WZ_AES,
    ) as handle:
        handle.setpassword(b"different-password")
        handle.writestr("inner.bin", b"unreadable-with-default-password")
    summary = one_shot.run_batch(
        [first, second, broken],
        tmp_path / "out",
        registry=REGISTRY,
        archive_mode="auto",
        assessment_only=True,
    )
    assert summary["counts"]["analyzed"] == 1
    assert summary["counts"]["duplicates"] == 1
    assert summary["counts"]["errors"] == 1
    assert summary["executed_sample"] is False
    assert summary["network_contacted"] is False


def test_resume_reuses_only_valid_completed_case(tmp_path: Path, monkeypatch) -> None:
    """再開時は安全に検証できた同一モードの完了caseだけを再利用する。"""

    sample = tmp_path / "resume.bin"
    sample.write_bytes(b"bounded-resume-fixture")
    output = tmp_path / "out"
    first = one_shot.run_batch(
        [sample],
        output,
        registry=REGISTRY,
        assessment_only=True,
    )
    assert first["counts"]["resumed"] == 0

    def fail_if_reanalyzed(*args, **kwargs):
        raise AssertionError("完了caseを再解析してはいけません")

    monkeypatch.setattr(one_shot, "analyze_unit", fail_if_reanalyzed)
    resumed = one_shot.run_batch(
        [sample],
        output,
        registry=REGISTRY,
        assessment_only=True,
        resume=True,
    )
    assert resumed["counts"]["analyzed"] == 1
    assert resumed["counts"]["resumed"] == 1
    assert resumed["cases"][0]["resumed"] is True


def test_generic_triage_failure_keeps_classification_and_handlers(
    tmp_path: Path, monkeypatch
) -> None:
    """汎用トリアージの例外をcase内へ隔離し、固有解析結果を保持する。"""

    def fail_generic(*args, **kwargs):
        raise KeyError("bounded test failure")

    monkeypatch.setattr(one_shot.analyze_family_sample, "analyze", fail_generic)
    sample = tmp_path / "sample.sh"
    sample.write_bytes(
        b"#!/bin/bash\nampusers /etc/asterisk crontab base64 '<?php' "
        b"https://example.invalid/hima_data/index.php"
    )
    output = tmp_path / "out"
    summary = one_shot.run_batch(
        [sample], output, registry=REGISTRY, forced_family="freepbx_k_php"
    )

    assert summary["counts"]["analyzed"] == 1
    assert summary["counts"]["analysis_stage_failures"] == 1
    assert summary["counts"]["handler_successes"] == 1
    case = summary["cases"][0]
    generic = json.loads(
        (output / "cases" / case["sha256"] / "generic-triage.json").read_text(
            encoding="utf-8"
        )
    )
    assert generic["status"] == "failed"
    assert generic["executed_sample"] is False
    assert generic["network_contacted"] is False


def test_catalog_exposes_input_contracts_for_automatic_handlers() -> None:
    """自動解析器へ形式契約を付け、厳格guardとadapter由来を区別する。"""

    specs = discover_handlers()
    freepbx = next(
        item
        for item in specs
        if item.family == "freepbx_k_php"
        and item.relative_path.endswith("freepbx_k_php/extract_config.py")
    )
    suomi = next(
        item
        for item in specs
        if item.family == "suomi_agent" and item.relative_path.endswith("extract_config.py")
    )
    profiled = next(item for item in specs if item.source == "profiled_shared_extractor")
    acrstealer = next(
        item
        for item in specs
        if item.family == "acrstealer" and item.relative_path.endswith("acrstealer/extractor.py")
    )
    amosstealer = next(
        item
        for item in specs
        if item.family == "amosstealer" and item.relative_path.endswith("amosstealer/extractor.py")
    )
    manageengine = next(
        item
        for item in specs
        if item.family == "manageengine_endpoint_central_abuse"
        and item.relative_path.endswith("manageengine_endpoint_central_abuse/extract_config.py")
    )
    assert freepbx.input_formats == ("script",)
    assert freepbx.input_contract_source == "strict_magic_guard"
    assert suomi.input_formats == ("pe",)
    assert profiled.input_formats == ("pe", "script", "data")
    assert all(item.minimum_evidence_score >= 0 for item in specs)
    assert {"zip", "pe", "ole"} <= set(acrstealer.input_formats)
    assert acrstealer.input_contract_source == "module_declaration"
    assert "apple-disk-image" in amosstealer.input_formats
    assert amosstealer.input_contract_source == "bounded_payload_adapter"
    assert manageengine.input_formats == ("zip", "script", "data")
    assert manageengine.input_contract_source == "module_declaration"
    summary = catalog_summary(specs)
    assert summary["legacy_unrestricted_automatic_count"] == 0
    assert summary["declared_contract_handler_count"] >= 9


def test_strict_guard_contract_is_fail_closed(tmp_path: Path) -> None:
    """magic guardが無条件かつ矛盾しない場合だけ入力形式を推定する。"""

    alternatives = tmp_path / "alternatives.py"
    alternatives.write_text(
        """def extract(data):
    if not data.startswith((b\"MZ\", b\"\\x7fELF\")):
        raise ValueError(\"形式不一致\")
    return {}
""",
        encoding="utf-8",
    )
    assert _strict_guard_formats(alternatives, "extract") == ("elf", "pe")

    conditional = tmp_path / "conditional.py"
    conditional.write_text(
        """def extract(data):
    if not data.startswith(b\"MZ\"):
        if len(data) < 2:
            raise ValueError(\"短すぎます\")
    return {}
""",
        encoding="utf-8",
    )
    assert _strict_guard_formats(conditional, "extract") == ()

    contradictory = tmp_path / "contradictory.py"
    contradictory.write_text(
        """def extract(data):
    if not data.startswith(b\"MZ\"):
        raise ValueError(\"PEではありません\")
    if not data.startswith(b\"\\x7fELF\"):
        raise ValueError(\"ELFではありません\")
    return {}
""",
        encoding="utf-8",
    )
    assert _strict_guard_formats(contradictory, "extract") == ()


def test_handler_quality_separates_family_label_from_evidence() -> None:
    """固定family名だけの空結果を成功証拠へ昇格しない。"""

    empty = handler_result_quality({"family": "fixture", "findings": []})
    candidate = handler_result_quality(
        {"findings": [{"kind": "url", "value": "https://example.org/gate"}]}
    )
    static = handler_result_quality(
        {"static_config_recovered": True, "config": {"host": "static.example.org"}}
    )
    decoded = handler_result_quality(
        {"decoded_config_recovered": True, "config": {"host": "decoded.example.org"}}
    )
    assert empty["tier_name"] == "no_evidence"
    assert empty["sufficient"] is False
    assert candidate["tier"] == 1
    assert static["tier"] == 3
    assert decoded["tier"] == 4
    assert decoded["score"] > static["score"] > candidate["score"]


def test_unmatched_forced_family_does_not_execute_handler(tmp_path: Path) -> None:
    """明示familyでも検出器不一致なら候補表示だけに留め、固有解析器を実行しない。"""

    sample = tmp_path / "benign.bin"
    sample.write_bytes(b"unrelated bounded fixture")
    output = tmp_path / "out"
    summary = one_shot.run_batch(
        [sample],
        output,
        registry=REGISTRY,
        forced_family="freepbx_k_php",
    )
    assert summary["counts"]["identified"] == 0
    assert summary["counts"]["handler_successes"] == 0
    case = summary["cases"][0]
    assert case["selected_families"] == []
    report = json.loads((output / case["report"]).read_text(encoding="utf-8"))
    assert report["classification"]["selection_basis"] == "explicit_family_detector_unmatched"
    assert report["handler_executions"] == []


def test_handler_never_runs_on_unrelated_sibling_layer(
    tmp_path: Path, monkeypatch
) -> None:
    """family一致子層と同階層の無関係データをhandlerへ渡さない。"""

    wrapper = b"routing-wrapper"
    matched = (
        b"#!/bin/bash\nampusers /etc/asterisk crontab */3 base64 '<?php' "
        b"https://example.invalid/hima_data/index.php"
    )
    sibling = b"unrelated sibling https://a.invalid https://b.invalid"

    def fake_unpack(data: bytes, source_name: str, **_kwargs):
        if data == wrapper:
            return (
                {"source_name": source_name, "method": "two_children"},
                [("matched_script", matched), ("unrelated_data", sibling)],
            )
        return ({"source_name": source_name, "method": "none"}, [])

    monkeypatch.setattr(one_shot, "unpack_bytes", fake_unpack)
    sample = tmp_path / "wrapper.bin"
    sample.write_bytes(wrapper)
    output = tmp_path / "out"
    summary = one_shot.run_batch([sample], output, registry=REGISTRY)
    report = json.loads((output / summary["cases"][0]["report"]).read_text(encoding="utf-8"))
    execution = next(item for item in report["handler_executions"] if item["status"] == "succeeded")
    handler = json.loads(
        (output / "cases" / summary["cases"][0]["sha256"] / execution["result"]).read_text(
            encoding="utf-8"
        )
    )
    sibling_attempt = next(
        item for item in handler["attempts"] if item["layer"]["sha256"] == one_shot.sha256_bytes(sibling)
    )
    assert sibling_attempt["routing_role"] == "unrelated_layer"
    assert sibling_attempt["status"] == "skipped_unrelated_layer"


def test_empty_handler_result_is_not_counted_as_success(
    tmp_path: Path, monkeypatch
) -> None:
    """例外なしの空dictをno_evidenceとして保持し、成功件数へ含めない。"""

    sample = tmp_path / "sample.sh"
    sample.write_bytes(
        b"#!/bin/bash\nampusers /etc/asterisk crontab base64 '<?php' "
        b"https://example.invalid/hima_data/index.php"
    )
    monkeypatch.setattr(
        one_shot,
        "execute_handler",
        lambda *_args, **_kwargs: {
            "result": {},
            "executed_sample": False,
            "network_contacted": False,
        },
    )
    output = tmp_path / "out"
    summary = one_shot.run_batch([sample], output, registry=REGISTRY)
    assert summary["counts"]["handler_successes"] == 0
    assert summary["counts"]["handler_no_evidence"] == 1
    assert summary["counts"]["partial"] == 1
    report = json.loads((output / summary["cases"][0]["report"]).read_text(encoding="utf-8"))
    assert report["handler_executions"][0]["status"] == "no_evidence"
    assert report["case_state"]["resumable"] is False


def test_resume_rejects_changed_routing_contract(tmp_path: Path, monkeypatch) -> None:
    """confidence閾値が変われば、同じ検体でも古いcaseを再利用しない。"""

    sample = tmp_path / "contract.bin"
    sample.write_bytes(b"resume contract fixture")
    output = tmp_path / "out"
    one_shot.run_batch([sample], output, registry=REGISTRY, assessment_only=True)
    original = one_shot.analyze_unit
    calls = []

    def counted(*args, **kwargs):
        calls.append(True)
        return original(*args, **kwargs)

    monkeypatch.setattr(one_shot, "analyze_unit", counted)
    rerun = one_shot.run_batch(
        [sample],
        output,
        registry=REGISTRY,
        assessment_only=True,
        minimum_confidence="high",
        resume=True,
    )
    assert calls == [True]
    assert rerun["counts"]["resumed"] == 0


def test_resume_rejects_changed_string_scan_contract(tmp_path: Path, monkeypatch) -> None:
    """文字列走査上限が変われば、完了caseを異なる契約として再解析する。"""

    sample = tmp_path / "string-contract.bin"
    sample.write_bytes(b"resume string scan contract fixture")
    output = tmp_path / "out-string-contract"
    monkeypatch.setattr(
        one_shot.classify_sample,
        "classify_bytes",
        lambda *_args, **_kwargs: {
            "schema_version": 1,
            "malware_type": "unknown",
            "malware_type_confidence": "low",
            "campaign_type": "unknown",
            "attribution_basis": "bounded_test",
            "observations": {},
            "campaign_candidates": [],
        },
    )
    first = one_shot.run_batch(
        [sample],
        output,
        registry=REGISTRY,
        assessment_only=True,
        string_scan_limit=100,
    )
    assert first["analysis_contract"]["settings"]["string_scan_limit"] == 100
    assert first["cases"][0]["case_state"] == "assessment_only_complete"
    original = one_shot.analyze_unit
    calls = []

    def counted(*args, **kwargs):
        calls.append(kwargs["string_scan_limit"])
        return original(*args, **kwargs)

    monkeypatch.setattr(one_shot, "analyze_unit", counted)
    rerun = one_shot.run_batch(
        [sample],
        output,
        registry=REGISTRY,
        assessment_only=True,
        string_scan_limit=101,
        resume=True,
    )
    assert calls == [101]
    assert rerun["counts"]["resumed"] == 0
    assert rerun["analysis_contract"]["settings"]["string_scan_limit"] == 101


def test_resume_rejects_modified_artifact(tmp_path: Path, monkeypatch) -> None:
    """成果物内容がreport記録hashと違う場合は完了caseを再解析する。"""

    sample = tmp_path / "tamper.bin"
    sample.write_bytes(b"resume artifact fixture")
    output = tmp_path / "out"
    first = one_shot.run_batch([sample], output, registry=REGISTRY, assessment_only=True)
    case_dir = output / "cases" / first["cases"][0]["sha256"]
    (case_dir / "classification.json").write_text("{}\n", encoding="utf-8")
    original = one_shot.analyze_unit
    calls = []

    def counted(*args, **kwargs):
        calls.append(True)
        return original(*args, **kwargs)

    monkeypatch.setattr(one_shot, "analyze_unit", counted)
    rerun = one_shot.run_batch(
        [sample], output, registry=REGISTRY, assessment_only=True, resume=True
    )
    assert calls == [True]
    assert rerun["counts"]["resumed"] == 0


@pytest.mark.parametrize(
    "value",
    [
        {"matched": "false", "observations": {}, "campaigns": []},
        {"matched": False, "observations": [], "campaigns": []},
        {"matched": True, "observations": {}, "campaigns": None},
        {
            "matched": True,
            "observations": {},
            "campaigns": [{"campaign_type": "x", "confidence": "certain"}],
        },
    ],
)
def test_detector_result_contract_rejects_malformed_values(value: dict) -> None:
    """truthy文字列や不正campaign shapeをfamily一致として受け入れない。"""

    with pytest.raises(TypeError):
        classify_sample.normalize_detection_result(value)


def test_generic_triage_rejects_invalid_ip_and_marks_parse_failure_partial(
    tmp_path: Path,
) -> None:
    """不正IPを候補から除外し、壊れたPEを汎用解析完了にしない。"""

    strings = [
        {
            "offset": 0,
            "encoding": "ascii",
            "value": "999.999.999.999 1.2.3.4:443 1.2.3.4:99999",
        }
    ]
    iocs = one_shot.analyze_family_sample.extract_iocs(strings)
    assert iocs["ips"] == ["1.2.3.4:443"]
    result = one_shot.analyze_family_sample.analyze(
        "broken.exe", b"MZ" + b"\0" * 32, tmp_path, persist_normalized_text=False
    )
    assert "pe_error" in result
    assert result["analysis_coverage"]["status"] == "partial"


def test_generic_string_limit_is_reported_as_partial(tmp_path: Path) -> None:
    """表示上限到達を黙って成功扱いせず、coverageへ残す。"""

    data = b"\0".join([b"ABCD"] * 20_002)
    result = one_shot.analyze_family_sample.analyze(
        "many.bin",
        data,
        tmp_path,
        persist_normalized_text=False,
        string_scan_limit=20_000,
    )
    assert result["string_scan"]["truncated"] is True
    assert result["analysis_coverage"]["status"] == "partial"


def test_one_shot_string_scan_limit_is_propagated_and_keeps_partial(tmp_path: Path) -> None:
    """低い上限を全経路へ渡し、打切りをtruncatedかつpartialとして保持する。"""

    sample = tmp_path / "bounded-strings.bin"
    sample.write_bytes(b"AAAA\0BBBB\0CCCC")
    output = tmp_path / "out-bounded-strings"
    summary = one_shot.run_batch(
        [sample],
        output,
        registry=REGISTRY,
        string_scan_limit=2,
    )

    case = summary["cases"][0]
    case_dir = output / "cases" / case["sha256"]
    generic = json.loads((case_dir / "generic-triage.json").read_text(encoding="utf-8"))
    report = json.loads((case_dir / "report.json").read_text(encoding="utf-8"))

    assert generic["string_scan"] == {"limit": 2, "returned": 2, "truncated": True}
    assert generic["analysis_coverage"]["status"] == "partial"
    assert summary["counts"]["analysis_stage_partial"] == 1
    assert summary["settings"]["string_scan_limit"] == 2
    assert report["analysis_contract"]["settings"]["string_scan_limit"] == 2