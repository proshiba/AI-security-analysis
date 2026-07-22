"""適用可否判定から一括静的解析までの共通入口を検証する。"""

from __future__ import annotations

import json
from pathlib import Path
import sys

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
from handler_catalog import discover_handlers, sanitize_public_value  # noqa: E402


REGISTRY = FRAMEWORK_ROOT / "registry" / "malware_types.json"


def test_cli_help_is_japanese() -> None:
    """人が読む新CLIのhelp見出しと説明を日本語へ統一する。"""

    rendered = one_shot.build_parser().format_help()
    assert "使用法:" in rendered
    assert "オプション:" in rendered
    assert "このヘルプを表示して終了します" in rendered
    assert "show this help message" not in rendered


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
    assert coverage["efimer"]["status"] == "manual_or_unsupported_only"
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
    assert not (output / "cases" / case["sha256"] / "scripts").exists()


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

    def fake_unpack(data: bytes, source_name: str):
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
    assert [item["status"] for item in handler["attempts"]] == ["failed", "succeeded"]
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
