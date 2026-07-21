from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
BATCH = ROOT / "analysis-results/research/malwarebazaar/batches/batch-0017"


def load(relative: str, name: str):
    path = ROOT / relative
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_suomi_dga_exact_vector_detector_and_emulator_are_offline() -> None:
    extractor = load("analysis-framework/malware/suomi_agent/extract_config.py", "b17_suomi_extract")
    candidates = extractor.generate_candidates(1784505600)
    assert [(item["host"], item["port"], item["bucket"]) for item in candidates] == [
        ("nodemetrics.com", 9095, 10327), ("apibyte.net", 4811, 10326), ("authservice.lol", 6020, 10328),
    ]
    emulator = load("analysis-framework/malware/suomi_agent/emulator.py", "b17_suomi_emulator")
    assert emulator.emulate(1784505600)["candidates"] == candidates
    assert emulator.status()["network_enabled"] is False
    detector = load("analysis-framework/malware/suomi_agent/network_detector.py", "b17_suomi_network")
    report = detector.detect([
        {"host": "nodemetrics.com", "port": 9095, "process_name": "plugin-container.exe"},
        {"suomi_environment_marker": True},
    ], timestamp=1784505600)
    assert report["matched"] is True
    assert report["c2_confirmed"] is False


def test_png_loader_detector_model_and_role_separation() -> None:
    detector = load("analysis-framework/malware/png_registry_loader/network_detector.py", "b17_png_network")
    report = detector.detect([
        {"host": "gwup.hkg.bcebos.com", "path": "/03.png"},
        {"registry_key": r"HKCU\Software\PngCache", "registry_value": "1.png"},
        {"virtual_alloc": True, "virtual_protect_rx": True, "create_thread": True},
    ])
    assert report["matched"] is True
    assert report["c2_confirmed"] is False
    emulator = load("analysis-framework/malware/png_registry_loader/emulator.py", "b17_png_emulator")
    modeled = emulator.model(None, b"synthetic-stage")
    assert modeled["would_cache"] is True
    assert modeled["would_transition_rw_to_rx"] is True
    assert modeled["payload_executed"] is False


def test_catddos_frame_and_detector_do_not_execute_attack() -> None:
    emulator = load("analysis-framework/malware/catddos/emulator.py", "b17_cat_emulator")
    frame = emulator.encode_synthetic_frame(b"\x10synthetic")
    parsed = emulator.parse_synthetic_frame(frame)
    assert parsed["recognized_attack_id"] is True
    assert parsed["attack_executed"] is False
    detector = load("analysis-framework/malware/catddos/network_detector.py", "b17_cat_network")
    report = detector.detect([
        {"host": "lifeisabouthavingfun448.duckdns.org", "port": 35342, "framing": "uint16-be-body-length", "registration_fields_valid": True},
        {"host": "185.196.41.201", "port": 2222, "message": "hi im here, i think"},
    ])
    assert report["matched"] is True
    assert report["c2_confirmed"] is False


def test_blackhorse_and_nsis_models_are_non_operational() -> None:
    blackhorse = load("analysis-framework/malware/blackhorse_miner_agent/emulator.py", "b17_blackhorse")
    signed = blackhorse.sign_synthetic("lab-device", 1, b"body", b"lab-key")
    assert signed["network_enabled"] is False
    assert signed["real_embedded_key_used"] is False
    nsis = load("analysis-framework/malware/nsis_obfuscated_loader/emulator.py", "b17_nsis")
    modeled = nsis.model(list(nsis.EXPECTED))
    assert modeled["layout_matched"] is True
    assert modeled["files_executed"] is False
    analyzer = load("analysis-framework/malware/nsis_obfuscated_loader/script_analyzer.py", "b17_nsis_script")
    script = "Function .onMouseOverSection\n" + "\n".join(f' File "{name}"' for name in sorted(nsis.EXPECTED)) + "\nFunctionEnd\n"
    analyzed = analyzer.analyze(script)
    assert analyzed["mouse_over_trigger"] is True
    assert analyzed["script_executed"] is False


def test_windows_stager_helpers_and_reviewed_hashes() -> None:
    corb = load("analysis-framework/malware/windows_script_stager/corb_xor_stager.py", "b17_corb")
    assert corb.decode_js_string(r"a\x62\u0063\n") == "abc\n"
    unicode_stager = load("analysis-framework/malware/windows_script_stager/unicode_separator_stager.py", "b17_unicode")
    assert unicode_stager.REVIEWED_SHA256.startswith("2624abf7")
    detector = load("analysis-framework/malware/windows_script_stager/detect.py", "b17_script_detect")
    assert "2624abf75eb9ebb06126954d914beaac6ea34f55f8307d6099f9f07efad27a13" in detector.REVIEWED
    assert "8aab978be727a120faf9ab28932c621808c141c6c4100651d7aecce70870a91d" in detector.REVIEWED


def test_batch17_yara_rules_compile() -> None:
    yara = pytest.importorskip("yara")
    for relative in (
        "analysis-framework/malware/png_registry_loader/rules/png_registry_loader.yar",
        "analysis-framework/malware/suomi_agent/rules/suomi_agent.yar",
        "analysis-framework/malware/blackhorse_miner_agent/rules/blackhorse_miner_agent.yar",
        "analysis-framework/malware/catddos/rules/catddos.yar",
        "analysis-framework/malware/nsis_obfuscated_loader/rules/nsis_obfuscated_loader.yar",
        "analysis-framework/malware/windows_script_stager/rules/unicode_separator_stager.yar",
        "analysis-framework/malware/windows_script_stager/rules/corb_xor_stager.yar",
    ):
        yara.compile(filepath=str(ROOT / relative))


def test_batch17_layout_registry_catalog_and_connection_safety() -> None:
    classification = json.loads((BATCH / "classification.json").read_text(encoding="utf-8"))
    assert len(classification["samples"]) == 10
    assert len({item["sha256"] for item in classification["samples"]}) == 10
    catalog = json.loads((ROOT / "analysis-results/catalog/cases.json").read_text(encoding="utf-8"))["cases"]
    for item in classification["samples"]:
        case_dir = ROOT / "analysis-results/malware" / item["family"] / "versions" / item["version"] / "cases" / item["sha256"]
        assert {"README.md", "metadata.json", "config.json", "iocs.json", "IOC-LIST.md"} <= {path.name for path in case_dir.iterdir()}
        text = (case_dir / "README.md").read_text(encoding="utf-8")
        assert "詳細な静的解析ロジック" in text
        assert "開発者・利用アクター・コモディティ性・過去の利用" in text
        assert catalog[item["sha256"]]["canonical_path"] == case_dir.relative_to(ROOT).as_posix()
    validation = json.loads((BATCH / "c2-validation.json").read_text(encoding="utf-8"))
    assert validation["sample_count"] == 10
    assert validation["unique_probe_count"] == 12
    assert validation["policy"]["server_data_read"] is False
    for sample in validation["samples"]:
        for result in sample["candidate_results"]:
            assert result["application_data_sent"] is False
            assert result.get("server_data_read", False) is False
            assert result["c2_confirmed"] is False
    registry = json.loads((ROOT / "analysis-framework/registry/malware_types.json").read_text(encoding="utf-8"))["malware_types"]
    for family in ("png_registry_loader", "suomi_agent", "blackhorse_miner_agent", "catddos", "nsis_obfuscated_loader", "windows_script_stager", "efimer"):
        assert registry[family]["known_sample_sha256"]
