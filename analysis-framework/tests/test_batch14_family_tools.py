"""第14バッチで追加した静的抽出・検知・安全境界を回帰検証する。"""

from __future__ import annotations
import base64
import importlib.util
import io
import json
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def load(name: str, relative: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    module_dir = str((ROOT / relative).parent)
    if module_dir not in sys.path: sys.path.insert(0, module_dir)
    spec.loader.exec_module(module)
    return module


def test_signed_dht_batch14_profiles_are_reviewed() -> None:
    module = load("batch14_signed_dht", "analysis-framework/malware/signed_dht_bot/extract_config.py")
    aarch64 = module.PROFILES["05a0ca0ac2527c0faddc2a8ec456e69fc1f0e0c9fff9d2d396327faf3f876c30"]
    arm = module.PROFILES["d5d41bf6ec3d3bfe82546234a095654cfa4200fefec12889689ac4d609076a95"]
    assert aarch64["ghidra_main"] == "0x00400180"
    assert arm["ghidra_main"] == "0x00008da8"
    assert aarch64["inserted_trailer_bytes"] == arm["inserted_trailer_bytes"] == 11
    assert len(aarch64["recovered_sha256"]) == len(arm["recovered_sha256"]) == 64
    assert len(module.COMMAND_IDS) == 9


def test_script_fragment_reconstruction_is_non_executing() -> None:
    module = load("batch14_script_extract", "analysis-framework/malware/windows_script_stager/extract_config.py")
    fragments = ["function tridmisalp{}Function Tamponsln{}Srinks"] + [""] * 9
    lines = [f'Stilsikre = "{fragments[0]}";'] + [f'Stilsikre = Stilsikre + "{value}";' for value in fragments[1:]]
    text = '\n'.join(lines + ['skytt = "Srinks";', "var Legalist = 'e';"])
    powershell, evidence = module.reconstruct_javascript_powershell(text)
    assert powershell.endswith("e")
    assert evidence["fragment_count"] == 10


def test_script_network_detector_requires_correlation() -> None:
    module = load("batch14_script_network", "analysis-framework/malware/windows_script_stager/network_detector.py")
    event = {"host": "example.invalid", "path": "/hejs.hhk", "method": "GET"}
    assert module.detect_events([event])["matched"] is False
    event["wscript_or_powershell_parent"] = True
    result = module.detect_events([event])
    assert result["matched"] is True
    assert result["c2_confirmed"] is False


def test_panchan_emulator_and_detector_are_bounded() -> None:
    emulator = load("batch14_panchan_emulator", "analysis-framework/malware/panchan/emulator.py")
    detector = load("batch14_panchan_network", "analysis-framework/malware/panchan/network_detector.py")
    message = emulator.build_synthetic_message("sharepeer")
    parsed = emulator.parse_synthetic_message(message)
    assert parsed["greeting_valid"] is True and parsed["terminator_valid"] is True
    assert parsed["network_contacted"] is False and parsed["command_executed"] is False
    weak = {"port": 2210, "payload_markers": []}
    assert detector.detect_events([weak])["matched"] is False
    strong = {"port": 2210, "payload_markers": ["pan-chan's mining rig hi!", "finish", "sharepeer"]}
    assert detector.detect_events([strong])["matched"] is True


def test_office_inventory_recurses_into_pdf_without_execution() -> None:
    module = load("batch14_office", "analysis-framework/common/office_container_inventory.py")
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        archive.writestr("document.pdf", b"%PDF-1.7\n1 0 obj << /Type /Catalog >> endobj\n%%EOF")
    result = module.analyze_bytes(stream.getvalue())
    nested = result["entries"][0]["inventory"]
    assert nested["type"] == "pdf"
    assert nested["active_content_observed"] is False


def test_office_inventory_flags_pdf_active_markers_only_as_inventory() -> None:
    module = load("batch14_office_active", "analysis-framework/common/office_container_inventory.py")
    result = module.analyze_bytes(b"%PDF-1.7\n/OpenAction /JavaScript\n%%EOF")
    assert result["active_markers"]["javascript"] is True
    assert result["active_markers"]["open_action"] is True


def test_agenttesla_powershell_layers_are_recovered_without_execution() -> None:
    module = load("batch14_agenttesla_recover", "analysis-framework/malware/agenttesla/agenttesla_recover.py")
    byte_payload = b"MZ" + b"A" * 98
    array = ",".join(str(value) for value in byte_payload)
    byte_script = f"[Byte[]] $payloadData = ({array})".encode()
    arrays = module.powershell_byte_arrays(byte_script)
    assert arrays == [("powershell-byte-array:payloadData", byte_payload)]

    key = b"review-key"
    inner = base64.b64encode(byte_payload)
    encrypted = bytes(value ^ key[index % len(key)] for index, value in enumerate(inner))
    script = f'$key = "{key.decode()}"\n$payloadBase64 = \'{base64.b64encode(encrypted).decode()}\''.encode()
    layers = module.powershell_xor_base64(script)
    assert layers[0][1] == byte_payload


def test_batch14_public_files_do_not_publish_agenttesla_credentials() -> None:
    public_roots = [ROOT / "analysis-framework", ROOT / "analysis-results"]
    forbidden = ("BLACK" + "BOy76@@", "credentials_" + "published\": true")
    for public_root in public_roots:
        for path in public_root.rglob("*"):
            if not path.is_file() or path.suffix.lower() not in {".md", ".json", ".py", ".yar"}:
                continue
            text = path.read_text(encoding="utf-8", errors="ignore")
            assert not any(value in text for value in forbidden), path


def test_new_json_files_are_valid() -> None:
    for relative in (
        "analysis-framework/malware/panchan/campaigns.json",
        "analysis-framework/malware/panchan/c2_profile.json",
        "analysis-framework/malware/windows_script_stager/campaigns.json",
        "analysis-framework/malware/windows_script_stager/c2_profile.json",
    ):
        json.loads((ROOT / relative).read_text(encoding="utf-8"))


def test_c2_batch_validation_forces_connect_only() -> None:
    module = load("batch14_c2_validation", "analysis-framework/common/c2_validation.py")
    candidate = {
        "host": "example.invalid", "port": 443, "protocol": "tcp", "role": "distribution",
        "source": "合成テスト", "timeout": 3, "max_bytes": 64,
    }
    args = module._probe_args(candidate, ["a" * 64], True)
    assert args.connect_only is True
    manifest = {"batch_id": "test", "samples": [{
        "sha256": "a" * 64, "c2_resolution_status": "not_recovered", "candidates": [candidate],
    }]}
    module.probe = lambda args: {"status": "tcp_connect_only", "network_contacted": True,
                                 "target_contact_attempted": True, "application_data_sent": False,
                                 "server_data_read": False, "target_role": args.target_role,
                                 "sample_sha256s": args.sample_sha256}
    result = module.validate_candidates(manifest, allow_network=True, include_non_c2=True)
    assert result["policy"]["server_data_read"] is False
    assert result["policy"]["maximum_response_bytes"] == 0


def test_batch14_publication_uses_fixed_depth() -> None:
    batch = ROOT / "analysis-results/research/malwarebazaar/batches/batch-0014"
    classification = json.loads((batch / "classification.json").read_text(encoding="utf-8"))
    samples = classification["samples"]
    assert len(samples) == 10
    assert sum(item["confidence"] == "pending_download" for item in samples) == 1

    published = 0
    for item in samples:
        if item["confidence"] == "pending_download":
            continue
        case_dir = (
            ROOT / "analysis-results/malware" / item["family"] / "versions"
            / (item["version"] or "unknown") / "cases" / item["sha256"]
        )
        for name in ("README.md", "metadata.json", "config.json", "iocs.json", "IOC-LIST.md"):
            assert (case_dir / name).is_file(), case_dir / name
        metadata = json.loads((case_dir / "metadata.json").read_text(encoding="utf-8"))
        assert metadata["sha256"] == item["sha256"]
        assert metadata["canonical_path"] == case_dir.relative_to(ROOT).as_posix()
        assert metadata["collections"] == ["malwarebazaar-1000"]
        published += 1
    assert published == 9


def test_batch14_c2_publication_preserves_connect_only_boundary() -> None:
    batch = ROOT / "analysis-results/research/malwarebazaar/batches/batch-0014"
    validation = json.loads((batch / "c2-validation.json").read_text(encoding="utf-8"))
    policy = validation["policy"]
    assert policy["exact_targets_only"] is True
    assert policy["tcp_connect_only"] is True
    for key in ("application_data_sent", "server_data_read", "tls_handshake", "banner_read", "port_scanning"):
        assert policy[key] is False
    assert len(validation["results"]) == 5
    assert all(item["tcp_connected"] is True for item in validation["results"])
    assert all(item["c2_confirmed"] is False for item in validation["results"])

    hunt = json.loads((batch / "shodan-hunt.json").read_text(encoding="utf-8"))
    assert len(hunt["queries"]) == 5
    assert len(hunt["internetdb_results"]) == 6
    assert all(item["vulnerability_list_omitted"] is True for item in hunt["internetdb_results"])
