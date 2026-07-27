"""2026-07-27 ValleyRAT／FormBook追加解析機能の回帰テスト。"""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import struct
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
import yara

ROOT = Path(__file__).resolve().parents[2]
COMMON = ROOT / "analysis-framework" / "common"
FORMBOOK = ROOT / "analysis-framework" / "malware" / "formbook_loader"
VALLEY = (
    ROOT
    / "analysis-framework"
    / "malware"
    / "valleyrat"
    / "campaigns"
    / "signed_proxy_sideload"
)
VALLEY_COMMON = ROOT / "analysis-framework" / "malware" / "valleyrat" / "common"
for directory in (COMMON, FORMBOOK, VALLEY, VALLEY_COMMON):
    if str(directory) not in sys.path:
        sys.path.insert(0, str(directory))


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


ISO = _load("targeted_iso", COMMON / "analyze_iso9660.py")
SUBMISSION = _load("targeted_submission", COMMON / "analyze_submission.py")
FORMBOOK_EXTRACT = _load("targeted_formbook_extract", FORMBOOK / "extract_script_chain.py")
FORMBOOK_EMULATOR = _load("targeted_formbook_emulator", FORMBOOK / "emulator.py")
FORMBOOK_DETECT = _load("targeted_formbook_detect", FORMBOOK / "detect.py")
IOC_MARKDOWN = _load("targeted_ioc_markdown", COMMON / "ioc_markdown.py")
WINOS = _load("winos_protocol", VALLEY / "winos_protocol.py")
WINOS_EMULATOR = _load("targeted_winos_emulator", VALLEY / "winos_emulator.py")
VALLEY_ANALYZE = _load("targeted_valley_analyze", VALLEY / "analyze.py")


def _iso_record(name: bytes, extent: int, size: int, flags: int = 0) -> bytes:
    length = 33 + len(name) + (1 if len(name) % 2 == 0 else 0)
    record = bytearray(length)
    record[0] = length
    record[2:6] = extent.to_bytes(4, "little")
    record[10:14] = size.to_bytes(4, "little")
    record[25] = flags
    record[32] = len(name)
    record[33 : 33 + len(name)] = name
    return bytes(record)


def test_submission_recursively_analyzes_raw_iso_members() -> None:
    image = bytearray(24 * ISO.SECTOR)
    pvd = 16 * ISO.SECTOR
    image[pvd] = 1
    image[pvd + 1 : pvd + 6] = b"CD001"
    image[pvd + 6] = 1
    image[pvd + 40 : pvd + 47] = b"TESTISO"
    root = _iso_record(b"\x00", 20, ISO.SECTOR, flags=2)
    image[pvd + 156 : pvd + 156 + len(root)] = root
    member = _iso_record(b"A.EXE;1", 21, 4)
    image[20 * ISO.SECTOR : 20 * ISO.SECTOR + len(member)] = member
    image[21 * ISO.SECTOR : 21 * ISO.SECTOR + 4] = b"MZ\0\0"

    result = SUBMISSION.analyze_blob("sample.img", bytes(image))

    assert result["type"] == "iso9660"
    assert result["iso"]["mounted"] is False
    assert result["iso"]["files"][0]["analysis"]["type"] == "pe"


def test_formbook_static_decoders_and_nonexecution_emulator() -> None:
    key = b"Philosop"
    plaintext = b"synthetic-loader-value"
    encrypted = bytes(value ^ key[index % len(key)] for index, value in enumerate(plaintext))
    encoded = base64.b64encode(encrypted).decode("ascii")

    assert FORMBOOK_EXTRACT.xor_base64(encoded) == plaintext.decode("ascii")
    result = FORMBOOK_EMULATOR.decode_synthetic_script_value(encoded)
    assert result["decoded_sha256"] == hashlib.sha256(plaintext).hexdigest()
    assert result["decoded_retained"] is False
    assert result["network_contacted"] is False
    assert result["process_started"] is False


def test_formbook_nested_stage_markers_are_structurally_named(monkeypatch) -> None:
    nested = (
        b"{9BA05972-F6A8-11CF-A442-00A0C90A8F39} "
        b"VirtualAlloc NtProtectVirtualMemory CallWindowProcA DefineDynamicAssembly"
    )
    prefix = b"A" * 1000
    script = f"$offset = 1000; $length = {len(nested)};"
    recovered = FORMBOOK_EXTRACT.recover_nested_stage(
        script, base64.b64encode(prefix + nested)
    )

    assert recovered is not None
    lowered = recovered.lower()
    for term in (
        "{9ba05972-f6a8-11cf-a442-00a0c90a8f39}",
        "virtualalloc",
        "ntprotectvirtualmemory",
        "callwindowproca",
        "definedynamicassembly",
    ):
        assert term in lowered

    monkeypatch.setattr(FORMBOOK_EXTRACT, "MAX_COMPANION_SIZE", 8)
    with pytest.raises(ValueError, match="64 MiB safety limit"):
        FORMBOOK_EXTRACT.recover_nested_stage(script, b"A" * 9)


def test_formbook_detector_recognizes_script_chain_without_hash() -> None:
    data = (
        b"Adfrdsbio TankerFest sadelta ShellExecute "
        b"Tedeummers61 frugtsala 80,104,105,108,111,115,111,112 141342 14613"
    )
    result = FORMBOOK_DETECT.detect(data, Path("sample.js"))

    assert result["matched"] is True
    assert result["campaigns"][0]["campaign_type"] == (
        "formbook_js_powershell_drive_chain_20260727"
    )


def test_winos_frame_and_emulator_only_ack_reviewed_control_messages() -> None:
    header = struct.pack("<II", 1234, 0) + b"\xca\x00"
    heartbeat = WINOS.build_frame(b"\xc9", header)
    parsed = WINOS.parse_frame(heartbeat)

    assert parsed.command == 0xC9
    assert parsed.complete is True
    response = WINOS_EMULATOR.response_for_frame(heartbeat)
    assert WINOS.parse_frame(response).payload_hex == "c900"
    unknown = WINOS.build_frame(b"\x10operation", header)
    assert WINOS_EMULATOR.response_for_frame(unknown) == b""
    with pytest.raises(PermissionError):
        WINOS.probe_reviewed_endpoint(
            "controller.invalid", 6685, "127.0.0.1", allow_live=False
        )
    with pytest.raises(ValueError, match="reviewed Winos endpoint"):
        WINOS.probe_reviewed_endpoint(
            "controller.invalid", 6685, "127.0.0.1", allow_live=True
        )


def test_pdfcore_proxy_uses_export_convergence_not_single_target(monkeypatch) -> None:
    names = list(VALLEY_ANALYZE.PDFCORE_EXPORTS)
    names.extend(f"ProxyExport{index}" for index in range(996))
    symbols = [
        SimpleNamespace(name=name.encode(), address=0x22C90 if index < 995 else 0x22000 + index)
        for index, name in enumerate(names)
    ]
    imports = [
        SimpleNamespace(name=name.encode(), ordinal=0)
        for name in ("WriteProcessMemory", "CreateProcessW", "CreateThread", "DeviceIoControl")
    ]
    pe = SimpleNamespace(
        DIRECTORY_ENTRY_IMPORT=[SimpleNamespace(dll=b"KERNEL32.dll", imports=imports)],
        DIRECTORY_ENTRY_EXPORT=SimpleNamespace(symbols=symbols),
        DIRECTORY_ENTRY_RESOURCE=SimpleNamespace(
            entries=[SimpleNamespace(name=name) for name in VALLEY_ANALYZE.WINOS_RESOURCE_TYPES]
        ),
        FILE_HEADER=SimpleNamespace(Machine=0x14C, TimeDateStamp=0),
        OPTIONAL_HEADER=SimpleNamespace(AddressOfEntryPoint=0x1000),
    )
    monkeypatch.setattr(VALLEY_ANALYZE.pefile, "PE", lambda **_kwargs: pe)
    monkeypatch.setattr(VALLEY_ANALYZE, "section_summaries", lambda _pe: [])

    result = VALLEY_ANALYZE._pe_summary("PDFCORE8.DLL", b"MZ synthetic")

    assert result["proxy_type"] == "pdfcore8_winos_proxy"
    assert result["export_target_count"] > 1
    assert result["export_target_peak_ratio"] >= 0.99


def test_targeted_yara_rules_compile() -> None:
    for path in (
        FORMBOOK / "rules" / "formbook_js_powershell_drive_chain.yar",
        VALLEY / "rules" / "signed_proxy_sideload.yar",
    ):
        yara.compile(filepath=str(path))

def test_canonical_ioc_renders_live_contact_and_provider_source() -> None:
    document = {
        "schema_version": 1,
        "hash_source": "Hatching Triage取得・提供検体",
        "sha256": ["a" * 64],
        "network": [
            {
                "domain": "controller.example",
                "port": 6685,
                "role": "reviewed control channel",
                "confidence": "confirmed_static_configuration",
                "source": "synthetic static config",
                "evidence": {"kind": "synthetic_test"},
            }
        ],
        "sample_executed": False,
        "network_contacted": True,
    }

    rendered = IOC_MARKDOWN.render_canonical_ioc_document(
        document, expected_sha256="a" * 64
    )

    assert "Hatching Triage取得・提供検体" in rendered
    assert "限定的な到達性確認" in rendered
    with pytest.raises(ValueError, match="canonical iocs.json"):
        IOC_MARKDOWN.canonical_ioc_view({**document, "hash_source": True})
