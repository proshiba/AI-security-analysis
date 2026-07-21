"""2026-07-21追加ValleyRAT検体向け解析器の回帰テスト。"""

from __future__ import annotations

import importlib.util
import hashlib
from pathlib import Path
from types import SimpleNamespace
import zipfile

import yara


ROOT = Path(__file__).resolve().parents[2]
CAMPAIGNS = ROOT / "analysis-framework" / "malware" / "valleyrat" / "campaigns"
VALLEY_COMMON = ROOT / "analysis-framework" / "malware" / "valleyrat" / "common"


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


SINGLE = _load("valley_single_resource", CAMPAIGNS / "single_pe_vvas_resource" / "analyze.py")
SINGLE_NET = _load(
    "valley_single_resource_net",
    CAMPAIGNS / "single_pe_vvas_resource" / "network_detector.py",
)
SINGLE_EMU = _load(
    "valley_single_resource_emu",
    CAMPAIGNS / "single_pe_vvas_resource" / "emulator.py",
)
PROXY = _load("valley_proxy", CAMPAIGNS / "signed_proxy_sideload" / "analyze.py")
PROXY_NET = _load(
    "valley_proxy_net", CAMPAIGNS / "signed_proxy_sideload" / "network_detector.py"
)
MSI_INVENTORY = _load(
    "valley_msi_inventory",
    CAMPAIGNS / "msi_embedded_cab_custom_actions" / "analyze_msi.py",
)
MSI_CHAIN = _load(
    "valley_msi_chain",
    CAMPAIGNS / "msi_embedded_cab_custom_actions" / "analyze_chain_c2.py",
)
PROTECTED = _load(
    "valley_protected_installer",
    CAMPAIGNS / "protected_installer_bundle" / "analyze.py",
)
PROTECTED_NET = _load(
    "valley_protected_installer_net",
    CAMPAIGNS / "protected_installer_bundle" / "network_detector.py",
)
PROTECTED_EMU = _load(
    "valley_protected_installer_emu",
    CAMPAIGNS / "protected_installer_bundle" / "emulator.py",
)
VALLEY_DETECTOR = _load(
    "valley_additional_detector",
    ROOT / "analysis-framework" / "malware" / "valleyrat" / "detect.py",
)
REVIEWED_SAMPLES = _load(
    "valley_reviewed_samples",
    VALLEY_COMMON / "reviewed_samples.py",
)
STATIC_PE = _load(
    "valley_static_pe",
    VALLEY_COMMON / "static_pe.py",
)


def test_single_pe_resource_requires_loader_chain_and_decoded_config(monkeypatch) -> None:
    raw_config = "|6666:1o|061.3.911.301:1p|".encode("utf-16le")
    resource = b"\x48\x81\xec" + raw_config
    lang = SimpleNamespace(
        id=1033,
        data=SimpleNamespace(
            struct=SimpleNamespace(OffsetToData=0x2000, Size=len(resource))
        ),
    )
    name = SimpleNamespace(id=788, directory=SimpleNamespace(entries=[lang]))
    resource_type = SimpleNamespace(id=10, directory=SimpleNamespace(entries=[name]))
    imports = [
        SimpleNamespace(name=item.encode())
        for item in sorted(SINGLE.REQUIRED_IMPORTS)
    ]
    image = SimpleNamespace(
        DIRECTORY_ENTRY_RESOURCE=SimpleNamespace(entries=[resource_type]),
        DIRECTORY_ENTRY_IMPORT=[SimpleNamespace(imports=imports)],
        OPTIONAL_HEADER=SimpleNamespace(AddressOfEntryPoint=0x1234),
        get_data=lambda _rva, _size: resource,
    )
    monkeypatch.setattr(SINGLE.pefile, "PE", lambda **_kwargs: image)

    result = SINGLE.analyze(b"MZ synthetic")

    assert result["campaign_type"] == "single_pe_vvas_resource"
    assert result["config"]["endpoints"] == ["103.119.3.160:6666"]
    assert result["config"]["liveness_confirmed"] is False
    assert result["executed"] is False


def _record(name: bytes, extent: int, size: int, flags: int = 0) -> bytes:
    length = 33 + len(name) + (1 if len(name) % 2 == 0 else 0)
    record = bytearray(length)
    record[0] = length
    record[2:6] = extent.to_bytes(4, "little")
    record[10:14] = size.to_bytes(4, "little")
    record[25] = flags
    record[32] = len(name)
    record[33 : 33 + len(name)] = name
    return bytes(record)


def test_iso_parser_honors_extent_and_size_boundaries() -> None:
    image = bytearray(24 * 2048)
    image[16 * 2048 + 1 : 16 * 2048 + 6] = b"CD001"
    root = _record(b"\x00", 20, 2048, flags=2)
    image[16 * 2048 + 156 : 16 * 2048 + 156 + len(root)] = root
    file_record = _record(b"A.BIN;1", 21, 4)
    image[20 * 2048 : 20 * 2048 + len(file_record)] = file_record
    image[21 * 2048 : 21 * 2048 + 4] = b"test"

    assert PROXY._iso_root_files(bytes(image)) == [("A.BIN", b"test")]


def test_msi_loaders_accept_raw_input(tmp_path: Path) -> None:
    sample = tmp_path / "sample.msi"
    sample.write_bytes(b"raw-msi")
    for module in (MSI_INVENTORY, MSI_CHAIN):
        data, provenance = module.load_msi(sample, None, None)
        assert data == b"raw-msi"
        assert provenance["source_msi"] == str(sample)


def test_msi_loaders_share_zip_member_provenance(tmp_path: Path) -> None:
    archive_path = tmp_path / "sample.zip"
    member = "nested/sample.msi"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr(member, b"raw-msi")

    for module in (MSI_INVENTORY, MSI_CHAIN):
        data, provenance = module.load_msi(None, archive_path, member)
        assert data == b"raw-msi"
        assert provenance == {
            "source_msi": None,
            "source_zip": str(archive_path),
            "member": member,
            "msi_member": member,
        }


def test_cab_memory_path_returns_only_pe(monkeypatch) -> None:
    fake = {
        "a.exe": SimpleNamespace(buf=b"MZpayload"),
        "b.txt": SimpleNamespace(buf=b"text"),
    }
    monkeypatch.setattr(MSI_CHAIN.cabarchive, "CabArchive", lambda _data: fake)
    blobs, method = MSI_CHAIN.cab_pe_blobs(b"MSCF", None)
    assert blobs == [("CAB/a.exe", b"MZpayload")]
    assert method == "cabarchive_memory"


def test_detectors_and_emulator_are_passive() -> None:
    config = {"endpoints": ["controller.example:6666"]}
    events = [
        {
            "host": "controller.example",
            "port": 6666,
            "valleyrat_process_or_hash_correlation": True,
        }
    ]
    result = SINGLE_NET.detect(events, config)
    assert result["matched"] is True
    assert result["c2_confirmed"] is False
    assert SINGLE_EMU.emulate(config)["packets_generated"] == 0

    proxy = PROXY_NET.detect(
        [
            {
                "stage": "dll_sideload",
                "host_hash_or_signature_verified": True,
                "module_hash_or_export_shape_verified": True,
            }
        ]
    )
    assert proxy["matched"] is True
    assert proxy["c2_confirmed"] is False

    protected = PROTECTED_NET.detect(
        [{"reviewed_sample_hash": True, "embedded_pe_created": True}]
    )
    assert protected["matched"] is True
    assert protected["c2_confirmed"] is False
    assert PROTECTED_EMU.emulate()["packets_generated"] == 0


def test_protected_installer_review_set_covers_unresolved_four() -> None:
    expected = {
        "959001875232215e49463f8528c5786a741fda70e8b0fd95159ebdb0b41e140a",
        "40c98ff9673f67cfa82d9e2e16a2e55644f71fec87e2d92f25821a2b917f8145",
        "e6f4c46f2a72a4d8b1eda2c2c431c64d73eae7057221b35a6fc16138e4dc4d43",
        "b1dd9ebb57480de3da86e683639b328e9dcf291b4bd2d4816986d1b0cdfa9342",
    }
    assert set(PROTECTED.REVIEWED) == expected


def test_reviewed_registry_is_the_single_routing_source() -> None:
    assert VALLEY_DETECTOR.KNOWN_CAMPAIGNS == REVIEWED_SAMPLES.campaign_map()
    assert PROTECTED.REVIEWED == REVIEWED_SAMPLES.records_for_campaign(
        "protected_installer_bundle"
    )
    assert PROXY.REVIEWED == REVIEWED_SAMPLES.records_for_campaign(
        "signed_proxy_sideload"
    )
    assert (
        VALLEY_DETECTOR.KNOWN_CAMPAIGNS[
            "7cfd372f0ff4e5237deafebaaa5a9f868778e9c06deb701fb43b2c30c7e03949"
        ]
        == "signed_proxy_sideload"
    )


def test_static_pe_helpers_apply_bounds_and_deterministic_sampling() -> None:
    image = bytearray(512)
    image[128:130] = b"MZ"
    image[128 + 0x3C : 128 + 0x40] = (0x40).to_bytes(4, "little")
    image[128 + 0x40 : 128 + 0x44] = b"PE\0\0"

    assert STATIC_PE.embedded_pe_header_offsets(bytes(image)) == [128]
    assert STATIC_PE.embedded_pe_header_offsets(
        bytes(image), max_scan_size=128
    ) == []
    assert STATIC_PE.bounded_entropy(b"\0" * (9 * 1024 * 1024)) == 0.0
    assert STATIC_PE.bounded_entropy(bytes(range(256)) * 32768) == 8.0


def test_reviewed_exact_hash_is_exposed_as_known_inner_evidence(monkeypatch) -> None:
    data = b"MZ reviewed synthetic sample"
    digest = hashlib.sha256(data).hexdigest()
    monkeypatch.setitem(
        VALLEY_DETECTOR.KNOWN_CAMPAIGNS,
        digest,
        "protected_installer_bundle",
    )

    result = VALLEY_DETECTOR.detect(data, Path("sample.exe"))

    assert result["matched"] is True
    assert "known inner SHA-256" in result["campaigns"][0]["reasons"]


def test_new_yara_rules_compile_and_docs_are_japanese() -> None:
    rule_paths = [
        CAMPAIGNS / "single_pe_vvas_resource" / "rules" / "single_pe_vvas_resource.yar",
        CAMPAIGNS / "msi_lzx_protected_pe" / "rules" / "msi_lzx_protected_pe.yar",
        CAMPAIGNS / "signed_proxy_sideload" / "rules" / "signed_proxy_sideload.yar",
        CAMPAIGNS / "protected_installer_bundle" / "rules" / "protected_installer_bundle.yar",
    ]
    for path in rule_paths:
        yara.compile(filepath=str(path))
    for directory in (
        "single_pe_vvas_resource",
        "msi_lzx_protected_pe",
        "signed_proxy_sideload",
        "protected_installer_bundle",
    ):
        text = (CAMPAIGNS / directory / "README.md").read_text(encoding="utf-8")
        assert "解析" in text
        assert "縺" not in text
