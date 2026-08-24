from __future__ import annotations

import importlib.util
from pathlib import Path

MODULE_PATH = (
    Path(__file__).resolve().parents[1]
    / "malware"
    / "valleyrat"
    / "common"
    / "reviewed_samples.py"
)
SPEC = importlib.util.spec_from_file_location("valleyrat_reviewed_jp_malspam", MODULE_PATH)
assert SPEC and SPEC.loader
REVIEWED = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(REVIEWED)


EXPECTED = {
    "da33a95b2ed28e2c50da002584eb81e4e94fe4a55e98945146842ed9e23be066": (
        "chrome_elf_winos_ca00_proxy_component_20260824",
        "4df8bda2718afbd6ee42a96e0097d24592e451a1c6a05d9bffa8921c683733e2",
    ),
    "22d1b5576ccb3c425a94e405076a0665efa0dd2d59325bfb561b6b16969e267f": (
        "vulkan_winos_ca01_proxy_component_20260820",
        "807361fe1ff663ff3716a7e667e964f9d8fd15a20766bd2796bd46b1f67e168e",
    ),
    "041a0aeb76e63f67abb258036b089e27174074c5367d7c7a2a644e3bf9dd3b51": (
        "msocf_rc4_xorff_component_resource_padded_20260824",
        "c77c885cae806025691827fa44ad1e40cdb737713473979212e0c986ceafdbf0",
    ),
    "04c9eae9f19a63e4a84da108fe6b768ab6e558c89126dbb6c35a0c383739a81f": (
        "msocf_rc4_xorff_component_overlay_padded_20260824",
        "c77c885cae806025691827fa44ad1e40cdb737713473979212e0c986ceafdbf0",
    ),
    "ad755d2dfeaa23b80d561656848d12d8e66edd99b1169d63a936fe7b01da57ab": (
        "msocf_rc4_xorff_component_baseline_20260824",
        "c77c885cae806025691827fa44ad1e40cdb737713473979212e0c986ceafdbf0",
    ),
}


def test_japanese_malspam_components_are_reviewed_exact_hashes() -> None:
    for digest, (variant, stage_sha256) in EXPECTED.items():
        record = REVIEWED.REVIEWED_SAMPLES[digest]
        assert record["campaign"] == "signed_proxy_sideload"
        assert record["variant"] == variant
        assert record["final_rat_confirmed"] is True
        assert record["recovered_stage_sha256"] == stage_sha256


def test_japanese_malspam_components_are_routable() -> None:
    mapping = REVIEWED.campaign_map()
    assert {digest: mapping[digest] for digest in EXPECTED} == {
        digest: "signed_proxy_sideload" for digest in EXPECTED
    }
