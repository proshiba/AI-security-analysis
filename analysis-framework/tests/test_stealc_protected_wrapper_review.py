"""StealC保護外層cluster reviewerの合成回帰試験。"""

from __future__ import annotations

import copy
import importlib.util
from pathlib import Path

import pytest


REPOSITORY = Path(__file__).resolve().parents[2]
MODULE_PATH = REPOSITORY / "analysis-framework" / "malware" / "stealc" / "protected_wrapper_review.py"
SPEC = importlib.util.spec_from_file_location("stealc_protected_wrapper_review", MODULE_PATH)
assert SPEC and SPEC.loader
reviewer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(reviewer)


SHA_A = "1" * 64
SHA_B = "2" * 64


def _section(name: str, raw: int, virtual: int, entropy: float, executable: bool) -> dict:
    return {
        "name": name,
        "raw_size": raw,
        "virtual_size": virtual,
        "entropy": entropy,
        "characteristics": "0xe0000040" if executable else "0xc0000040",
    }


def _case(sha256: str, names: tuple[str, str], *, resource: bool = False) -> dict:
    sections = [
        _section("   \x00    ", 80_896, 2_000_000, 7.98, True),
        _section(".rsrc   ", 512 if resource else 0, 4096, 0.4 if resource else 0.0, False),
        _section(".idata  ", 512, 4096, 0.9, False),
        _section("        ", 512, 2_700_000, 0.2, True),
        _section(names[0], 1_680_000, 1_684_000, 7.95, True),
        _section(names[1], 1024, 4096, 6.2, True),
        _section(".taggant", 8704, 12_288, 0.7, True),
    ]
    pe = {
        "machine": "0x14c",
        "is_dotnet": False,
        "imports": 1,
        "import_libraries": ["kernel32.dll"],
        "sections": sections,
        "classification": "suspected_packed",
        "packing_suspected": True,
        "entrypoint_section": ".taggant",
        "overlay_size": 0,
        "resource_count": 1 if resource else 0,
        "control_flow_triage": {
            "status": "analyzed",
            "metrics": {
                "basic_blocks": 4,
                "known_edges": 3,
                "instructions": 21,
                "calls": 1,
                "returns": 0,
                "unresolved_successors": 0,
                "decode_failures": 0,
                "stop_mnemonics": {"int3": 1},
            },
        },
    }
    return {
        "case": {
            "sha256": sha256,
            "family": "stealc",
            "group_id": "stealc_themida",
            "blockers": ["themida_winlicense_2x", "terminal_config_not_recovered"],
        },
        "status": "analyzed",
        "source_kind": "aes_zip",
        "nodes": [
            {
                "sha256": sha256,
                "size": 1_780_000,
                "depth": 0,
                "relation": "root",
                "children": [],
                "format": "pe",
                "unpack": {
                    "sha256": sha256,
                    "format": "pe",
                    "entropy": 7.94,
                    "executed": False,
                    "network_contacted": False,
                    "unpack_status": "no_artifact_recovered",
                    "pe": pe,
                },
            }
        ],
    }


def _report() -> dict:
    return {
        "analysis_mode": "bounded_static_only",
        "safety": {
            "executed": False,
            "emulated": False,
            "network_contacted": False,
            "raw_artifacts_written": False,
        },
        "cases": [
            _case(SHA_A, ("abcdefgh", "ijklmnop")),
            _case(SHA_B, ("qrstuvwx", "yzabcdef"), resource=True),
        ],
    }


def test_build_review_correlates_randomized_wrappers_without_promoting_terminal() -> None:
    review = reviewer.build_review(_report())
    assert review["sample_count"] == 2
    assert review["assessment"]["confirmed"][0].startswith("2件")
    assert review["cluster"]["correlation_confidence"] == "high"
    assert review["cluster"]["protector_exact_version_confirmed"] is False
    assert review["cluster"]["terminal_family_confirmed_from_wrapper_alone"] is False
    assert review["cases"][0]["terminal_payload_recovered"] is False
    assert review["cases"][0]["static_config_recovered"] is False
    assert review["cases"][0]["c2_recovered"] is False
    assert review["safety"] == {
        "samples_executed": False,
        "cpu_emulated": False,
        "network_contacted": False,
        "network_scope": "malware_or_c2_endpoints_not_contacted; provider_acquisition_outside_review",
        "raw_artifacts_published": False,
        "source": "bounded_deep_static_report",
    }


def test_cluster_fingerprint_ignores_randomized_names_and_resource_variant() -> None:
    first = reviewer.build_review(_report())
    changed = _report()
    changed["cases"][0] = _case(SHA_A, ("zzzzzzzz", "yyyyyyyy"), resource=True)
    second = reviewer.build_review(changed)
    assert first["cluster"]["structural_fingerprint_sha256"] == second["cluster"]["structural_fingerprint_sha256"]


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda value: value["safety"].__setitem__("executed", True), "safety.executed"),
        (lambda value: value["cases"][0].__setitem__("source_kind", "raw_file"), "AES ZIP"),
        (lambda value: value["cases"][0]["nodes"][0].__setitem__("sha256", SHA_B), "binding"),
        (
            lambda value: value["cases"][0]["nodes"][0]["unpack"]["pe"].__setitem__("entrypoint_section", ".text"),
            "entrypoint",
        ),
        (
            lambda value: value["cases"][0]["nodes"][0]["unpack"]["pe"]["sections"][4].__setitem__("name", "not-random"),
            "section名",
        ),
        (
            lambda value: value["cases"][0]["nodes"][0]["unpack"]["pe"]["control_flow_triage"]["metrics"].__setitem__("calls", 2),
            "CFG calls",
        ),
    ],
)
def test_build_review_rejects_contract_mutations(mutation, message: str) -> None:
    report = copy.deepcopy(_report())
    mutation(report)
    with pytest.raises(reviewer.ProtectedWrapperReviewError, match=message):
        reviewer.build_review(report)


def test_build_review_requires_multiple_samples() -> None:
    report = _report()
    report["cases"] = report["cases"][:1]
    with pytest.raises(reviewer.ProtectedWrapperReviewError, match="2件以上"):
        reviewer.build_review(report)


def test_render_markdown_is_japanese_and_keeps_terminal_limit() -> None:
    text = reviewer.render_markdown(reviewer.build_review(_report()))
    assert "StealC保護外層clusterの追加静的解析" in text
    assert "内側のStealC payload" in text
    assert "CPU emulation：なし" in text
