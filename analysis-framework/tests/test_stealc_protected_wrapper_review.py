"""StealC保護外層cluster reviewerの合成回帰試験。"""

from __future__ import annotations

import copy
import importlib.util
import json
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
                "branch_instructions": 3,
                "conditional_branches": 0,
                "unconditional_branches": 3,
                "indirect_branches": 0,
                "calls": 1,
                "returns": 0,
                "unresolved_successors": 0,
                "decode_failures": 0,
                "cyclomatic_complexity": 1,
                "stop_mnemonics": {"int3": 1},
                "top_mnemonics": {
                    "mov": 9,
                    "jmp": 3,
                    "push": 3,
                    "sub": 3,
                    "add": 1,
                    "call": 1,
                    "int3": 1,
                },
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


def _handler_document(
    sha256: str,
    names: tuple[str, str],
    *,
    source_sha256: str = "3" * 64,
) -> dict:
    wrapper = {
        "artifact_role": "reviewed_protected_wrapper",
        "reviewed_hash": True,
        "cluster_id": "stealc-taggant-wrapper-466909e3ef5d175a",
        "structural_fingerprint_sha256": (
            "466909e3ef5d175acc1f3923245a3f8069248bfe78def549965adbee1522e331"
        ),
        "matched_patterns": [
            "reviewed_exact_sha256",
            "x86_pe32_seven_section_layout",
            "randomized_dual_executable_sections",
            "taggant_entrypoint_section",
            "no_overlay",
        ],
        "observed": {
            "randomized_section_names": list(names),
        },
        "protector_exact_version_confirmed": False,
        "terminal_family_confirmed_from_wrapper_alone": False,
        "terminal_payload_recovered": False,
        "static_config_recovered": False,
        "c2_recovered": False,
    }
    evidence = {
        "tier": 2,
        "tier_name": "structural_corroboration",
        "score": 20_205,
        "minimum_score": 1,
        "sufficient": True,
        "structural_groups": ["artifact_role", "matched_patterns"],
        "candidate_groups": [],
    }
    return {
        "handler": {"id": reviewer.HANDLER_ID},
        "selected_layer": {"sha256": sha256, "format": "pe"},
        "selected_evidence": evidence,
        "attempts": [
            {
                "status": "succeeded",
                "evidence_status": "sufficient",
                "preflight": {
                    "eligible": True,
                    "blockers": [],
                    "source_sha256": source_sha256,
                },
            }
        ],
        "result": {
            "family": "stealc",
            "sample_sha256": sha256,
            "config": {
                "profile": None,
                "static_config_recovered": False,
                "protected_wrapper": wrapper,
            },
            "findings": [],
            "executed": False,
            "network_contacted": False,
            "credentials_published": False,
        },
        "result_quota": {"truncated": False, "reasons": []},
        "verified_binary_outputs": [],
        "observed_binary_outputs": [],
    }


def _write_handler_root(root: Path, *, second_source_sha256: str = "3" * 64) -> None:
    for sha256, names, source_sha256 in (
        (SHA_A, ("abcdefgh", "ijklmnop"), "3" * 64),
        (SHA_B, ("qrstuvwx", "yzabcdef"), second_source_sha256),
    ):
        handler_dir = root / sha256 / "cases" / sha256 / "handlers"
        handler_dir.mkdir(parents=True)
        (handler_dir / "stealc.json").write_text(
            json.dumps(
                _handler_document(sha256, names, source_sha256=source_sha256),
                ensure_ascii=False,
            ),
            encoding="utf-8",
        )


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
    assert review["entrypoint_extended_analysis"]["stable_branch_profile"] == {
        "branch_instructions": 3,
        "conditional_branches": 0,
        "unconditional_branches": 3,
        "indirect_branches": 0,
        "cyclomatic_complexity": 1,
    }
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
        (
            lambda value: value["cases"][0]["nodes"][0]["unpack"]["pe"]["control_flow_triage"]["metrics"].__setitem__("conditional_branches", 1),
            "CFG conditional_branches",
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


def test_handler_validation_automates_tier_two_without_terminal_promotion(
    short_tmp: Path,
) -> None:
    _write_handler_root(short_tmp)
    review = reviewer.build_review(_report())
    validation = reviewer.build_handler_validation(review, short_tmp)
    assert validation["status"] == "structural_evidence_automated_terminal_unresolved"
    assert validation["sample_count"] == 2
    assert validation["handler"]["evidence_tier"] == 2
    assert validation["cases"][0]["terminal_payload_recovered"] is False
    assert validation["cases"][0]["static_config_recovered"] is False
    assert validation["cases"][0]["c2_recovered"] is False
    assert validation["safety"] == {
        "samples_executed": False,
        "network_contacted": False,
        "binary_outputs_published": False,
        "credentials_published": False,
    }
    text = reviewer.render_markdown(review, validation)
    assert "自動handlerへの接続" in text
    assert "全件でtier 2" in text
    assert "設定、C2は未復元" in text


def test_handler_validation_rejects_terminal_overpromotion(short_tmp: Path) -> None:
    _write_handler_root(short_tmp)
    path = short_tmp / SHA_A / "cases" / SHA_A / "handlers" / "stealc.json"
    document = json.loads(path.read_text(encoding="utf-8"))
    document["result"]["config"]["protected_wrapper"]["c2_recovered"] = True
    path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(reviewer.ProtectedWrapperReviewError, match="過剰昇格"):
        reviewer.build_handler_validation(reviewer.build_review(_report()), short_tmp)


def test_handler_validation_requires_one_handler_source_hash(short_tmp: Path) -> None:
    _write_handler_root(short_tmp, second_source_sha256="4" * 64)
    with pytest.raises(reviewer.ProtectedWrapperReviewError, match="source SHA-256"):
        reviewer.build_handler_validation(reviewer.build_review(_report()), short_tmp)
