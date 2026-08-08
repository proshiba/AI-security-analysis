from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MODULE_DIR = ROOT / "analysis-framework" / "malware" / "formbook_loader"
sys.path.insert(0, str(MODULE_DIR))
SPEC = importlib.util.spec_from_file_location("xloader_unresolved_evidence", MODULE_DIR / "unresolved_evidence.py")
assert SPEC is not None and SPEC.loader is not None
EVIDENCE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = EVIDENCE
SPEC.loader.exec_module(EVIDENCE)

classify_unresolved = EVIDENCE.classify_unresolved
count_absolute_references = EVIDENCE.count_absolute_references
find_alignment = EVIDENCE.find_alignment


def test_find_alignment_for_mapped_image() -> None:
    source = bytes(range(256)) * 24
    candidate = b"P" * 0x321 + source + b"S" * 0x80

    alignment = find_alignment(source, candidate)

    assert alignment is not None
    assert alignment.offset == 0x321
    assert alignment.similarity == 1.0


def test_count_absolute_references_supports_raw_and_default_image_base() -> None:
    address = 0x267E0
    data = address.to_bytes(4, "little") + (0x400000 + address).to_bytes(4, "little") + address.to_bytes(4, "little")

    assert count_absolute_references(data, address) == 3


def test_classify_not_observed_in_static_reference_set() -> None:
    result = classify_unresolved(
        direct_call_count=0,
        absolute_reference_count=0,
        resolved_mix_candidate_count=0,
        marker_hit_image_count=0,
        target_mutation_observed=False,
    )

    assert result == ("not_observed_in_static_reference_set", "none", False)


def test_classify_resolved_mix_without_marker() -> None:
    result = classify_unresolved(
        direct_call_count=1,
        absolute_reference_count=0,
        resolved_mix_candidate_count=1,
        marker_hit_image_count=0,
        target_mutation_observed=False,
    )

    assert result == (
        "resolved_mix_marker_not_observed_in_evidence_set",
        "low",
        False,
    )


def test_runtime_mutation_has_high_capture_priority() -> None:
    result = classify_unresolved(
        direct_call_count=1,
        absolute_reference_count=0,
        resolved_mix_candidate_count=1,
        marker_hit_image_count=0,
        target_mutation_observed=True,
    )

    assert result == ("runtime_target_mutation_observed", "high", True)
