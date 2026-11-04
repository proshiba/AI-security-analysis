# ruff: noqa: E402
from __future__ import annotations

import struct
import sys
from pathlib import Path

import pytest

_FRAMEWORK = Path(__file__).resolve().parents[2] / "analysis-framework"
if str(_FRAMEWORK) not in sys.path:
    sys.path.insert(0, str(_FRAMEWORK))

from malware.purehvnc.managed_resource_recovery import decrypt_keyed_eaz_resource

from unpackers.managed_purerat_cache import (
    ManagedPureRatCacheError,
    VerifiedKeyedWordRecipe,
    decode_complete_utf16_cache,
    decode_referenced_utf16_cache,
    recover_verified_cache_model,
    replay_ordered_byte_writes,
)


def _writes(length: int, *, bias: int = 0) -> list[tuple[int, int]]:
    return [(index, (index + bias) & 0xFF) for index in range(length)]


def _recipe(*, partial_verified: bool = True) -> VerifiedKeyedWordRecipe:
    return VerifiedKeyedWordRecipe(
        method_token=0x06000044,
        method_body_sha256="a" * 64,
        seed=1_892_639_617,
        addend=775_421_640,
        partial_word_profile_verified=partial_verified,
    )


def test_ordered_writes_accept_deterministic_overwrite_final_state() -> None:
    writes = [(0, 1), (1, 2), (0, 9), (2, 3), (3, 4)]

    assert replay_ordered_byte_writes(4, writes) == bytes((9, 2, 3, 4))


@pytest.mark.parametrize(
    "writes,reason",
    [
        ([(0, 1)], "ordered_write_final_state_incomplete"),
        ([(0, 1), (1, 256)], "ordered_write_value_invalid"),
        ([(0, 1), (2, 2)], "ordered_write_value_invalid"),
    ],
)
def test_ordered_writes_reject_incomplete_or_nonbyte_values(
    writes: list[tuple[int, int]], reason: str
) -> None:
    with pytest.raises(ManagedPureRatCacheError, match=reason):
        replay_ordered_byte_writes(2, writes)


def test_referenced_cache_decodes_only_exact_nonoverlapping_offsets() -> None:
    first = "alpha".encode("utf-16le")
    second = "beta".encode("utf-16le")
    data = (
        struct.pack("<i", len(first)) + first + struct.pack("<i", len(second)) + second
    )
    second_offset = 4 + len(first)

    assert decode_complete_utf16_cache(data) == (
        (0, "alpha"),
        (second_offset, "beta"),
    )
    assert decode_referenced_utf16_cache(data, (0, second_offset)) == (
        "alpha",
        "beta",
    )
    with pytest.raises(ManagedPureRatCacheError, match="cache_offset_set_duplicate"):
        decode_referenced_utf16_cache(data, (0, 0))
    with pytest.raises(
        ManagedPureRatCacheError, match="cache_offset_not_entry_boundary"
    ):
        decode_referenced_utf16_cache(data, (1,))


def test_verified_model_recovers_partial_word_resource_without_raw_report() -> None:
    key_writes = _writes(32, bias=3) + [(0, 0xA5), (31, 0x5A)]
    mask_writes = _writes(16, bias=17) + [(0, 0x33)]
    key = replay_ordered_byte_writes(32, key_writes)
    mask = replay_ordered_byte_writes(16, mask_writes)
    first = "schema-candidate".encode("utf-16le")
    second = "1.2.3".encode("utf-16le")
    first_offset = 0
    second_offset = 4 + len(first)
    clear = (
        struct.pack("<i", len(first)) + first + struct.pack("<i", len(second)) + second
    )
    encrypted = decrypt_keyed_eaz_resource(
        clear,
        key,
        key_mask=mask[::-1],
        seed=_recipe().seed,
        addend=_recipe().addend,
        allow_partial_word=True,
    )

    report, values = recover_verified_cache_model(
        (("bound-resource", encrypted), ("unrelated", b"not-empty")),
        resource_name="bound-resource",
        key_writes=key_writes,
        mask_writes=mask_writes,
        referenced_offsets=(first_offset, second_offset),
        recipe=_recipe(),
    )

    assert values == ("schema-candidate", "1.2.3")
    assert report["status"] == "recovered_verified_referenced_utf16_cache"
    assert report["cache"]["decoded_string_count"] == 2
    assert report["cache"]["complete_table_entry_count"] == 2
    assert report["cache"]["complete_table_consumed"] is True
    assert report["cache"]["raw_strings_published"] is False
    assert report["family_attribution_allowed"] is False
    assert report["c2_confirmation_allowed"] is False
    assert report["provider_or_protector_label_used"] is False
    assert report["sample_executed"] is False
    assert report["network_contacted"] is False
    assert "schema-candidate" not in repr(report)


def test_verified_model_rejects_unverified_recipe_and_resource_ambiguity() -> None:
    arguments = {
        "resource_name": "same",
        "key_writes": _writes(32),
        "mask_writes": _writes(16),
        "referenced_offsets": (0,),
    }
    with pytest.raises(ManagedPureRatCacheError, match="transform_recipe_not_verified"):
        recover_verified_cache_model(
            (("same", b"abcd"),),
            recipe=_recipe(partial_verified=False),
            **arguments,
        )
    with pytest.raises(
        ManagedPureRatCacheError,
        match="resource_set_entry_invalid_or_ambiguous",
    ):
        recover_verified_cache_model(
            (("same", b"abcd"), ("same", b"efgh")),
            recipe=_recipe(),
            **arguments,
        )
