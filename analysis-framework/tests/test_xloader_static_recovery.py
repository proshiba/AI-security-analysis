"""XLoader多段静的復元と通常wrapper復元の統合を検証する。"""

from __future__ import annotations

import copy
import hashlib
import importlib
import json
import struct
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
FORMBOOK = ROOT / "analysis-framework" / "malware" / "formbook_loader"
sys.path.insert(0, str(FORMBOOK))

NATIVE = importlib.import_module("native_xloader")
PROTECTED = importlib.import_module("protected_functions")
STATIC = importlib.import_module("static_recovery")


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _call(source: int, target: int) -> bytes:
    return b"\xe8" + struct.pack("<i", target - (source + 5))


def _descriptor_material(
    *,
    name: str,
    seed: int,
    mix: int,
    start_marker: bytes,
    end_marker: bytes,
    base: tuple[int, ...],
    xor_constant: int,
) -> tuple[bytes, bytes, bytes]:
    descriptor = NATIVE.ProtectedFunctionDescriptor(
        name=name,
        seed=seed,
        mix=mix,
        encrypted_start_marker=b"",
        encrypted_end_marker=b"",
    )
    key = NATIVE.derive_protected_function_key(descriptor, base, xor_constant)
    return (
        key,
        NATIVE.encrypt_rc4_sub(start_marker, key),
        NATIVE.encrypt_rc4_sub(end_marker, key),
    )


def _wrapper(
    *,
    wrapper_start: int,
    decrypt_target: int,
    protected_target: int,
    seed: int,
    encrypted_start: bytes,
    encrypted_end: bytes,
) -> bytes:
    value = bytearray(b"\x55\x8b\xec")
    value += b"\xc7\x45\xc0" + struct.pack("<I", seed)
    value += b"\xc7\x45\xec" + encrypted_start[:4]
    value += b"\x66\xc7\x45\xf0" + encrypted_start[4:]
    value += b"\xc7\x45\xdc" + encrypted_end[:4]
    value += b"\x66\xc7\x45\xe0" + encrypted_end[4:]
    value += b"\x8b\x45\x08\x8b\x48\x04"
    value += b"\x89\x8d\x78\xff\xff\xff"
    value += _call(wrapper_start + len(value), decrypt_target)
    value += _call(wrapper_start + len(value), protected_target)
    value += b"\xc3"
    return bytes(value)


def _nested_fixture() -> dict[str, object]:
    base = (0x10203040, 0x50607080, 0x90A0B0C0, 0xD0E0F000, 0x12345678)
    xor_constant = 0x33333333
    decrypt_target = 0x100
    wrapper_a, wrapper_b, wrapper_c = 0x200, 0x300, 0x400
    target_a, marker_b, target_c = 0x700, 0x800, 0x906
    target_b = marker_b + 6
    mix_a, mix_b, mix_c = 0x11112222, 0x22223333, 0x33334444
    seeds = (0xA1A2A3A4, 0xB1B2B3B4, 0xC1C2C3C4)
    start_markers = (b"ASTART", b"BSTART", b"CSTART")
    end_markers = (b"AEND!!", b"BEND!!", b"CEND!!")
    materials = [
        _descriptor_material(
            name=f"wrapper-{index}",
            seed=seed,
            mix=mix,
            start_marker=start,
            end_marker=end,
            base=base,
            xor_constant=xor_constant,
        )
        for index, (seed, mix, start, end) in enumerate(
            zip(seeds, (mix_a, mix_b, mix_c), start_markers, end_markers), start=1
        )
    ]

    image = bytearray(b"\x90" * 0xD00)
    for offset, target, seed, material in zip(
        (wrapper_a, wrapper_b, wrapper_c),
        (target_a, target_b, target_c),
        seeds,
        materials,
    ):
        _, encrypted_start, encrypted_end = material
        value = _wrapper(
            wrapper_start=offset,
            decrypt_target=decrypt_target,
            protected_target=target,
            seed=seed,
            encrypted_start=encrypted_start,
            encrypted_end=encrypted_end,
        )
        image[offset : offset + len(value)] = value

    body_b = b"\x55\x8b\xec\x83\xec\x08\x33\xc0\xc3"
    key_b = materials[1][0]
    encrypted_b = NATIVE.encrypt_rc4_sub(body_b, key_b)
    protected_b = start_markers[1] + encrypted_b + end_markers[1]
    image[marker_b : marker_b + len(protected_b)] = protected_b

    body_c = b"\x55\x8b\xec\x33\xc0\xc3"
    image[target_c : target_c + len(body_c)] = body_c

    inner_marker_start = b"INSTAR"
    inner_marker_end = b"INEND!"
    inner_seed = seeds[0]
    inner_mix = mix_a
    inner_key, encrypted_inner_start, encrypted_inner_end = _descriptor_material(
        name="nested-a",
        seed=inner_seed,
        mix=inner_mix,
        start_marker=inner_marker_start,
        end_marker=inner_marker_end,
        base=base,
        xor_constant=xor_constant,
    )
    code_a = bytearray(b"\x55\x8b\xec")
    code_a += b"\xc7\x45\xc0" + struct.pack("<I", 0xAABBCCDD)
    code_a += b"\xc7\x45\xc4" + struct.pack("<I", mix_b)
    code_a += b"\x8d\x45\xc0\x50"
    code_a_start = target_a + len(inner_marker_start)
    code_a += _call(code_a_start + len(code_a), wrapper_b)
    code_a += b"\xc3"
    encrypted_code_a = NATIVE.encrypt_rc4_sub(bytes(code_a), inner_key)
    completed = inner_marker_start + encrypted_code_a + inner_marker_end
    final_patch = b"\x90" * len(inner_marker_start) + bytes(code_a) + b"\x90" * len(inner_marker_end)

    outer_key = b"synthetic-injection-key"
    outer_second_key = b"synthetic-network-key"
    outer_start = b"OUTER<"
    outer_end = b">OUTER"
    outer_payload = NATIVE.encrypt_rc4_sub(completed, outer_second_key)
    outer_payload = NATIVE.encrypt_rc4_sub(outer_payload, outer_key)
    outer_offset = 0xA00
    outer_container = outer_start + outer_payload + outer_end
    image[outer_offset : outer_offset + len(outer_container)] = outer_container
    protected_image = bytes(image)

    stage_output = bytearray(protected_image)
    stage_output[target_a : target_a + len(final_patch)] = final_patch
    stage_output_bytes = bytes(stage_output)
    nested_profile = {
        "schema_version": 1,
        "profile_type": "xloader_nested_static_recovery",
        "expected_input_sha256": _sha256(protected_image),
        "expected_final_sha256": _sha256(stage_output_bytes),
        "stages": [
            {
                "id": "synthetic_nested_a",
                "parent_sha256": _sha256(protected_image),
                "expected_output_sha256": _sha256(stage_output_bytes),
                "target_offset": target_a,
                "patch_start": target_a,
                "patch_end": target_a + len(final_patch),
                "source_kind": "static_nested_container",
                "outer_container": {
                    "start_marker_hex": outer_start.hex(),
                    "end_marker_hex": outer_end.hex(),
                    "payload_start_delta": len(outer_start),
                    "payload_end_delta": 0,
                    "decrypted_prefix_hex": "",
                    "ordered_transforms": [
                        {"algorithm": "rc4_sub", "key_hex": outer_key.hex()},
                        {"algorithm": "rc4_sub", "key_hex": outer_second_key.hex()},
                    ],
                },
                "inner_function": {
                    "seed": inner_seed,
                    "mix": inner_mix,
                    "encrypted_start_marker_hex": encrypted_inner_start.hex(),
                    "encrypted_end_marker_hex": encrypted_inner_end.hex(),
                    "marker_order": "start_then_end",
                    "marker_size": len(inner_marker_start),
                    "base_key_dwords": list(base),
                    "xor_constant": xor_constant,
                    "expected_patch_sha256": _sha256(final_patch),
                },
            }
        ],
        "known_mix_candidates": [
            {
                "wrapper_start": wrapper_b,
                "protected_target": target_b,
                "mix": mix_b,
                "expected_body_sha256": _sha256(body_b),
            }
        ],
    }
    regular_report = {
        "schema_version": 1,
        "analysis_type": "xloader_protected_function_static_recovery",
        "input_sha256": _sha256(protected_image),
        "output_sha256": _sha256(protected_image),
        "profile_sha256": "a" * 64,
        "wrapper_count": 3,
        "recovered_count": 1,
        "unresolved_count": 2,
        "functions": [
            {
                "wrapper_start": wrapper_c,
                "protected_target": target_c,
                "function_start": target_c,
                "function_end": target_c + len(body_c),
                "body_sha256": _sha256(body_c),
                "method": "caller_dataflow",
            }
        ],
        "unresolved": [
            {"wrapper_start": wrapper_a, "protected_target": target_a},
            {"wrapper_start": wrapper_b, "protected_target": target_b},
        ],
    }
    profile = PROTECTED.ProtectedFunctionProfile(
        base_key_dwords=base,
        xor_constant=xor_constant,
        decrypt_call_targets=frozenset({decrypt_target}),
        restore_targets=frozenset(),
        minimum_x86_score=1,
    )
    return {
        "protected_image": protected_image,
        "regular_report": regular_report,
        "profile": profile,
        "nested_profile": nested_profile,
        "body_b": body_b,
        "body_c": body_c,
        "wrapper_a": wrapper_a,
        "wrapper_b": wrapper_b,
        "target_a": target_a,
        "outer_key": outer_key,
        "outer_second_key": outer_second_key,
        "encrypted_inner_start": encrypted_inner_start,
        "inner_mix": inner_mix,
    }


def _overlay_stage(
    fixture: dict[str, object],
    *,
    patch_start: int | None = None,
) -> object:
    output, patches, _ = STATIC.recover_nested_static_stages(fixture["protected_image"], fixture["nested_profile"])
    patch = patches[0]
    start = patch.patch_start if patch_start is None else patch_start
    return STATIC.StaticRecoveryStage(
        image=output,
        report={
            "schema_version": 1,
            "analysis_type": "xloader_static_recovery_stage",
            "parent_sha256": _sha256(fixture["protected_image"]),
            "output_sha256": _sha256(output),
            "patches": [
                {
                    "wrapper_start": fixture["wrapper_a"],
                    "protected_target": fixture["target_a"],
                    "patch_start": start,
                    "patch_end": patch.patch_end,
                    "function_start": patch.target_offset,
                    "function_end": patch.patch_end,
                    "body_sha256": _sha256(output[patch.target_offset : patch.patch_end]),
                }
            ],
        },
    )


def test_nested_reconcile_promotes_dependent_wrapper_and_hides_secrets() -> None:
    fixture = _nested_fixture()
    regular_image = fixture["protected_image"]
    output, report = STATIC.reconcile_nested_static_profile(
        regular_image,
        fixture["regular_report"],
        fixture["protected_image"],
        fixture["nested_profile"],
        fixture["profile"],
        profile_sha256="a" * 64,
        nested_profile_sha256="b" * 64,
    )

    assert report["recovered_count"] == 3
    assert report["unresolved_count"] == 0
    assert report["regular_recovered_count"] == 1
    assert report["external_static_recovered_count"] == 1
    assert report["post_stage_regular_recovered_count"] == 1
    assert report["private_candidate_recovered_count"] == 0
    assert fixture["body_b"] in output
    assert fixture["body_c"] in output
    by_wrapper = {row["wrapper_start"]: row for row in report["functions"]}
    assert by_wrapper[fixture["wrapper_b"]]["method"].startswith("post_stage_")
    candidate = report["private_candidate_results"][0]
    assert candidate["wrapper_start"] == f"0x{fixture['wrapper_b']:x}"
    assert candidate["protected_target"] == (f"0x{by_wrapper[fixture['wrapper_b']]['protected_target']:x}")
    assert candidate["body_sha256"] == by_wrapper[fixture["wrapper_b"]]["body_sha256"]
    assert candidate["status"] == "already_recovered"

    published = json.dumps(report, ensure_ascii=False)
    assert report["nested_static_recovery"]["stages"][0]["id"] == "stage-001"
    assert "synthetic_nested_a" not in published
    assert fixture["outer_key"].hex() not in published
    assert fixture["outer_second_key"].hex() not in published
    assert fixture["encrypted_inner_start"].hex() not in published
    assert str(fixture["inner_mix"]) not in published
    assert "key_hex" not in published
    assert "marker_hex" not in published
    assert report["safety"]["secret_material_published"] is False


def test_nested_two_outer_transforms_recover_inner_function_in_declared_order() -> None:
    fixture = _nested_fixture()

    output, patches, report = STATIC.recover_nested_static_stages(
        fixture["protected_image"],
        fixture["nested_profile"],
        profile_sha256="b" * 64,
    )

    assert len(patches) == 1
    patch = patches[0]
    assert patch.target_offset == fixture["target_a"]
    assert output[patch.patch_start : patch.patch_end] == patch.body
    assert _sha256(patch.body) == patch.body_sha256
    assert report["status"] == "complete"
    assert report["stage_count"] == 1
    published = json.dumps(report, ensure_ascii=False)
    assert fixture["outer_key"].hex() not in published
    assert fixture["outer_second_key"].hex() not in published


def test_nested_two_outer_transforms_wrong_order_fails_closed() -> None:
    fixture = _nested_fixture()
    profile = copy.deepcopy(fixture["nested_profile"])
    transforms = profile["stages"][0]["outer_container"]["ordered_transforms"]
    transforms.reverse()

    with pytest.raises(STATIC.StaticRecoveryError):
        STATIC.recover_nested_static_stages(fixture["protected_image"], profile)


def test_nested_outer_payload_boundary_fails_closed() -> None:
    fixture = _nested_fixture()
    profile = copy.deepcopy(fixture["nested_profile"])
    outer = profile["stages"][0]["outer_container"]
    outer["payload_start_delta"] = len(bytes.fromhex(outer["start_marker_hex"])) - 1

    with pytest.raises(STATIC.StaticRecoveryError, match="marker"):
        STATIC.recover_nested_static_stages(fixture["protected_image"], profile)


def test_nested_inner_patch_hash_mismatch_fails_closed() -> None:
    fixture = _nested_fixture()
    profile = copy.deepcopy(fixture["nested_profile"])
    profile["stages"][0]["inner_function"]["expected_patch_sha256"] = "0" * 64

    with pytest.raises(STATIC.StaticRecoveryError, match="patch SHA-256"):
        STATIC.recover_nested_static_stages(fixture["protected_image"], profile)


def test_nested_profile_wrong_parent_hash_fails_closed() -> None:
    fixture = _nested_fixture()
    profile = copy.deepcopy(fixture["nested_profile"])
    profile["stages"][0]["parent_sha256"] = "0" * 64

    with pytest.raises(STATIC.StaticRecoveryError, match="parent SHA-256"):
        STATIC.recover_nested_static_stages(fixture["protected_image"], profile)


def test_nested_profile_duplicate_stage_id_fails_closed() -> None:
    fixture = _nested_fixture()
    profile = copy.deepcopy(fixture["nested_profile"])
    profile["stages"].append(copy.deepcopy(profile["stages"][0]))

    with pytest.raises(STATIC.StaticRecoveryError, match="重複stage.id"):
        STATIC.recover_nested_static_stages(fixture["protected_image"], profile)


def test_nested_outer_marker_ambiguity_fails_closed() -> None:
    fixture = _nested_fixture()
    profile = copy.deepcopy(fixture["nested_profile"])
    image = bytearray(fixture["protected_image"])
    marker = bytes.fromhex(profile["stages"][0]["outer_container"]["start_marker_hex"])
    image[0xC00 : 0xC00 + len(marker)] = marker
    mutated = bytes(image)
    profile["expected_input_sha256"] = _sha256(mutated)
    profile["stages"][0]["parent_sha256"] = _sha256(mutated)

    with pytest.raises(STATIC.StaticRecoveryError, match="一意"):
        STATIC.recover_nested_static_stages(mutated, profile)


def test_nested_reconcile_rejects_same_length_wrong_base_lineage() -> None:
    fixture = _nested_fixture()
    report = copy.deepcopy(fixture["regular_report"])
    report["input_sha256"] = "0" * 64

    with pytest.raises(STATIC.StaticRecoveryError, match="多段復元入力像"):
        STATIC.reconcile_nested_static_profile(
            fixture["protected_image"],
            report,
            fixture["protected_image"],
            fixture["nested_profile"],
            fixture["profile"],
            profile_sha256="a" * 64,
            nested_profile_sha256="b" * 64,
        )


def test_stage_rejects_partial_overlap_with_wrapper_instruction_range() -> None:
    fixture = _nested_fixture()
    stage = _overlay_stage(
        fixture,
        patch_start=fixture["wrapper_a"] + 1,
    )

    with pytest.raises(STATIC.StaticRecoveryError, match="命令区間"):
        STATIC.reconcile_static_recovery(
            fixture["protected_image"],
            fixture["regular_report"],
            [stage],
            fixture["profile"],
            profile_sha256="a" * 64,
        )


def test_regular_pass_rejects_same_count_different_wrapper_set(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _nested_fixture()
    stage = _overlay_stage(fixture)
    source_rows = [
        *fixture["regular_report"]["functions"],
        *fixture["regular_report"]["unresolved"],
    ]

    def fake_recovery(
        data: bytes,
        _profile: object,
        **options: object,
    ) -> tuple[bytes, dict[str, object]]:
        unresolved = []
        for index, row in enumerate(source_rows):
            unresolved.append(
                {
                    "wrapper_start": (row["wrapper_start"] + 1 if index == 0 else row["wrapper_start"]),
                    "protected_target": row["protected_target"],
                }
            )
        output_sha256 = _sha256(data)
        return data, {
            "schema_version": 1,
            "analysis_type": "xloader_protected_function_static_recovery",
            "input_sha256": output_sha256,
            "output_sha256": output_sha256,
            "profile_sha256": options.get("profile_sha256"),
            "wrapper_count": len(unresolved),
            "recovered_count": 0,
            "unresolved_count": len(unresolved),
            "functions": [],
            "unresolved": unresolved,
        }

    monkeypatch.setattr(STATIC, "recover_protected_functions", fake_recovery)
    with pytest.raises(STATIC.StaticRecoveryError, match="start/target集合"):
        STATIC.reconcile_static_recovery(
            fixture["protected_image"],
            fixture["regular_report"],
            [stage],
            fixture["profile"],
            profile_sha256="a" * 64,
        )


def test_profile_hash_arguments_require_lower_hex() -> None:
    fixture = _nested_fixture()

    with pytest.raises(STATIC.StaticRecoveryError, match="SHA-256"):
        STATIC.reconcile_static_recovery(
            fixture["protected_image"],
            fixture["regular_report"],
            [],
            fixture["profile"],
            profile_sha256="A" * 64,
        )
    with pytest.raises(STATIC.StaticRecoveryError, match="SHA-256"):
        STATIC.recover_nested_static_stages(
            fixture["protected_image"],
            fixture["nested_profile"],
            profile_sha256="B" * 64,
        )


def test_known_mix_candidate_recovers_unreferenced_wrapper_without_leak() -> None:
    base = (1, 2, 3, 4, 5)
    xor_constant = 0x12345678
    seed = 0x11111111
    mix = 0x76543210
    decrypt_target = 0x100
    wrapper_start = 0x200
    marker_offset = 0x500
    target = marker_offset + 6
    start_marker, end_marker = b"START!", b"!END!!"
    key, encrypted_start, encrypted_end = _descriptor_material(
        name="known-mix",
        seed=seed,
        mix=mix,
        start_marker=start_marker,
        end_marker=end_marker,
        base=base,
        xor_constant=xor_constant,
    )
    body = b"\x55\x8b\xec\x33\xc0\xc3"
    image = bytearray(b"\x90" * 0x800)
    wrapper = _wrapper(
        wrapper_start=wrapper_start,
        decrypt_target=decrypt_target,
        protected_target=target,
        seed=seed,
        encrypted_start=encrypted_start,
        encrypted_end=encrypted_end,
    )
    image[wrapper_start : wrapper_start + len(wrapper)] = wrapper
    protected = start_marker + NATIVE.encrypt_rc4_sub(body, key) + end_marker
    image[marker_offset : marker_offset + len(protected)] = protected
    image_bytes = bytes(image)
    report = {
        "schema_version": 1,
        "analysis_type": "xloader_protected_function_static_recovery",
        "input_sha256": _sha256(image_bytes),
        "output_sha256": _sha256(image_bytes),
        "profile_sha256": None,
        "wrapper_count": 1,
        "recovered_count": 0,
        "unresolved_count": 1,
        "functions": [],
        "unresolved": [{"wrapper_start": wrapper_start, "protected_target": target}],
    }
    profile = PROTECTED.ProtectedFunctionProfile(
        base_key_dwords=base,
        xor_constant=xor_constant,
        decrypt_call_targets=frozenset({decrypt_target}),
        restore_targets=frozenset(),
        minimum_x86_score=1,
    )
    with pytest.raises(STATIC.StaticRecoveryError, match="SHA-256"):
        STATIC.reconcile_static_recovery(
            image_bytes,
            report,
            [],
            profile,
            known_mix_candidates=[
                {
                    "wrapper_start": wrapper_start,
                    "mix": mix,
                }
            ],
        )

    output, public = STATIC.reconcile_static_recovery(
        image_bytes,
        report,
        [],
        profile,
        known_mix_candidates=[
            {
                "wrapper_start": wrapper_start,
                "mix": mix,
                "expected_body_sha256": _sha256(body),
            }
        ],
    )

    assert body in output
    assert public["private_candidate_recovered_count"] == 1
    assert public["functions"][0]["method"] == "private_candidate_static_recovery"
    assert str(mix) not in json.dumps(public, ensure_ascii=False)


def test_output_paths_reject_input_and_output_aliases(tmp_path: Path) -> None:
    input_path = tmp_path / "input.bin"
    output_path = tmp_path / "output.bin"
    input_path.write_bytes(b"input")

    with pytest.raises(STATIC.StaticRecoveryError, match="入力path"):
        STATIC._validated_output_paths(
            [input_path],
            [input_path, output_path],
        )
    with pytest.raises(STATIC.StaticRecoveryError, match="出力path"):
        STATIC._validated_output_paths(
            [input_path],
            [output_path, output_path],
        )


def test_output_paths_reject_symlink_alias_when_supported(tmp_path: Path) -> None:
    input_path = tmp_path / "input.bin"
    alias_path = tmp_path / "input-alias.bin"
    output_path = tmp_path / "output.bin"
    input_path.write_bytes(b"input")
    try:
        alias_path.symlink_to(input_path)
    except OSError:
        pytest.skip("この環境ではsymlink作成権限がありません")

    with pytest.raises(STATIC.StaticRecoveryError, match="入力path"):
        STATIC._validated_output_paths(
            [input_path],
            [alias_path, output_path],
        )


def test_atomic_write_failure_preserves_existing_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = tmp_path / "result.json"
    output.write_bytes(b"original")

    def fail_replace(_source: object, _target: object) -> None:
        raise OSError("synthetic replace failure")

    monkeypatch.setattr(STATIC.os, "replace", fail_replace)
    with pytest.raises(OSError, match="synthetic"):
        STATIC._atomic_write_bytes(output, b"replacement")

    assert output.read_bytes() == b"original"
    assert not list(tmp_path.glob(".result.json.*.tmp"))


def test_output_paths_reject_existing_hardlink_aliases(tmp_path: Path) -> None:
    input_path = tmp_path / "input.bin"
    input_alias = tmp_path / "input-alias.bin"
    output_path = tmp_path / "output.bin"
    output_alias = tmp_path / "output-alias.bin"
    input_path.write_bytes(b"input")
    output_path.write_bytes(b"output")
    try:
        input_alias.hardlink_to(input_path)
        output_alias.hardlink_to(output_path)
    except OSError:
        pytest.skip("hardlink creation is unavailable")

    with pytest.raises(STATIC.StaticRecoveryError, match="path"):
        STATIC._validated_output_paths(
            [input_path],
            [input_alias, output_path],
        )
    with pytest.raises(STATIC.StaticRecoveryError, match="path"):
        STATIC._validated_output_paths(
            [input_path],
            [output_path, output_alias],
        )
