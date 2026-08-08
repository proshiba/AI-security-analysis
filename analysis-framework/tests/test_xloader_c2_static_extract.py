"""XLoader C2 seedのlineage固定静的抽出器テスト。"""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
MODULE_DIR = ROOT / "analysis-framework" / "malware" / "formbook_loader"


def _load_module(name: str, filename: str):  # type: ignore[no-untyped-def]
    spec = importlib.util.spec_from_file_location(name, MODULE_DIR / filename)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


NATIVE = _load_module("native_xloader", "native_xloader.py")
C2 = _load_module("xloader_c2", "xloader_c2.py")
EXTRACT = _load_module("c2_static_extract", "c2_static_extract.py")


IMAGE = b"synthetic recovered xloader image"
BASE_KEY = b"base-key-material-that-stays-private"
PRIMARY_OFFSETS = tuple(0x1000 + index * 0x10 for index in range(64))
ISOLATED_OFFSETS = (0x3000,)
HELPER_OFFSETS = tuple(0x4000 + index * 0x10 for index in range(4))
API_OFFSETS = tuple(0x5000 + index * 0x10 for index in range(4))
ALL_OFFSETS = PRIMARY_OFFSETS + ISOLATED_OFFSETS + HELPER_OFFSETS + API_OFFSETS


def _encoded(index: int) -> bytes:
    return base64.b64encode(f"builder-value-{index:03d}".encode("ascii"))


def _builders(values: list[bytes] | None = None):  # type: ignore[no-untyped-def]
    encoded_values = values or [_encoded(index) for index in range(73)]
    return [
        NATIVE.DecodedBuilder(offset, index & 0xFF, encoded_values[index]) for index, offset in enumerate(ALL_OFFSETS)
    ]


def _profile(**changes):  # type: ignore[no-untyped-def]
    values = {
        "name": "synthetic-v8-lineage",
        "expected_input_sha256": hashlib.sha256(IMAGE).hexdigest(),
        "decrypt_call_target": 0x80,
        "primary_candidate_offsets": PRIMARY_OFFSETS,
        "isolated_bootstrap_offsets": ISOLATED_OFFSETS,
        "helper_offsets": HELPER_OFFSETS,
        "api_offsets": API_OFFSETS,
        "max_primary_gap": 0x20,
        "expected_fingerprints": {},
    }
    values.update(changes)
    return EXTRACT.LineageProfile(**values)


def _install_builder_result(monkeypatch: pytest.MonkeyPatch, builders):  # type: ignore[no-untyped-def]
    calls: list[tuple[bytes, int, bytes]] = []

    def fake_decode(image: bytes, target: int, key: bytes):  # type: ignore[no-untyped-def]
        calls.append((image, target, key))
        return builders

    monkeypatch.setattr(EXTRACT, "decode_stack_string_builders", fake_decode)
    return calls


def test_extract_uses_native_builder_result_and_classifies_64_plus_1(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = _install_builder_result(monkeypatch, _builders())

    report = EXTRACT.extract_static_c2_inventory(IMAGE, BASE_KEY, _profile())

    assert calls == [(IMAGE, 0x80, BASE_KEY)]
    assert report["input_sha256"] == hashlib.sha256(IMAGE).hexdigest()
    assert report["observed_counts"] == {
        "decoded_builder_total": 73,
        "classified_base64_builders": 73,
        "primary_candidate_seed": 64,
        "isolated_bootstrap_seed": 1,
        "classified_network_material_total": 65,
        "excluded_helper": 4,
        "excluded_api": 4,
    }
    assert len(report["groups"]["primary_candidate_seed"]) == 64
    bootstrap = report["groups"]["isolated_bootstrap_seed"][0]
    assert "candidate_index" not in bootstrap
    assert report["raw_candidate_retained"] is False
    assert report["sample_executed"] is False
    assert report["network_contacted"] is False
    assert report["real_c2_static_decidable"] is False


def test_non_base64_normal_builders_are_ignored(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    builders = _builders()
    builders.append(NATIVE.DecodedBuilder(0x6000, 0, b"ordinary.dll"))
    _install_builder_result(monkeypatch, builders)

    report = EXTRACT.extract_static_c2_inventory(IMAGE, BASE_KEY, _profile())

    assert report["observed_counts"]["decoded_builder_total"] == 74
    assert report["observed_counts"]["classified_base64_builders"] == 73


def test_lineage_sha_mismatch_fails_before_builder_decode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = _install_builder_result(monkeypatch, _builders())
    profile = _profile(expected_input_sha256="0" * 64)

    with pytest.raises(EXTRACT.StaticC2ExtractionError, match="SHA-256"):
        EXTRACT.extract_static_c2_inventory(IMAGE, BASE_KEY, profile)

    assert calls == []


def test_builder_count_mismatch_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_builder_result(monkeypatch, _builders()[:-1])

    with pytest.raises(EXTRACT.StaticC2ExtractionError, match="73"):
        EXTRACT.extract_static_c2_inventory(IMAGE, BASE_KEY, _profile())


def test_unknown_address_cannot_be_ambiguously_classified(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    builders = _builders()
    builders[-1] = NATIVE.DecodedBuilder(0xDEAD, 0, _encoded(72))
    _install_builder_result(monkeypatch, builders)

    with pytest.raises(EXTRACT.StaticC2ExtractionError, match="address"):
        EXTRACT.extract_static_c2_inventory(IMAGE, BASE_KEY, _profile())


def test_profile_overlap_is_rejected_as_ambiguous() -> None:
    profile = _profile(api_offsets=(HELPER_OFFSETS[0],) + API_OFFSETS[1:])

    with pytest.raises(EXTRACT.StaticC2ExtractionError, match="曖昧"):
        profile.validate()


def test_duplicate_builder_offset_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    builders = _builders()
    builders[-1] = NATIVE.DecodedBuilder(builders[-2].function_offset, 0, _encoded(72))
    _install_builder_result(monkeypatch, builders)

    with pytest.raises(EXTRACT.StaticC2ExtractionError, match="重複"):
        EXTRACT.extract_static_c2_inventory(IMAGE, BASE_KEY, _profile())


@pytest.mark.parametrize("field", ["decoded_length", "decoded_sha256"])
def test_expected_fingerprint_mismatch_is_rejected(monkeypatch: pytest.MonkeyPatch, field: str) -> None:
    builders = _builders()
    actual = builders[0]
    fingerprint = EXTRACT.BuilderFingerprint(
        decoded_length=(len(actual.decoded) + 4 if field == "decoded_length" else len(actual.decoded)),
        decoded_sha256=("f" * 64 if field == "decoded_sha256" else hashlib.sha256(actual.decoded).hexdigest()),
    )
    _install_builder_result(monkeypatch, builders)

    with pytest.raises(EXTRACT.StaticC2ExtractionError, match="decoded"):
        EXTRACT.extract_static_c2_inventory(
            IMAGE,
            BASE_KEY,
            _profile(expected_fingerprints={PRIMARY_OFFSETS[0]: fingerprint}),
        )


def test_non_base64_builder_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    builders = _builders()
    builders[10] = NATIVE.DecodedBuilder(PRIMARY_OFFSETS[10], 0, b"not base64!")
    _install_builder_result(monkeypatch, builders)

    with pytest.raises(EXTRACT.StaticC2ExtractionError, match="Base64"):
        EXTRACT.extract_static_c2_inventory(IMAGE, BASE_KEY, _profile())


def _layered_values(first_key: bytes, second_key: bytes) -> list[bytes]:
    values: list[bytes] = []
    for index in range(64):
        plaintext = f"node{index:02d}.example.test:443".encode("ascii") + b"\x00"
        first_layer = NATIVE.encrypt_rc4_sub(plaintext, second_key)
        values.append(base64.b64encode(NATIVE.encrypt_rc4_sub(first_layer, first_key)))
    values.append(_encoded(64))
    values.extend(_encoded(index + 65) for index in range(8))
    return values


def test_reviewed_batch_recovery_is_hash_only_in_public_and_raw_in_private(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    first_key = b"reviewed-first-layer-key"
    second_key = b"reviewed-second-layer-key"
    values = _layered_values(first_key, second_key)
    _install_builder_result(monkeypatch, _builders(values))
    plan = EXTRACT.ReviewedLayeredKeyPlan(
        reviewed=True,
        review_basis="Ghidra dataflowで確認した合成test鍵",
        first_layer=EXTRACT.KeyDerivationSpec(key=first_key),
        second_layer=EXTRACT.KeyDerivationSpec(key=second_key),
    )
    private_output = tmp_path / "private-candidates.json"

    report = EXTRACT.extract_static_c2_inventory(
        IMAGE,
        BASE_KEY,
        _profile(),
        layered_key_plan=plan,
        private_output_path=private_output,
    )

    public_text = json.dumps(report, ensure_ascii=False)
    assert report["layered_recovery"]["candidate_count"] == 64
    assert report["layered_recovery"]["guessed_key_promoted"] is False
    assert all(record["endpoint_candidate"] is True for record in report["layered_recovery"]["records"])
    assert values[0].decode("ascii") not in public_text
    assert first_key.decode("ascii") not in public_text
    assert second_key.decode("ascii") not in public_text
    assert "node00.example.test" not in public_text
    private_text = private_output.read_text(encoding="utf-8")
    assert values[0].hex() in private_text
    assert b"node00.example.test:443\x00".hex() in private_text


def _layered_encoded(plaintext: bytes, first_key: bytes, second_key: bytes) -> bytes:
    first_layer = NATIVE.encrypt_rc4_sub(plaintext, second_key)
    return base64.b64encode(NATIVE.encrypt_rc4_sub(first_layer, first_key))


def _record_recovery_fixture():  # type: ignore[no-untyped-def]
    primary_first = b"primary-first-reviewed"
    primary_second = b"primary-second-reviewed"
    bootstrap_first = b"bootstrap-first-reviewed"
    bootstrap_second = b"bootstrap-second-reviewed"
    all_primary_suffixes = {
        selector: f"node{selector:02d}.example.test" for selector in range(1, 65)
    }
    bootstrap_endpoint = "bootstrap.example.test"
    values = [
        _layered_encoded(endpoint.encode("ascii"), primary_first, primary_second)
        for endpoint in all_primary_suffixes.values()
    ]
    values.append(
        _layered_encoded(bootstrap_endpoint.encode("ascii"), bootstrap_first, bootstrap_second)
    )
    values.extend(_encoded(index + 65) for index in range(8))
    primary_plan = EXTRACT.ReviewedLayeredKeyPlan(
        reviewed=True,
        review_basis="primary 64 dataflowを静的確認",
        first_layer=EXTRACT.KeyDerivationSpec(key=primary_first),
        second_layer=EXTRACT.KeyDerivationSpec(key=primary_second),
    )
    bootstrap_plan = EXTRACT.ReviewedLayeredKeyPlan(
        reviewed=True,
        review_basis="isolated bootstrap dataflowを静的確認",
        first_layer=EXTRACT.KeyDerivationSpec(key=bootstrap_first),
        second_layer=EXTRACT.KeyDerivationSpec(key=bootstrap_second),
    )
    selectors = tuple(range(1, 17))
    all_path_tokens = {selector: f"p{selector - 1:03d}" for selector in range(1, 65)}
    record_plan = EXTRACT.ReviewedInitialRecordPlan(
        reviewed=True,
        review_basis="0x6b50と0x1a80のselector/path対応を静的確認",
        selector_sequence=selectors,
        path_tokens=tuple(f"/{all_path_tokens[selector]}/" for selector in selectors),
        primary_prefix="www.",
        primary_suffixes={selector: all_primary_suffixes[selector] for selector in selectors},
        all_path_tokens=all_path_tokens,
        expected_ordered_path_inventory_sha256=EXTRACT._ordered_inventory_sha256(
            [all_path_tokens[selector] for selector in range(1, 65)]
        ),
        expected_ordered_primary_suffix_inventory_sha256=EXTRACT._ordered_inventory_sha256(list(all_primary_suffixes.values())),
        bootstrap_record_index=12,
        bootstrap_endpoint=bootstrap_endpoint,
        logical_payload_prefix="dat=",
    )
    return values, primary_plan, bootstrap_plan, record_plan


def test_bootstrap_and_initial_record_table_are_structurally_verified(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    values, primary_plan, bootstrap_plan, record_plan = _record_recovery_fixture()
    _install_builder_result(monkeypatch, _builders(values))

    report = EXTRACT.extract_static_c2_inventory(
        IMAGE,
        BASE_KEY,
        _profile(),
        layered_key_plan=primary_plan,
        bootstrap_key_plan=bootstrap_plan,
        initial_record_plan=record_plan,
    )

    table = report["initial_record_table"]
    assert report["real_c2_static_decidable"] is True
    assert report["static_decidable_scope"] == "bootstrap_only"
    assert table["record_count"] == 16
    assert table["confirmed_static_bootstrap_c2_count"] == 1
    assert table["records"][0]["request_target"] == "www.node01.example.test/p000/"
    assert table["primary_suffix_inventory"]["count"] == 64
    assert table["path_token_inventory"]["unique_count"] == 64
    bootstrap = table["records"][12]
    assert bootstrap["selector"] == 13
    assert bootstrap["endpoint"] == "bootstrap.example.test"
    assert bootstrap["request_target"] == "bootstrap.example.test/p012/"
    assert bootstrap["url"] == "http://bootstrap.example.test/p012/"
    assert table["bootstrap_url"] == bootstrap["url"]
    assert bootstrap["superseded_primary_endpoint"] == "www.node13.example.test"
    assert report["bootstrap_recovery"]["record"]["structural_role_verified"] is True
    assert report["bootstrap_recovery"]["record"]["real_c2_static_decidable"] is True
    assert report["bootstrap_recovery"]["record"]["static_decidable_scope"] == "bootstrap_only"
    assert report["bootstrap_recovery"]["record"]["network_liveness_verified"] is False
    protocol = table["request_protocol"]
    assert protocol["methods_by_request_type"] == {"6": "GET", "10": "GET", "default": "POST"}
    assert protocol["logical_envelope"]["prefix"] == "dat="
    assert protocol["wire_post"]["body_prefix_model"] == "<dynamic_8char_parameter_name>="
    assert protocol["headers"]["Accept-Encoding"] == "gzip, deflate, br"
    assert protocol["record_key_derivation"] == "SHA-1(hostname + path)、20 byte"


def test_initial_record_plan_requires_both_key_plans(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    values, primary_plan, _, record_plan = _record_recovery_fixture()
    _install_builder_result(monkeypatch, _builders(values))

    with pytest.raises(EXTRACT.StaticC2ExtractionError, match="両方"):
        EXTRACT.extract_static_c2_inventory(
            IMAGE,
            BASE_KEY,
            _profile(),
            layered_key_plan=primary_plan,
            initial_record_plan=record_plan,
        )


def test_initial_record_plan_endpoint_mismatch_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    values, primary_plan, bootstrap_plan, record_plan = _record_recovery_fixture()
    bad_suffixes = dict(record_plan.primary_suffixes)
    bad_suffixes[1] = "wrong.example.test"
    bad_plan = EXTRACT.ReviewedInitialRecordPlan(
        reviewed=True,
        review_basis=record_plan.review_basis,
        selector_sequence=record_plan.selector_sequence,
        path_tokens=record_plan.path_tokens,
        primary_prefix=record_plan.primary_prefix,
        primary_suffixes=bad_suffixes,
        bootstrap_record_index=record_plan.bootstrap_record_index,
        all_path_tokens=record_plan.all_path_tokens,
        expected_ordered_path_inventory_sha256=record_plan.expected_ordered_path_inventory_sha256,
        expected_ordered_primary_suffix_inventory_sha256=record_plan.expected_ordered_primary_suffix_inventory_sha256,
        bootstrap_endpoint=record_plan.bootstrap_endpoint,
    )
    _install_builder_result(monkeypatch, _builders(values))

    with pytest.raises(EXTRACT.StaticC2ExtractionError, match="一致しません"):
        EXTRACT.extract_static_c2_inventory(
            IMAGE,
            BASE_KEY,
            _profile(),
            layered_key_plan=primary_plan,
            bootstrap_key_plan=bootstrap_plan,
            initial_record_plan=bad_plan,
        )


def test_private_output_inside_repository_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_builder_result(monkeypatch, _builders())
    forbidden = ROOT / ".work" / "forbidden-private-candidates.json"

    with pytest.raises(EXTRACT.StaticC2ExtractionError, match="repository外"):
        EXTRACT.extract_static_c2_inventory(IMAGE, BASE_KEY, _profile(), private_output_path=forbidden)

    assert not forbidden.exists()

def test_atomic_json_write_preserves_legacy_tmp_sibling(tmp_path: Path) -> None:
    output = tmp_path / "result.json"
    legacy_tmp = tmp_path / "result.json.tmp"
    sentinel = b"do-not-overwrite"
    legacy_tmp.write_bytes(sentinel)

    EXTRACT._write_json(output, {"schema_version": 1})

    assert legacy_tmp.read_bytes() == sentinel
    assert json.loads(output.read_text(encoding="utf-8")) == {"schema_version": 1}



def test_unreviewed_key_plan_is_never_promoted() -> None:
    plan = EXTRACT.ReviewedLayeredKeyPlan(
        reviewed=False,
        review_basis="推測",
        first_layer=EXTRACT.KeyDerivationSpec(key=b"first"),
        second_layer=EXTRACT.KeyDerivationSpec(key=b"second"),
    )

    with pytest.raises(EXTRACT.StaticC2ExtractionError, match="reviewed=true"):
        plan.validate()


def test_key_plan_mapping_rejects_typo_and_supports_explicit_salt() -> None:
    seed = bytes(range(20))
    plan = EXTRACT.layered_key_plan_from_mapping(
        {
            "reviewed": True,
            "review_basis": "逆コンパイルで確認",
            "candidate_index_base": 1,
            "first_layer": {
                "seed_hex": seed.hex(),
                "index_mode": "byte",
            },
            "second_layer": {
                "seed_hex": seed.hex(),
                "salt_dword": "0x11223344",
            },
        }
    )

    assert plan.first_layer.derive(7) == bytes(value ^ 7 for value in seed)
    assert plan.second_layer.derive(7) == C2.derive_candidate_key(seed, dword_xor=0x11223344)
    with pytest.raises(EXTRACT.StaticC2ExtractionError, match="未知key"):
        EXTRACT.layered_key_plan_from_mapping(
            {
                "reviewed": True,
                "review_basis": "逆コンパイルで確認",
                "first_layer": {"key_hex": "00", "typo": 1},
                "second_layer": {"key_hex": "00"},
            }
        )


def test_cli_help_headings_and_descriptions_are_japanese() -> None:
    help_text = EXTRACT._argument_parser().format_help()

    assert "使用方法:" in help_text
    assert "位置引数:" in help_text
    assert "オプション:" in help_text
    assert "このhelpを表示して終了する" in help_text
    assert "positional arguments:" not in help_text
    assert "show this help message" not in help_text
PRIVATE_INTEGRATION_ENV = (
    "XLOADER_C2_TEST_IMAGE",
    "XLOADER_C2_TEST_BASE_KEY",
    "XLOADER_C2_TEST_PRIMARY_PLAN",
    "XLOADER_C2_TEST_BOOTSTRAP_PLAN",
)


@pytest.mark.skipif(
    not all(os.environ.get(name) for name in PRIVATE_INTEGRATION_ENV),
    reason="repo外のXLoader実サンプル統合test入力が未指定です",
)
def test_private_real_sample_reproduces_bootstrap_url() -> None:
    case_dir = (
        ROOT
        / "analysis-results"
        / "malware"
        / "guloader"
        / "versions"
        / "unknown"
        / "cases"
        / "8d96249aa92bee27d9ac8ffa8e32e3f8dd3a5c77cbe541b1d0cc97f37e962a1e"
    )
    image_path = Path(os.environ["XLOADER_C2_TEST_IMAGE"])
    base_key_path = Path(os.environ["XLOADER_C2_TEST_BASE_KEY"])
    primary_plan_path = Path(os.environ["XLOADER_C2_TEST_PRIMARY_PLAN"])
    bootstrap_plan_path = Path(os.environ["XLOADER_C2_TEST_BOOTSTRAP_PLAN"])

    report = EXTRACT.extract_static_c2_inventory(
        EXTRACT._bounded_read(image_path),
        NATIVE.read_private_key_material(base_key_path),
        EXTRACT.load_lineage_profile(case_dir / "xloader-c2-lineage-profile.json"),
        layered_key_plan=EXTRACT.load_private_layered_key_plan(primary_plan_path),
        bootstrap_key_plan=EXTRACT.load_private_layered_key_plan(bootstrap_plan_path),
        initial_record_plan=EXTRACT.load_initial_record_plan(
            case_dir / "xloader-c2-initial-record-plan.json"
        ),
    )

    assert report["input_sha256"] == "2dee3986363adac0185279b0412a04db30b11bee2c4f2fd30e5e7ffdb5a3366f"
    assert report["observed_counts"]["decoded_builder_total"] == 171
    assert report["layered_recovery"]["candidate_count"] == 64
    assert report["initial_record_table"]["record_count"] == 16
    assert report["initial_record_table"]["bootstrap_url"] == (
        "http://www.plantaonewsms.com.br/ximu/"
    )
    assert report["sample_executed"] is False
    assert report["network_contacted"] is False




def test_output_paths_reject_existing_hardlink_aliases(tmp_path: Path) -> None:
    input_path = tmp_path / "input.bin"
    input_alias = tmp_path / "input-alias.bin"
    public_output = tmp_path / "public.json"
    private_alias = tmp_path / "private.json"
    input_path.write_bytes(b"input")
    public_output.write_bytes(b"output")
    try:
        input_alias.hardlink_to(input_path)
        private_alias.hardlink_to(public_output)
    except OSError:
        pytest.skip("hardlink creation is unavailable")

    with pytest.raises(EXTRACT.StaticC2ExtractionError, match="\u540c\u4e00\u5b9f\u4f53"):
        EXTRACT._validated_output_paths(
            [input_path],
            [input_alias, public_output],
        )
    with pytest.raises(EXTRACT.StaticC2ExtractionError, match="\u540c\u4e00\u5b9f\u4f53"):
        EXTRACT._validated_output_paths(
            [input_path],
            [public_output, private_alias],
        )
