from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from extractors.remcosrat import strict_config as strict_remcos

ROOT = Path(__file__).resolve().parents[2]
FAMILY_DIR = ROOT / "analysis-framework" / "malware" / "remcosrat"
COMMON_DIR = ROOT / "analysis-framework" / "common"


def load(name: str, filename: str):
    path = FAMILY_DIR / filename
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.path[:0] = [str(FAMILY_DIR), str(COMMON_DIR)]
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path.remove(str(FAMILY_DIR))
        sys.path.remove(str(COMMON_DIR))
    return module


def modern_clear(delimiter: bytes) -> bytes:
    fields = [b"0"] * 57
    fields[0] = b"c2.example:2404:1\x1e8.8.8.8:443:0"
    fields[1] = b"reviewed-botnet"
    fields[2] = b"30"
    fields[0x0E] = b"Rmc-TEST"
    fields[0x29] = b"5"
    fields[0x36] = b"agent-certificate"
    fields[0x37] = b"private-key-must-not-be-published"
    fields[0x38] = b"peer-certificate"
    return delimiter.join(fields)


@pytest.mark.parametrize(
    "filename",
    [
        "remcos_config_extractor.py",
        "analyze_corpus.py",
        "analyze_triage_artifacts.py",
    ],
)
def test_family_cli_bootstraps_repository_imports(
    filename: str,
    tmp_path: Path,
) -> None:
    completed = subprocess.run(
        [sys.executable, "-I", str(FAMILY_DIR / filename), "--help"],
        cwd=tmp_path,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
    )
    assert completed.returncode == 0, completed.stderr
    assert "usage:" in completed.stdout.casefold()


@pytest.mark.parametrize("delimiter", [b"\x7c\x1f\x1e\x1e\x7c", b"\x7c\x1e\x1e\x1f\x7c"])
def test_both_published_delimiters_recover_index_zero_c2(delimiter: bytes) -> None:
    module = load("remcos_config_delimiters", "remcos_config_extractor.py")
    result = module.parse_decrypted_settings(modern_clear(delimiter))
    assert result["field_count"] == 57
    assert [item["endpoint"] for item in result["c2"]] == [
        "c2.example:2404",
        "8.8.8.8:443",
    ]
    assert [item["tls_enabled"] for item in result["c2"]] == [True, False]
    assert result["connect_interval_seconds"] == 30
    assert result["initial_connect_delay_seconds"] == 5


def test_legacy_third_field_is_withheld_instead_of_mislabelled_tls() -> None:
    module = load("remcos_config_legacy", "remcos_config_extractor.py")
    delimiter = module.DELIMITERS[0]
    fields = [b"0"] * 20
    fields[0] = b"old.example:9001:private-password"
    fields[0x0E] = b"Rmc-LEGACY"
    parsed = module.parse_decrypted_settings(delimiter.join(fields))
    assert parsed["c2"][0]["tls_enabled"] is None
    assert parsed["c2"][0]["third_field_kind"] == "withheld_unknown_or_credential"
    assert parsed["credential_or_unknown_c2_field_present"] is True
    assert "private-password" not in json.dumps(parsed, ensure_ascii=False)


def test_unknown_c2_field_flag_is_monotonic_across_records() -> None:
    """後続の空fieldで先に観測した非公開値を未観測へ戻さない。"""

    module = load("remcos_config_unknown_field_union", "remcos_config_extractor.py")
    fields = [b"0"] * 57
    fields[0] = b"first.example:9001:secret\x1esecond.example:9002:"
    fields[0x0E] = b"Rmc-TEST"
    parsed = module.parse_decrypted_settings(module.DELIMITERS[0].join(fields))
    assert parsed["credential_or_unknown_c2_field_present"] is True
    assert [item["third_field_kind"] for item in parsed["c2"]] == [
        "withheld_unknown_or_credential",
        "withheld_unknown_or_credential",
    ]


def test_endpoint_outside_config_index_zero_is_not_promoted() -> None:
    module = load("remcos_config_index_zero", "remcos_config_extractor.py")
    fields = [b"0"] * 57
    fields[5] = b"decoy.example:4444:1"
    with pytest.raises(ValueError, match="index 0"):
        module.parse_decrypted_settings(module.DELIMITERS[0].join(fields))


def test_extract_config_redacts_key_private_material_and_raw_config(monkeypatch: pytest.MonkeyPatch) -> None:
    module = load("remcos_config_extract", "remcos_config_extractor.py")
    key = b"reviewed-test-key"
    clear = modern_clear(module.DELIMITERS[1])
    resource = bytes([len(key)]) + key + module.rc4_crypt(clear, key)
    monkeypatch.setattr(strict_remcos, "_settings_resource", lambda _data: resource)
    report = module.extract_config(b"MZ\x00" + b"7.2.6 Pro" + b"\x00" * 64)
    rendered = json.dumps(report, ensure_ascii=False)
    assert report["static_config_recovered"] is True
    assert report["decoded_config_recovered"] is True
    assert report["version_candidates"] == ["7.2.6 Pro"]
    assert report["version_candidate_provenance"]["status"] == "single_candidate_not_confirmed"
    assert report["version_candidate_provenance"]["confirmed_version"] is None
    assert report["version_candidate_provenance"]["observations"][0]["scope"] == "entire_input_pe"
    assert report["config"]["tls_material"]["private_key_present"] is True
    assert report["config"]["tls_material"]["private_key_published"] is False
    assert report["c2"][0]["evidence"] == {
        "kind": "rc4_decrypted_rcdata_settings",
        "resource_type": "RT_RCDATA",
        "resource_name": "SETTINGS",
        "config_field_index": 0,
        "all_expected_fields_validated": True,
        "validated_field_indices": [0, 1, 2, 14, 41],
        "complete_c2_record_set_validated": True,
        "family_specific_schema_validated": True,
        "family_specific_mutex_prefix_validated": True,
        "family_schema_validation_profile": "elastic_published_56_field_subset_v1",
    }
    assert report["c2"][0]["contacted"] is False
    assert report["c2"][0]["liveness_confirmed"] is False
    assert "reviewed-test-key" not in rendered
    assert "private-key-must-not-be-published" not in rendered
    assert report["safety"]["network_contacted"] is False


def test_decode_settings_rejects_empty_ciphertext_and_oversized_resource() -> None:
    module = load("remcos_config_bounds", "remcos_config_extractor.py")
    with pytest.raises(ValueError, match="鍵長"):
        module.decode_settings_blob(b"\x07abcdefg")
    with pytest.raises(ValueError, match="サイズ"):
        module.decode_settings_blob(b"A" * (module.MAX_SETTINGS_BYTES + 1))


def test_resource_leaf_ambiguity_and_bounds_have_typed_reasons(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def image_for(*leaves: tuple[int, int]) -> SimpleNamespace:
        languages = [
            SimpleNamespace(data=SimpleNamespace(struct=SimpleNamespace(OffsetToData=offset, Size=size)))
            for offset, size in leaves
        ]
        name = SimpleNamespace(
            name="SETTINGS",
            struct=SimpleNamespace(Id=0),
            directory=SimpleNamespace(entries=languages),
        )
        resource_type = SimpleNamespace(
            struct=SimpleNamespace(Id=10),
            directory=SimpleNamespace(entries=[name]),
        )
        return SimpleNamespace(
            DIRECTORY_ENTRY_RESOURCE=SimpleNamespace(entries=[resource_type]),
            get_offset_from_rva=lambda value: value,
        )

    mutable = bytearray(b"MZ" + b"A" * 254)
    mutable[32:40] = b"BBBBBBBB"
    data = bytes(mutable)
    monkeypatch.setattr(strict_remcos.pefile, "PE", lambda **_kwargs: image_for((8, 8), (32, 8)))
    with pytest.raises(strict_remcos.RemcosConfigError) as ambiguous:
        strict_remcos._settings_resource(data)
    assert ambiguous.value.reason == "settings_resource_leaf_ambiguous"
    assert ambiguous.value.mapped_layout_retry_eligible is False

    monkeypatch.setattr(strict_remcos.pefile, "PE", lambda **_kwargs: image_for((250, 16)))
    with pytest.raises(strict_remcos.RemcosConfigError) as bounds:
        strict_remcos._settings_resource(data)
    assert bounds.value.reason == "settings_resource_bounds_invalid"
    assert bounds.value.mapped_layout_retry_eligible is False


def test_settings_resource_leaf_and_copy_quotas_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """同一内容のlanguage leafでも件数・累積copy上限を迂回できない。"""

    def image_for(*leaves: tuple[int, int]) -> SimpleNamespace:
        languages = [
            SimpleNamespace(data=SimpleNamespace(struct=SimpleNamespace(OffsetToData=offset, Size=size)))
            for offset, size in leaves
        ]
        name = SimpleNamespace(
            name="SETTINGS",
            struct=SimpleNamespace(Id=0),
            directory=SimpleNamespace(entries=languages),
        )
        resource_type = SimpleNamespace(
            struct=SimpleNamespace(Id=10),
            directory=SimpleNamespace(entries=[name]),
        )
        return SimpleNamespace(
            DIRECTORY_ENTRY_RESOURCE=SimpleNamespace(entries=[resource_type]),
            get_offset_from_rva=lambda value: value,
        )

    data = b"MZ" + b"A" * 254
    monkeypatch.setattr(strict_remcos, "MAX_SETTINGS_LANGUAGE_LEAVES", 1)
    monkeypatch.setattr(strict_remcos.pefile, "PE", lambda **_kwargs: image_for((8, 8), (8, 8)))
    with pytest.raises(strict_remcos.RemcosConfigError) as leaf_count:
        strict_remcos._settings_resource(data)
    assert leaf_count.value.reason == "settings_resource_leaf_count_exceeded"

    monkeypatch.setattr(strict_remcos, "MAX_SETTINGS_LANGUAGE_LEAVES", 4)
    monkeypatch.setattr(strict_remcos, "MAX_SETTINGS_RESOURCE_COPY_BYTES", 15)
    with pytest.raises(strict_remcos.RemcosConfigError) as copy_bytes:
        strict_remcos._settings_resource(data)
    assert copy_bytes.value.reason == "settings_resource_copy_bytes_exceeded"


def test_missing_file_layout_resource_is_the_only_retry_eligible_resource_reason(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(strict_remcos.pefile, "PE", lambda **_kwargs: SimpleNamespace())
    with pytest.raises(strict_remcos.RemcosConfigError) as caught:
        strict_remcos._settings_resource(b"MZ" + b"\x00" * 64)
    assert caught.value.reason == "settings_resource_unavailable_in_file_layout"
    assert caught.value.stage == "resource_lookup"
    assert caught.value.mapped_layout_retry_eligible is True


def test_strict_cli_uses_bounded_single_link_input_and_atomic_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CLIが検体aliasを拒否し、通常fileだけをatomicに保存する。"""

    sample = tmp_path / "sample.bin"
    output = tmp_path / "report.json"
    sample.write_bytes(b"MZ" + b"A" * 62)
    monkeypatch.setattr(
        strict_remcos,
        "extract_config",
        lambda data: {"sample_size": len(data), "network_contacted": False},
    )
    monkeypatch.setattr(sys, "argv", ["strict_config.py", str(sample), "--output", str(output)])
    assert strict_remcos.main() == 0
    assert json.loads(output.read_text(encoding="utf-8")) == {
        "sample_size": 64,
        "network_contacted": False,
    }
    assert not list(tmp_path.glob(".report.json.*.tmp"))

    with pytest.raises(ValueError, match="同じfile"):
        strict_remcos._reject_input_output_alias(sample, sample)

    hardlink = tmp_path / "sample-hardlink.bin"
    try:
        os.link(sample, hardlink)
    except OSError as error:
        pytest.skip(f"このfilesystemではhardlinkを作成できません: {error}")
    with pytest.raises(ValueError, match="single-link"):
        strict_remcos._read_bounded_regular_file(sample)
    with pytest.raises(ValueError, match="同じfile"):
        strict_remcos._reject_input_output_alias(sample, hardlink)


def test_strict_cli_reader_rejects_oversized_input(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """stat値だけでなく読取上限を常に有限に保つ。"""

    sample = tmp_path / "oversized.bin"
    sample.write_bytes(b"12345")
    monkeypatch.setattr(strict_remcos, "MAX_INPUT_BYTES", 4)
    with pytest.raises(ValueError, match="size"):
        strict_remcos._read_bounded_regular_file(sample)


def test_hunt_output_has_offline_target_and_configured_certificate_pivot() -> None:
    module = load("remcos_hunt", "c2_detector.py")
    certificate = "a" * 64
    result = module.build_hunt(
        {
            "c2": [
                {
                    "host": "c2.example",
                    "port": 2404,
                    "tls_enabled": True,
                    "monitor_eligible": True,
                }
            ],
            "config": {"tls_material": {"peer_certificate_sha256": certificate}},
            "version_candidates": ["7.2.6 Pro"],
        }
    )
    assert result["targets"][0]["shodan_queries"] == ["hostname:c2.example port:2404"]
    assert result["certificate_pivots"][0]["sha256"] == certificate
    assert result["active_scan_performed"] is False
    assert result["network_contacted"] is False


def test_external_endpoint_hunt_keeps_provider_evidence_separate() -> None:
    module = load("remcos_external_hunt", "c2_detector.py")
    result = module.build_endpoint_hunt(
        ["external.example:4489", "invalid", "external.example:4489"],
        source="external_sandbox_reported_configuration",
    )
    assert len(result["targets"]) == 1
    assert result["targets"][0]["source"] == "external_sandbox_reported_configuration"
    assert result["targets"][0]["shodan_queries"] == ["hostname:external.example port:4489"]
    assert result["active_scan_performed"] is False
    assert result["network_contacted"] is False


def test_external_endpoint_hunt_rejects_injectable_authorities() -> None:
    module = load("remcos_external_hunt_injection", "c2_detector.py")
    rejected = [
        "operator@evil.example:2404",
        "evil.example port:443:2404",
        "evil.example:2404?token=secret",
        "evil.example:2404#fragment",
        "https://evil.example:2404/path",
        "evil.example :2404",
    ]

    result = module.build_endpoint_hunt(
        [*rejected, "External.Example.:4489", "[2001:4860:4860::8888]:443"],
        source="external_sandbox_reported_configuration",
    )

    assert [item["endpoint"] for item in result["targets"]] == [
        "external.example:4489",
        "[2001:4860:4860::8888]:443",
    ]
    rendered = json.dumps(result, ensure_ascii=False)
    assert all(value not in rendered for value in rejected)
    assert result["targets"][0]["shodan_queries"] == ["hostname:external.example port:4489"]
    assert result["targets"][1]["shodan_queries"] == ["ip:2001:4860:4860::8888 port:443"]


def test_standard_handler_declares_bounded_pe_contract() -> None:
    module = load("remcos_standard_handler", "extract_config.py")
    assert module.HANDLER_CONTRACT == {
        "input_formats": ["pe"],
        "minimum_evidence_score": 1,
    }


def test_standard_handler_rebuilds_mapped_pe_without_publishing_bytes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = load("remcos_standard_mapped_handler", "extract_config.py")
    original = b"MZmapped-memory"
    rebuilt = b"MZrebuilt-file"

    def fake_extract(data: bytes) -> dict:
        if data == original:
            raise module.RemcosConfigError(
                "settings_resource_unavailable_in_file_layout",
                "resource not present in file layout",
                stage="resource_lookup",
                mapped_layout_retry_eligible=True,
            )
        assert data == rebuilt
        return {
            "sample_sha256": "0" * 64,
            "sample": {"sha256": "0" * 64, "size": len(data), "format": "pe"},
            "limitations": [],
        }

    monkeypatch.setattr(module, "_extract_config", fake_extract)
    monkeypatch.setattr(module, "_mapped_layout_is_plausible", lambda _data: True)
    monkeypatch.setattr(
        module,
        "rebuild_mapped_pe",
        lambda data, max_output_bytes: (
            rebuilt,
            {
                "status": "rebuilt",
                "input_sha256": hashlib.sha256(data).hexdigest(),
                "output_sha256": hashlib.sha256(rebuilt).hexdigest(),
                "executed": False,
                "network_contacted": False,
            },
        ),
    )

    result = module.extract_config(original)
    assert result["sample_sha256"] == hashlib.sha256(original).hexdigest()
    assert result["sample"]["format"] == "mapped_pe_memory_image"
    assert result["sample"]["reconstructed_pe_sha256"] == hashlib.sha256(rebuilt).hexdigest()
    assert "mapped_pe_reconstruction" in result
    assert rebuilt.hex() not in json.dumps(result)


@pytest.mark.parametrize(
    ("reason", "stage"),
    [
        ("settings_resource_leaf_ambiguous", "resource_lookup"),
        ("settings_resource_bounds_invalid", "resource_bounds"),
        ("rc4_key_length_invalid", "settings_blob"),
        ("settings_delimiter_ambiguous_or_missing", "config_schema"),
        ("config_field_count_out_of_bounds", "config_schema"),
        ("configured_c2_not_recovered", "c2_schema"),
    ],
)
def test_standard_handler_does_not_map_retry_strict_failures(
    monkeypatch: pytest.MonkeyPatch,
    reason: str,
    stage: str,
) -> None:
    module = load(f"remcos_no_mapped_retry_{reason}", "extract_config.py")
    error = module.RemcosConfigError(reason, "strict rejection", stage=stage)
    monkeypatch.setattr(module, "_extract_config", lambda _data: (_ for _ in ()).throw(error))
    monkeypatch.setattr(
        module,
        "rebuild_mapped_pe",
        lambda *_args, **_kwargs: pytest.fail("厳格設定失敗でmapped retryしてはならない"),
    )

    with pytest.raises(module.RemcosConfigError) as caught:
        module.extract_config(b"MZ" + b"\x00" * 128)
    assert caught.value.reason == reason


def test_standard_handler_requires_plausible_mapped_layout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = load("remcos_mapped_layout_gate", "extract_config.py")
    unavailable = module.RemcosConfigError(
        "settings_resource_unavailable_in_file_layout",
        "missing",
        stage="resource_lookup",
        mapped_layout_retry_eligible=True,
    )
    monkeypatch.setattr(module, "_extract_config", lambda _data: (_ for _ in ()).throw(unavailable))
    monkeypatch.setattr(module, "_mapped_layout_is_plausible", lambda _data: False)
    monkeypatch.setattr(
        module,
        "rebuild_mapped_pe",
        lambda *_args, **_kwargs: pytest.fail("不正layoutを再構成してはならない"),
    )

    with pytest.raises(module.RemcosConfigError) as caught:
        module.extract_config(b"MZ" + b"\x00" * 128)
    assert caught.value.reason == "mapped_layout_not_plausible"


def test_c2_record_quota_and_conflict_fail_closed() -> None:
    module = load("remcos_c2_quota", "remcos_config_extractor.py")
    delimiter = module.DELIMITERS[0]
    fields = [b"0"] * 57
    fields[0] = b"\x1e".join(
        f"host{index}.example:2404:1".encode("ascii") for index in range(module.MAX_C2_RECORDS + 1)
    )
    with pytest.raises(module.RemcosConfigError) as quota:
        module.parse_decrypted_settings(delimiter.join(fields))
    assert quota.value.reason == "c2_record_count_exceeded"

    fields[0] = b"same.example:2404:1\x1esame.example:2404:0"
    with pytest.raises(module.RemcosConfigError) as conflict:
        module.parse_decrypted_settings(delimiter.join(fields))
    assert conflict.value.reason == "c2_record_conflict"


@pytest.mark.parametrize(
    ("value", "reason"),
    [
        (b"valid.example:2404:1\x1enot-an-endpoint", "c2_record_structure_invalid"),
        (b"valid.example:2404:1\x1ebad host:443:1", "c2_record_endpoint_invalid"),
        (b"\x1evalid.example:2404:1", "c2_record_empty"),
        (b"valid.example:2404:1\x1e\x1e", "c2_record_empty"),
        (
            b"valid.example:2404:1\x1e\x1esecond.example:443:0",
            "c2_record_empty",
        ),
        (b"999.999.999.999:2404:1", "c2_record_endpoint_invalid"),
        (b"010.0.0.1:2404:1", "c2_record_endpoint_invalid"),
        (b"1.2.3:2404:1", "c2_record_endpoint_invalid"),
    ],
)
def test_any_malformed_c2_record_rejects_the_complete_settings(
    value: bytes,
    reason: str,
) -> None:
    fields = [b"0"] * 57
    fields[0] = value
    fields[0x0E] = b"Rmc-TEST"
    with pytest.raises(strict_remcos.RemcosConfigError) as raised:
        strict_remcos.parse_decrypted_settings(strict_remcos.DELIMITERS[0].join(fields))
    assert raised.value.reason == reason


@pytest.mark.parametrize(
    ("value", "endpoint", "host_kind"),
    [
        (b"8.8.8.8:2404:1", "8.8.8.8:2404", "ipv4"),
        (b"valid.example:2404:1", "valid.example:2404", "dns"),
    ],
)
def test_valid_ipv4_and_dns_c2_records_remain_supported(
    value: bytes,
    endpoint: str,
    host_kind: str,
) -> None:
    fields = [b"0"] * 57
    fields[0] = value
    fields[0x0E] = b"Rmc-TEST"

    parsed = strict_remcos.parse_decrypted_settings(strict_remcos.DELIMITERS[0].join(fields))

    assert parsed["c2"][0]["endpoint"] == endpoint
    assert parsed["c2"][0]["host_kind"] == host_kind


def test_single_trailing_c2_record_separator_is_a_valid_terminator() -> None:
    """実検体で観測した単一0x1e終端を空recordとして誤拒否しない。"""

    fields = [b"0"] * 57
    fields[0] = b"first.example:2404:1\x1esecond.example:443:0\x1e"
    fields[0x0E] = b"Rmc-TEST"

    parsed = strict_remcos.parse_decrypted_settings(strict_remcos.DELIMITERS[0].join(fields))

    assert parsed["c2_record_count"] == 2
    assert [record["endpoint"] for record in parsed["c2"]] == [
        "first.example:2404",
        "second.example:443",
    ]


def test_modern_family_schema_accepts_custom_mutex_name() -> None:
    fields = [b"0"] * 57
    fields[0] = b"valid.example:2404:1"
    fields[0x0E] = b"custom-operation-name"

    parsed = strict_remcos.parse_decrypted_settings(strict_remcos.DELIMITERS[0].join(fields))

    assert parsed["family_specific_schema_validated"] is True
    assert parsed["family_specific_mutex_prefix_validated"] is False
    assert parsed["family_schema_validation_profile"] == "elastic_published_56_field_subset_v1"


def test_legacy_family_schema_requires_independent_remcos_mutex_anchor() -> None:
    fields = [b"0"] * 20
    fields[0] = b"valid.example:2404:private"
    fields[0x0E] = b"custom-operation-name"
    with pytest.raises(strict_remcos.RemcosConfigError) as raised:
        strict_remcos.parse_decrypted_settings(strict_remcos.DELIMITERS[0].join(fields))
    assert raised.value.reason == "legacy_remcos_mutex_anchor_missing"


def test_modern_family_schema_rejects_invalid_published_boolean_field() -> None:
    fields = [b"0"] * 57
    fields[0] = b"valid.example:2404:1"
    fields[0x03] = b"enabled"
    fields[0x0E] = b"custom-operation-name"
    with pytest.raises(strict_remcos.RemcosConfigError) as raised:
        strict_remcos.parse_decrypted_settings(strict_remcos.DELIMITERS[0].join(fields))
    assert raised.value.reason == "published_boolean_field_invalid"


def test_version_conflict_and_quota_are_not_promoted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = load("remcos_version_provenance", "remcos_config_extractor.py")
    key = b"bounded-key"
    clear = modern_clear(module.DELIMITERS[0])
    resource = bytes([len(key)]) + key + module.rc4_crypt(clear, key)
    monkeypatch.setattr(strict_remcos, "_settings_resource", lambda _data: resource)

    conflict = module.extract_config(b"MZ\x00 7.2.6 Pro 7.3.1 Pro")
    assert conflict["version_candidates"] == []
    assert conflict["version_candidate_provenance"]["status"] == "conflicting_candidates_withheld"
    assert all(
        item["used_for_version_confirmation"] is False
        for item in conflict["version_candidate_provenance"]["observations"]
    )

    versions = b" ".join(f"{index}.1 Pro".encode("ascii") for index in range(1, module.MAX_VERSION_CANDIDATES + 2))
    quota = module.extract_config(b"MZ\x00 " + versions)
    assert quota["version_candidates"] == []
    assert quota["version_candidate_provenance"]["status"] == "candidate_quota_exceeded_withheld"
    assert quota["version_candidate_provenance"]["observations"] == []
