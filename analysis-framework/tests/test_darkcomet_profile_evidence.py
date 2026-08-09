from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

import pytest

COMMON = Path(__file__).parents[1] / "common"
REPOSITORY_ROOT = Path(__file__).parents[2]
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

from c2_protocol_probe_profiles import load_profiles
from darkcomet_profile_evidence import (
    MAXIMUM_EVIDENCE_BYTES,
    DarkCometEvidenceError,
    validate_darkcomet_profile_evidence,
)

PROFILE_ID = "darkcomet-b9b052df-f168-name-1604"


def fixture(tmp_path: Path) -> tuple[Path, dict, dict, Path]:
    root = tmp_path / "repository"
    root.mkdir()
    profile = copy.deepcopy(load_profiles()[PROFILE_ID])
    source_path = REPOSITORY_ROOT / str(profile["source"]).split(":", 1)[0]
    payload = json.loads(source_path.read_text(encoding="utf-8"))
    profile["source"] = "evidence.json:config.netdata[0]"
    evidence = root / "evidence.json"
    evidence.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    return root, profile, payload, evidence


def test_valid_profile_is_bound_to_evidence_sha256(tmp_path: Path) -> None:
    root, profile, _payload, _evidence = fixture(tmp_path)
    result = validate_darkcomet_profile_evidence(profile, repository_root=root)
    assert len(result["sha256"]) == 64
    assert result["pointer"] == "config.netdata[0]"
    assert result["endpoint"] == "f168.name:1604"
    assert result["root_sha256"] == profile["sample_sha256s"][0]
    assert result["terminal_sha256"] == profile["sample_sha256s"][1]


@pytest.mark.parametrize(
    "source",
    [
        "../outside.json:config.netdata[0]",
        "evidence.json:config.netdata[-1]",
        "evidence.json:protocol.network_key",
        "C:/outside.json:config.netdata[0]",
    ],
)
def test_traversal_absolute_and_invalid_pointer_are_rejected(tmp_path: Path, source: str) -> None:
    root, profile, _payload, _evidence = fixture(tmp_path)
    profile["source"] = source
    with pytest.raises(DarkCometEvidenceError, match="source"):
        validate_darkcomet_profile_evidence(profile, repository_root=root)


def test_symlink_escape_is_rejected(tmp_path: Path) -> None:
    root, profile, payload, _evidence = fixture(tmp_path)
    outside = tmp_path / "outside.json"
    outside.write_text(json.dumps(payload), encoding="utf-8")
    link = root / "link.json"
    try:
        link.symlink_to(outside)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"symlinkを作成できない環境です: {exc}")
    profile["source"] = "link.json:config.netdata[0]"
    with pytest.raises(DarkCometEvidenceError, match="root 外"):
        validate_darkcomet_profile_evidence(profile, repository_root=root)


def test_symlink_ancestor_inside_repository_is_rejected(tmp_path: Path) -> None:
    root, profile, _payload, evidence = fixture(tmp_path)
    real_directory = root / "real"
    real_directory.mkdir()
    nested = real_directory / "evidence.json"
    nested.write_bytes(evidence.read_bytes())
    alias = root / "alias"
    try:
        alias.symlink_to(real_directory, target_is_directory=True)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"symlinkを作成できない環境です: {exc}")
    profile["source"] = "alias/evidence.json:config.netdata[0]"
    with pytest.raises(DarkCometEvidenceError, match="reparse-free"):
        validate_darkcomet_profile_evidence(profile, repository_root=root)


def test_hardlink_evidence_is_rejected(tmp_path: Path) -> None:
    root, profile, _payload, evidence = fixture(tmp_path)
    hardlink = root / "hardlink.json"
    try:
        hardlink.hardlink_to(evidence)
    except OSError as exc:
        pytest.skip(f"hardlinkを作成できない環境です: {exc}")
    profile["source"] = "hardlink.json:config.netdata[0]"
    with pytest.raises(DarkCometEvidenceError, match="single-link"):
        validate_darkcomet_profile_evidence(profile, repository_root=root)


def test_duplicate_json_keys_are_rejected(tmp_path: Path) -> None:
    root, profile, _payload, evidence = fixture(tmp_path)
    evidence.write_bytes(b'{"schema_version":1,"schema_version":1}')
    with pytest.raises(DarkCometEvidenceError, match="厳密な JSON"):
        validate_darkcomet_profile_evidence(profile, repository_root=root)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda profile, payload: payload.__setitem__("root_sha256", "0" * 64),
        lambda profile, payload: payload.__setitem__("terminal_sha256", "1" * 64),
        lambda profile, payload: payload["config"]["endpoint_records"][0].__setitem__("port", 1605),
        lambda profile, payload: payload["protocol"].__setitem__("network_key_hex", "00"),
        lambda profile, payload: payload["protocol"].__setitem__("config_resource_key_reused", True),
        lambda profile, payload: payload["static_verification"].__setitem__("protocol_key_verified", False),
        lambda profile, payload: profile.__setitem__("sample_sha256s", [profile["sample_sha256s"][0]]),
        lambda profile, payload: profile.__setitem__("host", "other.example"),
    ],
)
def test_hash_endpoint_key_resource_and_static_mutations_fail_closed(
    tmp_path: Path,
    mutation,
) -> None:
    root, profile, payload, evidence = fixture(tmp_path)
    mutation(profile, payload)
    evidence.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    with pytest.raises(DarkCometEvidenceError):
        validate_darkcomet_profile_evidence(profile, repository_root=root)


def test_evidence_mutation_and_deletion_after_pin_are_rejected(tmp_path: Path) -> None:
    root, profile, payload, evidence = fixture(tmp_path)
    pinned = validate_darkcomet_profile_evidence(profile, repository_root=root)["sha256"]
    payload["safety"]["network_contacted"] = True
    evidence.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    with pytest.raises(DarkCometEvidenceError, match="SHA-256"):
        validate_darkcomet_profile_evidence(profile, repository_root=root, expected_sha256=pinned)
    evidence.unlink()
    with pytest.raises(DarkCometEvidenceError, match="解決"):
        validate_darkcomet_profile_evidence(profile, repository_root=root, expected_sha256=pinned)


def test_oversized_evidence_is_rejected_before_json_parse(tmp_path: Path) -> None:
    root, profile, _payload, evidence = fixture(tmp_path)
    evidence.write_bytes(b"{" + b" " * MAXIMUM_EVIDENCE_BYTES + b"}")
    with pytest.raises(DarkCometEvidenceError, match="64 KiB"):
        validate_darkcomet_profile_evidence(profile, repository_root=root)
