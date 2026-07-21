"""第6バッチで追加・拡張した静的解析資材の回帰試験。"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import struct
import sys

import pytest


FRAMEWORK = Path(__file__).parents[1]
REPOSITORY = FRAMEWORK.parent
BATCH6 = REPOSITORY / "analysis-results" / "research" / "malwarebazaar" / "batches" / "batch-0006"
COMMON = FRAMEWORK / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

import extract_pyinstaller_archive  # noqa: E402
import passive_c2_detector  # noqa: E402


def load_file(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def family_module(family: str, filename: str = "extract_config.py"):
    return load_file(FRAMEWORK / "malware" / family / filename, f"batch6_{family}_{filename}")


def minimal_elf(payload: bytes) -> bytes:
    ident = b"\x7fELF" + bytes([2, 1, 1]) + b"\0" * 9
    header = struct.pack("<HHIQQQIHHHHHH", 2, 62, 1, 0, 0, 0, 0, 64, 56, 0, 0, 0, 0)
    return ident + header + payload


def test_pyinstaller_paths_reject_escape_and_drives() -> None:
    assert extract_pyinstaller_archive.safe_relative_path("data_p002/002.xml").as_posix() == "data_p002/002.xml"
    for value in ("../escape", r"..\escape", r"C:\escape", "/absolute", "a/./b"):
        with pytest.raises(ValueError):
            extract_pyinstaller_archive.safe_relative_path(value)


def test_pyinstaller_selection_requires_exact_name_or_prefix() -> None:
    names = ["campus.py", "installer", "data_p002/002.xml", "python313.dll"]
    assert extract_pyinstaller_archive.selected_names(names, {"campus.py"}, ("data_p002/",)) == [
        "campus.py",
        "data_p002/002.xml",
    ]


def test_credential_phishing_extractor_redacts_prefilled_values() -> None:
    module = family_module("credential_phishing_html")
    source = b"""<html><form method='post' action='https://smartforms.dev/submit/test'>
    <input name='email' value='victim@example.invalid'><input name='password' type='password'></form></html>"""
    result = module.extract_config(source)
    field = result["forms"][0]["fields"][0]
    assert field["value"] == "<redacted>"
    assert "victim@example.invalid" not in json.dumps(result)
    assert result["network_endpoints"][0]["role"] == "credential_exfiltration"
    assert result["c2"] == []


def test_credential_form_emulator_never_retains_values() -> None:
    module = family_module("credential_phishing_html", "emulator.py")
    result = module.parse_submission(b"email=alice%40example.invalid&password=secret")
    serialized = json.dumps(result)
    assert result["field_names"] == ["email", "password"]
    assert "secret" not in serialized
    assert "alice" not in serialized
    assert result["credential_values_stored"] is False


def test_credential_exfiltration_role_does_not_emit_shodan_query() -> None:
    profile = json.loads((FRAMEWORK / "malware" / "credential_phishing_html" / "c2_profile.json").read_text(encoding="utf-8"))
    result = passive_c2_detector.detect(
        profile,
        [{"destination_host": "smartforms.dev", "destination_port": 443, "http": {"path": "/submit/6a5ac8f0c184545ccc22c342"}}],
    )
    assert result["matches"][0]["verdict"] == "non_c2_role"
    assert result["shodan"]["queries"] == []


def test_mig_extractor_and_synthetic_emulator() -> None:
    module = family_module("mig_logcleaner")
    result = module.extract_config(
        minimal_elf(b"MIG Logcleaner v2.0 by no1\0/var/log/\0/tmp/mig.sh\0wtmp\0utmp\0lastlog\0")
    )
    assert result["version"] == "2.0"
    assert result["c2"] == []
    assert result["network_capability"] is False

    emulator = family_module("mig_logcleaner", "emulator.py")
    records = [{"user": "alice", "host": "10.0.0.1"}, {"user": "bob", "host": "10.0.0.2"}]
    assert emulator.emulate_records(records, "remove", {"user": "alice"}) == [{"user": "bob", "host": "10.0.0.2"}]
    assert records[0]["user"] == "alice"
    assert emulator.status()["filesystem_access"] is False


def test_eclipse_profiles_cover_four_new_architectures() -> None:
    module = family_module("eclipse_ddos_bot")
    expected = {
        "0cc04fbf0c3c6b33914852fba88eee6f375a0230d19ca573447af21702bc01ab": ("x86", "i586"),
        "c66b83d2e4f021f73b630d23f3dde7042358e0447b42ff3c213c6ce61d11a58b": ("arm", "armv4l"),
        "275b9450462c7661b71d61bdf4186f279c932c7651cba7818a04215ee3f0844f": ("m68k", "m68k"),
        "87a2fbd422bfc36691da037a288b6fd151bbb8631081c447e616c6fb55494e1c": ("mipsel", "mipsel"),
    }
    for digest, values in expected.items():
        profile = module.HASH_PROFILES[digest]
        assert (profile["architecture"], profile["registration"]) == values
        assert profile["port"] == 7000


def test_eclipse_emulator_accepts_registration_and_refuses_nonloopback() -> None:
    module = family_module("eclipse_ddos_bot", "emulator.py")
    assert module.parse_registration(b"armv4l\n") == "armv4l"
    assert module.parse_pong(b"PONG\n") is True
    with pytest.raises(ValueError):
        module.require_loopback("45.66.228.114")


def test_efimer_parser_redacts_synthetic_http_values() -> None:
    module = family_module("efimer", "emulator.py")
    result = module.parse_http_request(b"POST /route.php HTTP/1.1\r\nHost: example.onion\r\n\r\nseed=secret&mode=test")
    serialized = json.dumps(result)
    assert result["path"] == "/route.php"
    assert "secret" not in serialized
    assert result["network_contacted"] is False
    assert module.status()["tor_emulated"] is False


def test_unrecovered_protocol_emulators_are_explicitly_unavailable() -> None:
    for family in ("protected_pe_loader", "sobfox_launcher", "infrastructure_decoy_hta"):
        module = family_module(family, "emulator.py")
        assert module.status()["available"] is False
        assert module.status()["malware_protocol_compatible"] is False


def test_batch6_yara_rules_compile() -> None:
    yara = pytest.importorskip("yara")
    for family in (
        "credential_phishing_html",
        "eclipse_ddos_bot",
        "infrastructure_decoy_hta",
        "mig_logcleaner",
        "protected_pe_loader",
        "sobfox_launcher",
    ):
        rule = next((FRAMEWORK / "malware" / family / "rules").glob("*.yar"))
        yara.compile(filepath=str(rule))


def test_batch6_publication_has_ten_unique_canonical_cases() -> None:
    classification = json.loads((BATCH6 / "classification.json").read_text(encoding="utf-8"))
    samples = classification["samples"]
    assert len(samples) == 10
    assert len({sample["sha256"] for sample in samples}) == 10
    for sample in samples:
        version = sample["version"] or "unknown"
        case = (
            REPOSITORY
            / "analysis-results"
            / "malware"
            / sample["family"]
            / "versions"
            / version
            / "cases"
            / sample["sha256"]
        )
        metadata = json.loads((case / "metadata.json").read_text(encoding="utf-8"))
        assert metadata["sha256"] == sample["sha256"]
        assert metadata["malware_version"]["normalized_key"] == version
        assert metadata["canonical_path"].endswith(f"/cases/{sample['sha256']}")
        assert (case / "README.md").is_file()
        assert (case / "IOC-LIST.md").is_file()


def test_batch6_connection_validation_preserves_safety_and_roles() -> None:
    validation = json.loads((BATCH6 / "c2-validation.json").read_text(encoding="utf-8"))
    assert validation["sample_count"] == 10
    assert validation["unique_probe_count"] == 5
    assert validation["validation_status_counts"] == {
        "not_applicable": 2,
        "not_performed_no_exact_target": 2,
        "performed": 6,
    }
    candidates = [item for sample in validation["samples"] for item in sample["candidate_results"]]
    assert candidates
    assert all(item["application_data_sent"] is False for item in candidates)
    assert all(item["c2_confirmed"] is False for item in candidates)
    eclipse = [sample for sample in validation["samples"] if sample["family"] == "eclipse-ddos-bot"]
    assert len(eclipse) == 4
    assert all(sample["candidate_results"][0]["deduplicated_probe"] is True for sample in eclipse)
    phishing = next(sample for sample in validation["samples"] if sample["family"] == "credential-phishing-html")
    assert phishing["c2_connection_validation_status"] == "not_applicable"
    assert phishing["non_c2_connection_validation_status"] == "performed"
    efimer = next(sample for sample in validation["samples"] if sample["family"] == "efimer")
    assert len(efimer["candidate_results"]) == 3
    assert all(item["transport"] == "tor-socks5" for item in efimer["candidate_results"])
