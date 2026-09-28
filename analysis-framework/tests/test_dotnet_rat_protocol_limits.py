"""通常moduleの最小guardを人工recordsだけで検証するportable陰性試験。"""

import copy
import hashlib
import importlib.util
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest


MODULE_PATH = Path(__file__).resolve().parents[1] / "common" / "dotnet_rat_protocol_evidence.py"
SPEC = importlib.util.spec_from_file_location("dotnet_rat_protocol_limits_module", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

@pytest.fixture(autouse=True)
def forbid_pe_cil_parser(monkeypatch):
    def forbidden(*_args, **_kwargs):
        raise AssertionError("人工records専用試験でPE/CIL parserを呼んだ")

    monkeypatch.setattr(MODULE.dnfile, "dnPE", forbidden)
    monkeypatch.setattr(MODULE, "read_method_body_from_bytes", forbidden)


def records_for(family):
    profile = MODULE.FAMILY_PROFILES[family]
    fields = list(profile["required_registration_fields"])
    targets = (profile["registration_method"], profile["dispatcher_method"], profile["heartbeat_method"])
    literals = (fields, list(profile["command_markers"]), [profile["packet_key"], "Ping", "Message"])
    keys = (fields, [], [])
    calls = (["ForcePathObject"], [], ["GetActiveWindowTitle", "Encode2Bytes", "Send"])
    return [
        {"token": f"0x0600000{index}", "owner": target[0], "name": target[1],
         "literals": [*values, "人工の非公開値"], "path_keys": list(path_keys), "calls": list(call_names),
         "cil_semantic_sha256": str(index) * 64}
        for index, (target, values, path_keys, call_names) in enumerate(zip(targets, literals, keys, calls), 1)
    ]


@pytest.mark.parametrize("family", ["asyncrat", "venomrat", "dcrat"])
def test_unique_artificial_records_keep_normal_complete(family):
    records = records_for(family)
    result = MODULE.summarize_records(records, family, "a" * 64)
    assert result["analysis_status"] == "complete"
    assert "人工の非公開値" not in repr(result)
    assert MODULE._select_record(records, *MODULE.FAMILY_PROFILES[family]["registration_method"]) is records[0]


@pytest.mark.parametrize("family", ["asyncrat", "venomrat", "dcrat"])
@pytest.mark.parametrize("role", [0, 1, 2], ids=["registration", "dispatcher", "heartbeat"])
@pytest.mark.parametrize("duplicate_first", [False, True])
def test_same_name_distinct_token_is_ambiguous_regardless_order_or_repeated_key_count(family, role, duplicate_first):
    records = records_for(family)
    duplicate = copy.deepcopy(records[role])
    duplicate.update(token="0x06000004", cil_semantic_sha256="4" * 64)
    duplicate["path_keys"] = ["SyntheticRepeatedNotWireKey"] * (len(records[role]["path_keys"]) + 4)
    values = [duplicate, *records] if duplicate_first else [*records, duplicate]
    with pytest.raises(MODULE.ProtocolMethodAmbiguityError, match="^protocol_method_selection_ambiguous$"):
        MODULE.summarize_records(values, family, "b" * 64)


@pytest.mark.parametrize("role", [0, 1, 2])
@pytest.mark.parametrize("duplicate_first", [False, True])
def test_tied_path_key_count_never_resolves_ambiguity(role, duplicate_first):
    records = records_for("asyncrat")
    duplicate = copy.deepcopy(records[role])
    duplicate["token"] = "0x06000004"
    values = [duplicate, *records] if duplicate_first else [*records, duplicate]
    with pytest.raises(MODULE.ProtocolMethodAmbiguityError):
        MODULE.summarize_records(values, "asyncrat", "c" * 64)


def test_identical_duplicate_record_is_ambiguous_and_reason_does_not_echo_names():
    record = {"owner": "SyntheticPrivateOwner", "name": "SyntheticPrivateName", "path_keys": []}
    with pytest.raises(MODULE.ProtocolMethodAmbiguityError) as error:
        MODULE._select_record([record, copy.deepcopy(record)], record["owner"], record["name"])
    assert str(error.value) == "protocol_method_selection_ambiguous"
    assert isinstance(error.value, MODULE.ProtocolEvidenceError)


@pytest.mark.parametrize("role", [0, 1, 2])
@pytest.mark.parametrize("duplicate_first", [False, True])
def test_recover_never_calls_compact_fallback_for_named_ambiguity(monkeypatch, role, duplicate_first):
    records = records_for("asyncrat")
    duplicate = copy.deepcopy(records[role])
    duplicate["token"] = "0x06000004"
    values = [duplicate, *records] if duplicate_first else [*records, duplicate]
    calls = []
    monkeypatch.setattr(MODULE, "extract_method_records", lambda _data: values)

    def compact_would_succeed(_records, _digest):
        calls.append("compact_called")
        return {"analysis_status": "complete", "protocol_variant": "synthetic_control"}

    monkeypatch.setattr(MODULE, "summarize_obfuscated_asyncrat_records", compact_would_succeed)
    # これはPE/CILではなく人工recordsへ渡すdigestのanchorだけ。
    data = b"synthetic protocol record digest anchor"
    with pytest.raises(MODULE.ProtocolMethodAmbiguityError):
        MODULE.recover(data, "asyncrat", hashlib.sha256(data).hexdigest())
    assert calls == []


@pytest.mark.parametrize("mode", ["missing", "partial"])
def test_reviewed_compact_fallback_control_remains_available(monkeypatch, mode):
    records = [] if mode == "missing" else records_for("asyncrat")
    if records:
        records[0]["path_keys"] = []
    monkeypatch.setattr(MODULE, "extract_method_records", lambda _data: records)
    expected = {"analysis_status": "complete", "protocol_variant": "synthetic_control"}
    calls = []

    def compact(_records, _digest):
        calls.append("compact_called")
        return expected

    monkeypatch.setattr(MODULE, "summarize_obfuscated_asyncrat_records", compact)
    data = b"synthetic protocol record digest anchor"
    assert MODULE.recover(data, "asyncrat", hashlib.sha256(data).hexdigest()) is expected
    assert calls == ["compact_called"]


class BytesSubclass(bytes):
    pass


@pytest.mark.parametrize("entry", ["recover", "extract"])
@pytest.mark.parametrize("value", [None, "", 0, False, bytearray(), memoryview(b""), BytesSubclass(b"")])
def test_non_exact_bytes_rejected_before_hash_or_parser(monkeypatch, entry, value):
    calls = []

    def forbidden(*_args, **_kwargs):
        calls.append("hash_or_parser_called")
        raise AssertionError("入力型拒否より前にhash/parserを呼んだ")

    monkeypatch.setattr(MODULE, "hashlib", SimpleNamespace(sha256=forbidden))
    monkeypatch.setattr(MODULE.dnfile, "dnPE", forbidden)
    with pytest.raises(MODULE.ProtocolEvidenceError, match="^protocol_input_not_exact_bytes$"):
        if entry == "recover":
            MODULE.recover(value, "asyncrat", "a" * 64)
        else:
            MODULE.extract_method_records(value)
    assert calls == []


@pytest.fixture(scope="module")
def oversized_artificial_bytes():
    return bytes(MODULE.MAXIMUM_INPUT_BYTES + 1)


@pytest.mark.parametrize("entry", ["recover", "extract"])
def test_32mib_plus_one_is_rejected_before_hash_or_parser(monkeypatch, entry, oversized_artificial_bytes):
    calls = []

    def forbidden(*_args, **_kwargs):
        calls.append("hash_or_parser_called")
        raise AssertionError("入力size拒否より前にhash/parserを呼んだ")

    monkeypatch.setattr(MODULE, "hashlib", SimpleNamespace(sha256=forbidden))
    monkeypatch.setattr(MODULE.dnfile, "dnPE", forbidden)
    with pytest.raises(MODULE.ProtocolEvidenceError, match="^protocol_input_size_limit_exceeded$"):
        if entry == "recover":
            MODULE.recover(oversized_artificial_bytes, "asyncrat", "a" * 64)
        else:
            MODULE.extract_method_records(oversized_artificial_bytes)
    assert calls == []


@pytest.mark.parametrize("size", [0, 1, 32 * 1024 * 1024])
def test_common_input_guard_accepts_exact_boundary_without_parsing(size):
    assert MODULE.MAXIMUM_INPUT_BYTES == 32 * 1024 * 1024
    assert MODULE._validate_input_bytes(bytes(size)) is None


def test_valid_hash_mismatch_still_precedes_record_extraction(monkeypatch):
    calls = []
    monkeypatch.setattr(MODULE, "extract_method_records", lambda _data: calls.append("extract_called"))
    with pytest.raises(MODULE.ProtocolEvidenceError, match="sample SHA-256が一致しません"):
        MODULE.recover(b"synthetic digest anchor", "asyncrat", "0" * 64)
    assert calls == []
