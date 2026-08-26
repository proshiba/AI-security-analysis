"""PureRAT direct-TLS adapterと共通runnerのoffline安全契約。"""

from __future__ import annotations

import copy
import json
import sys
from pathlib import Path
from typing import Any

import pytest

COMMON = Path(__file__).parents[1] / "common"
ROOT = Path(__file__).parents[2]
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

import run_defensive_rat_emulator as runner  # noqa: E402
from rat_emulator_profiles import (  # noqa: E402
    DEFAULT_REGISTRY_PATH,
    RatEmulatorProfileError,
    load_registry,
    resolve_profile,
)
from rat_emulator_transcript import (  # noqa: E402
    SessionTranscriptWriter,
    build_public_summary,
)

PROFILE_ID = "purerat-441-d025a296-direct-tls10-empty-gclass4"
REGISTRATION_HEX = "160000001f8b08000000000002ffe362000075fa36bb02000000"
REGISTRATION_SHA256 = "fae7f27b56eed121c893860cd4764d64541fe1a0b67bc22da050e70161f44001"


class FragmentingOfflineStream:
    """外部networkを使わず、transport readを3 byteへ分割する。"""

    def __init__(self, inbound: bytes) -> None:
        self.inbound = bytearray(inbound)
        self.sent: list[bytes] = []
        self.timeout: float | None = None

    def settimeout(self, value: float) -> None:
        self.timeout = value

    def recv(self, maximum: int) -> bytes:
        size = min(maximum, 3, len(self.inbound))
        if size == 0:
            return b""
        output = bytes(self.inbound[:size])
        del self.inbound[:size]
        return output

    def sendall(self, value: bytes) -> None:
        self.sent.append(bytes(value))


def _run_offline(short_tmp: Path) -> tuple[dict[str, Any], dict[str, Any], Any, Path]:
    profile = resolve_profile(PROFILE_ID)
    adapter = runner._load_adapter("purerat_direct_tls_v1")
    response = adapter.encode_inner_frame(b"\xb2\x05\x00")
    stream = FragmentingOfflineStream(response)
    private_parent = short_tmp / "pure-private"
    private_parent.mkdir()
    transcript_path = private_parent / "session"
    transcript = SessionTranscriptWriter(transcript_path, session_id="pure-offline")
    kill_path = short_tmp / "pure-kill"
    kill_path.write_text("armed\n", encoding="ascii")
    guarded = runner.GuardedStream(
        stream,
        limits=profile["limits"],
        kill_switch=runner.KillSwitch(kill_path),
        transcript=transcript,
    )
    result = runner._run_adapter(
        profile,
        guarded,
        runner._adapter_event_callback(
            transcript,
            adapter_id="purerat_direct_tls_v1",
        ),
    )
    public = runner._public_adapter_result(result, profile)
    transcript.finalize(status="completed", stop_reason=result["status"])
    return result, public, (stream, guarded), transcript_path


def test_offline_runner_sends_one_fixed_registration_reads_one_frame_and_stops(
    short_tmp: Path,
) -> None:
    _result, public, pair, transcript_path = _run_offline(short_tmp)
    stream, guarded = pair
    assert stream.sent == [bytes.fromhex(REGISTRATION_HEX)]
    assert guarded.outbound_frames == 1
    assert guarded.outbound_bytes == 26
    assert guarded.inbound_frames == 1
    assert guarded.inbound_bytes == public["collection"]["response_size"]
    assert public["c2_confirmed"] is False
    assert public["result_scope"] == "offline_or_loopback_only"
    assert public["registration"]["packet_size"] == 26
    assert public["registration"]["packet_sha256"] == REGISTRATION_SHA256
    assert public["registration"]["real_identity_sent"] is False
    assert public["registration"]["populated_member_count"] == 0
    assert public["decisions"] == [
        {
            "discriminator": 86,
            "message_type": "command",
            "classification": "command_refused",
            "action": "refuse_command_and_terminate",
            "should_respond": False,
            "terminate_session": True,
            "frame_size": public["collection"]["response_size"],
            "frame_sha256": public["collection"]["response_sha256"],
            "decoded_size": 3,
            "decoded_sha256": public["decisions"][0]["decoded_sha256"],
        }
    ]
    assert public["safety"]["application_send_count"] == 1
    assert public["safety"]["task_executed"] is False
    assert public["safety"]["command_reply_sent"] is False
    assert public["safety"]["pfx_loaded"] is False
    assert public["safety"]["private_key_loaded"] is False
    summary = build_public_summary(transcript_path)
    assert [event["event_type"] for event in summary["events"]].count("reviewed_registration_frame") == 1
    serialized = json.dumps({"public": public, "summary": summary}, ensure_ascii=False)
    for forbidden in ('"raw_response":', "PRIVATE KEY", ".pfx", "payload_body"):
        assert forbidden not in serialized


def test_public_mapper_redacts_unknown_nested_values_and_rejects_semantic_mutation(
    short_tmp: Path,
) -> None:
    result, _public, _pair, _transcript_path = _run_offline(short_tmp)
    profile = resolve_profile(PROFILE_ID)
    marker = "RAW-PFX-PRIVATE-KEY-PAYLOAD"
    injected = copy.deepcopy(result)
    injected["raw_response"] = marker
    injected["registration"]["pfx_path"] = marker
    injected["collection"]["payload_body"] = marker
    injected["decisions"][0]["fingerprint"]["raw"] = marker
    injected["safety"]["private_key"] = marker
    public = runner._public_adapter_result(injected, profile)
    assert marker not in json.dumps(public, ensure_ascii=False)
    assert set(public["decisions"][0]) == {
        "discriminator",
        "message_type",
        "classification",
        "action",
        "should_respond",
        "terminate_session",
        "frame_size",
        "frame_sha256",
        "decoded_size",
        "decoded_sha256",
    }

    mutations = []
    wrong_status = copy.deepcopy(result)
    wrong_status["status"] = "c2_confirmed"
    mutations.append(wrong_status)
    wrong_pair = copy.deepcopy(result)
    wrong_pair["decisions"][0]["classification"] = "plugin_descriptor_refused"
    mutations.append(wrong_pair)
    wrong_reply = copy.deepcopy(result)
    wrong_reply["decisions"][0]["should_respond"] = True
    mutations.append(wrong_reply)
    wrong_size = copy.deepcopy(result)
    wrong_size["collection"]["response_size"] += 1
    mutations.append(wrong_size)
    for mutation in mutations:
        with pytest.raises(runner.RatEmulatorRunError):
            runner._public_adapter_result(mutation, profile)


def test_profile_exact_contract_and_mutations_fail_closed(short_tmp: Path) -> None:
    profile = resolve_profile(PROFILE_ID)
    assert profile["adapter_id"] == "purerat_direct_tls_v1"
    assert profile["host"] == "45.192.211.77"
    assert profile["port"] == 56001
    assert profile["pinned_ips"] == ["45.192.211.77"]
    assert profile["tls_version"] == "TLSv1.0"
    assert profile["sni"] is None
    assert profile["registration_mode"] == "fixed_empty_gclass4"
    assert profile["live_scope"] == "offline_or_loopback_only"
    assert profile["evidence_sha256"] == ("6317d660a214c6f5eaf7b369a85e36b3b9d5459baed2876d8315aa60ee410c77")
    assert profile["protocol_profile_object_sha256"] == (
        "01ef2619ccbcc772d95a1bb73291c900627522b5f45b6d7e72f2d2b8b0979cec"
    )
    assert profile["limits"] == {
        "duration_seconds": 3.0,
        "maximum_connections": 1,
        "maximum_outbound_frames": 1,
        "maximum_outbound_bytes": 26,
        "maximum_inbound_frames": 1,
        "maximum_inbound_read_calls": 64,
        "maximum_inbound_bytes": 65536,
        "maximum_frame_bytes": 65536,
        "maximum_commands": 1,
        "minimum_send_interval_seconds": 0.0,
    }

    document = json.loads(DEFAULT_REGISTRY_PATH.read_text(encoding="utf-8"))
    pure_index = next(index for index, item in enumerate(document["profiles"]) if item["profile_id"] == PROFILE_ID)
    mutations = [
        ("live_scope", "leased_external"),
        ("evidence_sha256", "0" * 64),
        ("protocol_profile_object_sha256", "0" * 64),
        ("expected_certificate_sha256", "0" * 64),
        ("tls_version", "TLSv1.2"),
    ]
    for sequence, (key, value) in enumerate(mutations):
        mutated = copy.deepcopy(document)
        mutated["profiles"][pure_index][key] = value
        path = short_tmp / f"pure-registry-{sequence}.json"
        path.write_text(json.dumps(mutated, ensure_ascii=False), encoding="utf-8")
        with pytest.raises(RatEmulatorProfileError):
            load_registry(path, root=ROOT)
    mutated = copy.deepcopy(document)
    mutated["profiles"][pure_index]["limits"]["maximum_outbound_frames"] = 2
    path = short_tmp / "pure-registry-limit.json"
    path.write_text(json.dumps(mutated, ensure_ascii=False), encoding="utf-8")
    with pytest.raises(RatEmulatorProfileError):
        load_registry(path, root=ROOT)


def test_external_live_is_rejected_before_lease_dns_maxmind_or_socket(
    short_tmp: Path,
) -> None:
    calls: list[str] = []

    def forbidden(*_args: object, **_kwargs: object) -> Any:
        calls.append("called")
        raise AssertionError("offline boundary crossed")

    preflight = runner.preflight(PROFILE_ID)
    assert preflight["live_scope"] == "offline_or_loopback_only"
    assert preflight["network_used"] is False
    with pytest.raises(runner.RatEmulatorRunError, match="offline.*loopback"):
        runner.run_live_session(
            PROFILE_ID,
            allow_network=True,
            allow_live_c2_emulation=True,
            acknowledged_profile=PROFILE_ID,
            kill_switch_path=None,
            private_output_directory=short_tmp / "must-not-exist",
            maxmind_cache_directory=short_tmp / "maxmind",
            resolver=forbidden,
            maxmind_preparer=forbidden,
            stream_opener=forbidden,
            adapter_runner=forbidden,
        )
    assert calls == []
