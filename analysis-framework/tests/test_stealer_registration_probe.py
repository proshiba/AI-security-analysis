from __future__ import annotations

import base64
import hashlib
import json
import re
import sys
from pathlib import Path
from urllib.parse import parse_qs

import pytest
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms

COMMON = Path(__file__).parents[1] / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

import c2_protocol_probe_profiles as profile_registry
import remus_profile_evidence as evidence
import stealer_registration_probe as probe
from remus_profile_evidence import build_evidence_binding


def response(
    body: bytes,
    *,
    status: int = 200,
    content_type: str = "application/json",
    truncated: bool = False,
) -> probe.BoundedHttpResponse:
    return probe.BoundedHttpResponse(
        status=status,
        content_type=content_type,
        body=body,
        truncated=truncated,
        resolved_ips=("203.0.113.10",),
        connected_ip="203.0.113.10",
    )


def base_profile(handler: str) -> dict:
    return {
        "handler": handler,
        "host": "c2.example",
        "port": 80,
        "http_path": "/",
        "http_host": "c2.example",
        "pinned_ips": ["203.0.113.10"],
        "timeout_seconds": 3.0,
        "maximum_request_bytes": 4096,
        "maximum_response_bytes": 65536,
    }


def reviewed_stealc_profile() -> dict:
    return profile_registry.load_profiles()[probe.STEALC_EXACT_PROFILE_ID]


def stealc_probe_kwargs() -> dict[str, str]:
    pin = profile_registry.profile_registry_metadata()
    return {
        "expected_profile_registry_source": pin["source"],
        "expected_profile_registry_sha256": pin["sha256"],
    }


def reviewed_lumma_profile() -> dict:
    return profile_registry.load_profiles()[probe.LUMMA_EXACT_PROFILE_ID]


def lumma_probe_kwargs() -> dict[str, str]:
    pin = profile_registry.profile_registry_metadata()
    return {
        "expected_profile_registry_source": pin["source"],
        "expected_profile_registry_sha256": pin["sha256"],
    }


def stealc_create_response(token: str, *, dynamic_key: str = "abcdef1234") -> dict:
    return {
        "opcode": "success",
        "access_token": token,
        "self_delete": True,
        "take_screenshot": False,
        "loader": True,
        "steal_steam": True,
        "steal_outlook": False,
        "browsers": ["fixture"],
        "plugins": [],
        "files": [],
        dynamic_key: "1234567890",
    }


def run_stealc(post) -> dict:
    return probe.probe_reviewed_stealer_registration(
        reviewed_stealc_profile(),
        allow_network=True,
        allow_registration_tasking=True,
        post=post,
        **stealc_probe_kwargs(),
    )


def reviewed_remus_profile(tmp_path: Path) -> dict:
    parent = "1" * 64
    dump = "2" * 64
    recovered = "3" * 64
    pinned_ip = "154.12.237.176"
    endpoint = {
        "slot_index": 1,
        "uri": "http://c2.example:80",
        "scheme": "http",
        "host": "c2.example",
        "port": 80,
    }
    values = {
        "parent_sha256": parent,
        "dump_sha256": dump,
        "recovered_pe_sha256": recovered,
        "tag": "b" * 32,
        "exp": 1_785_860_014,
        "http_host": "microsoft.com",
        "pinned_ip": pinned_ip,
        "endpoint": endpoint,
    }
    flow_relative = "evidence/remus-probe-flow.json"
    flow_artifact = {
        "schema_version": 1,
        "artifact_type": evidence.FLOW_ARTIFACT_TYPE,
        "sample": {"sha256": parent},
        "run": {"id": "probe-test-run"},
        "artifacts": {
            "process_dump": {"sha256": dump},
            "recovered_pe": {"sha256": recovered},
        },
        "flow": {
            "tag": "b" * 32,
            "exp": 1_785_860_014,
            "http_host": "microsoft.com",
            "pinned_ip": pinned_ip,
            "endpoint": endpoint,
        },
    }
    flow_raw = (json.dumps(flow_artifact, sort_keys=True) + "\n").encode("utf-8")
    flow_path = tmp_path / Path(*flow_relative.split("/"))
    flow_path.parent.mkdir(parents=True, exist_ok=True)
    flow_path.write_bytes(flow_raw)
    flow_sha256 = hashlib.sha256(flow_raw).hexdigest()
    flow_fields = {"tag", "exp", "http_host", "pinned_ip", "endpoint"}
    manifest = {
        "schema_version": 1,
        "manifest_type": evidence.MANIFEST_TYPE,
        "family": "remusstealer",
        "review": {
            "status": "reviewed",
            "same_sample_verified": True,
            "same_flow_verified": True,
            "flow_evidence_sha256": flow_sha256,
        },
        "fields": {
            name: {
                "value": value,
                "sample_sha256": parent,
                "flow_evidence_sha256": flow_sha256 if name in flow_fields else None,
            }
            for name, value in values.items()
        },
    }
    raw = (json.dumps(manifest, sort_keys=True) + "\n").encode("utf-8")
    relative = Path("evidence") / "remus-probe.json"
    path = tmp_path / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    manifest_sha256 = hashlib.sha256(raw).hexdigest()
    review_id = "probe-test-review"
    binding = build_evidence_binding(relative.as_posix(), manifest_sha256, review_id)
    review_registry = {
        "schema_version": 1,
        "registry_type": evidence.REVIEW_REGISTRY_TYPE,
        "reviews": [
            {
                "review_id": review_id,
                "status": "approved",
                "manifest_source": relative.as_posix(),
                "manifest_sha256": manifest_sha256,
                "flow_artifact_source": flow_relative,
                "flow_artifact_sha256": flow_sha256,
                "flow_artifact_pointers": evidence.FLOW_ARTIFACT_POINTERS,
                "sample_sha256": parent,
                "run_id": "probe-test-run",
                "dump_sha256": dump,
                "recovered_pe_sha256": recovered,
            }
        ],
    }
    review_raw = (json.dumps(review_registry, sort_keys=True) + "\n").encode("utf-8")
    review_path = tmp_path / Path(*evidence.REVIEW_REGISTRY_SOURCE.split("/"))
    review_path.parent.mkdir(parents=True, exist_ok=True)
    review_path.write_bytes(review_raw)
    return {
        **base_profile("remus_registration_task"),
        "family": "remusstealer",
        "protocol": "remusstealer",
        "method": "remus_registration_task",
        "sample_sha256s": [parent],
        "selected_slot_index": 1,
        "dump_sha256": dump,
        "recovered_pe_sha256": recovered,
        "request_budget": 2,
        "tag": "b" * 32,
        "exp": 1_785_860_014,
        "http_host": "microsoft.com",
        "pinned_ips": [pinned_ip],
        "maximum_response_bytes": 8192,
        "evidence_binding": binding,
        "evidence_source": binding["source"],
        "evidence_sha256": binding["sha256"],
        "review_id": review_id,
        "review_registry_source": evidence.REVIEW_REGISTRY_SOURCE,
        "review_registry_sha256": hashlib.sha256(review_raw).hexdigest(),
        "flow_artifact_source": flow_relative,
        "flow_artifact_sha256": flow_sha256,
        "run_id": "probe-test-run",
        "source": f"{binding['source']}:/fields/endpoint/value",
    }


def test_safety_gates_prevent_registration() -> None:
    calls = []

    def post(*args):
        calls.append(args)
        raise AssertionError("安全gate未充足時は送信しない")

    profile = base_profile("lumma_v6_registration_task")
    assert probe.probe_reviewed_stealer_registration(profile, post=post)["status"] == "network_disabled"
    result = probe.probe_reviewed_stealer_registration(profile, allow_network=True, post=post)
    assert result["status"] == "malware_registration_tasking_disabled"
    assert calls == []


def test_stealc_registers_synthetic_hwid_and_polls_loader_once() -> None:
    profile = reviewed_stealc_profile()
    key = base64.b64decode(profile["network_rc4_key_base64"])
    token = "a" * 72
    calls: list[dict] = []

    def post(_profile: dict, body: bytes, _headers: dict[str, str]):
        decoded = probe._stealc_decode(body, key)
        assert decoded is not None
        calls.append(decoded)
        if len(calls) == 1:
            return response(probe._stealc_encode(stealc_create_response(token), key))
        return response(
            probe._stealc_encode(
                {"opcode": "success", "loader": [{"url": "https://payload.invalid/secret"}]},
                key,
            )
        )

    result = probe.probe_reviewed_stealer_registration(
        profile,
        allow_network=True,
        allow_registration_tasking=True,
        post=post,
        **stealc_probe_kwargs(),
    )
    assert calls[0]["build"] == "1backs"
    assert calls[0]["type"] == "create"
    assert re.fullmatch(r"[0-9A-F-]{36}", calls[0]["hwid"])
    assert calls[1] == {"access_token": token, "type": "loader"}
    assert result["status"] == "confirmed_stealc_registration_task"
    assert result["request_count"] == 2
    assert result["task_available"] is True
    assert result["task_entry_count"] == 1
    published = json.dumps(result)
    assert result["registration_response_class"] == "success"
    assert result["configuration_schema_confirmed"] is True
    assert result["configuration_schema_scope"] == ("configured_acceptance_policy_not_version_confirmation")
    assert result["version_confirmed_by_response_schema"] is False
    assert result["task_entry_schema_confirmed"] is True
    assert result["task_url_follow_attempted"] is False
    assert result["task_reply_sent"] is False
    assert token not in published
    assert "payload.invalid" not in published
    assert calls[0]["hwid"] not in published
    assert result["task_executed"] is False
    assert result["payload_download_attempted"] is False


def test_lumma_v6_requests_configuration_then_task_with_synthetic_hwid() -> None:
    calls: list[dict[str, list[str]]] = []
    profile = reviewed_lumma_profile()

    def post(_profile: dict, body: bytes, _headers: dict[str, str]):
        calls.append(parse_qs(body.decode("ascii"), keep_blank_values=True))
        body_value = b"{}" if len(calls) == 1 else b"[]"
        return response(body_value, content_type="application/octet-stream")

    result = probe.probe_reviewed_stealer_registration(
        profile,
        allow_network=True,
        allow_registration_tasking=True,
        post=post,
        **lumma_probe_kwargs(),
    )
    assert calls[0] == {"uid": [probe.LUMMA_EXACT_UID], "cid": [""]}
    assert calls[1]["uid"] == [probe.LUMMA_EXACT_UID]
    assert calls[1]["cid"] == [""]
    assert re.fullmatch(r"[0-9A-F]{32}", calls[1]["hwid"][0])
    assert result["status"] == "lumma_task_schema_unverified"
    assert result["c2_confirmed"] is False
    assert result["task_response_decrypted"] is True
    assert result["task_available"] is False
    assert result["task_entry_count"] == 0
    assert result["task_schema_confirmed"] is False
    assert result["version_confirmed"] is False
    assert calls[1]["hwid"][0] not in json.dumps(result)


def test_lumma_opaque_task_response_is_not_protocol_confirmation() -> None:
    calls = 0
    profile = reviewed_lumma_profile()

    def post(_profile: dict, _body: bytes, _headers: dict[str, str]):
        nonlocal calls
        calls += 1
        return response(bytes([calls]) * 64, content_type="application/octet-stream")

    result = probe.probe_reviewed_stealer_registration(
        profile,
        allow_network=True,
        allow_registration_tasking=True,
        post=post,
        **lumma_probe_kwargs(),
    )
    assert calls == 2
    assert result["task_response_received"] is True
    assert result["task_response_decrypted"] is False
    assert result["c2_confirmed"] is False


def remus_encrypted(value: dict, key_byte: int, nonce_byte: int) -> bytes:
    key = bytes([key_byte]) * 32
    nonce = bytes([nonce_byte]) * 8
    plain = json.dumps(value, separators=(",", ":")).encode("utf-8") + b"\0"
    transform = Cipher(algorithms.ChaCha20(key, b"\0" * 8 + nonce), mode=None).encryptor()
    return key + nonce + transform.update(plain) + transform.finalize()


def test_remus_decrypts_token_and_polls_step_one_without_publishing_task(tmp_path: Path) -> None:
    token = "9702295b-244d-4bc7-95ed-a2597ae41d4b"
    calls: list[dict[str, list[str]]] = []
    profile = reviewed_remus_profile(tmp_path)

    registry_pin = profile_registry.profile_registry_metadata()

    def post(_profile: dict, body: bytes, _headers: dict[str, str]):
        calls.append(parse_qs(body.decode("ascii")))
        if len(calls) == 1:
            return response(
                remus_encrypted({"vm": False, "ss": True, "access_token": token}, 1, 2),
                status=201,
                content_type="application/octet-stream",
            )
        return response(
            remus_encrypted(
                {"type": 0, "name": "secret-task-name", "data": {"secret": "value"}},
                3,
                4,
            ),
            status=201,
            content_type="application/octet-stream",
        )

    result = probe.probe_reviewed_stealer_registration(
        profile,
        allow_network=True,
        allow_registration_tasking=True,
        post=post,
        repository_root=tmp_path,
        expected_evidence_sha256=profile["evidence_sha256"],
        expected_evidence_source=profile["evidence_source"],
        expected_profile_registry_source=registry_pin["source"],
        expected_profile_registry_sha256=registry_pin["sha256"],
        expected_registry_source=profile["review_registry_source"],
        expected_registry_sha256=profile["review_registry_sha256"],
        expected_flow_artifact_source=profile["flow_artifact_source"],
        expected_flow_artifact_sha256=profile["flow_artifact_sha256"],
        expected_review_id=profile["review_id"],
    )
    assert calls[0]["tag"] == ["b" * 32]
    assert calls[0]["exp"] == ["1785860014"]
    assert re.fullmatch(r"[0-9a-f]{32}", calls[0]["hwid"][0])
    assert calls[1] == {"access_token": [token], "step": ["1"]}
    assert result["status"] == "remus_task_schema_unverified"
    assert result["c2_confirmed"] is False
    assert result["task_type"] == 0
    assert result["task_available"] is None
    assert result["task_schema_confirmed"] is False
    published = json.dumps(result)
    assert token not in published
    assert "secret-task-name" not in published
    assert "secret" not in published
    assert calls[0]["hwid"][0] not in published


def test_registration_truncation_never_advances_to_task_poll() -> None:
    calls = 0
    profile = reviewed_lumma_profile()

    def post(_profile: dict, _body: bytes, _headers: dict[str, str]):
        nonlocal calls
        calls += 1
        return response(b"x" * 10, content_type="application/octet-stream", truncated=True)

    result = probe.probe_reviewed_stealer_registration(
        profile,
        allow_network=True,
        allow_registration_tasking=True,
        post=post,
        **lumma_probe_kwargs(),
    )
    assert calls == 1
    assert result["c2_confirmed"] is False
    assert result["task_poll_attempted"] is False


@pytest.mark.parametrize(
    ("field", "mutation"),
    [
        ("profile_id", "lumma-other"),
        ("sample_sha256s", ["0" * 64]),
        ("host", "other.example"),
        ("port", True),
        ("pinned_ips", ["8.8.8.8"]),
        ("uid", "0" * 40),
        ("cid", "campaign"),
        ("http_path", "/other"),
        ("http_host", "other.example"),
        ("request_budget", 1),
        ("timeout_seconds", 2.0),
        ("maximum_request_bytes", 4095),
        ("maximum_response_bytes", 65535),
        ("source", "analysis-results/other.json:samples[2]"),
    ],
)
def test_lumma_non_exact_profile_sends_zero_requests(
    field: str,
    mutation: object,
) -> None:
    profile = reviewed_lumma_profile()
    profile[field] = mutation
    calls: list[object] = []

    def post(*args: object, **kwargs: object) -> None:
        calls.append((args, kwargs))
        raise AssertionError("exact profile不一致時は送信しない")

    with pytest.raises(probe.StealerProbeError, match="exact profile|binding"):
        probe.probe_reviewed_stealer_registration(
            profile,
            allow_network=True,
            allow_registration_tasking=True,
            post=post,
            **lumma_probe_kwargs(),
        )
    assert calls == []


@pytest.mark.parametrize(
    ("pin_name", "mutation"),
    [
        ("expected_profile_registry_source", "analysis-framework/common/other.json"),
        ("expected_profile_registry_sha256", "0" * 64),
    ],
)
def test_lumma_registry_pin_mismatch_sends_zero_requests(
    pin_name: str,
    mutation: str,
) -> None:
    kwargs = lumma_probe_kwargs()
    kwargs[pin_name] = mutation
    calls: list[object] = []

    def post(*args: object, **post_kwargs: object) -> None:
        calls.append((args, post_kwargs))
        raise AssertionError("registry pin不一致時は送信しない")

    with pytest.raises(probe.StealerProbeError, match="registry pin"):
        probe.probe_reviewed_stealer_registration(
            reviewed_lumma_profile(),
            allow_network=True,
            allow_registration_tasking=True,
            post=post,
            **kwargs,
        )
    assert calls == []


def test_http_transport_oserror_is_normalized(monkeypatch: pytest.MonkeyPatch) -> None:
    profile = reviewed_lumma_profile()

    def fail_resolve(_profile: dict) -> tuple[tuple[str, ...], str]:
        raise OSError("private transport detail")

    monkeypatch.setattr(probe, "_resolve_and_pin", fail_resolve)
    with pytest.raises(probe.StealerProbeError, match="transport failed: OSError") as caught:
        probe._post_http(profile, b"x", {})
    assert "private transport detail" not in str(caught.value)


def test_http_body_read_uses_absolute_deadline(monkeypatch: pytest.MonkeyPatch) -> None:
    profile = reviewed_lumma_profile()
    profile["maximum_response_bytes"] = 4

    class FakeSocket:
        def __init__(self) -> None:
            self.timeouts: list[float] = []

        def settimeout(self, timeout: float) -> None:
            self.timeouts.append(timeout)

    class FakeResponse:
        status = 200

        @staticmethod
        def getheader(_name: str) -> str:
            return "application/octet-stream"

        @staticmethod
        def read(_size: int) -> bytes:
            return b"x"

    class FakeConnection:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            self.sock = FakeSocket()
            self.closed = False

        def putrequest(self, *_args: object, **_kwargs: object) -> None:
            pass

        def putheader(self, *_args: object) -> None:
            pass

        def endheaders(self, _body: bytes) -> None:
            pass

        @staticmethod
        def getresponse() -> FakeResponse:
            return FakeResponse()

        def close(self) -> None:
            self.closed = True

    ticks = iter([10.0, 10.1, 13.1])
    monkeypatch.setattr(
        probe,
        "_resolve_and_pin",
        lambda _profile: (("64.89.161.173",), "64.89.161.173"),
    )
    monkeypatch.setattr(probe.http.client, "HTTPConnection", FakeConnection)
    monkeypatch.setattr(probe.time, "monotonic", lambda: next(ticks))

    with pytest.raises(probe.StealerProbeError, match="絶対期限"):
        probe._post_http(profile, b"x", {})


def remus_probe_kwargs(profile: dict, repository_root: Path) -> dict:
    registry_pin = profile_registry.profile_registry_metadata()
    return {
        "repository_root": repository_root,
        "expected_evidence_sha256": profile["evidence_sha256"],
        "expected_evidence_source": profile["evidence_source"],
        "expected_profile_registry_source": registry_pin["source"],
        "expected_profile_registry_sha256": registry_pin["sha256"],
        "expected_registry_source": profile["review_registry_source"],
        "expected_registry_sha256": profile["review_registry_sha256"],
        "expected_flow_artifact_source": profile["flow_artifact_source"],
        "expected_flow_artifact_sha256": profile["flow_artifact_sha256"],
        "expected_review_id": profile["review_id"],
    }


@pytest.mark.parametrize(
    ("field", "mutation"),
    [
        ("request_budget", True),
        ("request_budget", 1),
        ("timeout_seconds", True),
        ("timeout_seconds", 2.9),
        ("maximum_request_bytes", True),
        ("maximum_request_bytes", 4095),
        ("maximum_response_bytes", True),
        ("maximum_response_bytes", 8191),
        ("pinned_ips", ["154.12.237.176", "8.8.8.8"]),
        ("pinned_ips", ["127.0.0.1"]),
    ],
)
def test_remus_limit_or_ip_mutation_sends_zero_requests(
    tmp_path: Path,
    field: str,
    mutation: object,
) -> None:
    profile = reviewed_remus_profile(tmp_path)
    profile[field] = mutation
    calls: list[object] = []

    def post(*args: object, **kwargs: object) -> None:
        calls.append((args, kwargs))
        raise AssertionError("network send must remain unreachable")

    with pytest.raises(probe.StealerProbeError):
        probe.probe_reviewed_stealer_registration(
            profile,
            allow_network=True,
            allow_registration_tasking=True,
            post=post,
            **remus_probe_kwargs(profile, tmp_path),
        )
    assert calls == []


@pytest.mark.parametrize(
    ("pin_name", "mutation"),
    [
        ("expected_evidence_sha256", "0" * 64),
        ("expected_evidence_source", "evidence/other.json"),
        ("expected_profile_registry_sha256", "0" * 64),
        ("expected_profile_registry_source", "analysis-framework/common/other.json"),
        ("expected_registry_sha256", "0" * 64),
        ("expected_registry_source", "analysis-framework/common/other.json"),
        ("expected_flow_artifact_sha256", "0" * 64),
        ("expected_flow_artifact_source", "evidence/other-flow.json"),
        ("expected_review_id", "other-review"),
    ],
)
def test_remus_preprobe_pin_mutation_sends_zero_requests(
    tmp_path: Path,
    pin_name: str,
    mutation: object,
) -> None:
    profile = reviewed_remus_profile(tmp_path)
    kwargs = remus_probe_kwargs(profile, tmp_path)
    kwargs[pin_name] = mutation
    calls: list[object] = []

    def post(*args: object, **post_kwargs: object) -> None:
        calls.append((args, post_kwargs))
        raise AssertionError("network send must remain unreachable")

    with pytest.raises(probe.StealerProbeError):
        probe.probe_reviewed_stealer_registration(
            profile,
            allow_network=True,
            allow_registration_tasking=True,
            post=post,
            **kwargs,
        )
    assert calls == []


@pytest.mark.parametrize("task_type", [True, None, -1, 6])
def test_remus_boolean_null_and_out_of_range_task_type_are_never_confirmed(
    tmp_path: Path,
    task_type: object,
) -> None:
    token = "9702295b-244d-4bc7-95ed-a2597ae41d4b"
    profile = reviewed_remus_profile(tmp_path)
    calls = 0

    def post(_profile: dict, _body: bytes, _headers: dict[str, str]):
        nonlocal calls
        calls += 1
        if calls == 1:
            return response(
                remus_encrypted(
                    {"vm": False, "ss": True, "access_token": token},
                    1,
                    2,
                ),
                status=201,
                content_type="application/octet-stream",
            )
        return response(
            remus_encrypted(
                {"type": task_type, "name": "opaque", "data": {}},
                3,
                4,
            ),
            status=201,
            content_type="application/octet-stream",
        )

    result = probe.probe_reviewed_stealer_registration(
        profile,
        allow_network=True,
        allow_registration_tasking=True,
        post=post,
        **remus_probe_kwargs(profile, tmp_path),
    )

    assert calls == 2
    assert result["status"] == "remus_task_response_mismatch"
    assert result["task_type"] is None
    assert result["task_available"] is None
    assert result["task_schema_confirmed"] is False
    assert result["c2_confirmed"] is False


def test_stealc_hwid_is_stable_and_dynamic_hex_fields_do_not_change_schema_fingerprint() -> None:
    profile = reviewed_stealc_profile()
    key = base64.b64decode(profile["network_rc4_key_base64"])
    token = "d" * 72

    def run_one(dynamic_key: str) -> tuple[str, str]:
        calls: list[dict] = []

        def post(_profile: dict, body: bytes, _headers: dict[str, str]):
            decoded = probe._stealc_decode(body, key)
            assert decoded is not None
            calls.append(decoded)
            message = (
                stealc_create_response(token, dynamic_key=dynamic_key)
                if len(calls) == 1
                else {"opcode": "success", "loader": []}
            )
            return response(probe._stealc_encode(message, key))

        result = run_stealc(post)
        assert result["status"] == "confirmed_stealc_registration_task"
        assert result["dynamic_hex_field_count"] == 1
        return calls[0]["hwid"], result["configuration_schema_sha256"]

    first_hwid, first_schema = run_one("abcdef1234")
    second_hwid, second_schema = run_one("abcdef5678")
    assert first_hwid == second_hwid
    assert first_schema == second_schema


@pytest.mark.parametrize(
    ("opcode", "expected_status"),
    [
        ("blocked", "stealc_registration_blocked"),
        ("block", "stealc_registration_block"),
        ("error", "stealc_registration_error"),
        ("unknown", "stealc_registration_unknown"),
        ("error1", "stealc_registration_error1"),
        ("error2", "stealc_registration_error2"),
        ("error3", "stealc_registration_error3"),
        ("error4", "stealc_registration_error4"),
        ("error5", "stealc_registration_error5"),
    ],
)
def test_stealc_create_statuses_are_classified_without_loader_poll(
    opcode: str,
    expected_status: str,
) -> None:
    profile = reviewed_stealc_profile()
    key = base64.b64decode(profile["network_rc4_key_base64"])
    calls = 0

    def post(_profile: dict, _body: bytes, _headers: dict[str, str]):
        nonlocal calls
        calls += 1
        return response(probe._stealc_encode({"opcode": opcode}, key))

    result = run_stealc(post)
    assert calls == 1
    assert result["status"] == expected_status
    assert result["registration_response_class"] == opcode
    assert result["registration_accepted"] is False
    assert result["task_poll_attempted"] is False
    assert result["c2_confirmed"] is False


@pytest.mark.parametrize(
    "payload",
    [
        b'{"opcode":"error","opcode":"success"}',
        b'{"outer":{"key":1,"key":2}}',
        b'{"items":[{"key":1,"key":2}]}',
    ],
)
def test_json_decoders_reject_duplicate_keys_at_every_object_depth(
    payload: bytes,
) -> None:
    assert probe._json_object(payload) is None
    assert probe._json_value(payload) is None


def test_stealc_duplicate_opcode_is_rejected_without_loader_poll() -> None:
    profile = reviewed_stealc_profile()
    key = base64.b64decode(profile["network_rc4_key_base64"])
    token = "9" * 72
    valid_payload = json.dumps(
        stealc_create_response(token),
        separators=(",", ":"),
    ).encode("ascii")
    duplicate_opcode_payload = valid_payload.replace(
        b'{"opcode":"success"',
        b'{"opcode":"error","opcode":"success"',
        1,
    )
    calls = 0

    def post(_profile: dict, _body: bytes, _headers: dict[str, str]):
        nonlocal calls
        calls += 1
        if calls > 1:
            raise AssertionError("duplicate opcode応答ではloaderをpollしない")
        encrypted = probe._rc4(duplicate_opcode_payload, key)
        return response(base64.b64encode(encrypted))

    result = run_stealc(post)
    assert calls == 1
    assert result["status"] == "stealc_registration_response_mismatch"
    assert result["registration_response_class"] == "unrecognized"
    assert result["registration_accepted"] is False
    assert result["configuration_schema_confirmed"] is False
    assert result["configuration_schema_scope"] == ("configured_acceptance_policy_not_version_confirmation")
    assert result["version_confirmed_by_response_schema"] is False
    assert result["task_poll_attempted"] is False
    assert result["c2_confirmed"] is False


@pytest.mark.parametrize(
    ("content_type", "mutation"),
    [
        ("text/plain", None),
        ("application/json", "missing_opcode"),
        ("application/json", "missing_config"),
        ("application/json", "wrong_config_type"),
        ("application/json", "unknown_field"),
    ],
)
def test_stealc_create_requires_reviewed_content_type_opcode_token_and_config_schema(
    content_type: str,
    mutation: str | None,
) -> None:
    profile = reviewed_stealc_profile()
    key = base64.b64decode(profile["network_rc4_key_base64"])
    token = "e" * 72
    message = stealc_create_response(token)
    if mutation == "missing_opcode":
        message.pop("opcode")
    elif mutation == "missing_config":
        message = {"opcode": "success", "access_token": token}
    elif mutation == "wrong_config_type":
        message["self_delete"] = 1
    elif mutation == "unknown_field":
        message["unexpected"] = False
    calls = 0

    def post(_profile: dict, _body: bytes, _headers: dict[str, str]):
        nonlocal calls
        calls += 1
        return response(
            probe._stealc_encode(message, key),
            content_type=content_type,
        )

    result = run_stealc(post)
    assert calls == 1
    assert result["status"] == "stealc_registration_response_mismatch"
    assert result["registration_accepted"] is False
    assert result["task_poll_attempted"] is False
    assert result["c2_confirmed"] is False


@pytest.mark.parametrize(
    "entry",
    [
        "https://payload.invalid/not-a-mapping",
        {"url": "ftp://payload.invalid/file"},
        {"url": "https://user:secret@payload.invalid/file"},
        {"url": "https://payload.invalid/file", "extra": True},
    ],
)
def test_stealc_loader_unknown_entry_or_url_schema_is_never_confirmed(entry: object) -> None:
    profile = reviewed_stealc_profile()
    key = base64.b64decode(profile["network_rc4_key_base64"])
    token = "f" * 72
    calls = 0

    def post(_profile: dict, _body: bytes, _headers: dict[str, str]):
        nonlocal calls
        calls += 1
        message = stealc_create_response(token) if calls == 1 else {"opcode": "success", "loader": [entry]}
        return response(probe._stealc_encode(message, key))

    result = run_stealc(post)
    assert calls == 2
    assert result["status"] == "stealc_task_response_mismatch"
    assert result["task_response_class"] == "success"
    assert result["task_entry_schema_confirmed"] is False
    assert result["task_available"] is None
    assert result["c2_confirmed"] is False
    assert result["task_url_follow_attempted"] is False
    assert result["task_reply_sent"] is False
    assert "payload.invalid" not in json.dumps(result)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("profile_id", "stealc-other"),
        ("sample_sha256s", ["0" * 64]),
        ("build", "other-build"),
    ],
)
def test_stealc_non_exact_profile_binding_sends_zero_requests(
    field: str,
    value: object,
) -> None:
    profile = reviewed_stealc_profile()
    profile[field] = value
    calls = 0

    def post(*_args):
        nonlocal calls
        calls += 1
        raise AssertionError("exact profile不一致時は送信しない")

    with pytest.raises(probe.StealerProbeError, match="exact profile"):
        probe.probe_reviewed_stealer_registration(
            profile,
            allow_network=True,
            allow_registration_tasking=True,
            post=post,
            **stealc_probe_kwargs(),
        )
    assert calls == 0
