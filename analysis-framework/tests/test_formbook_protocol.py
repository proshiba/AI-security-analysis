"""FormBook legacy offline wire codecとXLoader metadataのsynthetic test。"""

from __future__ import annotations

import dataclasses
import hashlib
import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = (
    ROOT
    / "analysis-framework"
    / "malware"
    / "formbook_loader"
    / "formbook_protocol.py"
)
SPEC = importlib.util.spec_from_file_location("formbook_protocol", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
PROTOCOL = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = PROTOCOL
SPEC.loader.exec_module(PROTOCOL)

HOST = "Example.Invalid"
PATH = "/unit/"


def test_exact_url_key_uses_dword_byte_swapped_sha1() -> None:
    assert PROTOCOL.legacy_url_material(HOST, PATH) == b"Example.Invalid/unit/"
    assert (
        PROTOCOL.derive_legacy_url_key(HOST, PATH).hex()
        == "a570363442bd7efdcdad6efb1fb3d88b8ff0c7b0"
    )
    assert PROTOCOL.derive_legacy_url_key(HOST.lower(), PATH) != (
        PROTOCOL.derive_legacy_url_key(HOST, PATH)
    )

    with pytest.raises(PROTOCOL.FormBookProtocolError):
        PROTOCOL.derive_legacy_url_key("http://Example.Invalid", PATH)
    with pytest.raises(PROTOCOL.FormBookProtocolError):
        PROTOCOL.derive_legacy_url_key(HOST, "/unit")


@pytest.mark.parametrize("symbol", [b"\x00", b"\t", b"\n", b" ", b"\x7f", b"\x80"])
def test_base64_profile_rejects_whitespace_and_control_symbols(symbol: bytes) -> None:
    with pytest.raises(PROTOCOL.FormBookProtocolError, match="空白・制御文字"):
        PROTOCOL.Base64AlphabetProfile("unsafe", symbol, b"/", b"=")


def test_mandiant_published_formbook_url_key_vector() -> None:
    assert (
        PROTOCOL.derive_legacy_url_key(
            "www.clicks-track.info", "/list/hx28/"
        ).hex()
        == "3c8a199b61f46ffa54b740cca84007c9aeb95915"
    )


def test_standard_rc4_known_vector_and_symmetry() -> None:
    ciphertext = PROTOCOL.rc4_crypt(b"Plaintext", b"Key")

    assert ciphertext.hex() == "bbf316e8d940af0ad3"
    assert PROTOCOL.rc4_crypt(ciphertext, b"Key") == b"Plaintext"


def test_checkpoint_published_xloader_1_1_two_layer_vector() -> None:
    encoded = (
        b"Rva7WvGfqee/ASq4k5lYe0dVNkfCuS3TauhC/YI8ic9vhGQpK/u62RmZZV0B"
    )
    outer_key = bytes.fromhex("00ad36f49703cee9023498d594df3b2e568ca3d2")
    inner_key = bytes.fromhex("f36e72e54647ffa7187046d3e035d0bd9d10c3c2")

    decoded, registration = PROTOCOL.decode_xloader_macos11_registration_wire(
        encoded,
        inner_key,
        outer_key,
    )

    assert decoded.plaintext == b"XLNG:572E4DF71.1:OS X 10.14.0 Mojave:cm9vdA=="
    assert registration.bot_id == "572E4DF7"
    assert registration.version == "1.1"
    assert registration.username == b"root"


def test_xloader_macos11_command_loopback_is_strict_and_sanitized() -> None:
    inner_key = bytes(range(20))
    outer_key = bytes(range(20, 40))
    plaintext = b"XLNG4https://example.invalid/payloadXLNG"
    encoded = PROTOCOL.encode_xloader_two_key_network_wire(
        plaintext,
        inner_key,
        outer_key,
    )

    decoded, response = PROTOCOL.decode_xloader_macos11_response_wire(
        encoded,
        inner_key,
        outer_key,
    )
    report = PROTOCOL.summarize_xloader_macos11_command_response(
        encoded,
        decoded,
        response,
    )

    assert response.command_id == 4
    assert response.trailing_magic_present is True
    assert response.body == b"https://example.invalid/payload"
    assert report["body_retained"] is False
    assert report["active_probe_supported"] is False
    assert "example.invalid" not in json.dumps(report)

    without_trailer = PROTOCOL.encode_xloader_two_key_network_wire(
        b"XLNG4https://example.invalid/payload",
        inner_key,
        outer_key,
    )
    with pytest.raises(PROTOCOL.FormBookProtocolError, match="末尾magic"):
        PROTOCOL.decode_xloader_macos11_response_wire(
            without_trailer,
            inner_key,
            outer_key,
        )

    forbidden_body = PROTOCOL.encode_xloader_two_key_network_wire(
        b"XLNG3unexpectedXLNG",
        inner_key,
        outer_key,
    )
    with pytest.raises(PROTOCOL.FormBookProtocolError, match="本文"):
        PROTOCOL.decode_xloader_macos11_response_wire(
            forbidden_body,
            inner_key,
            outer_key,
        )


def test_empty_generation_command_map_never_falls_back_to_current_map() -> None:
    with pytest.raises(PROTOCOL.FormBookProtocolError, match="世代profile"):
        PROTOCOL.parse_xloader_command_plaintext(
            b"XLNG9XLNG",
            command_map=(),
        )


@pytest.mark.parametrize(
    "profile",
    (
        PROTOCOL.BASE64_STANDARD,
        PROTOCOL.BASE64_DASH_UNDERSCORE_DOT,
        PROTOCOL.BASE64_TILDE_PAREN,
    ),
)
def test_profile_base64_round_trip(profile: object) -> None:
    plaintext = b"\xfb\xff\xfe\x00synthetic"
    encoded = PROTOCOL.strict_base64_encode(plaintext, profile)

    assert PROTOCOL.strict_base64_decode(encoded, profile) == plaintext


def test_strict_base64_rejects_wrong_profile_whitespace_and_noncanonical_bits() -> None:
    modified = PROTOCOL.strict_base64_encode(
        b"\xfb\xff\xfe", PROTOCOL.BASE64_DASH_UNDERSCORE_DOT
    )
    assert b"-" in modified or b"_" in modified

    with pytest.raises(PROTOCOL.FormBookProtocolError):
        PROTOCOL.strict_base64_decode(
            modified, PROTOCOL.BASE64_STANDARD
        )
    with pytest.raises(PROTOCOL.FormBookProtocolError):
        PROTOCOL.strict_base64_decode(b"Zg==\n")
    with pytest.raises(PROTOCOL.FormBookProtocolError):
        PROTOCOL.strict_base64_decode(b"Zh==")


def test_registration_wire_round_trip_and_sanitized_summary() -> None:
    plaintext = PROTOCOL.build_legacy_registration(
        bot_id="DEADBEEF",
        version="4.1",
        os_version="Windows Test x64",
        username=b"synthetic-user",
    )
    assert plaintext.startswith(b"FBNG:DEADBEEF4.1:")

    encoded = PROTOCOL.encode_legacy_registration_wire(
        plaintext,
        HOST,
        PATH,
        base64_profile=PROTOCOL.BASE64_DASH_UNDERSCORE_DOT,
    )
    registration = PROTOCOL.decode_legacy_registration_wire(
        encoded,
        HOST,
        PATH,
        base64_profile=PROTOCOL.BASE64_DASH_UNDERSCORE_DOT,
    )
    report = PROTOCOL.summarize_legacy_registration(encoded, registration)

    assert registration.bot_id == "DEADBEEF"
    assert registration.version == "4.1"
    assert registration.username == b"synthetic-user"
    assert report["plaintext_sha256"] == hashlib.sha256(plaintext).hexdigest()
    assert report["plaintext_length"] == len(plaintext)
    assert report["plaintext_retained"] is False
    assert "DEADBEEF" not in str(report)
    assert "synthetic-user" not in str(report)


def test_legacy_registration_defaults_to_observed_modified_base64() -> None:
    plaintext = PROTOCOL.build_legacy_registration(
        bot_id="DEADBEEF",
        version="4.1",
        os_version="Windows Test x64",
        username=b"synthetic-user",
    )

    encoded = PROTOCOL.encode_legacy_registration_wire(
        plaintext,
        HOST,
        PATH,
    )

    assert encoded == PROTOCOL.encode_legacy_registration_wire(
        plaintext,
        HOST,
        PATH,
        base64_profile=PROTOCOL.BASE64_DASH_UNDERSCORE_DOT,
    )
    assert encoded != PROTOCOL.encode_legacy_registration_wire(
        plaintext,
        HOST,
        PATH,
        base64_profile=PROTOCOL.BASE64_STANDARD,
    )
    assert PROTOCOL.decode_legacy_registration_wire(
        encoded,
        HOST,
        PATH,
    ).plaintext == plaintext


def test_registration_parser_accepts_observed_single_space_but_rejects_bad_grammar() -> None:
    spaced = PROTOCOL.build_legacy_registration(
        bot_id="A1B2C3D4",
        version="2.9",
        os_version="Synthetic OS x86",
        username=b"user",
        bot_version_separator=" ",
    )
    assert PROTOCOL.parse_legacy_registration(spaced).bot_version_separator == " "

    with pytest.raises(PROTOCOL.FormBookProtocolError):
        PROTOCOL.parse_legacy_registration(
            b"FBNG:deadbeef4.1:Synthetic OS x64:dXNlcg=="
        )
    with pytest.raises(PROTOCOL.FormBookProtocolError):
        PROTOCOL.parse_legacy_registration(
            b"FBNG:DEADBEEF4.1:Synthetic:OS:dXNlcg=="
        )


def test_legacy_response_round_trip_and_body_is_not_published() -> None:
    body = b"synthetic-offline-argument"
    wire = PROTOCOL.encode_legacy_response(4, body, HOST, PATH)
    response = PROTOCOL.parse_legacy_response(wire, HOST, PATH)
    report = PROTOCOL.summarize_legacy_response(wire, response)

    assert wire[:5] == b"FBNG4"
    assert response.command_id == 4
    assert response.body == body
    assert report["body_sha256"] == hashlib.sha256(body).hexdigest()
    assert report["body_length"] == len(body)
    assert report["body_retained"] is False
    assert report["execution_supported"] is False
    assert body.decode("ascii") not in str(report)


def test_legacy_response_strictly_rejects_magic_command_key_and_shape_errors() -> None:
    valid = PROTOCOL.encode_legacy_response(4, b"argument", HOST, PATH)

    with pytest.raises(PROTOCOL.FormBookProtocolError):
        PROTOCOL.parse_legacy_response(b"BANG" + valid[4:], HOST, PATH)
    with pytest.raises(PROTOCOL.FormBookProtocolError):
        PROTOCOL.parse_legacy_response(
            b"FBNG0" + valid[5:], HOST, PATH
        )
    with pytest.raises(PROTOCOL.FormBookProtocolError):
        PROTOCOL.parse_legacy_response(valid, HOST, "/other/")
    with pytest.raises(PROTOCOL.FormBookProtocolError):
        PROTOCOL.encode_legacy_response(3, b"unexpected", HOST, PATH)
    with pytest.raises(PROTOCOL.FormBookProtocolError):
        PROTOCOL.encode_legacy_response(1, b"", HOST, PATH)


def test_xloader_profiles_are_declarative_and_validate() -> None:
    names = PROTOCOL.validate_all_xloader_profiles()

    assert "xloader_4_3" in names
    assert "xloader_8_1_plus" in names
    for profile in PROTOCOL.XLOADER_PROFILES.values():
        assert profile.implementation == "metadata_only"
        assert profile.magic == b"XLNG"
        assert all(not callable(step.operation) for graph in profile.transform_graphs for step in graph.steps)

    current = PROTOCOL.XLOADER_PROFILES["xloader_8_1_plus"]
    command_map = {command.command_id: command for command in current.commands}
    assert command_map[6].action == "資格情報収集を起動"
    assert command_map[7].action == "OSを再起動"
    assert command_map[9].action == "未実装stub"
    assert {graph.name for graph in current.transform_graphs} == {
        "get_encode_metadata",
        "post_encode_metadata",
        "response_decode_metadata",
    }
    assert {(flow.method, flow.internal_request_id) for flow in current.network_flows} == {
        ("GET", 6),
        ("POST", 3),
        ("RAW_TCP", None),
    }


def test_xloader_profile_validator_rejects_executable_or_unknown_transform() -> None:
    profile = PROTOCOL.XLOADER_PROFILES["xloader_8_1_plus"]
    with pytest.raises(PROTOCOL.FormBookProtocolError):
        PROTOCOL.validate_xloader_profile(
            dataclasses.replace(profile, implementation="codec")
        )

    bad_step = PROTOCOL.TransformStep("bad", "network_request")
    bad_graph = PROTOCOL.TransformGraph("bad_graph", "encode", (bad_step,))
    with pytest.raises(PROTOCOL.FormBookProtocolError):
        PROTOCOL.validate_transform_graph(bad_graph)


def test_cli_decodes_saved_registration_without_retaining_plaintext(
    tmp_path: Path,
) -> None:
    plaintext = PROTOCOL.build_legacy_registration(
        bot_id="DEADBEEF",
        version="4.1",
        os_version="Synthetic Windows",
        username=b"private-user",
    )
    wire = PROTOCOL.encode_legacy_registration_wire(plaintext, HOST, PATH)
    wire_path = tmp_path / "registration.bin"
    output_path = tmp_path / "summary.json"
    wire_path.write_bytes(wire)

    assert PROTOCOL.main(
        [
            "decode-registration",
            str(wire_path),
            "--host",
            HOST,
            "--path",
            PATH,
            "--output",
            str(output_path),
        ]
    ) == 0
    document = json.loads(output_path.read_text(encoding="utf-8"))

    assert document["analysis_type"] == "formbook_legacy_registration_offline_decode"
    assert document["network_contacted"] is False
    assert "DEADBEEF" not in output_path.read_text(encoding="utf-8")
    assert "private-user" not in output_path.read_text(encoding="utf-8")


def test_cli_profiles_explicitly_excludes_active_probe(tmp_path: Path) -> None:
    output_path = tmp_path / "profiles.json"

    assert PROTOCOL.main(
        ["profiles", "--output", str(output_path)]
    ) == 0
    document = json.loads(output_path.read_text(encoding="utf-8"))

    assert document["formbook_legacy_codec"] == "implemented_offline_only"
    assert {
        command["command_id"]
        for command in document["formbook_legacy_protocol"]["commands"]
    } == set(range(1, 10))
    assert document["active_probe_supported"] is False
    assert document["command_execution_supported"] is False
    assert any(
        profile["name"] == "xloader_8_1_plus"
        for profile in document["xloader_profiles"]
    )
    assert document["c2_confirmation_policy"]["open_port_alone"] == "insufficient"
    assert (
        document["c2_confirmation_policy"]["minimum_independent_evidence_classes"]
        == 4
    )
    assert (
        document["xloader_implemented_codecs"]["v2_5_network_wire"]
        ["key_schedule"]
        == "Key0Comm_to_Key1Comm_and_Key2Comm"
    )
    assert (
        document["xloader_implemented_codecs"]["v2_5_real_c2_candidate"]
        ["requires_three_statically_recovered_keys"]
        is True
    )
    current = next(
        profile
        for profile in document["xloader_profiles"]
        if profile["name"] == "xloader_8_1_plus"
    )
    assert current["commands"][0]["command_id"] == 1
    assert {flow["internal_request_id"] for flow in current["network_flows"]} == {
        None,
        3,
        6,
    }


def test_xloader_current_response_offline_decode_and_summary() -> None:
    body = b"RMTD:https://payload.invalid/unit.ps1"
    plaintext = b"XLNG4" + body + b"XLNG"
    url_key = bytes(range(20))
    derived_key = bytes(reversed(range(20)))
    encrypted = PROTOCOL.rc4_crypt(
        PROTOCOL.rc4_crypt(plaintext, derived_key), url_key
    )
    wire = PROTOCOL.strict_base64_encode(encrypted)

    response = PROTOCOL.decode_xloader_current_response_wire(
        wire,
        url_key,
        derived_key,
        require_trailing_magic=True,
    )
    report = PROTOCOL.summarize_xloader_command_response(wire, response)

    assert response.command_id == 4
    assert response.body == body
    assert response.trailing_magic_present is True
    assert report["framing_strength"] == "magic_command_and_trailer"
    assert report["body_sha256"] == hashlib.sha256(body).hexdigest()
    assert report["body_retained"] is False
    assert body.decode("ascii") not in str(report)

    with pytest.raises(PROTOCOL.FormBookProtocolError):
        PROTOCOL.decode_xloader_current_response_wire(
            wire,
            url_key,
            b"W" * 20,
        )


def test_xloader_v25_key_schedule_known_vector_and_wire_round_trip() -> None:
    key0 = bytes(range(20))
    keys = PROTOCOL.derive_xloader_v25_comm_keys(key0, HOST, PATH)

    assert keys.key1_comm.hex() == "a570363442bd7efdcdad6efb1fb3d88b8ff0c7b0"
    assert keys.key2_comm.hex() == "49c10aaa7f6b229a55480caf0a29cfd994c5452a"

    plaintext = b"XLNG9XLNG"
    wire = PROTOCOL.encode_xloader_v25_network_wire(plaintext, keys)
    assert wire == b"xU7iaBDHyKjb"
    decoded = PROTOCOL.decode_xloader_v25_network_wire(wire, keys)
    response = PROTOCOL.parse_xloader_command_plaintext(
        decoded.plaintext,
        command_map=PROTOCOL.XLOADER_V25_OPAQUE_COMMANDS,
        require_trailing_magic=True,
        enforce_command_shape=False,
    )
    report = PROTOCOL.summarize_xloader_v25_command_response(
        wire,
        decoded,
        response,
    )

    assert decoded.plaintext == plaintext
    assert response.command_id == 9
    assert report["key_schedule"] == "Key0Comm_to_Key1Comm_and_Key2Comm"
    assert report["wire_rc4_layer_count"] == 2
    assert report["command_semantics_confirmed"] is False
    assert report["key_material_retained"] is False

    wrong_keys = PROTOCOL.derive_xloader_v25_comm_keys(key0, "other.invalid", PATH)
    wrong = PROTOCOL.decode_xloader_v25_network_wire(wire, wrong_keys)
    with pytest.raises(PROTOCOL.FormBookProtocolError):
        PROTOCOL.parse_xloader_command_plaintext(
            wrong.plaintext,
            command_map=PROTOCOL.XLOADER_V25_OPAQUE_COMMANDS,
            enforce_command_shape=False,
        )


def test_xloader_v25_real_c2_requires_three_layers_and_exact_grammar() -> None:
    encrypted = bytes.fromhex(
        "a577a230dc4f21705afb4a48f9a1fb3fd20fdb41f6e118e187a452"
    )
    keys = (
        bytes(range(20)),
        bytes(range(20, 40)),
        bytes(reversed(range(20))),
    )
    candidate = PROTOCOL.decode_xloader_v25_real_c2_candidate(encrypted, keys)
    report = PROTOCOL.summarize_xloader_real_c2_candidate(encrypted, candidate)

    assert candidate.host == "www.synthetic.invalid"
    assert candidate.path == "/unit/"
    assert report["candidate_role"] == "real_c2_candidate"
    assert report["candidate_c2_confirmed"] is False
    assert report["decoy_ambiguity_resolved"] is False
    assert report["rc4_sub_layer_count"] == 3
    assert candidate.plaintext.decode("ascii") not in str(report)

    with pytest.raises(PROTOCOL.FormBookProtocolError):
        PROTOCOL.decode_xloader_v25_real_c2_candidate(encrypted, keys[:2])
    with pytest.raises(PROTOCOL.FormBookProtocolError):
        PROTOCOL.decode_xloader_v25_real_c2_candidate(
            encrypted,
            (keys[0], keys[1], b"W" * 20),
        )
    with pytest.raises(PROTOCOL.FormBookProtocolError):
        PROTOCOL.decode_xloader_v25_real_c2_candidate(
            b"A" * (PROTOCOL.MAX_XLOADER_REAL_C2_CANDIDATE_SIZE + 1),
            keys,
        )


def test_xloader_command_parser_rejects_weak_or_invalid_framing() -> None:
    parsed = PROTOCOL.parse_xloader_command_plaintext(b"XLNG9")
    assert parsed.command_id == 9
    assert parsed.trailing_magic_present is False

    with pytest.raises(PROTOCOL.FormBookProtocolError):
        PROTOCOL.parse_xloader_command_plaintext(
            b"XLNG9", require_trailing_magic=True
        )
    with pytest.raises(PROTOCOL.FormBookProtocolError):
        PROTOCOL.parse_xloader_command_plaintext(b"XLNG\x09")
    with pytest.raises(PROTOCOL.FormBookProtocolError):
        PROTOCOL.parse_xloader_command_plaintext(b"XLNG3unexpected")


def test_passive_assessment_never_confirms_open_port_alone() -> None:
    evidence = PROTOCOL.PassiveC2Evidence(
        transport_open=True,
        tls_established=True,
        http_response_observed=True,
    )
    report = PROTOCOL.assess_passive_c2_evidence(evidence)

    assert report["status"] == "inconclusive"
    assert report["endpoint_c2_confirmed"] is False
    assert report["open_port_is_c2_confirmation"] is False


def test_passive_assessment_requires_full_endpoint_and_protocol_binding() -> None:
    partial = PROTOCOL.PassiveC2Evidence(
        capture_endpoint_bound=True,
        url_key_binding_verified=True,
        command_response_valid=True,
        command_trailing_magic_present=True,
    )
    partial_report = PROTOCOL.assess_passive_c2_evidence(partial)
    assert partial_report["status"] == "supported_not_endpoint_confirmed"
    assert partial_report["endpoint_c2_confirmed"] is False
    assert "endpoint_matches_static_config" in partial_report["blockers"]
    assert partial_report["independent_evidence_count"] == 3
    assert partial_report["minimum_independent_evidence_count"] == 4

    complete = dataclasses.replace(
        partial,
        endpoint_matches_static_config=True,
        process_attributed_capture=True,
        decoy_ambiguity_present=False,
    )
    complete_report = PROTOCOL.assess_passive_c2_evidence(complete)
    assert complete_report["status"] == "supported_not_endpoint_confirmed"
    assert complete_report["endpoint_c2_confirmed"] is False
    assert complete_report["caller_asserted_complete"] is True
    assert complete_report["evidence_scope"] == "caller_asserted_v1"
    assert complete_report["trusted_capture_provenance_verified"] is False
    assert "trusted_capture_provenance" in complete_report["blockers"]
    assert complete_report["independent_evidence_count"] == 4


def test_passive_assessment_does_not_confirm_unattributed_or_ambiguous_capture() -> None:
    four_classes = PROTOCOL.PassiveC2Evidence(
        endpoint_matches_static_config=True,
        capture_endpoint_bound=True,
        url_key_binding_verified=True,
        command_response_valid=True,
    )
    ambiguous = PROTOCOL.assess_passive_c2_evidence(four_classes)
    assert ambiguous["independent_evidence_count"] == 4
    assert ambiguous["endpoint_c2_confirmed"] is False
    assert "process_attributed_capture" in ambiguous["blockers"]
    assert "real_c2_decoy_ambiguity_resolved" in ambiguous["blockers"]

    unattributed = PROTOCOL.assess_passive_c2_evidence(
        dataclasses.replace(four_classes, decoy_ambiguity_present=False)
    )
    assert unattributed["endpoint_c2_confirmed"] is False
    assert "process_attributed_capture" in unattributed["blockers"]


def test_legacy_saved_exchange_binds_both_frames_to_exact_endpoint() -> None:
    registration_plaintext = PROTOCOL.build_legacy_registration(
        bot_id="DEADBEEF",
        version="4.1",
        os_version="Windows Test x64",
        username=b"synthetic-user",
    )
    registration_wire = PROTOCOL.encode_legacy_registration_wire(
        registration_plaintext,
        HOST,
        PATH,
    )
    response_wire = PROTOCOL.encode_legacy_response(3, b"", HOST, PATH)

    confirmed = PROTOCOL.assess_formbook_legacy_saved_exchange(
        registration_wire,
        response_wire,
        static_host=HOST,
        static_path=PATH,
        capture_host=HOST,
        capture_path=PATH,
        process_attributed_capture=True,
    )
    assert confirmed["assessment"]["status"] == "supported_not_endpoint_confirmed"
    assert confirmed["assessment"]["endpoint_c2_confirmed"] is False
    assert confirmed["assessment"]["caller_asserted_complete"] is True
    assert confirmed["assessment"]["trusted_capture_provenance_verified"] is False
    assert confirmed["assessment"]["independent_evidence_count"] == 4
    assert confirmed["evidence_derivation"]["evidence_scope"] == (
        "caller_asserted_saved_exchange_v1"
    )
    assert confirmed["evidence_derivation"]["key_material_retained"] is False
    assert "synthetic-user" not in json.dumps(confirmed)

    wrong_static_endpoint = PROTOCOL.assess_formbook_legacy_saved_exchange(
        registration_wire,
        response_wire,
        static_host="other.invalid",
        static_path=PATH,
        capture_host=HOST,
        capture_path=PATH,
        process_attributed_capture=True,
    )
    assert wrong_static_endpoint["assessment"]["endpoint_c2_confirmed"] is False
    assert "endpoint_matches_static_config" in wrong_static_endpoint["assessment"][
        "blockers"
    ]

    unattributed = PROTOCOL.assess_formbook_legacy_saved_exchange(
        registration_wire,
        response_wire,
        static_host=HOST,
        static_path=PATH,
        capture_host=HOST,
        capture_path=PATH,
    )
    assert unattributed["assessment"]["endpoint_c2_confirmed"] is False
    assert "process_attributed_capture" in unattributed["assessment"]["blockers"]

    with pytest.raises(PROTOCOL.FormBookProtocolError):
        PROTOCOL.assess_formbook_legacy_saved_exchange(
            registration_wire,
            response_wire,
            static_host=HOST,
            static_path=PATH,
            capture_host=HOST,
            capture_path="/wrong/",
            process_attributed_capture=True,
        )


def test_cli_xloader_decode_and_passive_assessment(tmp_path: Path) -> None:
    plaintext = b"XLNG9XLNG"
    url_key = b"U" * 20
    derived_key = b"D" * 20
    encrypted = PROTOCOL.rc4_crypt(
        PROTOCOL.rc4_crypt(plaintext, derived_key), url_key
    )
    wire_path = tmp_path / "xloader-response.bin"
    url_key_path = tmp_path / "url-key.bin"
    derived_key_path = tmp_path / "derived-key.hex"
    output_path = tmp_path / "xloader-summary.json"
    wire_path.write_bytes(PROTOCOL.strict_base64_encode(encrypted))
    url_key_path.write_bytes(url_key)
    derived_key_path.write_text(derived_key.hex(), encoding="ascii")

    assert PROTOCOL.main(
        [
            "decode-xloader-response",
            str(wire_path),
            "--url-key-file",
            str(url_key_path),
            "--derived-key-file",
            str(derived_key_path),
            "--require-trailing-magic",
            "--output",
            str(output_path),
        ]
    ) == 0
    decoded = json.loads(output_path.read_text(encoding="utf-8"))
    assert decoded["command_id"] == 9
    assert decoded["network_contacted"] is False

    evidence_path = tmp_path / "passive-evidence.json"
    assessment_path = tmp_path / "passive-assessment.json"
    evidence_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "endpoint_matches_static_config": True,
                "capture_endpoint_bound": True,
                "process_attributed_capture": True,
                "url_key_binding_verified": True,
                "command_response_valid": True,
                "decoy_ambiguity_present": False,
            }
        ),
        encoding="utf-8",
    )
    assert PROTOCOL.main(
        [
            "assess-passive",
            str(evidence_path),
            "--output",
            str(assessment_path),
        ]
    ) == 0
    assessment = json.loads(assessment_path.read_text(encoding="utf-8"))
    assert assessment["status"] == "supported_not_endpoint_confirmed"
    assert assessment["endpoint_c2_confirmed"] is False
    assert assessment["caller_asserted_complete"] is True
    assert assessment["trusted_capture_provenance_verified"] is False


def test_cli_xloader_v25_key_schedule_and_real_c2_decode(tmp_path: Path) -> None:
    key0 = bytes(range(20))
    keys = PROTOCOL.derive_xloader_v25_comm_keys(key0, HOST, PATH)
    response_wire = PROTOCOL.encode_xloader_v25_network_wire(
        b"XLNG9XLNG",
        keys,
    )
    response_path = tmp_path / "saved-response.bin"
    key0_path = tmp_path / "key0.hex"
    response_output = tmp_path / "response-summary.json"
    response_path.write_bytes(response_wire)
    key0_path.write_text(key0.hex(), encoding="ascii")

    assert PROTOCOL.main(
        [
            "decode-xloader-v25-response",
            str(response_path),
            "--key0-file",
            str(key0_path),
            "--host",
            HOST,
            "--path",
            PATH,
            "--require-trailing-magic",
            "--output",
            str(response_output),
        ]
    ) == 0
    response_report = json.loads(response_output.read_text(encoding="utf-8"))
    assert response_report["command_id"] == 9
    assert response_report["network_contacted"] is False

    encrypted = bytes.fromhex(
        "a577a230dc4f21705afb4a48f9a1fb3fd20fdb41f6e118e187a452"
    )
    layer_keys = (
        bytes(range(20)),
        bytes(range(20, 40)),
        bytes(reversed(range(20))),
    )
    candidate_path = tmp_path / "encrypted-c2.bin"
    candidate_output = tmp_path / "candidate-summary.json"
    candidate_path.write_bytes(encrypted)
    key_paths: list[Path] = []
    for index, key in enumerate(layer_keys, start=1):
        key_path = tmp_path / f"layer-{index}.bin"
        key_path.write_bytes(key)
        key_paths.append(key_path)

    assert PROTOCOL.main(
        [
            "decode-xloader-v25-real-c2",
            str(candidate_path),
            "--layer1-key-file",
            str(key_paths[0]),
            "--layer2-key-file",
            str(key_paths[1]),
            "--layer3-key-file",
            str(key_paths[2]),
            "--output",
            str(candidate_output),
        ]
    ) == 0
    candidate_report = json.loads(candidate_output.read_text(encoding="utf-8"))
    assert candidate_report["candidate_host"] == "www.synthetic.invalid"
    assert candidate_report["candidate_c2_confirmed"] is False
    assert candidate_report["network_contacted"] is False
