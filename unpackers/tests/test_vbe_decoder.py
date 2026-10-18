"""Microsoft Script Encoder形式の有界静的復号テスト。"""

from __future__ import annotations

import base64

from unpackers import static_unpacker, vbe_decoder

VECTOR = b"#@~^DgAAAA==\\ko$K6,JC\x7fV^GJqAQAAA==^#~@"
PLAINTEXT = b'MsgBox "Hello"'


def _metadata(value: int) -> bytes:
    return base64.b64encode(value.to_bytes(4, "little"))


def _encode_fixture(payload: bytes) -> bytes:
    """無害な短いfixture用に、復号表から正規encoded byteを逆引きする。"""

    body = bytearray()
    position = -1
    escapes = {
        0x40: b"@$",
        0x3C: b"@!",
        0x3E: b"@*",
        0x0D: b"@#",
        0x0A: b"@&",
    }
    for value in payload:
        if value < 0x80:
            position += 1
        if value in escapes:
            body.extend(escapes[value])
            continue
        candidate = None
        for encoded in (0x09, *range(0x20, 0x80)):
            if encoded in (0x3C, 0x3E, 0x40):
                continue
            table_offset = (encoded - 9) * 3
            decoded = vbe_decoder._DECODE_TABLE[
                table_offset + vbe_decoder._POSITION_OFFSETS[position % 64]
            ]
            if decoded == value:
                candidate = encoded
                break
        if candidate is None:
            raise AssertionError(f"fixtureをencodeできません: {value:#x}")
        body.append(candidate)
    return (
        b"#@~^"
        + _metadata(len(payload))
        + body
        + _metadata(sum(payload) & 0xFFFFFFFF)
        + b"^#~@"
    )


def test_decodes_known_vector_without_execution_or_network() -> None:
    report, decoded = vbe_decoder.decode_vbe_blocks(VECTOR)

    assert decoded == PLAINTEXT
    assert report["status"] == "decoded"
    assert report["block_count"] == 1
    assert report["blocks"][0]["checksum"] == sum(PLAINTEXT)
    assert report["executed"] is False
    assert report["network_contacted"] is False


def test_preserves_prefix_suffix_and_interstitial_bytes_for_multiple_blocks() -> None:
    source = b"<job>" + VECTOR + b"\r\n<!-- separator -->" + VECTOR + b"</job>"

    report, decoded = vbe_decoder.decode_vbe_blocks(source)

    assert report["status"] == "decoded"
    assert report["block_count"] == 2
    assert report["prefix_size"] == len(b"<job>")
    assert report["suffix_size"] == len(b"</job>")
    assert decoded == (
        b"<job>" + PLAINTEXT + b"\r\n<!-- separator -->" + PLAINTEXT + b"</job>"
    )


def test_decodes_all_defined_script_encoder_escapes() -> None:
    payload = b"A@<>\r\nZ"
    encoded = _encode_fixture(payload)

    report, decoded = vbe_decoder.decode_vbe_blocks(encoded)

    assert decoded == payload
    assert report["blocks"][0]["escape_count"] == 5


def test_rejects_truncated_checksum_and_never_returns_partial_output() -> None:
    report, decoded = vbe_decoder.decode_vbe_blocks(VECTOR[:-4])

    assert decoded is None
    assert report["status"] == "malformed_envelope"
    assert report["reason"] == "no_valid_trailer"


def test_rejects_checksum_mismatch() -> None:
    damaged = VECTOR.replace(b"qAQAAA==", b"AAAAAA==")

    report, decoded = vbe_decoder.decode_vbe_blocks(damaged)

    assert decoded is None
    assert report["status"] == "malformed_envelope"


def test_rejects_unknown_escape() -> None:
    encoded = b"#@~^" + _metadata(2) + b"@x" + _metadata(0) + b"^#~@"

    report, decoded = vbe_decoder.decode_vbe_blocks(encoded)

    assert decoded is None
    assert report["status"] == "malformed_envelope"


def test_invalid_marker_literal_is_not_treated_as_an_envelope() -> None:
    report, decoded = vbe_decoder.decode_vbe_blocks(
        b'WScript.Echo "#@~^not-an-envelope"'
    )

    assert decoded is None
    assert report["status"] == "pattern_not_found"


def test_valid_header_without_complete_envelope_fails_closed() -> None:
    report, decoded = vbe_decoder.decode_vbe_blocks(b'WScript.Echo "#@~^DgAAAA=="')

    assert decoded is None
    assert report["status"] == "malformed_envelope"


def test_input_output_and_block_limits_are_enforced() -> None:
    input_report, input_decoded = vbe_decoder.decode_vbe_blocks(
        VECTOR,
        max_input_size=len(VECTOR) - 1,
    )
    output_report, output_decoded = vbe_decoder.decode_vbe_blocks(
        VECTOR,
        max_output_size=len(PLAINTEXT) - 1,
    )
    block_report, block_decoded = vbe_decoder.decode_vbe_blocks(
        VECTOR + VECTOR,
        max_blocks=1,
    )

    assert input_decoded is None
    assert input_report["status"] == "size_blocked"
    assert output_decoded is None
    assert output_report["status"] == "output_size_blocked"
    assert block_decoded is None
    assert block_report["status"] == "block_limit_blocked"


def test_malformed_second_block_discards_first_decoded_block() -> None:
    report, decoded = vbe_decoder.decode_vbe_blocks(VECTOR + b"#@~^DgAAAA==")

    assert decoded is None
    assert report["status"] == "malformed_envelope"
    assert report["block_count"] == 0


def test_static_unpacker_routes_vbe_into_recursive_artifact() -> None:
    report, artifacts = static_unpacker.unpack_bytes(VECTOR, "invoice.vbe")

    assert report["format"] == "script"
    assert report["windows_script_encoder"]["status"] == "decoded"
    assert ("windows-script-encoder-decoded", PLAINTEXT) in artifacts


def test_static_unpacker_recognizes_complete_header_without_vbe_suffix() -> None:
    report, artifacts = static_unpacker.unpack_bytes(VECTOR, "payload.bin")

    assert report["format"] == "script"
    assert report["windows_script_encoder"]["status"] == "decoded"
    assert ("windows-script-encoder-decoded", PLAINTEXT) in artifacts


def test_static_unpacker_does_not_emit_artifact_for_plain_vbs() -> None:
    source = b'WScript.Echo "hello"'

    report, artifacts = static_unpacker.unpack_bytes(source, "harmless.vbs")

    assert report["windows_script_encoder"]["status"] == "pattern_not_found"
    assert not any(kind == "windows-script-encoder-decoded" for kind, _ in artifacts)
