"""webio/wer同梱loaderの手動route候補と安全境界を検証する。"""

from __future__ import annotations

import struct

import pytest

from extractors.valleyrat import silverfox_webio_stage_loader as loader

IMAGE_BASE = 0x140000000
TEXT_RVA = 0x1000
DATA_RVA = 0x5000
TABLE_RVA = 0x8C00
STATE_RVA = 0x8D00
BLOB_RVA = DATA_RVA
SECOND_BLOB_RVA = DATA_RVA + 0x2000


def _put_call(buffer: bytearray, offset: int, base_rva: int, target: int) -> int:
    if len(buffer) < offset + 5:
        buffer.extend(b"\0" * (offset + 5 - len(buffer)))
    buffer[offset] = 0xE8
    struct.pack_into("<i", buffer, offset + 1, target - (base_rva + offset + 5))
    return offset + 5


def _put_lea_rip(
    buffer: bytearray,
    offset: int,
    base_rva: int,
    opcode: bytes,
    target: int,
) -> int:
    if len(buffer) < offset + 7:
        buffer.extend(b"\0" * (offset + 7 - len(buffer)))
    buffer[offset : offset + 3] = opcode
    struct.pack_into("<i", buffer, offset + 3, target - (base_rva + offset + 7))
    return offset + 7


def _stack_literal(displacement: int, value: bytes) -> bytes:
    result = bytearray()
    cursor = 0
    while cursor + 4 <= len(value):
        result.extend(b"\xc7\x44\x24" + bytes((displacement + cursor,)))
        result.extend(value[cursor : cursor + 4])
        cursor += 4
    if cursor + 2 <= len(value):
        result.extend(b"\x66\xc7\x44\x24" + bytes((displacement + cursor,)))
        result.extend(value[cursor : cursor + 2])
        cursor += 2
    if cursor < len(value):
        result.extend(b"\xc6\x44\x24" + bytes((displacement + cursor, value[cursor])))
    return bytes(result)


def _lznt1_literal(value: bytes) -> bytes:
    output = bytearray()
    for offset in range(0, len(value), 0x1000):
        chunk = value[offset : offset + 0x1000]
        output.extend(struct.pack("<H", 0x3000 | (len(chunk) - 1)))
        output.extend(chunk)
    return bytes(output)


def _ksa_code() -> bytes:
    return (
        b"\x81\x3c\x24\x00\x01\x00\x00"
        b"\x81\x7c\x24\x04\x00\x01\x00\x00"
        b"\x48\xf7\x74\x24\x08"
        b"\x88\x10"
        b"\x88\x14\x08"
        b"\x88\x1c\x08"
        b"\x88\x04\x08"
        b"\xc6\x80\x00\x01\x00\x00\x00"
        b"\xc6\x80\x01\x01\x00\x00\x00"
        b"\x75\xfc"
        b"\xc3"
    )


def _prga_code() -> bytes:
    return (
        b"\x0f\xb6\x81\x00\x01\x00\x00"
        b"\x0f\xb6\x91\x01\x01\x00\x00"
        b"\x0f\xb6\x99\x00\x01\x00\x00"
        b"\x0f\xb6\xb1\x01\x01\x00\x00"
        b"\x0f\xb6\xb9\x00\x01\x00\x00"
        b"\x0f\xb6\xa9\x01\x01\x00\x00"
        b"\x0f\xb6\x81\x00\x01\x00\x00"
        b"\x0f\xb6\x91\x01\x01\x00\x00"
        b"\x0f\xb6\x04\x01"
        b"\x0f\xb6\x0c\x0a"
        b"\x0f\xb6\x14\x03"
        b"\x31\xc8"
        b"\x31\xc2"
        b"\x88\x01"
        b"\x88\x11"
        b"\x88\x19"
        b"\x75\xfc"
        b"\xc3"
    )


def _downloader_code() -> bytes:
    result = bytearray()
    result.extend(_stack_literal(0x20, loader.WININET_LIBRARY))
    result.extend(_stack_literal(0x50, loader.HTTP_AGENT))
    result.extend(b"\xb8\x00\x00\x00\x80" * 2)
    result.extend(b"\xb8\x00\x04\x00\x00")
    result.extend(b"\xb8\x00\x00\x40\x00" * 2)
    result.extend(b"\xff\xd0" * 6)
    result.extend(b"\x75\xfc\xc3")
    return bytes(result)


def _stage2(
    *,
    route_format: bytes = loader.HTTP_ROUTE_FORMAT,
    config_size: int = loader.WEBIO_CONFIG_SIZE,
    duplicate_marker: bool = False,
) -> bytes:
    marker_offset = 0x900
    ksa = 0x100
    prga = 0x200
    main = 0x300
    downloader = 0x700
    stage = bytearray(marker_offset)

    entry = bytearray(b"\x48\x83\xec\x28")
    _put_call(entry, len(entry), 0, main)
    entry.extend(b"\x90\x48\x83\xc4\x28\xc3")
    stage[: len(entry)] = entry
    stage[ksa : ksa + len(_ksa_code())] = _ksa_code()
    stage[prga : prga + len(_prga_code())] = _prga_code()

    body = bytearray()
    body.extend(b"\x48\x89\xc3")  # marker scanner result -> rbx
    body.extend(b"\x31\xc0\x44\x8d\x40\x08")
    body.extend(b"\x48\x89\xda\x48\x89\xf1\xff\xd7")
    body.extend(b"\x48\x8d\x4d\xc0\x48\x89\xf2\x41\xb8\x08\x00\x00\x00")
    _put_call(body, len(body), main, ksa)
    body.extend(b"\x48\x8d\x4d\xc0\x48\x8d\x53\x0c\x44\x8b\x45\x10")
    _put_call(body, len(body), main, prga)
    body.extend(b"\xba\x88\x0a\x00\x00")
    body.extend(b"\x41\xb8\x88\x0a\x00\x00")
    body.extend(b"\x81\x7d\x10\x88\x0a\x00\x00")
    body.extend(_stack_literal(0x40, route_format))
    body.extend(b"\x48\x8d\x54\x24\x40")
    body.extend(b"\x48\x8d\x4d\x20")
    body.extend(b"\x49\x89\xf0")
    body.extend(b"\x44\x0f\xb7\x8e\x00\x01\x00\x00")
    body.extend(b"\xff\xd0")
    body.extend(b"\x48\x89\xc2\x48\x8d\x4d\x20")
    _put_call(body, len(body), main, downloader)
    body.extend(b"\xc3")
    stage[main : main + len(body)] = body
    download_body = _downloader_code()
    stage[downloader : downloader + len(download_body)] = download_body

    config = bytearray(config_size)
    host = b"updates.example.invalid"
    config[: len(host)] = host
    struct.pack_into("<H", config, 0x100, 8080)
    config[0x102 : 0x102 + len("HTTP".encode("utf-16le"))] = "HTTP".encode("utf-16le")
    marker = bytes((0xFE, 0xFA, 0xC8, 0xC9, 0xCA, 0xCB, 0xEB, 0xFF))
    assert sum(marker) == 0x708
    if duplicate_marker:
        stage[marker_offset - 32 : marker_offset - 24] = marker
    compressed = _lznt1_literal(bytes(config))
    encrypted = loader._xor_swap_stream_transform(marker, compressed)
    stage.extend(marker)
    stage.extend(struct.pack("<I", len(encrypted)))
    stage.extend(encrypted)
    return bytes(stage)


def _factory_code(factory_rva: int, wrapper_rva: int) -> bytes:
    code = bytearray(b"\x48\x83\xec\x68")
    _put_lea_rip(code, len(code), factory_rva, b"\x48\x8d\x05", wrapper_rva)
    code.extend(b"\x48\x89\x44\x24\x50")
    code.extend(b"\xb8\x08\x00\x00\x00")
    code.extend(b"\x48\x6b\xc0\x0a")
    code.extend(b"\x48\x8b\x04\x04")
    code.extend(b"\x48\x83\xc4\x68\xc3")
    return bytes(code)


def _pe(
    *,
    route_format: bytes = loader.HTTP_ROUTE_FORMAT,
    config_size: int = loader.WEBIO_CONFIG_SIZE,
    duplicate_marker: bool = False,
    cipher_slot: int = loader.CUSTOM_CIPHER_SLOT,
    ambiguous_binding: bool = False,
    entrypoint_rva: int = 0x1000,
) -> bytes:
    stage2 = _stage2(
        route_format=route_format,
        config_size=config_size,
        duplicate_marker=duplicate_marker,
    )
    compressed_stage2 = _lznt1_literal(stage2)
    key = b"synthetic-route-key"
    encrypted_stage2 = loader._custom_cipher_transform(key, compressed_stage2)
    stage1 = (
        bytes((len(key),))
        + key
        + struct.pack("<I", len(encrypted_stage2))
        + encrypted_stage2
    )
    compressed_stage1 = _lznt1_literal(stage1)
    prefix = b"route"
    blob = (
        bytes((len(prefix),))
        + prefix
        + struct.pack("<I", len(compressed_stage1))
        + compressed_stage1
    )

    text = bytearray(0x3000)
    data = bytearray(0x5000)
    data[BLOB_RVA - DATA_RVA : BLOB_RVA - DATA_RVA + len(blob)] = blob
    if ambiguous_binding:
        start = SECOND_BLOB_RVA - DATA_RVA
        data[start : start + len(blob)] = blob
    data.extend(b"198.51.100.99\0HTTP\0")  # xrefのない平文decoy

    producer = 0x1100
    parser = 0x1180
    lznt1 = 0x1190
    decoder = 0x11A0
    append = 0x2300
    chain = 0x1000

    def place_root_chain(chain_rva: int, producer_rva: int) -> None:
        offset = chain_rva - TEXT_RVA
        for target in (producer_rva, parser, lznt1, decoder):
            text[offset : offset + 3] = b"\x48\x8b\x0d"
            struct.pack_into(
                "<i",
                text,
                offset + 3,
                STATE_RVA - (chain_rva + (offset - (chain_rva - TEXT_RVA)) + 7),
            )
            text[offset + 7] = 0xE8
            current_rva = TEXT_RVA + offset
            struct.pack_into("<i", text, offset + 8, target - (current_rva + 12))
            offset += 12

    def place_producer(producer_rva: int, blob_rva: int) -> None:
        offset = producer_rva - TEXT_RVA
        code = bytearray(b"\x41\xb8" + struct.pack("<I", len(blob)))
        _put_lea_rip(code, len(code), producer_rva, b"\x48\x8d\x15", blob_rva)
        code.extend(b"\x48\x8b\x4c\x24\x20")
        _put_call(code, len(code), producer_rva, append)
        code.extend(b"\xc3")
        text[offset : offset + len(code)] = code

    place_root_chain(chain, producer)
    place_producer(producer, BLOB_RVA)
    text[parser - TEXT_RVA] = 0xC3
    text[lznt1 - TEXT_RVA] = 0xC3
    decoder_code = bytearray()
    _put_lea_rip(decoder_code, 0, decoder, b"\x48\x8d\x0d", TABLE_RVA)
    decoder_code.extend(b"\x48\x8b\x04\xc1")
    decoder_code.extend(b"\x48\x89\x44\x24\x20")
    decoder_code.extend(b"\xff\x54\x24\x20\xc3")
    text[decoder - TEXT_RVA : decoder - TEXT_RVA + len(decoder_code)] = decoder_code
    text[append - TEXT_RVA] = 0xC3

    if ambiguous_binding:
        second_producer = 0x2400
        place_producer(second_producer, SECOND_BLOB_RVA)
        place_root_chain(0x2500, second_producer)

    factories = [0x1500 + index * 0x80 for index in range(loader.DISPATCH_SLOT_COUNT)]
    init_rva = 0x1300
    init_offset = init_rva - TEXT_RVA
    for index, factory in enumerate(factories):
        current_rva = TEXT_RVA + init_offset
        init_offset = _put_call(text, init_offset, TEXT_RVA, factory)
        text[init_offset : init_offset + 3] = b"\x48\x89\x05"
        struct.pack_into(
            "<i",
            text,
            init_offset + 3,
            TABLE_RVA + index * 8 - (current_rva + 12),
        )
        init_offset += 7

    wrapper = 0x2000
    key_schedule = 0x2100
    transform = 0x2200
    for index, factory in enumerate(factories):
        offset = factory - TEXT_RVA
        code = _factory_code(factory, wrapper) if index == cipher_slot else b"\xc3"
        text[offset : offset + len(code)] = code
    wrapper_code = bytearray()
    _put_call(wrapper_code, len(wrapper_code), wrapper, key_schedule)
    _put_call(wrapper_code, len(wrapper_code), wrapper, transform)
    wrapper_code.extend(b"\xc3")
    text[wrapper - TEXT_RVA : wrapper - TEXT_RVA + len(wrapper_code)] = wrapper_code
    text[key_schedule - TEXT_RVA : key_schedule - TEXT_RVA + 11] = (
        b"\xb8"
        + struct.pack("<I", loader._CIPHER_CONSTANTS[0])
        + b"\xb9"
        + struct.pack("<I", loader._CIPHER_CONSTANTS[1])
        + b"\xc3"
    )
    text[transform - TEXT_RVA : transform - TEXT_RVA + 11] = (
        b"\xb8"
        + struct.pack("<I", loader._CIPHER_CONSTANTS[2])
        + b"\xb9"
        + struct.pack("<I", loader._CIPHER_CONSTANTS[3])
        + b"\xc3"
    )

    headers_size = 0x400
    text_raw = headers_size
    data_raw = text_raw + len(text)
    image = bytearray(data_raw + len(data))
    image[:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, 0x80)
    image[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", image, 0x84, 0x8664, 2, 0, 0, 0, 0xF0, 0x22)
    optional = 0x98
    struct.pack_into("<H", image, optional, 0x20B)
    struct.pack_into("<I", image, optional + 4, len(text))
    struct.pack_into("<I", image, optional + 8, len(data))
    struct.pack_into("<I", image, optional + 16, entrypoint_rva)
    struct.pack_into("<I", image, optional + 20, TEXT_RVA)
    struct.pack_into("<Q", image, optional + 24, IMAGE_BASE)
    struct.pack_into("<II", image, optional + 32, 0x1000, 0x200)
    struct.pack_into("<I", image, optional + 56, 0xA000)
    struct.pack_into("<I", image, optional + 60, headers_size)
    struct.pack_into("<H", image, optional + 68, 2)
    struct.pack_into("<QQQQ", image, optional + 72, 0x100000, 0x1000, 0x100000, 0x1000)
    struct.pack_into("<I", image, optional + 108, 16)
    section_table = 0x80 + 24 + 0xF0
    for index, values in enumerate(
        (
            (b".text", len(text), TEXT_RVA, len(text), text_raw, 0x60000020),
            (b".data", len(data), DATA_RVA, len(data), data_raw, 0xC0000040),
        )
    ):
        name, virtual_size, rva, raw_size, raw_offset, characteristics = values
        offset = section_table + index * 40
        image[offset : offset + 8] = name.ljust(8, b"\0")
        struct.pack_into(
            "<IIII", image, offset + 8, virtual_size, rva, raw_size, raw_offset
        )
        struct.pack_into("<I", image, offset + 36, characteristics)
    image[text_raw : text_raw + len(text)] = text
    image[data_raw : data_raw + len(data)] = data
    return bytes(image)


def test_synthetic_shape_is_only_unverified_manual_route_candidate() -> None:
    # decoderへ到達しないentry pointでも既知byte shapeは成立する。このfixtureは
    # CFG/data-flow証明ではなく、manual candidateへの安全な降格を検証する。
    result = loader.analyze_silverfox_webio_stage_loader(_pe(entrypoint_rva=0x2F00))

    assert result is not None
    report = result.observation
    assert report["status"] == "unverified_silverfox_webio_manual_route_candidate"
    assert report["matched"] is False
    assert report["candidate_recovered"] is True
    assert report["automatic_route_eligible"] is False
    assert report["manual_review_required"] is True
    assert report["route_validated"] is False
    assert report["static_config_recovered"] is False
    endpoint = report["route"]["endpoint"]
    assert endpoint == {
        "host": "updates.example.invalid",
        "port": 8080,
        "transport": "http",
        "role": "stage_acquisition_route_candidate",
        "evidence": "unverified_decoded_value_without_complete_cfg_dataflow_binding",
    }
    assert report["route"]["path"] == "/getinstall64"
    assert report["supports_family_attribution"] is False
    assert report["terminal_family_confirmed"] is False
    assert report["final_rat_confirmed"] is False
    assert report["command_c2_confirmed"] is False
    assert report["liveness_confirmed"] is False
    boundary = report["evidence_boundary"]
    assert boundary["entrypoint_reachable_root_chain_proven"] is False
    assert boundary["root_cfg_and_dataflow_proven"] is False
    assert boundary["runtime_dispatch_slot_two_binding_proven"] is False
    assert boundary["hardcoded_cipher_to_runtime_dispatch_bound"] is False
    assert boundary["marker_to_xor_swap_key_dataflow_proven"] is False
    assert boundary["config_to_http_get_consumer_dataflow_proven"] is False
    assert boundary["end_to_end_route_lineage_proven"] is False
    assert boundary["root_plaintext_endpoint_candidates_used"] is False
    assert report["decoders"]["raw_key_included"] is False
    assert report["decoders"]["raw_stage_included"] is False
    assert report["decoders"]["raw_config_included"] is False
    assert report["route"]["downloaded_bundle_recovered"] is False
    assert report["route"]["downloaded_bundle_executed"] is False
    assert report["sample_executed"] is False
    assert report["network_contacted"] is False


@pytest.mark.parametrize(
    "sample",
    [
        _pe(cipher_slot=3),
        _pe(duplicate_marker=True),
        _pe(config_size=0xA94),
        _pe(route_format="http://%hs:%d/".encode("utf-16le")),
        _pe(ambiguous_binding=True),
    ],
    ids=(
        "cipher-is-not-dispatch-slot-two",
        "marker-is-ambiguous",
        "onyx-sized-config-is-not-this-route",
        "getinstall64-consumer-is-missing",
        "root-producer-consumer-is-ambiguous",
    ),
)
def test_broken_or_ambiguous_chain_fails_closed(sample: bytes) -> None:
    assert loader.analyze_silverfox_webio_stage_loader(sample) is None


def test_preflight_rejection_never_promotes_family_or_network_evidence() -> None:
    report = loader.probe_silverfox_webio_stage_loader(b"MZ" + b"\0" * 512)

    assert report["matched"] is False
    assert report["candidate_recovered"] is False
    assert report["automatic_route_eligible"] is False
    assert report["route_validated"] is False
    assert report["static_config_recovered"] is False
    assert report["family"] is None
    assert report["supports_family_attribution"] is False
    assert report["terminal_family_confirmed"] is False
    assert report["final_rat_confirmed"] is False
    assert report["command_c2_confirmed"] is False
    assert report["liveness_confirmed"] is False
    assert report["endpoint_values_included"] is False
    assert report["sample_executed"] is False
    assert report["network_contacted"] is False


def test_input_budget_is_checked_before_pe_parse(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(loader, "MAXIMUM_INPUT_SIZE", 8)

    assert loader.analyze_silverfox_webio_stage_loader(b"MZ" + b"A" * 8) is None


def test_executable_budget_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(loader, "MAXIMUM_TOTAL_EXECUTABLE_SIZE", 0x100)

    report = loader.probe_silverfox_webio_stage_loader(_pe())

    assert report["matched"] is False
    assert report["supports_family_attribution"] is False
    assert report["endpoint_values_included"] is False
