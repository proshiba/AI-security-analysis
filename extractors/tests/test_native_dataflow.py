"""共通native data-flow coreを値非依存の合成命令列で検証する。"""

from __future__ import annotations

import struct
from types import SimpleNamespace

from extractors.native_dataflow import (
    NativeFlowLimits,
    NativeSource,
    analyze_x86_pe_dataflow,
)

_IMAGE_BASE = 0x400000
_TEXT_RVA = 0x1000
_TEXT_RAW = 0x200
_TEXT_SIZE = 0x1000
_ROOT = _IMAGE_BASE + _TEXT_RVA
_CALLBACK = _ROOT + 0x100
_SOURCE_BASE = _IMAGE_BASE + 0x4000

_IAT = {
    "CreateThread": _IMAGE_BASE + 0x3000,
    "gethostbyname": _IMAGE_BASE + 0x3004,
    "htons": _IMAGE_BASE + 0x3008,
    "socket": _IMAGE_BASE + 0x300C,
    "connect": _IMAGE_BASE + 0x3010,
    "send": _IMAGE_BASE + 0x3014,
    "recv": _IMAGE_BASE + 0x3018,
}


def _push_immediate(value: int) -> bytes:
    return b"\x68" + struct.pack("<I", value)


def _iat_call(name: str) -> bytes:
    return b"\xff\x15" + struct.pack("<I", _IAT[name])


def _image(
    *,
    split_receive_socket: bool = False,
    unknown_call: bool = False,
    unknown_branch: bool = False,
    port_pointer: bool = False,
) -> tuple[bytes, object]:
    """endpoint文字列を含まないx86 callback→network命令列を構成する。"""

    data = bytearray(0x1800)
    data[:2] = b"MZ"
    root = b"".join(
        (
            b"\x6a\x00",
            b"\x6a\x00",
            b"\x6a\x00",
            _push_immediate(_CALLBACK),
            b"\x6a\x00",
            b"\x6a\x00",
            _iat_call("CreateThread"),
            b"\xc3",
        )
    )
    callback = b"".join(
        (
            _push_immediate(_SOURCE_BASE),
            _iat_call("gethostbyname"),
            b"\x89\x45\xe4",  # mov [ebp-0x1c], eax
            (
                _push_immediate(_SOURCE_BASE + 0x20)
                if port_pointer
                else b"\xff\x35" + struct.pack("<I", _SOURCE_BASE + 0x20)
            ),
            _iat_call("htons"),
            b"\x66\x89\x45\xe0",  # mov [ebp-0x20], ax
            b"\xa1" + struct.pack("<I", _SOURCE_BASE + 0x40),
            b"\x89\xc7",  # mov edi, eax
            b"\xff\xd0" if unknown_call else b"",
            b"\x85\xff\x74\x00" if unknown_branch else b"",
            b"\x6a\x06\x6a\x01\x6a\x02",
            _iat_call("socket"),
            b"\x89\xc6",  # mov esi, eax
            b"\x8d\x45\xe0",  # lea eax, [ebp-0x20]
            b"\x6a\x10\x50\x56",
            _iat_call("connect"),
            b"\x6a\x00\x6a\x04",
            _push_immediate(_SOURCE_BASE + 0x80),
            b"\x56",
            _iat_call("send"),
            (
                b"\x6a\x06\x6a\x01\x6a\x02"
                + _iat_call("socket")
                + b"\x89\xc7"
                if split_receive_socket
                else b""
            ),
            b"\x6a\x00\x6a\x04",
            _push_immediate(_SOURCE_BASE + 0x80),
            b"\x57" if split_receive_socket else b"\x56",
            _iat_call("recv"),
            b"\xc3",
        )
    )
    root_offset = _TEXT_RAW
    callback_offset = _TEXT_RAW + (_CALLBACK - _ROOT)
    data[root_offset : root_offset + len(root)] = root
    data[callback_offset : callback_offset + len(callback)] = callback
    text_section = SimpleNamespace(
        PointerToRawData=_TEXT_RAW,
        SizeOfRawData=_TEXT_SIZE,
        VirtualAddress=_TEXT_RVA,
        Characteristics=0x60000020,
    )
    imports = [
        SimpleNamespace(
            imports=[
                SimpleNamespace(name=name.encode("ascii"), address=address)
                for name, address in _IAT.items()
            ]
        )
    ]
    image = SimpleNamespace(
        sections=[text_section],
        OPTIONAL_HEADER=SimpleNamespace(ImageBase=_IMAGE_BASE),
        DIRECTORY_ENTRY_IMPORT=imports,
    )
    return bytes(data), image


def _sources() -> tuple[NativeSource, ...]:
    return (
        NativeSource("config_host", _SOURCE_BASE, 0x20, "host"),
        NativeSource("config_port", _SOURCE_BASE + 0x20, 0x20, "port"),
        NativeSource("transport_selector", _SOURCE_BASE + 0x40, 4, "selector"),
    )


def test_proves_direct_iat_callback_config_and_same_socket_lineage() -> None:
    """全field、変換、connect、同一socketのsend/recvが揃う場合だけ閉じる。"""

    data, image = _image()

    result = analyze_x86_pe_dataflow(
        data,
        image,
        roots=(_ROOT,),
        sources=_sources(),
        require_callback=True,
    )

    assert result["analysis_complete"] is True
    assert result["terminal_network_lineage_proven"] is True
    assert result["missing_proof_codes"] == []
    assert result["proof"] == {
        "root_mapped": True,
        "callback_lineage_reached": True,
        "all_config_fields_referenced": True,
        "host_source_to_name_resolution": True,
        "port_source_to_network_conversion": True,
        "config_source_to_connect": True,
        "same_socket_connect_send_receive": True,
    }
    assert result["coverage"]["reachable_api_groups"] == [
        "name_resolution",
        "port_conversion",
        "socket_create",
        "connect",
        "send",
        "receive",
    ]
    assert result["raw_addresses_included"] is False
    assert result["raw_source_values_included"] is False


def test_rejects_send_receive_on_different_socket_identity() -> None:
    """APIの単純な存在だけでは同一socketのnetwork lineageに昇格しない。"""

    data, image = _image(split_receive_socket=True)

    result = analyze_x86_pe_dataflow(
        data,
        image,
        roots=(_ROOT,),
        sources=_sources(),
        require_callback=True,
    )

    assert result["analysis_complete"] is True
    assert result["proof"]["config_source_to_connect"] is True
    assert result["proof"]["same_socket_connect_send_receive"] is False
    assert result["terminal_network_lineage_proven"] is False
    assert "native_flow_same_socket_connect_send_receive_unproven" in result["missing_proof_codes"]


def test_rejects_port_field_address_as_converted_port_value() -> None:
    """port fieldへのpointerをport値そのものとしてhtonsへ流用しない。"""

    data, image = _image(port_pointer=True)

    result = analyze_x86_pe_dataflow(
        data,
        image,
        roots=(_ROOT,),
        sources=_sources(),
        require_callback=True,
    )

    assert result["proof"]["port_source_to_network_conversion"] is False
    assert result["terminal_network_lineage_proven"] is False
    assert "native_flow_port_to_conversion_unproven" in result["missing_proof_codes"]


def test_unknown_indirect_call_fails_closed_with_machine_code() -> None:
    """register間接callを推測せず、未解決制御移譲として報告する。"""

    data, image = _image(unknown_call=True)

    result = analyze_x86_pe_dataflow(
        data,
        image,
        roots=(_ROOT,),
        sources=_sources(),
        require_callback=True,
    )

    assert result["analysis_complete"] is False
    assert result["terminal_network_lineage_proven"] is False
    assert result["coverage"]["unresolved_indirect_count"] == 1
    assert "native_flow_unresolved_indirect_control_flow" in result["missing_proof_codes"]


def test_instruction_budget_fails_closed() -> None:
    """budgetを超えた部分解析を完全なnetwork lineageとして扱わない。"""

    data, image = _image()

    result = analyze_x86_pe_dataflow(
        data,
        image,
        roots=(_ROOT,),
        sources=_sources(),
        limits=NativeFlowLimits(max_instructions=4),
        require_callback=True,
    )

    assert result["analysis_complete"] is False
    assert result["terminal_network_lineage_proven"] is False
    assert result["coverage"]["budget_exhausted"] is True
    assert "native_flow_budget_exhausted" in result["missing_proof_codes"]


def test_unknown_branch_on_sink_lineage_fails_closed() -> None:
    """条件が不明なbranchの片側だけを採用してnetwork証明を作らない。"""

    data, image = _image(unknown_branch=True)

    result = analyze_x86_pe_dataflow(
        data,
        image,
        roots=(_ROOT,),
        sources=_sources(),
        require_callback=True,
    )

    assert result["terminal_network_lineage_proven"] is False
    assert result["coverage"]["conditional_branch_count"] == 1
    assert result["coverage"]["branch_rejected_sink_count"] > 0
    assert "native_flow_unknown_branch_on_sink_lineage" in result["missing_proof_codes"]


def test_overlapping_source_ranges_are_rejected() -> None:
    """source aliasが入力時点で曖昧なら解析を開始しない。"""

    data, image = _image()
    overlapping = (
        NativeSource("first", _SOURCE_BASE, 0x20, "host"),
        NativeSource("second", _SOURCE_BASE + 0x10, 0x20, "port"),
    )

    result = analyze_x86_pe_dataflow(
        data,
        image,
        roots=(_ROOT,),
        sources=overlapping,
    )

    assert result["status"] == "invalid_sources"
    assert result["missing_proof_codes"] == ["native_flow_invalid_sources"]
