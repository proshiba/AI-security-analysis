"""BIN/101 native loaderの静的復元とfail-closed条件を検証する。"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from unpackers import bin101_nibble_rc4 as target
from unpackers import static_unpacker


def _inverse_nibble_transform(decoded: bytes) -> bytes:
    state = 0x55
    encoded = bytearray(len(decoded))
    for index, value in enumerate(decoded):
        rotated = value ^ (((state ^ 0xAA) + index) & 0xFF)
        mixed = ((rotated << 4) & 0xFF) | (rotated >> 4)
        encoded[index] = mixed ^ state
        state = (state + value + 0x0D) & 0xFF
    return bytes(encoded)


def _payload() -> bytes:
    # 実検体byteを含めず、PEB参照と十分な分岐を持つ無害なfixture。
    block = (
        bytes.fromhex("65488b042560000000")
        + b"\x48\x85\xc0\x74\x02\x90\x90"
        + b"\x48\x31\xc9\x75\x02\x90\x90"
        + b"\xe8\x00\x00\x00\x00\xeb\x02\x90\x90\xc3"
    )
    prefix = (block * 40)[:1100]
    config = b"codemark" + b"\0" * 120
    return (prefix + config).ljust(1400, b"\x90")


def _fake_image(resource: bytes, *, resource_id: int = 101):
    leaf = SimpleNamespace(
        data=SimpleNamespace(
            struct=SimpleNamespace(OffsetToData=0x3000, Size=len(resource))
        )
    )
    name = SimpleNamespace(
        id=resource_id,
        directory=SimpleNamespace(entries=[leaf]),
    )
    resource_type = SimpleNamespace(
        name="BIN",
        directory=SimpleNamespace(entries=[name]),
    )
    directories = [SimpleNamespace(VirtualAddress=0, Size=0) for _ in range(15)]
    return SimpleNamespace(
        FILE_HEADER=SimpleNamespace(Machine=0x8664),
        OPTIONAL_HEADER=SimpleNamespace(DATA_DIRECTORY=directories),
        DIRECTORY_ENTRY_RESOURCE=SimpleNamespace(entries=[resource_type]),
        parse_data_directories=lambda **_kwargs: None,
        get_data=lambda rva, size: (
            resource if (rva, size) == (0x3000, len(resource)) else b""
        ),
    )


def _outer_fixture(payload: bytes) -> tuple[bytes, bytes]:
    transformed = target._rc4(payload)  # noqa: SLF001 - RC4は対称変換
    resource = _inverse_nibble_transform(transformed)
    outer = (
        b"MZ"
        + b"\0" * 126
        + target.FNV_SEED
        + target.FNV_PRIME
        + target.RC4_KEY
        + b"\0" * 512
    )
    return outer, resource


def test_recovery_requires_structure_and_returns_public_metadata(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = _payload()
    outer, resource = _outer_fixture(payload)
    monkeypatch.setattr(target.pefile, "PE", lambda **_kwargs: _fake_image(resource))

    recovered = target.recover_bin101_payload(outer)

    assert recovered is not None
    assert recovered.payload == payload
    metadata = recovered.metadata()
    assert metadata["status"] == "shellcode_recovered"
    assert metadata["family_attribution"] == "unresolved_component_only"
    assert metadata["raw_payload_included"] is False
    assert metadata["rc4_key"]["raw_value_included"] is False
    assert metadata["executed"] is False
    assert metadata["network_contacted"] is False


@pytest.mark.parametrize(
    "mutation",
    ["machine", "resource_id", "seed", "marker"],
)
def test_profile_mismatch_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    payload = _payload()
    if mutation == "marker":
        payload = payload.replace(b"codemark", b"not-mark")
    outer, resource = _outer_fixture(payload)
    image = _fake_image(
        resource,
        resource_id=102 if mutation == "resource_id" else 101,
    )
    if mutation == "machine":
        image.FILE_HEADER.Machine = 0x14C
    if mutation == "seed":
        outer = outer.replace(target.FNV_SEED, b"NOPE", 1)
    monkeypatch.setattr(target.pefile, "PE", lambda **_kwargs: image)

    assert target.recover_bin101_payload(outer) is None


def test_static_unpacker_routes_only_verified_payload(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = _payload()
    recovery = target.Bin101Recovery(
        payload=payload,
        input_sha256="1" * 64,
        resource_size=2048,
        resource_sha256="2" * 64,
        transformed_sha256="3" * 64,
        instruction_count=100,
        instruction_coverage=0.99,
        branch_count=8,
        codemark_offset=1100,
    )
    monkeypatch.setattr(
        static_unpacker,
        "recover_bin101_payload",
        lambda _data: recovery,
    )
    monkeypatch.setattr(
        static_unpacker,
        "pe_summary",
        lambda _data: (
            {
                "is_dotnet": False,
                "sections": [],
                "packer_markers": [],
                "containerized": False,
                "analysis_coverage": {"imports_known": True},
                "imports": 1,
                "is_go": False,
            },
            [],
        ),
    )
    monkeypatch.setattr(
        static_unpacker,
        "recover_inflated_pe",
        lambda _data: ({}, None),
    )
    monkeypatch.setattr(
        static_unpacker,
        "recover_dotnet_bundle",
        lambda *_args, **_kwargs: ({}, []),
    )
    monkeypatch.setattr(
        static_unpacker,
        "recover_embedded_installer_archive",
        lambda *_args, **_kwargs: ({}, [], set()),
    )
    monkeypatch.setattr(
        static_unpacker,
        "recover_xor32_donut_wrapper",
        lambda _data: ({}, []),
    )
    monkeypatch.setattr(
        static_unpacker,
        "recover_donut_payloads",
        lambda _data: ({}, []),
    )
    monkeypatch.setattr(
        static_unpacker,
        "carve_embedded_pes",
        lambda _data: [],
    )

    report, artifacts = static_unpacker.unpack_bytes(
        b"MZ" + b"\0" * 1024,
        "fixture.exe",
    )

    assert report["bin101_nibble_rc4_loader"]["status"] == "shellcode_recovered"
    assert ("bin101-nibble-rc4-shellcode", payload) in artifacts
