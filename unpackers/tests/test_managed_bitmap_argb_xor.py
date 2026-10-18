"""managed Bitmap／ARGB／XOR loaderの境界とfail-closed性を検証する。"""

from __future__ import annotations

import struct
import time
import zlib
from dataclasses import replace

import pytest

from unpackers import managed_bitmap_argb_xor as loader


def _u7(value: int) -> bytes:
    result = bytearray()
    while value >= 0x80:
        result.append((value & 0x7F) | 0x80)
        value >>= 7
    result.append(value)
    return bytes(result)


def _nrbf_string(value: str) -> bytes:
    encoded = value.encode("utf-8")
    return _u7(len(encoded)) + encoded


def _bitmap_nrbf(payload: bytes, *, array_id: int = 3) -> bytes:
    """許可されたBitmap/Data/byte[]だけを持つ最小NRBFを作る。"""

    return b"".join(
        (
            _u7(64),
            b"\x00",
            struct.pack("<iiii", 1, -1, 1, 0),
            b"\x0c",
            struct.pack("<i", 2),
            _nrbf_string(loader.SYSTEM_DRAWING_IDENTITY),
            b"\x05",
            struct.pack("<i", 1),
            _nrbf_string("System.Drawing.Bitmap"),
            struct.pack("<i", 1),
            _nrbf_string("Data"),
            b"\x07\x02",
            struct.pack("<i", 2),
            b"\x09",
            struct.pack("<i", array_id),
            b"\x0f",
            struct.pack("<ii", array_id, len(payload)),
            b"\x02",
            payload,
            b"\x0b",
        )
    )


def _png_chunk(kind: bytes, payload: bytes) -> bytes:
    return (
        struct.pack(">I", len(payload))
        + kind
        + payload
        + struct.pack(">I", zlib.crc32(kind + payload) & 0xFFFFFFFF)
    )


def _rgba_png(width: int, height: int, rgba: bytes) -> bytes:
    assert len(rgba) == width * height * 4
    filtered = b"".join(
        b"\x00" + rgba[row * width * 4 : (row + 1) * width * 4] for row in range(height)
    )
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0)
    return b"".join(
        (
            loader.PNG_MAGIC,
            _png_chunk(b"IHDR", ihdr),
            _png_chunk(b"IDAT", zlib.compress(filtered)),
            _png_chunk(b"IEND", b""),
        )
    )


def _bmp24() -> tuple[bytes, bytes]:
    """2x2 bottom-up BMPと期待するx-major RGB列を返す。"""

    width = height = 2
    stride = 8
    bottom = bytes((90, 80, 70, 120, 110, 100, 0, 0))
    top = bytes((30, 20, 10, 60, 50, 40, 0, 0))
    pixels = bottom + top
    size = 54 + len(pixels)
    file_header = b"BM" + struct.pack("<IHHI", size, 0, 0, 54)
    dib = struct.pack(
        "<IiiHHIIiiII",
        40,
        width,
        height,
        1,
        24,
        0,
        stride * height,
        0,
        0,
        0,
        0,
    )
    expected = bytes((10, 20, 30, 70, 80, 90, 40, 50, 60, 100, 110, 120))
    return file_header + dib + pixels, expected


def _deadline() -> float:
    return time.monotonic() + 2.0


def test_bitmap_nrbf_parser_returns_only_exact_byte_array() -> None:
    """BinaryFormatterを起動せず、許可record列のbyte[]だけを返す。"""

    payload = b"\x89PNG\r\n\x1a\nfixture"
    assert loader._parse_bitmap_nrbf(_bitmap_nrbf(payload)) == payload


@pytest.mark.parametrize(
    "mutate,reason",
    (
        (lambda value: value + b"\x00", "nrbf_message_end_or_trailing"),
        (lambda value: value[:-1], "nrbf_truncated"),
        (lambda value: b"\xc0\x00" + value[1:], "nrbf_7bit_integer_noncanonical"),
        (
            lambda value: value.replace(
                b"System.Drawing.Bitmap", b"System.Drawing.BitmaX", 1
            ),
            "nrbf_bitmap_class_identity",
        ),
    ),
)
def test_bitmap_nrbf_parser_rejects_trailing_truncated_and_wrong_class(
    mutate,
    reason: str,
) -> None:
    """追加record、切断、別classは曖昧な復元へ進めない。"""

    with pytest.raises(loader.RecoveryError, match=reason):
        loader._parse_bitmap_nrbf(mutate(_bitmap_nrbf(b"payload")))


def test_bitmap_nrbf_parser_rejects_duplicate_library_and_array_ids() -> None:
    """library IDをbyte array objectへ再利用するenvelopeを拒否する。"""

    with pytest.raises(loader.RecoveryError, match="nrbf_array_reference"):
        loader._parse_bitmap_nrbf(_bitmap_nrbf(b"payload", array_id=2))


def test_duplicate_bitmap_resource_candidates_are_rejected() -> None:
    """同名Bitmapが複数ResourceSetにあっても最初の候補を選ばない。"""

    entries = [
        loader.ResourceEntry("One.resources", "image", "System.Drawing.Bitmap", b"one"),
        loader.ResourceEntry("Two.resources", "image", "System.Drawing.Bitmap", b"two"),
    ]
    with pytest.raises(loader.RecoveryError, match="bitmap_resource_entry_ambiguous"):
        loader._find_bitmap_entry(entries, resource_set_name=None, entry_name="image")


def test_bmp_rgb_take_uses_x_major_y_minor_and_logical_top_left() -> None:
    """bottom-up BMPでもGetPixel相当の座標順とRGB順を保つ。"""

    bmp, expected = _bmp24()
    decoded, shape = loader._bmp_rgb_take(
        bmp,
        len(expected),
        _deadline(),
        time.monotonic,
    )
    assert decoded == expected
    assert shape == {
        "width": 2,
        "height": 2,
        "bits_per_pixel": 24,
        "pixel_count": 4,
    }


def test_bmp_rgb_take_enforces_deadline_during_scan() -> None:
    """pixel走査中も協調的deadlineを超えたら停止する。"""

    bmp, expected = _bmp24()
    ticks = iter((0.0, 2.0))
    with pytest.raises(loader.RecoveryError, match="time_limit"):
        loader._bmp_rgb_take(bmp, len(expected), 1.0, lambda: next(ticks))


def test_png_decoder_requires_single_crc_valid_rgba8_image() -> None:
    """単一のRGBA8 PNGだけを完全走査し、raw RGBAを復元する。"""

    rgba = bytes(range(16))
    png = _rgba_png(2, 2, rgba)
    width, height, decoded, shape = loader._decode_rgba_png(
        png,
        _deadline(),
        time.monotonic,
    )
    assert (width, height, decoded) == (2, 2, rgba)
    assert shape["filter_counts"] == {"0": 2}


def test_png_decoder_rejects_crc_trailing_and_noncontiguous_idat() -> None:
    """CRC破損、連結PNG、分断IDATをすべてfail-closedにする。"""

    rgba = bytes(range(16))
    png = _rgba_png(2, 2, rgba)
    corrupted = png[:-1] + bytes((png[-1] ^ 0xFF,))
    with pytest.raises(loader.RecoveryError, match="png_crc_mismatch"):
        loader._decode_rgba_png(corrupted, _deadline(), time.monotonic)
    with pytest.raises(loader.RecoveryError, match="png_iend_or_trailing"):
        loader._decode_rgba_png(png + png, _deadline(), time.monotonic)

    filtered = b"\x00" + rgba[:8] + b"\x00" + rgba[8:]
    compressed = zlib.compress(filtered)
    ihdr = struct.pack(">IIBBBBB", 2, 2, 8, 6, 0, 0, 0)
    split = len(compressed) // 2
    discontinuous = b"".join(
        (
            loader.PNG_MAGIC,
            _png_chunk(b"IHDR", ihdr),
            _png_chunk(b"IDAT", compressed[:split]),
            _png_chunk(b"tEXt", b"separator"),
            _png_chunk(b"IDAT", compressed[split:]),
            _png_chunk(b"IEND", b""),
        )
    )
    with pytest.raises(loader.RecoveryError, match="png_idat_order"):
        loader._decode_rgba_png(discontinuous, _deadline(), time.monotonic)


def test_png_decoder_rejects_decompression_beyond_declared_image() -> None:
    """zlib展開はIHDR由来の上限+1で止まり、flushで再展開しない。"""

    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 6, 0, 0, 0)
    bomb = b"".join(
        (
            loader.PNG_MAGIC,
            _png_chunk(b"IHDR", ihdr),
            _png_chunk(b"IDAT", zlib.compress(b"\x00" * 1_000_000)),
            _png_chunk(b"IEND", b""),
        )
    )
    with pytest.raises(loader.RecoveryError, match="png_zlib_size_or_eof"):
        loader._decode_rgba_png(bomb, _deadline(), time.monotonic)


def test_argb_xor_transform_validates_crop_scan_length_and_key_period() -> None:
    """crop後をx-major BGRA化し、文字列長周期のXORを再現する。"""

    rgba = bytearray(3 * 3 * 4)
    rgba[0:4] = bytes((0, 0, 4, 0))
    encoded = bytes((0x13, 0x73, 0x5E, 0x2E))
    rgba[3 * 4 : 4 * 4] = bytes((encoded[2], encoded[1], encoded[0], encoded[3]))
    decoded, metadata = loader._argb_xor_transform(
        bytes(rgba),
        3,
        3,
        crop_right=1,
        crop_bottom=1,
        key_text="wgb",
        mask_xor=0x70,
        deadline=_deadline(),
        clock=time.monotonic,
    )
    assert decoded == b"MZ\x00p"
    assert metadata["cropped_width"] == metadata["cropped_height"] == 2
    assert metadata["declared_output_size"] == 4
    assert metadata["key_period"] == 3
    assert metadata["key_byte_length"] == 6
    assert metadata["mask_constant_verified"] is True


def test_argb_xor_transform_rejects_non_square_crop_and_timeout() -> None:
    """CIL profileと異なるcrop形状や期限超過を採用しない。"""

    rgba = bytes(3 * 3 * 4)
    with pytest.raises(loader.RecoveryError, match="argb_crop_not_square"):
        loader._argb_xor_transform(
            rgba,
            3,
            3,
            crop_right=1,
            crop_bottom=0,
            key_text="k",
            mask_xor=0x70,
            deadline=_deadline(),
            clock=time.monotonic,
        )
    with pytest.raises(loader.RecoveryError, match="time_limit"):
        loader._argb_xor_transform(
            bytes((0, 0, 4, 0)) + bytes(12),
            2,
            2,
            crop_right=0,
            crop_bottom=0,
            key_text="k",
            mask_xor=0x70,
            deadline=1.0,
            clock=lambda: 2.0,
        )


def _instruction(
    opcode: str,
    *,
    token: int | None = None,
    resolved: str = "",
    integer: int | None = None,
    user_string: str | None = None,
    local: int | None = None,
) -> loader.Instruction:
    return loader.Instruction(0, opcode, token, resolved, integer, user_string, local)


def _split_constructor_method(*, invoke_uses_args: bool) -> loader.MethodModel:
    """3引数生成からConstructorInfo.Invokeまでの限定CIL fixtureを作る。"""

    delimiter_local = 6
    split_local = 7
    args_local = 8
    field_token = 0x04000001
    instructions = [
        _instruction("stloc.s", local=5),
        _instruction("ldstr", user_string="Sep"),
        _instruction("stloc.s", local=delimiter_local),
        _instruction("ldarg.0"),
        _instruction("ldfld", token=field_token),
        _instruction("ldc.i4.1", integer=1),
        _instruction("newarr", resolved="System.String"),
        _instruction("dup"),
        _instruction("ldc.i4.0", integer=0),
        _instruction("ldloc.s", local=delimiter_local),
        _instruction("stelem.ref"),
        _instruction("ldc.i4.0", integer=0),
        _instruction("callvirt", resolved="System.String::Split"),
        _instruction("stloc.s", local=split_local),
        _instruction("ldc.i4.3", integer=3),
        _instruction("newarr", resolved="System.String"),
        _instruction("dup"),
        _instruction("ldc.i4.0", integer=0),
        _instruction("ldloc.s", local=split_local),
        _instruction("ldc.i4.1", integer=1),
        _instruction("ldelem.ref"),
        _instruction("stelem.ref"),
        _instruction("dup"),
        _instruction("ldc.i4.1", integer=1),
        _instruction("ldloc.s", local=split_local),
        _instruction("ldc.i4.2", integer=2),
        _instruction("ldelem.ref"),
        _instruction("stelem.ref"),
        _instruction("dup"),
        _instruction("ldc.i4.2", integer=2),
        _instruction("ldloc.s", local=delimiter_local),
        _instruction("stelem.ref"),
        _instruction("stloc.s", local=args_local),
        _instruction("ldloc.s", local=5),
        _instruction("ldloc.s", local=args_local),
        _instruction("ldsfld", token=0x04000002),
        _instruction("dup"),
        _instruction("brtrue.s"),
        _instruction("pop"),
        _instruction("ldsfld", token=0x04000003),
        _instruction("ldftn", token=0x06000020),
        _instruction("newobj"),
        _instruction("dup"),
        _instruction("stsfld", token=0x04000002),
        _instruction("call", resolved="System.Linq.Enumerable::Select"),
        _instruction("call", resolved="System.Linq.Enumerable::ToArray"),
        _instruction("callvirt", resolved="System.Type::GetConstructor"),
        _instruction("stloc.s", local=9),
        _instruction("ldloc.s", local=9),
        _instruction("ldloc.s", local=args_local if invoke_uses_args else 99),
        _instruction("stloc.s", local=11),
        _instruction("ldloc.s", local=11),
        _instruction("callvirt", resolved="System.Reflection.ConstructorInfo::Invoke"),
    ]
    return loader.MethodModel(
        1,
        "Fixture",
        "Caller",
        1,
        1,
        "0" * 64,
        tuple(instructions),
    )


def test_constructor_arguments_must_reach_the_same_invoke_callsite() -> None:
    """型選択とInvoke値の双方へ同じ3引数localが届く場合だけ受理する。"""

    assignments = {0x04000001: ["Sep6A48Sep7767SepSep"]}
    assert loader._match_split_arguments(
        _split_constructor_method(invoke_uses_args=True),
        assignments,
    ) == ("6A48", "7767", "Sep")
    assert (
        loader._match_split_arguments(
            _split_constructor_method(invoke_uses_args=False),
            assignments,
        )
        is None
    )


def _rgb_lambda(token: int) -> loader.MethodModel:
    opcodes = (
        "ldc.i4.3",
        "newarr",
        "dup",
        "ldc.i4.0",
        "ldarga.s",
        "call",
        "stelem.i1",
        "dup",
        "ldc.i4.1",
        "ldarga.s",
        "call",
        "stelem.i1",
        "dup",
        "ldc.i4.2",
        "ldarga.s",
        "call",
        "stelem.i1",
        "ret",
    )
    integers = {0: 3, 3: 0, 8: 1, 13: 2}
    resolved = {
        1: "System.Byte",
        5: "System.Drawing.Color::get_R",
        10: "System.Drawing.Color::get_G",
        15: "System.Drawing.Color::get_B",
    }
    instructions = tuple(
        loader.Instruction(
            offset=index,
            opcode=opcode,
            token=None,
            resolved=resolved.get(index, ""),
            integer=integers.get(index),
            user_string=None,
            local=None,
        )
        for index, opcode in enumerate(opcodes)
    )
    return loader.MethodModel(token, "Fixture", "Rgb", 1, 1, "0" * 64, instructions)


def test_competing_rgb_lambdas_are_rejected_as_ambiguous() -> None:
    """同形候補が複数なら後続resourceを読まず曖昧として止める。"""

    with pytest.raises(loader.RecoveryError, match="outer_rgb_lambda_ambiguous"):
        loader._find_first_rgb_recipe([_rgb_lambda(1), _rgb_lambda(2)])


def test_duplicate_loader_method_profile_is_rejected() -> None:
    """reviewed body hashが複数methodへ一致した場合は競合候補を採らない。"""

    digest = loader.LOADER_METHOD_BODY_SHA256["entry"]
    fixture = loader.MethodModel(1, "Fixture", "One", 1, 1, digest, ())
    duplicate = loader.MethodModel(2, "Fixture", "Two", 2, 1, digest, ())
    with pytest.raises(
        loader.RecoveryError,
        match="loader_method_profile_incomplete_or_ambiguous",
    ):
        loader._loader_recipe([fixture, duplicate])


@pytest.mark.parametrize(
    "export_index,signature",
    (
        (1, b"\x00\x03\x01\x0e\x0e\x0e"),
        (0, b"\x00\x02\x01\x0e\x0e"),
    ),
)
def test_loader_entry_must_match_first_exported_type_and_signature(
    export_index: int,
    signature: bytes,
) -> None:
    """body hash群だけで、別ownerや別signatureへ移植したmethodを受理しない。"""

    methods = []
    for index, (role, digest) in enumerate(
        loader.LOADER_METHOD_BODY_SHA256.items(),
        1,
    ):
        methods.append(
            loader.MethodModel(
                index,
                "Fixture",
                role,
                index,
                1,
                digest,
                (),
                owner_token=0x02000002,
                owner_export_index=export_index if role == "entry" else 0,
                signature=signature if role == "entry" else b"\x00\x00\x01",
                is_static=True,
                is_public=role == "entry",
            )
        )
    with pytest.raises(
        loader.RecoveryError,
        match="loader_entry_owner_or_signature_mismatch",
    ):
        loader._loader_recipe(methods)


def test_public_report_never_promotes_family_or_returns_secret_material() -> None:
    """非候補でもprovider等を参照せず、帰属・C2・secret公開を禁止する。"""

    report, artifacts = loader.recover_managed_bitmap_argb_xor(b"not a managed PE")
    assert artifacts == []
    assert report["status"] == "not_candidate"
    assert report["family_attribution_allowed"] is False
    assert report["c2_confirmation_allowed"] is False
    assert report["terminal_promotion_eligible"] is False
    assert report["binaryformatter_deserialized"] is False
    assert report["raw_payload_content_in_report"] is False
    assert report["secret_material_in_report"] is False
    assert report["private_recursive_artifact_returned"] is False
    assert "provider" not in report


def test_loader_profile_hashes_are_complete_sha256_values() -> None:
    """profileの転記欠落を64桁hex検査で防ぐ。"""

    assert len(loader.LOADER_METHOD_BODY_SHA256) == 19
    assert all(
        len(value) == 64 and int(value, 16) >= 0
        for value in loader.LOADER_METHOD_BODY_SHA256.values()
    )


def test_v2_split_arguments_require_exact_shape_and_uniform_delimiter() -> None:
    """選択slot以外の値や混在separatorをconstructor引数として採用しない。"""

    late_delimiter = "50 6C 61 74 66 6F 72 6D"
    late_literal = late_delimiter.join(("41776253", "726C67", "", "", ""))
    assert loader._v2_split_arguments(late_literal, late_delimiter, 0, 1) == (
        "41776253",
        "726C67",
    )
    assert (
        loader._v2_split_arguments(
            late_delimiter.join(("41776253", "726C67", "", "unexpected", "")),
            late_delimiter,
            0,
            1,
        )
        is None
    )

    activator_delimiter = "61,7A,65"
    activator_literal = activator_delimiter.join(
        ("", "736561", "", "6B6579", "", "", "", "")
    )
    assert loader._v2_split_arguments(
        activator_literal,
        activator_delimiter,
        1,
        3,
    ) == ("736561", "6B6579")
    assert (
        loader._v2_split_arguments(
            activator_literal,
            "61,7A 65",
            1,
            3,
        )
        is None
    )


def test_v2_static_string_assignment_rejects_any_second_field_write() -> None:
    """cctor literal後に別経路で再書込みされるstatic fieldは定数とみなさない。"""

    field_token = 0x04000001
    initializer = loader.MethodModel(
        1,
        "Fixture",
        ".cctor",
        1,
        1,
        "0" * 64,
        (
            _instruction("ldstr", user_string="constant"),
            _instruction(
                "stsfld",
                token=field_token,
                resolved="Fixture::Config",
            ),
        ),
        signature=b"\x00\x00\x01",
        is_static=True,
        is_special_name=True,
        is_runtime_special_name=True,
    )
    assert loader._static_string_assignments([initializer]) == {
        field_token: ["constant"]
    }
    overwrite = loader.MethodModel(
        2,
        "Fixture",
        "Overwrite",
        2,
        1,
        "1" * 64,
        (
            _instruction("ldnull"),
            _instruction(
                "stsfld",
                token=field_token,
                resolved="Fixture::Config",
            ),
        ),
    )
    assert loader._static_string_assignments([initializer, overwrite]) == {}

    wrong_owner = loader.MethodModel(
        3,
        "Fixture",
        ".cctor",
        3,
        1,
        "2" * 64,
        (
            _instruction("ldstr", user_string="constant"),
            _instruction(
                "stsfld",
                token=field_token,
                resolved="OtherType::Config",
            ),
        ),
        signature=b"\x00\x00\x01",
        is_static=True,
        is_special_name=True,
        is_runtime_special_name=True,
    )
    assert loader._static_string_assignments([wrong_owner]) == {}


def _v2_bitmap_getter_fixture(*, signature: bytes) -> loader.MethodModel:
    owner = "ClydeShipyard.Properties.Resources"
    instructions = (
        _instruction("call", resolved=f"{owner}::get_ResourceManager"),
        _instruction("ldstr", user_string="Virtual"),
        _instruction("ldsfld", resolved=f"{owner}::resourceCulture"),
        _instruction(
            "callvirt",
            resolved="System.Resources.ResourceManager::GetObject",
        ),
        _instruction("stloc.0", local=0),
        _instruction("ldloc.0", local=0),
        _instruction("castclass", resolved="System.Drawing.Bitmap"),
        _instruction("stloc.1", local=1),
        _instruction("br.s"),
        _instruction("ldloc.1", local=1),
        _instruction("ret"),
    )
    return loader.MethodModel(
        0x06000068,
        owner,
        "get_Virtual",
        1,
        len(instructions),
        "5d17a51a9ce1814af27bb5f6ce77a492b907cb6c2b2b595c45cf96c49423e5e8",
        instructions,
        signature=signature,
        is_static=True,
        is_special_name=True,
    )


def test_v2_bitmap_getter_binds_exact_body_signature_and_resource_set() -> None:
    """同名GetObject断片ではなくreview済みgetterとowner resource setを要求する。"""

    valid = _v2_bitmap_getter_fixture(signature=bytes.fromhex("000012816d"))
    assert loader._v2_bitmap_getter([valid], valid.token) == (
        "Virtual",
        "ClydeShipyard.Properties.Resources.resources",
    )
    wrong_signature = _v2_bitmap_getter_fixture(signature=b"\x00\x00\x01")
    with pytest.raises(loader.RecoveryError, match="getter_profile_mismatch"):
        loader._v2_bitmap_getter([wrong_signature], wrong_signature.token)

    entries = [
        loader.ResourceEntry(
            "Decoy.resources",
            "Virtual",
            "System.Drawing.Bitmap",
            b"decoy",
        ),
        loader.ResourceEntry(
            "ClydeShipyard.Properties.Resources.resources",
            "Virtual",
            "System.Drawing.Bitmap",
            b"bound",
        ),
    ]
    assert (
        loader._find_bitmap_entry(
            entries,
            resource_set_name="ClydeShipyard.Properties.Resources.resources",
            entry_name="Virtual",
        ).data
        == b"bound"
    )


def _v2_handoff_method(
    profile: str,
    *,
    corrupt_fragment: bool = False,
    duplicate_alias_store: bool = False,
) -> loader.MethodModel:
    selected_type_local = 1
    args_local = 2
    if profile == "gettypes1-activator":
        instructions = [
            _instruction("ldloc.s", local=selected_type_local),
            _instruction("ldloc.s", local=args_local),
            _instruction("stloc.s", local=3),
            _instruction("ldloc.s", local=3),
            _instruction("call", resolved="System.Activator::CreateInstance"),
        ]
        if duplicate_alias_store:
            instructions.extend(
                (_instruction("ldnull"), _instruction("stloc.s", local=3))
            )
    elif profile == "gettypes1-latecall":
        instructions = [
            _instruction("ldloc.s", local=selected_type_local),
            _instruction("callvirt", resolved="System.Type::GetMethods"),
            _instruction("ldc.i4.0", integer=0),
            _instruction("ldelem.ref"),
            _instruction("stloc.s", local=3),
            _instruction("ldloc.s", local=3),
            _instruction("ldnull"),
            _instruction("ldstr", user_string="Invoke"),
            _instruction("ldc.i4.2", integer=2),
            _instruction("newarr", resolved="System.Object"),
            _instruction("dup"),
            _instruction("ldc.i4.0", integer=0),
            _instruction("ldc.i4.0", integer=0),
            _instruction("box", resolved="System.Int32"),
            _instruction("stelem.ref"),
            _instruction("dup"),
            _instruction("ldc.i4.1", integer=1),
            _instruction("ldloc.s", local=args_local),
            _instruction("stelem.ref"),
            _instruction("ldnull"),
            _instruction("ldnull"),
            _instruction(
                "call",
                resolved=(
                    "Microsoft.VisualBasic.CompilerServices.LateBinding::LateCall"
                ),
            ),
        ]
        if duplicate_alias_store:
            instructions.extend(
                (_instruction("ldnull"), _instruction("stloc.s", local=3))
            )
    else:
        fragments = ["Cr", "eat", "eIns", "ta", "nce"]
        if corrupt_fragment:
            fragments[2] = "eInx"
        instructions = [
            _instruction("ldtoken", resolved="System.Activator"),
            _instruction("call", resolved="System.Type::GetTypeFromHandle"),
            _instruction("ldc.i4.5", integer=5),
            _instruction("newarr", resolved="System.String"),
        ]
        for index, fragment in enumerate(fragments):
            instructions.extend(
                (
                    _instruction("dup"),
                    _instruction(f"ldc.i4.{index}", integer=index),
                    _instruction("ldstr", user_string=fragment),
                    _instruction("stelem.ref"),
                )
            )
        instructions.extend(
            (
                _instruction("call", resolved="System.String::Concat"),
                _instruction("ldc.i4", integer=256),
                _instruction("ldnull"),
                _instruction("ldnull"),
                _instruction("ldc.i4.2", integer=2),
                _instruction("newarr", resolved="System.Object"),
                _instruction("dup"),
                _instruction("ldc.i4.0", integer=0),
                _instruction("ldloc.s", local=selected_type_local),
                _instruction("stelem.ref"),
                _instruction("dup"),
                _instruction("ldc.i4.1", integer=1),
                _instruction("ldloc.s", local=args_local),
                _instruction("stelem.ref"),
                _instruction("call", resolved="System.Type::InvokeMember"),
            )
        )
    return loader.MethodModel(
        1,
        "Fixture",
        "Handoff",
        1,
        len(instructions),
        "0" * 64,
        tuple(instructions),
    )


@pytest.mark.parametrize(
    "profile",
    (
        "gettypes1-latecall",
        "gettypes1-type-invokemember",
        "gettypes1-activator",
    ),
)
def test_v2_handoff_requires_same_selected_type_and_argument_array(
    profile: str,
) -> None:
    """3方式ともGetTypes選択型と構築済みargsの同一localだけを受理する。"""

    method = _v2_handoff_method(profile)
    assert loader._v2_handoff_count(method, profile, 1, 2) == 1
    assert loader._v2_handoff_count(method, profile, 1, 99) == 0


def test_v2_handoff_rejects_alias_redefinition_and_fragment_spoof() -> None:
    """alias再定義とCreateInstance断片の一文字差をfail-closedにする。"""

    for profile in ("gettypes1-latecall", "gettypes1-activator"):
        method = _v2_handoff_method(profile, duplicate_alias_store=True)
        assert loader._v2_handoff_count(method, profile, 1, 2) == 0
    spoofed = _v2_handoff_method(
        "gettypes1-type-invokemember",
        corrupt_fragment=True,
    )
    assert (
        loader._v2_handoff_count(
            spoofed,
            "gettypes1-type-invokemember",
            1,
            2,
        )
        == 0
    )


def _resolved_call_method(
    token: int,
    digest: str,
    names: tuple[str, ...],
    *,
    owner_token: int,
    owner_export_index: int | None,
    signature: bytes,
    is_static: bool,
    is_public: bool,
    extra_instructions: tuple[loader.Instruction, ...] = (),
) -> loader.MethodModel:
    instructions = tuple(_instruction("call", resolved=name) for name in names) + (
        extra_instructions
    )
    return loader.MethodModel(
        token,
        "Fixture",
        "RgbRole",
        token,
        len(instructions),
        digest,
        instructions,
        owner_token=owner_token,
        owner_export_index=owner_export_index,
        signature=signature,
        is_static=is_static,
        is_public=is_public,
    )


def _iterator_rgb_fixture(
    move_digest: str = "41e0a6d4aaf23cee97b8bcd1dfc839fab10d0b2cf9939ef8e979027934317fb6",
) -> list[loader.MethodModel]:
    """実review済みowner／edgeを持つiterator RGB profileを組み立てる。"""

    constructor_token = 5
    wrapper = _resolved_call_method(
        1,
        "9a89b81cfa8f9321203c61968b473dfdbffdafe67883c48fd92d46fe0fe3e480",
        (
            "System.Drawing.Image::get_Width",
            "System.Drawing.Image::get_Height",
            "System.Collections.IEnumerator::MoveNext",
        ),
        owner_token=0x02000004,
        owner_export_index=1,
        signature=bytes.fromhex("000215128159010512809108"),
        is_static=True,
        is_public=True,
        extra_instructions=(_instruction("call", token=2),),
    )
    factory = _resolved_call_method(
        2,
        "5fbc5b1adacd64e0101ff08b597bc8d94a5a718732872c0b4688770bf266e24b",
        (
            "System.Drawing.Image::get_Width",
            "System.Drawing.Image::get_Height",
        ),
        owner_token=0x02000003,
        owner_export_index=0,
        signature=bytes.fromhex("000215128089010512809108"),
        is_static=True,
        is_public=False,
        extra_instructions=(_instruction("newobj", token=constructor_token),),
    )
    move_next = _resolved_call_method(
        3,
        move_digest,
        (
            "System.Drawing.Bitmap::GetPixel",
            "System.Drawing.Color::get_R",
            "System.Drawing.Color::get_G",
            "System.Drawing.Color::get_B",
        ),
        owner_token=0x02000005,
        owner_export_index=None,
        signature=bytes.fromhex("200002"),
        is_static=False,
        is_public=False,
    )
    constructor = loader.MethodModel(
        constructor_token,
        "Fixture.Iterator",
        ".ctor",
        constructor_token,
        1,
        "3c732762770ada8ac9b6b743f6aa538b7a0504c2b61f45ffcf6df820c44cf70d",
        (),
        owner_token=0x02000005,
        owner_export_index=None,
        signature=bytes.fromhex("20010108"),
        is_public=True,
        is_special_name=True,
        is_runtime_special_name=True,
    )
    return [wrapper, factory, move_next, constructor]


def test_v2_rgb_reviewed_movenext_alternative_remains_unique() -> None:
    """review済みMoveNext差分は1種だけ存在する時に限り受理する。"""

    methods = _iterator_rgb_fixture()
    assert loader._v2_rgb_profile(methods, 1) == ("iterator-rgb-a-v2")

    d152_movenext = _resolved_call_method(
        6,
        "83e306b041c882d1f88ed11edda5ad37ef256153185e9218aedee89ce5bf0f74",
        ("System.Drawing.Bitmap::GetPixel",),
        owner_token=0x02000005,
        owner_export_index=None,
        signature=bytes.fromhex("200002"),
        is_static=False,
        is_public=False,
    )
    with pytest.raises(loader.RecoveryError, match="related_body_ambiguous"):
        loader._v2_rgb_profile(
            [*methods, d152_movenext],
            1,
        )


def test_v2_rgb_profile_rejects_dead_decoy_and_metadata_shape_mutation() -> None:
    """review済みbodyのdead decoyやsignature／owner差替えを受理しない。"""

    methods = _iterator_rgb_fixture()
    dead_wrapper = replace(
        methods[0],
        instructions=tuple(
            replace(item, token=0x0600FFFF)
            if item.opcode == "call" and item.token == methods[1].token
            else item
            for item in methods[0].instructions
        ),
    )
    with pytest.raises(loader.RecoveryError, match="related_edge_mismatch"):
        loader._v2_rgb_profile([dead_wrapper, *methods[1:]], dead_wrapper.token)

    wrong_signature = replace(methods[0], signature=b"\x00\x02\xff\xff\xff")
    with pytest.raises(loader.RecoveryError, match="profile_mismatch"):
        loader._v2_rgb_profile(
            [wrong_signature, *methods[1:]],
            wrong_signature.token,
        )

    wrong_owner = replace(methods[1], owner_token=0x02000006)
    with pytest.raises(loader.RecoveryError, match="related_method_shape_mismatch"):
        loader._v2_rgb_profile([methods[0], wrong_owner, *methods[2:]], 1)

    wrong_flags = replace(methods[0], is_public=False)
    with pytest.raises(loader.RecoveryError, match="profile_mismatch"):
        loader._v2_rgb_profile([wrong_flags, *methods[1:]], 1)

    detached_constructor = replace(methods[3], owner_token=0x02000006)
    with pytest.raises(loader.RecoveryError, match="iterator_owner_binding_mismatch"):
        loader._v2_rgb_profile([*methods[:3], detached_constructor], 1)


def test_v2_cil_inventory_binds_signature_flags_and_unique_tokens() -> None:
    """exact child profileをbody hashだけで別signature／flagsへ移植できない。"""

    base = loader.MethodModel(
        1,
        "Fixture",
        "Role",
        1,
        1,
        "0" * 64,
        (),
        owner_token=0x02000001,
        owner_export_index=1,
        signature=b"\x00\x00\x01",
        is_static=True,
    )
    changed = loader.MethodModel(
        1,
        "Fixture",
        "Role",
        1,
        1,
        "0" * 64,
        (),
        owner_token=0x02000001,
        owner_export_index=1,
        signature=b"\x00\x01\x01\x08",
        is_static=False,
    )
    assert loader._cil_inventory_sha256([base]) != loader._cil_inventory_sha256(
        [changed]
    )
    with pytest.raises(loader.RecoveryError, match="method_token_ambiguous"):
        loader._cil_inventory_sha256([base, changed])


def test_v2_load_sink_high_fanout_returns_typed_incomplete() -> None:
    """敵対的なAssembly.Load callsite増幅をN+1件目で未完了として止める。"""

    instructions: list[loader.Instruction] = []
    for index in range(loader.MAX_V2_LOAD_SINK_CANDIDATES + 1):
        instructions.extend(
            (
                _instruction("ldloc.s", local=index),
                _instruction("ldc.i4", integer=4_096),
                _instruction("call", token=0x06000001),
                _instruction("call", resolved="System.Linq.Enumerable::ToArray"),
                _instruction("call", resolved="System.Reflection.Assembly::Load"),
                _instruction("stloc.s", local=1_000 + index),
            )
        )
    method = loader.MethodModel(
        1,
        "Fixture",
        "Fanout",
        1,
        len(instructions),
        "0" * 64,
        tuple(instructions),
    )

    with pytest.raises(loader.IncompleteRecoveryError) as raised:
        loader._v2_load_sinks(method, "gettypes1-activator")
    assert str(raised.value) == "outer_gettypes1_candidate_limit"
    assert raised.value.report_details() == {
        "type": "candidate_limit",
        "stage": "outer_gettypes1_root_recipe",
        "role": "load_sink",
        "observed": loader.MAX_V2_LOAD_SINK_CANDIDATES + 1,
        "limit": loader.MAX_V2_LOAD_SINK_CANDIDATES,
    }


def test_v2_root_recipe_propagates_deadline_to_search() -> None:
    """root recipe探索開始時から既存10秒deadlineを協調検査する。"""

    method = loader.MethodModel(
        1,
        "Fixture",
        "Root",
        1,
        1,
        "0" * 64,
        (_instruction("callvirt", resolved="System.Reflection.Assembly::GetTypes"),),
    )
    with pytest.raises(loader.IncompleteRecoveryError) as raised:
        loader._root_recipe_v2([method], deadline=1.0, clock=lambda: 2.0)
    assert str(raised.value) == "elapsed_time_limit"
    assert raised.value.report_details()["type"] == "deadline"


def test_v1_recipe_helpers_propagate_deadline_to_search() -> None:
    """v1のroot／loader／sequence探索も同じdeadlineで協調停止する。"""

    method = loader.MethodModel(
        1,
        "Fixture",
        "Root",
        1,
        1,
        "0" * 64,
        (_instruction("nop"),),
    )
    for callback in (
        lambda: loader._root_recipe_v1([method], deadline=1.0, clock=lambda: 2.0),
        lambda: loader._loader_recipe_v1([method], deadline=1.0, clock=lambda: 2.0),
        lambda: loader._sequence(
            method,
            (lambda item: item.opcode == "nop",),
            deadline=1.0,
            clock=lambda: 2.0,
        ),
    ):
        with pytest.raises(loader.IncompleteRecoveryError) as raised:
            callback()
        assert raised.value.report_details()["type"] == "deadline"


def test_v2_root_recipe_limits_total_join_width(monkeypatch) -> None:
    """role単体が上限内でも直積が大きい場合はjoin前に停止する。"""

    root = loader.MethodModel(
        1,
        "Fixture",
        "Root",
        1,
        1,
        "0" * 64,
        (_instruction("callvirt", resolved="System.Reflection.Assembly::GetTypes"),),
    )
    monkeypatch.setattr(
        loader, "_static_string_assignments", lambda *args, **kwargs: {1: ["x"]}
    )
    monkeypatch.setattr(
        loader,
        "_v2_load_sinks",
        lambda *args, **kwargs: [(1, 4_096, 0x06000002, 2)],
    )
    monkeypatch.setattr(
        loader,
        "_v2_split_locals",
        lambda *args, **kwargs: [(1, 3, "AA")],
    )
    monkeypatch.setattr(loader, "_v2_split_arguments", lambda *args: ("41", "42"))
    monkeypatch.setattr(
        loader,
        "_v2_argument_arrays",
        lambda *args, **kwargs: [(100 + index, "Fixture") for index in range(15)],
    )
    monkeypatch.setattr(loader, "_v2_handoff_pairs", lambda *args, **kwargs: {})
    monkeypatch.setattr(loader, "_v2_rgb_profile", lambda *args, **kwargs: "rgb")
    monkeypatch.setattr(
        loader,
        "_v2_bitmap_getters",
        lambda *args, **kwargs: [
            (0x06000100 + index, f"Bitmap{index}", "Fixture.resources")
            for index in range(17)
        ],
    )
    monkeypatch.setattr(
        loader,
        "_v2_gettypes_locals",
        lambda *args, **kwargs: list(range(200, 217)),
    )

    with pytest.raises(loader.IncompleteRecoveryError) as raised:
        loader._root_recipe_v2([root])
    assert str(raised.value) == "outer_gettypes1_combination_limit"
    assert raised.value.report_details() == {
        "type": "combination_limit",
        "stage": "outer_gettypes1_root_recipe",
        "role": "recipe_join",
        "observed": 4_335,
        "limit": loader.MAX_V2_RECIPE_COMBINATIONS,
    }


def test_public_report_distinguishes_incomplete_search(monkeypatch) -> None:
    """上限・deadline到達を静的recipe不一致のrejectedへ潰さない。"""

    def incomplete_parse(*args, **kwargs):
        raise loader.IncompleteRecoveryError(
            "outer_gettypes1_candidate_limit",
            incomplete_type="candidate_limit",
            stage="outer_gettypes1_root_recipe",
            role="root_method",
            observed=65,
            limit=64,
        )

    monkeypatch.setattr(loader, "_parse_managed", incomplete_parse)
    report, artifacts = loader.recover_managed_bitmap_argb_xor(
        b"System.Drawing.Bitmap GetPixel GetTypes"
    )
    assert artifacts == []
    assert report["status"] == "analysis_incomplete"
    assert report["reason"] == "outer_gettypes1_candidate_limit"
    assert report["incomplete"] == {
        "type": "candidate_limit",
        "stage": "outer_gettypes1_root_recipe",
        "role": "root_method",
        "observed": 65,
        "limit": 64,
    }


def test_v2_loader_recipe_does_not_claim_unverified_call_graph() -> None:
    """exact body profileは未検証role edgeまでcall graph確認済みにしない。"""

    recipe = loader.LoaderRecipe(
        crop_right=177,
        crop_bottom=225,
        mask_xor=112,
        method_tokens={},
        constructor_token=1,
        profile_id="managed-bitmap-argb-xor-v2-fixture",
        exact_child_profile_verified=True,
    )
    assert recipe.exact_child_profile_verified is True
    assert recipe.call_graph_verified is False


def _v2_semantic_loader_fixture() -> list[loader.MethodModel]:
    """a191d02e shapeを、実binaryを実行せずMethodModelで再現する。"""

    profile = loader.LOADER_V2_PROFILES[
        "a191d02ea8e94d4e60af487303704e362981530ded0c3f0199f6c5878ce2d82e"
    ]
    signatures = profile["role_signatures"]
    assert isinstance(signatures, dict)
    owner_token = 0x02000002

    def method(
        token: int,
        role: str,
        instructions: tuple[loader.Instruction, ...],
        *,
        name: str | None = None,
        is_public: bool = False,
        is_static: bool = True,
        is_special_name: bool = False,
        is_runtime_special_name: bool = False,
    ) -> loader.MethodModel:
        digest_key = (
            "resource_getter_body_sha256"
            if role == "resource_getter"
            else f"{role}_body_sha256"
        )
        digest = profile[digest_key]
        signature = signatures[role]
        assert isinstance(digest, str)
        assert isinstance(signature, str)
        return loader.MethodModel(
            token,
            "Fixture.Loader",
            name or role,
            token,
            len(instructions),
            digest,
            instructions,
            owner_token=owner_token,
            owner_export_index=1,
            signature=bytes.fromhex(signature),
            is_static=is_static,
            is_public=is_public,
            is_special_name=is_special_name,
            is_runtime_special_name=is_runtime_special_name,
        )

    entry = method(
        2,
        "entry",
        (
            _instruction("ldarg.0"),
            _instruction("ldarg.1"),
            _instruction("ldarg.2"),
            _instruction("call", token=3),
            _instruction("call", token=4),
            _instruction("call", token=5),
        ),
        is_public=True,
    )
    return [
        method(
            1,
            "constructor",
            (
                _instruction("ldarg.1"),
                _instruction("ldarg.2"),
                _instruction("ldarg.3"),
                _instruction("call", token=2),
                _instruction(
                    "call",
                    token=0x0A000001,
                    resolved="System.Windows.Forms.Form::.ctor",
                ),
                _instruction("newarr", token=0x01000001, resolved="System.String"),
            ),
            name=".ctor",
            is_public=True,
            is_static=False,
            is_special_name=True,
            is_runtime_special_name=True,
        ),
        entry,
        method(
            3,
            "crop",
            (
                _instruction("ldc.i4", integer=177),
                _instruction("ldc.i4", integer=225),
            ),
        ),
        method(
            4,
            "mask",
            (
                _instruction("ldc.i4", integer=112),
                _instruction("xor"),
                _instruction("xor"),
                _instruction("newarr", token=0x01000002, resolved="System.Byte"),
            ),
            is_public=True,
        ),
        method(5, "load_wrapper", (_instruction("call", token=6),)),
        method(
            6,
            "load_inner",
            (
                _instruction("newarr", token=0x01000003, resolved="System.Char"),
                _instruction("ldtoken", token=0x04000001),
                _instruction(
                    "newobj", token=0x0A000002, resolved="System.String::.ctor"
                ),
                _instruction("ldc.i4.1", integer=1),
                _instruction("newarr", token=0x01000004, resolved="System.Object"),
                _instruction("dup"),
                _instruction("ldc.i4.0", integer=0),
                _instruction("ldarg.0"),
                _instruction("stelem.ref"),
                _instruction(
                    "castclass",
                    token=0x01000005,
                    resolved="System.Reflection.Assembly",
                ),
            ),
        ),
        method(
            7,
            "resource_getter",
            (
                _instruction(
                    "castclass", token=0x01000006, resolved="System.Drawing.Bitmap"
                ),
                _instruction(
                    "newobj",
                    token=0x0A000003,
                    resolved="System.Resources.ResourceManager::.ctor",
                ),
            ),
        ),
    ]


def test_v2_semantic_profile_accepts_benign_metadata_resource_variation() -> None:
    """child SHAや未使用resource metadataが変わっても完全semantic形状を受理する。"""

    methods = _v2_semantic_loader_fixture()
    methods.append(
        loader.MethodModel(
            99,
            "Fixture.UnusedResources",
            "get_Unused",
            99,
            1,
            "f" * 64,
            (_instruction("ldstr", user_string="renamed-benign-resource"),),
            owner_token=0x02000063,
            signature=b"\x00\x00\x0e",
            is_static=True,
        )
    )
    recipe = loader._loader_recipe(methods, assembly_sha256="f" * 64)
    assert recipe.profile_id == "managed-bitmap-argb-xor-v2-a191d02e"
    assert recipe.semantic_child_profile_verified is True
    assert recipe.exact_child_profile_verified is False
    assert recipe.call_graph_verified is False


def test_v2_semantic_profile_rejects_resolution_target_substitution() -> None:
    """body labelが一致してもresource getterのMemberRef差替えは受理しない。"""

    methods = _v2_semantic_loader_fixture()
    getter = methods[-1]
    methods[-1] = loader.MethodModel(
        getter.token,
        getter.owner,
        getter.name,
        getter.rva,
        getter.body_size,
        getter.body_sha256,
        tuple(
            _instruction(
                item.opcode,
                token=item.token,
                resolved=(
                    "System.Resources.ResourceManager::ReleaseAllResources"
                    if item.resolved == "System.Resources.ResourceManager::.ctor"
                    else item.resolved
                ),
                integer=item.integer,
                user_string=item.user_string,
                local=item.local,
            )
            for item in getter.instructions
        ),
        owner_token=getter.owner_token,
        owner_export_index=getter.owner_export_index,
        signature=getter.signature,
        is_static=getter.is_static,
        is_public=getter.is_public,
    )
    with pytest.raises(loader.RecoveryError):
        loader._loader_recipe_v2(methods, "f" * 64)


def test_v2_loader_role_high_fanout_returns_typed_incomplete() -> None:
    """semantic role bodyの複製増幅をN+1件目で未完了として止める。"""

    methods = _v2_semantic_loader_fixture()
    constructor = methods[0]
    methods.extend(
        loader.MethodModel(
            100 + index,
            constructor.owner,
            constructor.name,
            100 + index,
            constructor.body_size,
            constructor.body_sha256,
            constructor.instructions,
            owner_token=constructor.owner_token,
            owner_export_index=constructor.owner_export_index,
            signature=constructor.signature,
            is_static=constructor.is_static,
            is_public=constructor.is_public,
            is_special_name=constructor.is_special_name,
            is_runtime_special_name=constructor.is_runtime_special_name,
        )
        for index in range(loader.MAX_V2_LOADER_ROLE_CANDIDATES)
    )
    with pytest.raises(loader.IncompleteRecoveryError) as raised:
        loader._loader_recipe_v2(methods, "f" * 64)
    assert raised.value.report_details() == {
        "type": "candidate_limit",
        "stage": "loader_v2_semantic_profile",
        "role": "constructor",
        "observed": loader.MAX_V2_LOADER_ROLE_CANDIDATES + 1,
        "limit": loader.MAX_V2_LOADER_ROLE_CANDIDATES,
    }


def test_v2_loader_semantic_search_propagates_deadline() -> None:
    """loader側の索引・profile探索にも既存10秒deadlineを伝播する。"""

    with pytest.raises(loader.IncompleteRecoveryError) as raised:
        loader._loader_recipe_v2(
            _v2_semantic_loader_fixture(),
            "f" * 64,
            deadline=1.0,
            clock=lambda: 2.0,
        )
    assert raised.value.report_details()["type"] == "deadline"


def test_root_recipe_ignores_unused_other_version_api_decoy(monkeypatch) -> None:
    """未使用GetExportedTypes decoyがあっても一意なv2 recipeは拒否しない。"""

    expected = loader.RootRecipe(1, 2, 3, 4, "bitmap", "41", "42", "Fixture")
    methods = [
        loader.MethodModel(
            1,
            "Fixture",
            "Root",
            1,
            2,
            "0" * 64,
            (
                _instruction(
                    "callvirt", resolved="System.Reflection.Assembly::GetTypes"
                ),
                _instruction(
                    "callvirt",
                    resolved="System.Reflection.Assembly::GetExportedTypes",
                ),
            ),
        )
    ]
    monkeypatch.setattr(
        loader,
        "_root_recipe_v1",
        lambda _methods, **_kwargs: (_ for _ in ()).throw(
            loader.RecoveryError("decoy")
        ),
    )
    monkeypatch.setattr(loader, "_root_recipe_v2", lambda *args, **kwargs: expected)
    assert loader._root_recipe(methods) == expected


def test_root_recipe_rejects_ambiguous_dual_complete_recipe(monkeypatch) -> None:
    """v1/v2がともに完全成立する入力は一方を優先せず拒否する。"""

    first = loader.RootRecipe(1, 2, 3, 4, "one", "41", "42", "Fixture")
    second = loader.RootRecipe(5, 6, 7, 8, "two", "43", "44", "Fixture")
    methods = [
        loader.MethodModel(
            1,
            "Fixture",
            "Root",
            1,
            2,
            "0" * 64,
            (
                _instruction(
                    "callvirt", resolved="System.Reflection.Assembly::GetTypes"
                ),
                _instruction(
                    "callvirt",
                    resolved="System.Reflection.Assembly::GetExportedTypes",
                ),
            ),
        )
    ]
    monkeypatch.setattr(loader, "_root_recipe_v1", lambda _methods, **_kwargs: first)
    monkeypatch.setattr(loader, "_root_recipe_v2", lambda *args, **kwargs: second)
    with pytest.raises(
        loader.RecoveryError,
        match="outer_type_selection_recipe_ambiguous",
    ):
        loader._root_recipe(methods)


def test_loader_recipe_rejects_ambiguous_v1_v2_complete_recipe(monkeypatch) -> None:
    """loader v1/v2も独立評価し、二重成立をfail-closedにする。"""

    first = loader.LoaderRecipe(1, 2, 3, {}, 1, profile_id="v1")
    second = loader.LoaderRecipe(4, 5, 6, {}, 2, profile_id="v2")
    monkeypatch.setattr(loader, "_loader_recipe_v1", lambda _methods, **_kwargs: first)
    monkeypatch.setattr(loader, "_loader_recipe_v2", lambda *args, **kwargs: second)
    with pytest.raises(loader.RecoveryError, match="loader_recipe_profile_ambiguous"):
        loader._loader_recipe([])
