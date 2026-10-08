"""managed Bitmap／ARGB／XOR loaderの境界とfail-closed性を検証する。"""

from __future__ import annotations

import struct
import time
import zlib

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
