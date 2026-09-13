"""BCrypt resource静的復号器のpositive/negative/boundary試験。"""

from __future__ import annotations

import json
import struct
import zlib
from types import SimpleNamespace

import pytest
from capstone import CS_ARCH_X86, CS_MODE_32, Cs
from Cryptodome.Cipher import AES

from unpackers import bcrypt_resource as bcrypt


def _recipe(password: bytes = b"synthetic-password") -> bcrypt.BcryptRecipe:
    return bcrypt.BcryptRecipe(
        password=password,
        salt=b"salt-123",
        iterations=10_000,
        key_size=32,
        decrypt_flags=0,
        call_addresses=(
            ("BCryptOpenAlgorithmProvider", 0x401000),
            ("BCryptDeriveKeyPBKDF2", 0x401020),
            ("BCryptOpenAlgorithmProvider", 0x401040),
            ("BCryptSetProperty", 0x401060),
            ("BCryptGenerateSymmetricKey", 0x401080),
            ("BCryptDecrypt", 0x4010A0),
        ),
        layout=bcrypt.ResourceLayout(0x400F00, 0x400F20, 21, 29),
    )


def _encrypt_resource(recipe: bcrypt.BcryptRecipe, payload: bytes) -> bytes:
    compressed = zlib.compress(payload, level=9)
    pad = AES.block_size - (len(compressed) % AES.block_size)
    plaintext = compressed + bytes([pad]) * pad
    iv = bytes(range(AES.block_size))
    key = bcrypt.hashlib.pbkdf2_hmac(
        "sha256",
        recipe.password,
        recipe.salt,
        recipe.iterations,
        dklen=recipe.key_size,
    )
    return iv + AES.new(key, AES.MODE_CBC, iv).encrypt(plaintext)


def _preflight_pe(
    *,
    include_imports: bool = True,
    include_resource_candidate: bool = True,
    include_call_anchor: bool = True,
    append_decoy_markers: bool = False,
    resource_size: int | None = None,
) -> bytes:
    """大容量先行判定専用の、実行しない最小PE32 fixtureを組み立てる。"""

    data = bytearray(0x1400)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", data, 0x84, 0x14C, 3, 0, 0, 0, 0xE0, 0x102)
    optional = 0x98
    struct.pack_into("<H", data, optional, 0x10B)
    struct.pack_into("<I", data, optional + 28, 0x400000)
    struct.pack_into("<I", data, optional + 92, 16)
    if include_imports:
        struct.pack_into("<II", data, optional + 104, 0x2000, 40)
    struct.pack_into("<II", data, optional + 112, 0x3000, 0x100)

    def section(
        index: int,
        name: bytes,
        virtual_address: int,
        raw_offset: int,
        raw_size: int,
        characteristics: int,
    ) -> None:
        offset = optional + 0xE0 + index * 40
        data[offset : offset + 8] = name.ljust(8, b"\0")
        struct.pack_into(
            "<IIIIIIHHI",
            data,
            offset + 8,
            raw_size,
            virtual_address,
            raw_size,
            raw_offset,
            0,
            0,
            0,
            0,
            characteristics,
        )

    section(0, b".text", 0x1000, 0x400, 0x200, 0x60000020)
    section(1, b".idata", 0x2000, 0x600, 0x600, 0x40000040)
    section(2, b".rsrc", 0x3000, 0xC00, 0x400, 0x40000040)

    derive_iat = 0
    if include_imports:
        struct.pack_into("<IIIII", data, 0x600, 0x2100, 0, 0, 0x2200, 0x2140)
        data[0x800:0x80C] = b"bcrypt.dll\0"
        cursor = 0x820
        required = sorted(bcrypt._REQUIRED_BCRYPT_APIS | bcrypt._REQUIRED_RESOURCE_APIS)
        for index, name in enumerate(required):
            name_blob = name.encode("ascii") + b"\0"
            name_rva = 0x2000 + cursor - 0x600
            struct.pack_into("<I", data, 0x700 + index * 4, name_rva)
            struct.pack_into("<H", data, cursor, 0)
            data[cursor + 2 : cursor + 2 + len(name_blob)] = name_blob
            if name == "BCryptDeriveKeyPBKDF2":
                derive_iat = 0x400000 + 0x2140 + index * 4
            cursor += 2 + len(name_blob)
        struct.pack_into("<I", data, 0x700 + len(required) * 4, 0)
    if include_call_anchor:
        data[0x420:0x426] = b"\xff\x15" + struct.pack("<I", derive_iat)

    struct.pack_into("<IIHHHH", data, 0xC00, 0, 0, 0, 0, 0, 1)
    struct.pack_into("<II", data, 0xC10, 10, 0x80000020)
    struct.pack_into("<IIHHHH", data, 0xC20, 0, 0, 0, 0, 0, 1)
    struct.pack_into("<II", data, 0xC30, 1, 0x80000040)
    struct.pack_into("<IIHHHH", data, 0xC40, 0, 0, 0, 0, 0, 1)
    struct.pack_into("<II", data, 0xC50, 1033, 0x60)
    resource_blob_size = (
        resource_size
        if resource_size is not None
        else (48 if include_resource_candidate else 31)
    )
    struct.pack_into("<IIII", data, 0xC60, 0x3100, resource_blob_size, 0, 0)
    data[0xD00 : 0xD00 + resource_blob_size] = bytes(range(resource_blob_size))

    if append_decoy_markers:
        decoy = b"\0".join(
            name.encode("ascii")
            for name in sorted(
                bcrypt._REQUIRED_BCRYPT_APIS | bcrypt._REQUIRED_RESOURCE_APIS
            )
        )
        data[0x1100 : 0x1100 + len(decoy)] = decoy
        data[0x1300:0x1306] = b"\xff\x15" + struct.pack("<I", 0x402140)
    return bytes(data)


def test_decrypts_pbkdf2_aes_cbc_zlib_without_execution() -> None:
    """確定済みrecipeだけでIV prefix、AES、zlibを順に復元する。"""

    recipe = _recipe()
    payload = b"\xe8\x00\x00\x00\x00" + bytes(range(256)) * 20
    recovered, transform = bcrypt._decrypt_resource(
        recipe, _encrypt_resource(recipe, payload)
    )
    assert recovered == payload
    assert transform == "zlib"


def test_wrong_secret_fails_closed() -> None:
    """paddingまたはzlibが検証できない復号結果は子artifactへ昇格しない。"""

    encrypted = _encrypt_resource(_recipe(), b"MZ" + b"payload" * 100)
    recovered, reason = bcrypt._decrypt_resource(
        _recipe(b"different-password"), encrypted
    )
    assert recovered is None
    assert reason in {"pkcs7_invalid", "zlib_invalid", "payload_type_unproven"}


def test_collects_stdcall_pushes_in_callee_argument_order() -> None:
    """PBKDF2の10引数をcall直前からcallee宣言順へ正しく並べる。"""

    code = bytes.fromhex(
        "6a00"  # flags
        "6a20"  # output length
        "8d45cc"  # output pointer
        "50"
        "6a00"  # iterations high
        "6810270000"  # iterations low
        "6a08"  # salt length
        "6800204000"  # salt pointer
        "6a13"  # password length
        "6800304000"  # password pointer
        "ff75b8"  # algorithm handle
        "ff1500104000"  # call [IAT]
    )
    engine = Cs(CS_ARCH_X86, CS_MODE_32)
    engine.detail = True
    instructions = list(engine.disasm(code, 0x401000))
    arguments = bcrypt._collect_push_arguments(instructions, len(instructions) - 1, 10)
    assert len(arguments) == 10
    assert arguments[0].kind == "memory"
    assert arguments[1].value == 0x403000
    assert arguments[2].value == 0x13
    assert arguments[3].value == 0x402000
    assert arguments[4].value == 8
    assert arguments[5].value == 10_000
    assert arguments[6].value == 0
    assert arguments[7].kind == "address_expression"
    assert arguments[8].value == 32
    assert arguments[9].value == 0


def test_register_zero_is_proven_only_on_checked_fallthrough() -> None:
    """test/jneの成功側では0を確定し、後続callでclobber後は継承しない。"""

    engine = Cs(CS_ARCH_X86, CS_MODE_32)
    engine.detail = True
    checked = list(engine.disasm(bytes.fromhex("85c075025090"), 0x401000))
    argument = bcrypt._push_argument(checked, 2)
    assert argument is not None
    assert argument.kind == "immediate"
    assert argument.value == 0

    clobbered = list(engine.disasm(bytes.fromhex("85c07507e8000000005090"), 0x401000))
    argument = bcrypt._push_argument(clobbered, 3)
    assert argument is not None
    assert argument.kind == "register"


def test_anchor_ranges_support_direct_iat_and_import_thunk() -> None:
    """全section逆アセンブルなしでdirect callとthunk callを発見する。"""

    iat = 0x405000
    section_address = 0x401000
    direct = b"\x90" * 32 + b"\xff\x15" + iat.to_bytes(4, "little")
    ranges = bcrypt._anchored_ranges(direct, section_address, (iat,))
    assert len(ranges) == 1
    assert ranges[0][0] == 0
    assert ranges[0][1] == len(direct)

    thunk_offset = 0x40
    call_offset = 0x10
    thunk_address = section_address + thunk_offset
    relative = thunk_address - (section_address + call_offset + 5)
    image = bytearray(b"\x90" * 0x80)
    image[call_offset : call_offset + 5] = b"\xe8" + relative.to_bytes(
        4, "little", signed=True
    )
    image[thunk_offset : thunk_offset + 6] = b"\xff\x25" + iat.to_bytes(4, "little")
    ranges = bcrypt._anchored_ranges(bytes(image), section_address, (iat,))
    assert len(ranges) == 1
    assert ranges[0][0] == 0
    assert ranges[0][1] == len(image)


def _import_item(name: bytes, address: int) -> SimpleNamespace:
    return SimpleNamespace(name=name, address=address)


def test_regular_import_descriptor_cap_accepts_exact_and_rejects_plus_one(
    monkeypatch,
) -> None:
    """descriptor上限ちょうどを許容し、+1は内容へ触れる前に拒否する。"""

    monkeypatch.setattr(bcrypt, "MAX_IMPORT_DESCRIPTORS", 2)
    exact = SimpleNamespace(
        DIRECTORY_ENTRY_IMPORT=[
            SimpleNamespace(imports=[]),
            SimpleNamespace(imports=[]),
        ]
    )
    assert bcrypt._import_map(exact) == {}

    class UnreadableDescriptor:
        @property
        def imports(self):
            raise AssertionError("overflow descriptor prefix must not be inspected")

    overflow = SimpleNamespace(
        DIRECTORY_ENTRY_IMPORT=[
            UnreadableDescriptor(),
            UnreadableDescriptor(),
            UnreadableDescriptor(),
        ]
    )
    with pytest.raises(bcrypt._ImportScanLimit):
        bcrypt._import_map(overflow)


def test_regular_import_thunk_cap_accepts_exact_and_discards_overflow_prefix(
    monkeypatch,
) -> None:
    """総thunk上限+1では名前prefixを読まず、import map全体を不採用にする。"""

    monkeypatch.setattr(bcrypt, "MAX_IMPORT_THUNKS", 2)
    exact = SimpleNamespace(
        DIRECTORY_ENTRY_IMPORT=[
            SimpleNamespace(
                imports=[
                    _import_item(b"LockResource", 0x401000),
                    _import_item(b"SizeofResource", 0x401004),
                ]
            )
        ]
    )
    assert bcrypt._import_map(exact) == {
        0x401000: "LockResource",
        0x401004: "SizeofResource",
    }

    name_reads = 0

    class UnreadableImport:
        @property
        def name(self):
            nonlocal name_reads
            name_reads += 1
            raise AssertionError("overflow thunk prefix must not be decoded")

    overflow = SimpleNamespace(
        DIRECTORY_ENTRY_IMPORT=[
            SimpleNamespace(imports=[UnreadableImport(), UnreadableImport()]),
            SimpleNamespace(imports=[UnreadableImport()]),
        ]
    )
    with pytest.raises(bcrypt._ImportScanLimit):
        bcrypt._import_map(overflow)
    assert name_reads == 0


def test_regular_derive_iat_cap_accepts_exact_and_rejects_plus_one(
    monkeypatch,
) -> None:
    """PBKDF2 IAT件数は上限ちょうどだけを完全inventoryとして返す。"""

    monkeypatch.setattr(bcrypt, "MAX_DERIVE_IAT_ADDRESSES", 2)
    exact_items = [
        _import_item(b"BCryptDeriveKeyPBKDF2", 0x401000 + index * 4)
        for index in range(2)
    ]
    exact = SimpleNamespace(
        DIRECTORY_ENTRY_IMPORT=[SimpleNamespace(imports=exact_items)]
    )
    assert len(bcrypt._import_map(exact)) == 2

    overflow_items = [
        _import_item(b"BCryptDeriveKeyPBKDF2", 0x402000 + index * 4)
        for index in range(3)
    ]
    overflow = SimpleNamespace(
        DIRECTORY_ENTRY_IMPORT=[SimpleNamespace(imports=overflow_items)]
    )
    with pytest.raises(bcrypt._ImportScanLimit):
        bcrypt._import_map(overflow)


def test_regular_derive_iat_product_is_rejected_before_section_scan(
    monkeypatch,
) -> None:
    """IAT上限+1ではsection×IAT探索を1回も開始しない。"""

    monkeypatch.setattr(bcrypt, "MAX_DERIVE_IAT_ADDRESSES", 1)
    section = SimpleNamespace(
        Characteristics=0x20000000,
        PointerToRawData=0,
        SizeOfRawData=1,
        VirtualAddress=0x1000,
    )
    pe = SimpleNamespace(
        OPTIONAL_HEADER=SimpleNamespace(ImageBase=0x400000),
        sections=[section],
    )
    calls = 0

    def anchored(*_args):
        nonlocal calls
        calls += 1
        return []

    monkeypatch.setattr(bcrypt, "_anchored_ranges", anchored)
    _, exact_error = bcrypt._disassemble(pe, b"\x90", (0x405000,))
    assert exact_error == "pbkdf2_call_anchor_not_found"
    assert calls == 1

    _, overflow_error = bcrypt._disassemble(pe, b"\x90", (0x405000, 0x405004))
    assert overflow_error == "import_scan_limit"
    assert calls == 1


def test_regular_import_limit_propagates_without_partial_recovery(
    monkeypatch,
) -> None:
    """通常解析のimport上限超過は公開statusへ伝播し後段処理を開始しない。"""

    monkeypatch.setattr(bcrypt, "MAX_IMPORT_THUNKS", 1)
    fake_pe = SimpleNamespace(
        FILE_HEADER=SimpleNamespace(Machine=0x14C),
        OPTIONAL_HEADER=SimpleNamespace(Magic=0x10B, ImageBase=0x400000),
        DIRECTORY_ENTRY_IMPORT=[
            SimpleNamespace(
                imports=[
                    _import_item(b"BCryptDeriveKeyPBKDF2", 0x401000),
                    _import_item(b"LockResource", 0x401004),
                ]
            )
        ],
        sections=[],
    )
    monkeypatch.setattr(bcrypt.pefile, "PE", lambda **_kwargs: fake_pe)

    def disassembly_must_not_start(*_args):
        raise AssertionError("partial import prefix must not reach disassembly")

    monkeypatch.setattr(bcrypt, "_disassemble", disassembly_must_not_start)
    report, artifacts = bcrypt.recover_bcrypt_resource(b"MZsynthetic")

    assert report["status"] == "import_scan_limit"
    assert report["candidate"] is False
    assert report["candidate_set_complete"] is False
    assert report["recovery_attempts_complete"] is False
    assert report["recovered_artifact_set_complete"] is False
    assert report["recipe_analysis"] == {
        "status": "import_scan_limit",
        "candidate_set_complete": False,
    }
    assert artifacts == []


def test_bounded_zlib_rejects_trailing_and_excessive_ratio() -> None:
    """有効prefixでもtrailing dataとzip bomb相当の比率を拒否する。"""

    recovered, reason = bcrypt._bounded_zlib(zlib.compress(b"small") + b"tail")
    assert recovered is None
    assert reason == "zlib_incomplete_or_trailing"

    recovered, reason = bcrypt._bounded_zlib(zlib.compress(b"A" * 1024 * 1024))
    assert recovered is None
    assert reason == "compression_ratio_limit"


def test_bounded_zlib_uses_ratio_cap_as_actual_decompress_limit(monkeypatch) -> None:
    """比率上限+1だけをdecoderへ渡し、巨大出力を割り当てる前に拒否する。"""

    requested: list[int] = []

    class Decoder:
        eof = False
        unused_data = b""
        unconsumed_tail = b"remaining"

        def decompress(self, _blob: bytes, max_length: int) -> bytes:
            requested.append(max_length)
            return b"A" * max_length

    monkeypatch.setattr(bcrypt, "MAX_COMPRESSION_RATIO", 3.0)
    monkeypatch.setattr(bcrypt.zlib, "decompressobj", Decoder)
    recovered, reason = bcrypt._bounded_zlib(b"\x78" + b"x" * 9)

    assert recovered is None
    assert reason == "compression_ratio_limit"
    assert requested == [31]


def test_bounded_zlib_accepts_output_exactly_at_ratio_limit(monkeypatch) -> None:
    """EOFまで完全な出力は比率上限ちょうどなら許容する。"""

    payload = b"exact-static-output" * 16
    compressed = zlib.compress(payload)
    monkeypatch.setattr(
        bcrypt,
        "MAX_COMPRESSION_RATIO",
        (len(payload) + 0.5) / len(compressed),
    )

    recovered, reason = bcrypt._bounded_zlib(compressed)

    assert recovered == payload
    assert reason == "zlib"


def test_public_report_never_contains_password_salt_or_key(
    monkeypatch,
) -> None:
    """内部recipeの秘密バイト列をJSON reportへ投影しない。"""

    secret = b"never-publish-this-password"
    salt = b"private-salt"
    recipe = bcrypt.BcryptRecipe(
        password=secret,
        salt=salt,
        iterations=10_000,
        key_size=32,
        decrypt_flags=0,
        call_addresses=_recipe().call_addresses,
        layout=_recipe().layout,
    )
    payload = b"\xe8" + b"static-child" * 100
    resource = _encrypt_resource(recipe, payload)
    fake_pe = SimpleNamespace(
        FILE_HEADER=SimpleNamespace(Machine=0x14C),
        OPTIONAL_HEADER=SimpleNamespace(Magic=0x10B, ImageBase=0x400000),
        sections=[],
    )
    monkeypatch.setattr(bcrypt.pefile, "PE", lambda **_kwargs: fake_pe)
    monkeypatch.setattr(
        bcrypt,
        "_import_map",
        lambda *_args: {
            index: name
            for index, name in enumerate(
                sorted(bcrypt._REQUIRED_BCRYPT_APIS | bcrypt._REQUIRED_RESOURCE_APIS)
            )
        },
    )
    monkeypatch.setattr(bcrypt, "_disassemble", lambda *_args: ([], None))
    monkeypatch.setattr(
        bcrypt,
        "_recover_recipes",
        lambda *_args: ([recipe], {"status": "recipe_recovered"}),
    )
    monkeypatch.setattr(
        bcrypt,
        "_resource_candidates",
        lambda *_args: (
            [bcrypt.ResourceCandidate(0, resource)],
            {"status": "candidates_recovered", "candidate_count": 1},
        ),
    )
    report, artifacts = bcrypt.recover_bcrypt_resource(b"MZsynthetic")
    serialized = json.dumps(report, sort_keys=True)
    assert report["status"] == "artifacts_recovered"
    assert artifacts == [("bcrypt-resource-zlib", payload)]
    assert secret.decode() not in serialized
    assert salt.decode() not in serialized
    assert report["raw_secrets_included"] is False
    assert report["terminal_promotion_eligible"] is False


def _derive_calls(count: int) -> list[bcrypt.CallEvidence]:
    return [
        bcrypt.CallEvidence(
            name="BCryptDeriveKeyPBKDF2",
            index=index,
            address=0x401000 + index,
            arguments=(),
        )
        for index in range(count)
    ]


def _mock_recipe_dependencies(
    monkeypatch,
    calls: list[bcrypt.CallEvidence],
) -> None:
    monkeypatch.setattr(
        bcrypt,
        "_import_map",
        lambda _pe: {
            index: name
            for index, name in enumerate(
                sorted(bcrypt._REQUIRED_BCRYPT_APIS | bcrypt._REQUIRED_RESOURCE_APIS)
            )
        },
    )
    monkeypatch.setattr(bcrypt, "_call_evidence", lambda *_args: calls)


def _mock_complete_recovery(
    monkeypatch,
    recipes: list[bcrypt.BcryptRecipe],
    resources: list[bcrypt.ResourceCandidate],
) -> None:
    """復号試行上限だけを検証するため、前段の静的証跡を確定済みにする。"""

    fake_pe = SimpleNamespace(
        FILE_HEADER=SimpleNamespace(Machine=0x14C),
        OPTIONAL_HEADER=SimpleNamespace(Magic=0x10B, ImageBase=0x400000),
        sections=[],
    )
    monkeypatch.setattr(bcrypt.pefile, "PE", lambda **_kwargs: fake_pe)
    monkeypatch.setattr(
        bcrypt,
        "_import_map",
        lambda *_args: {
            index: name
            for index, name in enumerate(
                sorted(bcrypt._REQUIRED_BCRYPT_APIS | bcrypt._REQUIRED_RESOURCE_APIS)
            )
        },
    )
    monkeypatch.setattr(bcrypt, "_disassemble", lambda *_args: ([], None))
    monkeypatch.setattr(
        bcrypt,
        "_recover_recipes",
        lambda *_args: (
            recipes,
            {
                "status": "recipe_recovered",
                "candidate_set_complete": True,
            },
        ),
    )
    monkeypatch.setattr(
        bcrypt,
        "_resource_candidates",
        lambda *_args: (
            resources,
            {
                "status": "candidates_recovered",
                "candidate_count": len(resources),
                "inventory_complete": True,
            },
        ),
    )


def test_recipe_cap_accepts_exact_complete_candidate_set(
    monkeypatch,
) -> None:
    """PBKDF2 callが上限ちょうどなら全件を評価して完全性を保持する。"""

    calls = _derive_calls(bcrypt.MAX_RECIPES)
    _mock_recipe_dependencies(monkeypatch, calls)
    monkeypatch.setattr(
        bcrypt,
        "_recipe_from_derive",
        lambda _pe, _data, _instructions, _calls, derive: _recipe(
            f"recipe-{derive.index}".encode()
        ),
    )

    recipes, report = bcrypt._recover_recipes(object(), b"", [])

    assert len(recipes) == bcrypt.MAX_RECIPES
    assert report["recipe_scan_truncated"] is False
    assert report["candidate_set_complete"] is True


def test_recipe_overflow_is_order_independent_and_never_evaluates_prefix(
    monkeypatch,
) -> None:
    """隠れた有効候補の位置を変えても不完全集合からrecipeを選ばない。"""

    calls = _derive_calls(bcrypt.MAX_RECIPES + 1)
    evaluated: list[int] = []

    def decode(*args):
        derive = args[-1]
        evaluated.append(derive.index)
        return _recipe(b"hidden-valid") if derive.index == bcrypt.MAX_RECIPES else None

    monkeypatch.setattr(bcrypt, "_recipe_from_derive", decode)
    for ordered in (calls, [calls[-1], *calls[:-1]]):
        _mock_recipe_dependencies(monkeypatch, ordered)
        recipes, report = bcrypt._recover_recipes(object(), b"", [])
        assert recipes == []
        assert report["status"] == "recipe_scan_limit"
        assert report["recipe_scan_truncated"] is True
        assert report["candidate_set_complete"] is False
    assert evaluated == []


def test_truncated_recipe_report_never_reaches_resource_decryption(
    monkeypatch,
) -> None:
    """内部契約が破られてrecipeが併記されても後段artifactへ昇格しない。"""

    fake_pe = SimpleNamespace(
        FILE_HEADER=SimpleNamespace(Machine=0x14C),
        OPTIONAL_HEADER=SimpleNamespace(Magic=0x10B, ImageBase=0x400000),
        sections=[],
    )
    monkeypatch.setattr(bcrypt.pefile, "PE", lambda **_kwargs: fake_pe)
    monkeypatch.setattr(
        bcrypt,
        "_import_map",
        lambda *_args: {
            index: name
            for index, name in enumerate(
                sorted(bcrypt._REQUIRED_BCRYPT_APIS | bcrypt._REQUIRED_RESOURCE_APIS)
            )
        },
    )
    monkeypatch.setattr(bcrypt, "_disassemble", lambda *_args: ([], None))
    monkeypatch.setattr(
        bcrypt,
        "_recover_recipes",
        lambda *_args: (
            [_recipe()],
            {
                "status": "recipe_scan_limit",
                "recipe_scan_truncated": True,
                "candidate_set_complete": False,
            },
        ),
    )

    def resources_must_not_be_read(*_args):
        raise AssertionError("不完全recipe集合ではresourceを読んではならない")

    monkeypatch.setattr(bcrypt, "_resource_candidates", resources_must_not_be_read)

    report, artifacts = bcrypt.recover_bcrypt_resource(b"MZsynthetic")

    assert report["status"] == "recipe_scan_limit"
    assert report["candidate"] is True
    assert artifacts == []


def test_decrypt_attempt_limit_rejects_product_before_decryption(monkeypatch) -> None:
    """recipe×resourceが上限超過なら先頭候補も復号しない。"""

    recipes = [_recipe(b"recipe-a"), _recipe(b"recipe-b")]
    resources = [
        bcrypt.ResourceCandidate(0, b"resource-a"),
        bcrypt.ResourceCandidate(1, b"resource-b"),
    ]
    _mock_complete_recovery(monkeypatch, recipes, resources)
    monkeypatch.setattr(bcrypt, "MAX_DECRYPT_ATTEMPTS", 3)

    def decryption_must_not_start(*_args):
        raise AssertionError("candidate product must be bounded before decryption")

    monkeypatch.setattr(bcrypt, "_decrypt_resource", decryption_must_not_start)
    report, artifacts = bcrypt.recover_bcrypt_resource(b"MZsynthetic")

    assert report["status"] == "decrypt_attempt_limit"
    assert report["candidate_attempt_count"] == 4
    assert report["attempt_count"] == 0
    assert report["candidate_set_complete"] is False
    assert report["recovery_attempts_complete"] is False
    assert report["recovered_artifact_set_complete"] is False
    assert artifacts == []


def test_incomplete_resource_inventory_never_decrypts_returned_prefix(
    monkeypatch,
) -> None:
    """内部契約違反で候補prefixが返っても不完全inventoryを採用しない。"""

    resource = bcrypt.ResourceCandidate(0, b"resource-prefix")
    _mock_complete_recovery(monkeypatch, [_recipe()], [resource])
    monkeypatch.setattr(
        bcrypt,
        "_resource_candidates",
        lambda *_args: (
            [resource],
            {
                "status": "resource_limits_exceeded",
                "inventory_complete": False,
            },
        ),
    )

    def decryption_must_not_start(*_args):
        raise AssertionError("incomplete resource inventory must not be decrypted")

    monkeypatch.setattr(bcrypt, "_decrypt_resource", decryption_must_not_start)
    report, artifacts = bcrypt.recover_bcrypt_resource(b"MZsynthetic")

    assert report["status"] == "resource_limits_exceeded"
    assert report["candidate_set_complete"] is False
    assert report["recovery_attempts_complete"] is False
    assert report["recovered_artifact_set_complete"] is False
    assert artifacts == []


def test_decrypt_attempt_limit_accepts_exact_complete_product(monkeypatch) -> None:
    """候補直積が上限ちょうどなら全組合せを評価する。"""

    recipes = [_recipe(b"recipe-a"), _recipe(b"recipe-b")]
    resources = [
        bcrypt.ResourceCandidate(0, b"resource-a"),
        bcrypt.ResourceCandidate(1, b"resource-b"),
    ]
    _mock_complete_recovery(monkeypatch, recipes, resources)
    monkeypatch.setattr(bcrypt, "MAX_DECRYPT_ATTEMPTS", 4)
    attempted: list[bytes] = []

    def reject(_recipe, resource: bytes, _key):
        attempted.append(resource)
        return None, "synthetic_rejection"

    monkeypatch.setattr(bcrypt, "_decrypt_resource", reject)
    report, artifacts = bcrypt.recover_bcrypt_resource(b"MZsynthetic")

    assert report["status"] == "profile_matched_recovery_failed"
    assert report["candidate_attempt_count"] == 4
    assert report["attempt_count"] == 4
    assert report["candidate_set_complete"] is True
    assert report["recovery_attempts_complete"] is True
    assert report["recovered_artifact_set_complete"] is True
    assert len(attempted) == 4
    assert artifacts == []


def test_recovered_artifact_count_limit_discards_prefix_results(monkeypatch) -> None:
    """unique artifact件数超過時は先頭で得た成果も公開しない。"""

    resources = [
        bcrypt.ResourceCandidate(0, b"resource-a"),
        bcrypt.ResourceCandidate(1, b"resource-b"),
    ]
    _mock_complete_recovery(monkeypatch, [_recipe()], resources)
    monkeypatch.setattr(bcrypt, "MAX_RECOVERED_ARTIFACTS", 1)
    monkeypatch.setattr(
        bcrypt,
        "_decrypt_resource",
        lambda _recipe, resource, _key: (b"decoded-" + resource, "zlib"),
    )

    report, artifacts = bcrypt.recover_bcrypt_resource(b"MZsynthetic")

    assert report["status"] == "recovered_artifact_count_limit"
    assert report["attempt_count"] == 2
    assert report["candidate_set_complete"] is False
    assert report["recovered_artifact_set_complete"] is False
    assert report["recovered_artifact_count"] == 0
    assert artifacts == []
    assert "decoded" not in json.dumps(report, sort_keys=True)


def test_recovered_artifact_total_size_limit_discards_prefix_results(
    monkeypatch,
) -> None:
    """unique artifactの合計byte超過時も部分的な先頭集合を返さない。"""

    resources = [
        bcrypt.ResourceCandidate(0, b"resource-a"),
        bcrypt.ResourceCandidate(1, b"resource-b"),
    ]
    _mock_complete_recovery(monkeypatch, [_recipe()], resources)
    monkeypatch.setattr(bcrypt, "MAX_RECOVERED_ARTIFACT_BYTES", 3)
    monkeypatch.setattr(
        bcrypt,
        "_decrypt_resource",
        lambda _recipe, resource, _key: (resource[-1:] * 2, "direct_pe"),
    )

    report, artifacts = bcrypt.recover_bcrypt_resource(b"MZsynthetic")

    assert report["status"] == "recovered_artifact_total_size_limit"
    assert report["attempt_count"] == 2
    assert report["candidate_set_complete"] is False
    assert report["recovery_attempts_complete"] is False
    assert report["recovered_artifact_set_complete"] is False
    assert report["recovered_artifact_total_size"] == 0
    assert artifacts == []


def test_large_matching_input_keeps_size_limit_fail_closed(monkeypatch) -> None:
    """必要な3 anchorが揃う大容量PEだけをsize limitとして残す。"""

    called = False

    def fail_if_called(**_kwargs):
        nonlocal called
        called = True
        raise AssertionError("PE parser must not be called")

    monkeypatch.setattr(bcrypt.pefile, "PE", fail_if_called)
    monkeypatch.setattr(bcrypt, "MAX_INPUT_SIZE", 0x1000)
    report, artifacts = bcrypt.recover_bcrypt_resource(_preflight_pe())
    assert report["status"] == "input_size_limit"
    assert report["candidate"] is True
    assert report["large_input_preflight"] == {
        "status": "candidate",
        "reason": "required_anchors_present",
        "required_imports_present": True,
        "resource_candidate_present": True,
        "pbkdf2_call_anchor_present": True,
        "executable_bytes_examined": 0x200,
        "whole_input_copied": False,
        "sample_executed": False,
    }
    assert artifacts == []
    assert called is False


def test_large_decoy_markers_without_imports_are_not_candidates(monkeypatch) -> None:
    """API文字列とcall風byteだけでは大容量routeを候補へ昇格しない。"""

    def fail_if_called(**_kwargs):
        raise AssertionError("large-input preflight must not invoke pefile")

    monkeypatch.setattr(bcrypt.pefile, "PE", fail_if_called)
    monkeypatch.setattr(bcrypt, "MAX_INPUT_SIZE", 0x1000)
    report, artifacts = bcrypt.recover_bcrypt_resource(
        _preflight_pe(include_imports=False, append_decoy_markers=True)
    )
    assert report["status"] == "profile_not_matched"
    assert report["candidate"] is False
    assert report["large_input_preflight"]["status"] == "not_candidate"
    assert report["large_input_preflight"]["reason"] == "import_directory_missing"
    assert artifacts == []


def test_large_input_requires_resource_and_call_anchors(monkeypatch) -> None:
    """importだけが一致してもresourceとcodeの各構造anchorを必須にする。"""

    def fail_if_called(**_kwargs):
        raise AssertionError("large-input preflight must not invoke pefile")

    monkeypatch.setattr(bcrypt.pefile, "PE", fail_if_called)
    monkeypatch.setattr(bcrypt, "MAX_INPUT_SIZE", 0x1000)
    no_resource, artifacts = bcrypt.recover_bcrypt_resource(
        _preflight_pe(include_resource_candidate=False)
    )
    assert no_resource["status"] == "profile_not_matched"
    assert no_resource["large_input_preflight"]["reason"] == (
        "resource_candidate_missing"
    )
    assert artifacts == []

    no_call, artifacts = bcrypt.recover_bcrypt_resource(
        _preflight_pe(include_call_anchor=False)
    )
    assert no_call["status"] == "profile_not_matched"
    assert no_call["large_input_preflight"]["reason"] == ("pbkdf2_call_anchor_missing")
    assert artifacts == []


def test_large_input_resource_candidate_accepts_minimum_iv_and_ciphertext() -> None:
    """IV 16 byteとciphertext 1 blockの最小32 byteを候補として許容する。"""

    accepted = bcrypt._large_input_preflight(_preflight_pe(resource_size=32))
    assert accepted.status == "candidate"
    assert accepted.reason == "required_anchors_present"
    assert accepted.resource_candidate_present is True

    rejected = bcrypt._large_input_preflight(_preflight_pe(resource_size=31))
    assert rejected.status == "not_candidate"
    assert rejected.reason == "resource_candidate_missing"
    assert rejected.resource_candidate_present is False


def test_regular_resource_candidate_accepts_minimum_iv_and_ciphertext(
    monkeypatch,
) -> None:
    """本列挙もpreflightと同じく最小32 byteを候補として保持する。"""

    structure = SimpleNamespace(Size=32, OffsetToData=0x3000)
    root = SimpleNamespace(
        entries=[
            SimpleNamespace(
                directory=None,
                data=SimpleNamespace(struct=structure),
            )
        ]
    )
    pe = SimpleNamespace(
        DIRECTORY_ENTRY_RESOURCE=root,
        OPTIONAL_HEADER=SimpleNamespace(ImageBase=0x400000),
    )
    monkeypatch.setattr(
        bcrypt,
        "_mapped_slice",
        lambda _pe, _data, _address, size: bytes(range(size)),
    )
    monkeypatch.setattr(bcrypt, "_entropy", lambda _data: 8.0)

    candidates, report = bcrypt._resource_candidates(pe, b"MZ")

    assert len(candidates) == 1
    assert len(candidates[0].blob) == 32
    assert report["status"] == "candidates_recovered"
    assert report["inventory_complete"] is True


def test_input_size_boundary_uses_full_parser(monkeypatch) -> None:
    """上限ちょうどはlarge-input preflightへ送らず通常解析する。"""

    called = False
    fake_pe = SimpleNamespace(
        FILE_HEADER=SimpleNamespace(Machine=0x8664),
        OPTIONAL_HEADER=SimpleNamespace(Magic=0x20B),
    )

    def parse(**_kwargs):
        nonlocal called
        called = True
        return fake_pe

    monkeypatch.setattr(bcrypt, "MAX_INPUT_SIZE", 0x1000)
    monkeypatch.setattr(bcrypt.pefile, "PE", parse)
    report, artifacts = bcrypt.recover_bcrypt_resource(_preflight_pe()[:0x1000])
    assert report["status"] == "profile_not_matched"
    assert artifacts == []
    assert called is True


def test_large_input_executable_scan_boundary_is_indeterminate(monkeypatch) -> None:
    """call anchorより前でscan予算が尽きた場合は非候補と断定しない。"""

    def fail_if_called(**_kwargs):
        raise AssertionError("large-input preflight must not invoke pefile")

    monkeypatch.setattr(bcrypt.pefile, "PE", fail_if_called)
    monkeypatch.setattr(bcrypt, "MAX_INPUT_SIZE", 0x1000)
    monkeypatch.setattr(bcrypt, "MAX_EXECUTABLE_BYTES", 0x20)
    report, artifacts = bcrypt.recover_bcrypt_resource(_preflight_pe())
    assert report["status"] == "large_input_preflight_limit"
    assert report["candidate"] is False
    assert report["large_input_preflight"]["status"] == "indeterminate"
    assert report["large_input_preflight"]["reason"] == "executable_scan_limit"
    assert report["large_input_preflight"]["executable_bytes_examined"] == 0x20
    assert artifacts == []


def test_regular_disassembly_rejects_section_count_before_raw_scan(monkeypatch) -> None:
    """多数sectionはraw byte探索を始める前にfail-closedにする。"""

    sections = [
        SimpleNamespace(
            Characteristics=0x20000000,
            PointerToRawData=index,
            SizeOfRawData=1,
            VirtualAddress=0x1000 + index,
        )
        for index in range(3)
    ]
    pe = SimpleNamespace(
        OPTIONAL_HEADER=SimpleNamespace(ImageBase=0x400000),
        sections=sections,
    )
    monkeypatch.setattr(bcrypt, "MAX_EXECUTABLE_SECTIONS", 2)

    def raw_scan_must_not_start(*_args):
        raise AssertionError("section count must be bounded before raw scanning")

    monkeypatch.setattr(bcrypt, "_anchored_ranges", raw_scan_must_not_start)
    instructions, reason = bcrypt._disassemble(pe, b"\x90" * 8, ())

    assert instructions == []
    assert reason == "executable_scan_limit"


def test_regular_disassembly_counts_duplicate_raw_sections_before_scan(
    monkeypatch,
) -> None:
    """同じraw rangeの重複sectionも累計予算へ算入し、再走査を防ぐ。"""

    duplicate = SimpleNamespace(
        Characteristics=0x20000000,
        PointerToRawData=0,
        SizeOfRawData=0x20,
        VirtualAddress=0x1000,
    )
    pe = SimpleNamespace(
        OPTIONAL_HEADER=SimpleNamespace(ImageBase=0x400000),
        sections=[duplicate, duplicate],
    )
    monkeypatch.setattr(bcrypt, "MAX_EXECUTABLE_SCAN_BYTES", 0x20)

    def raw_scan_must_not_start(*_args):
        raise AssertionError("raw byte total must be bounded before scanning")

    monkeypatch.setattr(bcrypt, "_anchored_ranges", raw_scan_must_not_start)
    instructions, reason = bcrypt._disassemble(pe, b"\x90" * 0x40, ())

    assert instructions == []
    assert reason == "executable_scan_limit"


def test_non_x86_pe_is_not_a_candidate(monkeypatch) -> None:
    """x64など未実装ABIを曖昧に処理せず対象外にする。"""

    fake_pe = SimpleNamespace(
        FILE_HEADER=SimpleNamespace(Machine=0x8664),
        OPTIONAL_HEADER=SimpleNamespace(Magic=0x20B, ImageBase=0x140000000),
    )
    monkeypatch.setattr(bcrypt.pefile, "PE", lambda **_kwargs: fake_pe)
    report, artifacts = bcrypt.recover_bcrypt_resource(b"MZsynthetic")
    assert report["status"] == "profile_not_matched"
    assert report["candidate"] is False
    assert artifacts == []
