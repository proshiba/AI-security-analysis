"""Remcos base52多段配送層の安全境界を合成fixtureで検証する。"""

from __future__ import annotations

import base64
import gzip
import struct

import pytest
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from unpackers import remcos_base52_chain as chain


def _minimal_pe() -> bytes:
    image = bytearray(0x400)
    image[:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, 0x80)
    image[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", image, 0x84, 0x14C, 1, 0, 0, 0, 0xE0, 0x210E)
    optional = 0x98
    struct.pack_into("<H", image, optional, 0x10B)
    struct.pack_into("<I", image, optional + 0x10, 0x1000)
    struct.pack_into("<I", image, optional + 0x14, 0x1000)
    struct.pack_into("<I", image, optional + 0x1C, 0x400000)
    struct.pack_into("<I", image, optional + 0x20, 0x1000)
    struct.pack_into("<I", image, optional + 0x24, 0x200)
    struct.pack_into("<I", image, optional + 0x38, 0x2000)
    struct.pack_into("<I", image, optional + 0x3C, 0x200)
    struct.pack_into("<H", image, optional + 0x44, 3)
    struct.pack_into("<I", image, optional + 0x5C, 16)
    section = optional + 0xE0
    image[section : section + 8] = b".text\0\0\0"
    struct.pack_into("<IIII", image, section + 8, 0x20, 0x1000, 0x200, 0x200)
    struct.pack_into("<I", image, section + 36, 0x60000020)
    image[0x200:0x210] = b"SYNTHETIC-REMCO!"
    return bytes(image)


def _rol8(value: int, count: int) -> int:
    return ((value << count) | (value >> (8 - count))) & 0xFF


def _outer_encrypt(clear: bytes, key: bytes) -> bytes:
    data = bytearray(len(clear).to_bytes(4, "big") + clear)
    seed = 17
    for current in key:
        seed = (seed * 33 + current) % chain.MBIG
    seed = max(seed, 1)
    sbox = list(range(256))
    state_value = seed
    for position in range(255, 0, -1):
        state_value = (state_value * 48271) % chain.MBIG
        target = state_value % (position + 1)
        sbox[position], sbox[target] = sbox[target], sbox[position]
    data = bytearray(sbox[current] for current in data)
    for position, current in enumerate(data):
        rotation = (key[(position + 11) & 15] & 3) + 2
        current = (current + key[position & 15] + ((position * 23) & 0xFF)) & 0xFF
        current = _rol8(current, rotation)
        data[position] = current ^ key[(position + 5) & 15] ^ ((position * 17) & 0xFF)

    state = list(range(256))
    target = 0
    for position in range(256):
        target = (target + state[position] + key[position & 15]) & 0xFF
        state[position], state[target] = state[target], state[position]
    i = 0
    j = 0
    for position in range(len(data)):
        i = (i + 1) & 0xFF
        j = (j + state[i]) & 0xFF
        state[i], state[j] = state[j], state[i]
        data[position] ^= state[(state[i] + state[j] + position) & 0xFF]

    output = bytearray(len(data))
    previous = key[0]
    for position, current in enumerate(data):
        mask = key[(position + 3) & 15] ^ ((position * 11) & 0xFF) ^ previous
        cipher = current ^ mask
        output[position] = cipher
        previous = (
            previous * 43 + cipher + key[(position + 7) & 15] + (position & 0xFF)
        ) & 0xFF
    return bytes(output)


def _encode_base52_nine(value: bytes, alphabet: str) -> str:
    assert len(value) % 6 == 0
    output = []
    for offset in range(0, len(value), 6):
        accumulator = int.from_bytes(value[offset : offset + 6], "big")
        chars = [alphabet[0]] * 9
        for index in range(8, -1, -1):
            accumulator, digit = divmod(accumulator, 52)
            chars[index] = alphabet[digit]
        assert accumulator == 0
        output.extend(chars)
    return "".join(output)


def _powershell_script() -> bytes:
    clear = (
        b"$x=[Convert]::FromBase64String('QUFBQQ==')\n"
        b"$g='GZipStream'\n[byte[]]$a=@(1,2,3)\n"
    )
    while (len(clear) + 4) % 6:
        clear += b" "
    return clear


def _javascript_fixture(clear: bytes, *, declared_delta: int = 0) -> bytes:
    alphabet = "qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM"
    key = bytes(range(1, 17))
    if declared_delta:
        value = bytearray(_outer_encrypt(clear, key))
        restored = bytearray(chain._outer_decrypt(bytes(value), key) or b"")
        assert restored == clear
        # 宣言長異常fixtureは平文headerから同じ逆変換をやり直す。
        original = len(clear).to_bytes(4, "big") + clear
        wrong = (len(clear) + declared_delta).to_bytes(4, "big") + original[4:]
        value = bytearray(_outer_encrypt(wrong[4:], key))
        # _outer_encrypt自身が正しいheaderを付けるため、最後に別helperを使う代わりに
        # encoded文字を1文字破損し、厳格な宣言長／UTF-8検証で拒否させる。
        value[0] ^= 1
        encrypted = bytes(value)
    else:
        encrypted = _outer_encrypt(clear, key)
    encoded = _encode_base52_nine(encrypted, alphabet)
    chunks = ",\n// bounded fixture\n".join(
        f'"{encoded[offset : offset + 90]}"' for offset in range(0, len(encoded), 90)
    )
    return f"""
function shape(i,key){{var seed=17;seed=(seed*33+key[i])%2147483647;
seed=(seed*48271)%2147483647;var x=((i*43)+1);var a=(i*11);var b=(i*17);var c=(i*23);
var d=i>>>2;var e=i<<2;return 16777216+65536+x+a+b+c+d+e;}}
var alphabet="{alphabet}";
var keyMaterial=[{",".join(map(str, key))}];
var carrier=[{chunks}].join("");
""".encode()


def _shield_encrypt(clear: bytes, key: bytes, vector: bytes) -> bytes:
    data = bytearray(gzip.compress(clear, mtime=0))
    seed = 17
    for current in key:
        seed = (seed * 37 + current) % chain.MBIG
    for current in vector:
        seed = (seed * 41 + current) % chain.MBIG
    random = chain.DotNetFrameworkRandom(seed)
    sbox = list(range(256))
    for index in range(255, 0, -1):
        target = random.next(index + 1)
        sbox[index], sbox[target] = sbox[target], sbox[index]
    data = bytearray(sbox[current] for current in data)

    for round_number in (0, 1):
        for index in range(0, len(data) - 1, 2):
            left = data[index]
            right = data[index + 1]
            left ^= (right * 47 + key[(index + round_number * 7) & 31] + 11) & 0xFF
            right ^= (left * 83 + key[(index + 1 + round_number * 13) & 31] + 19) & 0xFF
            data[index] = left
            data[index + 1] = right

    for index, current in enumerate(data):
        rotation = (key[(index + 11) & 31] % 5) + 2
        current = (current + key[index & 31] + (((index & 0xFF) * 23) & 0xFF)) & 0xFF
        current = _rol8(current, rotation)
        data[index] = current ^ vector[index & 15] ^ (((index & 0xFF) * 19) & 0xFF)

    state = list(range(256))
    target = 0
    for index in range(256):
        target = (target + state[index] + key[index & 31] + vector[index & 15]) & 0xFF
        state[index], state[target] = state[target], state[index]
    x = 0
    y = 0
    for index in range(len(data)):
        x = (x + 1) & 0xFF
        y = (y + state[x]) & 0xFF
        state[x], state[y] = state[y], state[x]
        data[index] ^= state[(state[x] + state[y] + x) & 0xFF]

    output = bytearray(len(data))
    chain_state = vector[0]
    for index, current in enumerate(data):
        mask = (
            vector[(index + 7) & 15]
            ^ key[(index + 5) & 31]
            ^ (((index & 0xFF) * 13) & 0xFF)
            ^ chain_state
        )
        cipher = current ^ mask
        output[index] = cipher
        chain_state = (
            chain_state * 43 + cipher + key[(index + 17) & 31] + (index & 0xFF)
        ) & 0xFF
    return bytes(output)


def _encode_base52_stream(value: bytes) -> str:
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    widths = {1: 2, 2: 3, 3: 5, 4: 6, 5: 8, 6: 9, 7: 10}
    output = []
    for offset in range(0, len(value), 7):
        chunk = value[offset : offset + 7]
        accumulator = int.from_bytes(chunk, "big")
        chars = [alphabet[0]] * widths[len(chunk)]
        for index in range(len(chars) - 1, -1, -1):
            accumulator, digit = divmod(accumulator, 52)
            chars[index] = alphabet[digit]
        assert accumulator == 0
        output.extend(chars)
    return "".join(output)


def _stage2_fixture(payload: bytes, *, extra_part: str | None = None) -> bytes:
    part_key = bytes(range(32))
    part_vector = bytes(range(16))
    encoded_part = _encode_base52_stream(
        _shield_encrypt(payload, part_key, part_vector)
    )
    payload_literal = (
        encoded_part if extra_part is None else f"{encoded_part}|||{extra_part}"
    )
    template = f"""
function Decode-Base52Stream {{}}
function Restore-ShieldedStream {{
$x=($x*43)+1;$a=$i*13;$b=$i*19;$c=$i*23;$d=$x*83;$e=$x*47
$s=($s*37+$x)%2147483647;$s=($s*41+$x)%2147483647
$gz='GZipStream'
}}
[byte[]]$payloadKey={",".join(f"0x{value:02X}" for value in part_key)}
[byte[]]$payloadVector={",".join(f"0x{value:02X}" for value in part_vector)}
$payload='__PLD__'
""".encode()
    padding = 16 - len(template) % 16
    padded = template + bytes([padding]) * padding
    aes_key = bytes(range(32, 64))
    transform_key = bytes(range(64, 96))
    transform_vector = bytes(range(96, 112))
    encryptor = Cipher(algorithms.AES(aes_key), modes.ECB()).encryptor()
    transformed = encryptor.update(padded) + encryptor.finalize()
    stored = bytearray(len(transformed))
    for position, current in enumerate(transformed):
        current ^= transform_key[position & 31]
        current ^= transform_key[(position + 17) & 31]
        rotation = (transform_key[(position + 7) & 31] % 7) + 1
        current = _rol8(current, rotation)
        stored[position] = current ^ transform_vector[position & 15]
    return f"""
$cipher=[Convert]::FromBa`se64String('{base64.b64encode(stored).decode()}')
$aes=[Convert]::FromBa`se64String('{base64.b64encode(aes_key).decode()}')
$transform='{transform_key.hex()}'
$vector='{transform_vector.hex()}'
for($i=0;$i -lt $cipher.Length;$i++){{$cipher[$i]=$cipher[$i] -bxor $v[$i -band 15];$r=($k[($i+7) -band 31]%7)+1}}
$provider=New-Object ('System.Security.Cryptography.A'+'esCryptoServiceProvider')
$provider.Mode=[System.Security.Cryptography.CipherMode]::ECB
$provider.Padding=[System.Security.Cryptography.PaddingMode]::PKCS7
$clear=$provider.CreateDecryptor().TransformFinalBlock($cipher,0,$cipher.Length)
$payload='{payload_literal}'
$template='__PLD__'
""".encode()


def test_javascript_base52_recovers_renamed_powershell() -> None:
    expected = _powershell_script()
    recovery = chain.recover_remcos_javascript_base52(_javascript_fixture(expected))

    assert recovery.script == expected
    assert recovery.report["status"] == "powershell_recovered"
    assert recovery.report["raw_key_published"] is False


def test_javascript_base52_accepts_reviewed_shape_above_legacy_four_mib() -> None:
    """4 MiB超の既知shapeも、16 MiBの有界入口内なら静的復元する。"""

    expected = _powershell_script()
    fixture = _javascript_fixture(expected)
    fixture += b" " * (4 * 1024 * 1024 + 1 - len(fixture))

    recovery = chain.recover_remcos_javascript_base52(fixture)

    assert recovery.script == expected
    assert recovery.report["status"] == "powershell_recovered"


def test_javascript_base52_precharges_candidate_product_before_decode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _javascript_fixture(_powershell_script())
    monkeypatch.setattr(chain, "MAXIMUM_CANDIDATE_ATTEMPTS", 0)
    monkeypatch.setattr(
        chain,
        "_decode_base52_nine",
        lambda *_args: pytest.fail("candidate積の上限判定後にdecodeしてはならない"),
    )

    recovery = chain.recover_remcos_javascript_base52(fixture)

    assert recovery.script is None
    assert recovery.report["status"] == "candidate_attempt_limit_exceeded"
    assert recovery.report["planned_decode_attempt_count"] == 1
    assert recovery.report["planned_transform_attempt_count"] == 1
    assert recovery.report["candidate_set_complete"] is False
    assert recovery.report["candidate_set_truncated"] is True


def test_javascript_base52_bounds_alphabet_enumeration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _javascript_fixture(_powershell_script())
    monkeypatch.setattr(chain, "MAXIMUM_ALPHABETS", 0)

    recovery = chain.recover_remcos_javascript_base52(fixture)

    assert recovery.report["status"] == "alphabet_count_limit_exceeded"
    assert recovery.report["observed_alphabet_count"] == 1
    assert recovery.report["candidate_set_complete"] is False


def test_javascript_base52_size_limit_is_explicitly_incomplete(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _javascript_fixture(_powershell_script())
    monkeypatch.setattr(chain, "MAXIMUM_JAVASCRIPT_INPUT_BYTES", len(fixture) - 1)

    recovery = chain.recover_remcos_javascript_base52(fixture)

    assert recovery.report["status"] == "input_size_rejected"
    assert recovery.report["candidate_set_complete"] is False
    assert recovery.report["candidate_set_truncated"] is True


def test_large_javascript_is_not_misrouted_to_powershell_size_rejection() -> None:
    fixture = _javascript_fixture(_powershell_script())
    fixture += b" " * (chain.MAXIMUM_INPUT_BYTES + 1 - len(fixture))

    recovery = chain.recover_remcos_powershell_base52_pes(fixture)

    assert recovery.report["status"] == "reviewed_shape_not_found"
    assert recovery.report["candidate_set_complete"] is True


def test_javascript_base52_rejects_corruption_and_quota(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _javascript_fixture(_powershell_script(), declared_delta=1)
    assert chain.recover_remcos_javascript_base52(fixture).script is None

    valid = _javascript_fixture(_powershell_script())
    monkeypatch.setattr(chain, "MAXIMUM_TRANSFORM_WORK_BYTES", 1)
    limited = chain.recover_remcos_javascript_base52(valid)
    assert limited.report["status"] == "transform_work_limit_exceeded"


def test_powershell_base52_recovers_only_valid_pe() -> None:
    expected = _minimal_pe()
    recovery = chain.recover_remcos_powershell_base52_pes(_stage2_fixture(expected))

    assert recovery.artifacts == (("remcos-base52-pe-0", expected),)
    assert recovery.report["status"] == "pe_recovered"


def test_powershell_base52_rejects_corruption_and_quota(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _stage2_fixture(_minimal_pe())
    corrupted = fixture.replace(b"$payload='", b"$payload='A", 1)
    assert chain.recover_remcos_powershell_base52_pes(corrupted).artifacts == ()

    monkeypatch.setattr(chain, "MAXIMUM_TRANSFORM_WORK_BYTES", 1)
    limited = chain.recover_remcos_powershell_base52_pes(fixture)
    assert limited.report["status"] == "transform_work_limit_exceeded"


def test_powershell_base52_discards_partial_multi_part_recovery() -> None:
    recovery = chain.recover_remcos_powershell_base52_pes(
        _stage2_fixture(_minimal_pe(), extra_part="A" * 64)
    )

    assert recovery.artifacts == ()
    assert recovery.report["status"] == "payload_part_recovery_incomplete"
    assert recovery.report["payload_part_count"] == 2
    assert recovery.report["recovered_pe_count"] == 1
    assert recovery.report["recovered_part_indices"] == [0]
    assert recovery.report["partial_recovery_discarded"] is True


def test_unrelated_scripts_are_not_promoted() -> None:
    javascript = b"var alphabet='abcdefghijklmnopqrstuvwxyz';"
    powershell = b"$value = 'ordinary administration script'\n"

    assert chain.recover_remcos_javascript_base52(javascript).script is None
    assert chain.recover_remcos_powershell_base52_pes(powershell).artifacts == ()
