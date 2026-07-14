#!/usr/bin/env python3
"""Pure N520 framing helpers for bounded defensive collection."""

from __future__ import annotations

import hashlib
import hmac
import os
import struct
import zlib

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def derive_session_key(handshake: bytes) -> bytes:
    if len(handshake) != 44:
        raise ValueError("N520 handshake must be exactly 44 bytes")
    session_id = struct.unpack_from("<I", handshake)[0]
    session_bytes = session_id.to_bytes(4, "little")
    return bytes(handshake[8 + index] ^ session_bytes[index % 4] for index in range(32))


def parse_handshake(raw: bytes) -> dict:
    result = {
        "length": len(raw),
        "expected_length": 44,
        "crc_matches": False,
        "magic_matches": False,
        "header_matches": False,
    }
    if len(raw) != 44:
        result["validation_error"] = "N520 handshake must be exactly 44 bytes"
        return result
    session_id, received_magic = struct.unpack_from("<II", raw)
    stored_crc = struct.unpack_from("<I", raw, 40)[0]
    calculated_crc = zlib.crc32(raw[:40]) & 0xFFFFFFFF
    expected_magic = (
        session_id ^ (((session_id >> 16) ^ (session_id & 0xFFFF)) | 0xA5A50000)
    ) & 0xFFFFFFFF
    key = derive_session_key(raw)
    result.update({
        "session_id": session_id,
        "session_id_hex": f"0x{session_id:08x}",
        "received_magic_hex": f"0x{received_magic:08x}",
        "expected_magic_hex": f"0x{expected_magic:08x}",
        "stored_crc32_hex": f"0x{stored_crc:08x}",
        "calculated_crc32_hex": f"0x{calculated_crc:08x}",
        "crc_matches": stored_crc == calculated_crc,
        "magic_matches": received_magic == expected_magic,
        "derived_session_key_sha256": hashlib.sha256(key).hexdigest(),
    })
    result["header_matches"] = result["crc_matches"] and result["magic_matches"]
    return result


def _encrypt(key: bytes, plaintext: bytes, iv: bytes) -> bytes:
    if len(key) != 32 or len(iv) != 16:
        raise ValueError("N520 key/IV length is invalid")
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    encryptor = Cipher(algorithms.AES(key[:16]), modes.CBC(iv)).encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    authenticated = iv + ciphertext
    return authenticated + hmac.new(key[16:], authenticated, hashlib.sha256).digest()


def _decrypt(key: bytes, encrypted: bytes) -> bytes:
    if len(key) != 32 or len(encrypted) < 64 or (len(encrypted) - 48) % 16:
        raise ValueError("N520 encrypted body length is invalid")
    authenticated, supplied_hmac = encrypted[:-32], encrypted[-32:]
    calculated_hmac = hmac.new(key[16:], authenticated, hashlib.sha256).digest()
    if not hmac.compare_digest(supplied_hmac, calculated_hmac):
        raise ValueError("N520 HMAC mismatch")
    iv, ciphertext = authenticated[:16], authenticated[16:]
    decryptor = Cipher(algorithms.AES(key[:16]), modes.CBC(iv)).decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def build_packet(
    session_id: int, sequence: int, command: int, payload: bytes, key: bytes,
    *, padding_length: int = 0, iv: bytes | None = None,
) -> bytes:
    if not 0 <= command <= 255 or not 0 <= padding_length <= 15:
        raise ValueError("N520 command or padding length is invalid")
    filler = os.urandom(padding_length) if padding_length else b""
    plaintext = bytes([command]) + payload + filler + bytes([padding_length])
    encrypted = _encrypt(key, plaintext, iv or os.urandom(16))
    packet = bytearray(struct.pack("<III", session_id, len(encrypted) + 8, sequence))
    packet.extend(encrypted)
    packet.extend(struct.pack("<I", zlib.crc32(packet) & 0xFFFFFFFF))
    return bytes(packet)


def decode_stream(data: bytes, session_id: int, key: bytes, max_frames: int = 16) -> tuple[list[dict], bytes]:
    frames = []
    remaining = data
    while len(remaining) >= 8 and len(frames) < max_frames:
        if struct.unpack_from("<I", remaining)[0] != session_id:
            remaining = remaining[1:]
            continue
        declared = struct.unpack_from("<I", remaining, 4)[0]
        total = declared + 8
        if total < 80 or total > 64 * 1024 * 1024:
            remaining = remaining[1:]
            continue
        if len(remaining) < total:
            break
        raw = remaining[:total]
        remaining = remaining[total:]
        stored_crc = struct.unpack_from("<I", raw, total - 4)[0]
        calculated_crc = zlib.crc32(raw[:-4]) & 0xFFFFFFFF
        frame = {
            "raw": raw,
            "size": total,
            "sequence": struct.unpack_from("<I", raw, 8)[0],
            "crc_matches": stored_crc == calculated_crc,
            "raw_sha256": hashlib.sha256(raw).hexdigest(),
        }
        if not frame["crc_matches"]:
            frame["error"] = "CRC32 mismatch"
            frames.append(frame)
            continue
        try:
            plaintext = _decrypt(key, raw[12:-4])
            if len(plaintext) < 2:
                raise ValueError("N520 plaintext is too short")
            padding_length = plaintext[-1]
            payload_length = len(plaintext) - padding_length - 2
            if padding_length > 15 or payload_length < 0:
                raise ValueError("N520 inner padding is invalid")
            frame.update({
                "command": plaintext[0],
                "payload": plaintext[1:1 + payload_length],
                "payload_size": payload_length,
                "authenticated": True,
            })
        except Exception as exc:
            frame.update({"authenticated": False, "error": f"{type(exc).__name__}: {exc}"})
        frames.append(frame)
    return frames, remaining


def extract_plugin(command: int, payload: bytes) -> dict | None:
    if command not in {16, 18}:
        return None
    delimiter = payload.find(b"\0")
    if delimiter < 0:
        return None
    name = payload[:delimiter].decode("utf-8", errors="replace")[:512]
    offset = delimiter + 1
    input_size = 0
    if command == 18:
        if offset + 4 > len(payload):
            return None
        input_size = struct.unpack_from("<i", payload, offset)[0]
        offset += 4
        if input_size < 0 or offset + input_size > len(payload):
            return None
        offset += input_size
    artifact = payload[offset:]
    if not artifact:
        return None
    return {
        "operator_name": name,
        "command": command,
        "input_size": input_size,
        "artifact": artifact,
        "artifact_size": len(artifact),
        "artifact_sha256": hashlib.sha256(artifact).hexdigest(),
        "pe_magic": artifact.startswith(b"MZ"),
    }
