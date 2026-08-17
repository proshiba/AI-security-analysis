"""Offline StealC v1 string and configuration extractor.

The module supports the two statically recoverable v1 layouts observed in the
reviewed corpus: Base64 plus RC4 skip-key strings and paired XOR buffers passed
through ``push size; push key; push ciphertext`` call sites.  It parses bytes
only; it never loads the PE, executes code, or contacts a recovered endpoint.
"""

from __future__ import annotations

import base64
import binascii
import math
import re
import struct
import urllib.parse
from dataclasses import dataclass

import pefile

from extractors.common import build_result, sha256_bytes

ASCII_RUN = re.compile(rb"[\x20-\x7e]{4,}")
BASE64_VALUE = re.compile(rb"[A-Za-z0-9+/]+={0,2}")
XOR_CALL = re.compile(rb"\x6a(.)\x68(.{4})\x68(.{4}).{0,5}\xe8", re.DOTALL)
KNOWN_MARKERS = (
    b"getprocaddress",
    b"content-type: multipart/form-data",
    b"select origin_url",
    b"sqlite3.dll",
    b"hwid",
    b"build",
)
MAX_KEY_CANDIDATES = 512
MAX_ENCODED_VALUES = 4096
MAX_ENCODED_LENGTH = 4096
MAX_PROBE_VALUES = 64
MAX_FINAL_KEYS = 4
IMAGE_SCN_MEM_EXECUTE = 0x20000000
PROTECTED_WRAPPER_CLUSTER_ID = "stealc-taggant-wrapper-466909e3ef5d175a"
PROTECTED_WRAPPER_FINGERPRINT_SHA256 = (
    "466909e3ef5d175acc1f3923245a3f8069248bfe78def549965adbee1522e331"
)
REVIEWED_PROTECTED_WRAPPER_SHA256 = frozenset(
    {
        "09034743ead73365c3077a85036d69c4ef0b0c19bba669db7cd53814b9308889",
        "125382411e94398dd47ef364807868a3d2a6a4d4821d1513897278e77ef005b1",
        "299c378868c76048c26d0e279655c08305f0ce42e5582fe5005aae776d525a1b",
        "99e3eaac03d77c6b24ebd5a17326ba051788d58f1f1d4aa6871310419a85d8af",
        "9b8e5b5f2e62640327fdd1616c62a29ec27eaddad731d66ed331b3a1135fd6cb",
        "ab5f78eaccc4a0f86106c547f828c2da8bd554a855deda50074c8a3cd003513a",
        "b42f055a7a568843360e4b8b46d514de26931303b039b700d15a336b5c53dc0b",
        "e08a69c8611950c16a0d273800acc6083cce9078358a8ff41b4639e02a7b18b0",
        "e1bdbadb3c03238af26c510775bb0aa63f7221dd43eb6f02a16332e091718779",
        "eb433e78acbf8dc7dfd0817a7699ebef2b44c5de873aa3cb9e950d7df895d49a",
        "f0947eaff9837140af164952d5ff422e3f9e35cea5c85a67709fb97638d03f12",
    }
)
RANDOMIZED_SECTION_NAME = re.compile(r"[a-z]{8}\Z")


@dataclass(frozen=True)
class DecodedProfile:
    """Normalized StealC configuration recovered from one string scheme."""

    method: str
    base_url: str
    gate_path: str
    dll_path: str
    build_id: str | None
    decoded_count: int
    string_key: str | None = None

    @property
    def c2_url(self) -> str:
        """Return the configured HTTP gate URL."""
        return urllib.parse.urljoin(self.base_url.rstrip("/") + "/", self.gate_path.lstrip("/"))

    @property
    def dll_url(self) -> str:
        """Return the configured dependency directory URL."""
        return urllib.parse.urljoin(self.base_url.rstrip("/") + "/", self.dll_path.lstrip("/"))


def rc4_skip(data: bytes, key: bytes) -> bytes:
    """Decrypt StealC's RC4 skip-key variant.

    The observed implementation retains the ciphertext byte when the normal
    RC4 XOR would produce NUL.  This avoids embedded NULs in decrypted C strings
    while still advancing the RC4 state.
    """
    if not key:
        raise ValueError("RC4 key must not be empty")
    state = list(range(256))
    j = 0
    for index in range(256):
        j = (j + state[index] + key[index % len(key)]) & 0xFF
        state[index], state[j] = state[j], state[index]
    output = bytearray()
    i = j = 0
    for value in data:
        i = (i + 1) & 0xFF
        j = (j + state[i]) & 0xFF
        state[i], state[j] = state[j], state[i]
        decoded = value ^ state[(state[i] + state[j]) & 0xFF]
        output.append(value if decoded == 0 else decoded)
    return bytes(output)


def _printable_ratio(value: bytes) -> float:
    if not value:
        return 0.0
    return sum(byte in (9, 10, 13) or 32 <= byte < 127 for byte in value) / len(value)


def _pe(data: bytes) -> pefile.PE | None:
    try:
        return pefile.PE(data=data, fast_load=True)
    except pefile.PEFormatError:
        return None


def _strict_int(value: object) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value


def _section_name(section: object) -> str | None:
    try:
        raw = section.Name
    except AttributeError:
        return None
    if not isinstance(raw, bytes):
        return None
    try:
        return raw.split(b"\0", 1)[0].decode("ascii").strip()
    except UnicodeDecodeError:
        return None


def _section_entropy(data: bytes, start: int, size: int) -> float | None:
    if start < 0 or size < 0 or start + size > len(data):
        return None
    if size == 0:
        return 0.0
    counts = [0] * 256
    for value in memoryview(data)[start : start + size]:
        counts[value] += 1
    entropy = 0.0
    for count in counts:
        if count:
            probability = count / size
            entropy -= probability * math.log2(probability)
    return round(entropy, 4)


def _section_record(data: bytes, section: object) -> dict | None:
    name = _section_name(section)
    try:
        raw_size = _strict_int(section.SizeOfRawData)
        virtual_size = _strict_int(section.Misc_VirtualSize)
        virtual_address = _strict_int(section.VirtualAddress)
        raw_offset = _strict_int(section.PointerToRawData)
        characteristics = _strict_int(section.Characteristics)
    except AttributeError:
        return None
    if (
        name is None
        or raw_size is None
        or virtual_size is None
        or virtual_address is None
        or raw_offset is None
        or characteristics is None
    ):
        return None
    entropy = _section_entropy(data, raw_offset, raw_size)
    if entropy is None:
        return None
    return {
        "name": name,
        "raw_size": raw_size,
        "virtual_size": virtual_size,
        "virtual_address": virtual_address,
        "raw_offset": raw_offset,
        "entropy": entropy,
        "executable": bool(characteristics & IMAGE_SCN_MEM_EXECUTE),
    }


def _protected_wrapper_profile(
    data: bytes,
    image: pefile.PE,
    sample_sha256: str,
) -> dict | None:
    """Bind reviewed wrapper hashes to the exact byte-level PE topology.

    The wrapper alone is not treated as recovered StealC configuration or a
    terminal-family proof. A structural result is returned only when both the
    reviewed exact hash and the reviewed seven-section shape match.
    """

    if sample_sha256 not in REVIEWED_PROTECTED_WRAPPER_SHA256:
        return None
    if not 1_700_000 <= len(data) <= 1_900_000:
        return None
    try:
        file_header = image.FILE_HEADER
        optional_header = image.OPTIONAL_HEADER
        machine = file_header.Machine
        magic = optional_header.Magic
        directories = optional_header.DATA_DIRECTORY
        raw_sections = image.sections
    except AttributeError:
        return None
    if machine != 0x14C or magic != 0x10B:
        return None
    if not isinstance(directories, list) or len(directories) <= 14:
        return None
    if directories[14].VirtualAddress != 0:
        return None

    if not isinstance(raw_sections, list) or len(raw_sections) != 7:
        return None
    sections = [_section_record(data, section) for section in raw_sections]
    if any(section is None for section in sections):
        return None
    records = [section for section in sections if section is not None]
    names = [section["name"] for section in records]
    if names[:4] != ["", ".rsrc", ".idata", ""]:
        return None
    if not RANDOMIZED_SECTION_NAME.fullmatch(names[4]) or not RANDOMIZED_SECTION_NAME.fullmatch(
        names[5]
    ):
        return None
    if names[4] == names[5] or names[6] != ".taggant":
        return None

    if not records[0]["executable"] or records[0]["entropy"] < 7.8:
        return None
    if not 64 * 1024 <= records[0]["raw_size"] <= 160 * 1024:
        return None
    if records[1]["executable"] or records[1]["raw_size"] not in {0, 512}:
        return None
    if records[2]["executable"] or records[2]["raw_size"] != 512:
        return None
    if (
        not records[3]["executable"]
        or records[3]["raw_size"] != 512
        or records[3]["entropy"] >= 1.0
    ):
        return None
    if not records[4]["executable"] or records[4]["entropy"] < 7.8:
        return None
    if not 1_600_000 <= records[4]["raw_size"] <= 1_750_000:
        return None
    if not records[5]["executable"] or records[5]["raw_size"] not in {1024, 1536}:
        return None
    if (
        not records[6]["executable"]
        or records[6]["raw_size"] != 8704
        or records[6]["entropy"] >= 1.0
    ):
        return None

    entrypoint = _strict_int(optional_header.AddressOfEntryPoint)
    if entrypoint is None:
        return None
    taggant = records[6]
    taggant_span = max(taggant["virtual_size"], taggant["raw_size"])
    if not taggant["virtual_address"] <= entrypoint < taggant["virtual_address"] + taggant_span:
        return None
    size_of_headers = _strict_int(optional_header.SizeOfHeaders)
    if size_of_headers is None or not 0 < size_of_headers <= len(data):
        return None
    raw_end = max(
        size_of_headers,
        *(section["raw_offset"] + section["raw_size"] for section in records),
    )
    if raw_end != len(data):
        return None

    return {
        "artifact_role": "reviewed_protected_wrapper",
        "reviewed_hash": True,
        "cluster_id": PROTECTED_WRAPPER_CLUSTER_ID,
        "structural_fingerprint_sha256": PROTECTED_WRAPPER_FINGERPRINT_SHA256,
        "protector_family_shape": "Themida_or_WinLicense_family",
        "matched_patterns": [
            "reviewed_exact_sha256",
            "x86_pe32_seven_section_layout",
            "randomized_dual_executable_sections",
            "taggant_entrypoint_section",
            "no_overlay",
        ],
        "observed": {
            "architecture": "x86-32",
            "section_count": 7,
            "randomized_section_names": names[4:6],
            "entrypoint_section": ".taggant",
            "overlay_size": 0,
        },
        "reviewed_cluster_observations": {
            "import_libraries": ["kernel32.dll"],
            "import_count": 1,
            "entrypoint_cfg": {
                "basic_blocks": 4,
                "known_edges": 3,
                "calls": 1,
                "terminal_instruction": "int3",
            },
        },
        "protector_exact_version_confirmed": False,
        "terminal_family_confirmed_from_wrapper_alone": False,
        "terminal_payload_recovered": False,
        "static_config_recovered": False,
        "c2_recovered": False,
    }


def extract_protected_wrapper_profile(data: bytes) -> dict | None:
    """Return reviewed protected-wrapper evidence without unpacking it."""

    image = _pe(data)
    if image is None:
        return None
    return _protected_wrapper_profile(data, image, sha256_bytes(data))


def _candidate_strings(data: bytes, image: pefile.PE) -> list[bytes]:
    values: list[bytes] = []
    for section in image.sections:
        if section.Name.rstrip(b"\0") in {b".rdata", b".data"}:
            values.extend(match.group() for match in ASCII_RUN.finditer(section.get_data()))
    return values or [match.group() for match in ASCII_RUN.finditer(data)]


def _key_candidates(values: list[bytes]) -> list[bytes]:
    candidates = []
    seen = set()
    for value in values:
        if not 16 <= len(value) <= 64 or not value.isalnum():
            continue
        if value.isdigit() or len(value) in {20, 32, 40, 50, 64}:
            if value in seen:
                continue
            seen.add(value)
            candidates.append(value)
            if len(candidates) >= MAX_KEY_CANDIDATES:
                break
    return candidates


def _base64_candidates(values: list[bytes]) -> list[bytes]:
    """Return bounded, unique syntactically valid Base64 values."""
    candidates: list[bytes] = []
    seen: set[bytes] = set()
    for value in values:
        if not 8 <= len(value) <= MAX_ENCODED_LENGTH or len(value) % 4 or value in seen:
            continue
        if not BASE64_VALUE.fullmatch(value):
            continue
        seen.add(value)
        candidates.append(value)
        if len(candidates) >= MAX_ENCODED_VALUES:
            break
    return candidates


def _even_sample(values: list[bytes], limit: int) -> list[bytes]:
    """Return a deterministic first-to-last sample bounded by ``limit``."""
    if limit <= 0 or not values:
        return []
    if len(values) <= limit:
        return values
    if limit == 1:
        return values[:1]
    return [values[(index * (len(values) - 1)) // (limit - 1)] for index in range(limit)]


def _decode_base64_values(values: list[bytes], key: bytes) -> tuple[int, list[str]]:
    score = 0
    decoded: list[str] = []
    for value in values:
        if len(value) < 8 or len(value) % 4 or not BASE64_VALUE.fullmatch(value):
            continue
        try:
            raw = base64.b64decode(value, validate=True)
        except (binascii.Error, ValueError):
            continue
        clear = rc4_skip(raw, key).rstrip(b"\0")
        if not clear or _printable_ratio(clear) < 0.9:
            continue
        text = clear.decode("ascii", errors="replace")
        decoded.append(text)
        score += 1 + 20 * sum(marker in clear.lower() for marker in KNOWN_MARKERS)
    return score, decoded


def _profile_from_strings(strings: list[str], method: str, key: str | None = None) -> DecodedProfile | None:
    base_index = next(
        (index for index, value in enumerate(strings) if value.startswith(("http://", "https://"))),
        None,
    )
    if base_index is None:
        return None
    base_url = strings[base_index]
    gate_index = next(
        (
            index
            for index in range(base_index + 1, min(len(strings), base_index + 8))
            if strings[index].startswith("/") and strings[index].lower().endswith(".php")
        ),
        None,
    )
    if gate_index is None:
        return None
    dll_index = next(
        (
            index
            for index in range(gate_index + 1, min(len(strings), gate_index + 8))
            if strings[index].startswith("/") and strings[index].endswith("/")
        ),
        None,
    )
    if dll_index is None:
        return None
    build_id = strings[dll_index + 1] if dll_index + 1 < len(strings) else None
    if build_id and (len(build_id) > 64 or "\\" in build_id or "/" in build_id):
        build_id = None
    return DecodedProfile(
        method=method,
        base_url=base_url,
        gate_path=strings[gate_index],
        dll_path=strings[dll_index],
        build_id=build_id,
        decoded_count=len(strings),
        string_key=key,
    )


def extract_rc4_profile(data: bytes) -> DecodedProfile | None:
    """Recover a Base64/RC4 skip-key StealC profile from PE data."""
    image = _pe(data)
    if image is None:
        return None
    values = _candidate_strings(data, image)
    encoded = _base64_candidates(values)
    keys = _key_candidates(values)
    if not encoded or not keys:
        return None
    probe = _even_sample(encoded, MAX_PROBE_VALUES)
    ranked: list[tuple[int, int, bytes]] = []
    for index, key in enumerate(keys):
        score, _strings = _decode_base64_values(probe, key)
        ranked.append((score, index, key))
    ranked.sort(key=lambda item: (-item[0], item[1]))
    best_score, best_key, best_strings = 0, None, []
    for _probe_score, _index, key in ranked[:MAX_FINAL_KEYS]:
        score, strings = _decode_base64_values(encoded, key)
        if score > best_score:
            best_score, best_key, best_strings = score, key, strings
    if best_key is None or best_score < 100 or len(best_strings) < 50:
        return None
    return _profile_from_strings(
        best_strings, "v1-base64-rc4-skip-key", best_key.decode("ascii")
    )


def extract_xor_profile(data: bytes) -> DecodedProfile | None:
    """Recover a paired-buffer XOR StealC profile from x86 PE call sites."""
    image = _pe(data)
    if image is None or image.OPTIONAL_HEADER.Magic != 0x10B:
        return None
    image_base = image.OPTIONAL_HEADER.ImageBase
    decoded: list[str] = []
    for match in XOR_CALL.finditer(data):
        size = match.group(1)[0]
        if not size:
            continue
        try:
            key_va = struct.unpack("<I", match.group(2))[0]
            text_va = struct.unpack("<I", match.group(3))[0]
            key_offset = image.get_offset_from_rva(key_va - image_base)
            text_offset = image.get_offset_from_rva(text_va - image_base)
            key = data[key_offset : key_offset + size]
            text = data[text_offset : text_offset + size]
            if len(key) != size or len(text) != size:
                continue
            clear = bytes(left ^ right for left, right in zip(text, key, strict=True))
            if _printable_ratio(clear) >= 0.9:
                decoded.append(clear.decode("ascii", errors="replace"))
        except (IndexError, struct.error, ValueError, pefile.PEFormatError):
            continue
    if len(decoded) < 50 or sum(marker.decode() in "\n".join(decoded).lower() for marker in KNOWN_MARKERS) < 3:
        return None
    return _profile_from_strings(decoded, "v1-paired-buffer-xor")


def extract(data: bytes, source_name: str = "sample.bin") -> dict:
    """Return publish-safe StealC configuration and IOC findings."""
    profile = extract_rc4_profile(data) or extract_xor_profile(data)
    protected_wrapper = None if profile is not None else extract_protected_wrapper_profile(data)
    config: dict = {
        "source_name": source_name,
        "profile": None,
        "static_config_recovered": profile is not None,
        "protected_wrapper": protected_wrapper,
    }
    findings: list[dict] = []
    limitations = [
        "Static extraction only; the sample was not executed.",
        "No recovered endpoint was contacted or assigned a liveness state.",
    ]
    if profile is None and protected_wrapper is None:
        limitations.append(
            "No supported plaintext profile was recovered; packing or another StealC generation may require a separately authorized unpacking workflow."
        )
    elif protected_wrapper is not None:
        limitations.extend(
            [
                "The exact sample and reviewed .taggant wrapper topology match the protected-wrapper cluster.",
                "The wrapper does not identify the exact protector version or recover the terminal payload, configuration, or C2.",
            ]
        )
    else:
        config["profile"] = {
            "generation": "StealC-v1",
            "method": profile.method,
            "base_url": profile.base_url,
            "gate_path": profile.gate_path,
            "c2_url": profile.c2_url,
            "dll_path": profile.dll_path,
            "dll_url": profile.dll_url,
            "build_id": profile.build_id,
            "decoded_string_count": profile.decoded_count,
            "string_key": profile.string_key,
        }
        findings.extend(
            [
                {"kind": "url", "value": profile.c2_url, "role": "stealc_c2_url", "confidence": "confirmed_static_config"},
                {"kind": "url", "value": profile.dll_url, "role": "stealc_dependency_directory", "confidence": "confirmed_static_config"},
            ]
        )
    return build_result("stealc", data, config, findings, limitations)
