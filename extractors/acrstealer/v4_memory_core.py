"""ACRStealer v4系のPE memory imageから暗号化文字列と設定候補を復元する。

検体や復元artifactは実行しない。x86の直接call-siteをCapstoneで読み、静的に
確定できる即値引数だけを再生する。復号結果は、収集・通信・識別情報という
独立した証拠群がそろった場合だけ高確度profileとして返す。
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
import hashlib
from itertools import islice
import re
from urllib.parse import urlsplit

from capstone import CS_ARCH_X86, CS_GRP_CALL, CS_MODE_32, Cs
from capstone.x86 import X86_OP_IMM
import pefile

MASK32 = 0xFFFFFFFF
MAX_MEMORY_IMAGE_BYTES = 64 * 1024 * 1024
MAX_TEXT_BYTES = 16 * 1024 * 1024
MAX_DISASSEMBLY_BYTES = MAX_TEXT_BYTES
MAX_DISASSEMBLY_INSTRUCTIONS = 1_000_000
MAX_DECODE_LENGTH = 4096
MAX_CALL_SITES = 16_384
MAX_PUBLIC_STRINGS = 2048

MIX_LOW_1 = 0x1CE4E5B9
MIX_HIGH_1 = 0xBF58476D
MIX_LOW_2 = 0x133111EB
MIX_HIGH_2 = 0x94D049BB
STATIC_KEY = 0xE39310A767D939A4
SEED_MULTIPLIER = 0xC6A4A7935BD1E995
INDEX_MULTIPLIER = 0x517CC1B727220A95

# 互いに離れた命令で使われるため、単一4-byte値だけではfamily証拠にしない。
PRNG_MARKERS = (
    bytes.fromhex("81f6a71093e3"),  # xor esi, e39310a7h
    bytes.fromhex("81f7a439d967"),  # xor edi, 67d939a4h
    bytes.fromhex("b9 95 e9 d1 5b"),
    bytes.fromhex("ba 95 0a 22 27"),
)

URL_RE = re.compile(r"(?i)\b(?:https?|wss?)://[^\s\x00\"'<>]{4,512}")
DOMAIN_RE = re.compile(
    r"(?i)(?<![a-z0-9.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"(?:cc|com|dev|io|net|org|pro|ru|site|top|xyz)(?![a-z0-9.-])"
)
GUID_RE = re.compile(
    r"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-"
    r"[89ab0-9][0-9a-f]{3}-[0-9a-f]{12}\b"
)
VERSION_RE = re.compile(r"(?i)\b\d+\.\d+(?:\.\d+)?(?:-alpha\d+|-beta\d+)?\b")


@dataclass(frozen=True)
class DecodedString:
    """静的call-siteから復元した1文字列。"""

    call_address: int
    decryptor_address: int
    source_address: int
    length: int
    seed: int
    value: str


@dataclass(frozen=True)
class V4MemoryProfile:
    """ACRStealer v4 memory imageから高確度で復元した設定profile。"""

    version: str | None
    c2_urls: tuple[str, ...]
    c2_hosts: tuple[str, ...]
    c2_paths: tuple[str, ...]
    decoy_hosts: tuple[str, ...]
    dns_resolvers: tuple[str, ...]
    guids: tuple[str, ...]
    user_agent: str | None
    decoded_strings: tuple[str, ...]
    decoded_count: int
    decryptor_address: int
    string_key_hex: str
    string_key_sha256: str
    layout: str
    evidence_categories: tuple[str, ...]
    generic_domain_findings: tuple[str, ...] = ()


@dataclass(frozen=True)
class _PEView:
    label: str
    image_base: int
    text_address: int
    text: bytes
    data: bytes
    pe: pefile.PE

    def read_address(self, address: int, size: int) -> bytes | None:
        if size <= 0 or size > MAX_DECODE_LENGTH:
            return None
        rva = address - self.image_base
        if rva < 0:
            return None
        if self.label == "memory_mapped":
            end = rva + size
            if end > len(self.data):
                return None
            return self.data[rva:end]
        try:
            offset = self.pe.get_offset_from_rva(rva)
        except (pefile.PEFormatError, TypeError, ValueError):
            return None
        end = offset + size
        if offset < 0 or end > len(self.data):
            return None
        return self.data[offset:end]


def _u32(value: int) -> int:
    return value & MASK32


def _mul32(left: int, right: int) -> tuple[int, int]:
    product = (left & MASK32) * (right & MASK32)
    return product & MASK32, (product >> 32) & MASK32


def _shld(destination: int, source: int, count: int) -> int:
    return _u32((destination << count) | (source >> (32 - count)))


def _initial_state(seed: int) -> tuple[int, int]:
    """Ghidraで復元した64-bit SplitMix系initial stateをx86半語で再現する。"""

    eax = _u32(0x70736575 ^ seed)
    ecx = _u32((eax >> 30) | 0xCDBDB594) ^ eax
    eax, edx = _mul32(ecx, MIX_LOW_1)
    esi = _u32(edx + _u32(ecx * MIX_HIGH_1) + 0x75708144)
    ecx = _shld(esi, eax, 5) ^ eax
    edi = (esi >> 27) ^ esi
    eax, edx = _mul32(ecx, MIX_LOW_2)
    edx = _u32(edx + _u32(edi * MIX_LOW_2) + _u32(ecx * MIX_HIGH_2))
    ecx = _shld(edx, eax, 1)
    edx ^= edx >> 31
    eax ^= ecx
    return eax, edx


def _keystream_word(seed: int, index: int) -> int:
    """文字列seedと文字位置から32-bitのbyte変換状態を作る。"""

    initial_low, initial_high = _initial_state(seed)
    low_state = initial_low ^ (STATIC_KEY & MASK32)
    high_state = initial_high ^ (STATIC_KEY >> 32)

    seed_low, seed_high_part = _mul32(seed, SEED_MULTIPLIER & MASK32)
    seed_high = _u32(seed_high_part + _u32(seed * (SEED_MULTIPLIER >> 32)))
    index_low, index_high_part = _mul32(index, INDEX_MULTIPLIER & MASK32)
    index_high = _u32(index_high_part + _u32(index * (INDEX_MULTIPLIER >> 32)))

    total = index_low + seed_low
    eax = _u32(total)
    ecx = _u32(index_high + seed_high + (total >> 32))
    total = eax + low_state
    eax = _u32(total)
    ecx = _u32(ecx + high_state + (total >> 32))

    for _ in range(4):
        prior_high = ecx
        mixed_low = _shld(prior_high, eax, 2) ^ eax
        mixed_high = (prior_high >> 30) ^ prior_high
        eax, product_high = _mul32(mixed_low, MIX_LOW_1)
        ecx = _u32(
            product_high
            + _u32(mixed_low * MIX_HIGH_1)
            + _u32(mixed_high * MIX_LOW_1)
        )
        mixed_high = (ecx >> 27) ^ ecx
        mixed_low = _shld(ecx, eax, 5) ^ eax
        eax, product_high = _mul32(mixed_low, MIX_LOW_2)
        ecx = _u32(
            product_high
            + _u32(mixed_low * MIX_HIGH_2)
            + _u32(mixed_high * MIX_LOW_2)
        )

    return ((_shld(ecx, eax, 1) ^ eax) & 0xFFFF07FF) + 0x100


def _ror8(value: int, count: int) -> int:
    count &= 7
    if count == 0:
        return value & 0xFF
    return ((value >> count) | (value << (8 - count))) & 0xFF


def decrypt_string(ciphertext: bytes, seed: int) -> bytes:
    """ACRStealer v4のper-string変換を静的に逆演算する。"""

    clear = bytearray()
    for index, cipher in enumerate(ciphertext):
        word = _keystream_word(seed, index)
        value = cipher ^ ((word >> 24) & 0xFF)
        value = (value - ((word >> 16) & 0xFF)) & 0xFF
        value = _ror8(value, (word >> 8) & 0xFF)
        value ^= word & 0xFF
        clear.append(value)
    return bytes(clear)


def _section_bytes(data: bytes, section: object, mapped: bool) -> tuple[int, bytes] | None:
    rva = int(section.VirtualAddress)
    if mapped:
        offset = rva
        size = int(section.Misc_VirtualSize or section.SizeOfRawData)
    else:
        offset = int(section.PointerToRawData)
        size = int(section.SizeOfRawData)
    size = min(size, MAX_TEXT_BYTES)
    if offset < 0 or size <= 0 or offset + size > len(data):
        return None
    return rva, data[offset : offset + size]


def _pe_views(data: bytes) -> list[_PEView]:
    if not data.startswith(b"MZ") or len(data) > MAX_MEMORY_IMAGE_BYTES:
        return []
    try:
        pe = pefile.PE(data=data, fast_load=True)
    except pefile.PEFormatError:
        return []
    if pe.FILE_HEADER.Machine != pefile.MACHINE_TYPE["IMAGE_FILE_MACHINE_I386"]:
        return []
    text_section = next(
        (section for section in pe.sections if section.Name.rstrip(b"\0") == b".text"),
        None,
    )
    if text_section is None:
        return []
    views: list[_PEView] = []
    image_base = int(pe.OPTIONAL_HEADER.ImageBase)
    for label, mapped in (("memory_mapped", True), ("file_backed", False)):
        content = _section_bytes(data, text_section, mapped)
        if content is None:
            continue
        rva, text = content
        if not all(marker in text for marker in PRNG_MARKERS):
            continue
        views.append(_PEView(label, image_base, image_base + rva, text, data, pe))
    return views


def _direct_immediate(instruction: object) -> int | None:
    operands = getattr(instruction, "operands", ())
    if len(operands) != 1 or operands[0].type != X86_OP_IMM:
        return None
    return int(operands[0].imm) & MASK32


def _is_printable(clear: bytes) -> bool:
    if not clear or b"\0" in clear:
        return False
    printable = sum(byte in (9, 10, 13) or 0x20 <= byte <= 0x7E for byte in clear)
    return printable / len(clear) >= 0.92


def _decode_calls(view: _PEView) -> list[DecodedString]:
    decoder = Cs(CS_ARCH_X86, CS_MODE_32)
    decoder.detail = True
    records: list[DecodedString] = []
    seen: set[tuple[int, int, int, int]] = set()
    recent: deque[object] = deque(maxlen=4)
    instructions = decoder.disasm(
        view.text[:MAX_DISASSEMBLY_BYTES],
        view.text_address,
    )
    for instruction in islice(instructions, MAX_DISASSEMBLY_INSTRUCTIONS):
        previous = tuple(recent)
        recent.append(instruction)
        if len(records) >= MAX_CALL_SITES:
            break
        if not instruction.group(CS_GRP_CALL):
            continue
        target = _direct_immediate(instruction)
        if target is None or len(previous) != 4:
            continue
        pushes = previous
        if any(item.mnemonic != "push" for item in pushes):
            continue
        seed = _direct_immediate(pushes[0])
        length = _direct_immediate(pushes[1])
        source = _direct_immediate(pushes[2])
        if seed is None or length is None or source is None:
            continue
        if length <= 0 or length > MAX_DECODE_LENGTH:
            continue
        ciphertext = view.read_address(source, length)
        if ciphertext is None:
            continue
        clear = decrypt_string(ciphertext, seed)
        if not _is_printable(clear):
            continue
        try:
            value = clear.decode("utf-8")
        except UnicodeDecodeError:
            value = clear.decode("ascii", errors="replace")
        identity = (target, source, length, seed)
        if identity in seen:
            continue
        seen.add(identity)
        records.append(
            DecodedString(
                call_address=int(instruction.address),
                decryptor_address=target,
                source_address=source,
                length=length,
                seed=seed,
                value=value,
            )
        )
    return records


def _network_values(strings: list[str]) -> tuple[list[str], list[str], list[str]]:
    urls: set[str] = set()
    domains: set[str] = set()
    paths: set[str] = set()
    for value in strings:
        urls.update(match.group(0).rstrip(".,;)") for match in URL_RE.finditer(value))
        domains.update(match.group(0).lower() for match in DOMAIN_RE.finditer(value))
        if value.startswith("/") and 2 <= len(value) <= 512 and " " not in value:
            paths.add(value)
    for url in urls:
        parsed = urlsplit(url)
        if parsed.hostname:
            domains.add(parsed.hostname.lower())
        if parsed.path and parsed.path != "/":
            paths.add(parsed.path)
    return sorted(urls), sorted(domains), sorted(paths)


def _evidence_categories(strings: list[str], urls: list[str], domains: list[str]) -> set[str]:
    lowered = "\n".join(strings).lower()
    categories: set[str] = set()
    if sum(marker in lowered for marker in ("login data", "local state", "cookies", "web data")) >= 2:
        categories.add("browser_collection")
    if any(token in lowered for token in ("user-agent", "mozilla/5.0", "websocket", "cloudflare-dns")):
        categories.add("network_protocol")
    if urls or domains:
        categories.add("network_endpoint")
    if GUID_RE.search("\n".join(strings)):
        categories.add("guid_identity")
    if VERSION_RE.search("\n".join(strings)):
        categories.add("version_identity")
    return categories


def _choose_c2(
    urls: list[str], domains: list[str]
) -> tuple[
    tuple[str, ...],
    tuple[str, ...],
    tuple[str, ...],
    tuple[str, ...],
    tuple[str, ...],
]:
    dns = tuple(
        value
        for value in domains
        if value in {"cloudflare-dns.com", "dns.google"} or value.startswith("dns.")
    )
    decoys = tuple(value for value in domains if value in {"keycdn.com"})
    c2_urls = tuple(
        value
        for value in urls
        if (urlsplit(value).hostname or "") not in set(dns) | set(decoys)
    )
    c2_hosts = tuple(
        sorted(
            {
                (urlsplit(value).hostname or "").lower()
                for value in c2_urls
                if urlsplit(value).hostname
            }
        )
    )
    generic_domain_findings = tuple(
        value
        for value in domains
        if value not in set(dns) | set(decoys)
        and value not in set(c2_hosts)
        and not value.endswith(("microsoft.com", "googleapis.com"))
    )
    return c2_urls, c2_hosts, generic_domain_findings, decoys, dns


def _select_profile(view: _PEView, records: list[DecodedString]) -> V4MemoryProfile | None:
    by_target: dict[int, list[DecodedString]] = {}
    for record in records:
        by_target.setdefault(record.decryptor_address, []).append(record)
    candidates: list[tuple[int, V4MemoryProfile]] = []
    for target, target_records in by_target.items():
        if len(target_records) < 12:
            continue
        strings = [record.value for record in target_records]
        urls, domains, paths = _network_values(strings)
        categories = _evidence_categories(strings, urls, domains)
        if not {"browser_collection", "network_protocol", "network_endpoint"}.issubset(
            categories
        ):
            continue
        c2_urls, c2_hosts, generic_domains, decoys, dns = _choose_c2(urls, domains)
        if not c2_urls and not generic_domains:
            continue
        joined = "\n".join(strings)
        versions = VERSION_RE.findall(joined)
        guids = tuple(sorted(set(GUID_RE.findall(joined))))
        user_agent = next(
            (value for value in strings if value.startswith("Mozilla/5.0")),
            None,
        )
        profile = V4MemoryProfile(
            version=versions[0] if versions else None,
            c2_urls=c2_urls,
            c2_hosts=c2_hosts,
            c2_paths=tuple(paths),
            decoy_hosts=decoys,
            dns_resolvers=dns,
            guids=guids,
            user_agent=user_agent,
            decoded_strings=tuple(strings[:MAX_PUBLIC_STRINGS]),
            decoded_count=len(strings),
            decryptor_address=target,
            string_key_hex=STATIC_KEY.to_bytes(8, "big").hex(),
            string_key_sha256=hashlib.sha256(STATIC_KEY.to_bytes(8, "big")).hexdigest(),
            layout=view.label,
            evidence_categories=tuple(sorted(categories)),
            generic_domain_findings=generic_domains,
        )
        score = len(categories) * 1000 + len(strings)
        candidates.append((score, profile))
    if not candidates:
        return None
    candidates.sort(key=lambda item: item[0], reverse=True)
    if len(candidates) > 1 and candidates[0][0] == candidates[1][0]:
        return None
    return candidates[0][1]


def extract_v4_memory_profile(data: bytes) -> V4MemoryProfile | None:
    """x86 PE/memory imageからACRStealer v4設定profileを静的復元する。"""

    profiles: list[tuple[int, V4MemoryProfile]] = []
    for view in _pe_views(data):
        records = _decode_calls(view)
        profile = _select_profile(view, records)
        if profile is not None:
            profiles.append((profile.decoded_count, profile))
    if not profiles:
        return None
    profiles.sort(key=lambda item: item[0], reverse=True)
    if len(profiles) > 1 and profiles[0][0] == profiles[1][0]:
        return None
    return profiles[0][1]
