"""19文字ASCII鍵を伴うWinos4.0完全RC4設定を静的に復元する。

Proofpointが2026年に報告した形式では、19文字のASCII鍵に続く16進文字列を
標準RC4で復号し、byte列全体を逆順にすると、3つのC2 slotと動作設定を含む
pipe区切り設定になる。直接向きの派生形式も同じ文法で検証する。
本moduleは検体をload／実行せず、このdata形式だけを有界走査する。

設定dataだけではloader、terminal payload、config consumer、socket data-flowを
証明できない。このため復元結果は常にroute-only候補とし、family確定または
C2確定へ昇格しない。呼出側はcode側のRC4 loop、同一bufferのfield parser、
connect／send／receive系譜を別途検証する必要がある。
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

from extractors.valleyrat.nvml_dat import is_public_host, normalize_host, render_endpoint

KEY_LENGTH = 19
MINIMUM_CIPHERTEXT_BYTES = 96
MAXIMUM_CIPHERTEXT_BYTES = 64 * 1024
MAXIMUM_INPUT_SIZE = 64 * 1024 * 1024
MAXIMUM_HEX_RUNS = 512
MAXIMUM_CANDIDATE_ATTEMPTS = 128
MAXIMUM_PLAINTEXT_BYTES = 32 * 1024

_HEX = frozenset(b"0123456789abcdefABCDEF")
_KEY = re.compile(rb"[A-Za-z0-9._-]{19}\Z")
_IDENTIFIER = re.compile(r"[A-Za-z0-9._-]{8,64}\Z")
_FIELD_KEY = re.compile(r"[A-Za-z][A-Za-z0-9_]{0,15}\Z")
_BUILD_VALUE = re.compile(r"[A-Za-z0-9._ -]{1,64}\Z")
_HOST_KEY = re.compile(r"([A-Za-z])(1|2|3)\Z")
_BOOLEAN_FIELDS = ("jp", "bh", "ll", "dl", "sh", "kl", "bd")
_TAIL_FIELDS = ("dd", "cl", "fz", "bb", "bz", *_BOOLEAN_FIELDS)


class Rc4FullConfigError(ValueError):
    """RC4完全設定を一意かつ安全に復元できない場合の例外。"""


class Rc4FullConfigLimitError(Rc4FullConfigError):
    """探索上限へ達し、候補集合の完全性を保証できない場合の例外。"""


@dataclass(frozen=True)
class Rc4FullConfigSlot:
    """完全設定から検証したC2 slot。"""

    index: int
    host_field: str
    host: str
    port: int
    transport_selector: int
    endpoint: str | None
    endpoint_role: str


@dataclass(frozen=True)
class Rc4FullConfigRecovery:
    """生鍵・暗号文・完全plaintextを除いた復元結果。"""

    source_sha256: str
    source_offset: int
    key_sha256: str
    ciphertext_sha256: str
    ciphertext_size: int
    plaintext_size: int
    plaintext_transform: str
    campaign_identifier_sha256: str
    slots: tuple[Rc4FullConfigSlot, ...]
    settings: tuple[tuple[str, object], ...]
    configuration_identity_sha256: str
    observed_candidate_count: int
    validated_candidate_count: int

    def public_summary(self) -> dict[str, Any]:
        """route-only境界を含む公開可能な要約を返す。"""

        return public_recovery_summary(self)


@dataclass(frozen=True)
class _ParsedConfig:
    campaign_identifier_sha256: str
    slots: tuple[Rc4FullConfigSlot, ...]
    settings: tuple[tuple[str, object], ...]
    identity_sha256: str


@dataclass(frozen=True)
class _ValidatedCandidate:
    source_offset: int
    key_sha256: str
    ciphertext_sha256: str
    ciphertext_size: int
    plaintext_size: int
    plaintext_transform: str
    parsed: _ParsedConfig


def _is_hex(value: int) -> bool:
    return value in _HEX


def _is_key(value: bytes) -> bool:
    return bool(_KEY.fullmatch(value))


def _rc4(data: bytes, key: bytes) -> bytes:
    """標準RC4 KSA／PRGAを適用する。"""

    if len(key) != KEY_LENGTH or not _is_key(key):
        raise Rc4FullConfigError("RC4 keyが19文字の安全なASCII形式ではありません")
    state = list(range(256))
    j = 0
    for i in range(256):
        j = (j + state[i] + key[i % len(key)]) & 0xFF
        state[i], state[j] = state[j], state[i]
    output = bytearray(data)
    i = j = 0
    for offset in range(len(output)):
        i = (i + 1) & 0xFF
        j = (j + state[i]) & 0xFF
        state[i], state[j] = state[j], state[i]
        output[offset] ^= state[(state[i] + state[j]) & 0xFF]
    return bytes(output)


def _hex_runs(data: bytes) -> tuple[tuple[int, int], ...]:
    """入力内の16進文字列runを有界列挙する。"""

    minimum_characters = MINIMUM_CIPHERTEXT_BYTES * 2
    maximum_characters = KEY_LENGTH + MAXIMUM_CIPHERTEXT_BYTES * 2
    runs: list[tuple[int, int]] = []
    offset = 0
    while offset < len(data):
        if not _is_hex(data[offset]):
            offset += 1
            continue
        start = offset
        offset += 1
        while offset < len(data) and _is_hex(data[offset]):
            offset += 1
        length = offset - start
        if length < minimum_characters:
            continue
        if length > maximum_characters:
            raise Rc4FullConfigLimitError(
                "16進文字列runがRC4設定探索上限を超えています"
            )
        runs.append((start, offset))
        if len(runs) > MAXIMUM_HEX_RUNS:
            raise Rc4FullConfigLimitError("16進文字列run数が探索上限を超えています")
    return tuple(runs)


def _candidate_spans(
    data: bytes, start: int, end: int
) -> tuple[tuple[int, int, int], ...]:
    """1つの16進runから19文字鍵とciphertext境界を列挙する。"""

    spans: list[tuple[int, int, int]] = []
    seen: set[tuple[int, int, int]] = set()
    run_length = end - start
    minimum_characters = MINIMUM_CIPHERTEXT_BYTES * 2

    # 公開例のように鍵自身もhexの場合、最大run全体は必ず奇数長になる。
    if (
        run_length >= KEY_LENGTH + minimum_characters
        and (run_length - KEY_LENGTH) % 2 == 0
    ):
        item = (start, start + KEY_LENGTH, end)
        spans.append(item)
        seen.add(item)

    # 鍵に非hex文字がある場合、run先頭はciphertextの途中または直前になる。
    # 鍵末尾に含まれるhex文字数を0..18で試し、境界はASCII文字列の先頭で
    # あることを要求する。最大19通りなので総試行数を厳密に制御できる。
    for key_hex_suffix in range(KEY_LENGTH):
        cipher_start = start + key_hex_suffix
        if end - cipher_start < minimum_characters or (end - cipher_start) % 2:
            continue
        key_start = cipher_start - KEY_LENGTH
        if key_start < 0:
            continue
        key = data[key_start:cipher_start]
        if not _is_key(key):
            continue
        if key_start and 0x21 <= data[key_start - 1] <= 0x7E:
            continue
        item = (key_start, cipher_start, end)
        if item not in seen:
            spans.append(item)
            seen.add(item)
    return tuple(spans)


def _parse_plaintext(plaintext: bytes) -> _ParsedConfig | None:
    """Proofpoint報告の完全pipe設定をbyte境界で厳格に検証する。

    ``fz`` は実検体でlegacy code page由来の非UTF-8 byte列を取り得るため、
    そのfieldだけを長さとSHA-256へ変換し、生値を公開しない。それ以外の
    識別子、host、port、flagはASCIIを要求する。
    """

    if not 1 <= len(plaintext) <= MAXIMUM_PLAINTEXT_BYTES:
        return None
    if not plaintext.startswith(b"|") or not plaintext.endswith(b"|"):
        return None
    if any(value < 0x20 or value == 0x7F for value in plaintext):
        return None
    segments = plaintext.split(b"|")[1:-1]
    if len(segments) != 1 + 9 + len(_TAIL_FIELDS):
        return None
    try:
        campaign_identifier = segments[0].decode("ascii", errors="strict")
    except UnicodeError:
        return None
    if not _IDENTIFIER.fullmatch(campaign_identifier):
        return None

    ordered: list[tuple[str, str, bytes]] = []
    seen: set[str] = set()
    for segment in segments[1:]:
        raw_key, separator, value = segment.partition(b":")
        try:
            key = raw_key.decode("ascii", errors="strict")
        except UnicodeError:
            return None
        if not separator or not _FIELD_KEY.fullmatch(key):
            return None
        canonical_key = key.casefold()
        if canonical_key in seen:
            return None
        seen.add(canonical_key)
        ordered.append((key, canonical_key, value))

    slots: list[Rc4FullConfigSlot] = []
    cursor = 0
    for index in (1, 2, 3):
        host_key, canonical_host_key, raw_host_bytes = ordered[cursor]
        host_match = _HOST_KEY.fullmatch(host_key)
        if (
            host_match is None
            or int(host_match.group(2)) != index
            or host_match.group(1).casefold() in {"o", "t"}
        ):
            return None
        if ordered[cursor + 1][1] != f"o{index}":
            return None
        if ordered[cursor + 2][1] != f"t{index}":
            return None
        try:
            raw_host = raw_host_bytes.decode("ascii", errors="strict")
            raw_port = ordered[cursor + 1][2].decode("ascii", errors="strict")
            raw_transport = ordered[cursor + 2][2].decode("ascii", errors="strict")
        except UnicodeError:
            return None
        host = normalize_host(raw_host)
        if (
            host is None
            or not raw_port.isdigit()
            or not 1 <= int(raw_port) <= 65535
            or raw_transport not in {"0", "1"}
        ):
            return None
        rendered = render_endpoint(host, int(raw_port))
        if rendered is None:
            return None
        public_endpoint = is_public_host(host)
        slots.append(
            Rc4FullConfigSlot(
                index=index,
                host_field=canonical_host_key,
                host=host,
                port=int(raw_port),
                transport_selector=int(raw_transport),
                endpoint=rendered if public_endpoint else None,
                endpoint_role=(
                    "interactive_c2_candidate"
                    if public_endpoint
                    else "non_public_placeholder"
                ),
            )
        )
        cursor += 3

    tail = ordered[cursor:]
    if tuple(item[1] for item in tail) != _TAIL_FIELDS:
        return None
    fields = {canonical: value for _original, canonical, value in tail}
    try:
        dd = fields["dd"].decode("ascii", errors="strict")
        cl = fields["cl"].decode("ascii", errors="strict")
        bb = fields["bb"].decode("ascii", errors="strict")
        bz = fields["bz"].decode("ascii", errors="strict")
        booleans = {
            name: fields[name].decode("ascii", errors="strict")
            for name in _BOOLEAN_FIELDS
        }
    except UnicodeError:
        return None
    fz = fields["fz"]
    if (
        not dd.isdigit()
        or not 1 <= int(dd) <= 86_400
        or not cl.isdigit()
        or not 1 <= int(cl) <= 86_400
        or not fz
        or len(fz) > 64
        or b"|" in fz
        or not _BUILD_VALUE.fullmatch(bb)
        or not _BUILD_VALUE.fullmatch(bz)
        or any(value not in {"0", "1"} for value in booleans.values())
    ):
        return None

    settings: tuple[tuple[str, object], ...] = (
        ("dd", int(dd)),
        ("cl", int(cl)),
        ("fz_length", len(fz)),
        ("fz_sha256", hashlib.sha256(fz).hexdigest()),
        ("bb", bb),
        ("bz", bz),
        *((name, int(booleans[name])) for name in _BOOLEAN_FIELDS),
    )
    identity = {
        "campaign_identifier_sha256": hashlib.sha256(
            campaign_identifier.encode("utf-8")
        ).hexdigest(),
        "slots": [
            {
                "index": item.index,
                "host_field": item.host_field,
                "host": item.host,
                "port": item.port,
                "transport_selector": item.transport_selector,
            }
            for item in slots
        ],
        "settings": dict(settings),
    }
    encoded_identity = json.dumps(
        identity, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return _ParsedConfig(
        campaign_identifier_sha256=identity["campaign_identifier_sha256"],
        slots=tuple(slots),
        settings=settings,
        identity_sha256=hashlib.sha256(encoded_identity).hexdigest(),
    )


def recover_config(data: bytes) -> Rc4FullConfigRecovery:
    """入力から一意な19文字鍵RC4完全設定を静的復元する。"""

    if not isinstance(data, bytes):
        raise Rc4FullConfigError("入力はbytesでなければなりません")
    if not data or len(data) > MAXIMUM_INPUT_SIZE:
        raise Rc4FullConfigLimitError("入力sizeがRC4設定探索上限外です")

    attempts = 0
    valid: list[_ValidatedCandidate] = []
    seen_spans: set[tuple[int, int, int]] = set()
    for run_start, run_end in _hex_runs(data):
        for key_start, cipher_start, cipher_end in _candidate_spans(
            data, run_start, run_end
        ):
            span = (key_start, cipher_start, cipher_end)
            if span in seen_spans:
                continue
            seen_spans.add(span)
            attempts += 1
            if attempts > MAXIMUM_CANDIDATE_ATTEMPTS:
                raise Rc4FullConfigLimitError("RC4設定候補数が探索上限を超えています")
            key = data[key_start:cipher_start]
            cipher_hex = data[cipher_start:cipher_end]
            if not _is_key(key) or len(cipher_hex) % 2:
                continue
            try:
                ciphertext = bytes.fromhex(cipher_hex.decode("ascii", errors="strict"))
            except (UnicodeError, ValueError):
                continue
            if (
                not MINIMUM_CIPHERTEXT_BYTES
                <= len(ciphertext)
                <= MAXIMUM_CIPHERTEXT_BYTES
            ):
                continue
            plaintext = _rc4(ciphertext, key)
            parsed_orientations = [
                ("direct_after_rc4", _parse_plaintext(plaintext)),
                ("reverse_bytes_after_rc4", _parse_plaintext(plaintext[::-1])),
            ]
            parsed_orientations = [
                (transform, parsed)
                for transform, parsed in parsed_orientations
                if parsed is not None
            ]
            if len(parsed_orientations) != 1:
                continue
            plaintext_transform, parsed = parsed_orientations[0]
            assert parsed is not None
            valid.append(
                _ValidatedCandidate(
                    source_offset=key_start,
                    key_sha256=hashlib.sha256(key).hexdigest(),
                    ciphertext_sha256=hashlib.sha256(ciphertext).hexdigest(),
                    ciphertext_size=len(ciphertext),
                    plaintext_size=len(plaintext),
                    plaintext_transform=plaintext_transform,
                    parsed=parsed,
                )
            )

    if not valid:
        raise Rc4FullConfigError("検証済みRC4完全設定を復元できません")
    identities = {item.parsed.identity_sha256 for item in valid}
    if len(identities) != 1:
        raise Rc4FullConfigError("相反するRC4完全設定候補があります")
    selected = min(valid, key=lambda item: item.source_offset)
    return Rc4FullConfigRecovery(
        source_sha256=hashlib.sha256(data).hexdigest(),
        source_offset=selected.source_offset,
        key_sha256=selected.key_sha256,
        ciphertext_sha256=selected.ciphertext_sha256,
        ciphertext_size=selected.ciphertext_size,
        plaintext_size=selected.plaintext_size,
        plaintext_transform=selected.plaintext_transform,
        campaign_identifier_sha256=selected.parsed.campaign_identifier_sha256,
        slots=selected.parsed.slots,
        settings=selected.parsed.settings,
        configuration_identity_sha256=selected.parsed.identity_sha256,
        observed_candidate_count=attempts,
        validated_candidate_count=len(valid),
    )


def public_recovery_summary(recovery: Rc4FullConfigRecovery) -> dict[str, Any]:
    """raw秘密値を除き、候補設定と証拠境界を返す。"""

    candidate_endpoints = tuple(
        item.endpoint for item in recovery.slots if item.endpoint is not None
    )
    return {
        "schema_version": 1,
        "status": "validated_route_only_rc4_full_config",
        "variant_profile": "proofpoint_2026_full_rc4_config",
        "family_role": "terminal_config_candidate",
        "source_artifact_sha256": recovery.source_sha256,
        "source_offset": recovery.source_offset,
        "decoder": (
            "standard_rc4_19_ascii_key_hex_ciphertext_" + recovery.plaintext_transform
        ),
        "key_length": KEY_LENGTH,
        "key_sha256": recovery.key_sha256,
        "ciphertext_sha256": recovery.ciphertext_sha256,
        "ciphertext_size": recovery.ciphertext_size,
        "plaintext_size": recovery.plaintext_size,
        "campaign_identifier_sha256": recovery.campaign_identifier_sha256,
        "configuration_identity_sha256": recovery.configuration_identity_sha256,
        "candidate_config_recovered": bool(candidate_endpoints),
        "static_config_recovered": False,
        "observed_candidate_count": recovery.observed_candidate_count,
        "validated_candidate_count": recovery.validated_candidate_count,
        "candidate_set_complete": True,
        "config": {
            "endpoint_role": (
                "interactive_c2_candidate"
                if candidate_endpoints
                else "non_public_placeholder_only"
            ),
            "slots": [
                {
                    "index": item.index,
                    "host_field": item.host_field,
                    "host": item.host,
                    "port": item.port,
                    "transport_selector": item.transport_selector,
                    "transport": "tcp" if item.transport_selector == 1 else "udp",
                    "endpoint": item.endpoint,
                    "endpoint_role": item.endpoint_role,
                }
                for item in recovery.slots
            ],
            "settings": dict(recovery.settings),
        },
        "evidence_boundary": {
            "supports_family_attribution": False,
            "terminal_family_confirmed": False,
            "used_for_family_resolution": False,
            "used_for_c2_confirmation": False,
            "config_consumer_code_lineage_proven": False,
            "config_to_connect_send_receive_proven": False,
            "required_additional_evidence": [
                "RC4復号routineと候補dataのcode参照",
                "復号bufferを読むfield parser",
                "同一設定からconnect／send／receiveへ至るdata-flow",
            ],
        },
        "safety": {
            "sample_executed": False,
            "network_contacted": False,
            "raw_key_included": False,
            "raw_ciphertext_included": False,
            "raw_plaintext_included": False,
        },
    }


def probe_rc4_full_config(data: bytes) -> dict[str, Any] | None:
    """検証済み候補がある場合だけ公開要約を返す。上限到達は伝播する。"""

    try:
        recovery = recover_config(data)
    except Rc4FullConfigLimitError:
        raise
    except Rc4FullConfigError:
        return None
    return public_recovery_summary(recovery)
