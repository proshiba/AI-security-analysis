"""DarkCometのASCII-hex RCDATA設定を実行せずにRC4復号する。"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Mapping

import pefile

from extractors.common import build_result, valid_host
from extractors.profiled_family import extract_family

RCDATA_TYPE_ID = 10
RESOURCE_KEY_BASE = b"#KCMDDC5#-"
RESOURCE_SUFFIX_START = 0x377
RESOURCE_SUFFIX_ITERATIONS = 4
NETWORK_KEY = RESOURCE_KEY_BASE
MAX_RESOURCE_SIZE = 64 * 1024
MAX_RESOURCE_COUNT = 128
MAX_HEX_TEXT_SIZE = MAX_RESOURCE_SIZE * 2
REQUIRED_FIELDS = frozenset({"NETDATA", "PWD"})
CONFIG_FIELDS = frozenset(
    {
        "CHANGEDATE",
        "CHIDED",
        "CHIDEF",
        "COMBOPATH",
        "DIRATTRIB",
        "EDTDATE",
        "EDTPATH",
        "FILEATTRIB",
        "FWB",
        "GENCODE",
        "INSTALL",
        "KEYNAME",
        "MELT",
        "MUTEX",
        "NETDATA",
        "OFFLINEK",
        "PDNS",
        "PERSINST",
        "PWD",
        "SH3",
        "SH4",
        "SID",
    }
)
PROTOCOL_MARKERS = ("IDTYPE", "SERVER", "GetSIN", "infoes")
ASCII_HEX = re.compile(rb"[0-9A-Fa-f]+")
HOST_PORT = re.compile(r"^\s*(.+?)\s*:\s*([0-9]{1,5})\s*$")


class DarkCometConfigError(ValueError):
    """DarkComet設定を安全に復号できない場合の例外。"""


def rc4_crypt(data: bytes, key: bytes) -> bytes:
    """標準RC4を副作用のないバイト変換として適用する。"""

    if not key:
        raise DarkCometConfigError("RC4鍵が空です")
    state = list(range(256))
    j = 0
    for i in range(256):
        j = (j + state[i] + key[i % len(key)]) & 0xFF
        state[i], state[j] = state[j], state[i]
    i = j = 0
    output = bytearray()
    for value in data:
        i = (i + 1) & 0xFF
        j = (j + state[i]) & 0xFF
        state[i], state[j] = state[j], state[i]
        output.append(value ^ state[(state[i] + state[j]) & 0xFF])
    return bytes(output)


def build_resource_key() -> bytes:
    """Ghidraで確認した0x377から4反復のsuffix生成を再現する。"""

    suffix = RESOURCE_SUFFIX_START + RESOURCE_SUFFIX_ITERATIONS - 1
    return RESOURCE_KEY_BASE + str(suffix).encode("ascii")


def decode_resource_value(raw: bytes) -> str:
    """ASCII-hex ciphertextを検証し、resource用RC4鍵で復号する。"""

    encoded = raw.rstrip(b"\x00")
    if (
        not encoded
        or len(encoded) > MAX_HEX_TEXT_SIZE
        or len(encoded) % 2
        or ASCII_HEX.fullmatch(encoded) is None
    ):
        raise DarkCometConfigError("RCDATA値が有界なASCII-hexではありません")
    clear = rc4_crypt(bytes.fromhex(encoded.decode("ascii")), build_resource_key())
    try:
        text = clear.rstrip(b"\x00").decode("ascii")
    except UnicodeDecodeError as exc:
        raise DarkCometConfigError("復号したRCDATA値がASCIIではありません") from exc
    if any(ord(character) < 0x20 or ord(character) > 0x7E for character in text):
        raise DarkCometConfigError("復号したRCDATA値に制御文字があります")
    return text


def _entry_name(entry: object) -> str:
    name = getattr(entry, "name", None)
    if name is not None:
        return str(name)
    structure = getattr(entry, "struct", None)
    return str(getattr(structure, "Id", ""))


def rcdata_resources(data: bytes) -> dict[str, bytes]:
    """PEの名前付きRCDATAだけを件数・サイズ上限付きで返す。"""

    try:
        image = pefile.PE(data=data, fast_load=False)
    except (AttributeError, ValueError, pefile.PEFormatError) as exc:
        raise DarkCometConfigError("入力は解析可能なPEではありません") from exc
    root = getattr(image, "DIRECTORY_ENTRY_RESOURCE", None)
    if root is None:
        raise DarkCometConfigError("PEにresource directoryがありません")

    resources: dict[str, bytes] = {}
    seen = 0
    for type_entry in root.entries:
        type_id = getattr(getattr(type_entry, "struct", None), "Id", None)
        if type_id != RCDATA_TYPE_ID:
            continue
        for name_entry in type_entry.directory.entries:
            seen += 1
            if seen > MAX_RESOURCE_COUNT:
                raise DarkCometConfigError("RCDATA件数が上限を超えました")
            name = _entry_name(name_entry).upper()
            if name not in CONFIG_FIELDS or name in resources:
                continue
            languages = getattr(name_entry.directory, "entries", [])
            if len(languages) != 1:
                raise DarkCometConfigError(
                    f"RCDATA/{name}のlanguage数が一意ではありません"
                )
            record = languages[0].data.struct
            size = int(record.Size)
            if not 0 < size <= MAX_RESOURCE_SIZE:
                raise DarkCometConfigError(f"RCDATA/{name}のsizeが上限外です")
            value = image.get_data(int(record.OffsetToData), size)
            if len(value) != size:
                raise DarkCometConfigError(f"RCDATA/{name}を完全に読めません")
            resources[name] = value
    if not REQUIRED_FIELDS.issubset(resources):
        raise DarkCometConfigError("NETDATAとPWDのRCDATAが揃っていません")
    return resources


def decode_config_resources(resources: Mapping[str, bytes]) -> dict[str, str]:
    """DarkComet設定resource集合をfail-closedで復号する。"""

    normalized = {str(name).upper(): value for name, value in resources.items()}
    if not REQUIRED_FIELDS.issubset(normalized):
        raise DarkCometConfigError("NETDATAとPWDのRCDATAが揃っていません")
    decoded: dict[str, str] = {}
    for name in sorted(CONFIG_FIELDS.intersection(normalized)):
        decoded[name] = decode_resource_value(normalized[name])
    if not decoded.get("NETDATA") or not decoded.get("PWD"):
        raise DarkCometConfigError("NETDATAまたはPWDを復号できません")
    return decoded


def parse_netdata(value: str) -> tuple[list[dict], list[dict]]:
    """NETDATAのhost:port列を正規化し、変更根拠を分離して返す。"""

    endpoints: list[dict] = []
    normalization: list[dict] = []
    seen: set[str] = set()
    for index, raw_token in enumerate(value.split("|")):
        if not raw_token.strip():
            continue
        match = HOST_PORT.fullmatch(raw_token)
        if match is None:
            raise DarkCometConfigError(
                f"NETDATA[{index}]がhost:port形式ではありません"
            )
        raw_host, _, raw_port = raw_token.rpartition(":")
        whitespace_stripped = raw_host.strip()
        dot_stripped = whitespace_stripped.rstrip(".")
        host = dot_stripped.lower()
        port = int(raw_port.strip())
        if not valid_host(host) or not 1 <= port <= 65535:
            raise DarkCometConfigError(
                f"NETDATA[{index}]のhostまたはportが不正です"
            )
        endpoint = f"{host}:{port}"
        if endpoint not in seen:
            seen.add(endpoint)
            endpoints.append(
                {
                    "host": host,
                    "port": port,
                    "endpoint": endpoint,
                    "role": "static_c2_candidate",
                    "source": f"RCDATA/NETDATA[{index}]",
                }
            )
        reasons: list[str] = []
        if raw_host != whitespace_stripped:
            reasons.append("whitespace_removed")
        if whitespace_stripped != dot_stripped:
            reasons.append("trailing_dot_removed")
        if dot_stripped != host:
            reasons.append("case_normalized")
        if reasons:
            normalization.append(
                {
                    "index": index,
                    "original_host": raw_host,
                    "normalized_host": host,
                    "reasons": reasons,
                }
            )
    if not endpoints:
        raise DarkCometConfigError("NETDATAに有効なendpointがありません")
    return endpoints, normalization


def _global_ip(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_global
    except ValueError:
        return False


def parse_pdns(value: str) -> list[dict]:
    """PDNSのdomain:resolver列を補助設定として正規化する。"""

    mappings: list[dict] = []
    for index, raw_token in enumerate(value.split("|")):
        token = raw_token.strip()
        if not token or ":" not in token:
            continue
        domain, resolver = token.rsplit(":", 1)
        domain = domain.strip().lower().rstrip(".")
        resolver = resolver.strip()
        if valid_host(domain) and _global_ip(resolver):
            mappings.append(
                {
                    "domain": domain,
                    "resolver": resolver,
                    "source": f"RCDATA/PDNS[{index}]",
                }
            )
    return mappings


def _protocol_markers(data: bytes) -> list[str]:
    return [
        marker for marker in PROTOCOL_MARKERS if marker.encode("ascii") in data
    ]


def extract(data: bytes, name: str = "sample") -> dict:
    """終端PEなら復号済み設定を返し、それ以外は既存profile判定へ戻す。"""

    try:
        resources = rcdata_resources(data)
        decoded = decode_config_resources(resources)
        endpoints, normalization = parse_netdata(decoded["NETDATA"])
    except DarkCometConfigError:
        return extract_family("darkcomet", data, name)

    markers = _protocol_markers(data)
    endpoint_values = [item["endpoint"] for item in endpoints]
    public_fields = {
        key.lower(): value
        for key, value in decoded.items()
        if key not in {"PWD", "GENCODE"}
    }
    return build_result(
        "darkcomet",
        data,
        {
            "source_name": name,
            "profile": "darkcomet_rcdata_v1",
            "category": "rat",
            "transport": "RC4-encrypted command-oriented TCP",
            "static_config_recovered": True,
            "c2_liveness_confirmed": False,
            "endpoints": endpoint_values,
            "endpoint_records": endpoints,
            "endpoint_normalization": normalization,
            "pdns": parse_pdns(decoded.get("PDNS", "")),
            "settings": public_fields,
            "sensitive_settings": {
                "pwd_present": bool(decoded.get("PWD")),
                "gencode_present": bool(decoded.get("GENCODE")),
                "values_published": False,
            },
            "resource_decryption": {
                "cipher": "RC4",
                "ciphertext_encoding": "ASCII-hex",
                "resource_key_derivation": (
                    "#KCMDDC5#- + decimal(0x377 advanced for 4 iterations)"
                ),
                "derived_suffix": 890,
                "resource_count": len(resources),
            },
            "protocol_analysis": {
                "status": "static_protocol_recovered_live_unverified",
                "protocol_markers": markers,
                "network_cipher": "RC4",
                "network_key": {
                    "encoding": "ascii",
                    "value_hex": NETWORK_KEY.hex(),
                    "length": len(NETWORK_KEY),
                    "password_concatenated": False,
                    "evidence": (
                        "SendDarkCometEncryptedMessage -> "
                        "RC4EncryptAndHexEncodeDarkCometMessage"
                    ),
                },
                "outbound_framing": "ASCII-hex(RC4(plaintext, network_key))",
                "server_first_plaintext": "IDTYPE",
                "passive_confirmation": {
                    "accepted_wire_encodings": ["raw_rc4", "ascii_hex_rc4"],
                    "exact_plaintext": "IDTYPE",
                    "client_data_sent": False,
                },
            },
        },
        [
            {
                "kind": "network.endpoint",
                "value": value,
                "role": "static_c2_candidate",
                "confidence": "confirmed_static_config",
                "source": "darkcomet_rcdata.NETDATA",
            }
            for value in endpoint_values
        ],
        [
            "NETDATAは終端PEのRCDATAから復号した静的設定であり、現在のC2稼働を確認したものではありません。",
            "PWDとGENCODEは検体設定として存在しますが、値を公開結果へ出しません。",
            "通信RC4鍵はPWDを連結せず、resource復号鍵とはsuffixの有無が異なります。",
            "C2候補へ接続せず、能動的なcheck-inも送信していません。",
        ],
    )
