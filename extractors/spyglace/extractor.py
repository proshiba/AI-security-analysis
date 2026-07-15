"""Extract SpyGlace configuration and protocol constants without execution."""

from __future__ import annotations

import ipaddress
import re
from typing import Any

from extractors.common import build_result, sha256_bytes
from unpackers.spyglace_unpacker import RecoveredPayload, recover_payload

COMMAND_XOR = 3
CONFIG_XOR = 2
SUBTRACT = 1
KNOWN_COMMANDS = (
    "procspawn",
    "prockill",
    "proclist",
    "diskinfo",
    "download",
    "downfree",
    "upload",
    "cancel",
    "screenupload",
    "screenauto",
    "turn on",
    "turn off",
    "extension",
    "stopextension",
    "cmd.exe /c ",
    "ddir",
    "ddel",
    "uld",
    "attach",
    "detach",
)
KNOWN_VERSIONS = {
    "e5f2c7068ade7b87d24c3b94bc749c351d53609f5fcaa48dce06234beaa2444f": "3.1.15",
    "9394627e9c44cf2226ddf50012e5cf47ccf7d3bd8afa2395c635a93637e23502": "3.1.15",
    "add013bf7ffc8a89789a7fd0ae0ff799c620af9b2755b214880b6a56768fd48c": "3.1.15",
    "c86f319f64d25f23ac29d9b53c9764f06a150634ee8e2d836424d460e5a99b52": "3.1.15",
    "7ab9c634216798d50ce3e19bf1650d6b7c2386150340e48ec3af8b38fd30ae4c": "3.1.15",
    "af24d54d56cbdffe5081c133dae8e8cd54a0d0e2f3059599bc388ef27cf19aa5": "3.1.15",
    "88f58087fc7e7a74455d19c0476954c3bd77d36d0683ab57a6598eb72c4ae37c": "3.1.15",
    "7621e4eff855b2679188b33fe4c71c377f6e2d0b9c25d939452e18992c52e067": "3.1.15",
}
AES_KEY = bytes.fromhex("B0747C82C23359D1342B47A669796989")
AES_IV = bytes.fromhex("21A44712685A8BA42985783B67883999")


def printable_strings(data: bytes, minimum: int = 4) -> list[tuple[int, str, str]]:
    """Return offset, encoding, and value for ASCII and UTF-16LE strings."""
    if minimum < 2:
        raise ValueError("minimum string length must be at least two")
    ascii_pattern = re.compile(rb"[\x20-\x7e]{%d,}" % minimum)
    wide_pattern = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % minimum)
    rows = [
        (match.start(), "ascii", match.group().decode("ascii"))
        for match in ascii_pattern.finditer(data)
    ]
    rows.extend(
        (match.start(), "utf-16le", match.group().decode("utf-16le"))
        for match in wide_pattern.finditer(data)
    )
    return sorted(rows, key=lambda item: (item[0], item[1]))


def decode_add_xor_sub(value: str, xor_key: int, subtract: int = SUBTRACT) -> str:
    """Decode SpyGlace's inverse of ``(plain + subtract) XOR key``."""
    if not 0 <= xor_key <= 255 or not 0 <= subtract <= 255:
        raise ValueError("transform values must fit one byte")
    return bytes((((ord(char) ^ xor_key) - subtract) & 255) for char in value).decode(
        "latin1"
    )


def decoded_strings(data: bytes, xor_key: int) -> list[str]:
    """Decode every static printable string with one SpyGlace transform key."""
    return list(
        dict.fromkeys(
            decode_add_xor_sub(value, xor_key)
            for _, _, value in printable_strings(data)
        )
    )


def _first_valid_ip(values: list[str]) -> str | None:
    """Return the first valid ``ipaddr$$$$`` configuration value."""
    for value in values:
        match = re.search(r"ipaddr\${4}((?:\d{1,3}\.){3}\d{1,3})", value, re.I)
        if not match:
            continue
        try:
            return str(ipaddress.ip_address(match.group(1)))
        except ValueError:
            continue
    return None


def _first_userid(values: list[str]) -> str | None:
    """Return the first bounded ``userid$$$$`` campaign identifier."""
    for value in values:
        match = re.search(r"userid\${4}([A-Za-z0-9_-]{1,64})", value, re.I)
        if match:
            return match.group(1)
    return None


def _request_paths(values: list[str]) -> list[str]:
    """Return ordered, unique ASP request paths from decoded configuration."""
    paths = []
    for value in values:
        for match in re.findall(
            r"(?<![A-Za-z0-9])([A-Za-z0-9]{4,24}\.asp)(?![A-Za-z0-9])", value, re.I
        ):
            if match.lower() not in {item.lower() for item in paths}:
                paths.append(match)
    return paths


def _rc4_key(values: list[str]) -> str | None:
    """Return the decoded 32-byte hexadecimal custom-RC4 key, if present."""
    for value in values:
        for match in re.findall(
            r"(?<![0-9a-f])([0-9a-f]{32})(?![0-9a-f])", value, re.I
        ):
            if len(set(match.lower())) >= 8:
                return match.lower()
    return None


def _mutex(values: list[str]) -> str | None:
    """Return the characteristic raw SpyGlace mutex candidate."""
    for value in values:
        match = re.search(r"\bK[0-9A-Z]{18,31}\b", value)
        if match:
            return match.group(0)
    return None


def extract_config(
    payload: bytes, identity_hashes: tuple[str, ...] = ()
) -> dict[str, Any]:
    """Extract family role, C2, command, crypto, and persistence configuration."""
    raw_values = [value for _, _, value in printable_strings(payload)]
    command_values = decoded_strings(payload, COMMAND_XOR)
    config_values = decoded_strings(payload, CONFIG_XOR)
    c2_ip = _first_valid_ip(config_values)
    userid = _first_userid(config_values)
    paths = _request_paths(config_values)
    commands = [
        command
        for command in KNOWN_COMMANDS
        if any(command in value for value in command_values)
    ]
    dynamic_apis = sorted(
        {
            match
            for value in command_values
            for match in re.findall(r"\bWinHttp[A-Za-z]+", value)
        }
    )
    version = next(
        (KNOWN_VERSIONS[item] for item in identity_hashes if item in KNOWN_VERSIONS),
        None,
    )
    persistence = sorted(
        {
            match.group(0)
            for value in config_values
            for match in re.finditer(
                r"(?:%[A-Za-z]+%|SOFTWARE\\)[^\x00\r\n]{4,160}", value, re.I
            )
            if any(
                token in match.group(0).lower() for token in ("microsoft", "software\\")
            )
        }
    )
    return {
        "variant": "spyglace" if c2_ip and commands else "unrecognized",
        "version": version,
        "c2_ip": c2_ip,
        "userid": userid,
        "request_paths": paths,
        "c2_urls_inferred": [f"http://{c2_ip}/{path}" for path in paths]
        if c2_ip
        else [],
        "transport": "HTTP POST via WinHTTP" if dynamic_apis and paths else None,
        "connectivity_probe": "api.ipify.org"
        if any("api.ipify.org" in value for value in config_values)
        else None,
        "mutex": _mutex(raw_values),
        "commands": commands,
        "dynamic_apis": dynamic_apis,
        "custom_rc4_key_hex": _rc4_key(config_values),
        "download_aes_key_hex": AES_KEY.hex().upper() if AES_KEY in payload else None,
        "download_aes_iv_hex": AES_IV.hex().upper() if AES_IV in payload else None,
        "persistence_strings": persistence,
    }


def extract(data: bytes, name: str = "sample") -> dict:
    """Recover an optional repository envelope and extract SpyGlace config."""
    recovered: RecoveredPayload | None = recover_payload(data)
    payload = recovered.data if recovered else data
    input_hash, payload_hash = sha256_bytes(data), sha256_bytes(payload)
    config = extract_config(payload, (input_hash, payload_hash))
    config.update(
        {
            "source_name": name,
            "envelope_method": recovered.method if recovered else None,
            "payload_sha256": payload_hash,
            "payload_role": recovered.role if recovered else None,
        }
    )
    findings = []
    if config["c2_ip"]:
        findings.append(
            {
                "type": "c2",
                "value": config["c2_ip"],
                "confidence": "confirmed",
                "source": "decoded_static_config",
            }
        )
    if config["userid"]:
        findings.append(
            {
                "type": "campaign_identifier",
                "value": config["userid"],
                "confidence": "confirmed",
                "source": "decoded_static_config",
            }
        )
    for path in config["request_paths"]:
        findings.append(
            {
                "type": "c2_path",
                "value": path,
                "confidence": "confirmed",
                "source": "decoded_static_config",
            }
        )
    return build_result(
        "spyglace",
        data,
        config,
        findings,
        [
            "Inferred C2 URLs combine the statically confirmed IP and request paths; the scheme was not actively verified.",
            "No C2 connection, payload execution, or dynamic debugging was performed.",
        ],
    )
