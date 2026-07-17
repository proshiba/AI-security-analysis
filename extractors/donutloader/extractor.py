"""Identify Donut delivery layers and separate them from terminal-family config."""

from __future__ import annotations

import struct
from typing import Any

from extractors.common import build_result, sha256_bytes
from unpackers.donut_unpacker import _pe_extent, decrypt_instance, find_donut_shellcodes, unpack_donut
from unpackers.index_xor_pe_unpacker import find_first_byte_xor_pes


def layer_markers(data: bytes) -> list[str]:
    """Return deterministic delivery-layer markers present in static bytes."""
    markers: list[str] = []
    for label, marker in (
        ("chrd_config", b"CHRD"),
        ("managed_payload_resource", b"PayloadSource.zip"),
        ("portable_executable", b"MZ"),
    ):
        if marker in data:
            markers.append(label)
    if find_donut_shellcodes(data):
        markers.append("strict_donut_shellcode")
    if len(data) <= 16 * 1024 * 1024 and find_first_byte_xor_pes(data):
        markers.append("index_xor_multi_pe")
    return markers


def _donut_metadata(data: bytes) -> list[dict[str, Any]]:
    """Return strict embedded Donut metadata and validated payload hashes."""
    values: list[dict[str, Any]] = []
    for candidate in find_donut_shellcodes(data):
        item: dict[str, Any] = {
            "offset": candidate.offset,
            "stride": candidate.stride,
            "shellcode_sha256": sha256_bytes(candidate.data),
            "shellcode_size": len(candidate.data),
        }
        try:
            instance, layout = decrypt_instance(candidate.data)
            if layout.module >= 0:
                result = unpack_donut(candidate.data)
                item.update(result.metadata)
            else:
                payloads = []
                cursor = 0
                while len(payloads) < 16:
                    offset = instance.find(b"MZ", cursor)
                    if offset < 0:
                        break
                    extent = _pe_extent(instance, offset)
                    if extent:
                        payload = instance[offset : offset + extent]
                        payloads.append(
                            {
                                "sha256": sha256_bytes(payload),
                                "size": len(payload),
                            }
                        )
                        cursor = offset + extent
                    else:
                        cursor = offset + 2
                item.update(
                    layout=layout.name,
                    instance_sha256=sha256_bytes(instance),
                    payloads=payloads,
                )
        except (ValueError, RuntimeError, struct.error) as error:
            item["unpack_error"] = type(error).__name__
        values.append(item)
    return values


def inspect_chain(data: bytes, deep: bool = True) -> dict[str, Any]:
    """Inspect Donut evidence, generic wrappers, and terminal configs separately."""
    from extractors.purehvnc.extractor import extract_direct_config

    markers = layer_markers(data)
    donut = _donut_metadata(data)
    recovered_pes: list[dict[str, Any]] = []
    terminal_configs: list[dict[str, Any]] = []
    chain: dict[str, Any] | None = None

    if deep and "chrd_config" in markers:
        try:
            from unpackers.chrd_donut_unpacker import unpack_chrd_donut

            result = unpack_chrd_donut(data)
            chain = result.metadata
            terminal, confidence = extract_direct_config(result.terminal_payload)
            terminal_configs.append(
                {
                    "family": "purehvnc",
                    "confidence": confidence,
                    "sha256": sha256_bytes(result.terminal_payload),
                    "config": terminal,
                }
            )
        except (ValueError, RuntimeError, OSError) as error:
            chain = {"unpack_error": type(error).__name__}

    if deep and "index_xor_multi_pe" in markers:
        for candidate in find_first_byte_xor_pes(data):
            digest = sha256_bytes(candidate.data)
            recovered_pes.append(
                {
                    "offset": candidate.offset,
                    "stride": candidate.stride,
                    "key": candidate.key,
                    "size": len(candidate.data),
                    "sha256": digest,
                }
            )
            try:
                terminal, confidence = extract_direct_config(candidate.data)
            except ValueError:
                continue
            terminal_configs.append(
                {
                    "family": "purehvnc",
                    "confidence": confidence,
                    "sha256": digest,
                    "config": terminal,
                }
            )

    donut_confirmed = bool(donut or (chain and chain.get("donut_shellcode_sha256")))
    if chain and chain.get("donut_shellcode_sha256"):
        delivery_profile = "chrd_wave_donut"
    elif donut:
        delivery_profile = "embedded_donut"
    elif recovered_pes:
        delivery_profile = "index_xor_multi_pe"
    else:
        delivery_profile = "unrecognized"
    return {
        "layer_markers": markers,
        "delivery_profile": delivery_profile,
        "donut_confirmed": donut_confirmed,
        "donut_candidates": donut,
        "chain": chain,
        "recovered_pe_artifacts": recovered_pes,
        "terminal_configs": terminal_configs,
    }


def extract(data: bytes, name: str = "sample", deep: bool = True) -> dict:
    """Analyze delivery evidence and preserve terminal-family boundaries."""
    analysis = inspect_chain(data, deep=deep)
    endpoints: list[str] = []
    findings: list[dict[str, Any]] = []
    for terminal in analysis["terminal_configs"]:
        for endpoint in terminal["config"].get("endpoints", []):
            if endpoint not in endpoints:
                endpoints.append(endpoint)
                findings.append(
                    {
                        "kind": "network.endpoint",
                        "value": endpoint,
                        "role": "terminal_payload_configured_c2",
                        "confidence": terminal["confidence"],
                        "source": "recovered_terminal_static_config",
                    }
                )
    analysis.update({"source_name": name, "endpoints": endpoints})
    limitations = ["Static extraction only; no payload execution or C2 contact was performed."]
    if not analysis["donut_confirmed"]:
        limitations.append("No strict Donut call-over-instance structure was recovered; a family label alone is not confirmation.")
    return build_result("donutloader", data, analysis, findings, limitations)
