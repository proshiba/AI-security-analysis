"""Recover the embedded JSON configuration used by MX-Go builds."""

from __future__ import annotations

import json
import re

from extractors.common import build_result


def embedded_config(data: bytes) -> tuple[dict, int | None]:
    """Find the bounded JSON object containing `control_server`."""
    decoder = json.JSONDecoder()
    markers = [match.start() for match in re.finditer(rb'"control_server"', data)]
    for marker in reversed(markers):
        for start in range(marker - 1, max(-1, marker - 65536), -1):
            if data[start] != 0x7B:
                continue
            try:
                value, _ = decoder.raw_decode(
                    data[start : start + 128000].decode("utf-8", errors="replace")
                )
            except json.JSONDecodeError:
                continue
            if isinstance(value, dict) and "control_server" in value:
                return value, start
    return {}, None


def public_config(value: dict) -> dict:
    """Keep operational settings while removing fields whose names imply secrets."""
    blocked = ("password", "token", "secret", "credential", "api_key")
    return {
        key: item
        for key, item in value.items()
        if not any(word in key.lower() for word in blocked)
    }


def extract(data: bytes, name: str = "sample") -> dict:
    """Extract and redact MX-Go embedded JSON configuration."""
    raw, offset = embedded_config(data)
    config = public_config(raw)
    control = config.get("control_server")
    findings = (
        []
        if not control
        else [
            {
                "kind": "network.url",
                "value": control,
                "role": "control_server",
                "confidence": "confirmed",
                "source": "embedded_json",
            }
        ]
    )
    config.update({"source_name": name, "file_offset": offset})
    return build_result(
        "mx-go",
        data,
        config,
        findings,
        ["Content URLs and control URLs have different infrastructure roles."],
    )
