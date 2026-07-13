#!/usr/bin/env python3
"""Extract normalized AgentTesla or Remcos configuration fields from Triage text."""
from __future__ import annotations
import argparse
import re
from pathlib import Path
from malware_io import write_json

def find_value(lines: list[str], key: str, start: int, window: int = 40) -> str | None:
    try:
        index = lines.index(key, start, min(len(lines), start + window))
    except ValueError:
        return None
    return lines[index + 1] if index + 1 < len(lines) else None

def agenttesla_configs(lines: list[str], lowered: list[str]) -> list[dict]:
    configs = []
    for index, value in enumerate(lowered):
        if value != "protocol" or index + 1 >= len(lines):
            continue
        config = {"protocol": lines[index + 1]}
        for key in ("Host", "Port", "Username", "Password"):
            config[key.lower()] = find_value(lines, key, index + 1)
        if config not in configs:
            configs.append(config)
    return configs

def remcos_configs(lines: list[str], lowered: list[str]) -> list[dict]:
    version = None
    for index, value in enumerate(lowered):
        if value == "version" and index + 1 < len(lines) and re.match(r"\d+\.\d+", lines[index + 1]):
            version = lines[index + 1]
            break
    endpoints = []
    stop = {"Attributes", "audio_folder", "remcos.exe", "copy_folder", "Signatures"}
    for index, value in enumerate(lines):
        if value != "C2":
            continue
        for candidate in lines[index + 1:index + 20]:
            if candidate in stop:
                break
            if re.fullmatch(r"(?:[A-Za-z0-9.-]+|(?:\d{1,3}\.){3}\d{1,3}):\d{1,5}", candidate) and candidate not in endpoints:
                endpoints.append(candidate)
    return [{"version": version, "c2": endpoints}] if version or endpoints else []

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--text", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    lines = [line.strip() for line in args.text.read_text(encoding="utf-8", errors="replace").splitlines() if line.strip()]
    lowered = [line.lower() for line in lines]
    family = "agenttesla" if "agenttesla" in lowered else ("remcos" if "remcos" in lowered else "unknown")
    configs = agenttesla_configs(lines, lowered) if family == "agenttesla" else (remcos_configs(lines, lowered) if family == "remcos" else [])
    result = {"schema_version": 2, "family": family, "configs": configs, "source": str(args.text), "executed_locally": False}
    write_json(args.output, result)
    print({"family": family, "config_count": len(configs)})
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
