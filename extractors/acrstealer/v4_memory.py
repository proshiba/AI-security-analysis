"""ACRStealer v4 memory profileの公開入口と設定値正規化。"""

from __future__ import annotations

from dataclasses import replace

from . import v4_memory_core as _core

DecodedString = _core.DecodedString
V4MemoryProfile = _core.V4MemoryProfile
PRNG_MARKERS = _core.PRNG_MARKERS
decrypt_string = _core.decrypt_string
_keystream_word = _core._keystream_word


def _select_malware_version(strings: tuple[str, ...]) -> str | None:
    candidates: list[tuple[tuple[bool, int, int], str]] = []
    for text in strings:
        # User-AgentのMozilla/5.0などをmalware版と誤認しない。
        if text.startswith("Mozilla/5.0"):
            continue
        for value in _core.VERSION_RE.findall(text):
            score = (
                "-alpha" in value.lower() or "-beta" in value.lower(),
                value.count("."),
                len(value),
            )
            candidates.append((score, value))
    if not candidates:
        return None
    candidates.sort(reverse=True)
    return candidates[0][1]


def _normalize_dns(profile: V4MemoryProfile) -> tuple[str, ...]:
    exact = {
        value.lower()
        for value in profile.decoded_strings
        if value.lower() in {"cloudflare-dns.com", "dns.google"}
    }
    return tuple(sorted(set(profile.dns_resolvers) | exact))


def extract_v4_memory_profile(data: bytes) -> V4MemoryProfile | None:
    """静的復元結果へversion・DNS識別の誤検知抑止を適用する。"""

    profile = _core.extract_v4_memory_profile(data)
    if profile is None:
        return None
    return replace(
        profile,
        version=_select_malware_version(profile.decoded_strings),
        dns_resolvers=_normalize_dns(profile),
    )


__all__ = [
    "DecodedString",
    "PRNG_MARKERS",
    "V4MemoryProfile",
    "decrypt_string",
    "extract_v4_memory_profile",
]
