"""follow-on保持metadata多重集合のcanonical commitmentを構築する。"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from typing import TypeAlias


MetadataIdentity: TypeAlias = tuple[str, str, str, str, int]
_SHA256_RE = re.compile(r"[0-9a-f]{64}")
_DOMAIN = b"AI-security-analysis/follow-on-retained-metadata-multiset/v1\x00"
_MAX_MULTIPLICITY = (1 << 63) - 1


def metadata_identity(value: Mapping[str, object]) -> MetadataIdentity:
    """検証済み保持metadataからcommitment用の不変identityを返す。"""

    digest = value.get("sha256")
    path = value.get("path")
    role = value.get("role")
    kind = value.get("kind")
    size = value.get("size")
    if (
        not isinstance(digest, str)
        or _SHA256_RE.fullmatch(digest) is None
        or any(not isinstance(item, str) or not item for item in (path, role, kind))
        or isinstance(size, bool)
        or not isinstance(size, int)
        or size < 0
    ):
        raise ValueError("保持metadata identityが不正です")
    return digest, path, role, kind, size


def canonical_multiset_commitment(
    counts: Mapping[MetadataIdentity, int],
) -> dict[str, int | str] | None:
    """正の多重度をstreaming hashし、空集合以外の件数とSHA-256を返す。

    各unique identityを辞書順に並べ、UTF-8 canonical JSONとbyte長をdomain
    separated SHA-256へ逐次投入する。多重度分のlistは生成しない。
    """

    total = 0
    for identity, multiplicity in counts.items():
        if (
            not isinstance(identity, tuple)
            or len(identity) != 5
            or isinstance(multiplicity, bool)
            or not isinstance(multiplicity, int)
            or not 1 <= multiplicity <= _MAX_MULTIPLICITY
        ):
            raise ValueError("保持metadata多重集合が不正です")
        normalized_identity = metadata_identity(
            {
                "sha256": identity[0],
                "path": identity[1],
                "role": identity[2],
                "kind": identity[3],
                "size": identity[4],
            }
        )
        if normalized_identity != identity:
            raise ValueError("保持metadata identityがcanonicalではありません")
        if total > _MAX_MULTIPLICITY - multiplicity:
            raise ValueError("保持metadata件数が上限を超えました")
        total += multiplicity
    if total == 0:
        return None

    digest = hashlib.sha256()
    digest.update(_DOMAIN)
    for identity in sorted(counts):
        multiplicity = counts[identity]
        encoded = json.dumps(
            {
                "count": multiplicity,
                "kind": identity[3],
                "path": identity[1],
                "role": identity[2],
                "sha256": identity[0],
                "size": identity[4],
            },
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
    return {"count": total, "sha256": digest.hexdigest()}
