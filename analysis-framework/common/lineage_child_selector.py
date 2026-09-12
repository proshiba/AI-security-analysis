#!/usr/bin/env python3
"""完全性を検証した静的lineageだけから後段childを有界選択する。

このモジュールはfilesystemやnetworkへ触れない純粋コアである。artifactはcontainment
側が実byteを再読込して得た ``observed_sha256`` / ``observed_size`` を持ち、edgeは
静的解析器が完全に列挙したsemantic relationだけを受け取る。公開用の情報は
``SelectionResult.public()`` から取得し、内部識別子を含むdataclassを直接公開しない。
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter, defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any, Final, Literal

SCHEMA_VERSION: Final = 1
MAX_DEPTH: Final = 4
MAX_ARTIFACTS: Final = 512
MAX_EDGES: Final = 1_024
MAX_CHILDREN_PER_PARENT: Final = 16
MAX_SELECTED_CHILDREN: Final = 256
MAX_OVERFLOW_COMMITMENT_SAMPLES: Final = 65
MAX_TOTAL_BYTES: Final = 256 * 1024 * 1024
MAX_CHILD_BYTES: Final = 128 * 1024 * 1024

Relation = Literal["script_launch", "pe_import", "pe_literal_load", "resource_decode"]
Status = Literal["complete_selected", "complete_no_executable_child", "partial"]

RELATIONS: Final[frozenset[str]] = frozenset(
    {"script_launch", "pe_import", "pe_literal_load", "resource_decode"}
)
SEED_RELATIONS: Final[frozenset[str]] = frozenset({"script_launch", "resource_decode"})
TRANSITIVE_RELATIONS: Final[frozenset[str]] = frozenset({"pe_import", "pe_literal_load"})
INTEGRITY_STATES: Final[frozenset[str]] = frozenset(
    {"complete", "truncated", "ambiguous", "unknown"}
)
_RELATION_ORDER: Final = {
    "script_launch": 0,
    "resource_decode": 1,
    "pe_import": 2,
    "pe_literal_load": 3,
}
_SHA256_RE: Final = re.compile(r"[0-9a-f]{64}")
_NAME_RE: Final = re.compile(r"[^/\\\x00-\x1f\x7f]{1,255}")
_ADDRESS_RE: Final = re.compile(r"(?:0x[0-9A-Fa-f]{1,16}|[A-Za-z0-9_.:+-]{1,128})")
_ARTIFACT_KEYS: Final = frozenset(
    {
        "sha256",
        "size",
        "observed_sha256",
        "observed_size",
        "path",
        "name",
        "depth",
        "parent_sha256",
    }
)
_EDGE_KEYS: Final = frozenset(
    {
        "relation",
        "source_sha256",
        "source_size",
        "source_parent_sha256",
        "source_path",
        "target_sha256",
        "target_size",
        "target_path",
        "target_name",
        "source_address",
        "integrity",
    }
)


@dataclass(frozen=True, slots=True)
class SelectionPolicy:
    """child選択に適用する変更不能な上限。"""

    max_depth: int = MAX_DEPTH
    max_artifacts: int = MAX_ARTIFACTS
    max_edges: int = MAX_EDGES
    max_children_per_parent: int = MAX_CHILDREN_PER_PARENT
    max_selected_children: int = MAX_SELECTED_CHILDREN
    max_total_bytes: int = MAX_TOTAL_BYTES
    max_child_bytes: int = MAX_CHILD_BYTES

    def __post_init__(self) -> None:
        values = (
            self.max_depth,
            self.max_artifacts,
            self.max_edges,
            self.max_children_per_parent,
            self.max_selected_children,
            self.max_total_bytes,
            self.max_child_bytes,
        )
        if any(isinstance(value, bool) or not isinstance(value, int) or value < 0 for value in values):
            raise ValueError("selection policyの上限は非負整数でなければなりません")
        compile_time_maxima = (
            MAX_DEPTH,
            MAX_ARTIFACTS,
            MAX_EDGES,
            MAX_CHILDREN_PER_PARENT,
            MAX_SELECTED_CHILDREN,
            MAX_TOTAL_BYTES,
            MAX_CHILD_BYTES,
        )
        if any(value > maximum for value, maximum in zip(values, compile_time_maxima, strict=True)):
            raise ValueError("selection policyはcompile-time上限を超えられません")
        if self.max_selected_children > self.max_artifacts:
            raise ValueError("max_selected_childrenはmax_artifacts以下でなければなりません")


@dataclass(frozen=True, slots=True)
class ArtifactRecord:
    """containmentが実byteと照合済みの内部artifact record。"""

    sha256: str
    size: int
    observed_sha256: str
    observed_size: int
    path: str
    name: str
    depth: int
    parent_sha256: str | None


@dataclass(frozen=True, slots=True)
class SemanticEdge:
    """source/target artifactへ一意に結合済みの内部semantic edge。"""

    relation: Relation
    source_sha256: str
    source_size: int
    source_parent_sha256: str | None
    source_path: str | None
    target_sha256: str
    target_size: int
    target_path: str | None
    target_name: str
    source_address: str | None
    integrity: Literal["complete"]
    target_parent_sha256: str | None


@dataclass(frozen=True, slots=True)
class OmittedCommitment:
    """通常commitmentまたは不完全なoverflow sampleを内部保持する。"""

    record_count: int
    complete: bool
    canonicalization: str
    sampled_record_count: int
    value: str

    def public(self) -> dict[str, object]:
        """commitment値を伏せた非相関の公開表現を返す。"""

        return {
            "complete": self.complete,
            "canonicalization": self.canonicalization,
            "sampled_record_count": self.sampled_record_count,
            "observed_record_count": self.record_count,
            "commitment_recorded": True,
            "value_disclosure": "internal_only",
        }


@dataclass(frozen=True, slots=True)
class SelectionResult:
    """内部選択結果と安全な公開projectionを保持する。"""

    status: Status
    selected_sha256: tuple[str, ...]
    selected_artifacts: tuple[ArtifactRecord, ...]
    validated_edges: tuple[SemanticEdge, ...]
    omitted_commitment: OmittedCommitment
    selected_total_size: int
    validated_artifact_count: int
    observed_artifact_count: int
    observed_edge_count: int
    omitted_reason_counts: tuple[tuple[str, int], ...]
    selected_relation_counts: tuple[tuple[str, int], ...]
    unselected_non_seed_edge_count: int
    policy: SelectionPolicy

    @property
    def selected_digests(self) -> tuple[str, ...]:
        """内部routing向けに選択済みdigest列を返す。"""

        return self.selected_sha256

    def public(self) -> dict[str, object]:
        """digest、path、name、addressを含まない公開summaryを返す。"""

        return {
            "schema_version": SCHEMA_VERSION,
            "status": self.status,
            "counts": {
                "observed_artifact_count": self.observed_artifact_count,
                "validated_artifact_count": self.validated_artifact_count,
                "observed_edge_count": self.observed_edge_count,
                "validated_edge_count": len(self.validated_edges),
                "selected_child_count": len(self.selected_sha256),
                "selected_total_size": self.selected_total_size,
                "unselected_non_seed_edge_count": self.unselected_non_seed_edge_count,
                "omitted_record_count": self.omitted_commitment.record_count,
            },
            "selected_relation_counts": dict(self.selected_relation_counts),
            "omitted_reason_counts": dict(self.omitted_reason_counts),
            "omitted_commitment": self.omitted_commitment.public(),
            "limits": {
                "maximum_depth": self.policy.max_depth,
                "maximum_artifacts": self.policy.max_artifacts,
                "maximum_edges": self.policy.max_edges,
                "maximum_children_per_parent": self.policy.max_children_per_parent,
                "maximum_selected_children": self.policy.max_selected_children,
                "maximum_total_bytes": self.policy.max_total_bytes,
                "maximum_child_bytes": self.policy.max_child_bytes,
            },
            "family_attribution_allowed": False,
            "c2_attribution_allowed": False,
            "maliciousness": "not_determined_from_lineage",
            "executed_sample": False,
            "network_contacted": False,
        }


def _is_sequence(value: object) -> bool:
    return isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray))


def _digest(value: object) -> str | None:
    return value if isinstance(value, str) and len(value) == 64 and _SHA256_RE.fullmatch(value) else None


def _size(value: object) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= (1 << 63) - 1:
        return None
    return value


def _depth(value: object) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= (1 << 31) - 1:
        return None
    return value


def _path(value: object) -> str | None:
    if not isinstance(value, str) or not value or len(value) > 1_024 or "\\" in value:
        return None
    path = PurePosixPath(value)
    if path.is_absolute() or value != path.as_posix() or any(part in {"", ".", ".."} for part in path.parts):
        return None
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in value):
        return None
    return value


def _path_key(value: str) -> str:
    """relative pathをWindowsの大小文字非区別semanticsへ正規化する。"""

    return value.casefold()


def _optional_path(value: object) -> tuple[bool, str | None]:
    if value is None:
        return True, None
    normalized = _path(value)
    return normalized is not None, normalized


def _name(value: object) -> str | None:
    return value if isinstance(value, str) and len(value) <= 255 and _NAME_RE.fullmatch(value) else None


def _address(value: object) -> tuple[bool, str | None]:
    if value is None:
        return True, None
    if isinstance(value, str) and len(value) <= 128 and _ADDRESS_RE.fullmatch(value):
        return True, value
    return False, None


def _artifact(value: object) -> tuple[ArtifactRecord | None, str | None]:
    if not isinstance(value, Mapping) or len(value) != len(_ARTIFACT_KEYS) or set(value) != _ARTIFACT_KEYS:
        return None, "invalid_artifact_schema"
    digest = _digest(value.get("sha256"))
    observed_digest = _digest(value.get("observed_sha256"))
    size = _size(value.get("size"))
    observed_size = _size(value.get("observed_size"))
    path = _path(value.get("path"))
    name = _name(value.get("name"))
    depth = _depth(value.get("depth"))
    raw_parent = value.get("parent_sha256")
    parent_digest = None if raw_parent is None else _digest(raw_parent)
    if None in {digest, observed_digest, size, observed_size, path, name, depth}:
        return None, "invalid_artifact_schema"
    if (raw_parent is not None and parent_digest is None) or (depth == 0 and parent_digest is not None):
        return None, "invalid_artifact_schema"
    if depth > 0 and parent_digest is None:
        return None, "invalid_artifact_schema"
    assert isinstance(path, str) and isinstance(name, str)
    if PurePosixPath(path).name.casefold() != name.casefold():
        return None, "invalid_artifact_schema"
    if digest != observed_digest:
        return None, "artifact_digest_mismatch"
    if size != observed_size:
        return None, "artifact_size_mismatch"
    return (
        ArtifactRecord(
            sha256=digest,
            size=size,
            observed_sha256=observed_digest,
            observed_size=observed_size,
            path=path,
            name=name,
            depth=depth,
            parent_sha256=parent_digest,
        ),
        None,
    )


def _edge_shape(value: object) -> tuple[dict[str, Any] | None, str | None]:
    if not isinstance(value, Mapping) or len(value) != len(_EDGE_KEYS) or set(value) != _EDGE_KEYS:
        return None, "invalid_edge_schema"
    relation = value.get("relation")
    if not isinstance(relation, str) or relation not in RELATIONS:
        return None, "unknown_relation"
    integrity = value.get("integrity")
    if not isinstance(integrity, str) or integrity not in INTEGRITY_STATES:
        return None, "invalid_edge_schema"
    source_digest = _digest(value.get("source_sha256"))
    raw_source_parent = value.get("source_parent_sha256")
    source_parent_digest = None if raw_source_parent is None else _digest(raw_source_parent)
    target_digest = _digest(value.get("target_sha256"))
    source_size = _size(value.get("source_size"))
    target_size = _size(value.get("target_size"))
    source_path_ok, source_path = _optional_path(value.get("source_path"))
    target_path_ok, target_path = _optional_path(value.get("target_path"))
    target_name = _name(value.get("target_name"))
    address_ok, source_address = _address(value.get("source_address"))
    if (
        source_digest is None
        or (raw_source_parent is not None and source_parent_digest is None)
        or target_digest is None
        or source_size is None
        or target_size is None
        or not source_path_ok
        or not target_path_ok
        or target_name is None
        or not address_ok
    ):
        return None, "invalid_edge_schema"
    if target_path is not None and PurePosixPath(target_path).name.casefold() != target_name.casefold():
        return None, "invalid_edge_schema"
    if integrity != "complete":
        return None, f"edge_{integrity}"
    return {
        "relation": relation,
        "source_sha256": source_digest,
        "source_size": source_size,
        "source_parent_sha256": source_parent_digest,
        "source_path": source_path,
        "target_sha256": target_digest,
        "target_size": target_size,
        "target_path": target_path,
        "target_name": target_name,
        "source_address": source_address,
        "integrity": integrity,
    }, None


def _artifact_key(item: ArtifactRecord) -> tuple[object, ...]:
    return (item.depth, item.parent_sha256 or "", _path_key(item.path), item.path, item.sha256, item.size)


def _artifact_identity(item: ArtifactRecord) -> tuple[str | None, str, str]:
    return (item.parent_sha256, _path_key(item.path), item.sha256)


def _edge_key(item: SemanticEdge) -> tuple[object, ...]:
    return (
        _RELATION_ORDER[item.relation],
        item.source_parent_sha256 or "",
        item.source_path or "",
        item.source_sha256,
        item.target_parent_sha256 or "",
        item.target_path or "",
        item.target_name,
        item.target_sha256,
        item.source_address or "",
    )


def _source_identity(edge: SemanticEdge) -> tuple[str | None, str, str]:
    assert edge.source_path is not None
    return (edge.source_parent_sha256, _path_key(edge.source_path), edge.source_sha256)


def _target_identity(edge: SemanticEdge) -> tuple[str | None, str, str]:
    assert edge.target_path is not None
    return (edge.target_parent_sha256, _path_key(edge.target_path), edge.target_sha256)


def _depth_compatible(relation: str, source: ArtifactRecord, target: ArtifactRecord) -> bool:
    if relation == "resource_decode":
        return target.depth == source.depth + 1
    if relation == "script_launch":
        return target.depth in {source.depth, source.depth + 1}
    return target.depth == source.depth


def _containment_compatible(relation: str, source: ArtifactRecord, target: ArtifactRecord) -> bool:
    if target.depth == source.depth + 1 and relation in {"script_launch", "resource_decode"}:
        return target.parent_sha256 == source.sha256
    return (
        target.depth == source.depth
        and relation in {"script_launch", "pe_import", "pe_literal_load"}
        and source.parent_sha256 is not None
        and source.parent_sha256 == target.parent_sha256
    )


def _edge_input_value(edge: SemanticEdge) -> dict[str, object]:
    return {key: getattr(edge, key) for key in _EDGE_KEYS}


def _cycle_edge_indexes(edges: Sequence[SemanticEdge]) -> set[int]:
    """semantic graphでcycleを構成するedge indexを反復探索で返す。"""

    adjacency: dict[tuple[str | None, str, str], set[tuple[str | None, str, str]]] = defaultdict(set)
    for edge in edges:
        adjacency[_source_identity(edge)].add(_target_identity(edge))
    cyclic: set[int] = set()
    for index, edge in enumerate(edges):
        source = _source_identity(edge)
        pending = [_target_identity(edge)]
        visited: set[tuple[str | None, str, str]] = set()
        while pending:
            current = pending.pop()
            if current == source:
                cyclic.add(index)
                break
            if current in visited:
                continue
            visited.add(current)
            pending.extend(adjacency.get(current, ()))
    return cyclic


def _bounded_value(value: object, *, depth: int = 0) -> object:
    """未信頼値を縮約し、provider例外時も固定fallbackを返す。"""

    try:
        return _bounded_value_impl(value, depth=depth)
    except Exception:  # noqa: BLE001 - 未信頼providerの例外を公開境界から出さない。
        return {"type": "unreadable", "projection_failed": True}


def _safe_text_fragment(value: str) -> str:
    """surrogateとcontrol文字を置換したbounded JSON文字列を返す。"""

    return "".join(
        character
        if ord(character) >= 0x20 and not 0xD800 <= ord(character) <= 0xDFFF
        else "\ufffd"
        for character in value
    )


def _bounded_value_impl(value: object, *, depth: int = 0) -> object:
    """一定depth・item数・文字数のcommitment材料へ縮約する内部実装。"""

    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        bit_length = value.bit_length()
        if bit_length <= 256:
            return value
        return {"type": "int", "bit_length": bit_length, "value_limited": True}
    if isinstance(value, float):
        return {"type": "float"}
    if isinstance(value, str):
        if len(value) <= 2_048:
            return _safe_text_fragment(value)
        return {
            "type": "str",
            "length": len(value),
            "head": _safe_text_fragment(value[:1_024]),
            "tail": _safe_text_fragment(value[-1_024:]),
        }
    if isinstance(value, (bytes, bytearray)):
        raw_length = len(value)
        if raw_length <= 2_048:
            return {"type": "bytes", "value": bytes(value).hex()}
        return {
            "type": "bytes",
            "length": raw_length,
            "head": bytes(value[:1_024]).hex(),
            "tail": bytes(value[-1_024:]).hex(),
        }
    if depth >= 4:
        return {"type": type(value).__name__, "depth_limited": True}
    if isinstance(value, Mapping):
        limited: list[object] = []
        iterator = iter(value.items())
        for _ in range(33):
            try:
                key, item = next(iterator)
            except StopIteration:
                break
            limited.append(
                [
                    _bounded_value(key, depth=depth + 1),
                    _bounded_value(item, depth=depth + 1),
                ]
            )
        limited.sort(
            key=lambda item: json.dumps(
                item,
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        return {
            "type": "mapping",
            "length": len(value),
            "items": limited[:32],
            "item_limited": len(limited) > 32,
        }
    if _is_sequence(value):
        length = len(value)
        indexes = list(range(min(length, 16)))
        indexes.extend(range(max(16, length - 16), length))
        return {
            "type": "sequence",
            "length": length,
            "items": [
                [index, _bounded_value(value[index], depth=depth + 1)]
                for index in indexes
            ],
            "item_limited": length > 32,
        }
    return {"type": type(value).__name__}


def _token(domain: str, reason: str, value: object) -> str:
    """省略recordを有界処理で公開不能な固定長tokenへ変換する。"""

    try:
        canonical = json.dumps(
            {"domain": domain, "reason": reason, "value": _bounded_value(value)},
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
    except Exception:  # noqa: BLE001 - token生成をtotal functionとして固定する。
        canonical = b'{"canonicalization":"bounded_token_failure_v1"}'
    return hashlib.sha256(canonical).hexdigest()


def _commitment(tokens: list[str], *, record_count: int | None = None) -> OmittedCommitment:
    canonical = "".join(f"{token}\n" for token in sorted(tokens)).encode("ascii")
    observed_count = len(tokens) if record_count is None else record_count
    return OmittedCommitment(
        record_count=observed_count,
        complete=observed_count == len(tokens),
        canonicalization="sorted_sha256_tokens_lineage_child_selector_v1",
        sampled_record_count=len(tokens),
        value=hashlib.sha256(canonical).hexdigest(),
    )


def _overflow_commitment(
    values: Sequence[object], *, domain: str, reason: str, maximum: int, observed_count: int
) -> OmittedCommitment:
    """件数超過入力を絶対scan cap内の決定的sampleとして固定する。"""

    length = observed_count
    if length <= MAX_OVERFLOW_COMMITMENT_SAMPLES:
        indexes = set(range(length))
    else:
        indexes = {0, length // 2, length - 1}
        intervals = MAX_OVERFLOW_COMMITMENT_SAMPLES - 1
        for index in range(MAX_OVERFLOW_COMMITMENT_SAMPLES):
            if len(indexes) >= MAX_OVERFLOW_COMMITMENT_SAMPLES:
                break
            indexes.add(index * (length - 1) // intervals)
    sampled_indexes = sorted(indexes)
    samples = []
    for index in sampled_indexes:
        try:
            value = values[index]
        except Exception:  # noqa: BLE001 - sample読取失敗もbounded evidenceへ変換する。
            value = {"sample_read_failed": True}
        samples.append({"index": index, "token": _token(domain, reason, value)})
    canonical = json.dumps(
        {
            "canonicalization": "bounded_overflow_sample_v1",
            "domain": domain,
            "maximum_count": maximum,
            "maximum_sample_count": MAX_OVERFLOW_COMMITMENT_SAMPLES,
            "observed_count": length,
            "reason": reason,
            "samples": samples,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    return OmittedCommitment(
        record_count=length,
        complete=False,
        canonicalization="bounded_overflow_sample_v1",
        sampled_record_count=len(samples),
        value=hashlib.sha256(canonical).hexdigest(),
    )


def _empty_result(
    *,
    policy: SelectionPolicy,
    artifact_count: int,
    edge_count: int,
    reason: str,
    domain: str,
    values: Sequence[object],
    omitted_record_count: int | None = None,
    commitment: OmittedCommitment | None = None,
) -> SelectionResult:
    tokens = [_token(domain, reason, value) for value in values]
    selected_commitment = commitment or _commitment(tokens, record_count=omitted_record_count)
    return SelectionResult(
        status="partial",
        selected_sha256=(),
        selected_artifacts=(),
        validated_edges=(),
        omitted_commitment=selected_commitment,
        selected_total_size=0,
        validated_artifact_count=0,
        observed_artifact_count=artifact_count,
        observed_edge_count=edge_count,
        omitted_reason_counts=((reason, selected_commitment.record_count),),
        selected_relation_counts=(),
        unselected_non_seed_edge_count=0,
        policy=policy,
    )


def select_lineage_children(
    artifacts: Sequence[object],
    semantic_edges: Sequence[object],
    *,
    policy: SelectionPolicy | None = None,
) -> SelectionResult:
    """完全なsemantic lineageで到達できるchildだけを決定的に選択する。

    ``script_launch`` と ``resource_decode`` はseedである。``pe_import`` と
    ``pe_literal_load`` は既に選択したartifactをsourceに持つ場合だけ推移する。
    schema不正、未知relation、不完全edge、曖昧なtarget、照合不一致、上限超過は
    選択せず、結果を ``partial`` にする。
    """

    selected_policy = policy or SelectionPolicy()
    if not _is_sequence(artifacts) or not _is_sequence(semantic_edges):
        return _empty_result(
            policy=selected_policy,
            artifact_count=0,
            edge_count=0,
            reason="invalid_input_schema",
            domain="input",
            values=[{"artifacts": type(artifacts).__name__, "edges": type(semantic_edges).__name__}],
        )
    try:
        artifact_count = len(artifacts)
        edge_count = len(semantic_edges)
    except Exception:  # noqa: BLE001 - top-level providerのlen例外をfail-closedにする。
        return _empty_result(
            policy=selected_policy,
            artifact_count=0,
            edge_count=0,
            reason="invalid_input_schema",
            domain="input",
            values=[{"artifacts": type(artifacts).__name__, "edges": type(semantic_edges).__name__}],
        )
    if artifact_count > selected_policy.max_artifacts:
        return _empty_result(
            policy=selected_policy,
            artifact_count=artifact_count,
            edge_count=edge_count,
            reason="artifact_limit_exceeded",
            domain="artifact",
            values=[],
            omitted_record_count=artifact_count,
            commitment=_overflow_commitment(
                artifacts,
                domain="artifact",
                reason="artifact_limit_exceeded",
                maximum=selected_policy.max_artifacts,
                observed_count=artifact_count,
            ),
        )
    if edge_count > selected_policy.max_edges:
        return _empty_result(
            policy=selected_policy,
            artifact_count=artifact_count,
            edge_count=edge_count,
            reason="edge_limit_exceeded",
            domain="edge",
            values=[],
            omitted_record_count=edge_count,
            commitment=_overflow_commitment(
                semantic_edges,
                domain="edge",
                reason="edge_limit_exceeded",
                maximum=selected_policy.max_edges,
                observed_count=edge_count,
            ),
        )

    omissions: list[str] = []
    reasons: Counter[str] = Counter()
    parsed_artifacts: list[ArtifactRecord] = []
    raw_artifacts: dict[int, object] = {}
    for index in range(artifact_count):
        try:
            raw = artifacts[index]
        except Exception:  # noqa: BLE001 - 未信頼Sequenceの読取例外を閉じる。
            reason = "invalid_artifact_schema"
            reasons[reason] += 1
            omissions.append(_token("artifact", reason, {"record_read_failed": True}))
            continue
        try:
            item, reason = _artifact(raw)
        except Exception:  # noqa: BLE001 - 未信頼Mapping実装の例外を閉じる。
            item, reason = None, "invalid_artifact_schema"
        if item is None:
            assert reason is not None
            reasons[reason] += 1
            omissions.append(_token("artifact", reason, raw))
            continue
        if item.depth > selected_policy.max_depth:
            reasons["depth_limit"] += 1
            omissions.append(_token("artifact", "depth_limit", raw))
            continue
        parsed_artifacts.append(item)
        raw_artifacts[id(item)] = raw
    parsed_artifacts.sort(key=_artifact_key)

    parsed_by_digest: dict[str, list[ArtifactRecord]] = defaultdict(list)
    for artifact in parsed_artifacts:
        parsed_by_digest[artifact.sha256].append(artifact)
    valid_artifacts = [artifact for artifact in parsed_artifacts if artifact.depth == 0]
    valid_identities = {_artifact_identity(artifact) for artifact in valid_artifacts}
    for depth in range(1, selected_policy.max_depth + 1):
        for artifact in (item for item in parsed_artifacts if item.depth == depth):
            assert artifact.parent_sha256 is not None
            parent_candidates = parsed_by_digest.get(artifact.parent_sha256, ())
            if not parent_candidates:
                reason = "parent_not_found"
            elif len(parent_candidates) != 1:
                reason = "parent_ambiguous"
            elif parent_candidates[0].depth != artifact.depth - 1:
                reason = "parent_depth_mismatch"
            elif _artifact_identity(parent_candidates[0]) not in valid_identities:
                reason = "parent_invalid"
            else:
                reason = None
            if reason is not None:
                reasons[reason] += 1
                omissions.append(_token("artifact", reason, raw_artifacts[id(artifact)]))
                continue
            valid_artifacts.append(artifact)
            valid_identities.add(_artifact_identity(artifact))
    valid_artifacts.sort(key=_artifact_key)

    by_digest: dict[str, list[ArtifactRecord]] = defaultdict(list)
    by_path: dict[str, list[ArtifactRecord]] = defaultdict(list)
    by_name: dict[str, list[ArtifactRecord]] = defaultdict(list)
    for artifact in valid_artifacts:
        by_digest[artifact.sha256].append(artifact)
        by_path[_path_key(artifact.path)].append(artifact)
        by_name[artifact.name.casefold()].append(artifact)

    valid_edges: list[SemanticEdge] = []
    for index in range(edge_count):
        try:
            raw = semantic_edges[index]
        except Exception:  # noqa: BLE001 - 未信頼Sequenceの読取例外を閉じる。
            reason = "invalid_edge_schema"
            reasons[reason] += 1
            omissions.append(_token("edge", reason, {"record_read_failed": True}))
            continue
        try:
            shaped, reason = _edge_shape(raw)
        except Exception:  # noqa: BLE001 - 未信頼Mapping実装の例外を閉じる。
            shaped, reason = None, "invalid_edge_schema"
        if shaped is None:
            assert reason is not None
            reasons[reason] += 1
            omissions.append(_token("edge", reason, raw))
            continue

        source_candidates = [
            item
            for item in by_digest.get(shaped["source_sha256"], ())
            if item.parent_sha256 == shaped["source_parent_sha256"]
        ]
        if shaped["source_path"] is not None:
            source_location_candidates = list(by_path.get(_path_key(shaped["source_path"]), ()))
            source_candidates = [item for item in source_location_candidates if item in source_candidates]
            colliding_source_groups = Counter(
                (item.parent_sha256, _path_key(item.path)) for item in source_location_candidates
            )
            if any(count > 1 for count in colliding_source_groups.values()):
                reason = "source_ambiguous"
                reasons[reason] += 1
                omissions.append(_token("edge", reason, raw))
                continue
        if not source_candidates:
            reason = "source_not_found"
        else:
            reason = None
        if reason is not None:
            reasons[reason] += 1
            omissions.append(_token("edge", reason, raw))
            continue
        source_candidates = [item for item in source_candidates if item.size == shaped["source_size"]]
        if not source_candidates:
            reason = "source_digest_size_mismatch"
            reasons[reason] += 1
            omissions.append(_token("edge", reason, raw))
            continue
        if any(count > 1 for count in Counter(_artifact_identity(item) for item in source_candidates).values()):
            reason = "source_ambiguous"
            reasons[reason] += 1
            omissions.append(_token("edge", reason, raw))
            continue
        if len(source_candidates) != 1:
            reason = "source_ambiguous"
            reasons[reason] += 1
            omissions.append(_token("edge", reason, raw))
            continue

        if shaped["target_path"] is not None:
            target_location_candidates = list(by_path.get(_path_key(shaped["target_path"]), ()))
        else:
            target_location_candidates = list(by_name.get(shaped["target_name"].casefold(), ()))
        if not target_location_candidates:
            reason = "target_not_found"
        else:
            reason = None
        if reason is not None:
            reasons[reason] += 1
            omissions.append(_token("edge", reason, raw))
            continue
        candidate_pairs = [
            (source, target)
            for source in source_candidates
            for target in target_location_candidates
            if _depth_compatible(shaped["relation"], source, target)
            and _containment_compatible(shaped["relation"], source, target)
        ]
        if not candidate_pairs:
            depth_pairs_exist = any(
                _depth_compatible(shaped["relation"], source, target)
                for source in source_candidates
                for target in target_location_candidates
            )
            reason = "cross_container" if depth_pairs_exist else "invalid_depth_transition"
            reasons[reason] += 1
            omissions.append(_token("edge", reason, raw))
            continue

        related_targets = {id(target): target for _, target in candidate_pairs}.values()
        target_collision_key = (
            (lambda item: (item.parent_sha256, _path_key(item.path)))
            if shaped["target_path"] is not None
            else (lambda item: (item.parent_sha256, item.name.casefold()))
        )
        if any(count > 1 for count in Counter(target_collision_key(item) for item in related_targets).values()):
            reason = "target_ambiguous"
            reasons[reason] += 1
            omissions.append(_token("edge", reason, raw))
            continue

        matching_pairs = [
            (source, target)
            for source, target in candidate_pairs
            if target.sha256 == shaped["target_sha256"]
            and target.size == shaped["target_size"]
            and target.name.casefold() == shaped["target_name"].casefold()
        ]
        if not matching_pairs:
            reason = "target_digest_size_mismatch"
            reasons[reason] += 1
            omissions.append(_token("edge", reason, raw))
            continue
        pair_identities = {
            (_artifact_identity(source), _artifact_identity(target)): (source, target)
            for source, target in matching_pairs
        }
        if len(pair_identities) != 1:
            reason = "target_ambiguous" if len({identity[1] for identity in pair_identities}) > 1 else "source_ambiguous"
            reasons[reason] += 1
            omissions.append(_token("edge", reason, raw))
            continue
        source, target = next(iter(pair_identities.values()))
        if _artifact_identity(source) == _artifact_identity(target):
            reason = "self_edge"
            reasons[reason] += 1
            omissions.append(_token("edge", reason, raw))
            continue
        shaped["source_path"] = source.path
        shaped["target_path"] = target.path
        valid_edges.append(
            SemanticEdge(
                **shaped,
                target_parent_sha256=target.parent_sha256,
            )
        )
    valid_edges.sort(key=_edge_key)
    cyclic_indexes = _cycle_edge_indexes(valid_edges)
    if cyclic_indexes:
        retained_edges: list[SemanticEdge] = []
        for index, edge in enumerate(valid_edges):
            if index in cyclic_indexes:
                reasons["cycle"] += 1
                omissions.append(_token("edge", "cycle", _edge_input_value(edge)))
            else:
                retained_edges.append(edge)
        valid_edges = retained_edges

    artifact_by_identity = {_artifact_identity(item): item for item in valid_artifacts}
    selected: dict[tuple[str | None, str, str], ArtifactRecord] = {}
    selected_by_parent: dict[str, set[tuple[str | None, str, str]]] = defaultdict(set)
    selected_relations: Counter[str] = Counter()
    omitted_edge_ids: set[int] = set()
    total_size = 0

    def select(edge: SemanticEdge) -> bool:
        nonlocal total_size
        target_identity = _target_identity(edge)
        target = artifact_by_identity[target_identity]
        if target_identity in selected:
            return False
        raw_edge = _edge_input_value(edge)
        parent = target.parent_sha256
        assert parent is not None
        if target.size > selected_policy.max_child_bytes:
            reason = "child_size_limit"
        elif len(selected_by_parent[parent]) >= selected_policy.max_children_per_parent:
            reason = "per_parent_limit"
        elif len(selected) >= selected_policy.max_selected_children:
            reason = "selected_child_limit"
        elif total_size + target.size > selected_policy.max_total_bytes:
            reason = "total_size_limit"
        else:
            reason = None
        if reason is not None:
            marker = id(edge)
            if marker not in omitted_edge_ids:
                omitted_edge_ids.add(marker)
                reasons[reason] += 1
                omissions.append(_token("edge", reason, raw_edge))
            return False
        selected[target_identity] = target
        selected_by_parent[parent].add(target_identity)
        selected_relations[edge.relation] += 1
        total_size += target.size
        return True

    for edge in valid_edges:
        if edge.relation in SEED_RELATIONS:
            select(edge)

    changed = True
    while changed:
        changed = False
        for edge in valid_edges:
            if edge.relation in TRANSITIVE_RELATIONS and _source_identity(edge) in selected:
                changed = select(edge) or changed

    unselected_non_seed = sum(
        1
        for edge in valid_edges
        if edge.relation in TRANSITIVE_RELATIONS and _source_identity(edge) not in selected
    )
    return SelectionResult(
        status=(
            "partial"
            if reasons
            else "complete_selected"
            if selected
            else "complete_no_executable_child"
        ),
        selected_sha256=tuple(item.sha256 for item in sorted(selected.values(), key=_artifact_key)),
        selected_artifacts=tuple(sorted(selected.values(), key=_artifact_key)),
        validated_edges=tuple(valid_edges),
        omitted_commitment=_commitment(omissions),
        selected_total_size=total_size,
        validated_artifact_count=len(valid_artifacts),
        observed_artifact_count=artifact_count,
        observed_edge_count=edge_count,
        omitted_reason_counts=tuple(sorted(reasons.items())),
        selected_relation_counts=tuple(sorted(selected_relations.items())),
        unselected_non_seed_edge_count=unselected_non_seed,
        policy=selected_policy,
    )


__all__ = [
    "MAX_ARTIFACTS",
    "MAX_CHILDREN_PER_PARENT",
    "MAX_CHILD_BYTES",
    "MAX_DEPTH",
    "MAX_EDGES",
    "MAX_OVERFLOW_COMMITMENT_SAMPLES",
    "MAX_SELECTED_CHILDREN",
    "MAX_TOTAL_BYTES",
    "RELATIONS",
    "SEED_RELATIONS",
    "TRANSITIVE_RELATIONS",
    "ArtifactRecord",
    "OmittedCommitment",
    "SelectionPolicy",
    "SelectionResult",
    "SemanticEdge",
    "select_lineage_children",
]
