#!/usr/bin/env python3
"""大規模なpair評価でendpointごとの上位候補だけを有界保持する。"""

from __future__ import annotations

from dataclasses import dataclass
import heapq
from typing import Any, Generic, TypeVar


T = TypeVar("T")
RankKey = tuple[Any, ...]
PairIdentity = tuple[str, str]


@dataclass(slots=True)
class _WorstFirstEntry(Generic[T]):
    """heap先頭が最も低い優先度になる比較entry。"""

    rank_key: RankKey
    identity: PairIdentity
    value: T

    def __lt__(self, other: _WorstFirstEntry[T]) -> bool:
        return (self.rank_key, self.identity) > (other.rank_key, other.identity)


class BoundedPairSelector(Generic[T]):
    """各endpointの上位N件を保持し、pair候補のメモリ増加を制限する。

    callerは同一pairを一度だけofferする。rank_keyは小さい値ほど高優先度とする。
    最終候補はendpoint heapの和集合なので、保持slot数は
    endpoint数×candidate_limit_per_endpointを超えない。
    """

    def __init__(self, *, candidate_limit_per_endpoint: int) -> None:
        if candidate_limit_per_endpoint < 0:
            raise ValueError("candidate_limit_per_endpoint must be non-negative")
        self._limit = candidate_limit_per_endpoint
        self._heaps: dict[str, list[_WorstFirstEntry[T]]] = {}
        self._offered_count = 0

    @property
    def offered_count(self) -> int:
        """評価条件に一致してofferされたpair総数を返す。"""

        return self._offered_count

    @property
    def endpoint_slot_count(self) -> int:
        """現在の全endpoint heapが使用するslot総数を返す。"""

        return sum(len(heap) for heap in self._heaps.values())

    @property
    def endpoint_count(self) -> int:
        """候補を保持しているendpoint数を返す。"""

        return len(self._heaps)

    def offer(
        self,
        *,
        left: str,
        right: str,
        rank_key: RankKey,
        value: T,
    ) -> None:
        """1つのpairを両endpointの有界heapへ提示する。"""

        if not left or not right or left == right:
            raise ValueError("pair endpoints must be non-empty and distinct")
        self._offered_count += 1
        if self._limit == 0:
            return
        identity = tuple(sorted((left, right)))
        entry = _WorstFirstEntry(rank_key=rank_key, identity=identity, value=value)
        for endpoint in identity:
            heap = self._heaps.setdefault(endpoint, [])
            if len(heap) < self._limit:
                heapq.heappush(heap, entry)
                continue
            worst = heap[0]
            if (entry.rank_key, entry.identity) < (worst.rank_key, worst.identity):
                heapq.heapreplace(heap, entry)

    def ordered_values(self) -> list[T]:
        """endpoint heapの和集合を優先順位順で返す。"""

        retained: dict[PairIdentity, _WorstFirstEntry[T]] = {}
        for heap in self._heaps.values():
            for entry in heap:
                previous = retained.get(entry.identity)
                if previous is None or (entry.rank_key, entry.identity) < (
                    previous.rank_key,
                    previous.identity,
                ):
                    retained[entry.identity] = entry
        return [
            entry.value
            for entry in sorted(
                retained.values(),
                key=lambda item: (item.rank_key, item.identity),
            )
        ]
