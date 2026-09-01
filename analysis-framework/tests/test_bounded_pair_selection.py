"""有界pair候補選択器の決定性とslot上限を検証する。"""

from __future__ import annotations

from pathlib import Path
import sys


COMMON = Path(__file__).resolve().parents[1] / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

from bounded_pair_selection import BoundedPairSelector  # noqa: E402


def test_selector_keeps_endpoint_local_best_candidates() -> None:
    selector: BoundedPairSelector[dict[str, object]] = BoundedPairSelector(
        candidate_limit_per_endpoint=2
    )
    pairs = (
        ("a", "b", (3,)),
        ("a", "c", (1,)),
        ("a", "d", (2,)),
        ("b", "c", (0,)),
        ("b", "e", (1,)),
    )
    for left, right, rank in pairs:
        selector.offer(
            left=left,
            right=right,
            rank_key=rank,
            value={"left": left, "right": right, "rank": rank},
        )

    retained = {
        tuple(sorted((str(item["left"]), str(item["right"]))))
        for item in selector.ordered_values()
    }

    assert ("a", "b") not in retained
    assert {("a", "c"), ("a", "d"), ("b", "c"), ("b", "e")} <= retained
    assert selector.offered_count == 5
    assert selector.endpoint_slot_count <= selector.endpoint_count * 2


def test_zero_limit_counts_without_retaining_values() -> None:
    selector: BoundedPairSelector[str] = BoundedPairSelector(
        candidate_limit_per_endpoint=0
    )
    selector.offer(left="a", right="b", rank_key=(0,), value="a-b")

    assert selector.offered_count == 1
    assert selector.endpoint_slot_count == 0
    assert selector.ordered_values() == []
