from __future__ import annotations

import pytest

from unpackers.managed_purerat_cache_frontend import (
    ManagedPureRatCacheFrontendError,
    _consume_dispatch_entry,
    recover_managed_purerat_cache_frontend,
)


def test_dispatch_switch_entry_consumes_direct_state_without_mutating_local() -> None:
    locals_ = {4: 9}
    stack = [27]

    state = _consume_dispatch_entry(30, (10, 20, 30), stack, locals_, 4)

    assert state == 27
    assert stack == []
    assert locals_ == {4: 9}


def test_dispatch_store_and_load_entries_preserve_exact_stack_effect() -> None:
    locals_: dict[int, object] = {}

    stored = _consume_dispatch_entry(10, (10, 20, 30), [41], locals_, 4)
    loaded = _consume_dispatch_entry(20, (10, 20, 30), [], locals_, 4)

    assert stored == 41
    assert loaded == 41
    assert locals_ == {4: 41}


@pytest.mark.parametrize(
    "destination,stack,reason",
    [
        (30, [], "dispatcher_next_state_stack_invalid"),
        (30, [1, 2], "dispatcher_next_state_stack_invalid"),
        (20, [1], "dispatcher_stack_not_empty"),
        (99, [], "dispatcher_entry_invalid"),
    ],
)
def test_dispatch_entries_reject_ambiguous_stack_shapes(
    destination: int,
    stack: list[int],
    reason: str,
) -> None:
    with pytest.raises(ManagedPureRatCacheFrontendError, match=reason):
        _consume_dispatch_entry(destination, (10, 20, 30), stack, {4: 7}, 4)


def test_frontend_rejects_non_managed_input_without_execution_or_network() -> None:
    report, table = recover_managed_purerat_cache_frontend(b"not-a-managed-pe")

    assert table == ()
    assert report["status"] == "rejected"
    assert report["reason"] == "constructor_preflight_rejected"
    assert report["family_attribution_allowed"] is False
    assert report["c2_confirmation_allowed"] is False
    assert report["sample_executed"] is False
    assert report["clr_loaded"] is False
    assert report["network_contacted"] is False
