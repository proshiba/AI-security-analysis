"""解析状態の最小待機防御を、MCPや検体を使わず合成応答で確認する。"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

COMMON = Path(__file__).parents[1] / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

import ghidra_function_batch as target  # noqa: E402

SELECTOR = "/Mock/Explicit/program.bin"


class StatusClient:
    """実I/Oを持たず、指定された合成応答だけを返す。"""

    timeout = 3600

    def __init__(self, clock: list[float], responses: list[object], *, duration: float = 0):
        self.clock = clock
        self.responses = list(responses)
        self.duration = duration
        self.calls: list[tuple[str, dict[str, object]]] = []

    def get(self, endpoint: str, **query: object) -> object:
        assert endpoint == "/analysis_status"
        assert query["program"] == SELECTOR
        assert type(query["transport_timeout"]) is float
        assert query["transport_timeout"] > 0
        self.calls.append((endpoint, query))
        self.clock[0] += self.duration
        value = self.responses.pop(0) if len(self.responses) > 1 else self.responses[0]
        if isinstance(value, BaseException):
            raise value
        return value


@pytest.fixture
def clock(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    value = [0.0]
    monkeypatch.setattr(target.time, "monotonic", lambda: value[0])
    monkeypatch.setattr(target.time, "sleep", lambda seconds: value.__setitem__(0, value[0] + seconds))
    return value


@pytest.mark.parametrize(
    "response",
    [None, [], "", "analyzing: false", {},
     {"analyzing": None}, {"analyzing": 0}, {"analyzing": 1},
     {"analyzing": "false"}, {"analyzing": False, "error": "synthetic failure"},
     {"analyzing": False, "error": ""}, {"analyzing": False, "error": None},
     {"analyzing": False, "error": False}],
)
def test_invalid_status_is_rejected_without_success_or_retry(
    clock: list[float], response: object,
) -> None:
    """欠落・非object・非boolean・本文errorをidle成功へ変換しない。"""
    client = StatusClient(clock, [response])
    with pytest.raises(target.GhidraMcpError):
        target._wait_for_analysis(client, SELECTOR, timeout_seconds=5)
    assert len(client.calls) == 1
    assert clock == [0.0]


@pytest.mark.parametrize("duration", [1.0, 1.01])
def test_idle_response_at_or_after_deadline_is_not_success(
    clock: list[float], duration: float,
) -> None:
    """遅れて戻ったfalse応答でも総deadlineを優先する。"""
    client = StatusClient(clock, [{"analyzing": False, "analyzed": True}], duration=duration)
    with pytest.raises(TimeoutError, match="auto-analysis timeout"):
        target._wait_for_analysis(client, SELECTOR, timeout_seconds=1)
    assert len(client.calls) == 1


def test_idle_response_before_deadline_preserves_unanalyzed_status(clock: list[float]) -> None:
    """idleと完了を分け、analyzed=falseを再解析判断へそのまま返す。"""
    response = {"analyzing": False, "analyzed": False, "should_ask_to_analyze": True}
    client = StatusClient(clock, [response], duration=0.99)
    observed = target._wait_for_analysis(client, SELECTOR, timeout_seconds=1)
    assert observed == response
    assert observed["analyzed"] is False
    assert observed["should_ask_to_analyze"] is True
    assert len(client.calls) == 1


def test_idle_does_not_invent_missing_completion_fields(clock: list[float]) -> None:
    """最小防御はanalyzed等を補完せず、idle観測だけを返す。"""
    client = StatusClient(clock, [{"analyzing": False}])
    assert target._wait_for_analysis(client, SELECTOR, timeout_seconds=1) == {"analyzing": False}


def test_busy_status_waits_and_bounds_sleep_to_deadline(clock: list[float]) -> None:
    """長い既定transport timeoutでも総deadlineを超えるsleepをしない。"""
    client = StatusClient(clock, [{"analyzing": True}], duration=0.4)
    with pytest.raises(TimeoutError, match="auto-analysis timeout"):
        target._wait_for_analysis(client, SELECTOR, timeout_seconds=1)
    assert clock == [1.0]
    assert client.calls == [("/analysis_status", {"program": SELECTOR, "transport_timeout": 1.0})]


def test_busy_to_idle_uses_fresh_response_and_remaining_budget(clock: list[float]) -> None:
    """前のbusy応答を返さず、最後のidle応答と残transport予算を使う。"""
    responses = [{"analyzing": True, "function_count": 7},
                 {"analyzing": True, "function_count": 8},
                 {"analyzing": False, "analyzed": True, "function_count": 4347}]
    client = StatusClient(clock, responses, duration=0.1)
    observed = target._wait_for_analysis(client, SELECTOR, timeout_seconds=5)
    assert observed["function_count"] == 4347
    assert clock[0] == pytest.approx(4.3)
    assert [call[1]["transport_timeout"] for call in client.calls] == pytest.approx([5.0, 2.9, 0.8])


@pytest.mark.parametrize("timeout", [0, -1, True, 0.5])
def test_invalid_total_timeout_makes_no_request(clock: list[float], timeout: object) -> None:
    """不正な総deadlineではMCP requestを開始しない。"""
    client = StatusClient(clock, [{"analyzing": False}])
    with pytest.raises(ValueError):
        target._wait_for_analysis(client, SELECTOR, timeout_seconds=timeout)
    assert client.calls == []


def test_transport_failure_propagates_without_success(clock: list[float]) -> None:
    """通信エラーをidleや空結果へ置き換えない。"""
    error = target.GhidraMcpError("synthetic transport failure")
    client = StatusClient(clock, [error])
    with pytest.raises(target.GhidraMcpError, match="synthetic transport failure"):
        target._wait_for_analysis(client, SELECTOR, timeout_seconds=1)
    assert len(client.calls) == 1
