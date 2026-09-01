"""MX-Go loopback labで共有する合成protocol契約。"""

from __future__ import annotations

from typing import Any

MAX_REQUEST_BYTES = 65_536
MAX_RESPONSE_BYTES = 65_536


def synthetic_heartbeat() -> dict[str, Any]:
    """実端末情報を含まない固定heartbeatを返す。"""
    return {
        "client_id": "LAB-MXGO-000000000000",
        "mxc_id": "LAB-MXC-000000000000",
        "app_version": "2.0.0-go-portable",
        "license_key": "LAB_ONLY",
        "is_running": False,
        "is_sending": False,
        "sent_total": 0,
        "sent_today": 0,
        "fail_today": 0,
        "lab_emulator": True,
    }


def require_synthetic_heartbeat(value: dict[str, Any]) -> None:
    """固定heartbeatとの完全一致を要求し、実identity混入を拒否する。"""
    if value != synthetic_heartbeat():
        raise ValueError("MX-Go heartbeatが合成profileと一致しません")


def synthetic_action(action: str) -> dict[str, object]:
    """状態遷移fixture用の固定lab actionを返す。"""
    if action not in {"activate", "shutdown", "selftest_result"}:
        raise ValueError(f"未対応のMX-Go lab actionです: {action}")
    return {"lab_emulator": True, "action": action}


def require_synthetic_action(value: dict[str, Any], action: str) -> None:
    """状態遷移requestが固定lab actionと完全一致することを要求する。"""
    if value != synthetic_action(action):
        raise ValueError("MX-Go actionが合成profileと一致しません")
