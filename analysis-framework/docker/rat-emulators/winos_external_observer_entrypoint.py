#!/usr/bin/env python3
"""最新review済みWinos C2を単発または8時間受信観測するDocker入口。"""

from __future__ import annotations

import argparse
import errno
import json
import os
import sys
import time
import uuid
from pathlib import Path
from typing import Any


FRAMEWORK_COMMON = Path("/opt/winos-external-observer/analysis-framework/common")
TRANSCRIPT_ROOT = Path("/var/lib/rat-emulator/transcripts")
MAXMIND_CACHE_ROOT = Path("/var/cache/rat-emulator/maxmind")
KILL_SWITCH = Path("/run/rat-emulator/armed")
MAXMIND_LICENSE_SECRET = Path("/run/secrets/maxmind_license_key")
PROFILE_ID = "valleyrat-winos-heartbeat-20260810-64-81-30-192-6666"
OBSERVATION_SECONDS = 8 * 60 * 60.0
MAXIMUM_RETRIES = 3
MAXIMUM_CONNECTION_ATTEMPTS = MAXIMUM_RETRIES + 1


class WinosExternalEntrypointError(RuntimeError):
    """Docker入口の固定path、profile、secret違反を表す。"""


def _load_runner() -> Any:
    if str(FRAMEWORK_COMMON) not in sys.path:
        sys.path.insert(0, str(FRAMEWORK_COMMON))
    import run_defensive_rat_emulator

    return run_defensive_rat_emulator


def _load_maxmind_secret() -> None:
    """process環境またはDocker secretから値を安全に受け渡す。"""

    value = os.environ.get("MAXMIND_LICENSE_KEY", "").strip()
    if not value:
        try:
            value = MAXMIND_LICENSE_SECRET.read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise WinosExternalEntrypointError(
                "MaxMind license secretを読み取れません"
            ) from exc
    if not value or len(value) > 512 or "\x00" in value or "\n" in value:
        raise WinosExternalEntrypointError("MaxMind license secretが不正です")
    os.environ["MAXMIND_LICENSE_KEY"] = value


def _new_output_paths() -> tuple[Path, Path]:
    if not TRANSCRIPT_ROOT.is_dir():
        raise WinosExternalEntrypointError("transcript rootがmountされていません")
    token = uuid.uuid4().hex
    private = TRANSCRIPT_ROOT / f"{PROFILE_ID}-{token}"
    public = TRANSCRIPT_ROOT / f"{PROFILE_ID}-{token}-public.json"
    if private.exists() or private.is_symlink() or public.exists() or public.is_symlink():
        raise WinosExternalEntrypointError("新規session pathを確保できません")
    return private, public


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("preflight", "live", "observe", "supervise"))
    parser.add_argument("--profile-id", required=True, choices=(PROFILE_ID,))
    parser.add_argument("--acknowledge-profile")
    parser.add_argument(
        "--duration-seconds",
        type=float,
        default=OBSERVATION_SECONDS,
    )
    parser.add_argument("--maximum-retries", type=int, default=MAXIMUM_RETRIES)
    return parser


def _event(event_type: str, **fields: object) -> None:
    print(
        json.dumps(
            {
                "schema_version": 1,
                "event_type": event_type,
                **fields,
                "sample_executed": False,
                "operation_executed": False,
                "command_reply_sent": False,
            },
            ensure_ascii=False,
            sort_keys=True,
        ),
        flush=True,
    )


def _retryable(exc: BaseException) -> bool:
    if isinstance(exc, (ConnectionError, TimeoutError)):
        return True
    return isinstance(exc, OSError) and getattr(exc, "errno", None) in {
        errno.ECONNREFUSED,
        errno.ECONNRESET,
        errno.ECONNABORTED,
        errno.ETIMEDOUT,
        errno.EHOSTUNREACH,
        errno.ENETUNREACH,
    }


def _observe(runner: Any, *, duration_seconds: float, maximum_retries: int) -> int:
    if type(duration_seconds) is not float or duration_seconds != OBSERVATION_SECONDS:
        raise WinosExternalEntrypointError("観測時間は8時間へ固定されています")
    if maximum_retries != MAXIMUM_RETRIES:
        raise WinosExternalEntrypointError("再接続は3回までへ固定されています")
    started = time.monotonic()
    deadline = started + duration_seconds
    attempts = 0
    retries_used = 0
    final_status = "observation_window_complete"
    _event(
        "observer_started",
        profile_id=PROFILE_ID,
        duration_seconds=duration_seconds,
        maximum_retries=maximum_retries,
    )
    while attempts < MAXIMUM_CONNECTION_ATTEMPTS:
        remaining = deadline - time.monotonic()
        if remaining < 1.0:
            break
        preflight = runner.preflight(PROFILE_ID)
        attempts += 1
        private, public = _new_output_paths()
        _event(
            "connection_attempt",
            attempt=attempts,
            retries_used=retries_used,
            endpoint=preflight.get("endpoint"),
            pinned_ips=preflight.get("pinned_ips"),
            remaining_seconds=remaining,
            preflight_network_used=preflight.get("network_used"),
        )
        try:
            result = runner.run_live_session(
                PROFILE_ID,
                allow_network=True,
                allow_live_c2_emulation=True,
                acknowledged_profile=PROFILE_ID,
                kill_switch_path=KILL_SWITCH,
                private_output_directory=private,
                maxmind_cache_directory=MAXMIND_CACHE_ROOT,
                public_output=public,
                session_duration_seconds=float(remaining),
            )
        except BaseException as exc:
            final_status = type(exc).__name__
            _event(
                "connection_failed",
                attempt=attempts,
                error_type=type(exc).__name__,
                error_number=getattr(exc, "errno", None),
                retryable=_retryable(exc),
            )
            if not _retryable(exc) or attempts >= MAXIMUM_CONNECTION_ATTEMPTS:
                break
        else:
            adapter = result.get("adapter_result")
            status = adapter.get("status") if isinstance(adapter, dict) else None
            final_status = str(status or result.get("stop_reason") or "completed")
            _event(
                "session_completed",
                attempt=attempts,
                status=final_status,
                transcript_root_sha256=result.get("transcript_root_sha256"),
                public_summary_file=public.name,
            )
            if final_status == "observation_window_complete":
                break
            if final_status != "peer_closed" or attempts >= MAXIMUM_CONNECTION_ATTEMPTS:
                break
        retries_used += 1
        cooldown = min(120.0, 30.0 * (2 ** (retries_used - 1)))
        remaining = deadline - time.monotonic()
        if remaining <= cooldown:
            break
        _event(
            "reconnect_scheduled",
            retries_used=retries_used,
            retries_remaining=MAXIMUM_RETRIES - retries_used,
            cooldown_seconds=cooldown,
        )
        time.sleep(cooldown)
    _event(
        "observer_stopped",
        status=final_status,
        attempt_count=attempts,
        retries_used=retries_used,
        elapsed_seconds=max(0.0, time.monotonic() - started),
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    runner = _load_runner()
    if args.mode == "preflight":
        result = runner.preflight(args.profile_id)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    if args.acknowledge_profile != args.profile_id:
        raise WinosExternalEntrypointError(
            "--acknowledge-profileは完全一致profile IDで指定してください"
        )
    if args.mode == "supervise":
        from purerat_long_running_observer import WINOS_SETTINGS, observe_forever

        return observe_forever(runner, settings=WINOS_SETTINGS)
    # 公式取得済みread-only cacheを使うobserverにはlicense keyを渡さない。
    if args.mode == "observe":
        return _observe(
            runner,
            duration_seconds=args.duration_seconds,
            maximum_retries=args.maximum_retries,
        )
    private, public = _new_output_paths()
    result = runner.run_live_session(
        args.profile_id,
        allow_network=True,
        allow_live_c2_emulation=True,
        acknowledged_profile=args.acknowledge_profile,
        kill_switch_path=KILL_SWITCH,
        private_output_directory=private,
        maxmind_cache_directory=MAXMIND_CACHE_ROOT,
        public_output=public,
    )
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (WinosExternalEntrypointError, OSError, RuntimeError, ValueError) as exc:
        print(
            json.dumps(
                {
                    "status": "refused",
                    "error_type": type(exc).__name__,
                    "error": str(exc),
                    "task_executed": False,
                    "operation_executed": False,
                },
                ensure_ascii=False,
            ),
            file=sys.stderr,
        )
        raise SystemExit(2) from None
