#!/usr/bin/env python3
"""完全一致PureRAT profileだけを扱うDocker入口。"""

from __future__ import annotations

import argparse
import json
import os
import sys
import uuid
from pathlib import Path
from typing import Any


PROFILE_ID = "purerat-441-d025a296-direct-tls10-empty-gclass4"
FRAMEWORK_COMMON = Path("/opt/rat-external-observer/analysis-framework/common")
TRANSCRIPT_ROOT = Path("/var/lib/rat-emulator/observations/sessions")
MAXMIND_CACHE_ROOT = Path("/var/cache/rat-emulator/maxmind")
KILL_SWITCH = Path("/run/rat-emulator/armed")
MAXMIND_LICENSE_SECRET = Path("/run/secrets/maxmind_license_key")


class PureRatExternalEntrypointError(RuntimeError):
    """Docker入口の固定profileまたはsecret契約に違反した。"""


def _load_runner() -> Any:
    if str(FRAMEWORK_COMMON) not in sys.path:
        sys.path.insert(0, str(FRAMEWORK_COMMON))
    import run_defensive_rat_emulator

    return run_defensive_rat_emulator


def _load_maxmind_secret() -> None:
    try:
        value = MAXMIND_LICENSE_SECRET.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise PureRatExternalEntrypointError(
            "MaxMind license secretを読み取れません"
        ) from exc
    if not value or len(value) > 512 or "\x00" in value or "\n" in value:
        raise PureRatExternalEntrypointError("MaxMind license secretが不正です")
    os.environ["MAXMIND_LICENSE_KEY"] = value


def _new_output_paths() -> tuple[Path, Path]:
    if not TRANSCRIPT_ROOT.is_dir():
        raise PureRatExternalEntrypointError("session rootがmountされていません")
    token = uuid.uuid4().hex
    private = TRANSCRIPT_ROOT / f"{PROFILE_ID}-{token}"
    public = TRANSCRIPT_ROOT / f"{PROFILE_ID}-{token}-public.json"
    if private.exists() or private.is_symlink() or public.exists() or public.is_symlink():
        raise PureRatExternalEntrypointError("新規session pathを確保できません")
    return private, public


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "mode",
        choices=("preflight", "maxmind-refresh", "live", "observe"),
    )
    parser.add_argument("--profile-id", required=True, choices=(PROFILE_ID,))
    parser.add_argument("--acknowledge-profile")
    parser.add_argument("--base-cooldown-seconds", type=float, default=30.0)
    parser.add_argument("--maximum-cooldown-seconds", type=float, default=900.0)
    parser.add_argument("--maximum-attempts", type=int, default=0)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    runner = _load_runner()
    if args.mode == "preflight":
        result = runner.preflight(args.profile_id)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    if args.mode == "maxmind-refresh":
        _load_maxmind_secret()
        from run_c2_monitoring_pipeline import acquire_private_databases

        _acquired, freshness = acquire_private_databases(
            MAXMIND_CACHE_ROOT,
            refresh=True,
            max_build_age_hours=24.0,
        )
        print(
            json.dumps(
                {
                    "status": "completed",
                    "operation": "maxmind_refresh",
                    "freshness": freshness,
                    "c2_contacted": False,
                    "command_executed": False,
                    "license_key_published": False,
                    "mmdb_published": False,
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        return 0
    if args.acknowledge_profile != PROFILE_ID:
        raise PureRatExternalEntrypointError(
            "--acknowledge-profileは完全一致profile IDで指定してください"
        )
    if args.mode == "observe":
        from purerat_long_running_observer import observe_forever

        return observe_forever(
            runner,
            base_cooldown_seconds=args.base_cooldown_seconds,
            maximum_cooldown_seconds=args.maximum_cooldown_seconds,
            maximum_attempts=args.maximum_attempts,
        )
    private, public = _new_output_paths()
    result = runner.run_live_session(
        PROFILE_ID,
        allow_network=True,
        allow_live_c2_emulation=True,
        acknowledged_profile=PROFILE_ID,
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
    except (PureRatExternalEntrypointError, OSError, RuntimeError, ValueError) as exc:
        print(
            json.dumps(
                {
                    "status": "refused",
                    "error_type": type(exc).__name__,
                    "error": str(exc),
                    "command_executed": False,
                    "operation_executed": False,
                },
                ensure_ascii=False,
            ),
            file=sys.stderr,
        )
        raise SystemExit(2) from None
