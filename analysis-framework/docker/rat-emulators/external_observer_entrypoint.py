#!/usr/bin/env python3
"""固定profileだけで外部RAT observerを1 session起動するDocker入口。"""

from __future__ import annotations

import argparse
import json
import os
import sys
import uuid
from pathlib import Path
from typing import Any


FRAMEWORK_COMMON = Path("/opt/rat-external-observer/analysis-framework/common")
TRANSCRIPT_ROOT = Path("/var/lib/rat-emulator/transcripts")
MAXMIND_CACHE_ROOT = Path("/var/cache/rat-emulator/maxmind")
KILL_SWITCH = Path("/run/rat-emulator/armed")
MAXMIND_LICENSE_SECRET = Path("/run/secrets/maxmind_license_key")

# endpointはCLIや環境変数から受け取らず、検証済みregistryの完全一致profileへ固定する。
ALLOWED_EXTERNAL_PROFILES = frozenset({"valleyrat-n520-host-d11e793-9999"})


class ExternalObserverEntrypointError(RuntimeError):
    """Docker入口の固定pathまたはsecret契約に違反した。"""


def _load_runner() -> Any:
    if str(FRAMEWORK_COMMON) not in sys.path:
        sys.path.insert(0, str(FRAMEWORK_COMMON))
    import run_defensive_rat_emulator

    return run_defensive_rat_emulator


def _load_maxmind_secret() -> None:
    """Docker inspectへ値を出さず、mount済みsecretをprocess環境へ渡す。"""

    try:
        value = MAXMIND_LICENSE_SECRET.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise ExternalObserverEntrypointError(
            "MaxMind license secretを読み取れません"
        ) from exc
    if not value or len(value) > 512 or "\x00" in value or "\n" in value:
        raise ExternalObserverEntrypointError("MaxMind license secretが不正です")
    os.environ["MAXMIND_LICENSE_KEY"] = value


def _new_output_paths(profile_id: str) -> tuple[Path, Path]:
    if not TRANSCRIPT_ROOT.is_dir():
        raise ExternalObserverEntrypointError("transcript rootがmountされていません")
    token = uuid.uuid4().hex
    private = TRANSCRIPT_ROOT / f"{profile_id}-{token}"
    public = TRANSCRIPT_ROOT / f"{profile_id}-{token}-public.json"
    if private.exists() or private.is_symlink() or public.exists() or public.is_symlink():
        raise ExternalObserverEntrypointError("新規session pathを確保できません")
    return private, public


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("preflight", "maxmind-refresh", "live"))
    parser.add_argument("--profile-id", required=True, choices=sorted(ALLOWED_EXTERNAL_PROFILES))
    parser.add_argument("--acknowledge-profile")
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
    if args.acknowledge_profile != args.profile_id:
        raise ExternalObserverEntrypointError(
            "--acknowledge-profileは完全一致profile IDで指定してください"
        )
    _load_maxmind_secret()
    private, public = _new_output_paths(args.profile_id)
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
    except (ExternalObserverEntrypointError, OSError, RuntimeError, ValueError) as exc:
        print(
            json.dumps(
                {
                    "status": "refused",
                    "error_type": type(exc).__name__,
                    "error": str(exc),
                    "command_executed": False,
                },
                ensure_ascii=False,
            ),
            file=sys.stderr,
        )
        raise SystemExit(2) from None
