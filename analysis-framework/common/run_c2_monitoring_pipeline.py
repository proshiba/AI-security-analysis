#!/usr/bin/env python3
"""C2限定観測、MaxMind Geo/AS付与、公開レポート生成を一括実行する。"""

from __future__ import annotations

import argparse
from datetime import UTC, datetime, timedelta
import json
from pathlib import Path
from typing import Any

from maxmind_c2_enrichment import (
    EDITIONS,
    MaxMindDownloadError,
    acquire_database,
    database_metadata,
    enrich_monitoring,
    user_environment,
    write_json,
)
from monitor_recent_c2 import PlanError, monitor, render_markdown, validate_plan
from render_c2_maxmind_section import insert_section, render_maxmind_section

DEFAULT_MAX_BUILD_AGE_HOURS = 24.0


def _maxminddb_module() -> Any:
    try:
        import maxminddb
    except ImportError as exc:
        raise MaxMindDownloadError(
            "geoip2/maxminddbが必要です。requirements-maxmind.txtを導入してください"
        ) from exc
    return maxminddb


def stale_build_epochs(
    build_epochs: dict[str, int],
    *,
    now: datetime,
    max_age_hours: float,
) -> dict[str, bool]:
    """DB build epochが指定時間以上前かをeditionごとに返す。"""
    if now.tzinfo is None:
        raise ValueError("nowはtimezone-awareである必要があります")
    if max_age_hours <= 0:
        raise ValueError("max_age_hoursは正数である必要があります")
    threshold = timedelta(hours=max_age_hours)
    return {
        edition: epoch <= 0 or now.astimezone(UTC) - datetime.fromtimestamp(epoch, UTC) >= threshold
        for edition, epoch in build_epochs.items()
    }


def _build_epochs(acquired: dict[str, tuple[Path, dict[str, Any]]]) -> dict[str, int]:
    maxminddb = _maxminddb_module()
    epochs: dict[str, int] = {}
    for edition, (path, _metadata) in acquired.items():
        with maxminddb.open_database(str(path)) as reader:
            epochs[edition] = int(getattr(reader.metadata(), "build_epoch", 0) or 0)
    return epochs


def acquire_private_databases(
    cache_dir: Path,
    *,
    refresh: bool = False,
    max_build_age_hours: float | None = None,
    now: datetime | None = None,
) -> tuple[dict[str, tuple[Path, dict[str, Any]]], dict[str, Any]]:
    """非公開DBを取得し、必要ならbuild時刻を基準に再取得する。"""
    license_key = user_environment("MAXMIND_LICENSE_KEY")
    if not license_key:
        raise MaxMindDownloadError("MAXMIND_LICENSE_KEYが見つかりません")
    account_id = user_environment("MAXMIND_ACCOUNT_ID") or user_environment("MAXMIND_USER_ID")

    def acquire(force: bool) -> dict[str, tuple[Path, dict[str, Any]]]:
        return {
            edition: acquire_database(
                cache_dir.resolve(),
                edition,
                account_id=account_id,
                license_key=license_key,
                refresh=force,
            )
            for edition in EDITIONS
        }

    acquired = acquire(refresh)
    checked_at = now or datetime.now(UTC)
    before_epochs = _build_epochs(acquired)
    stale_before = (
        stale_build_epochs(
            before_epochs,
            now=checked_at,
            max_age_hours=max_build_age_hours,
        )
        if max_build_age_hours is not None
        else {edition: False for edition in EDITIONS}
    )
    refresh_performed = refresh
    if any(stale_before.values()) and not refresh:
        acquired = acquire(True)
        refresh_performed = True
    after_epochs = _build_epochs(acquired)
    stale_after = (
        stale_build_epochs(
            after_epochs,
            now=checked_at,
            max_age_hours=max_build_age_hours,
        )
        if max_build_age_hours is not None
        else {edition: False for edition in EDITIONS}
    )
    freshness = {
        "schema_version": 1,
        "checked_at_utc": checked_at.astimezone(UTC).isoformat(),
        "checked_before_live_check": max_build_age_hours is not None,
        "maximum_build_age_hours": max_build_age_hours,
        "build_epoch_before_refresh": before_epochs,
        "stale_before_refresh": stale_before,
        "refresh_performed": refresh_performed,
        "refresh_reason": (
            "explicit_operator_request"
            if refresh
            else ("database_build_age_threshold_exceeded" if any(stale_before.values()) else None)
        ),
        "build_epoch_after_refresh": after_epochs,
        "stale_after_refresh": stale_after,
        "latest_available_still_stale": refresh_performed and any(stale_after.values()),
    }
    return acquired, freshness


def enrich_with_acquired_databases(
    monitoring: dict[str, Any],
    acquired: dict[str, tuple[Path, dict[str, Any]]],
    freshness: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    """取得済み非公開DBで監視結果をエンリッチする。"""
    maxminddb = _maxminddb_module()
    city_path, city_acquisition = acquired["GeoLite2-City"]
    asn_path, asn_acquisition = acquired["GeoLite2-ASN"]
    with (
        maxminddb.open_database(str(city_path)) as city_reader,
        maxminddb.open_database(str(asn_path)) as asn_reader,
    ):
        enriched = enrich_monitoring(
            monitoring,
            city_reader,
            asn_reader,
            city_metadata=database_metadata(city_reader, city_path, city_acquisition),
            asn_metadata=database_metadata(asn_reader, asn_path, asn_acquisition),
        )
    enriched["maxmind"]["freshness_policy"] = freshness
    summary = {
        "lookup_count": enriched["maxmind"]["lookup_count"],
        "matched_count": enriched["maxmind"]["matched_count"],
        "city_build_time_utc": enriched["maxmind"]["city_database"]["build_time_utc"],
        "asn_build_time_utc": enriched["maxmind"]["asn_database"]["build_time_utc"],
        "authentication_mode": city_acquisition.get("authentication_mode"),
        "freshness_policy": freshness,
        "license_key_published": False,
        "mmdb_published": False,
    }
    return enriched, summary


def enrich_with_private_databases(
    monitoring: dict[str, Any],
    cache_dir: Path,
    *,
    refresh: bool = False,
    max_build_age_hours: float | None = None,
    now: datetime | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """非公開DBを取得または再利用し、監視結果と公開可能な要約を返す。"""
    acquired, freshness = acquire_private_databases(
        cache_dir,
        refresh=refresh,
        max_build_age_hours=max_build_age_hours,
        now=now,
    )
    return enrich_with_acquired_databases(monitoring, acquired, freshness)


def render_enriched_report(result: dict[str, Any]) -> str:
    """通常のC2監視レポートへMaxMind節を再現可能な形で追加する。"""
    return insert_section(render_markdown(result), render_maxmind_section(result))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--targets", type=Path, required=True)
    parser.add_argument("--output-directory", type=Path, required=True)
    parser.add_argument("--maxmind-cache-dir", type=Path, required=True)
    parser.add_argument("--refresh-maxmind-databases", action="store_true")
    parser.add_argument(
        "--maxmind-max-build-age-hours",
        type=float,
        default=DEFAULT_MAX_BUILD_AGE_HOURS,
        help="ライブチェック前に許容するMaxMind DB build age。既定値は24時間。",
    )
    parser.add_argument("--allow-network", action="store_true")
    args = parser.parse_args()

    try:
        plan = json.loads(args.targets.read_text(encoding="utf-8"))
        validate_plan(plan)
        acquired, freshness = acquire_private_databases(
            args.maxmind_cache_dir,
            refresh=args.refresh_maxmind_databases,
            max_build_age_hours=(args.maxmind_max_build_age_hours if args.allow_network else None),
        )
        result = monitor(plan, allow_network=args.allow_network)
        result, maxmind_summary = enrich_with_acquired_databases(result, acquired, freshness)
    except (OSError, json.JSONDecodeError, PlanError, ValueError, MaxMindDownloadError) as exc:
        parser.error(str(exc))

    args.output_directory.mkdir(parents=True, exist_ok=True)
    results_path = args.output_directory / "monitoring-results.json"
    readme_path = args.output_directory / "README.md"
    write_json(results_path, result)
    readme_path.write_text(render_enriched_report(result), encoding="utf-8")
    print(
        json.dumps(
            {
                "target_count": result["target_count"],
                "state_counts": result["state_counts"],
                "output_directory": str(args.output_directory),
                "network_enabled": args.allow_network,
                "maxmind": maxmind_summary,
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
