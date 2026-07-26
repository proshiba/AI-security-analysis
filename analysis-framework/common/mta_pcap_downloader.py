from __future__ import annotations

"""PCAPアーカイブを台帳に従って取得し、サイズとSHA-256を記録する。"""

import argparse
import hashlib
import json
import os
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path


MANIFEST = Path()
ARCHIVES = Path()
LOG = Path()
USER_AGENT = "AI-security-analysis/1.0 (+offline-PCAP-research)"


def log(message: str) -> None:
    line = f"{datetime.now(timezone.utc).isoformat()} {message}"
    with LOG.open("a", encoding="utf-8") as handle:
        handle.write(line + "\n")
    print(line, flush=True)


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def save(data: dict[str, object]) -> None:
    temporary = MANIFEST.with_suffix(MANIFEST.suffix + ".tmp")
    temporary.write_text(
        json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    os.replace(temporary, MANIFEST)


def main() -> int:
    global MANIFEST, ARCHIVES, LOG

    parser = argparse.ArgumentParser(
        description="台帳に記載された暗号化PCAPアーカイブを取得します。"
    )
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--archives", type=Path, required=True)
    parser.add_argument("--log", type=Path)
    args = parser.parse_args()

    MANIFEST = args.manifest.resolve()
    ARCHIVES = args.archives.resolve()
    LOG = (args.log or MANIFEST.with_name("download.log")).resolve()
    if not MANIFEST.is_file():
        parser.error(f"台帳が見つかりません: {MANIFEST}")

    ARCHIVES.mkdir(parents=True, exist_ok=True)
    LOG.parent.mkdir(parents=True, exist_ok=True)
    data = json.loads(MANIFEST.read_text(encoding="utf-8"))
    items = data.get("items", [])
    if not isinstance(items, list) or not items:
        parser.error("台帳にダウンロード対象がありません")
    total = len(items)
    width = max(2, len(str(total)))
    errors = 0

    for index, item in enumerate(items, 1):
        archive_name = str(item["archive_name"])
        if Path(archive_name).name != archive_name:
            parser.error(f"安全でないアーカイブ名です: {archive_name}")
        target = ARCHIVES / archive_name
        expected_size = item.get("reported_content_length")
        if target.is_file() and (
            not expected_size or target.stat().st_size == expected_size
        ):
            item["download_status"] = "complete"
            item["archive_path"] = str(target)
            item["zip_size"] = target.stat().st_size
            item["zip_sha256"] = digest(target)
            save(data)
            log(f"[{index:0{width}d}/{total}] reuse {target.name} {item['zip_size']}")
            continue

        partial = target.with_suffix(target.suffix + ".part")
        if partial.exists():
            partial.unlink()
        request = urllib.request.Request(
            str(item["archive_url"]), headers={"User-Agent": USER_AGENT}
        )
        try:
            with urllib.request.urlopen(request, timeout=120) as response, partial.open(
                "wb"
            ) as output:
                while chunk := response.read(1024 * 1024):
                    output.write(chunk)
            actual_size = partial.stat().st_size
            if expected_size and actual_size != expected_size:
                raise ValueError(
                    f"size mismatch expected={expected_size} actual={actual_size}"
                )
            os.replace(partial, target)
            item["download_status"] = "complete"
            item["archive_path"] = str(target)
            item["zip_size"] = actual_size
            item["zip_sha256"] = digest(target)
            item["downloaded_at"] = datetime.now(timezone.utc).isoformat()
            item.pop("download_error", None)
            log(f"[{index:0{width}d}/{total}] complete {target.name} {actual_size}")
        except Exception as exc:
            errors += 1
            item["download_status"] = "error"
            item["download_error"] = f"{type(exc).__name__}: {exc}"
            log(f"[{index:0{width}d}/{total}] ERROR {target.name} {type(exc).__name__}")
            if partial.exists():
                partial.unlink()
        save(data)
        time.sleep(0.2)

    completed = sum(item.get("download_status") == "complete" for item in items)
    data["download_summary"] = {
        "requested": total,
        "completed": completed,
        "errors": errors,
        "archives_remain_encrypted": True,
        "sample_executed": False,
        "pcap_replayed": False,
        "network_contacted_for_repository_download_only": True,
    }
    save(data)
    log(f"finished completed={completed} errors={errors}")
    return 0 if completed == total and errors == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
