#!/usr/bin/env python3
"""Local-only MX-Go client emulator for lab check-in and synthetic recipient fetch."""
from __future__ import annotations

import argparse
import hashlib
import json
from urllib.parse import urlparse
from urllib.request import Request, urlopen


def require_loopback(base_url: str) -> str:
    parsed = urlparse(base_url)
    if parsed.scheme != "http" or parsed.hostname not in {"localhost", "127.0.0.1", "::1"}:
        raise ValueError("MX-Go client emulator accepts only loopback HTTP URLs")
    return base_url.rstrip("/")


def heartbeat() -> dict:
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


def run(base_url: str, mode: str, timeout: float = 3.0) -> dict:
    base = require_loopback(base_url)
    result: dict = {"base_url": base, "mode": mode, "network_scope": "loopback_only"}
    if mode in {"checkin", "both"}:
        body = json.dumps(heartbeat(), separators=(",", ":")).encode()
        request = Request(
            base + "/api/v1/heartbeat_direct", data=body,
            headers={"Content-Type": "application/json", "User-Agent": "MX-Go-Lab-Client/1"},
        )
        response = json.loads(urlopen(request, timeout=timeout).read())
        result["checkin"] = {
            "http_ok": response.get("ok") is True,
            "lab_emulator": response.get("lab_emulator") is True,
            "response_keys": sorted(response),
            "real_machine_identity_sent": False,
        }
    if mode in {"recipients", "both"}:
        body = urlopen(base + "/jp01.txt", timeout=timeout).read(65_536)
        values = [line.strip() for line in body.decode(errors="replace").splitlines() if "@" in line]
        result["recipients"] = {
            "count": len(values),
            "sha256": hashlib.sha256(body).hexdigest(),
            "values_redacted": True,
            "all_addresses_use_invalid_tld": bool(values) and all(
                value.rsplit("@", 1)[-1].endswith(".invalid") for value in values
            ),
        }
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default="http://127.0.0.1:5000")
    parser.add_argument("--mode", choices=["checkin", "recipients", "both"], default="both")
    parser.add_argument("--output")
    args = parser.parse_args()
    try:
        result = run(args.base_url, args.mode)
    except ValueError as exc:
        parser.error(str(exc))
    rendered = json.dumps(result, indent=2)
    if args.output:
        from pathlib import Path
        Path(args.output).write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())