#!/usr/bin/env python3
"""合成check-inと受信者取得を行うloopback限定MX-Go client。"""

from __future__ import annotations

import argparse
import hashlib
import json
from urllib import error, request

from emulators.common import (
    load_strict_json_object,
    require_loopback_http_base_url,
    require_timeout,
)
from emulators.unclassified.mx_go.protocol import (
    MAX_RESPONSE_BYTES,
    synthetic_heartbeat,
)


class _NoRedirect(request.HTTPRedirectHandler):
    """loopbackから別endpointへのredirectを常に拒否する。"""

    def redirect_request(self, *args: object, **kwargs: object) -> None:
        return None


def require_loopback(base_url: str) -> str:
    """credentialや追加pathのないloopback HTTP base URLを返す。"""
    return require_loopback_http_base_url(base_url, "MX-Go client emulator")


def heartbeat() -> dict[str, object]:
    """後方互換APIとして固定の合成heartbeatを返す。"""
    return synthetic_heartbeat()


def _read_response(
    opener: request.OpenerDirector,
    target: str,
    *,
    timeout: float,
    request_object: request.Request | None = None,
) -> tuple[str, bytes]:
    """redirectを拒否し、HTTP応答を上限付きで読む。"""
    try:
        with opener.open(request_object or target, timeout=timeout) as response:
            content_type = (
                response.headers.get("Content-Type", "").split(";", 1)[0].lower()
            )
            body = response.read(MAX_RESPONSE_BYTES + 1)
    except error.HTTPError as exc:
        if 300 <= exc.code < 400:
            raise ValueError("MX-Go client emulatorはredirectを拒否しました") from exc
        raise ValueError(f"MX-Go labがHTTP {exc.code}を返しました") from exc
    except error.URLError as exc:
        raise ValueError("MX-Go loopback labへ接続できませんでした") from exc
    if len(body) > MAX_RESPONSE_BYTES:
        raise ValueError("MX-Go lab responseがsize上限を超えています")
    return content_type, body


def run(base_url: str, mode: str, timeout: float = 3.0) -> dict[str, object]:
    """固定の合成requestだけをloopbackへ送信し、応答契約を検証する。"""
    base = require_loopback(base_url)
    if mode not in {"checkin", "recipients", "both"}:
        raise ValueError(f"未対応のMX-Go client modeです: {mode}")
    timeout = require_timeout(timeout, label="MX-Go client timeout")
    opener = request.build_opener(request.ProxyHandler({}), _NoRedirect)
    result: dict[str, object] = {
        "base_url": base,
        "mode": mode,
        "network_scope": "loopback_only",
        "redirect_followed": False,
        "proxy_used": False,
    }
    if mode in {"checkin", "both"}:
        body = json.dumps(heartbeat(), sort_keys=True, separators=(",", ":")).encode()
        request_object = request.Request(
            base + "/api/v1/heartbeat_direct",
            data=body,
            headers={
                "Content-Type": "application/json",
                "User-Agent": "MX-Go-Lab-Client/2",
            },
        )
        content_type, response_body = _read_response(
            opener,
            request_object.full_url,
            timeout=timeout,
            request_object=request_object,
        )
        response = load_strict_json_object(
            response_body,
            label="MX-Go heartbeat response",
            maximum_bytes=MAX_RESPONSE_BYTES,
        )
        commands = response.get("commands")
        expected_commands = {
            "do_restart": False,
            "do_exit_mx": False,
            "do_show_ui": False,
        }
        response_validated = (
            content_type == "application/json"
            and set(response)
            == {"lab_emulator", "ok", "active", "commands", "recipients_url"}
            and response.get("ok") is True
            and response.get("lab_emulator") is True
            and isinstance(response.get("active"), bool)
            and commands == expected_commands
            and response.get("recipients_url") == base + "/jp01.txt"
        )
        if not response_validated:
            raise ValueError("MX-Go heartbeat response contractが一致しません")
        result["checkin"] = {
            "http_ok": True,
            "lab_emulator": True,
            "response_validated": True,
            "response_keys": sorted(response),
            "response_bytes": len(response_body),
            "real_machine_identity_sent": False,
        }
    if mode in {"recipients", "both"}:
        content_type, body = _read_response(opener, base + "/jp01.txt", timeout=timeout)
        if content_type != "text/plain":
            raise ValueError("MX-Go recipients responseのContent-Typeが一致しません")
        try:
            lines = body.decode("utf-8", errors="strict").splitlines()
        except UnicodeDecodeError as exc:
            raise ValueError("MX-Go recipients responseがUTF-8ではありません") from exc
        values = [line.strip() for line in lines if line.strip()]
        all_invalid = bool(values) and all(
            value.count("@") == 1 and value.rsplit("@", 1)[-1].endswith(".invalid")
            for value in values
        )
        if not all_invalid:
            raise ValueError("MX-Go recipients responseに非合成addressがあります")
        result["recipients"] = {
            "count": len(values),
            "sha256": hashlib.sha256(body).hexdigest(),
            "response_bytes": len(body),
            "response_validated": True,
            "values_redacted": True,
            "all_addresses_use_invalid_tld": True,
        }
    return result


def main() -> int:
    """CLI引数を読み、loopback限定clientを実行する。"""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default="http://127.0.0.1:5000")
    parser.add_argument(
        "--mode", choices=["checkin", "recipients", "both"], default="both"
    )
    parser.add_argument("--timeout", type=float, default=3.0)
    parser.add_argument("--output")
    args = parser.parse_args()
    try:
        result = run(args.base_url, args.mode, timeout=args.timeout)
    except ValueError as exc:
        parser.error(str(exc))
    rendered = json.dumps(result, ensure_ascii=False, indent=2)
    if args.output:
        from pathlib import Path

        Path(args.output).write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
