#!/usr/bin/env python3
"""Chrome DevTools ProtocolでClickFix landing pageを安全に実ブラウザ観測する。"""

from __future__ import annotations

import argparse
import base64
import hashlib
import ipaddress
import json
import os
import secrets
import shutil
import socket
import struct
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


CHROME_DEFAULT = Path(r"C:\Program Files\Google\Chrome\Application\chrome.exe")
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
COPY_LABELS = (
    "copy",
    "verify",
    "i am not a robot",
    "i'm not a robot",
    "verification",
    "continue",
    "click to verify",
)


def utc_now() -> str:
    return datetime.now(UTC).isoformat()


def is_public_address(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return bool(address.is_global)


def resolve_public(host: str) -> tuple[bool, list[str], str | None]:
    addresses: list[str] = []
    try:
        for item in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM):
            value = item[4][0]
            if value not in addresses:
                addresses.append(value)
    except OSError as error:
        return False, [], type(error).__name__
    if not addresses:
        return False, [], "no_address"
    if not all(is_public_address(value) for value in addresses):
        return False, addresses, "non_public_address"
    return True, addresses, None


def observation_url(item: dict[str, Any]) -> str:
    explicit = str(item.get("landing_url") or item.get("url") or "").strip()
    if explicit.startswith(("http://", "https://")):
        return explicit
    domain = str(item.get("domain") or "").strip().rstrip(".")
    return f"https://{domain}/"


def atomic_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.replace(temporary, path)


class WebSocket:
    """CDPだけに使う最小WebSocket client。"""

    def __init__(self, url: str, timeout: float = 10.0):
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme != "ws" or not parsed.hostname:
            raise ValueError("localhostのws URLが必要です")
        self.socket = socket.create_connection((parsed.hostname, parsed.port or 80), timeout=timeout)
        self.socket.settimeout(0.25)
        key = base64.b64encode(secrets.token_bytes(16)).decode("ascii")
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        request = (
            f"GET {path} HTTP/1.1\r\nHost: {parsed.hostname}:{parsed.port or 80}\r\n"
            f"Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\n"
            "Sec-WebSocket-Version: 13\r\n\r\n"
        )
        self.socket.sendall(request.encode("ascii"))
        response = bytearray()
        while b"\r\n\r\n" not in response:
            chunk = self.socket.recv(4096)
            if not chunk:
                raise ConnectionError("WebSocket handshakeが切断されました")
            response.extend(chunk)
        if not bytes(response).startswith(b"HTTP/1.1 101"):
            raise ConnectionError(bytes(response[:200]).decode("latin-1", errors="replace"))
        self.buffer = bytearray(bytes(response).split(b"\r\n\r\n", 1)[1])

    def close(self) -> None:
        try:
            self.socket.close()
        except OSError:
            pass

    def _recv_exact(self, length: int) -> bytes:
        while len(self.buffer) < length:
            chunk = self.socket.recv(max(4096, length - len(self.buffer)))
            if not chunk:
                raise ConnectionError("WebSocketが切断されました")
            self.buffer.extend(chunk)
        value = bytes(self.buffer[:length])
        del self.buffer[:length]
        return value

    def recv(self) -> str | None:
        try:
            header = self._recv_exact(2)
        except socket.timeout:
            return None
        first, second = header
        opcode = first & 0x0F
        length = second & 0x7F
        if length == 126:
            length = struct.unpack("!H", self._recv_exact(2))[0]
        elif length == 127:
            length = struct.unpack("!Q", self._recv_exact(8))[0]
        mask = self._recv_exact(4) if second & 0x80 else b""
        payload = self._recv_exact(length)
        if mask:
            payload = bytes(value ^ mask[index % 4] for index, value in enumerate(payload))
        if opcode == 0x8:
            raise ConnectionError("WebSocket close frameを受信しました")
        if opcode == 0x9:
            self._send_frame(payload, opcode=0xA)
            return None
        if opcode not in {0x0, 0x1}:
            return None
        return payload.decode("utf-8", errors="replace")

    def _send_frame(self, payload: bytes, opcode: int = 0x1) -> None:
        mask = secrets.token_bytes(4)
        length = len(payload)
        header = bytearray([0x80 | opcode])
        if length < 126:
            header.append(0x80 | length)
        elif length <= 0xFFFF:
            header.append(0x80 | 126)
            header.extend(struct.pack("!H", length))
        else:
            header.append(0x80 | 127)
            header.extend(struct.pack("!Q", length))
        masked = bytes(value ^ mask[index % 4] for index, value in enumerate(payload))
        self.socket.sendall(bytes(header) + mask + masked)

    def send_json(self, value: dict[str, Any]) -> None:
        self._send_frame(json.dumps(value, separators=(",", ":")).encode("utf-8"))


class CDP:
    def __init__(self, websocket_url: str):
        self.ws = WebSocket(websocket_url)
        self.sequence = 0

    def close(self) -> None:
        self.ws.close()

    def send(self, method: str, params: dict[str, Any] | None = None, timeout: float = 10.0) -> dict[str, Any]:
        self.sequence += 1
        sequence = self.sequence
        self.ws.send_json({"id": sequence, "method": method, "params": params or {}})
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            message = self.ws.recv()
            if not message:
                continue
            value = json.loads(message)
            if value.get("id") == sequence:
                if "error" in value:
                    raise RuntimeError(f"{method}: {value['error']}")
                return value.get("result") or {}
        raise TimeoutError(f"CDP timeout: {method}")

    def pump(self, seconds: float, handler: Any | None = None) -> None:
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            message = self.ws.recv()
            if not message:
                continue
            value = json.loads(message)
            if value.get("method") and handler:
                handler(value)


INTERCEPT_SCRIPT = r"""
(() => {
  const events = [];
  const push = (api, value) => {
    let text = '';
    try { text = String(value ?? ''); } catch (_) {}
    events.push({api, private_value: text, observed_at_utc: new Date().toISOString()});
    return Promise.resolve();
  };
  Object.defineProperty(window, '__clickfixObservation', {value: events, configurable: false});
  try {
    Object.defineProperty(navigator, 'clipboard', {configurable: true, value: {
      writeText: value => push('navigator.clipboard.writeText', value),
      write: items => push('navigator.clipboard.write', JSON.stringify(items)),
      readText: async () => ''
    }});
  } catch (_) {}
  try {
    document.execCommand = function(command) {
      if (String(command).toLowerCase() === 'copy') {
        let selected = '';
        try { selected = String(window.getSelection() || ''); } catch (_) {}
        push('document.execCommand(copy)', selected);
        return true;
      }
      return false;
    };
  } catch (_) {}
  window.addEventListener('copy', event => {
    let value = '';
    try { value = event.clipboardData?.getData('text/plain') || String(window.getSelection() || ''); } catch (_) {}
    push('copy_event', value);
    event.preventDefault();
    event.stopImmediatePropagation();
  }, true);
})();
"""


CLICK_SCRIPT = r"""
(() => {
  const labels = %s;
  const candidates = [...document.querySelectorAll('button,[role="button"],a,input[type="button"]')];
  const clicked = [];
  for (const element of candidates) {
    const text = String(element.innerText || element.value || element.getAttribute('aria-label') || '').trim().toLowerCase();
    if (!text || !labels.some(label => text.includes(label))) continue;
    if (element.closest('form') || String(element.getAttribute('type') || '').toLowerCase() === 'submit') continue;
    const rect = element.getBoundingClientRect();
    const style = getComputedStyle(element);
    if (rect.width <= 0 || rect.height <= 0 || style.visibility === 'hidden' || style.display === 'none') continue;
    if (element.tagName === 'A' && element.href && new URL(element.href, location.href).origin !== location.origin) continue;
    element.click();
    clicked.push(text.slice(0, 160));
    if (clicked.length >= 3) break;
  }
  return clicked;
})()
""" % json.dumps(COPY_LABELS)


STATE_SCRIPT = r"""
(() => ({
  title: document.title,
  final_url: location.href,
  visible_text: String(document.body?.innerText || '').slice(0, 12000),
  clipboard_events: Array.isArray(window.__clickfixObservation) ? window.__clickfixObservation : []
}))()
"""


def _http_json(url: str, timeout: float = 5.0) -> Any:
    with urllib.request.urlopen(url, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


def wait_debugger(port: int, timeout: float = 15.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            _http_json(f"http://127.0.0.1:{port}/json/version", timeout=1)
            return
        except (OSError, urllib.error.URLError, json.JSONDecodeError):
            time.sleep(0.2)
    raise TimeoutError("Chrome DevTools endpointを開始できません")


def new_page(port: int) -> dict[str, Any]:
    request = urllib.request.Request(f"http://127.0.0.1:{port}/json/new?about:blank", method="PUT")
    with urllib.request.urlopen(request, timeout=5) as response:
        return json.loads(response.read().decode("utf-8"))


def lure_markers(text: str) -> list[str]:
    lowered = text.casefold()
    return sorted(
        {
            marker
            for marker in ("captcha", "verify", "verification", "not a robot", "copy", "windows+r", "powershell")
            if marker in lowered
        }
    )


def observe_case(item: dict[str, Any], port: int, timeout: float) -> dict[str, Any]:
    case_id = str(item["case_id"])
    domain = str(item["domain"])
    url = observation_url(item)
    public, addresses, error = resolve_public(domain)
    base = {
        "schema_version": 1,
        "case_id": case_id,
        "domain": domain,
        "observed_at_utc": utc_now(),
        "status": "unreachable",
        "policy": {
            "javascript_executed": False,
            "clipboard_intercepted": False,
            "native_clipboard_write_suppressed": False,
            "command_executed": False,
            "command_pasted": False,
            "credentials_sent": False,
            "form_submitted": False,
            "payload_opened": False,
            "unsafe_request_blocked": False,
        },
        "preflight": {"url": url, "public": public, "addresses": addresses, "error": error},
        "page": {"title": "", "final_url": url, "lure_markers": [], "clicked_labels": []},
        "clipboard_events": [],
        "network": {"requests": [], "blocked": []},
        "observer": {"engine": "Chrome DevTools Protocol", "fallback_reason": "in_app_browser_kernel_unavailable_1344"},
    }
    if not public:
        return base
    page = new_page(port)
    cdp = CDP(str(page["webSocketDebuggerUrl"]))
    requests: list[dict[str, Any]] = []
    blocked: list[dict[str, Any]] = []

    def handle(event: dict[str, Any]) -> None:
        if event.get("method") != "Fetch.requestPaused":
            return
        params = event.get("params") or {}
        request = params.get("request") or {}
        request_id = str(params.get("requestId") or "")
        method = str(request.get("method") or "GET").upper()
        request_url = str(request.get("url") or "")
        parsed = urllib.parse.urlsplit(request_url)
        host = parsed.hostname or ""
        allowed = method in SAFE_METHODS
        reason = None
        resolved: list[str] = []
        if not allowed:
            reason = "unsafe_method"
        elif parsed.scheme not in {"http", "https", "data", "blob"}:
            allowed = False
            reason = "unsupported_scheme"
        elif parsed.scheme in {"http", "https"}:
            allowed, resolved, reason = resolve_public(host)
        record = {
            "url": urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", "")),
            "method": method,
            "resource_type": params.get("resourceType"),
            "public_addresses": resolved,
        }
        cdp.sequence += 1
        if allowed:
            requests.append(record)
            cdp.ws.send_json(
                {"id": cdp.sequence, "method": "Fetch.continueRequest", "params": {"requestId": request_id}}
            )
        else:
            blocked.append({**record, "reason": reason})
            cdp.ws.send_json(
                {
                    "id": cdp.sequence,
                    "method": "Fetch.failRequest",
                    "params": {"requestId": request_id, "errorReason": "BlockedByClient"},
                }
            )

    try:
        cdp.send("Page.enable")
        cdp.send("Runtime.enable")
        cdp.send("Network.enable")
        cdp.send("Browser.setDownloadBehavior", {"behavior": "deny"})
        cdp.send("Page.addScriptToEvaluateOnNewDocument", {"source": INTERCEPT_SCRIPT})
        cdp.send("Fetch.enable", {"patterns": [{"urlPattern": "*", "requestStage": "Request"}]})
        cdp.sequence += 1
        cdp.ws.send_json({"id": cdp.sequence, "method": "Page.navigate", "params": {"url": url}})
        deadline = time.monotonic() + timeout
        load_seen = False
        while time.monotonic() < deadline:
            message = cdp.ws.recv()
            if not message:
                continue
            value = json.loads(message)
            if value.get("method") == "Fetch.requestPaused":
                handle(value)
            if value.get("method") == "Page.loadEventFired":
                load_seen = True
                break
        cdp.pump(2.0, handle)
        clicked_result = cdp.send("Runtime.evaluate", {"expression": CLICK_SCRIPT, "returnByValue": True})
        clicked = ((clicked_result.get("result") or {}).get("value")) or []
        cdp.pump(2.0, handle)
        state_result = cdp.send("Runtime.evaluate", {"expression": STATE_SCRIPT, "returnByValue": True})
        state = ((state_result.get("result") or {}).get("value")) or {}
        visible = str(state.get("visible_text") or "")
        base["status"] = "ok" if load_seen else "blocked"
        base["policy"].update(
            {
                "javascript_executed": True,
                "clipboard_intercepted": True,
                "native_clipboard_write_suppressed": True,
                "unsafe_request_blocked": bool(blocked),
            }
        )
        base["page"] = {
            "title": str(state.get("title") or "")[:500],
            "final_url": str(state.get("final_url") or url),
            "lure_markers": lure_markers(visible),
            "visible_text_sha256": hashlib.sha256(visible.encode("utf-8")).hexdigest(),
            "visible_text_length": len(visible),
            "clicked_labels": [str(value)[:160] for value in clicked],
        }
        base["clipboard_events"] = [
            {
                "api": str(event.get("api") or "unknown"),
                "private_value": str(event.get("private_value") or ""),
                "observed_at_utc": event.get("observed_at_utc"),
            }
            for event in state.get("clipboard_events") or []
            if isinstance(event, dict)
        ]
        base["network"] = {"requests": requests[:500], "blocked": blocked[:200]}
    except (OSError, RuntimeError, TimeoutError, ValueError, json.JSONDecodeError, ConnectionError) as exc:
        base["status"] = "error"
        base["error"] = {"type": type(exc).__name__, "message": str(exc)[:500]}
        base["network"] = {"requests": requests[:500], "blocked": blocked[:200]}
    finally:
        try:
            cdp.send("Page.close", timeout=2)
        except Exception:
            pass
        cdp.close()
    return base


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--selection", type=Path, required=True)
    parser.add_argument("--private-output", type=Path, required=True)
    parser.add_argument("--chrome", type=Path, default=CHROME_DEFAULT)
    parser.add_argument("--port", type=int, default=9227)
    parser.add_argument("--timeout", type=float, default=15.0)
    parser.add_argument("--limit", type=int, default=50)
    arguments = parser.parse_args()
    selection = json.loads(arguments.selection.resolve().read_text(encoding="utf-8"))
    items = list(selection.get("selected") or [])[: arguments.limit]
    if not items:
        raise SystemExit("selectionに対象caseがありません")
    chrome = arguments.chrome.resolve()
    if not chrome.is_file():
        raise SystemExit(f"Chromeがありません: {chrome}")
    private_output = arguments.private_output.resolve()
    private_output.mkdir(parents=True, exist_ok=True)
    user_data = Path(tempfile.mkdtemp(prefix="clickfix-browser-", dir=str(private_output)))
    process = subprocess.Popen(
        [
            str(chrome),
            "--headless=new",
            f"--remote-debugging-port={arguments.port}",
            f"--user-data-dir={user_data}",
            "--disable-extensions",
            "--disable-background-networking",
            "--disable-component-update",
            "--disable-sync",
            "--no-first-run",
            "--no-default-browser-check",
            "--disable-features=Translate,OptimizationHints,MediaRouter",
            "about:blank",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    results: list[dict[str, Any]] = []
    try:
        wait_debugger(arguments.port)
        for index, item in enumerate(items, 1):
            result = observe_case(item, arguments.port, arguments.timeout)
            target = private_output / "cases" / str(item["case_id"]) / "browser-observation.json"
            atomic_json(target, result)
            results.append(
                {
                    "case_id": item["case_id"],
                    "status": result["status"],
                    "clipboard_events": len(result["clipboard_events"]),
                }
            )
            print(json.dumps({"index": index, **results[-1]}, ensure_ascii=False), flush=True)
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
        shutil.rmtree(user_data, ignore_errors=True)
    print(
        json.dumps(
            {
                "attempted": len(results),
                "status_counts": {
                    status: sum(item["status"] == status for item in results)
                    for status in sorted({item["status"] for item in results})
                },
                "clipboard_events": sum(item["clipboard_events"] for item in results),
                "command_executed": False,
            },
            ensure_ascii=False,
        )
    )
    return 0 if len(results) == len(items) else 1


if __name__ == "__main__":
    raise SystemExit(main())
