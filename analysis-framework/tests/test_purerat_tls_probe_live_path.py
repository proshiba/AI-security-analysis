"""PureRAT probeの実TLS経路を、loopbackの模擬C2に対して検証する。

`test_purerat_tls_probe.py` は `tls_handshaker` を差し替えているため、実際に
TLSを張る `_perform_tls_handshake` を一度も実行していない。ここでは
文書どおりに振る舞う模擬C2(4 byte preludeを読んでから同じsocketをTLSへ昇格)
を立て、probeの本物のコードを通す。

安全境界を保つため、
- resolver は「globalなIPが返ってきた」ように見せかけてprobeの判定を通す
- connector は実際にはloopbackの模擬サーバへ繋ぐ
としている。テストは外部へ一切接続しない。
"""

from __future__ import annotations

import hashlib
import socket
import ssl
import subprocess
import sys
import threading
from pathlib import Path
from typing import Any

import pytest


COMMON = Path(__file__).parents[1] / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

from purerat_tls_probe import (  # noqa: E402
    PURE_PROTOCOL_PRELUDE,
    probe_reviewed_purerat_tls,
)


# 実際には接続しない。probeのglobal IP判定を通すためだけの値。
FAKE_GLOBAL_IP = "45.66.228.114"

# 到達しなかった場合でも常にFalseでなければならない安全フラグ。
SAFETY_FLAGS = (
    "c2_confirmed",
    "victim_metadata_sent",
    "registration_attempted",
    "task_poll_attempted",
    "task_executed",
    "payload_download_attempted",
    "stage_requested",
    "operation_command_sent",
)


def _self_signed(tmp_path: Path, tag: str, *, bits: int = 2048) -> tuple[Path, Path, str]:
    """自己署名証明書を作り、DER SHA-256を返す。

    CIにcryptographyは入っていないためopenssl CLIを使う。無ければskipする。
    """
    key_path = tmp_path / f"{tag}-key.pem"
    crt_path = tmp_path / f"{tag}-cert.pem"
    try:
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", f"rsa:{bits}", "-nodes",
             "-keyout", str(key_path), "-out", str(crt_path),
             "-days", "365", "-sha256", "-subj", "/CN=PureRAT Agent"],
            check=True, capture_output=True,
        )
        der = subprocess.run(
            ["openssl", "x509", "-in", str(crt_path), "-outform", "DER"],
            check=True, capture_output=True,
        ).stdout
    except (OSError, subprocess.CalledProcessError) as exc:  # pragma: no cover
        pytest.skip(f"openssl CLIが使えないためskipします: {exc}")
    return key_path, crt_path, hashlib.sha256(der).hexdigest()


class MockC2:
    """TCP接続後に4 byte preludeを読み、そのsocket上でTLSへ昇格する模擬C2。"""

    def __init__(
        self,
        key_path: Path,
        crt_path: Path,
        *,
        require_client_cert: bool = False,
        tls_version: ssl.TLSVersion = ssl.TLSVersion.TLSv1_2,
        expect_prelude: bool = True,
    ) -> None:
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(crt_path, key_path)
        self.context.minimum_version = tls_version
        self.context.maximum_version = tls_version
        if require_client_cert:
            self.context.verify_mode = ssl.CERT_REQUIRED
            self.context.load_verify_locations(crt_path)
        self.expect_prelude = expect_prelude
        self.observed_prelude: bytes | None = None
        self.listener = socket.socket()
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(1)
        self.port = int(self.listener.getsockname()[1])
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self) -> None:
        try:
            conn, _ = self.listener.accept()
            conn.settimeout(5)
            if self.expect_prelude:
                self.observed_prelude = conn.recv(len(PURE_PROTOCOL_PRELUDE))
            with self.context.wrap_socket(conn, server_side=True) as tls:
                tls.recv(1)
        except OSError:
            # client側の検証が目的なので、server側の失敗は握って良い
            pass

    def close(self) -> None:
        self.listener.close()


def profile(expected_sha256: str) -> dict[str, Any]:
    return {
        "profile_id": "fixture-purerat-live",
        "handler": "purerat_tls_prelude",
        "host": "rat.example.test",
        "port": 56001,
        "send_hex": "04000000",
        "sni": None,
        "tls_version": "TLSv1.2",
        "expected_certificate_sha256": expected_sha256,
        "timeout_seconds": 5.0,
        "maximum_request_bytes": 4,
        "maximum_response_bytes": 64,
    }


def resolver(*_args: Any, **_kwargs: Any) -> list[tuple[Any, ...]]:
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (FAKE_GLOBAL_IP, 56001))]


def probe(server: MockC2 | None, expected_sha256: str, **kwargs: Any) -> dict[str, Any]:
    def connector(_endpoint: Any, timeout: float) -> Any:
        assert server is not None
        return socket.create_connection(("127.0.0.1", server.port), timeout)

    return probe_reviewed_purerat_tls(
        profile(expected_sha256),
        allow_network=True,
        allow_protocol_prelude=True,
        resolver=kwargs.pop("resolver", resolver),
        connector=kwargs.pop("connector", connector),
        **kwargs,
    )


def assert_safe(result: dict[str, Any], *, confirmed: bool = False) -> None:
    """どの経路でも観測以上のことをしていないことを確認する。"""
    assert result["c2_confirmed"] is confirmed
    for flag in SAFETY_FLAGS:
        if flag == "c2_confirmed":
            continue
        assert result[flag] is False, flag
    assert result["protocol_response_received"] is False
    assert result["observation_excludes_purerat"] is False
    assert isinstance(result["timestamp_utc"], str) and result["timestamp_utc"]


def test_prelude_and_certificate_pin_confirm_over_real_tls(tmp_path: Path) -> None:
    key, crt, sha = _self_signed(tmp_path, "match")
    server = MockC2(key, crt)
    try:
        result = probe(server, sha)
    finally:
        server.close()
    assert result["status"] == "confirmed_purerat_prelude_tls_certificate"
    assert result["tls"]["version"] == "TLSv1.2"
    assert result["tls"]["certificate"]["observed_sha256"] == sha
    assert result["protocol_prelude_accepted"] is True
    assert result["connected_ip"] == FAKE_GLOBAL_IP
    server.thread.join(timeout=3)
    assert server.observed_prelude == PURE_PROTOCOL_PRELUDE
    assert_safe(result, confirmed=True)


def test_different_server_certificate_is_mismatch_not_exclusion(tmp_path: Path) -> None:
    key, crt, sha = _self_signed(tmp_path, "served")
    _, _, other = _self_signed(tmp_path, "expected")
    server = MockC2(key, crt)
    try:
        result = probe(server, other)
    finally:
        server.close()
    assert result["status"] == "purerat_prelude_tls_certificate_mismatch"
    assert result["tls"]["certificate"]["state"] == "mismatch_inconclusive"
    assert result["tls"]["certificate"]["observed_sha256"] == sha
    # 別build・証明書rotationがあり得るのでfamilyの否定には使わない
    assert result["certificate_mismatch_excludes_c2"] is False
    assert_safe(result)


def test_plain_tls_server_does_not_produce_a_false_positive(tmp_path: Path) -> None:
    """preludeを読まない普通のTLS serverでは判定が成立しないことを確認する。

    「ClientHelloの前の4 byteを一般のTLS serverは受理しない」という前提が、
    この判定方式の特異性そのもの。前提が崩れたらここが落ちる。
    """
    key, crt, sha = _self_signed(tmp_path, "plain")
    server = MockC2(key, crt, expect_prelude=False)
    try:
        result = probe(server, sha)
    finally:
        server.close()
    assert result["status"] == "purerat_prelude_rejected"
    assert result["target_connection_established"] is True
    assert result["protocol_prelude_sent"] is True
    assert result["protocol_prelude_accepted"] is False
    assert_safe(result)


def test_server_requiring_client_certificate_is_reported_not_raised(tmp_path: Path) -> None:
    """C2がTLSクライアント認証を要求する場合の挙動を固定する。

    設定に含まれるのは秘密鍵つきPFXで、client認証に使われている可能性がある。
    probeはclient証明書を提示しないため、その構成のC2とはhandshakeできない。
    その事実を例外ではなく観測結果として残す。
    """
    key, crt, sha = _self_signed(tmp_path, "clientauth")
    server = MockC2(key, crt, require_client_cert=True)
    try:
        result = probe(server, sha)
    finally:
        server.close()
    assert result["status"] == "purerat_prelude_tls_handshake_failed"
    assert result["tls"]["handshake"] is False
    assert "SSLError" in result["error"]
    assert_safe(result)


def test_tls13_only_server_is_reported_not_raised(tmp_path: Path) -> None:
    key, crt, sha = _self_signed(tmp_path, "tls13")
    server = MockC2(key, crt, tls_version=ssl.TLSVersion.TLSv1_3)
    try:
        result = probe(server, sha)
    finally:
        server.close()
    assert result["status"] == "purerat_prelude_tls_handshake_failed"
    assert_safe(result)


def test_unreachable_endpoint_is_an_observation_not_an_exception() -> None:
    def refuse(*_args: Any, **_kwargs: Any) -> Any:
        raise ConnectionRefusedError(111, "Connection refused")

    result = probe(None, "a" * 64, connector=refuse)
    assert result["status"] == "not_reachable_at_observation"
    assert result["target_contact_attempted"] is True
    assert result["target_connection_established"] is False
    assert result["alive"] is False
    assert result["resolved_ips"] == [FAKE_GLOBAL_IP]
    assert "ConnectionRefusedError" in result["error"]
    assert_safe(result)


def test_timeout_is_an_observation_not_an_exception() -> None:
    def stall(*_args: Any, **_kwargs: Any) -> Any:
        raise TimeoutError("timed out")

    result = probe(None, "a" * 64, connector=stall)
    assert result["status"] == "not_reachable_at_observation"
    assert_safe(result)


def test_unresolvable_target_is_an_observation_not_an_exception() -> None:
    def private_only(*_args: Any, **_kwargs: Any) -> list[tuple[Any, ...]]:
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.1", 56001))]

    result = probe(
        None,
        "a" * 64,
        resolver=private_only,
        connector=lambda *_a: pytest.fail("解決できない時に接続してはいけない"),
    )
    assert result["status"] == "dns_unresolved"
    assert result["target_contact_attempted"] is False
    assert_safe(result)


def test_dns_failure_is_an_observation_not_an_exception() -> None:
    def failing(*_args: Any, **_kwargs: Any) -> list[tuple[Any, ...]]:
        raise socket.gaierror(-2, "Name or service not known")

    result = probe(
        None,
        "a" * 64,
        resolver=failing,
        connector=lambda *_a: pytest.fail("解決できない時に接続してはいけない"),
    )
    assert result["status"] == "dns_unresolved"
    assert_safe(result)


def test_every_outcome_shares_the_same_result_shape(tmp_path: Path) -> None:
    """成功・失敗・gate無効のどれでもkeyが揃っていることを確認する。

    形が揃っていないと、監視側が経路ごとに場合分けを迫られる。
    """
    key, crt, sha = _self_signed(tmp_path, "shape")
    server = MockC2(key, crt)
    try:
        success = probe(server, sha)
    finally:
        server.close()
    disabled = probe_reviewed_purerat_tls(profile(sha))
    refused = probe(
        None, sha, connector=lambda *_a: (_ for _ in ()).throw(ConnectionRefusedError())
    )
    baseline = set(disabled)
    for result in (success, refused):
        assert baseline <= set(result), baseline - set(result)
