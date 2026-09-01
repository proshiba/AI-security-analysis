"""PureRAT 4.4.1 direct-TLS host adapterの限定送受信契約を検証する。"""

from __future__ import annotations

import ast
import gzip
import importlib.util
import socket
import struct
import sys
import threading
from pathlib import Path

import pytest

FRAMEWORK = Path(__file__).resolve().parents[1]
MODULE = FRAMEWORK / "malware" / "purehvnc" / "purerat_host_emulator.py"
COMMON_RUNNER = FRAMEWORK / "common" / "run_defensive_rat_emulator.py"
SYNTHETIC_RESULT = (
    FRAMEWORK / "malware" / "purehvnc" / "purerat_synthetic_result.py"
)
LOOPBACK_OBSERVER = FRAMEWORK.parent / "emulators" / "purehvnc" / "observer.py"


def _load():
    spec = importlib.util.spec_from_file_location(
        "purerat_direct_tls_host_contract",
        MODULE,
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


PURERAT = _load()


def _varint(value: int) -> bytes:
    output = bytearray()
    while value > 0x7F:
        output.append((value & 0x7F) | 0x80)
        value >>= 7
    output.append(value)
    return bytes(output)


def _frame(message_type: int, body: bytes = b"") -> bytes:
    """ProtoInclude fieldをLE32/GZip envelopeへ格納するoffline fixture。"""

    protobuf = _varint((message_type << 3) | 2) + _varint(len(body)) + body
    compressed = gzip.compress(protobuf, mtime=0)
    return struct.pack("<I", len(compressed)) + compressed


class FragmentStream:
    """TLS復号後の受信byteを返し、送信試行を記録するoffline fixture。"""

    def __init__(
        self,
        incoming: bytes,
        *,
        fragment_size: int = 7,
        finish: str = "closed",
    ) -> None:
        self.incoming = bytearray(incoming)
        self.fragment_size = fragment_size
        self.finish = finish
        self.sent: list[bytes] = []
        self.recv_calls = 0
        self.timeout_seconds: float | None = None

    def settimeout(self, timeout_seconds: float) -> None:
        self.timeout_seconds = timeout_seconds

    def sendall(self, data: bytes) -> None:
        self.sent.append(bytes(data))

    def recv(self, maximum_bytes: int) -> bytes:
        self.recv_calls += 1
        if self.incoming:
            length = min(maximum_bytes, self.fragment_size, len(self.incoming))
            chunk = bytes(self.incoming[:length])
            del self.incoming[:length]
            return chunk
        if self.finish == "timeout":
            raise TimeoutError("offline fixture idle")
        return b""


def _run(stream, *, events: list[dict] | None = None) -> dict:
    return PURERAT.run_host_session(
        stream,
        session_limits={
            "idle_timeout_seconds": 1.0,
            "maximum_response_bytes": 65536,
            "maximum_frames": 1,
            "maximum_read_calls": 32,
            "read_chunk_bytes": 4096,
        },
        allow_registration=True,
        allow_heartbeat_request=False,
        transcript_callback=None if events is None else events.append,
    )


def test_contract_is_direct_tls_and_limited_to_fixed_empty_registration() -> None:
    assert PURERAT.ADAPTER_ID == "purerat_direct_tls_v1"
    assert PURERAT.LOOPBACK_REGISTRATION_SUPPORTED is True
    assert PURERAT.LIVE_REGISTRATION_ALLOWED is False
    assert PURERAT.LIVE_HEARTBEAT_REQUEST_ALLOWED is False
    assert PURERAT.LIVE_TASK_REPLY_ALLOWED is False
    assert PURERAT.LIVE_FAKE_RESULT_TRANSMISSION_ALLOWED is False
    assert PURERAT.LIVE_PLUGIN_OR_FILE_RETENTION_ALLOWED is False
    assert PURERAT.REQUIRES_PREVALIDATED_TLS_CERTIFICATE is True
    assert PURERAT.build_empty_gclass4_registration_payload() == b"\x0a\x00"
    policy = PURERAT.HostPolicy()
    assert policy.maximum_frames == 1
    assert policy.maximum_response_bytes <= 65536


@pytest.mark.parametrize(
    ("message_type", "classification"),
    [
        (5, "plugin_descriptor_refused"),
        (38, "configuration_update_refused"),
        (86, "command_refused"),
        (127, "unknown_discriminator_rejected"),
    ],
)
def test_known_and_unknown_messages_are_classified_without_reply(
    message_type: int,
    classification: str,
) -> None:
    secret = b"operator-private-command-or-plugin"
    stream = FragmentStream(_frame(message_type, secret))
    events: list[dict] = []

    result = _run(stream, events=events)

    assert stream.sent == [PURERAT.build_empty_gclass4_registration_frame()]
    assert result["registration"]["sent"] is True
    assert result["registration"]["real_identity_sent"] is False
    assert result["registration"]["populated_member_count"] == 0
    assert result["decisions"][0]["discriminator"] == message_type
    assert result["decisions"][0]["classification"] == classification
    assert result["decisions"][0]["should_respond"] is False
    assert result["decisions"][0]["terminate_session"] is True
    assert result["safety"]["application_send_count"] == 1
    assert result["safety"]["task_executed"] is False
    assert result["safety"]["operation_executed"] is False
    assert result["safety"]["plugin_or_file_retained"] is False
    assert result["safety"]["command_reply_sent"] is False
    assert secret.decode("ascii") not in repr(result)
    assert secret.decode("ascii") not in repr(events)


def _recv_exact(stream: socket.socket, size: int) -> bytes:
    output = bytearray()
    while len(output) < size:
        chunk = stream.recv(size - len(output))
        if not chunk:
            raise ConnectionError("loopback受信が途中で終了しました")
        output.extend(chunk)
    return bytes(output)


def test_actual_loopback_tcp_sends_one_registration_and_never_replies() -> None:
    """127.0.0.1へ固定registrationを1回送り、受信後は返信しない。"""

    secret = b"loopback-private-command-body"
    response = _frame(86, secret)
    peer_received: list[bytes] = []
    unexpected_after_response: list[bytes] = []
    server_errors: list[BaseException] = []

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(2.0)
        port = int(listener.getsockname()[1])

        def serve() -> None:
            try:
                connection, peer = listener.accept()
                assert peer[0].startswith("127.")
                with connection:
                    connection.settimeout(2.0)
                    prefix = _recv_exact(connection, 4)
                    declared = struct.unpack("<I", prefix)[0]
                    peer_received.append(prefix + _recv_exact(connection, declared))
                    for start, end in ((0, 1), (1, 4), (4, 19), (19, len(response))):
                        if start < len(response):
                            connection.sendall(response[start:end])
                    unexpected_after_response.append(connection.recv(1))
            except BaseException as exc:  # noqa: BLE001 - thread失敗をmainへ転送する
                server_errors.append(exc)

        server = threading.Thread(target=serve, daemon=True)
        server.start()
        events: list[dict] = []
        with socket.create_connection(("127.0.0.1", port), timeout=2.0) as client:
            result = _run(client, events=events)
        server.join(timeout=3.0)

    assert not server.is_alive()
    assert server_errors == []
    assert peer_received == [PURERAT.build_empty_gclass4_registration_frame()]
    assert unexpected_after_response == [b""]
    assert result["collection"]["frame_count"] == 1
    assert result["decisions"][0]["discriminator"] == 86
    assert result["safety"]["application_send_count"] == 1
    assert result["safety"]["command_reply_sent"] is False
    assert secret.decode("ascii") not in repr(result)
    assert secret.decode("ascii") not in repr(events)


def test_only_first_frame_is_consumed_and_second_frame_is_not_polled() -> None:
    first = _frame(3, b"status")
    second = _frame(86, b"second-private-command")
    stream = FragmentStream(first + second, fragment_size=len(first))

    result = _run(stream)

    assert stream.sent == [PURERAT.build_empty_gclass4_registration_frame()]
    assert bytes(stream.incoming) == second
    assert result["collection"]["frame_count"] == 1
    assert result["decisions"][0]["discriminator"] == 3


def test_declared_length_and_read_call_limits_fail_closed_after_single_registration() -> None:
    oversized = FragmentStream(struct.pack("<I", 65537) + b"private")
    with pytest.raises(PURERAT.ResponseLimitExceededError):
        _run(oversized)
    assert oversized.sent == [PURERAT.build_empty_gclass4_registration_frame()]
    assert bytes(oversized.incoming) == b"private"

    fragmented = FragmentStream(_frame(86, b"private"), fragment_size=1)
    with pytest.raises(PURERAT.ResponseLimitExceededError):
        PURERAT.run_host_session(
            fragmented,
            session_limits={
                "idle_timeout_seconds": 1.0,
                "maximum_response_bytes": 65536,
                "maximum_frames": 1,
                "maximum_read_calls": 2,
                "read_chunk_bytes": 4096,
            },
            allow_registration=True,
        )
    assert fragmented.sent == [PURERAT.build_empty_gclass4_registration_frame()]


def test_adapter_and_common_runner_do_not_load_pfx_or_private_key() -> None:
    """PFX hashは照合metadataに限り、秘密鍵をTLS client証明書へ使わない。"""

    forbidden_calls = {
        "load_cert_chain",
        "load_key_and_certificates",
        "load_pkcs12",
    }
    for source_path in (MODULE, COMMON_RUNNER):
        tree = ast.parse(source_path.read_text(encoding="utf-8"))
        observed = {
            node.func.attr
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
        }
        assert observed.isdisjoint(forbidden_calls)

    secret = b"raw-protobuf-private-material"
    events: list[dict] = []
    result = _run(FragmentStream(_frame(5, secret)), events=events)
    assert result["safety"]["pfx_loaded"] is False
    assert result["safety"]["client_certificate_sent"] is False
    assert result["safety"]["private_key_loaded"] is False
    public_repr = repr({"result": result, "events": events}).casefold()
    assert secret.decode("ascii") not in public_repr
    for forbidden in (
        "private_key_bytes",
        "pfx_bytes",
        "pkcs12_bytes",
        "raw_frame",
        "raw_protobuf",
        "payload_hex",
    ):
        assert forbidden not in public_repr


def test_receive_only_path_has_no_command_execution_primitives() -> None:
    """受信frameからprocess起動や動的code評価へ到達する実装を拒否する。"""

    forbidden_import_roots = {
        "ctypes",
        "multiprocessing",
        "subprocess",
        "winreg",
    }
    forbidden_builtin_calls = {"compile", "eval", "exec"}
    forbidden_generic_attributes = {
        "CreateProcess",
        "Popen",
        "ShellExecute",
        "WinExec",
        "check_call",
        "check_output",
    }
    reviewed = (MODULE, SYNTHETIC_RESULT, LOOPBACK_OBSERVER, COMMON_RUNNER)
    for source_path in reviewed:
        tree = ast.parse(source_path.read_text(encoding="utf-8"))
        imported_roots: set[str] = set()
        os_aliases: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    root = alias.name.split(".", 1)[0]
                    imported_roots.add(root)
                    if root == "os":
                        os_aliases.add(alias.asname or alias.name)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported_roots.add(node.module.split(".", 1)[0])
        assert imported_roots.isdisjoint(forbidden_import_roots), source_path

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if isinstance(node.func, ast.Name):
                assert node.func.id not in forbidden_builtin_calls, source_path
                continue
            if not isinstance(node.func, ast.Attribute):
                continue
            assert node.func.attr not in forbidden_generic_attributes, source_path
            if isinstance(node.func.value, ast.Name) and node.func.value.id in os_aliases:
                assert node.func.attr not in {"popen", "startfile", "system"}, source_path
                assert not node.func.attr.startswith("spawn"), source_path
                assert not node.func.attr.startswith("exec"), source_path


def test_production_sendall_is_limited_to_fixed_registration() -> None:
    """PureRAT production adapterとobserverの送信元を固定registrationに限定する。"""

    for source_path in (MODULE, LOOPBACK_OBSERVER):
        tree = ast.parse(source_path.read_text(encoding="utf-8"))
        send_calls = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "sendall"
        ]
        assert len(send_calls) == 1, source_path
        assert len(send_calls[0].args) == 1, source_path
        assert isinstance(send_calls[0].args[0], ast.Name), source_path
        assert send_calls[0].args[0].id == "registration", source_path
