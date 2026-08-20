"""複数検体C2 profileのloopback-only facadeを検証する。"""

from __future__ import annotations

import importlib
import json
import queue
import socket
import sys
import threading
from pathlib import Path
from typing import Any

import pytest

COMMON = Path(__file__).parents[1] / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

COLLECTION = importlib.import_module("reviewed_c2_collection")
EMULATOR = importlib.import_module("reviewed_c2_loopback_emulator")
HOST = importlib.import_module("tls_messagepack_rat_host_emulator")


def _profiles(tmp_path: Path) -> tuple[Path, dict[str, str]]:
    analysis = {
        "schema_version": 2,
        "sample_executed": False,
        "network_contacted": False,
        "raw_keys_published": False,
        "results": [
            {
                "source_member": "private/a.exe",
                "root_sha256": "1" * 64,
                "sample_executed": False,
                "network_contacted": False,
                "terminal": {"sha256": "2" * 64},
                "config": {
                    "family": COLLECTION.BW_FAMILY,
                    "endpoints": [],
                    "certificate": {"sha256": "3" * 64},
                },
            },
            {
                "source_member": "private/b.exe",
                "root_sha256": "4" * 64,
                "sample_executed": False,
                "network_contacted": False,
                "terminal": {"sha256": "5" * 64},
                "config": {"family": COLLECTION.VVAS_FAMILY, "endpoints": []},
            },
        ],
    }
    source = tmp_path / "analysis.json"
    source.write_text(json.dumps(analysis), encoding="utf-8")
    document = COLLECTION.build_collection(
        source,
        collection_id="test-collection-20260819",
        source_path_label="private fixture",
    )
    path = tmp_path / "profiles.json"
    COLLECTION.write_collection(path, document)
    ids = {profile["family"]: profile["profile_id"] for profile in document["profiles"]}
    return path, ids


def _start(
    path: Path,
    profile_id: str,
    *,
    application_layer_only: bool = False,
) -> tuple[threading.Thread, queue.Queue[int], list[dict[str, Any]], list[BaseException]]:
    ready: queue.Queue[int] = queue.Queue(maxsize=1)
    results: list[dict[str, Any]] = []
    errors: list[BaseException] = []

    def worker() -> None:
        try:
            results.append(
                EMULATOR.serve_once(
                    path,
                    profile_id,
                    application_layer_only=application_layer_only,
                    ready_callback=ready.put,
                )
            )
        except BaseException as exc:  # pragma: no cover - 親threadで検証する。
            errors.append(exc)

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()
    return thread, ready, results, errors


def test_bwrat_application_facade_replies_only_to_exact_ping(tmp_path: Path) -> None:
    path, ids = _profiles(tmp_path)
    thread, ready, results, errors = _start(
        path,
        ids[COLLECTION.BW_FAMILY],
        application_layer_only=True,
    )
    port = ready.get(timeout=2.0)
    with socket.create_connection(("127.0.0.1", port), timeout=2.0) as stream:
        stream.sendall(HOST.encode_frame({"Pac_ket": "Ping", "Message": ""}))
        header = stream.recv(4)
        size = int.from_bytes(header, "little")
        response = header + stream.recv(size)
    thread.join(timeout=2.0)

    assert errors == []
    assert not thread.is_alive()
    assert HOST.decode_frame(response).values == {"Pac_ket": "Po_ng"}
    assert results[0]["status"] == "reviewed_heartbeat_response_sent"
    assert results[0]["safety"]["task_sent"] is False
    assert results[0]["safety"]["arbitrary_result_sent"] is False
    assert results[0]["safety"]["application_layer_only"] is True


def test_bwrat_mismatch_receives_no_response(tmp_path: Path) -> None:
    path, ids = _profiles(tmp_path)
    thread, ready, results, errors = _start(
        path,
        ids[COLLECTION.BW_FAMILY],
        application_layer_only=True,
    )
    port = ready.get(timeout=2.0)
    with socket.create_connection(("127.0.0.1", port), timeout=2.0) as stream:
        stream.sendall(HOST.encode_frame({"Pac_ket": "plu_gin", "Message": ""}))
        stream.shutdown(socket.SHUT_WR)
        assert stream.recv(1) == b""
    thread.join(timeout=2.0)

    assert errors == []
    assert results[0]["status"] == "heartbeat_request_mismatch_no_response"
    assert results[0]["response"] is None


def test_vvas_facade_sends_header_but_never_stage(tmp_path: Path) -> None:
    path, ids = _profiles(tmp_path)
    thread, ready, results, errors = _start(path, ids[COLLECTION.VVAS_FAMILY])
    port = ready.get(timeout=2.0)
    with socket.create_connection(("127.0.0.1", port), timeout=2.0) as stream:
        stream.sendall(b"32\x00")
        response = stream.recv(64)
        assert len(response) == 14
        assert stream.recv(1) == b""
    thread.join(timeout=2.0)

    assert errors == []
    assert not thread.is_alive()
    assert results[0]["status"] == "reviewed_vvas_header_only_sent"
    assert results[0]["response"]["size"] == 14
    assert results[0]["safety"]["stage_sent"] is False
    assert results[0]["safety"]["task_sent"] is False


@pytest.mark.parametrize("bind", ["0.0.0.0", "192.0.2.1", "localhost"])
def test_nonloopback_or_name_bind_is_rejected(tmp_path: Path, bind: str) -> None:
    path, ids = _profiles(tmp_path)
    with pytest.raises(EMULATOR.ReviewedC2LoopbackError, match="loopback"):
        EMULATOR.serve_once(path, ids[COLLECTION.VVAS_FAMILY], bind=bind)


def test_bwrat_tls_mode_requires_external_certificate_pair(tmp_path: Path) -> None:
    path, ids = _profiles(tmp_path)
    with pytest.raises(EMULATOR.ReviewedC2LoopbackError, match="tls-cert"):
        EMULATOR.serve_once(path, ids[COLLECTION.BW_FAMILY])
