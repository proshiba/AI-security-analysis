"""外部artifact取得補助の有界GETとfailure metadata契約を検証する。"""

from __future__ import annotations

import importlib.util
import json
import socket
import urllib.error
from pathlib import Path
from typing import Any, Self

import pytest
import pyzipper

MODULE_PATH = Path(__file__).parents[1] / "common" / "fetch_http_artifact.py"
SPEC = importlib.util.spec_from_file_location("fetch_http_artifact_under_test", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
FETCH = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(FETCH)


class _Response:
    def __init__(self, body: bytes, *, headers: dict[str, str] | None = None) -> None:
        self.status = 200
        self.headers = (
            headers
            if headers is not None
            else {
                "Content-Type": "application/octet-stream",
                "Content-Length": str(len(body)),
            }
        )
        self.body = body
        self.maximum_read: int | None = None

    def read(self, maximum: int) -> bytes:
        self.maximum_read = maximum
        return self.body

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_args: object) -> bool:
        return False


class _Opener:
    def __init__(self, result: _Response | BaseException) -> None:
        self.result = result
        self.request = None
        self.timeout: float | None = None

    def open(self, request: Any, timeout: float) -> _Response:
        self.request = request
        self.timeout = timeout
        if isinstance(self.result, BaseException):
            raise self.result
        return self.result


def _arguments(tmp_path: Path, url: str) -> list[str]:
    return [
        "--url",
        url,
        "--allow-network",
        "--output-zip",
        str(tmp_path / "artifact.zip"),
        "--metadata",
        str(tmp_path / "metadata.json"),
        "--max-bytes",
        "16",
    ]


def test_url_credentials_are_refused_before_network_contact(
    tmp_path: Path, monkeypatch: Any, capsys: Any
) -> None:
    """userinfo付きURLは秘密値を出さずnetwork接触前に拒否する。"""

    opener = _Opener(TimeoutError("private-token"))
    monkeypatch.setattr(FETCH.urllib.request, "build_opener", lambda *_handlers: opener)
    url = "https://operator:secret@example.test/payload.bin?token=private-token#fragment"

    assert FETCH.main(_arguments(tmp_path, url)) == 2

    metadata = json.loads((tmp_path / "metadata.json").read_text(encoding="utf-8"))
    output = capsys.readouterr().out
    assert metadata["status"] == "failed"
    assert metadata["failure"]["code"] == "url_credentials_refused"
    assert metadata["url"] == "https://example.test/payload.bin"
    assert metadata["url_query_present"] is True
    assert metadata["url_credentials_redacted"] is True
    assert metadata["url_fragment_redacted"] is True
    assert metadata["redirects_followed"] is False
    assert metadata["raw_response_published"] is False
    assert metadata["credentials_published"] is False
    assert metadata["network_contacted"] is False
    assert opener.request is None
    assert not (tmp_path / "artifact.zip").exists()
    assert "private-token" not in json.dumps(metadata)
    assert "private-token" not in output
    assert "secret" not in output


def test_timeout_writes_redacted_failure_metadata_without_archive(
    tmp_path: Path, monkeypatch: Any, capsys: Any
) -> None:
    """timeoutはtracebackやquery値を出さず、非0で終了する。"""

    opener = _Opener(TimeoutError("private-token"))
    monkeypatch.setattr(FETCH.urllib.request, "build_opener", lambda *_handlers: opener)
    url = "https://example.test/payload.bin?token=private-token#fragment"

    assert FETCH.main(_arguments(tmp_path, url)) == 2

    metadata = json.loads((tmp_path / "metadata.json").read_text(encoding="utf-8"))
    output = capsys.readouterr().out
    assert metadata["status"] == "failed"
    assert metadata["failure"]["code"] == "timeout"
    assert metadata["network_contacted"] is True
    assert not (tmp_path / "artifact.zip").exists()
    assert "private-token" not in json.dumps(metadata)
    assert "private-token" not in output


def test_dns_and_http_failures_have_stable_public_classification() -> None:
    """例外本文を公開せず、DNS／HTTP／redirectを個別分類する。"""

    cases = [
        (
            urllib.error.URLError(socket.gaierror(-2, "sensitive resolver detail")),
            "dns_error",
            None,
        ),
        (
            urllib.error.HTTPError(
                "https://example.test/payload",
                404,
                "private server detail",
                {},
                None,
            ),
            "http_error",
            404,
        ),
        (
            urllib.error.HTTPError(
                "https://example.test/payload",
                302,
                "https://secret.example/redirect-token",
                {"Location": "https://secret.example/redirect-token"},
                None,
            ),
            "redirect_refused",
            302,
        ),
    ]
    for exception, expected_code, expected_status in cases:
        try:
            FETCH._download(
                url="https://example.test/payload",
                timeout=1.0,
                max_bytes=16,
                opener=_Opener(exception),
            )
        except FETCH.ArtifactFetchFailure as failure:
            assert failure.code == expected_code
            assert failure.http_status == expected_status
            assert "sensitive" not in failure.message
            assert "private" not in failure.message
            assert "redirect-token" not in failure.message
        else:
            raise AssertionError("取得失敗が成功扱いになりました")

    response = _Response(b"redirect", headers={"Location": "https://secret.example/token"})
    response.status = 302
    try:
        FETCH._download(
            url="https://example.test/payload",
            timeout=1.0,
            max_bytes=16,
            opener=_Opener(response),
        )
    except FETCH.ArtifactFetchFailure as failure:
        assert failure.code == "redirect_refused"
        assert failure.http_status == 302
        assert response.maximum_read is None
    else:
        raise AssertionError("redirect応答が成功扱いになりました")


def test_success_keeps_aes_archive_and_filters_sensitive_headers(tmp_path: Path, monkeypatch: Any) -> None:
    """成功時のAES ZIP互換を維持し、headerはallowlistだけを記録する。"""

    body = b"fixture"
    response = _Response(
        body,
        headers={
            "Content-Type": "application/octet-stream",
            "Content-Length": str(len(body)),
            "Server": "fixture",
            "Set-Cookie": "session=private-token",
            "X-Api-Key": "private-token",
        },
    )
    opener = _Opener(response)
    monkeypatch.setattr(FETCH.urllib.request, "build_opener", lambda *_handlers: opener)

    assert FETCH.main(_arguments(tmp_path, "https://example.test/payload.bin?token=private-token")) == 0

    metadata = json.loads((tmp_path / "metadata.json").read_text(encoding="utf-8"))
    assert metadata["status"] == "success"
    assert metadata["archive_encryption"] == "WinZip AES-256"
    assert metadata["archive_verified"] is True
    assert metadata["url"] == "https://example.test/payload.bin"
    assert metadata["response_headers"] == {
        "Content-Type": "application/octet-stream",
        "Content-Length": str(len(body)),
        "Server": "fixture",
    }
    assert response.maximum_read == 17
    assert opener.timeout == 15.0
    with pyzipper.AESZipFile(tmp_path / "artifact.zip") as archive:
        archive.setpassword(b"infected")
        assert archive.getinfo("retrieved-artifact.bin").wz_aes_strength == 3
        assert archive.read("retrieved-artifact.bin") == body
    assert "private-token" not in json.dumps(metadata)


def test_declared_and_streamed_oversize_are_structured_failures() -> None:
    """Content-Lengthと実本文の双方に上限を適用する。"""

    declared = _Response(b"not-read", headers={"Content-Length": "17"})
    streamed = _Response(b"x" * 17, headers={})
    for response in (declared, streamed):
        try:
            FETCH._download(
                url="https://example.test/payload",
                timeout=1.0,
                max_bytes=16,
                opener=_Opener(response),
            )
        except FETCH.ArtifactFetchFailure as failure:
            assert failure.code == "size_limit_exceeded"
            assert failure.http_status == 200
        else:
            raise AssertionError("size上限超過が成功扱いになりました")

    assert declared.maximum_read is None
    assert streamed.maximum_read == 17


def test_empty_body_is_a_structured_failure_without_archive(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """HTTP 200でも0-byte本文はpayloadとして保存しない。"""

    opener = _Opener(_Response(b""))
    monkeypatch.setattr(FETCH.urllib.request, "build_opener", lambda *_handlers: opener)

    assert FETCH.main(_arguments(tmp_path, "https://example.test/empty")) == 2

    metadata = json.loads((tmp_path / "metadata.json").read_text(encoding="utf-8"))
    assert metadata["failure"]["code"] == "empty_body"
    assert metadata["http_status"] == 200
    assert metadata["output_archive_written"] is False
    assert not (tmp_path / "artifact.zip").exists()


@pytest.mark.parametrize("existing_name", ["artifact.zip", "metadata.json"])
def test_existing_output_is_refused_before_network(
    tmp_path: Path,
    monkeypatch: Any,
    existing_name: str,
) -> None:
    """既存archiveまたはmetadataを上書きせず、GETも開始しない。"""

    existing = tmp_path / existing_name
    existing.write_bytes(b"sentinel")
    opener = _Opener(_Response(b"fixture"))
    monkeypatch.setattr(FETCH.urllib.request, "build_opener", lambda *_handlers: opener)

    with pytest.raises(FileExistsError):
        FETCH.main(_arguments(tmp_path, "https://example.test/payload"))

    assert existing.read_bytes() == b"sentinel"
    assert opener.request is None


@pytest.mark.parametrize(
    ("member_name", "member_body"),
    [
        ("other.bin", b"fixture"),
        ("retrieved-artifact.bin", b"different"),
    ],
)
def test_archive_verification_rejects_member_or_hash_mismatch(
    tmp_path: Path,
    member_name: str,
    member_body: bytes,
) -> None:
    """復号後のmember集合とSHA-256が期待値と異なるarchiveを拒否する。"""

    path = tmp_path / "artifact.zip"
    with pyzipper.AESZipFile(
        path,
        "w",
        compression=pyzipper.ZIP_DEFLATED,
        encryption=pyzipper.WZ_AES,
    ) as archive:
        archive.setpassword(b"infected")
        archive.setencryption(pyzipper.WZ_AES, nbits=256)
        archive.writestr(member_name, member_body)

    with pytest.raises(FETCH.ArtifactFetchFailure) as captured:
        FETCH._verify_archive(
            path,
            member_name="retrieved-artifact.bin",
            expected=b"fixture",
            password=b"infected",
        )
    assert captured.value.code == "archive_verification_failed"
