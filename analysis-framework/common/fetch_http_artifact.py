#!/usr/bin/env python3
"""明示的に許可されたHTTP(S) artifactを1件だけAES ZIPへ取得する。

応答sizeと時間を制限し、redirectを拒否する。平文の応答byteはdiskへ書かない。
これは証拠収集補助であり、C2 clientではない。
"""

from __future__ import annotations

import argparse
import hashlib
import json
import socket
import ssl
import sys
import urllib.error
import urllib.request
from http.client import HTTPException
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import pyzipper

SAFE_RESPONSE_HEADERS = frozenset(
    {
        "accept-ranges",
        "content-encoding",
        "content-length",
        "content-type",
        "etag",
        "last-modified",
        "server",
    }
)


class ArtifactFetchFailure(Exception):
    """公開可能な分類だけを保持する取得失敗。"""

    def __init__(self, code: str, message: str, *, http_status: int | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.http_status = http_status


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(req.full_url, code, "redirect refused", headers, fp)


def _redact_url(url: str) -> dict[str, Any]:
    """userinfo、query値、fragmentを公開metadataへ出さない。"""

    parsed = urlsplit(url)
    hostname = parsed.hostname or ""
    if ":" in hostname and not hostname.startswith("["):
        hostname = f"[{hostname}]"
    netloc = hostname
    if parsed.port is not None:
        netloc = f"{netloc}:{parsed.port}"
    return {
        "url": urlunsplit((parsed.scheme, netloc, parsed.path, "", "")),
        "url_query_present": bool(parsed.query),
        "url_credentials_redacted": parsed.username is not None or parsed.password is not None,
        "url_fragment_redacted": bool(parsed.fragment),
        "url_sha256": hashlib.sha256(url.encode("utf-8", errors="surrogatepass")).hexdigest(),
    }


def _safe_response_headers(headers: Any) -> dict[str, str]:
    """cookie、Location、独自tokenを除き、固定allowlistだけを返す。"""

    return {str(name): str(value) for name, value in headers.items() if str(name).casefold() in SAFE_RESPONSE_HEADERS}


def _classify_url_error(error: urllib.error.URLError) -> ArtifactFetchFailure:
    reason = error.reason
    if isinstance(reason, TimeoutError):
        return ArtifactFetchFailure("timeout", "HTTP取得が制限時間を超過しました")
    if isinstance(reason, socket.gaierror):
        return ArtifactFetchFailure("dns_error", "接続先のDNS解決に失敗しました")
    if isinstance(reason, ssl.SSLError):
        return ArtifactFetchFailure("tls_error", "TLS接続に失敗しました")
    if isinstance(reason, ConnectionRefusedError):
        return ArtifactFetchFailure("connection_refused", "接続先に拒否されました")
    return ArtifactFetchFailure("network_error", "HTTP接続に失敗しました")


def _download(
    *,
    url: str,
    timeout: float,
    max_bytes: int,
    opener: Any | None = None,
) -> tuple[bytes, int, dict[str, str]]:
    """1回限定GETを実行し、失敗は秘密情報を含まない分類へ変換する。"""

    if timeout <= 0:
        raise ValueError("--timeout must be greater than zero")
    if max_bytes <= 0:
        raise ValueError("--max-bytes must be greater than zero")
    http_opener = opener if opener is not None else urllib.request.build_opener(NoRedirect())
    request = urllib.request.Request(url, method="GET", headers={"User-Agent": "AI-security-analysis/1.0"})
    try:
        with http_opener.open(request, timeout=timeout) as response:
            status = int(response.status)
            if 300 <= status < 400:
                raise ArtifactFetchFailure(
                    "redirect_refused",
                    "HTTP redirectを拒否しました",
                    http_status=status,
                )
            if status < 200 or status >= 400:
                raise ArtifactFetchFailure(
                    "http_error",
                    "HTTPサーバーがエラーを返しました",
                    http_status=status,
                )
            headers = _safe_response_headers(response.headers)
            declared_length = response.headers.get("Content-Length")
            if declared_length is not None:
                try:
                    if int(declared_length) > max_bytes:
                        raise ArtifactFetchFailure(
                            "size_limit_exceeded",
                            "応答のContent-Lengthが上限を超えました",
                            http_status=status,
                        )
                except ValueError:
                    pass
            data = response.read(max_bytes + 1)
            if len(data) > max_bytes:
                raise ArtifactFetchFailure(
                    "size_limit_exceeded",
                    "応答本文が上限を超えました",
                    http_status=status,
                )
            if not data:
                raise ArtifactFetchFailure(
                    "empty_body",
                    "HTTP応答本文が空でした",
                    http_status=status,
                )
            return data, status, headers
    except ArtifactFetchFailure:
        raise
    except urllib.error.HTTPError as error:
        status = int(error.code)
        if 300 <= status < 400:
            raise ArtifactFetchFailure(
                "redirect_refused",
                "HTTP redirectを拒否しました",
                http_status=status,
            ) from None
        raise ArtifactFetchFailure(
            "http_error",
            "HTTPサーバーがエラーを返しました",
            http_status=status,
        ) from None
    except urllib.error.URLError as error:
        raise _classify_url_error(error) from None
    except TimeoutError:
        raise ArtifactFetchFailure("timeout", "HTTP取得が制限時間を超過しました") from None
    except socket.gaierror:
        raise ArtifactFetchFailure("dns_error", "接続先のDNS解決に失敗しました") from None
    except ssl.SSLError:
        raise ArtifactFetchFailure("tls_error", "TLS接続に失敗しました") from None
    except ConnectionRefusedError:
        raise ArtifactFetchFailure("connection_refused", "接続先に拒否されました") from None
    except HTTPException:
        raise ArtifactFetchFailure("http_protocol_error", "HTTP応答の解析に失敗しました") from None
    except OSError:
        raise ArtifactFetchFailure("network_error", "HTTP接続に失敗しました") from None


def _write_metadata(path: Path, result: dict[str, Any]) -> None:
    """既存metadataを上書きせず、今回の結果を新規作成する。"""

    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8") as stream:
        stream.write(json.dumps(result, ensure_ascii=False, indent=2) + "\n")


def _ensure_output_paths_available(output_zip: Path, metadata: Path) -> None:
    """出力先の同一指定と既存fileへの上書きをnetwork接触前に拒否する。"""

    if output_zip.resolve(strict=False) == metadata.resolve(strict=False):
        raise ValueError("--output-zip and --metadata must be different paths")
    for path in (output_zip, metadata):
        if path.exists():
            raise FileExistsError(f"refusing to overwrite existing output: {path}")


def _validated_member_name(value: str) -> str:
    """単一fileとして安全な相対archive member名だけを受理する。"""

    candidate = PurePosixPath(value.replace("\\", "/"))
    if (
        not value
        or candidate.is_absolute()
        or len(candidate.parts) != 1
        or candidate.name in {"", ".", ".."}
    ):
        raise ValueError("--member-name must be one relative file name")
    return candidate.name


def _verify_archive(
    path: Path,
    *,
    member_name: str,
    expected: bytes,
    password: bytes,
) -> None:
    """AES ZIPを復号し、member集合・AES強度・size・SHA-256を照合する。"""

    expected_hash = hashlib.sha256(expected).digest()
    with pyzipper.AESZipFile(path, "r") as archive:
        archive.setpassword(password)
        if archive.namelist() != [member_name]:
            raise ArtifactFetchFailure(
                "archive_verification_failed",
                "暗号化archiveのmember集合を検証できませんでした",
            )
        member = archive.getinfo(member_name)
        if getattr(member, "wz_aes_strength", None) != 3:
            raise ArtifactFetchFailure(
                "archive_verification_failed",
                "暗号化archiveがWinZip AES-256ではありません",
            )
        recovered = archive.read(member_name)
    if len(recovered) != len(expected) or hashlib.sha256(recovered).digest() != expected_hash:
        raise ArtifactFetchFailure(
            "archive_verification_failed",
            "暗号化archiveの復号後sizeまたはSHA-256が一致しません",
        )


def _write_verified_archive(
    path: Path,
    *,
    member_name: str,
    data: bytes,
    password: bytes,
) -> None:
    """archiveをexclusive-createし、復号検証失敗時だけ自作fileを除去する。"""

    path.parent.mkdir(parents=True, exist_ok=True)
    created = False
    try:
        with path.open("xb") as stream:
            created = True
            with pyzipper.AESZipFile(
                stream,
                "w",
                compression=pyzipper.ZIP_DEFLATED,
                encryption=pyzipper.WZ_AES,
            ) as archive:
                archive.setpassword(password)
                archive.setencryption(pyzipper.WZ_AES, nbits=256)
                archive.writestr(member_name, data)
        _verify_archive(
            path,
            member_name=member_name,
            expected=data,
            password=password,
        )
    except Exception:
        if created:
            path.unlink(missing_ok=True)
        raise


def _failure_result(
    url: str,
    failure: ArtifactFetchFailure,
    *,
    network_contacted: bool = True,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "schema_version": 1,
        "status": "failed",
        **_redact_url(url),
        "failure": {"code": failure.code, "message": failure.message},
        "output_archive_written": False,
        "executed": False,
        "network_contacted": network_contacted,
        "network_scope": (
            "one bounded GET; redirects disabled"
            if network_contacted
            else "no network contact; URL rejected during validation"
        ),
        "redirects_followed": False,
        "plaintext_artifact_written": False,
        "raw_response_published": False,
        "credentials_published": False,
    }
    if failure.http_status is not None:
        result["http_status"] = failure.http_status
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", required=True)
    parser.add_argument("--allow-network", action="store_true")
    parser.add_argument("--output-zip", required=True, type=Path)
    parser.add_argument("--metadata", required=True, type=Path)
    parser.add_argument("--member-name", default="retrieved-artifact.bin")
    parser.add_argument("--password", default="infected")
    parser.add_argument("--timeout", type=float, default=15.0)
    parser.add_argument("--max-bytes", type=int, default=64 * 1024 * 1024)
    args = parser.parse_args(argv)
    if not args.allow_network:
        raise SystemExit("refusing network request without --allow-network")
    parsed = urlsplit(args.url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("only an explicit HTTP(S) URL is accepted")
    _ensure_output_paths_available(args.output_zip, args.metadata)
    member_name = _validated_member_name(args.member_name)
    if parsed.username is not None or parsed.password is not None:
        failure = ArtifactFetchFailure(
            "url_credentials_refused",
            "userinfoを含むURLを拒否しました",
        )
        result = _failure_result(
            args.url,
            failure,
            network_contacted=False,
        )
        _write_metadata(args.metadata, result)
        print(
            json.dumps(
                {
                    "metadata": str(args.metadata),
                    "status": "failed",
                    "failure_code": failure.code,
                },
                ensure_ascii=False,
            )
        )
        return 2

    try:
        data, status, headers = _download(url=args.url, timeout=args.timeout, max_bytes=args.max_bytes)
    except ArtifactFetchFailure as failure:
        result = _failure_result(args.url, failure)
        _write_metadata(args.metadata, result)
        print(
            json.dumps(
                {"metadata": str(args.metadata), "status": "failed", "failure_code": failure.code},
                ensure_ascii=False,
            )
        )
        return 2

    password = args.password.encode()
    try:
        _write_verified_archive(
            args.output_zip,
            member_name=member_name,
            data=data,
            password=password,
        )
    except ArtifactFetchFailure as failure:
        result = _failure_result(args.url, failure)
        _write_metadata(args.metadata, result)
        print(
            json.dumps(
                {
                    "metadata": str(args.metadata),
                    "status": "failed",
                    "failure_code": failure.code,
                },
                ensure_ascii=False,
            )
        )
        return 2

    result = {
        "schema_version": 1,
        "status": "success",
        **_redact_url(args.url),
        "http_status": status,
        "response_headers": headers,
        "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "output_archive": str(args.output_zip),
        "output_archive_written": True,
        "archive_member": member_name,
        "archive_encryption": "WinZip AES-256",
        "archive_verified": True,
        "executed": False,
        "network_contacted": True,
        "network_scope": "one bounded GET; redirects disabled",
        "redirects_followed": False,
        "plaintext_artifact_written": False,
        "raw_response_published": False,
        "credentials_published": False,
    }
    _write_metadata(args.metadata, result)
    print(json.dumps({"metadata": str(args.metadata), "size": len(data), "sha256": result["sha256"]}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
