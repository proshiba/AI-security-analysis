#!/usr/bin/env python3
"""Fetch one explicitly authorized HTTP(S) artifact into an AES ZIP.

The response is bounded, redirects are refused, and plaintext response bytes are
never written to disk.  This is an evidence-collection helper, not a C2 client.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlsplit

import pyzipper


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001, ANN201
        raise urllib.error.HTTPError(req.full_url, code, "redirect refused", headers, fp)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", required=True)
    parser.add_argument("--allow-network", action="store_true")
    parser.add_argument("--output-zip", required=True, type=Path)
    parser.add_argument("--metadata", required=True, type=Path)
    parser.add_argument("--member-name", default="retrieved-artifact.bin")
    parser.add_argument("--password", default="infected")
    parser.add_argument("--timeout", type=float, default=15.0)
    parser.add_argument("--max-bytes", type=int, default=64 * 1024 * 1024)
    args = parser.parse_args()
    if not args.allow_network:
        raise SystemExit("refusing network request without --allow-network")
    parsed = urlsplit(args.url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("only an explicit HTTP(S) URL is accepted")

    opener = urllib.request.build_opener(NoRedirect())
    request = urllib.request.Request(args.url, method="GET", headers={"User-Agent": "AI-security-analysis/1.0"})
    with opener.open(request, timeout=args.timeout) as response:
        data = response.read(args.max_bytes + 1)
        if len(data) > args.max_bytes:
            raise ValueError("response exceeded --max-bytes")
        status = response.status
        headers = dict(response.headers.items())

    args.output_zip.parent.mkdir(parents=True, exist_ok=True)
    with pyzipper.AESZipFile(
        args.output_zip,
        "w",
        compression=pyzipper.ZIP_DEFLATED,
        encryption=pyzipper.WZ_AES,
    ) as archive:
        archive.setpassword(args.password.encode())
        archive.setencryption(pyzipper.WZ_AES, nbits=256)
        archive.writestr(args.member_name, data)

    result = {
        "schema_version": 1,
        "url": args.url,
        "http_status": status,
        "response_headers": headers,
        "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "output_archive": str(args.output_zip),
        "archive_member": args.member_name,
        "executed": False,
        "network_contacted": True,
        "network_scope": "one bounded GET; redirects disabled",
        "plaintext_artifact_written": False,
    }
    args.metadata.parent.mkdir(parents=True, exist_ok=True)
    args.metadata.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"metadata": str(args.metadata), "size": len(data), "sha256": result["sha256"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
