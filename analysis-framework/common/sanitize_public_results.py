"""外部通信を行わず、公開JSON解析結果を無害化して監査する。

MalwareBazaarの応答には、報告者識別情報、コメント、archive password、
vendor情報など、provider所有のfieldが含まれる可能性がある。raw応答は
Git管理外の `.work` にだけ保存する。このmoduleは明示的に許可した最小限の
要約だけを公開し、厳密なallowlistで検証する。

tree監査はemail形式の値も拒否する。`--write` は該当値を固定の伏字へ
置換し、check modeはread-onlyかつfail-closedで動作する。
"""

from __future__ import annotations

import argparse
from datetime import datetime
import json
from pathlib import Path
import re
from typing import Any


SCHEMA_VERSION = 1
REDACTED_EMAIL = "[redacted-email]"
MALWAREBAZAAR_FILENAME = "malwarebazaar-info.json"
SUMMARY_KEYS = frozenset(
    {
        "schema_version",
        "provider",
        "query_status",
        "raw_provider_response_published",
        "sample",
    }
)
SAMPLE_KEYS = frozenset(
    {
        "sha256",
        "first_seen",
        "last_seen",
        "file_size",
        "file_type",
        "file_type_mime",
        "signature",
        "tags",
    }
)

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_FILE_TYPE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,31}$")
_MIME_RE = re.compile(r"^[A-Za-z0-9.+-]+/[A-Za-z0-9.+-]+$")
_PUBLIC_LABEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._+-]{0,127}$")
_EMAIL_RE = re.compile(
    r"(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]+@"
    r"[A-Za-z0-9.-]+\.[A-Za-z]{2,63}(?![A-Za-z0-9._%+-])"
)


class PublicArtifactError(ValueError):
    """公開artifactがfail-closed契約に違反した場合の例外。"""


def _require_exact_keys(value: dict[str, Any], allowed: frozenset[str], context: str) -> None:
    actual = frozenset(value)
    if actual != allowed:
        missing = sorted(allowed - actual)
        unexpected = sorted(actual - allowed)
        raise PublicArtifactError(
            f"{context} keys do not match the public allowlist "
            f"(missing={missing}, unexpected={unexpected})"
        )


def _validate_timestamp(value: Any, field: str, *, nullable: bool) -> None:
    if value is None and nullable:
        return
    if not isinstance(value, str):
        raise PublicArtifactError(f"{field} must be a timestamp string")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%d %H:%M:%S")
    except ValueError as exc:
        raise PublicArtifactError(f"{field} must use YYYY-MM-DD HH:MM:SS") from exc
    if parsed.strftime("%Y-%m-%d %H:%M:%S") != value:
        raise PublicArtifactError(f"{field} is not a canonical timestamp")


def _validate_public_label(value: Any, field: str, *, nullable: bool = True) -> None:
    if value is None and nullable:
        return
    if not isinstance(value, str) or not _PUBLIC_LABEL_RE.fullmatch(value):
        raise PublicArtifactError(f"{field} must be a short public label")


def validate_malwarebazaar_summary(document: Any, expected_sha256: str) -> None:
    """公開MalwareBazaar要約1件を厳密なschemaで検証する。"""
    if not isinstance(document, dict):
        raise PublicArtifactError("MalwareBazaar summary must be a JSON object")
    _require_exact_keys(document, SUMMARY_KEYS, "summary")
    if type(document["schema_version"]) is not int or document["schema_version"] != SCHEMA_VERSION:
        raise PublicArtifactError("unsupported public summary schema_version")
    if document["provider"] != "MalwareBazaar":
        raise PublicArtifactError("provider must be MalwareBazaar")
    if document["query_status"] != "ok":
        raise PublicArtifactError("only successful exact-hash metadata may be published")
    if document["raw_provider_response_published"] is not False:
        raise PublicArtifactError("raw_provider_response_published must be false")

    sample = document["sample"]
    if not isinstance(sample, dict):
        raise PublicArtifactError("sample must be a JSON object")
    _require_exact_keys(sample, SAMPLE_KEYS, "sample")

    if not isinstance(expected_sha256, str) or not _SHA256_RE.fullmatch(expected_sha256):
        raise PublicArtifactError("parent directory must be a lowercase SHA-256")
    if sample["sha256"] != expected_sha256:
        raise PublicArtifactError("sample SHA-256 does not match its parent directory")
    _validate_timestamp(sample["first_seen"], "sample.first_seen", nullable=False)
    _validate_timestamp(sample["last_seen"], "sample.last_seen", nullable=True)

    file_size = sample["file_size"]
    if isinstance(file_size, bool) or not isinstance(file_size, int) or file_size < 0:
        raise PublicArtifactError("sample.file_size must be a non-negative integer")

    file_type = sample["file_type"]
    if file_type is not None and (
        not isinstance(file_type, str) or not _FILE_TYPE_RE.fullmatch(file_type)
    ):
        raise PublicArtifactError("sample.file_type is not a safe type label")
    mime = sample["file_type_mime"]
    if mime is not None and (not isinstance(mime, str) or not _MIME_RE.fullmatch(mime)):
        raise PublicArtifactError("sample.file_type_mime is not a safe MIME label")
    _validate_public_label(sample["signature"], "sample.signature")

    tags = sample["tags"]
    if not isinstance(tags, list) or len(tags) > 64:
        raise PublicArtifactError("sample.tags must be a bounded list")
    for index, tag in enumerate(tags):
        _validate_public_label(tag, f"sample.tags[{index}]", nullable=False)
    if len(tags) != len(set(tags)):
        raise PublicArtifactError("sample.tags must not contain duplicates")


def sanitize_malwarebazaar_document(document: Any, expected_sha256: str) -> dict[str, Any]:
    """exact-hash raw応答1件を厳密な公開要約へ変換する。"""
    if not isinstance(document, dict):
        raise PublicArtifactError("MalwareBazaar response must be a JSON object")

    if any(key in document for key in ("schema_version", "sample", "provider")):
        validate_malwarebazaar_summary(document, expected_sha256)
        return document

    if document.get("query_status") != "ok":
        raise PublicArtifactError("MalwareBazaar response query_status must be ok")
    records = document.get("data")
    if not isinstance(records, list) or len(records) != 1 or not isinstance(records[0], dict):
        raise PublicArtifactError("MalwareBazaar response must contain exactly one record")
    record = records[0]
    tags = record.get("tags")
    if tags is None:
        tags = []
    summary = {
        "schema_version": SCHEMA_VERSION,
        "provider": "MalwareBazaar",
        "query_status": "ok",
        "raw_provider_response_published": False,
        "sample": {
            "sha256": record.get("sha256_hash"),
            "first_seen": record.get("first_seen"),
            "last_seen": record.get("last_seen"),
            "file_size": record.get("file_size"),
            "file_type": record.get("file_type"),
            "file_type_mime": record.get("file_type_mime"),
            "signature": record.get("signature"),
            "tags": tags,
        },
    }
    validate_malwarebazaar_summary(summary, expected_sha256)
    return summary


def _redact_email_values(value: Any, location: str = "$") -> tuple[Any, int]:
    if isinstance(value, dict):
        output: dict[str, Any] = {}
        count = 0
        for key, item in value.items():
            if _EMAIL_RE.search(str(key)):
                raise PublicArtifactError(f"email-like JSON key at {location}")
            cleaned, found = _redact_email_values(item, f"{location}.{key}")
            output[key] = cleaned
            count += found
        return output, count
    if isinstance(value, list):
        output_list: list[Any] = []
        count = 0
        for index, item in enumerate(value):
            cleaned, found = _redact_email_values(item, f"{location}[{index}]")
            output_list.append(cleaned)
            count += found
        return output_list, count
    if isinstance(value, str) and value != REDACTED_EMAIL:
        cleaned, count = _EMAIL_RE.subn(REDACTED_EMAIL, value)
        return cleaned, count
    return value, 0


def _assert_no_email_values(value: Any, location: str = "$") -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if _EMAIL_RE.search(str(key)):
                raise PublicArtifactError(f"email-like JSON key at {location}")
            _assert_no_email_values(item, f"{location}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _assert_no_email_values(item, f"{location}[{index}]")
    elif isinstance(value, str) and value != REDACTED_EMAIL and _EMAIL_RE.search(value):
        raise PublicArtifactError(f"email-like public value at {location}")


def process_public_tree(root: Path, *, write: bool = False) -> dict[str, int]:
    """root配下の全JSON文書を無害化または監査する。

    書込み前に全fileをparseして検証するため、検証失敗時に一部だけ変換された
    result treeを残さない。
    """
    root = root.resolve()
    if not root.is_dir():
        raise PublicArtifactError(f"public result root is not a directory: {root}")

    pending: dict[Path, Any] = {}
    json_files = 0
    malwarebazaar_files = 0
    email_redactions = 0
    for path in sorted(root.rglob("*.json")):
        json_files += 1
        try:
            original = json.loads(path.read_text(encoding="utf-8-sig"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise PublicArtifactError(f"invalid public JSON: {path}") from exc

        transformed = original
        if path.name == MALWAREBAZAAR_FILENAME:
            malwarebazaar_files += 1
            expected_sha256 = path.parent.name
            if write:
                transformed = sanitize_malwarebazaar_document(transformed, expected_sha256)
            else:
                validate_malwarebazaar_summary(transformed, expected_sha256)

        if write:
            transformed, found = _redact_email_values(transformed)
            email_redactions += found
        _assert_no_email_values(transformed)
        if path.name == MALWAREBAZAAR_FILENAME:
            validate_malwarebazaar_summary(transformed, path.parent.name)
        if transformed != original:
            pending[path] = transformed

    if write:
        for path, document in pending.items():
            path.write_text(
                json.dumps(document, indent=2, ensure_ascii=False) + "\n",
                encoding="utf-8",
            )

    return {
        "json_files": json_files,
        "malwarebazaar_files": malwarebazaar_files,
        "changed_files": len(pending),
        "email_redactions": email_redactions,
    }


def build_parser() -> argparse.ArgumentParser:
    """安全側を既定とするCLI引数parserを構築する。"""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, type=Path, help="監査する公開result tree")
    parser.add_argument(
        "--write",
        action="store_true",
        help="raw MalwareBazaar文書を要約し、email形式のJSON値を伏字にする",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """offline公開artifact無害化またはread-only監査を実行する。"""
    args = build_parser().parse_args(argv)
    report = process_public_tree(args.root, write=args.write)
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
