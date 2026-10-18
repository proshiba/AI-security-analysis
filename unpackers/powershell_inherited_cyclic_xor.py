"""親PowerShellの検証済みcontextを子scriptへ静的継承する。

同一PowerShell process内で取得scriptをIEXするloaderでは、子scriptが親定義の
復号関数と鍵を再利用する。親の限定profileをもう一度検証し、literal callと
``Marshal.Copy`` のsource spanだけをboundedに復元する。PowerShell、shellcode、
復元物は実行しない。
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import math
import re
from collections import Counter
from dataclasses import asdict, dataclass

from unpackers.powershell_cyclic_xor_calls import (
    CyclicXorCallLimits,
    recover_reviewed_cyclic_xor_context,
)
from unpackers.remcos_native_span_loader import recover_remcos_native_span_stage
from unpackers.remcos_polymorphic_xor_loader import (
    recover_remcos_polymorphic_xor_loader,
)

_IDENTIFIER = r"[A-Za-z_][A-Za-z0-9_]*"
_SIMPLE_INTEGER_ASSIGNMENT = re.compile(
    rf"(?i)(?<![A-Za-z0-9_])\$({_IDENTIFIER})\s*=\s*"
    r"(-?\d+)(?:\s*([+-])\s*(\d+))?\s*(?=;|\r?$)",
    re.MULTILINE,
)
_COPY_CALL = re.compile(
    rf"(?i)^\s*\${_IDENTIFIER}::Copy\(\s*\$({_IDENTIFIER})\s*,\s*"
    rf"(\d+|\${_IDENTIFIER})\s*,\s*\${_IDENTIFIER}\s*,\s*"
    rf"(\d+|\${_IDENTIFIER})\s*\)\s*$"
)


@dataclass(frozen=True)
class InheritedCyclicXorLimits:
    """親子context解析とremote span復元のhard limit。"""

    max_parent_bytes: int = 2 * 1024 * 1024
    max_child_bytes: int = 4 * 1024 * 1024
    max_response_bytes: int = 64 * 1024 * 1024
    max_decoded_response_bytes: int = 48 * 1024 * 1024
    max_calls: int = 512
    max_call_base64_characters: int = 2 * 1024 * 1024
    max_call_output_bytes: int = 1 * 1024 * 1024
    max_copy_spans: int = 8
    max_span_bytes: int = 32 * 1024 * 1024
    max_artifacts: int = 128


DEFAULT_LIMITS = InheritedCyclicXorLimits()


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _decode_source(value: bytes) -> tuple[str, str] | None:
    for encoding, source in (
        ("utf-8-sig", value),
        ("utf-16-le", value[2:]) if value.startswith(b"\xff\xfe") else ("", b""),
        ("cp1252", value),
    ):
        if not encoding:
            continue
        try:
            text = source.decode(encoding)
        except UnicodeDecodeError:
            continue
        if "\x00" not in text:
            return text, encoding
    return None


def _printable_utf8(value: bytes) -> str | None:
    try:
        text = value.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if not text or "\x00" in text:
        return None
    printable = sum(
        character.isprintable() or character in "\r\n\t" for character in text
    )
    return text if printable / len(text) >= 0.98 else None


def _looks_like_script(value: str) -> bool:
    lowered = value.casefold()
    return "$" in value and any(
        marker in lowered
        for marker in ("=", "::", ".invoke", "return ", "get-", "new-object")
    )


def _integer_assignments(source: str) -> dict[str, int]:
    observed: dict[str, list[int]] = {}
    for match in _SIMPLE_INTEGER_ASSIGNMENT.finditer(source):
        value = int(match.group(2))
        if match.group(3) is not None:
            operand = int(match.group(4))
            value = value + operand if match.group(3) == "+" else value - operand
        if -64 * 1024 * 1024 <= value <= 64 * 1024 * 1024:
            observed.setdefault(match.group(1).casefold(), []).append(value)
    return {name: values[0] for name, values in observed.items() if len(values) == 1}


def _resolve_integer(value: str, assignments: dict[str, int]) -> int | None:
    if value.startswith("$"):
        return assignments.get(value[1:].casefold())
    try:
        return int(value)
    except ValueError:
        return None


def recover_inherited_cyclic_xor_loader(
    parent_data: bytes,
    child_data: bytes,
    *,
    response_data: bytes | None = None,
    limits: InheritedCyclicXorLimits = DEFAULT_LIMITS,
) -> tuple[dict[str, object], list[tuple[str, bytes]]]:
    """親contextで子literalを復号し、任意の取得済みresponseからspanを復元する。"""

    base: dict[str, object] = {
        "schema_version": 1,
        "profile": "powershell-inherited-cyclic-xor-loader-v1",
        "status": "rejected",
        "parent_size": len(parent_data),
        "parent_sha256": _sha256(parent_data),
        "child_size": len(child_data),
        "child_sha256": _sha256(child_data),
        "candidate_set_complete": False,
        "candidate_set_truncated": False,
        "candidate_count": 0,
        "limits": asdict(limits),
        "candidates": [],
        "rejections": {},
        "safety": {
            "sample_executed": False,
            "network_contacted": False,
            "powershell_started": False,
            "shellcode_executed": False,
            "general_expression_evaluator_used": False,
            "raw_key_included": False,
            "raw_script_included": False,
        },
        "evidence_boundary": {
            "family_attribution_allowed": False,
            "c2_confirmation_allowed": False,
            "recovered_native_span_is_terminal_payload": False,
        },
    }
    if not isinstance(parent_data, bytes) or not isinstance(child_data, bytes):
        raise TypeError("parent_dataとchild_dataはbytesである必要があります")
    if (
        not parent_data
        or len(parent_data) > limits.max_parent_bytes
        or not child_data
        or len(child_data) > limits.max_child_bytes
    ):
        base["status"] = "input_size_rejected"
        return base, []
    parent_limits = CyclicXorCallLimits(max_input_bytes=limits.max_parent_bytes)
    context = recover_reviewed_cyclic_xor_context(parent_data, limits=parent_limits)
    base["parent_context"] = context.report
    if context.key is None or context.function_name is None:
        base["status"] = "parent_context_rejected"
        return base, []
    decoded = _decode_source(child_data)
    if decoded is None:
        base["status"] = "child_text_decode_failed"
        return base, []
    child_text, child_encoding = decoded
    call_re = re.compile(
        rf"(?i)(?<!function\s)\b{re.escape(context.function_name)}\s+"
        r"(['\"])([A-Za-z0-9+/=]{4,})\1(?:\s+(\d+))?"
    )
    calls = list(call_re.finditer(child_text))
    if len(calls) > limits.max_calls:
        base.update(
            {
                "status": "call_limit_exceeded",
                "candidate_set_truncated": True,
                "call_count_lower_bound": len(calls),
            }
        )
        return base, []
    candidates: list[dict[str, object]] = []
    decoded_texts: list[str] = []
    artifacts: list[tuple[str, bytes]] = []
    rejections: Counter[str] = Counter()
    seen: set[str] = set()
    for sequence, match in enumerate(calls, 1):
        encoded = match.group(2)
        if len(encoded) > limits.max_call_base64_characters or len(encoded) % 4:
            rejections["base64_size_rejected"] += 1
            continue
        try:
            ciphertext = base64.b64decode(encoded, validate=True)
        except (binascii.Error, ValueError):
            rejections["base64_rejected"] += 1
            continue
        if not ciphertext or len(ciphertext) > limits.max_call_output_bytes:
            rejections["decoded_size_rejected"] += 1
            continue
        clear = bytes(
            value ^ context.key[index % len(context.key)]
            for index, value in enumerate(ciphertext)
        )
        text = _printable_utf8(clear)
        if text is None:
            rejections["non_text_output"] += 1
            continue
        decoded_texts.append(text)
        flag = int(match.group(3)) if match.group(3) is not None else None
        digest = _sha256(clear)
        is_script = flag == 1 and _looks_like_script(text)
        emitted = is_script and digest not in seen
        candidates.append(
            {
                "sequence": sequence,
                "execute_flag": flag,
                "role": "iex_script_fragment" if is_script else "decoded_constant",
                "output_size": len(clear),
                "output_sha256": digest,
                "artifact_emitted": emitted,
            }
        )
        if emitted:
            if len(artifacts) >= limits.max_artifacts:
                base.update(
                    {
                        "status": "artifact_limit_exceeded",
                        "candidate_set_truncated": True,
                    }
                )
                return base, []
            seen.add(digest)
            artifacts.append((f"inherited-iex-fragment-{sequence:03d}.ps1", clear))

    assignments = _integer_assignments(child_text)
    copy_spans: list[tuple[int, int, str]] = []
    for decoded_text in decoded_texts:
        copy = _COPY_CALL.fullmatch(decoded_text)
        if copy is None:
            continue
        offset = _resolve_integer(copy.group(2), assignments)
        length = _resolve_integer(copy.group(3), assignments)
        if offset is None or length is None or offset < 0 or length <= 0:
            rejections["copy_span_unresolved"] += 1
            continue
        if length > limits.max_span_bytes:
            rejections["copy_span_size_rejected"] += 1
            continue
        copy_spans.append((offset, length, copy.group(1).casefold()))
    copy_spans = sorted(set(copy_spans))
    remote_transform = context.report.get("remote_payload_transform")
    expected_prefix_size = (
        remote_transform.get("substring_offset")
        if isinstance(remote_transform, dict)
        and isinstance(remote_transform.get("substring_offset"), int)
        else None
    )
    span_profile_valid = bool(copy_spans) and len(copy_spans) <= limits.max_copy_spans
    if span_profile_valid:
        expected_offset = 0
        buffers = {buffer_name for _, _, buffer_name in copy_spans}
        for offset, length, _buffer_name in copy_spans:
            if offset != expected_offset:
                span_profile_valid = False
                break
            expected_offset += length
        if len(buffers) != 1 or expected_prefix_size != expected_offset:
            span_profile_valid = False

    response_report: dict[str, object] = {
        "status": "not_supplied",
        "network_contacted": False,
        "copy_span_profile_valid": span_profile_valid,
        "copy_span_count": len(copy_spans),
    }
    if response_data is not None:
        if not isinstance(response_data, bytes):
            raise TypeError("response_dataはbytesまたはNoneである必要があります")
        response_report.update(
            {
                "input_size": len(response_data),
                "input_sha256": _sha256(response_data),
            }
        )
        if len(response_data) > limits.max_response_bytes:
            response_report["status"] = "input_size_rejected"
        elif not response_data:
            response_report["status"] = "empty_input_rejected"
        elif not span_profile_valid:
            response_report["status"] = "copy_span_profile_rejected"
        else:
            try:
                compact = re.sub(rb"\s+", b"", response_data)
                remote = base64.b64decode(compact, validate=True)
            except (binascii.Error, ValueError):
                remote = b""
                response_report["status"] = "strict_base64_rejected"
            if not remote and response_report["status"] == "not_supplied":
                response_report["status"] = "decoded_content_empty"
            if remote and len(remote) <= limits.max_decoded_response_bytes:
                recovered_spans: list[dict[str, object]] = []
                native_blobs: list[bytes] = []
                for index, (offset, length, _buffer_name) in enumerate(copy_spans, 1):
                    if offset + length > len(remote):
                        response_report["status"] = "copy_span_bounds_rejected"
                        artifacts = [
                            item
                            for item in artifacts
                            if not item[0].startswith("remote-native-span-")
                        ]
                        recovered_spans = []
                        break
                    if len(artifacts) >= limits.max_artifacts:
                        response_report["status"] = "artifact_limit_exceeded"
                        base.update(
                            {
                                "status": "artifact_limit_exceeded",
                                "candidate_set_truncated": True,
                            }
                        )
                        return base, []
                    blob = remote[offset : offset + length]
                    native_blobs.append(blob)
                    digest = _sha256(blob)
                    artifacts.append((f"remote-native-span-{index:02d}.bin", blob))
                    counts = Counter(blob)
                    entropy = -sum(
                        (count / len(blob)) * math.log2(count / len(blob))
                        for count in counts.values()
                    )
                    recovered_spans.append(
                        {
                            "sequence": index,
                            "source_offset": offset,
                            "size": length,
                            "sha256": digest,
                            "entropy": round(entropy, 4),
                            "mz_prefix": blob.startswith(b"MZ"),
                            "terminal_payload_confirmed": False,
                        }
                    )
                if recovered_spans:
                    if len(native_blobs) == 2:
                        xor_report, xor_artifacts = (
                            recover_remcos_polymorphic_xor_loader(
                                native_blobs[0], native_blobs[1]
                            )
                        )
                        response_report["polymorphic_xor_loader"] = xor_report
                        stage_report, stage_artifacts = (
                            recover_remcos_native_span_stage(
                                native_blobs[0], native_blobs[1]
                            )
                        )
                        response_report["native_span_stage"] = stage_report
                        derived_artifacts = xor_artifacts + stage_artifacts
                        normalization: dict[str, object] = {
                            "status": "not_applicable",
                        }
                        if len(xor_artifacts) == 1 and len(stage_artifacts) == 1:
                            prefix = xor_artifacts[0][1]
                            stage = stage_artifacts[0][1]
                            padding_size = stage_report.get("zero_padding_size")
                            prefix_report = stage_report.get(
                                "recovered_payload_prefix", {}
                            )
                            if (
                                stage.startswith(prefix)
                                and isinstance(padding_size, int)
                                and len(stage) - len(prefix) == padding_size
                                and isinstance(prefix_report, dict)
                                and prefix_report.get("size") == len(prefix)
                                and prefix_report.get("sha256") == _sha256(prefix)
                            ):
                                derived_artifacts = stage_artifacts
                                normalization = {
                                    "status": "single_logical_candidate",
                                    "primary_artifact": stage_artifacts[0][0],
                                    "legacy_prefix_size": len(prefix),
                                    "legacy_prefix_sha256": _sha256(prefix),
                                    "zero_padding_tail_size": padding_size,
                                    "prefix_relation_verified": True,
                                }
                            else:
                                derived_artifacts = []
                                normalization = {
                                    "status": "derived_output_conflict",
                                    "derived_artifacts_emitted": False,
                                }
                        response_report["native_stage_normalization"] = normalization
                        if (
                            len(artifacts) + len(derived_artifacts)
                            > limits.max_artifacts
                        ):
                            response_report["status"] = "artifact_limit_exceeded"
                            base.update(
                                {
                                    "status": "artifact_limit_exceeded",
                                    "candidate_set_truncated": True,
                                }
                            )
                            return base, []
                        artifacts.extend(derived_artifacts)
                    else:
                        response_report["polymorphic_xor_loader"] = {
                            "status": "not_applicable_span_count",
                            "span_count": len(native_blobs),
                        }
                        response_report["native_span_stage"] = {
                            "status": "not_applicable_span_count",
                            "span_count": len(native_blobs),
                        }
                    response_report.update(
                        {
                            "status": "native_spans_recovered",
                            "decoded_size": len(remote),
                            "decoded_sha256": _sha256(remote),
                            "recovered_spans": recovered_spans,
                        }
                    )
            elif remote:
                response_report["status"] = "decoded_size_rejected"

    base.update(
        {
            "status": "artifacts_recovered" if artifacts else "calls_recovered",
            "child_encoding": child_encoding,
            "candidate_set_complete": True,
            "candidate_count": len(candidates),
            "decoded_call_count": len(decoded_texts),
            "iex_artifact_count": sum(
                name.startswith("inherited-iex-fragment-") for name, _ in artifacts
            ),
            "copy_span_profile_valid": span_profile_valid,
            "copy_spans": [
                {"source_offset": offset, "size": length}
                for offset, length, _buffer_name in copy_spans
            ],
            "response_recovery": response_report,
            "candidates": candidates,
            "rejections": dict(sorted(rejections.items())),
        }
    )
    return base, artifacts
