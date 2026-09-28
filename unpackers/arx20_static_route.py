"""ARX20の有界抽出結果を通常の静的layer解析へ接続する。"""

from __future__ import annotations

from unpackers.arx20_chunk_unpacker import (
    MAX_INPUT_BYTES,
    Arx20ChunkError,
    Arx20ChunkLimitError,
    recover_arx20_chunk_payloads,
)


def recover_arx20_static_route(data: bytes) -> tuple[dict, list[tuple[str, bytes]]]:
    """包装の復元だけを返し、ファミリーやC2の確定へ昇格させない。"""
    report = {
        "schema_version": 1,
        "status": "not_candidate",
        "method": "code_verified_arx20_chunk_reassembly",
        "sample_executed": False,
        "instruction_emulation_performed": False,
        "network_contacted": False,
        "raw_key_published": False,
        "family_attribution_allowed": False,
        "c2_confirmation_allowed": False,
        "terminal_promotion_eligible": False,
    }
    if not isinstance(data, bytes):
        raise TypeError("入力はbytesで指定してください")
    if not data.startswith(b"MZ"):
        return report, []
    if len(data) > MAX_INPUT_BYTES:
        report["status"] = "input_limit_exceeded"
        return report, []
    try:
        results = recover_arx20_chunk_payloads(data)
    except Arx20ChunkLimitError as exc:
        report.update({
            "status": "limit_exceeded",
            "constraint": exc.constraint,
            "observed": exc.observed,
            "limit": exc.limit,
            "partial_results_returned": False,
        })
        return report, []
    except Arx20ChunkError:
        report["status"] = "structure_rejected"
        return report, []
    if not results:
        return report, []
    artifacts = []
    for result in results:
        kind = (
            "arx20-chunks-donut-shellcode"
            if result.evidence["payload_format"] == "donut"
            else "arx20-chunks-decoded-pe"
        )
        artifacts.append((kind, result.payload))
    report.update({
        "status": "recovered",
        "candidate_count": len(results),
        "candidate_set_complete": True,
        "candidates": [result.evidence for result in results],
    })
    return report, artifacts
