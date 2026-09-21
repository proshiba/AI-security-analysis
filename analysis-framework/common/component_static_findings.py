"""帰属未確定のcomponent handler成果を、機密値なしで独立記録する。"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Mapping
from typing import Any

from analysis_contract import handler_result_quality
from handler_catalog import sanitize_public_value

SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
COMPONENT_RE = re.compile(r"[a-z][a-z0-9_-]{0,63}\Z")
MAX_FINDINGS = 64
CLIPBOARD_IMPORTS = frozenset({
    "OpenClipboard", "CloseClipboard", "GetClipboardSequenceNumber",
    "GetClipboardData", "EmptyClipboard", "SetClipboardData",
})


def _valid_digest(value: object) -> bool:
    return isinstance(value, str) and SHA256_RE.fullmatch(value) is not None


def _bounded_count(value: object, limit: int) -> int | None:
    if not isinstance(value, list) or len(value) > limit:
        return None
    return len(value)


def _known_component_observations(component: str, result: Mapping[str, Any]) -> dict[str, Any]:
    """未検証の復号文字列・stack断片をコピーせず、型付き証拠だけ残す。"""

    if component == "clipboard_replacement_dll":
        imports = result.get("clipboard_imports")
        literals = result.get("address_literal_candidates")
        if (
            isinstance(imports, list)
            and len(imports) == len(CLIPBOARD_IMPORTS)
            and all(isinstance(item, str) for item in imports)
            and set(imports) == CLIPBOARD_IMPORTS
            and (count := _bounded_count(literals, 64)) is not None
            and count >= 2
        ):
            return {
                "clipboard_api_correlation": True,
                "xor_address_literal_candidate_count": count,
                "raw_address_literals_published": False,
            }
        return {}
    if component == "ror13_network_loader":
        candidates = result.get("network_candidates")
        if not isinstance(candidates, list) or len(candidates) != 1:
            return {}
        candidate = candidates[0]
        if not isinstance(candidate, Mapping):
            return {}
        host = candidate.get("host")
        port = candidate.get("port")
        if (
            not isinstance(host, str)
            or type(port) is not int
            or not 1 <= port <= 65535
            or candidate.get("transport") != "tcp"
            or candidate.get("confidence") != "static_candidate_dataflow_review_required"
        ):
            return {}
        try:
            address = ipaddress.IPv4Address(host)
        except ipaddress.AddressValueError:
            return {}
        if not address.is_global or str(address) != host:
            return {}
        return {
            "network_endpoint_candidates": [{
                "host": host,
                "port": port,
                "transport": "tcp",
                "confidence": "static_candidate_dataflow_review_required",
                "c2_confirmed": False,
                "liveness_confirmed": False,
            }],
            "raw_stack_fragments_published": False,
        }
    return {}


def _route_only_finding(
    family: str, attempt: Mapping[str, Any]
) -> dict[str, Any] | None:
    if attempt.get("status") != "handler_evidence_route_only":
        return None
    layer = attempt.get("layer")
    wrapper = attempt.get("result")
    evidence = attempt.get("handler_evidence")
    attribution = attempt.get("handler_family_attribution")
    if (
        not isinstance(layer, Mapping)
        or not _valid_digest(layer.get("sha256"))
        or not isinstance(wrapper, Mapping)
        or wrapper.get("executed_sample") is not False
        or wrapper.get("network_contacted") is not False
        or not isinstance(evidence, Mapping)
        or evidence.get("sufficient") is not True
        or not isinstance(attribution, Mapping)
        or attribution.get("route_only") is not True
        or attribution.get("supports_family_confirmation") is not False
    ):
        return None
    quota = wrapper.get("result_quota")
    if not isinstance(quota, Mapping) or quota.get("truncated") is not False:
        return None
    handler = wrapper.get("handler")
    result = wrapper.get("result")
    handler_id = attempt.get("handler_id")
    if (
        not isinstance(handler, Mapping)
        or not isinstance(result, Mapping)
        or not isinstance(handler_id, str)
        or handler.get("id") != handler_id
        or handler.get("family") != family
        or not handler_id.startswith(f"{family}:")
        or result.get("supports_family_attribution") is not False
        or result.get("terminal_family_confirmed") is not False
        or result.get("attribution_scope") != "component_handler_route"
        or result.get("family") != family
        or not isinstance(result.get("sample"), Mapping)
        or result["sample"].get("sha256") != layer["sha256"]
    ):
        return None
    minimum = handler.get("minimum_evidence_score")
    if type(minimum) is not int or not 1 <= minimum <= 100_000:
        return None
    computed = handler_result_quality(result, minimum_score=minimum)
    if dict(evidence) != computed:
        return None
    # handler result本体の公開文字列も、その秘密値由来のdigestも複製しない。
    finding = {
        "component_candidate": family,
        "handler_id": handler_id,
        "selected_layer_sha256": layer["sha256"],
        "evidence_tier": computed["tier_name"],
        "evidence_score": computed["score"],
        "family_attribution_confirmed": False,
        "c2_confirmed": False,
        "observations": _known_component_observations(family, result),
    }
    return sanitize_public_value(finding)


def build_component_static_findings(
    *, sha256: str, assessment: Mapping[str, Any]
) -> dict[str, Any]:
    """候補handlerのroute-only成功だけを、上限付き・fail-closedで射影する。"""

    if not _valid_digest(sha256):
        raise ValueError("component findingsのSHA-256が不正です")
    findings: list[dict[str, Any]] = []
    if assessment.get("executed_sample") is False and assessment.get("network_contacted") is False:
        families = assessment.get("families")
        if isinstance(families, list):
            for family_result in families[:256]:
                if not isinstance(family_result, Mapping) or family_result.get("confirmed") is not False:
                    continue
                family = family_result.get("family")
                if not isinstance(family, str) or COMPONENT_RE.fullmatch(family) is None:
                    continue
                attempts = family_result.get("attempts")
                if not isinstance(attempts, list):
                    continue
                for attempt in attempts[:256]:
                    if not isinstance(attempt, Mapping):
                        continue
                    finding = _route_only_finding(family, attempt)
                    if finding is not None:
                        findings.append(finding)
    unique = {
        (item["component_candidate"], item["handler_id"], item["selected_layer_sha256"]): item
        for item in findings
    }
    ordered = [unique[key] for key in sorted(unique)]
    truncated = len(ordered) > MAX_FINDINGS
    return {
        "schema_version": 1,
        "sha256": sha256,
        "status": "route_only_component_findings" if ordered else "no_route_only_component_findings",
        "finding_count": min(len(ordered), MAX_FINDINGS),
        "truncated": truncated,
        "findings": ordered[:MAX_FINDINGS],
        "evidence_boundary": {
            "family_attribution_confirmed": False,
            "c2_confirmed": False,
            "liveness_confirmed": False,
            "raw_payload_published": False,
            "raw_unvalidated_strings_published": False,
        },
        "safety": {"sample_executed": False, "network_contacted": False},
    }
