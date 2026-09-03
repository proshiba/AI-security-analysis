#!/usr/bin/env python3
"""旧ScreenConnect静的成果物を厳格な双用途config証跡へ投影する。"""

from __future__ import annotations

from collections.abc import Mapping
from ipaddress import ip_address
import re
from typing import Any
from urllib.parse import urlsplit


SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
HOST_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
APPLICATION_PATH = "/Bin/ScreenConnect.Client.application"


def _valid_host(value: object) -> str | None:
    if not isinstance(value, str) or value != value.strip().lower().rstrip("."):
        return None
    if not value or len(value) > 253 or any(ord(character) < 0x20 for character in value):
        return None
    try:
        ip_address(value)
        return value
    except ValueError:
        labels = value.split(".")
        if len(labels) < 2 or any(HOST_LABEL_RE.fullmatch(label) is None for label in labels):
            return None
        return value


def _legacy_relay_endpoint(value: object) -> dict[str, Any] | None:
    if not isinstance(value, Mapping) or set(value) != {
        "host",
        "port",
        "transport",
        "role",
        "c2_classification",
        "tenant_key_sha256",
        "tenant_key_length",
        "redacted_query",
    }:
        return None
    host = _valid_host(value.get("host"))
    port = value.get("port")
    key_length = value.get("tenant_key_length")
    if (
        host is None
        or not isinstance(port, int)
        or isinstance(port, bool)
        or not 1 <= port <= 65_535
        or value.get("transport") != "tcp_tls"
        or value.get("role") != "remote_management_relay"
        or value.get("c2_classification") != "dual_use_not_c2_by_itself"
        or not isinstance(value.get("tenant_key_sha256"), str)
        or SHA256_RE.fullmatch(value["tenant_key_sha256"]) is None
        or not isinstance(key_length, int)
        or isinstance(key_length, bool)
        or not 32 <= key_length <= 2_048
        or value.get("redacted_query") != f"?h={host}&p={port}&k=<redacted>"
    ):
        return None
    return {
        "host": host,
        "port": port,
        "transport": "tcp_tls",
        "role": "remote_management_relay",
        "confidence": "confirmed_static_configuration",
        "evidence": {
            "kind": "screenconnect_embedded_management_endpoint",
            "c2_classification": "dual_use_not_c2_by_itself",
            "malicious_use_confirmed": False,
            "legacy_projection": True,
        },
    }


def _legacy_application_endpoint(value: object) -> dict[str, Any] | None:
    if not isinstance(value, Mapping) or set(value) != {
        "url",
        "scheme",
        "host",
        "port",
        "path",
        "transport",
        "role",
        "contacted",
        "c2_classification",
    }:
        return None
    host = _valid_host(value.get("host"))
    port = value.get("port")
    scheme = value.get("scheme")
    url = value.get("url")
    try:
        parsed = urlsplit(url) if isinstance(url, str) else None
        parsed_port = parsed.port if parsed is not None else None
    except ValueError:
        return None
    if (
        host is None
        or scheme not in {"http", "https"}
        or not isinstance(port, int)
        or isinstance(port, bool)
        or not 1 <= port <= 65_535
        or value.get("path") != APPLICATION_PATH
        or value.get("transport") != ("tcp_tls" if scheme == "https" else "tcp")
        or value.get("role") != "screenconnect_clickonce_bootstrap"
        or value.get("contacted") is not False
        or value.get("c2_classification")
        != "dual_use_management_endpoint_not_c2_by_itself"
        or parsed is None
        or parsed.scheme != scheme
        or parsed.hostname != host
        or (parsed_port or (443 if scheme == "https" else 80)) != port
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path != APPLICATION_PATH
        or parsed.query
        or parsed.fragment
    ):
        return None
    return {
        "url": url,
        "host": host,
        "port": port,
        "transport": value["transport"],
        "path": APPLICATION_PATH,
        "role": "screenconnect_clickonce_bootstrap",
        "confidence": "confirmed_static_configuration",
        "evidence": {
            "kind": "screenconnect_embedded_management_endpoint",
            "c2_classification": "dual_use_management_endpoint_not_c2_by_itself",
            "malicious_use_confirmed": False,
            "legacy_projection": True,
        },
    }


def _screenconnect_context_valid(payload: object) -> bool:
    if not isinstance(payload, Mapping):
        return False
    context = payload.get("malicious_use_context")
    return not (
        payload.get("schema_version") != 1
        or payload.get("family") != "ScreenConnect RMM"
        or payload.get("classification") != "commercial_rmm_dual_use"
        or payload.get("malware_by_itself") is not False
        or payload.get("abuse_attribution") != "not_established"
        or payload.get("network_contacted") is not False
        or payload.get("sample_executed") is not False
        or not isinstance(context, Mapping)
        or context.get("assessment") != "requires_incident_context"
        or context.get("malicious_use_confirmed") is not False
        or context.get("unauthorized_installation_observed") is not False
        or context.get("embedded_management_endpoint_observed") is not True
        or context.get("requires_authorization_and_delivery_context") is not True
    )


def legacy_screenconnect_config(payload: object) -> dict[str, Any] | None:
    """新config契約を持たない旧成果物だけをfail-closedで正規化する。"""

    if (
        not _screenconnect_context_valid(payload)
        or not isinstance(payload, Mapping)
        or isinstance(payload.get("config"), Mapping)
    ):
        return None
    endpoints = []
    if "relay" in payload:
        relay = _legacy_relay_endpoint(payload.get("relay"))
        if relay is None:
            return None
        endpoints.append(relay)
    if "application" in payload:
        application = _legacy_application_endpoint(payload.get("application"))
        if application is None:
            return None
        endpoints.append(application)
    if not endpoints:
        return None
    return {
        "static_config_recovered": True,
        "config_endpoints": endpoints,
        "static_evidence": {
            "all_expected_fields_validated": True,
            "source": "screenconnect_legacy_embedded_management_configuration",
            "dual_use_endpoint": True,
            "legacy_projection": True,
        },
    }


def _validated_new_endpoint(value: object) -> dict[str, Any] | None:
    if not isinstance(value, Mapping):
        return None
    role = value.get("role")
    evidence = value.get("evidence")
    expected_classification = (
        "dual_use_not_c2_by_itself"
        if role == "remote_management_relay"
        else "dual_use_management_endpoint_not_c2_by_itself"
        if role == "screenconnect_clickonce_bootstrap"
        else None
    )
    expected_keys = (
        {"host", "port", "transport", "role", "confidence", "evidence"}
        if role == "remote_management_relay"
        else {"url", "host", "port", "transport", "path", "role", "confidence", "evidence"}
        if role == "screenconnect_clickonce_bootstrap"
        else set()
    )
    if (
        set(value) != expected_keys
        or value.get("confidence") != "confirmed_static_configuration"
        or not isinstance(evidence, Mapping)
        or set(evidence) != {"kind", "c2_classification", "malicious_use_confirmed"}
        or evidence.get("kind") != "screenconnect_embedded_management_endpoint"
        or evidence.get("c2_classification") != expected_classification
        or evidence.get("malicious_use_confirmed") is not False
    ):
        return None
    if role == "remote_management_relay":
        host = _valid_host(value.get("host"))
        port = value.get("port")
        if (
            host is None
            or not isinstance(port, int)
            or isinstance(port, bool)
            or not 1 <= port <= 65_535
            or value.get("transport") != "tcp_tls"
        ):
            return None
        return dict(value)
    projected = _legacy_application_endpoint(
        {
            "url": value.get("url"),
            "scheme": "https" if value.get("transport") == "tcp_tls" else "http",
            "host": value.get("host"),
            "port": value.get("port"),
            "path": value.get("path"),
            "transport": value.get("transport"),
            "role": role,
            "contacted": False,
            "c2_classification": expected_classification,
        }
    )
    if projected is None:
        return None
    projected["evidence"] = dict(evidence)
    projected.pop("confidence", None)
    projected["confidence"] = "confirmed_static_configuration"
    return projected


def validated_screenconnect_config(payload: object) -> dict[str, Any] | None:
    """新旧どちらのScreenConnect configも同じ厳格な証跡へ正規化する。"""

    if not _screenconnect_context_valid(payload) or not isinstance(payload, Mapping):
        return None
    config = payload.get("config")
    if not isinstance(config, Mapping):
        return legacy_screenconnect_config(payload)
    static_evidence = config.get("static_evidence")
    supplied_endpoints = config.get("config_endpoints")
    if (
        set(config) != {"static_config_recovered", "config_endpoints", "static_evidence"}
        or config.get("static_config_recovered") is not True
        or not isinstance(static_evidence, Mapping)
        or set(static_evidence) != {"all_expected_fields_validated", "source", "dual_use_endpoint"}
        or static_evidence.get("all_expected_fields_validated") is not True
        or static_evidence.get("source") != "screenconnect_embedded_management_configuration"
        or static_evidence.get("dual_use_endpoint") is not True
        or not isinstance(supplied_endpoints, list)
        or not supplied_endpoints
        or len(supplied_endpoints) > 2
    ):
        return None
    endpoints = [_validated_new_endpoint(value) for value in supplied_endpoints]
    if any(value is None for value in endpoints):
        return None
    return {
        "static_config_recovered": True,
        "config_endpoints": endpoints,
        "static_evidence": dict(static_evidence),
    }


def screenconnect_management_role(payload: object, mapping: object) -> str | None:
    """検証済みconfigに完全相関する双用途管理endpointのroleだけを返す。"""

    if not isinstance(mapping, Mapping):
        return None
    role = mapping.get("role")
    if role not in {"remote_management_relay", "screenconnect_clickonce_bootstrap"}:
        return None
    config = validated_screenconnect_config(payload)
    if config is None:
        return None
    host = _valid_host(mapping.get("host"))
    port = mapping.get("port")
    transport = mapping.get("transport")
    if host is None or not isinstance(port, int) or isinstance(port, bool):
        return None
    for endpoint in config["config_endpoints"]:
        if (
            endpoint.get("role") == role
            and endpoint.get("host") == host
            and endpoint.get("port") == port
            and endpoint.get("transport") == transport
        ):
            return str(role)
    return None
