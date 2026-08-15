#!/usr/bin/env python3
"""能動C2 profile、共通monitor、Nmap登録の整合性をオフライン監査する。"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections.abc import Iterable
from pathlib import Path
from typing import Any

COMMON_ROOT = Path(__file__).resolve().parent
FRAMEWORK_ROOT = COMMON_ROOT.parent
REPOSITORY_ROOT = FRAMEWORK_ROOT.parent
NMAP_ROOT = FRAMEWORK_ROOT / "nmap"
NMAP_PROFILES = NMAP_ROOT / "profiles.json"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
NMAP_MODE_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
NSE_SELECTOR_RE = re.compile(
    r'local\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*stdnse\.get_script_args\("([^"]+)"\)'
)

if str(COMMON_ROOT) not in sys.path:
    sys.path.insert(0, str(COMMON_ROOT))

import c2_protocol_probe_profiles as profile_module  # noqa: E402
import monitor_recent_c2 as monitor_module  # noqa: E402


class IntegrationAuditError(ValueError):
    """監査入力を安全に解釈できない場合の例外。"""


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for key, value in pairs:
        if key in output:
            raise IntegrationAuditError(f"JSONに重複keyがあります: {key}")
        output[key] = value
    return output


def _reject_constant(value: str) -> None:
    raise IntegrationAuditError(f"JSONに非標準数値があります: {value}")


def _read_json_object(path: Path, *, maximum_bytes: int = 1024 * 1024) -> dict[str, Any]:
    try:
        metadata = path.stat()
    except OSError as exc:
        raise IntegrationAuditError(f"JSONをstatできません: {path}") from exc
    if not path.is_file() or path.is_symlink() or metadata.st_size > maximum_bytes:
        raise IntegrationAuditError(f"JSONは上限内の通常fileである必要があります: {path}")
    try:
        text = path.read_text(encoding="utf-8-sig")
        value = json.loads(
            text,
            object_pairs_hook=_reject_duplicates,
            parse_constant=_reject_constant,
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise IntegrationAuditError(f"JSONを厳格に読めません: {path}") from exc
    if not isinstance(value, dict):
        raise IntegrationAuditError(f"JSON rootはobjectである必要があります: {path}")
    return value


def _canonical_family(value: Any) -> str:
    return str(value or "").strip().casefold()


def _nse_dispatched_modes(text: str) -> set[str] | None:
    """NSEのmode/family selectorから明示dispatch値を静的に抽出する。"""

    selectors = [
        variable
        for variable, argument in NSE_SELECTOR_RE.findall(text)
        if argument.endswith((".mode", ".family"))
    ]
    if not selectors:
        return None
    values: set[str] = set()
    for variable in selectors:
        comparison = re.compile(
            rf'\b{re.escape(variable)}\s*(?:==|~=)\s*"([a-z0-9][a-z0-9._-]{{0,63}})"'
        )
        values.update(comparison.findall(text))
    return values


def _validate_required_contracts(
    required_contracts: Iterable[dict[str, str]],
) -> list[dict[str, str]]:
    output: list[dict[str, str]] = []
    seen_handlers: set[str] = set()
    for raw in required_contracts:
        if not isinstance(raw, dict):
            raise IntegrationAuditError("required contractはobjectである必要があります")
        contract = {
            key: str(raw.get(key) or "").strip()
            for key in ("handler", "protocol", "method", "nmap_family")
        }
        if not all(contract.values()):
            raise IntegrationAuditError("required contractの4項目はすべて必要です")
        if contract["handler"] in seen_handlers:
            raise IntegrationAuditError("required contractのhandlerが重複しています")
        seen_handlers.add(contract["handler"])
        contract["nmap_family"] = contract["nmap_family"].casefold()
        output.append(contract)
    return output


def audit_integration_state(
    *,
    profile_methods: dict[str, tuple[str, str]],
    loaded_profiles: dict[str, dict[str, Any]],
    allowed_methods: set[str],
    active_methods: set[str],
    method_ceilings: dict[str, float],
    method_labels: dict[str, str],
    nmap_mapping: dict[str, Any],
    nmap_root: Path,
    required_contracts: Iterable[dict[str, str]] = (),
) -> dict[str, Any]:
    """純粋な入力から4層のdriftを検出する。外部通信やfile更新は行わない。"""

    errors: list[dict[str, str]] = []
    warnings: list[dict[str, str]] = []

    def add_error(code: str, detail: str) -> None:
        errors.append({"code": code, "detail": detail})

    def add_warning(code: str, detail: str) -> None:
        warnings.append({"code": code, "detail": detail})

    handler_rows: list[dict[str, Any]] = []
    method_owners: dict[str, str] = {}
    for handler, pair in sorted(profile_methods.items()):
        if (
            not isinstance(handler, str)
            or not isinstance(pair, tuple)
            or len(pair) != 2
            or any(not isinstance(value, str) or not value for value in pair)
        ):
            add_error("invalid_handler_contract", repr((handler, pair)))
            continue
        protocol, method = pair
        previous = method_owners.get(method)
        if previous and previous != handler:
            add_error("duplicate_method_owner", f"{method}: {previous}, {handler}")
        method_owners[method] = handler
        missing_layers: list[str] = []
        for present, layer in (
            (method in allowed_methods, "allowed_methods"),
            (method in active_methods, "active_methods"),
            (method in method_ceilings, "method_ceilings"),
            (method in method_labels, "method_labels"),
        ):
            if not present:
                missing_layers.append(layer)
                add_error("monitor_method_missing", f"{handler}/{method}: {layer}")
        ceiling = method_ceilings.get(method)
        if ceiling is not None and (
            isinstance(ceiling, bool)
            or not isinstance(ceiling, (int, float))
            or not 0.0 <= float(ceiling) <= 1.0
        ):
            add_error("invalid_method_ceiling", f"{method}: {ceiling!r}")
        label = method_labels.get(method)
        if label is not None and (not isinstance(label, str) or not label.strip()):
            add_error("invalid_method_label", method)
        handler_rows.append(
            {
                "handler": handler,
                "protocol": protocol,
                "method": method,
                "monitor_complete": not missing_layers,
            }
        )

    profile_families: set[str] = set()
    profiles_by_handler: dict[str, int] = {}
    for profile_id, profile in sorted(loaded_profiles.items()):
        handler = str(profile.get("handler") or "")
        expected = profile_methods.get(handler)
        observed = (profile.get("protocol"), profile.get("method"))
        if expected is None:
            add_error("profile_handler_unknown", f"{profile_id}: {handler}")
        elif expected != observed:
            add_error(
                "profile_handler_pair_mismatch",
                f"{profile_id}: expected={expected!r}, observed={observed!r}",
            )
        family = _canonical_family(profile.get("family"))
        if not family:
            add_error("profile_family_missing", profile_id)
        else:
            profile_families.add(family)
        samples = profile.get("sample_sha256s")
        if (
            not isinstance(samples, list)
            or not samples
            or any(not isinstance(value, str) or not SHA256_RE.fullmatch(value) for value in samples)
        ):
            add_error("profile_sample_binding_invalid", profile_id)
        profiles_by_handler[handler] = profiles_by_handler.get(handler, 0) + 1

    canonical = nmap_mapping.get("canonical_families")
    nmap_schema_version = nmap_mapping.get("schema_version")
    if nmap_schema_version not in {1, 2} or not isinstance(canonical, list):
        add_error("nmap_mapping_schema_invalid", "schema_version 1／2とcanonical_families listが必要です")
        canonical = []

    nmap_families: set[str] = set()
    nmap_aliases: set[str] = set()
    script_records: dict[str, dict[str, Any]] = {}
    root = nmap_root.resolve()
    for index, raw in enumerate(canonical):
        if not isinstance(raw, dict):
            add_error("nmap_family_invalid", f"index={index}")
            continue
        family = _canonical_family(raw.get("family"))
        if not family or family in nmap_families or family in nmap_aliases:
            add_error("nmap_family_duplicate_or_missing", family or f"index={index}")
            continue
        nmap_families.add(family)
        aliases = raw.get("aliases", [])
        if not isinstance(aliases, list):
            add_error("nmap_aliases_invalid", family)
            aliases = []
        for alias_raw in aliases:
            alias = _canonical_family(alias_raw)
            if not alias or alias in nmap_families or alias in nmap_aliases:
                add_error("nmap_alias_duplicate_or_missing", f"{family}: {alias!r}")
            else:
                nmap_aliases.add(alias)

        modes = raw.get("modes")
        normalized_modes: list[str] = []
        if (
            not isinstance(modes, list)
            or not modes
            or any(type(mode) is not str or NMAP_MODE_RE.fullmatch(mode) is None for mode in modes)
            or len(set(modes)) != len(modes)
        ):
            add_error("nmap_modes_invalid", family)
        else:
            normalized_modes = list(modes)

        relative = raw.get("script")
        if not isinstance(relative, str) or not relative:
            add_error("nmap_script_missing", family)
            continue
        lexical = Path(relative)
        if lexical.is_absolute() or any(part in {"", ".", ".."} for part in lexical.parts):
            add_error("nmap_script_path_unsafe", f"{family}: {relative}")
            continue
        candidate = nmap_root.joinpath(*lexical.parts)
        try:
            resolved = candidate.resolve(strict=True)
            resolved.relative_to(root)
            text = resolved.read_text(encoding="utf-8")
        except (OSError, ValueError, UnicodeError) as exc:
            add_error("nmap_script_unreadable", f"{family}: {relative}: {type(exc).__name__}")
            continue
        if not resolved.is_file() or resolved.is_symlink():
            add_error("nmap_script_not_regular", f"{family}: {relative}")
            continue
        if "categories" not in text or "c2_confirmed" not in text:
            add_error("nmap_script_contract_marker_missing", f"{family}: {relative}")
        record = script_records.setdefault(
            relative,
            {
                "path": str(resolved),
                "families": [],
                "declared_modes": set(),
                "dispatched_modes": _nse_dispatched_modes(text),
            },
        )
        record["families"].append(family)
        record["declared_modes"].update(normalized_modes)

    method_binding_count = 0
    if nmap_schema_version == 2:
        if nmap_mapping.get("execution_backend") != "nmap_nse_only":
            add_error(
                "nmap_execution_backend_invalid",
                repr(nmap_mapping.get("execution_backend")),
            )
        bindings = nmap_mapping.get("method_bindings")
        if not isinstance(bindings, list) or not bindings:
            add_error("nmap_method_bindings_invalid", "method_bindingsは空でないlistが必要です")
            bindings = []
        binding_methods: set[str] = set()
        for index, raw in enumerate(bindings):
            if not isinstance(raw, dict):
                add_error("nmap_method_binding_invalid", f"index={index}")
                continue
            method = raw.get("method")
            relative = raw.get("script")
            mode = raw.get("mode")
            confirmation = raw.get("confirmation_allowed")
            if not isinstance(method, str) or not method or method in binding_methods:
                add_error("nmap_method_binding_duplicate_or_missing", repr(method))
                continue
            binding_methods.add(method)
            method_binding_count += 1
            if method not in allowed_methods:
                add_error("nmap_method_binding_unknown", method)
            if not isinstance(mode, str) or NMAP_MODE_RE.fullmatch(mode) is None:
                add_error("nmap_method_binding_mode_invalid", f"{method}: {mode!r}")
                continue
            if type(confirmation) is not bool:
                add_error("nmap_method_confirmation_invalid", f"{method}: {confirmation!r}")
            if not isinstance(relative, str) or not relative:
                add_error("nmap_method_script_missing", method)
                continue
            lexical = Path(relative)
            if lexical.is_absolute() or any(part in {"", ".", ".."} for part in lexical.parts):
                add_error("nmap_method_script_path_unsafe", f"{method}: {relative}")
                continue
            candidate = nmap_root.joinpath(*lexical.parts)
            try:
                resolved = candidate.resolve(strict=True)
                resolved.relative_to(root)
                text = resolved.read_text(encoding="utf-8")
            except (OSError, ValueError, UnicodeError) as exc:
                add_error(
                    "nmap_method_script_unreadable",
                    f"{method}: {relative}: {type(exc).__name__}",
                )
                continue
            if not resolved.is_file() or resolved.is_symlink():
                add_error("nmap_method_script_not_regular", f"{method}: {relative}")
                continue
            if "categories" not in text or "c2_confirmed" not in text:
                add_error("nmap_method_script_contract_marker_missing", f"{method}: {relative}")
            record = script_records.setdefault(
                relative,
                {
                    "path": str(resolved),
                    "families": [],
                    "declared_modes": set(),
                    "dispatched_modes": _nse_dispatched_modes(text),
                },
            )
            record["families"].append(f"method:{method}")
            record["declared_modes"].add(mode)

        for method in sorted(allowed_methods - binding_methods):
            add_error("monitor_method_missing_from_nmap", method)
        for method in sorted(binding_methods - allowed_methods):
            add_error("nmap_method_missing_from_monitor", method)
        declared_count = nmap_mapping.get("network_method_count")
        if type(declared_count) is not int or declared_count != len(bindings):
            add_error(
                "nmap_method_count_mismatch",
                f"declared={declared_count!r}, actual={len(bindings)}",
            )

    for relative, record in sorted(script_records.items()):
        dispatched = record["dispatched_modes"]
        if dispatched is None:
            continue
        declared = record["declared_modes"]
        for mode in sorted(declared - dispatched):
            add_error("nmap_mode_not_dispatched", f"{relative}: {mode}")
        for mode in sorted(dispatched - declared):
            add_error("nmap_dispatch_not_registered", f"{relative}: {mode}")

    for family in sorted(profile_families - nmap_families - nmap_aliases):
        add_error("reviewed_family_missing_from_nmap", family)

    required_rows = _validate_required_contracts(required_contracts)
    for contract in required_rows:
        handler = contract["handler"]
        pair = (contract["protocol"], contract["method"])
        if profile_methods.get(handler) != pair:
            add_error(
                "required_handler_missing_or_mismatched",
                f"{handler}: expected={pair!r}, observed={profile_methods.get(handler)!r}",
            )
        if contract["nmap_family"] not in nmap_families and contract["nmap_family"] not in nmap_aliases:
            add_error("required_nmap_family_missing", contract["nmap_family"])
        if profiles_by_handler.get(handler, 0) == 0:
            add_warning(
                "capability_has_no_reviewed_endpoint_profile",
                f"{handler}: 実endpointへの送信はfail-closedのままです",
            )

    errors.sort(key=lambda item: (item["code"], item["detail"]))
    warnings.sort(key=lambda item: (item["code"], item["detail"]))
    return {
        "schema_version": 1,
        "analysis": "c2_active_integration_offline_audit",
        "network_contacted": False,
        "status": "pass" if not errors else "fail",
        "summary": {
            "handler_count": len(profile_methods),
            "reviewed_profile_count": len(loaded_profiles),
            "reviewed_family_count": len(profile_families),
            "nmap_family_count": len(nmap_families),
            "nmap_script_count": len(script_records),
            "nmap_method_binding_count": method_binding_count,
            "required_contract_count": len(required_rows),
            "error_count": len(errors),
            "warning_count": len(warnings),
        },
        "handlers": handler_rows,
        "required_contracts": required_rows,
        "errors": errors,
        "warnings": warnings,
    }


def audit_repository(
    *,
    required_contracts: Iterable[dict[str, str]] = (),
    nmap_profiles: Path = NMAP_PROFILES,
) -> dict[str, Any]:
    """現在のrepositoryを読み取り専用で監査する。"""

    return audit_integration_state(
        profile_methods=dict(profile_module.PROFILE_METHODS),
        loaded_profiles=profile_module.load_profiles(),
        allowed_methods=set(monitor_module.ALLOWED_METHODS),
        active_methods=set(monitor_module.ACTIVE_PROFILE_METHODS),
        method_ceilings=dict(monitor_module.METHOD_CEILINGS),
        method_labels=dict(monitor_module.METHOD_LABELS),
        nmap_mapping=_read_json_object(nmap_profiles),
        nmap_root=nmap_profiles.parent,
        required_contracts=required_contracts,
    )


def _parse_required(value: str) -> dict[str, str]:
    parts = [part.strip() for part in value.split(",")]
    if len(parts) != 4 or any(not part for part in parts):
        raise argparse.ArgumentTypeError(
            "--requireはhandler,protocol,method,nmap_familyの4項目です"
        )
    return dict(zip(("handler", "protocol", "method", "nmap_family"), parts))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--require",
        action="append",
        default=[],
        type=_parse_required,
        help="必須契約: handler,protocol,method,nmap_family。複数指定できます",
    )
    parser.add_argument("--output", type=Path, help="監査JSONの出力先")
    args = parser.parse_args(argv)
    report = audit_repository(required_contracts=args.require)
    encoded = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.write_text(encoded, encoding="utf-8")
    else:
        print(encoded, end="")
    return 0 if report["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
