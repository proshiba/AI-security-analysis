#!/usr/bin/env python3
"""外部通信に必要な初期dataと全emulator sourceの被覆を通信なしで監査する。"""

from __future__ import annotations

import argparse
import ast
import json
from pathlib import Path
from typing import Any, Final

SCHEMA_VERSION: Final = 1
MAXIMUM_JSON_BYTES: Final = 2 * 1024 * 1024
DEFAULT_CATALOG: Final = Path(
    "analysis-framework/common/external_communication_requirements.json"
)
PROTOCOL_REGISTRY: Final = Path(
    "analysis-framework/common/c2_protocol_probe_profiles.json"
)
HOST_REGISTRY: Final = Path("analysis-framework/common/rat_emulator_profiles.json")
EMULATOR_ROOT: Final = Path("analysis-framework/malware")

REQUIREMENT_KEYS: Final = frozenset(
    {
        "contract_id",
        "families",
        "profile_handlers",
        "host_adapters",
        "transports",
        "client_sequence",
        "server_material",
        "registration_fields",
        "real_host_fields",
        "synthetic_support",
        "external_status",
        "exactness",
        "unresolved",
        "evidence",
    }
)
EXTERNAL_STATUSES: Final = frozenset(
    {
        "leased_external",
        "bounded_external_gate",
        "fixed_probe_only",
        "server_first_receive_only",
        "offline_or_loopback_only",
        "passive_only",
        "unresolved",
    }
)
EXACTNESS_VALUES: Final = frozenset(
    {"sample_bound", "public_reference_only", "mixed", "unresolved"}
)
NETWORK_MODULES: Final = frozenset(
    {"socket", "ssl", "requests", "urllib", "http", "ftplib", "smtplib"}
)
SOURCE_FAMILY_ALIASES: Final = {
    "formbook_loader": ("formbook", "xloader"),
}


class CommunicationRequirementAuditError(ValueError):
    """catalog、registry、sourceの監査契約違反を表す。"""


def _repository_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CommunicationRequirementAuditError(f"JSON keyが重複しています: {key}")
        result[key] = value
    return result


def _safe_path(repository: Path, relative: Path) -> Path:
    if ".." in relative.parts:
        raise CommunicationRequirementAuditError(f"repository外のpathは読めません: {relative}")
    root = repository.resolve()
    candidate = relative.resolve() if relative.is_absolute() else (root / relative).resolve()
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise CommunicationRequirementAuditError(
            f"repository外のpathは読めません: {relative}"
        ) from exc
    return candidate


def _load_json(repository: Path, relative: Path) -> dict[str, Any]:
    candidate = _safe_path(repository, relative)
    try:
        raw = candidate.read_bytes()
    except OSError as exc:
        raise CommunicationRequirementAuditError(f"JSONを読めません: {relative}") from exc
    if len(raw) > MAXIMUM_JSON_BYTES:
        raise CommunicationRequirementAuditError(f"JSONが上限を超えています: {relative}")
    try:
        value = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_reject_duplicate_keys,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CommunicationRequirementAuditError(f"JSONが不正です: {relative}") from exc
    if not isinstance(value, dict):
        raise CommunicationRequirementAuditError(f"JSON rootがobjectではありません: {relative}")
    return value


def _string_list(value: Any, *, label: str, allow_empty: bool = True) -> list[str]:
    if (
        not isinstance(value, list)
        or (not allow_empty and not value)
        or any(not isinstance(item, str) or not item for item in value)
        or len(set(value)) != len(value)
    ):
        raise CommunicationRequirementAuditError(f"{label}は重複のない文字列listが必要です")
    return value


def _registry_profiles(document: dict[str, Any], *, label: str) -> list[dict[str, Any]]:
    profiles = document.get("profiles")
    if document.get("schema_version") != SCHEMA_VERSION or not isinstance(profiles, list):
        raise CommunicationRequirementAuditError(f"{label} registry schemaが不正です")
    seen: set[str] = set()
    output: list[dict[str, Any]] = []
    for profile in profiles:
        if not isinstance(profile, dict):
            raise CommunicationRequirementAuditError(f"{label} profileがobjectではありません")
        profile_id = profile.get("profile_id")
        if not isinstance(profile_id, str) or not profile_id or profile_id in seen:
            raise CommunicationRequirementAuditError(f"{label} profile_idが不正または重複です")
        seen.add(profile_id)
        output.append(profile)
    return output


def _validate_requirement(
    repository: Path,
    requirement: dict[str, Any],
    *,
    seen_contracts: set[str],
) -> None:
    if set(requirement) != REQUIREMENT_KEYS:
        missing = sorted(REQUIREMENT_KEYS - set(requirement))
        extra = sorted(set(requirement) - REQUIREMENT_KEYS)
        raise CommunicationRequirementAuditError(
            f"requirement keyが不正です: missing={missing}, extra={extra}"
        )
    contract_id = requirement.get("contract_id")
    if not isinstance(contract_id, str) or not contract_id or contract_id in seen_contracts:
        raise CommunicationRequirementAuditError("contract_idが不正または重複です")
    seen_contracts.add(contract_id)
    for name in (
        "families",
        "profile_handlers",
        "host_adapters",
        "transports",
        "client_sequence",
        "server_material",
        "registration_fields",
        "real_host_fields",
        "unresolved",
        "evidence",
    ):
        _string_list(
            requirement.get(name),
            label=f"{contract_id}.{name}",
            allow_empty=name not in {"families", "transports", "client_sequence", "server_material", "evidence"},
        )
    if requirement.get("external_status") not in EXTERNAL_STATUSES:
        raise CommunicationRequirementAuditError(f"{contract_id}.external_statusが不正です")
    if requirement.get("exactness") not in EXACTNESS_VALUES:
        raise CommunicationRequirementAuditError(f"{contract_id}.exactnessが不正です")
    if not isinstance(requirement.get("synthetic_support"), str) or not requirement["synthetic_support"]:
        raise CommunicationRequirementAuditError(f"{contract_id}.synthetic_supportが不正です")
    for evidence in requirement["evidence"]:
        path = _safe_path(repository, Path(evidence))
        if not path.is_file():
            raise CommunicationRequirementAuditError(
                f"{contract_id}のevidenceが存在しません: {evidence}"
            )


def _emulator_sources(repository: Path, requirements: list[dict[str, Any]]) -> list[dict[str, Any]]:
    root = _safe_path(repository, EMULATOR_ROOT)
    contracts_by_family: dict[str, list[str]] = {}
    for requirement in requirements:
        for family in requirement["families"]:
            contracts_by_family.setdefault(family, []).append(requirement["contract_id"])
    inventory: list[dict[str, Any]] = []
    for path in sorted(root.rglob("*emulator*.py")):
        relative = path.relative_to(repository).as_posix()
        if "tests" in path.relative_to(root).parts:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="strict")
            tree = ast.parse(text, filename=relative)
        except (OSError, UnicodeDecodeError, SyntaxError) as exc:
            raise CommunicationRequirementAuditError(f"emulator sourceを解析できません: {relative}") from exc
        family = path.relative_to(root).parts[0]
        mapped_families = SOURCE_FAMILY_ALIASES.get(family, (family,))
        imported: set[str] = set()
        for node in tree.body:
            if isinstance(node, ast.Import):
                imported.update(item.name.split(".", 1)[0] for item in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".", 1)[0])
        docstring = ast.get_docstring(tree, clean=True) or ""
        normalized = docstring.casefold()
        if any(marker in normalized for marker in ("loopback", "ループバック")):
            declared_mode = "loopback"
        elif any(
            marker in normalized
            for marker in ("非通信", "通信せず", "通信なし", "ネットワーク送信を行わない")
        ):
            declared_mode = "offline"
        else:
            declared_mode = "bounded_or_unresolved"
        inventory.append(
            {
                "path": relative,
                "family_directory": family,
                "declared_mode": declared_mode,
                "network_module_imports": sorted(imported & NETWORK_MODULES),
                "mapped_contract_ids": sorted(
                    {
                        contract_id
                        for mapped_family in mapped_families
                        for contract_id in contracts_by_family.get(mapped_family, [])
                    }
                ),
                "docstring_present": bool(docstring),
            }
        )
    return inventory


def build_audit(
    *,
    repository: Path | None = None,
    catalog_path: Path = DEFAULT_CATALOG,
) -> dict[str, Any]:
    """registry被覆と全emulator source inventoryを通信なしで構築する。"""

    root = (repository or _repository_root()).resolve()
    catalog = _load_json(root, catalog_path)
    expected_scope = {
        "protocol_registry": PROTOCOL_REGISTRY.as_posix(),
        "host_emulator_registry": HOST_REGISTRY.as_posix(),
        "emulator_source_root": EMULATOR_ROOT.as_posix(),
        "statement_ja": (
            "登録済み外部通信profileを全件監査し、未登録のemulator sourceは"
            "offline／loopback／未解決として別集計します。"
        ),
    }
    if catalog.get("schema_version") != SCHEMA_VERSION or catalog.get("scope") != expected_scope:
        raise CommunicationRequirementAuditError("communication requirement catalog schemaが不正です")
    raw_requirements = catalog.get("requirements")
    if not isinstance(raw_requirements, list) or not raw_requirements:
        raise CommunicationRequirementAuditError("requirementsは空でないlistが必要です")
    requirements: list[dict[str, Any]] = []
    seen_contracts: set[str] = set()
    for raw_requirement in raw_requirements:
        if not isinstance(raw_requirement, dict):
            raise CommunicationRequirementAuditError("requirementはobjectである必要があります")
        _validate_requirement(root, raw_requirement, seen_contracts=seen_contracts)
        requirements.append(raw_requirement)

    protocol_profiles = _registry_profiles(
        _load_json(root, PROTOCOL_REGISTRY),
        label="protocol",
    )
    host_profiles = _registry_profiles(
        _load_json(root, HOST_REGISTRY),
        label="host emulator",
    )
    registry_handlers = {
        str(profile["handler"])
        for profile in protocol_profiles
        if isinstance(profile.get("handler"), str) and profile["handler"]
    }
    registry_adapters = {
        str(profile["adapter_id"])
        for profile in host_profiles
        if isinstance(profile.get("adapter_id"), str) and profile["adapter_id"]
    }
    catalog_handlers = {
        handler for requirement in requirements for handler in requirement["profile_handlers"]
    }
    catalog_adapters = {
        adapter for requirement in requirements for adapter in requirement["host_adapters"]
    }
    missing_handlers = sorted(registry_handlers - catalog_handlers)
    stale_handlers = sorted(catalog_handlers - registry_handlers)
    missing_adapters = sorted(registry_adapters - catalog_adapters)
    stale_adapters = sorted(catalog_adapters - registry_adapters)
    if missing_handlers or stale_handlers or missing_adapters or stale_adapters:
        raise CommunicationRequirementAuditError(
            "registry被覆が不一致です: "
            f"missing_handlers={missing_handlers}, stale_handlers={stale_handlers}, "
            f"missing_adapters={missing_adapters}, stale_adapters={stale_adapters}"
        )

    source_inventory = _emulator_sources(root, requirements)
    no_docstring = [item["path"] for item in source_inventory if not item["docstring_present"]]
    if no_docstring:
        raise CommunicationRequirementAuditError(
            f"module docstringのないemulatorがあります: {', '.join(no_docstring)}"
        )
    source_mode_counts = {
        mode: sum(item["declared_mode"] == mode for item in source_inventory)
        for mode in ("offline", "loopback", "bounded_or_unresolved")
    }
    mapped_source_count = sum(bool(item["mapped_contract_ids"]) for item in source_inventory)
    return {
        "schema_version": SCHEMA_VERSION,
        "status": "complete",
        "network_used": False,
        "sample_executed": False,
        "coverage": {
            "requirement_contract_count": len(requirements),
            "protocol_profile_count": len(protocol_profiles),
            "protocol_handler_count": len(registry_handlers),
            "host_profile_count": len(host_profiles),
            "host_adapter_count": len(registry_adapters),
            "emulator_source_count": len(source_inventory),
            "mapped_emulator_source_count": mapped_source_count,
            "unmapped_emulator_source_count": len(source_inventory) - mapped_source_count,
            "network_module_source_count": sum(
                bool(item["network_module_imports"]) for item in source_inventory
            ),
            "source_mode_counts": source_mode_counts,
            "unmapped_registry_handlers": [],
            "unmapped_host_adapters": [],
        },
        "external_status_counts": {
            status: sum(item["external_status"] == status for item in requirements)
            for status in sorted(EXTERNAL_STATUSES)
        },
        "requirements": requirements,
        "emulator_source_inventory": source_inventory,
        "safety": {
            "catalog_contains_secret_values": False,
            "external_connection_attempted": False,
            "malware_application_data_sent": False,
            "unregistered_emulator_implies_live_support": False,
        },
    }


def main(argv: list[str] | None = None) -> int:
    """監査JSONをstdoutへ出し、``--check``時は不一致を終了code 2にする。"""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, default=_repository_root())
    parser.add_argument("--catalog", type=Path, default=DEFAULT_CATALOG)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    try:
        result = build_audit(repository=args.repository, catalog_path=args.catalog)
    except CommunicationRequirementAuditError as exc:
        print(
            json.dumps(
                {"schema_version": SCHEMA_VERSION, "status": "error", "error": str(exc)},
                ensure_ascii=False,
                sort_keys=True,
            )
        )
        return 2
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
