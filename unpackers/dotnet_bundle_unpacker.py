#!/usr/bin/env python3
""".NET単一ファイルbundleを実行せずに検証・展開する。"""

from __future__ import annotations

import hashlib
import struct
import zlib
from dataclasses import dataclass

import dnfile
import pefile

from extractors.managed_pe import has_clr_metadata
from unpackers.path_safety import safe_member_name

BUNDLE_SIGNATURE = bytes.fromhex(
    "8b1202b96a612038727b930214d7a032"
    "13f5b9e6efae3318ee3b2dce24b36aae"
)
SUPPORTED_MAJOR_VERSIONS = {2, 6}
FILE_TYPES = {
    0: "unknown",
    1: "assembly",
    2: "native_binary",
    3: "deps_json",
    4: "runtime_config_json",
    5: "symbols",
}

RUNTIME_ASSEMBLY_PREFIXES = ("system.", "microsoft.")
RUNTIME_ASSEMBLY_NAMES = {
    "mscorlib.dll",
    "netstandard.dll",
    "windowsbase.dll",
    "winrt.runtime.dll",
}
RUNTIME_NATIVE_NAMES = {
    "coreclr.dll",
    "clrjit.dll",
    "hostfxr.dll",
    "hostpolicy.dll",
}

# static layer pipeline側の64 layer／256 MiB上限の半分をbundle単体へ割り当て、
# rootと他方式で復元したartifactのためのreserveを残す。呼出側は検証用に
# 縮小できるが、この上限を拡張できない。
MAX_ANALYSIS_ARTIFACTS = 32
MAX_ANALYSIS_BYTES = 128 * 1024 * 1024
MAX_RUNTIME_CONTENT_PROBE_BYTES = 32 * 1024 * 1024
MAX_RUNTIME_CONTENT_PROBES = 64
MAX_RUNTIME_CONTENT_PROBE_TOTAL_BYTES = 128 * 1024 * 1024
MAX_NATIVE_RUNTIME_EXPORTS = 4096

NATIVE_RUNTIME_REQUIRED_EXPORTS = {
    "coreclr.dll": frozenset(
        {
            "coreclr_create_delegate",
            "coreclr_execute_assembly",
            "coreclr_initialize",
            "coreclr_shutdown",
        }
    ),
    "clrjit.dll": frozenset({"getJit", "jitStartup"}),
    "hostfxr.dll": frozenset(
        {
            "hostfxr_close",
            "hostfxr_get_runtime_delegate",
            "hostfxr_initialize_for_runtime_config",
        }
    ),
    "hostpolicy.dll": frozenset({"corehost_load", "corehost_main", "corehost_unload"}),
}


class DotnetBundleError(ValueError):
    """bundleが不正、未対応、または安全上の上限を超えたことを示す。"""


@dataclass(frozen=True)
class BundleEntry:
    """検証済みbundle manifest entry。"""

    offset: int
    size: int
    compressed_size: int
    file_type: int
    relative_path: str


@dataclass(frozen=True)
class _AnalysisAssessment:
    """raw identityを公開せずに保持するcontent-based解析優先度。"""

    priority: int
    reason: str
    evidence: dict[str, object]


@dataclass(frozen=True)
class _AnalysisCandidate:
    """bundle entryの解析候補。blob本体は二重保持しない。"""

    entry_index: int
    digest: str
    size: int
    artifact_kind: str
    assessment: _AnalysisAssessment


def _entry_basename(entry: BundleEntry) -> str:
    return entry.relative_path.replace("\\", "/").rsplit("/", 1)[-1]


def _application_stems(entries: list[BundleEntry]) -> set[str]:
    """runtime/deps設定名からアプリケーション本体のstemを求める。"""

    stems: set[str] = set()
    for entry in entries:
        name = _entry_basename(entry).casefold()
        for suffix in (".runtimeconfig.json", ".deps.json"):
            if name.endswith(suffix):
                stems.add(name[: -len(suffix)])
    return stems


def _managed_stem(value: str) -> str:
    normalized = value.strip().replace("\\", "/").rsplit("/", 1)[-1].casefold()
    for suffix in (".dll", ".exe"):
        if normalized.endswith(suffix):
            return normalized[: -len(suffix)]
    return normalized


def _is_runtime_assembly_name(name: str) -> bool:
    return name in RUNTIME_ASSEMBLY_NAMES or name.startswith(RUNTIME_ASSEMBLY_PREFIXES)


def _managed_runtime_content_evidence(
    name: str,
    blob: bytes,
    *,
    probe_allowed: bool,
) -> dict[str, object]:
    """CLR metadata identityをboundedに確認し、raw identityは返さない。"""

    expected_stem = _managed_stem(name)
    evidence: dict[str, object] = {
        "status": "unverified",
        "expected_extension_valid": name.endswith(".dll"),
        "content_probe_within_budget": len(blob) <= MAX_RUNTIME_CONTENT_PROBE_BYTES,
        "managed_metadata_validated": False,
        "assembly_identity_matches_basename": False,
        "module_identity_matches_basename": False,
    }
    if not evidence["expected_extension_valid"]:
        evidence["status"] = "extension_mismatch"
        return evidence
    if not probe_allowed:
        evidence["status"] = "aggregate_content_probe_budget_exceeded"
        return evidence
    if not evidence["content_probe_within_budget"]:
        evidence["status"] = "content_probe_budget_exceeded"
        return evidence
    if not has_clr_metadata(blob):
        evidence["status"] = "managed_metadata_invalid"
        return evidence
    evidence["managed_metadata_validated"] = True

    image = None
    try:
        image = dnfile.dnPE(data=blob, clr_lazy_load=True)
        assembly_rows = image.net.mdtables.Assembly.rows
        module_rows = image.net.mdtables.Module.rows
        if len(assembly_rows) != 1 or len(module_rows) != 1:
            evidence["status"] = "identity_table_cardinality_invalid"
            return evidence
        assembly_name = str(assembly_rows[0].Name).strip()
        module_name = str(module_rows[0].Name).strip()
        if len(assembly_name) > 512 or len(module_name) > 512:
            evidence["status"] = "identity_length_invalid"
            return evidence
        evidence["assembly_identity_matches_basename"] = (
            _managed_stem(assembly_name) == expected_stem
        )
        evidence["module_identity_matches_basename"] = (
            _managed_stem(module_name) == expected_stem
        )
    except Exception:
        evidence["status"] = "identity_parser_rejected"
        return evidence
    finally:
        if image is not None:
            try:
                image.close()
            except Exception:
                pass

    if (
        evidence["assembly_identity_matches_basename"]
        and evidence["module_identity_matches_basename"]
    ):
        evidence["status"] = "runtime_identity_consistent"
    else:
        evidence["status"] = "runtime_identity_mismatch"
    return evidence


def _native_runtime_content_evidence(
    name: str,
    blob: bytes,
    *,
    probe_allowed: bool,
) -> dict[str, object]:
    """既知native runtimeのDLL／export構造をboundedに確認する。"""

    required_exports = NATIVE_RUNTIME_REQUIRED_EXPORTS.get(name)
    evidence: dict[str, object] = {
        "status": "unverified",
        "expected_extension_valid": name.endswith(".dll"),
        "content_probe_within_budget": len(blob) <= MAX_RUNTIME_CONTENT_PROBE_BYTES,
        "pe_dll_validated": False,
        "export_identity_matches_basename": False,
        "required_export_profile_matches": False,
    }
    if not evidence["expected_extension_valid"]:
        evidence["status"] = "extension_mismatch"
        return evidence
    if required_exports is None:
        evidence["status"] = "unsupported_runtime_profile"
        return evidence
    if not probe_allowed:
        evidence["status"] = "aggregate_content_probe_budget_exceeded"
        return evidence
    if not evidence["content_probe_within_budget"]:
        evidence["status"] = "content_probe_budget_exceeded"
        return evidence

    image = None
    try:
        image = pefile.PE(data=blob, fast_load=True)
        if not image.FILE_HEADER.Characteristics & 0x2000:
            evidence["status"] = "pe_is_not_dll"
            return evidence
        evidence["pe_dll_validated"] = True
        image.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]]
        )
        export_directory = image.DIRECTORY_ENTRY_EXPORT
        symbols = export_directory.symbols
        if len(symbols) > MAX_NATIVE_RUNTIME_EXPORTS:
            evidence["status"] = "export_count_budget_exceeded"
            return evidence
        exported_names: set[str] = set()
        for symbol in symbols:
            raw_name = symbol.name
            if raw_name is None or len(raw_name) > 256:
                continue
            try:
                exported_names.add(raw_name.decode("ascii"))
            except UnicodeDecodeError:
                continue
        raw_export_name = export_directory.name
        if raw_export_name is not None and len(raw_export_name) <= 512:
            try:
                export_name = raw_export_name.decode("ascii").casefold()
            except UnicodeDecodeError:
                export_name = ""
            evidence["export_identity_matches_basename"] = export_name == name
        evidence["required_export_profile_matches"] = required_exports <= exported_names
    except Exception:
        evidence["status"] = "native_parser_rejected"
        return evidence
    finally:
        if image is not None:
            try:
                image.close()
            except Exception:
                pass

    if (
        evidence["export_identity_matches_basename"]
        and evidence["required_export_profile_matches"]
    ):
        evidence["status"] = "runtime_structure_consistent"
    else:
        evidence["status"] = "runtime_structure_mismatch"
    return evidence


def _analysis_selection(
    entry: BundleEntry,
    application_stems: set[str],
    blob: bytes,
    *,
    runtime_content_probe_allowed: bool,
) -> _AnalysisAssessment:
    """name、manifest型、内容を相関し、再帰解析の優先度を決める。"""

    name = _entry_basename(entry).casefold()
    if entry.file_type in {3, 4}:
        return _AnalysisAssessment(0, "application_configuration", {"status": "configuration"})
    if entry.file_type == 5:
        extension_valid = name.endswith(".pdb")
        pdb_signature_valid = blob.startswith(b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\0") or blob.startswith(
            b"BSJB"
        )
        evidence = {
            "status": "symbol_content_validated" if extension_valid and pdb_signature_valid else "symbol_content_mismatch",
            "expected_extension_valid": extension_valid,
            "pdb_signature_validated": pdb_signature_valid,
        }
        if evidence["status"] == "symbol_content_validated":
            return _AnalysisAssessment(4, "validated_symbols_bounded_audit", evidence)
        return _AnalysisAssessment(1, "symbol_type_content_mismatch_requires_analysis", evidence)
    if entry.file_type == 1:
        stem = _managed_stem(name)
        if stem in application_stems:
            return _AnalysisAssessment(0, "application_assembly", {"status": "application_stem_match"})
        if _is_runtime_assembly_name(name):
            evidence = _managed_runtime_content_evidence(
                name,
                blob,
                probe_allowed=runtime_content_probe_allowed,
            )
            if evidence["status"] == "runtime_identity_consistent":
                return _AnalysisAssessment(
                    3,
                    "managed_runtime_identity_consistent_bounded_audit",
                    evidence,
                )
            return _AnalysisAssessment(
                1,
                "managed_runtime_name_content_mismatch_requires_analysis",
                evidence,
            )
        if not name.endswith((".dll", ".exe")):
            return _AnalysisAssessment(
                1,
                "assembly_extension_mismatch_requires_analysis",
                {"status": "extension_mismatch"},
            )
        return _AnalysisAssessment(2, "non_runtime_assembly", {"status": "non_runtime_name"})
    if entry.file_type == 2:
        runtime_like = name in RUNTIME_NATIVE_NAMES or name.startswith(
            ("api-ms-win-", "clrcompression")
        )
        if runtime_like:
            evidence = _native_runtime_content_evidence(
                name,
                blob,
                probe_allowed=runtime_content_probe_allowed,
            )
            if evidence["status"] == "runtime_structure_consistent":
                return _AnalysisAssessment(
                    3,
                    "native_runtime_structure_consistent_bounded_audit",
                    evidence,
                )
            return _AnalysisAssessment(
                1,
                "native_runtime_name_content_mismatch_requires_analysis",
                evidence,
            )
        return _AnalysisAssessment(2, "non_runtime_native_binary", {"status": "non_runtime_name"})
    return _AnalysisAssessment(
        0,
        "unknown_entry_requires_analysis",
        {"status": "unknown_manifest_type"},
    )


def _runtime_content_probe_requested(entry: BundleEntry, blob: bytes) -> bool:
    """実際にdnfile／pefileを起動し得るentryだけをaggregate予算へ数える。"""

    name = _entry_basename(entry).casefold()
    if len(blob) > MAX_RUNTIME_CONTENT_PROBE_BYTES or not name.endswith(".dll"):
        return False
    if entry.file_type == 1:
        return _is_runtime_assembly_name(name)
    if entry.file_type == 2:
        return name in NATIVE_RUNTIME_REQUIRED_EXPORTS
    return False

def _read_exact(data: bytes, offset: int, size: int) -> tuple[bytes, int]:
    if offset < 0 or size < 0 or offset + size > len(data):
        raise DotnetBundleError("bundleの読取範囲がファイル境界を超えています")
    return data[offset : offset + size], offset + size


def _read_u32(data: bytes, offset: int) -> tuple[int, int]:
    raw, offset = _read_exact(data, offset, 4)
    return struct.unpack("<I", raw)[0], offset


def _read_i32(data: bytes, offset: int) -> tuple[int, int]:
    raw, offset = _read_exact(data, offset, 4)
    return struct.unpack("<i", raw)[0], offset


def _read_i64(data: bytes, offset: int) -> tuple[int, int]:
    raw, offset = _read_exact(data, offset, 8)
    return struct.unpack("<q", raw)[0], offset


def _read_u64(data: bytes, offset: int) -> tuple[int, int]:
    raw, offset = _read_exact(data, offset, 8)
    return struct.unpack("<Q", raw)[0], offset


def _read_binary_writer_string(
    data: bytes, offset: int, *, max_length: int = 4096
) -> tuple[str, int]:
    """BinaryWriter互換の7-bit長UTF-8文字列を境界付きで読む。"""

    length = 0
    shift = 0
    for _ in range(5):
        raw, offset = _read_exact(data, offset, 1)
        value = raw[0]
        length |= (value & 0x7F) << shift
        if value & 0x80 == 0:
            break
        shift += 7
    else:
        raise DotnetBundleError("文字列長の7-bit encodingが不正です")
    if length <= 0 or length > max_length:
        raise DotnetBundleError("bundle内の文字列長が許容範囲外です")
    raw, offset = _read_exact(data, offset, length)
    try:
        return raw.decode("utf-8"), offset
    except UnicodeDecodeError as exc:
        raise DotnetBundleError("bundle内のパスがUTF-8ではありません") from exc


def locate_bundle_header(data: bytes) -> tuple[int, int]:
    """apphost markerからmanifest offsetとmarker位置を返す。"""

    marker_offset = data.find(BUNDLE_SIGNATURE)
    if marker_offset < 8:
        raise DotnetBundleError(".NET bundle markerがありません")
    if data.find(BUNDLE_SIGNATURE, marker_offset + 1) >= 0:
        raise DotnetBundleError(".NET bundle markerが複数あり一意に選べません")
    header_offset = struct.unpack_from("<q", data, marker_offset - 8)[0]
    if header_offset <= 0 or header_offset >= len(data):
        raise DotnetBundleError("bundle header offsetがファイル境界外です")
    return header_offset, marker_offset


def parse_bundle(
    data: bytes,
    *,
    max_entries: int = 512,
    max_entry_size: int = 256 * 1024 * 1024,
    max_total_size: int = 768 * 1024 * 1024,
) -> tuple[dict[str, object], list[BundleEntry]]:
    """公式manifest形式を検証し、メタデータとentryを返す。"""

    header_offset, marker_offset = locate_bundle_header(data)
    cursor = header_offset
    major, cursor = _read_u32(data, cursor)
    minor, cursor = _read_u32(data, cursor)
    count, cursor = _read_i32(data, cursor)
    if major not in SUPPORTED_MAJOR_VERSIONS or minor != 0:
        raise DotnetBundleError(f"未対応のbundle versionです: {major}.{minor}")
    if count <= 0 or count > max_entries:
        raise DotnetBundleError("bundle entry数が許容範囲外です")
    bundle_id, cursor = _read_binary_writer_string(data, cursor, max_length=1024)

    deps_offset = deps_size = runtime_offset = runtime_size = flags = 0
    if major >= 2:
        deps_offset, cursor = _read_i64(data, cursor)
        deps_size, cursor = _read_i64(data, cursor)
        runtime_offset, cursor = _read_i64(data, cursor)
        runtime_size, cursor = _read_i64(data, cursor)
        flags, cursor = _read_u64(data, cursor)

    entries: list[BundleEntry] = []
    total_size = 0
    for _ in range(count):
        entry_offset, cursor = _read_i64(data, cursor)
        size, cursor = _read_i64(data, cursor)
        compressed_size = 0
        if major >= 6:
            compressed_size, cursor = _read_i64(data, cursor)
        raw_type, cursor = _read_exact(data, cursor, 1)
        file_type = raw_type[0]
        relative_path, cursor = _read_binary_writer_string(data, cursor)
        try:
            relative_path = safe_member_name(relative_path, "dotnet-bundle")
        except ValueError as exc:
            raise DotnetBundleError("bundle entryのパスが安全ではありません") from exc
        stored_size = compressed_size or size
        if (
            entry_offset <= 0
            or size < 0
            or compressed_size < 0
            or size > max_entry_size
            or stored_size > max_entry_size
            or entry_offset + stored_size > len(data)
            or file_type not in FILE_TYPES
        ):
            raise DotnetBundleError(
                f"bundle entryの範囲または型が不正です: {relative_path}"
            )
        total_size += size
        if total_size > max_total_size:
            raise DotnetBundleError("bundle展開後の合計サイズが上限を超えます")
        entries.append(
            BundleEntry(
                offset=entry_offset,
                size=size,
                compressed_size=compressed_size,
                file_type=file_type,
                relative_path=relative_path,
            )
        )

    return {
        "status": "parsed",
        "version": f"{major}.{minor}",
        "header_offset": header_offset,
        "marker_offset": marker_offset,
        "manifest_end_offset": cursor,
        "bundle_id": bundle_id,
        "entry_count": len(entries),
        "declared_total_size": total_size,
        "deps_json": {"offset": deps_offset, "size": deps_size},
        "runtime_config_json": {"offset": runtime_offset, "size": runtime_size},
        "flags": flags,
        "netcoreapp3_compat_mode": bool(flags & 1),
        "executed": False,
        "network_contacted": False,
    }, entries


def _decompress_raw_deflate_bounded(
    stored: bytes,
    declared_size: int,
) -> tuple[bytes | None, dict[str, object] | None]:
    """raw DEFLATEを宣言サイズ+1までに制限し、stream全体を検証する。"""

    decoder = zlib.decompressobj(wbits=-zlib.MAX_WBITS)
    try:
        blob = decoder.decompress(stored, declared_size + 1)
    except zlib.error as exc:
        return None, {
            "status": "decompression_failed",
            "error": type(exc).__name__,
        }

    # ここでflushすると、不正streamが内部に保持した出力を上限なしで返し得る。
    # 正常なstreamは、宣言サイズ+1の余裕を残した状態でEOFまで到達するため、
    # eof/unconsumed_tail/unused_dataの検証だけで完全性を判定できる。
    if len(blob) > declared_size:
        return None, {
            "status": "size_mismatch_blocked",
            "declared_size": declared_size,
            "actual_size": len(blob),
            "actual_size_is_lower_bound": not decoder.eof
            or bool(decoder.unconsumed_tail),
        }
    if decoder.unconsumed_tail:
        return None, {
            "status": "decompression_failed",
            "error": "unconsumed_compressed_input",
        }
    if not decoder.eof:
        return None, {
            "status": "decompression_failed",
            "error": "incomplete_deflate_stream",
        }
    if decoder.unused_data:
        return None, {
            "status": "decompression_failed",
            "error": "trailing_data_after_deflate_stream",
        }
    if len(blob) != declared_size:
        return None, {
            "status": "size_mismatch_blocked",
            "declared_size": declared_size,
            "actual_size": len(blob),
            "actual_size_is_lower_bound": False,
        }
    return blob, None


def _recover_entry_blob(
    data: bytes,
    entry: BundleEntry,
) -> tuple[bytes | None, dict[str, object] | None]:
    """検証済みentryを一つだけ復元する。"""

    stored_size = entry.compressed_size or entry.size
    stored = data[entry.offset : entry.offset + stored_size]
    if entry.compressed_size:
        return _decompress_raw_deflate_bounded(stored, entry.size)
    if len(stored) != entry.size:
        return None, {
            "status": "size_mismatch_blocked",
            "declared_size": entry.size,
            "actual_size": len(stored),
        }
    return stored, None


def _validate_analysis_budget(value: int, *, maximum: int, label: str) -> int:
    """呼出側による予算縮小だけを許し、上限拡張を拒否する。"""

    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= maximum:
        raise DotnetBundleError(f"{label}が固定上限の範囲外です")
    return value


def recover_dotnet_bundle(
    data: bytes,
    *,
    max_entries: int = 512,
    max_entry_size: int = 256 * 1024 * 1024,
    max_total_size: int = 768 * 1024 * 1024,
    max_analysis_artifacts: int = MAX_ANALYSIS_ARTIFACTS,
    max_analysis_bytes: int = MAX_ANALYSIS_BYTES,
) -> tuple[dict[str, object], list[tuple[str, bytes]]]:
    """bundleを安全に展開し、台帳と解析対象artifactを返す。"""

    if BUNDLE_SIGNATURE not in data:
        return {"status": "not_dotnet_bundle"}, []
    try:
        max_analysis_artifacts = _validate_analysis_budget(
            max_analysis_artifacts,
            maximum=MAX_ANALYSIS_ARTIFACTS,
            label="bundle解析artifact件数",
        )
        max_analysis_bytes = _validate_analysis_budget(
            max_analysis_bytes,
            maximum=MAX_ANALYSIS_BYTES,
            label="bundle解析byte数",
        )
        report, entries = parse_bundle(
            data,
            max_entries=max_entries,
            max_entry_size=max_entry_size,
            max_total_size=max_total_size,
        )
    except DotnetBundleError as exc:
        return {
            "status": "parse_failed",
            "error": str(exc),
            "executed": False,
            "network_contacted": False,
        }, []

    application_stems = _application_stems(entries)
    inventory: list[dict[str, object]] = []
    candidates: list[_AnalysisCandidate] = []
    recovered_entries = 0
    runtime_content_probe_count = 0
    runtime_content_probe_bytes = 0
    runtime_content_probe_aggregate_omitted_count = 0
    runtime_content_probe_per_entry_omitted_count = 0
    for entry_index, entry in enumerate(entries):
        blob, failure = _recover_entry_blob(data, entry)
        if failure is not None:
            inventory.append(
                {
                    "name": entry.relative_path,
                    **failure,
                    "analysis_selected": False,
                    "analysis_selection_reason": "entry_recovery_failed_before_content_assessment",
                }
            )
            continue
        assert blob is not None
        probe_allowed = True
        if _runtime_content_probe_requested(entry, blob):
            if (
                runtime_content_probe_count >= MAX_RUNTIME_CONTENT_PROBES
                or len(blob)
                > MAX_RUNTIME_CONTENT_PROBE_TOTAL_BYTES - runtime_content_probe_bytes
            ):
                probe_allowed = False
                runtime_content_probe_aggregate_omitted_count += 1
            else:
                runtime_content_probe_count += 1
                runtime_content_probe_bytes += len(blob)
        assessment = _analysis_selection(
            entry,
            application_stems,
            blob,
            runtime_content_probe_allowed=probe_allowed,
        )
        if assessment.evidence.get("status") == "content_probe_budget_exceeded":
            runtime_content_probe_per_entry_omitted_count += 1
        digest = hashlib.sha256(blob).hexdigest()
        recovered_entries += 1
        inventory.append(
            {
                "name": entry.relative_path,
                "status": "recovered",
                "type": FILE_TYPES[entry.file_type],
                "offset": entry.offset,
                "size": entry.size,
                "compressed_size": entry.compressed_size,
                "sha256": digest,
                "analysis_selected": False,
                "analysis_selection_reason": "pending_bounded_selection",
                "analysis_candidate_reason": assessment.reason,
                "analysis_priority": assessment.priority,
                "analysis_content_evidence": assessment.evidence,
            }
        )
        candidates.append(
            _AnalysisCandidate(
                entry_index=entry_index,
                digest=digest,
                size=entry.size,
                artifact_kind=f"dotnet-bundle-{FILE_TYPES[entry.file_type]}",
                assessment=assessment,
            )
        )

    # 同一blobは一度だけ解析する。異なる名前で同じbytesを重複させても、件数・
    # byte予算を消費させない。代表はcontent-based優先度、次にmanifest順で固定する。
    representatives: dict[str, _AnalysisCandidate] = {}
    for candidate in sorted(
        candidates,
        key=lambda item: (item.assessment.priority, item.entry_index),
    ):
        representatives.setdefault(candidate.digest, candidate)

    selected_digests: set[str] = set()
    omission_reasons: dict[str, str] = {}
    selected_bytes_reserved = 0
    for candidate in sorted(
        representatives.values(),
        key=lambda item: (item.assessment.priority, item.entry_index),
    ):
        if len(selected_digests) >= max_analysis_artifacts:
            omission_reasons[candidate.digest] = "analysis_count_budget_inventory_only"
            continue
        if candidate.size > max_analysis_bytes - selected_bytes_reserved:
            omission_reasons[candidate.digest] = "analysis_byte_budget_inventory_only"
            continue
        selected_digests.add(candidate.digest)
        selected_bytes_reserved += candidate.size

    for candidate in candidates:
        item = inventory[candidate.entry_index]
        representative = representatives[candidate.digest]
        if candidate.digest not in selected_digests:
            item["analysis_selection_reason"] = omission_reasons[candidate.digest]
        elif candidate.entry_index == representative.entry_index:
            item["analysis_selected"] = True
            item["analysis_selection_reason"] = candidate.assessment.reason
        else:
            item["analysis_selection_reason"] = "duplicate_content_covered_by_selected_artifact"
            item["analysis_covered_by_duplicate"] = True

    artifacts: list[tuple[str, bytes]] = []
    selected_bytes = 0
    second_pass_failures = 0
    selected_representatives = sorted(
        (
            representative
            for digest, representative in representatives.items()
            if digest in selected_digests
        ),
        key=lambda item: item.entry_index,
    )
    for candidate in selected_representatives:
        entry = entries[candidate.entry_index]
        blob, failure = _recover_entry_blob(data, entry)
        item = inventory[candidate.entry_index]
        if failure is not None or blob is None or hashlib.sha256(blob).hexdigest() != candidate.digest:
            item["analysis_selected"] = False
            item["analysis_selection_reason"] = "second_pass_recovery_consistency_failed"
            second_pass_failures += 1
            continue
        artifacts.append((candidate.artifact_kind, blob))
        selected_bytes += len(blob)

    selection_complete = (
        len(selected_digests) == len(representatives) and second_pass_failures == 0
    )

    report["inventory"] = inventory
    report["recovered_count"] = recovered_entries
    report["analysis_artifact_count"] = len(artifacts)
    report["analysis_excluded_count"] = recovered_entries - len(artifacts)
    report["application_stems"] = sorted(application_stems)
    report["analysis_budget"] = {
        "maximum_artifacts": max_analysis_artifacts,
        "maximum_bytes": max_analysis_bytes,
        "candidate_entry_count": len(candidates),
        "unique_candidate_count": len(representatives),
        "selected_unique_artifact_count": len(artifacts),
        "selected_bytes": selected_bytes,
        "omitted_unique_artifact_count": len(representatives) - len(artifacts),
        "budget_exhausted": bool(omission_reasons),
        "selection_complete": selection_complete,
        "second_pass_failure_count": second_pass_failures,
    }
    report["runtime_content_assessment_budget"] = {
        "maximum_probes": MAX_RUNTIME_CONTENT_PROBES,
        "maximum_probe_bytes": MAX_RUNTIME_CONTENT_PROBE_TOTAL_BYTES,
        "per_entry_maximum_bytes": MAX_RUNTIME_CONTENT_PROBE_BYTES,
        "performed_probe_count": runtime_content_probe_count,
        "performed_probe_bytes": runtime_content_probe_bytes,
        "omitted_probe_count": (
            runtime_content_probe_aggregate_omitted_count
            + runtime_content_probe_per_entry_omitted_count
        ),
        "aggregate_budget_omitted_probe_count": runtime_content_probe_aggregate_omitted_count,
        "per_entry_budget_omitted_probe_count": runtime_content_probe_per_entry_omitted_count,
        "budget_exhausted": (
            runtime_content_probe_aggregate_omitted_count > 0
            or runtime_content_probe_per_entry_omitted_count > 0
        ),
    }
    report["analysis_selection"] = (
        "全entryを型・SHA-256・content assessment付きで台帳化し、アプリ・設定、runtime名の不整合、"
        "非標準依存関係、content整合runtimeの順に固定件数・byte予算内で再帰解析する"
    )
    if recovered_entries != len(entries):
        report["status"] = "partially_recovered"
    elif not selection_complete:
        report["status"] = "analysis_budget_partial"
    else:
        report["status"] = "recovered"
    return report, artifacts
