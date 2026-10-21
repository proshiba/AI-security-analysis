#!/usr/bin/env python3
"""ZIP内の隣接PE依存関係を、静的解析の優先候補として厳格に抽出する。"""

from __future__ import annotations

import unicodedata
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import PurePosixPath

import pefile

MAX_ZIP_PE_CANDIDATES = 64
MAX_ZIP_PE_SIZE = 128 * 1024 * 1024
MAX_IMPORT_DESCRIPTORS = 256
MAX_IMPORT_SYMBOLS = 16_384
MAX_EXPORT_SYMBOLS = 16_384
MAX_PAIR_CANDIDATES = 256


@dataclass(frozen=True)
class ZipSideLoadArtifactRole:
    """単一ZIP memberに付与する候補役割と、その候補pair数。"""

    role: str
    pair_count: int


@dataclass(frozen=True)
class _ImportDescriptor:
    library_basename: str
    named_symbols: frozenset[bytes]
    ordinal_symbols: frozenset[int]


@dataclass(frozen=True)
class _PeFacts:
    artifact_index: int
    canonical_path: str
    machine: int
    optional_header_magic: int
    imports: tuple[_ImportDescriptor, ...]
    named_exports: frozenset[bytes]
    ordinal_exports: frozenset[int]


@dataclass(frozen=True)
class _Pair:
    host_index: int
    dll_index: int
    named_intersection_count: int
    ordinal_intersection_count: int


@dataclass(frozen=True)
class ZipSideLoadPairAnalysis:
    """優先化に使う内部役割と、値を含まない公開集計を分離して保持する。"""

    status: str
    roles: tuple[tuple[int, ZipSideLoadArtifactRole], ...]
    pair_count: int
    host_count: int
    dll_count: int
    candidate_pe_count: int
    parsed_pe_count: int
    rejected_pe_count: int
    named_match_pair_count: int
    ordinal_match_pair_count: int
    blocker: str | None = None

    def roles_by_index(self) -> dict[int, ZipSideLoadArtifactRole]:
        """artifact indexごとの候補役割を新しい辞書で返す。"""

        return dict(self.roles)

    def public(self) -> dict[str, object]:
        """個別path、hash、symbolを含まない公開集計を返す。"""

        return {
            "schema_version": 1,
            "status": self.status,
            "candidate_pe_count": self.candidate_pe_count,
            "parsed_pe_count": self.parsed_pe_count,
            "rejected_pe_count": self.rejected_pe_count,
            "pair_count": self.pair_count,
            "prioritized_artifact_count": len(self.roles),
            "host_artifact_count": self.host_count,
            "dll_artifact_count": self.dll_count,
            "named_symbol_match_pair_count": self.named_match_pair_count,
            "ordinal_match_pair_count": self.ordinal_match_pair_count,
            "blocker": self.blocker,
            "criteria": {
                "container": "zip",
                "same_canonical_directory_required": True,
                "host_extension": ".exe",
                "dll_extension": ".dll",
                "complete_required_pe_directories": True,
                "machine_type_equality_required": True,
                "optional_header_magic_equality_required": True,
                "import_library_basename_equality_required": True,
                "named_or_ordinal_import_export_intersection_required": True,
            },
            "evidence_boundary": {
                "queue_prioritization_only": True,
                "execution_confirmed": False,
                "maliciousness_confirmed": False,
                "family_confirmation": False,
                "c2_confirmation": False,
            },
            "sample_executed": False,
            "network_contacted": False,
        }


def _empty_analysis(
    status: str,
    *,
    candidate_pe_count: int = 0,
    parsed_pe_count: int = 0,
    rejected_pe_count: int = 0,
    blocker: str | None = None,
) -> ZipSideLoadPairAnalysis:
    return ZipSideLoadPairAnalysis(
        status=status,
        roles=(),
        pair_count=0,
        host_count=0,
        dll_count=0,
        candidate_pe_count=candidate_pe_count,
        parsed_pe_count=parsed_pe_count,
        rejected_pe_count=rejected_pe_count,
        named_match_pair_count=0,
        ordinal_match_pair_count=0,
        blocker=blocker,
    )


def _ascii_basename(value: object) -> str | None:
    """import libraryをpathなしのASCII DLL basenameへ限定する。"""

    if not isinstance(value, bytes) or not 5 <= len(value) <= 260:
        return None
    try:
        decoded = value.decode("ascii")
    except UnicodeDecodeError:
        return None
    if (
        decoded.casefold().endswith(".dll") is False
        or decoded in {".", ".."}
        or "/" in decoded
        or "\\" in decoded
        or ":" in decoded
        or any(ord(character) < 32 or ord(character) == 127 for character in decoded)
    ):
        return None
    return decoded.casefold()


def _symbol_name(value: object) -> bytes | None:
    """GetProcAddress互換の比較に使える有界ASCII名だけを返す。"""

    if not isinstance(value, bytes) or not 1 <= len(value) <= 1024:
        return None
    if any(byte < 0x20 or byte >= 0x7F for byte in value):
        return None
    return value


def _canonical_member_path(value: object) -> PurePosixPath | None:
    """side-load照合に使うWindows向け相対POSIX pathを再検証する。"""

    if not isinstance(value, str) or not value or len(value) > 4096:
        return None
    if value != unicodedata.normalize("NFC", value) or "\\" in value:
        return None
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        return None
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or value != path.as_posix()
        or any(part in {"", ".", ".."} or ":" in part for part in path.parts)
    ):
        return None
    return path


def _parse_pe_facts(
    artifact_index: int,
    canonical_path: str,
    blob: bytes,
    *,
    expect_dll: bool,
) -> _PeFacts | None:
    """必要directoryを完全に読めたPEだけを候補factへ変換する。"""

    if not blob or len(blob) > MAX_ZIP_PE_SIZE:
        return None
    image = None
    try:
        image = pefile.PE(data=blob, fast_load=True)
        directory_name = "IMAGE_DIRECTORY_ENTRY_EXPORT" if expect_dll else "IMAGE_DIRECTORY_ENTRY_IMPORT"
        parse_directories = getattr(image, "parse_data_directories", None)
        if not callable(parse_directories):
            return None
        parse_directories(
            directories=[pefile.DIRECTORY_ENTRY[directory_name]],
        )
        characteristics = int(image.FILE_HEADER.Characteristics)
        is_dll = bool(characteristics & 0x2000)
        if is_dll is not expect_dll:
            return None
        machine = int(image.FILE_HEADER.Machine)
        if not 0 < machine <= 0xFFFF:
            return None
        optional_header_magic = int(image.OPTIONAL_HEADER.Magic)
        if optional_header_magic not in {0x10B, 0x20B}:
            return None

        if expect_dll:
            export_directory = getattr(image, "DIRECTORY_ENTRY_EXPORT", None)
            raw_exports = getattr(export_directory, "symbols", None)
            if not isinstance(raw_exports, Sequence) or isinstance(raw_exports, (str, bytes, bytearray)):
                return None
            if not raw_exports or len(raw_exports) > MAX_EXPORT_SYMBOLS:
                return None
            named_exports: set[bytes] = set()
            ordinal_exports: set[int] = set()
            for raw_export in raw_exports:
                name = _symbol_name(getattr(raw_export, "name", None))
                if name is not None:
                    named_exports.add(name)
                ordinal = getattr(raw_export, "ordinal", None)
                if isinstance(ordinal, int) and not isinstance(ordinal, bool) and 0 <= ordinal <= 0xFFFF:
                    ordinal_exports.add(ordinal)
            if not named_exports and not ordinal_exports:
                return None
            return _PeFacts(
                artifact_index=artifact_index,
                canonical_path=canonical_path,
                machine=machine,
                optional_header_magic=optional_header_magic,
                imports=(),
                named_exports=frozenset(named_exports),
                ordinal_exports=frozenset(ordinal_exports),
            )

        raw_descriptors = getattr(image, "DIRECTORY_ENTRY_IMPORT", None)
        if not isinstance(raw_descriptors, Sequence) or isinstance(raw_descriptors, (str, bytes, bytearray)):
            return None
        if not raw_descriptors or len(raw_descriptors) > MAX_IMPORT_DESCRIPTORS:
            return None
        descriptors: list[_ImportDescriptor] = []
        total_symbols = 0
        for raw_descriptor in raw_descriptors:
            library_basename = _ascii_basename(getattr(raw_descriptor, "dll", None))
            raw_imports = getattr(raw_descriptor, "imports", None)
            if (
                library_basename is None
                or not isinstance(raw_imports, Sequence)
                or isinstance(raw_imports, (str, bytes, bytearray))
            ):
                return None
            total_symbols += len(raw_imports)
            if total_symbols > MAX_IMPORT_SYMBOLS:
                return None
            named_symbols: set[bytes] = set()
            ordinal_symbols: set[int] = set()
            for raw_import in raw_imports:
                name = _symbol_name(getattr(raw_import, "name", None))
                if name is not None:
                    named_symbols.add(name)
                ordinal = getattr(raw_import, "ordinal", None)
                if isinstance(ordinal, int) and not isinstance(ordinal, bool) and 0 <= ordinal <= 0xFFFF:
                    ordinal_symbols.add(ordinal)
            if not named_symbols and not ordinal_symbols:
                return None
            descriptors.append(
                _ImportDescriptor(
                    library_basename=library_basename,
                    named_symbols=frozenset(named_symbols),
                    ordinal_symbols=frozenset(ordinal_symbols),
                )
            )
        return _PeFacts(
            artifact_index=artifact_index,
            canonical_path=canonical_path,
            machine=machine,
            optional_header_magic=optional_header_magic,
            imports=tuple(descriptors),
            named_exports=frozenset(),
            ordinal_exports=frozenset(),
        )
    except Exception:  # noqa: BLE001 - 不正PEを候補単位でfail closedにするparser境界。
        return None
    finally:
        close = getattr(image, "close", None)
        if callable(close):
            close()


def analyze_zip_sideload_pairs(
    artifacts: Sequence[object],
    canonical_paths: Mapping[int, str],
) -> ZipSideLoadPairAnalysis:
    """ZIP内EXEのimportと同一directory DLLのexportが交差するpairを返す。

    この結果はqueue優先化だけに使う。実行edge、悪性、family、C2の確認には
    使用しない。
    """

    if not isinstance(artifacts, Sequence) or isinstance(artifacts, (str, bytes, bytearray)):
        return _empty_analysis("invalid_input", blocker="artifact_sequence_invalid")
    if not isinstance(canonical_paths, Mapping):
        return _empty_analysis("invalid_input", blocker="canonical_path_mapping_invalid")

    candidate_records: list[tuple[int, str, bytes, bool]] = []
    observed_paths: set[str] = set()
    missing_zip_provenance = False
    for artifact_index, artifact in enumerate(artifacts):
        if not isinstance(artifact, tuple) or len(artifact) != 2:
            continue
        artifact_kind, blob = artifact
        canonical_path = canonical_paths.get(artifact_index)
        if (
            not isinstance(artifact_kind, str)
            or not artifact_kind.casefold().startswith("zip-")
            or not isinstance(blob, bytes)
        ):
            continue
        if not isinstance(canonical_path, str):
            missing_zip_provenance = True
            continue
        path = _canonical_member_path(canonical_path)
        if path is None:
            return _empty_analysis("invalid_input", blocker="canonical_path_invalid")
        folded_path = canonical_path.casefold()
        if folded_path in observed_paths:
            return _empty_analysis("invalid_input", blocker="canonical_path_collision")
        observed_paths.add(folded_path)
        suffix = path.suffix.casefold()
        if suffix not in {".exe", ".dll"}:
            continue
        candidate_records.append((artifact_index, canonical_path, blob, suffix == ".dll"))

    candidate_count = len(candidate_records)
    if missing_zip_provenance:
        return _empty_analysis(
            "provenance_unavailable",
            candidate_pe_count=candidate_count,
            rejected_pe_count=candidate_count,
            blocker="zip_artifact_provenance_incomplete",
        )
    if candidate_count == 0:
        return _empty_analysis("no_pe_name_candidates")
    if candidate_count > MAX_ZIP_PE_CANDIDATES:
        return _empty_analysis(
            "budget_blocked",
            candidate_pe_count=candidate_count,
            rejected_pe_count=candidate_count,
            blocker="candidate_pe_count_limit",
        )

    hosts: list[_PeFacts] = []
    dlls: list[_PeFacts] = []
    rejected = 0
    for artifact_index, canonical_path, blob, expect_dll in candidate_records:
        facts = _parse_pe_facts(
            artifact_index,
            canonical_path,
            blob,
            expect_dll=expect_dll,
        )
        if facts is None:
            rejected += 1
            continue
        (dlls if expect_dll else hosts).append(facts)

    parsed_count = len(hosts) + len(dlls)
    pairs: list[_Pair] = []
    for host in hosts:
        host_directory = PurePosixPath(host.canonical_path).parent.as_posix().casefold()
        for dll in dlls:
            dll_path = PurePosixPath(dll.canonical_path)
            if (
                dll_path.parent.as_posix().casefold() != host_directory
                or dll.machine != host.machine
                or dll.optional_header_magic != host.optional_header_magic
            ):
                continue
            dll_basename = dll_path.name.casefold()
            for descriptor in host.imports:
                if descriptor.library_basename != dll_basename:
                    continue
                named = descriptor.named_symbols & dll.named_exports
                ordinals = descriptor.ordinal_symbols & dll.ordinal_exports
                if not named and not ordinals:
                    continue
                pairs.append(
                    _Pair(
                        host_index=host.artifact_index,
                        dll_index=dll.artifact_index,
                        named_intersection_count=len(named),
                        ordinal_intersection_count=len(ordinals),
                    )
                )
                break
            if len(pairs) > MAX_PAIR_CANDIDATES:
                return _empty_analysis(
                    "budget_blocked",
                    candidate_pe_count=candidate_count,
                    parsed_pe_count=parsed_count,
                    rejected_pe_count=rejected,
                    blocker="pair_count_limit",
                )

    if not pairs:
        return _empty_analysis(
            "no_strict_pair",
            candidate_pe_count=candidate_count,
            parsed_pe_count=parsed_count,
            rejected_pe_count=rejected,
        )

    host_pair_counts: dict[int, int] = {}
    dll_pair_counts: dict[int, int] = {}
    for pair in pairs:
        host_pair_counts[pair.host_index] = host_pair_counts.get(pair.host_index, 0) + 1
        dll_pair_counts[pair.dll_index] = dll_pair_counts.get(pair.dll_index, 0) + 1
    roles: list[tuple[int, ZipSideLoadArtifactRole]] = []
    for artifact_index in sorted(set(host_pair_counts) | set(dll_pair_counts)):
        host_pairs = host_pair_counts.get(artifact_index, 0)
        dll_pairs = dll_pair_counts.get(artifact_index, 0)
        role = "host_and_dll" if host_pairs and dll_pairs else "host" if host_pairs else "dll"
        roles.append(
            (
                artifact_index,
                ZipSideLoadArtifactRole(
                    role=role,
                    pair_count=host_pairs + dll_pairs,
                ),
            )
        )
    return ZipSideLoadPairAnalysis(
        status="strict_pairs_prioritized",
        roles=tuple(roles),
        pair_count=len(pairs),
        host_count=len(host_pair_counts),
        dll_count=len(dll_pair_counts),
        candidate_pe_count=candidate_count,
        parsed_pe_count=parsed_count,
        rejected_pe_count=rejected,
        named_match_pair_count=sum(pair.named_intersection_count > 0 for pair in pairs),
        ordinal_match_pair_count=sum(pair.ordinal_intersection_count > 0 for pair in pairs),
    )
