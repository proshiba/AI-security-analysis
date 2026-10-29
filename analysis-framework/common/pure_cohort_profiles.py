#!/usr/bin/env python3
"""PureLogs／PureRATコホート評価で共有するfamily別証拠profile。"""

from __future__ import annotations

import hashlib
import importlib.abc
import importlib.util
import re
import sys
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType
from typing import Any

from immutable_snapshot import read_bounded_snapshot

COMMON_ROOT = Path(__file__).resolve().parent
FRAMEWORK_ROOT = COMMON_ROOT.parent
REPOSITORY_ROOT = FRAMEWORK_ROOT.parent
SHA256_RE = re.compile(r"[0-9a-f]{64}")
MAX_PROFILE_SOURCE_BYTES = 16 * 1024 * 1024
MAX_PROFILE_SOURCE_COUNT = 1_024
MAX_PROFILE_SOURCE_TOTAL_BYTES = 128 * 1024 * 1024
PURELOGS_DETECTOR_PATH = FRAMEWORK_ROOT / "malware" / "purelogs" / "detect.py"
PURERAT_DETECTOR_PATH = FRAMEWORK_ROOT / "malware" / "purehvnc" / "detect.py"
PURELOGS_EXTRACTOR_PATH = REPOSITORY_ROOT / "extractors" / "purelogs" / "extractor.py"
PURERAT_EXTRACTOR_PATH = REPOSITORY_ROOT / "extractors" / "purehvnc" / "extractor.py"

Detector = Callable[[bytes, Path | None], Mapping[str, Any]]
Extractor = Callable[[bytes, str], Mapping[str, Any]]
ConfigIdentity = tuple[tuple[str, ...], ...]


@dataclass(frozen=True)
class LayerAssessment:
    """1つの静的layerに対するfamily・設定証拠の分離結果。"""

    loader_family_confirmed: bool
    terminal_candidate_verified: bool
    terminal_family_confirmed: bool
    config_identity: ConfigIdentity | None
    endpoint_count: int
    endpoint_sha256: tuple[str, ...]


@dataclass(frozen=True)
class PureCohortProfile:
    """familyごとのdetector／extractorと厳格証拠検証契約。"""

    profile_id: str
    cohort_name: str
    family: str
    detector_confidence: str
    detector: Detector
    extractor: Extractor
    assess: Callable[[str, Mapping[str, Any], Mapping[str, Any]], LayerAssessment]
    configuration_format: str
    import_source_sha256: tuple[tuple[str, str], ...]
    detector_extractor_independence_claimed: bool


def _source_bytes(path: Path) -> bytes:
    """profile依存sourceを通常fileとして上限付きで固定する。"""

    try:
        return read_bounded_snapshot(path, MAX_PROFILE_SOURCE_BYTES).data
    except (OSError, ValueError) as exc:
        raise RuntimeError(
            f"profile sourceが通常fileではありません: {path.name}"
        ) from exc


def _source_sha256(path: Path) -> str:
    """profile import前後で同じ通常fileを読んだことを確認する。"""

    return hashlib.sha256(_source_bytes(path)).hexdigest()


def _profile_dependency_paths() -> tuple[Path, ...]:
    """detector／extractorがimportし得るrepo内Python sourceを列挙する。"""

    paths = {
        PURELOGS_DETECTOR_PATH,
        PURERAT_DETECTOR_PATH,
        COMMON_ROOT / "pe_structural_profile.py",
    }
    for root in (
        REPOSITORY_ROOT / "extractors",
        REPOSITORY_ROOT / "unpackers",
    ):
        paths.update(
            path
            for path in root.rglob("*.py")
            if "tests" not in path.relative_to(root).parts
        )
    ordered = tuple(
        sorted(paths, key=lambda path: path.relative_to(REPOSITORY_ROOT).as_posix())
    )
    if len(ordered) > MAX_PROFILE_SOURCE_COUNT:
        raise RuntimeError("profile依存source数が安全上限を超えました")
    return ordered


def _snapshot_profile_sources() -> dict[Path, bytes]:
    """transitive sourceをimport前にmemoryへ固定する。"""

    snapshots: dict[Path, bytes] = {}
    total = 0
    for path in _profile_dependency_paths():
        data = _source_bytes(path)
        total += len(data)
        if total > MAX_PROFILE_SOURCE_TOTAL_BYTES:
            raise RuntimeError("profile依存source総量が安全上限を超えました")
        snapshots[path] = data
    return snapshots


def _module_name_for_path(path: Path) -> tuple[str, bool] | None:
    """snapshot対象pathを通常import名とpackage属性へ変換する。"""

    for package_name in ("extractors", "unpackers"):
        root = REPOSITORY_ROOT / package_name
        try:
            relative = path.relative_to(root)
        except ValueError:
            continue
        parts = relative.parts
        if parts[-1] == "__init__.py":
            suffix = parts[:-1]
            return ".".join((package_name, *suffix)), True
        return ".".join((package_name, *parts[:-1], path.stem)), False
    if path == COMMON_ROOT / "pe_structural_profile.py":
        return "pe_structural_profile", False
    return None


class _FrozenRepoSourceLoader(importlib.abc.Loader):
    """import前に固定したbytesだけを実行するsource loader。"""

    def __init__(self, path: Path, data: bytes, *, is_package: bool) -> None:
        self._path = path
        self._data = data
        self._is_package = is_package

    def create_module(self, spec: object) -> ModuleType | None:
        return None

    def exec_module(self, module: ModuleType) -> None:
        module.__file__ = str(self._path)
        if self._is_package:
            module.__path__ = [str(self._path.parent)]
        code = compile(self._data, str(self._path), "exec", dont_inherit=True)
        exec(code, module.__dict__)

    def is_package(self, fullname: str) -> bool:
        return self._is_package


class _FrozenRepoSourceFinder(importlib.abc.MetaPathFinder):
    """profile依存moduleをmemory snapshotへ束縛するfinder。"""

    def __init__(self, modules: Mapping[str, tuple[Path, bytes, bool]]) -> None:
        self._modules = dict(modules)

    def find_spec(
        self,
        fullname: str,
        path: object = None,
        target: ModuleType | None = None,
    ) -> object:
        del path, target
        item = self._modules.get(fullname)
        if item is None:
            return None
        source_path, data, is_package = item
        loader = _FrozenRepoSourceLoader(source_path, data, is_package=is_package)
        return importlib.util.spec_from_loader(
            fullname,
            loader,
            origin=str(source_path),
            is_package=is_package,
        )


_IMPORT_SOURCE_BYTES = _snapshot_profile_sources()
_FROZEN_MODULE_SOURCES = {
    binding[0]: (path, _IMPORT_SOURCE_BYTES[path], binding[1])
    for path in _IMPORT_SOURCE_BYTES
    if (binding := _module_name_for_path(path)) is not None
}
_FROZEN_SOURCE_FINDER = _FrozenRepoSourceFinder(_FROZEN_MODULE_SOURCES)
for _frozen_module_name in sorted(
    _FROZEN_MODULE_SOURCES,
    key=lambda name: (name.count("."), name),
    reverse=True,
):
    sys.modules.pop(_frozen_module_name, None)
sys.meta_path.insert(0, _FROZEN_SOURCE_FINDER)


_IMPORT_SOURCE_SHA256 = {
    path: hashlib.sha256(data).hexdigest()
    for path, data in _IMPORT_SOURCE_BYTES.items()
}


def _profile_source_binding() -> tuple[tuple[str, str], ...]:
    """import時に固定したtransitive sourceのrepo相対hashを返す。"""

    return tuple(
        sorted(
            (
                path.relative_to(REPOSITORY_ROOT).as_posix(),
                digest,
            )
            for path, digest in _IMPORT_SOURCE_SHA256.items()
        )
    )


def _load_detector(path: Path, module_name: str) -> Detector:
    """通常package外のdetectorをimport前memory snapshotから読み込む。"""

    expected_sha256 = _IMPORT_SOURCE_SHA256[path]
    if _source_sha256(path) != expected_sha256:
        raise RuntimeError(f"detector sourceがimport前に変更されました: {path.name}")
    module = ModuleType(module_name)
    module.__file__ = str(path)
    module.__package__ = ""
    sys.modules[module_name] = module
    code = compile(_IMPORT_SOURCE_BYTES[path], str(path), "exec", dont_inherit=True)
    exec(code, module.__dict__)
    if _source_sha256(path) != expected_sha256:
        raise RuntimeError(f"detector sourceがimport中に変更されました: {path.name}")
    detector = getattr(module, "detect", None)
    if not callable(detector):
        raise TypeError(f"detectorにdetect関数がありません: {path.name}")
    return detector


def _endpoint_hashes(
    endpoints: object,
    *,
    require_sorted: bool,
) -> tuple[str, ...] | None:
    """正規化済みendpoint列を検証し、公開可能なfingerprintへ変換する。"""

    if (
        not isinstance(endpoints, list)
        or not endpoints
        or any(not isinstance(item, str) or not item or len(item) > 512 for item in endpoints)
        or len(endpoints) != len(set(endpoints))
        or (require_sorted and endpoints != sorted(endpoints))
    ):
        return None
    return tuple(sorted(hashlib.sha256(item.encode("utf-8")).hexdigest() for item in endpoints))


def _purelogs_config_identity(result: Mapping[str, Any]) -> tuple[ConfigIdentity | None, int, tuple[str, ...]]:
    """PureLogs protobuf設定と標準C2 recordの完全一致を検証する。"""

    config = result.get("config")
    if not isinstance(config, Mapping):
        return None, 0, ()
    required_true = (
        result.get("supports_family_attribution"),
        result.get("terminal_family_confirmed"),
        config.get("static_config_recovered"),
        config.get("decoded_config_recovered"),
        config.get("family_attribution_confirmed"),
        config.get("supports_family_attribution"),
        config.get("terminal_family_confirmed"),
    )
    if any(value is not True for value in required_true):
        return None, 0, ()
    if (
        config.get("variant") != "purelogs_protobuf_config"
        or config.get("confidence") != "confirmed"
        or config.get("status") != "purelogs_protobuf_config_recovered"
    ):
        return None, 0, ()
    endpoints = config.get("configured_endpoints")
    endpoint_hashes = _endpoint_hashes(endpoints, require_sorted=True)
    if endpoint_hashes is None or not isinstance(endpoints, list):
        return None, 0, ()
    protobuf = config.get("protobuf")
    if not isinstance(protobuf, Mapping):
        return None, 0, ()
    key_hashes = protobuf.get("aes_key_sha256")
    if (
        not isinstance(key_hashes, list)
        or len(key_hashes) != 1
        or any(not isinstance(item, str) or SHA256_RE.fullmatch(item) is None for item in key_hashes)
        or key_hashes != sorted(set(key_hashes))
        or protobuf.get("aes_key_length_bytes") != 32
        or protobuf.get("aes_key_material_published") is not False
    ):
        return None, 0, ()
    c2 = result.get("c2")
    if not isinstance(c2, list) or len(c2) != len(endpoints):
        return None, 0, ()
    reconstructed: list[str] = []
    for item in c2:
        if not isinstance(item, Mapping):
            return None, 0, ()
        host = item.get("host")
        port = item.get("port")
        evidence = item.get("evidence")
        if (
            not isinstance(host, str)
            or not host
            or len(host) > 253
            or isinstance(port, bool)
            or not isinstance(port, int)
            or not 1 <= port <= 65535
            or item.get("role") != "c2"
            or item.get("confidence") != "confirmed_static_configuration"
            or not isinstance(evidence, Mapping)
            or evidence.get("kind") != "base64_protobuf_config"
            or evidence.get("aes_key_length_validated") is not True
            or evidence.get("family_markers_correlated") is not True
        ):
            return None, 0, ()
        reconstructed.append(f"{host}:{port}")
    if sorted(reconstructed) != endpoints:
        return None, 0, ()
    identity: ConfigIdentity = (
        ("endpoints", *endpoints),
        ("aes_key_sha256", *key_hashes),
    )
    return identity, len(endpoints), endpoint_hashes


def _assess_purelogs(
    layer_sha256: str,
    detection: Mapping[str, Any],
    extraction: Mapping[str, Any],
) -> LayerAssessment:
    """PureLogsのdetector結果とextractor結果を同一layerで相関する。"""

    detector_family = bool(
        detection.get("matched") is True
        and detection.get("confidence") == "high_static"
        and detection.get("sha256") == layer_sha256
    )
    config = extraction.get("config")
    extractor_family = bool(
        extraction.get("sample_sha256") == layer_sha256
        and extraction.get("family") == "purelogs"
        and extraction.get("supports_family_attribution") is True
        and extraction.get("terminal_family_confirmed") is True
        and isinstance(config, Mapping)
        and config.get("family_attribution_confirmed") is True
    )
    if extraction.get("sample_sha256") == layer_sha256:
        identity, endpoint_count, endpoint_hashes = _purelogs_config_identity(extraction)
    else:
        identity, endpoint_count, endpoint_hashes = None, 0, ()
    terminal_family = detector_family and extractor_family
    return LayerAssessment(
        loader_family_confirmed=False,
        terminal_candidate_verified=bool(extractor_family or identity is not None),
        terminal_family_confirmed=terminal_family,
        config_identity=identity,
        endpoint_count=endpoint_count,
        endpoint_sha256=endpoint_hashes,
    )


def _purerat_config_identity(
    layer_sha256: str,
    detection: Mapping[str, Any],
    result: Mapping[str, Any],
) -> tuple[ConfigIdentity | None, int, tuple[str, ...]]:
    """PureRAT protobuf／PFX設定とdetector証拠を相関する。"""

    observations = detection.get("observations")
    managed = observations.get("managed_terminal") if isinstance(observations, Mapping) else None
    config = result.get("config")
    if not isinstance(managed, Mapping) or not isinstance(config, Mapping):
        return None, 0, ()
    if (
        detection.get("matched") is not True
        or detection.get("confidence") != "high"
        or detection.get("sha256") != layer_sha256
        or managed.get("matched") is not True
        or result.get("sample_sha256") != layer_sha256
        or result.get("family") != "purehvnc"
        or config.get("variant") != "managed_purerat"
        or config.get("static_config_recovered") is not True
        or config.get("decoded_config_recovered") is not True
        or config.get("status") != "managed_terminal_config_recovered"
        or config.get("terminal_family_confirmation_requires_detector") is not True
    ):
        return None, 0, ()
    endpoints = config.get("endpoints")
    endpoint_hashes = _endpoint_hashes(endpoints, require_sorted=False)
    if endpoint_hashes is None or not isinstance(endpoints, list):
        return None, 0, ()
    host = config.get("c2_host")
    ports = config.get("c2_ports")
    expected = [f"{host}:{port}" for port in ports] if isinstance(host, str) and isinstance(ports, list) else []
    certificate = config.get("certificate")
    versions = config.get("version_candidates")
    campaign = config.get("campaign_id")
    if (
        endpoints != expected
        or managed.get("endpoints") != endpoints
        or managed.get("campaign_id") != campaign
        or not isinstance(versions, list)
        or len(versions) != 1
        or managed.get("version") != versions[0]
        or not isinstance(certificate, Mapping)
        or managed.get("certificate_sha256") != certificate.get("certificate_sha256")
        or managed.get("pfx_sha256") != certificate.get("pfx_sha256")
    ):
        return None, 0, ()
    certificate_sha256 = certificate.get("certificate_sha256")
    pfx_sha256 = certificate.get("pfx_sha256")
    if (
        not isinstance(certificate_sha256, str)
        or SHA256_RE.fullmatch(certificate_sha256) is None
        or not isinstance(pfx_sha256, str)
        or SHA256_RE.fullmatch(pfx_sha256) is None
        or not isinstance(campaign, str)
        or not campaign
        or len(campaign) > 128
        or not isinstance(host, str)
        or not host
        or len(host) > 253
    ):
        return None, 0, ()
    c2 = result.get("c2")
    if not isinstance(c2, list) or len(c2) != len(endpoints):
        return None, 0, ()
    reconstructed: list[str] = []
    for item in c2:
        if not isinstance(item, Mapping):
            return None, 0, ()
        evidence = item.get("evidence")
        host_value = item.get("host")
        port_value = item.get("port")
        if (
            not isinstance(host_value, str)
            or not host_value
            or isinstance(port_value, bool)
            or not isinstance(port_value, int)
            or not 1 <= port_value <= 65535
            or item.get("role") != "c2"
            or item.get("confidence") != "confirmed_static_configuration"
            or not isinstance(evidence, Mapping)
            or evidence.get("kind") != "managed_base64_gzip_protobuf_config"
            or evidence.get("variant") != "managed_purerat"
            or evidence.get("host_and_ports_validated") is not True
            or evidence.get("endpoint_correlated") is not True
        ):
            return None, 0, ()
        reconstructed.append(f"{host_value}:{port_value}")
    if reconstructed != endpoints:
        return None, 0, ()
    identity: ConfigIdentity = (
        ("endpoints", *endpoints),
        ("certificate_sha256", certificate_sha256),
        ("pfx_sha256", pfx_sha256),
        ("version", versions[0]),
        ("campaign_sha256", hashlib.sha256(campaign.encode("utf-8")).hexdigest()),
    )
    return identity, len(endpoints), endpoint_hashes


def _assess_purerat(
    layer_sha256: str,
    detection: Mapping[str, Any],
    extraction: Mapping[str, Any],
) -> LayerAssessment:
    """PureRATのloader証拠とmanaged terminal証拠を混同せず評価する。"""

    detector_match = bool(
        detection.get("matched") is True
        and detection.get("confidence") == "high"
        and detection.get("sha256") == layer_sha256
    )
    observations = detection.get("observations")
    managed = observations.get("managed_terminal") if isinstance(observations, Mapping) else None
    managed_terminal = bool(detector_match and isinstance(managed, Mapping) and managed.get("matched") is True)
    identity, endpoint_count, endpoint_hashes = _purerat_config_identity(
        layer_sha256,
        detection,
        extraction,
    )
    return LayerAssessment(
        loader_family_confirmed=bool(detector_match and not managed_terminal),
        terminal_candidate_verified=bool(managed_terminal or identity is not None),
        terminal_family_confirmed=managed_terminal,
        config_identity=identity,
        endpoint_count=endpoint_count,
        endpoint_sha256=endpoint_hashes,
    )


from extractors.purehvnc.extractor import extract as extract_purerat  # noqa: E402
from extractors.purelogs.extractor import extract as extract_purelogs  # noqa: E402

for _imported_source_path, _imported_source_sha256 in _IMPORT_SOURCE_SHA256.items():
    if _source_sha256(_imported_source_path) != _imported_source_sha256:
        raise RuntimeError(
            f"profile依存sourceがimport中に変更されました: {_imported_source_path.name}"
        )

PURELOGS_PROFILE = PureCohortProfile(
    profile_id="purelogs",
    cohort_name="PureLogsStealer",
    family="purelogs",
    detector_confidence="high_static",
    detector=_load_detector(
        PURELOGS_DETECTOR_PATH,
        "purelogs_strict_cohort_detector",
    ),
    extractor=extract_purelogs,
    assess=_assess_purelogs,
    configuration_format="base64_protobuf",
    import_source_sha256=_profile_source_binding(),
    detector_extractor_independence_claimed=False,
)

PURERAT_PROFILE = PureCohortProfile(
    profile_id="purerat",
    cohort_name="PureRAT",
    family="purehvnc",
    detector_confidence="high",
    detector=_load_detector(
        PURERAT_DETECTOR_PATH,
        "purerat_strict_cohort_detector",
    ),
    extractor=extract_purerat,
    assess=_assess_purerat,
    configuration_format="base64_gzip_protobuf_with_pfx",
    import_source_sha256=_profile_source_binding(),
    detector_extractor_independence_claimed=False,
)

PROFILES = {
    PURELOGS_PROFILE.profile_id: PURELOGS_PROFILE,
    PURERAT_PROFILE.profile_id: PURERAT_PROFILE,
}


def get_profile(profile_id: str) -> PureCohortProfile:
    """固定allowlistからfamily評価profileを返す。"""

    try:
        return PROFILES[profile_id]
    except KeyError as exc:
        raise ValueError(f"未対応のPure cohort profileです: {profile_id}") from exc
