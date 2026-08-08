#!/usr/bin/env python3
"""静的復元処理を安全に束ねるための共通オーケストレーション基盤。"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import re
import stat
import tempfile
from types import MappingProxyType
from typing import Any, Callable, Iterable, Mapping, Sequence


PRIVATE_BUNDLE_MANIFEST_TYPE = "static_analysis_private_bundle"
_MANIFEST_KEYS = frozenset({"schema_version", "manifest_type", "settings", "artifacts"})
_ARTIFACT_KEYS = frozenset({"role", "path", "sha256", "size", "media_type", "json_identity"})
_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")
_IDENTIFIER_PATTERN = re.compile(r"[A-Za-z][A-Za-z0-9_.-]{0,127}")
_MEDIA_TYPE_PATTERN = re.compile(r"[a-z0-9][a-z0-9!#$&^_.+-]{0,63}/[a-z0-9][a-z0-9!#$&^_.+-]{0,127}")
_FORBIDDEN_SETTING_KEYS = frozenset(
    {
        "argv",
        "callable",
        "callables",
        "cmd",
        "command",
        "commands",
        "executable",
        "function",
        "handler",
        "import",
        "module",
        "path",
        "python",
        "script",
        "shell",
    }
)
_JSON_MEDIA_TYPES = frozenset({"application/json", "text/json"})
_JSON_SCALAR = str | int | float | bool | None


class StaticOrchestrationError(ValueError):
    """オーケストレーション契約違反を表す基底例外。"""


class ManifestValidationError(StaticOrchestrationError):
    """private bundle manifestが契約に一致しないことを表す。"""


class PublicationError(StaticOrchestrationError):
    """成果物を安全に公開できなかったことを表す。"""


class StageGraphError(StaticOrchestrationError):
    """stage DAGの定義が不正であることを表す。"""


def _reject_json_constant(value: str) -> None:
    raise ManifestValidationError(f"JSONの非有限値は使用できません: {value}")


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ManifestValidationError(f"JSON keyが重複しています: {key}")
        result[key] = value
    return result


def _load_json_bytes(data: bytes, *, label: str) -> Any:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ManifestValidationError(f"{label}はUTF-8 JSONではありません") from exc
    try:
        return json.loads(
            text,
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=_reject_json_constant,
        )
    except ManifestValidationError:
        raise
    except (json.JSONDecodeError, RecursionError, TypeError, ValueError) as exc:
        raise ManifestValidationError(f"{label}をJSONとして解釈できません") from exc


def _read_bounded_regular(path: Path, *, maximum: int, label: str) -> bytes:
    """通常fileを上限付きで読み、読込中の差替えとhardlinkを拒否する。"""

    if isinstance(maximum, bool) or not isinstance(maximum, int) or maximum <= 0:
        raise StaticOrchestrationError("read上限は正の整数で指定してください")
    try:
        with path.open("rb") as stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode):
                raise StaticOrchestrationError(f"{label}は通常fileである必要があります")
            if before.st_nlink != 1:
                raise StaticOrchestrationError(f"{label}にhardlinkは使用できません")
            if before.st_size < 0 or before.st_size > maximum:
                raise StaticOrchestrationError(f"{label}がsize上限を超えています")
            data = stream.read(maximum + 1)
            after = os.fstat(stream.fileno())
    except StaticOrchestrationError:
        raise
    except OSError as exc:
        raise StaticOrchestrationError(f"{label}を安全に読み取れません") from exc
    if len(data) > maximum:
        raise StaticOrchestrationError(f"{label}がsize上限を超えています")
    before_identity = (before.st_dev, before.st_ino, before.st_size)
    after_identity = (after.st_dev, after.st_ino, after.st_size)
    if before_identity != after_identity or len(data) != before.st_size:
        raise StaticOrchestrationError(f"{label}が読込中に変更されました")
    return data


def _is_json_value(value: Any) -> bool:
    if value is None or isinstance(value, (str, bool, int)):
        return True
    if isinstance(value, float):
        return value == value and value not in (float("inf"), float("-inf"))
    if isinstance(value, list):
        return all(_is_json_value(item) for item in value)
    if isinstance(value, dict):
        return all(isinstance(key, str) and _is_json_value(item) for key, item in value.items())
    return False


def _freeze_json(value: Any) -> Any:
    if isinstance(value, dict):
        return MappingProxyType({key: _freeze_json(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_freeze_json(item) for item in value)
    return value


def _thaw_json(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _thaw_json(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw_json(item) for item in value]
    return value


def canonical_json_bytes(value: Any) -> bytes:
    """JSON-safe値をfingerprint用の決定的UTF-8表現へ変換する。"""

    thawed = _thaw_json(value)
    if not _is_json_value(thawed):
        raise StaticOrchestrationError("canonical JSONにはJSON-safe値だけを指定してください")
    return json.dumps(
        thawed,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _has_reparse_attribute(path: Path) -> bool:
    try:
        info = path.lstat()
    except OSError as exc:
        raise StaticOrchestrationError(f"pathを検査できません: {path}") from exc
    attributes = int(getattr(info, "st_file_attributes", 0))
    reparse_flag = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
    return path.is_symlink() or bool(attributes & reparse_flag)


def _assert_no_reparse_chain(path: Path, *, root: Path) -> None:
    """rootからpathまでの既存要素にsymlink/reparse pointがないことを確認する。"""

    root_absolute = Path(os.path.abspath(root))
    path_absolute = Path(os.path.abspath(path))
    try:
        relative = path_absolute.relative_to(root_absolute)
    except ValueError as exc:
        raise StaticOrchestrationError("pathが許可root外です") from exc
    current = root_absolute
    if not current.exists() or _has_reparse_attribute(current):
        raise StaticOrchestrationError("許可rootは実在する通常directoryである必要があります")
    for part in relative.parts:
        current = current / part
        if not current.exists():
            break
        if _has_reparse_attribute(current):
            raise StaticOrchestrationError(f"symlink/reparse pointは使用できません: {current.name}")


def _contained(path: Path, root: Path) -> bool:
    try:
        return os.path.commonpath((str(path), str(root))) == str(root)
    except ValueError:
        return False


def validate_private_root(private_root: Path, *, repository_root: Path) -> Path:
    """private rootがrepositoryと重ならない実directoryであることを検証する。"""

    private_absolute = Path(os.path.abspath(private_root))
    repository_absolute = Path(os.path.abspath(repository_root))
    if not private_absolute.is_dir() or not repository_absolute.is_dir():
        raise StaticOrchestrationError("private rootとrepository rootは実在するdirectoryが必要です")
    if _has_reparse_attribute(private_absolute) or _has_reparse_attribute(repository_absolute):
        raise StaticOrchestrationError("root自体にsymlink/reparse pointは使用できません")
    private_resolved = private_absolute.resolve(strict=True)
    repository_resolved = repository_absolute.resolve(strict=True)
    if _contained(private_resolved, repository_resolved) or _contained(repository_resolved, private_resolved):
        raise StaticOrchestrationError("private rootはrepository rootの外側で分離してください")
    return private_resolved


def _validate_relative_artifact_path(raw_path: Any) -> tuple[str, ...]:
    if not isinstance(raw_path, str) or not raw_path or len(raw_path) > 4096:
        raise ManifestValidationError("artifact pathは有界な非空文字列で指定してください")
    if any(ord(character) < 32 or ord(character) == 127 for character in raw_path):
        raise ManifestValidationError("artifact pathに制御文字は使用できません")
    if ":" in raw_path:
        raise ManifestValidationError("artifact pathにdrive指定やADSは使用できません")
    windows_path = PureWindowsPath(raw_path)
    posix_path = PurePosixPath(raw_path.replace("\\", "/"))
    if windows_path.is_absolute() or windows_path.drive or windows_path.root or posix_path.is_absolute():
        raise ManifestValidationError("artifact pathは相対pathで指定してください")
    parts = tuple(part for part in re.split(r"[\\/]", raw_path) if part != "")
    if not parts or any(part in {".", ".."} for part in parts):
        raise ManifestValidationError("artifact pathに現在・親directory参照は使用できません")
    if raw_path.startswith(("\\", "/")) or "//" in raw_path or "\\\\" in raw_path:
        raise ManifestValidationError("artifact pathにUNCまたは空要素は使用できません")
    return parts


def _validate_settings(value: Any) -> Mapping[str, Any]:
    if value is None:
        return MappingProxyType({})
    if not isinstance(value, dict) or not _is_json_value(value):
        raise ManifestValidationError("settingsはJSON-safe objectで指定してください")

    def visit(item: Any) -> None:
        if isinstance(item, dict):
            for key, child in item.items():
                normalized = key.casefold().replace("-", "_")
                tokens = {part for part in re.split(r"[^a-z0-9]+", normalized) if part}
                if normalized in _FORBIDDEN_SETTING_KEYS or tokens & _FORBIDDEN_SETTING_KEYS:
                    raise ManifestValidationError(f"settingsで実行・path指定keyは使用できません: {key}")
                visit(child)
        elif isinstance(item, list):
            for child in item:
                visit(child)

    visit(value)
    return _freeze_json(value)


def _identity_matches(actual: Any, expected: Any) -> bool:
    if isinstance(expected, Mapping):
        return isinstance(actual, dict) and all(
            key in actual and _identity_matches(actual[key], value) for key, value in expected.items()
        )
    if isinstance(expected, tuple):
        return (
            isinstance(actual, list)
            and len(actual) == len(expected)
            and all(_identity_matches(left, right) for left, right in zip(actual, expected, strict=True))
        )
    return type(actual) is type(expected) and actual == expected


@dataclass(frozen=True)
class ArtifactRequirement:
    """roleごとのmedia typeとJSON identityを固定する読込契約。"""

    role: str
    media_type: str
    json_identity: Mapping[str, Any] | None = None
    max_size: int = 512 * 1024 * 1024
    required: bool = True

    def __post_init__(self) -> None:
        if not isinstance(self.role, str) or not _IDENTIFIER_PATTERN.fullmatch(self.role):
            raise ValueError("roleは安全な識別子で指定してください")
        if not isinstance(self.media_type, str) or not _MEDIA_TYPE_PATTERN.fullmatch(self.media_type):
            raise ValueError("media_typeは正規化したMIME typeで指定してください")
        if isinstance(self.max_size, bool) or not isinstance(self.max_size, int) or self.max_size <= 0:
            raise ValueError("max_sizeは正の整数で指定してください")
        if not isinstance(self.required, bool):
            raise TypeError("requiredはboolで指定してください")
        if self.json_identity is not None:
            if not isinstance(self.json_identity, Mapping) or not self.json_identity:
                raise ValueError("json_identityは非空objectで指定してください")
            identity = _thaw_json(self.json_identity)
            if not _is_json_value(identity):
                raise ValueError("json_identityはJSON-safe値だけを含めてください")
            object.__setattr__(self, "json_identity", _freeze_json(identity))


@dataclass(frozen=True)
class LoadedArtifact:
    """hash等を検証済みのprivate artifact。raw bytesはpublic()へ含めない。"""

    role: str
    path: Path = field(repr=False)
    data: bytes = field(repr=False)
    sha256: str
    size: int
    media_type: str
    json_value: Any = field(default=None, repr=False)
    json_identity_verified: bool = False

    def public(self) -> dict[str, Any]:
        """private pathとraw bytesを除外した公開可能メタデータを返す。"""

        return {
            "role": self.role,
            "sha256": self.sha256,
            "size": self.size,
            "media_type": self.media_type,
            "json_identity_verified": self.json_identity_verified,
        }


@dataclass(frozen=True)
class ArtifactBundle:
    """manifestと全artifactを検証済みのprivate bundle。"""

    manifest_path: Path = field(repr=False)
    manifest_sha256: str
    settings: Mapping[str, Any]
    artifacts: tuple[LoadedArtifact, ...]

    def require(self, role: str) -> LoadedArtifact:
        """指定roleを返し、存在しなければfail-closedで終了する。"""

        for artifact in self.artifacts:
            if artifact.role == role:
                return artifact
        raise ManifestValidationError(f"必要なartifact roleがありません: {role}")

    def public(self) -> dict[str, Any]:
        """private path・raw bytes・settingsを含まない公開可能情報を返す。"""

        return {
            "schema_version": 1,
            "manifest_type": PRIVATE_BUNDLE_MANIFEST_TYPE,
            "manifest_sha256": self.manifest_sha256,
            "artifacts": [artifact.public() for artifact in self.artifacts],
        }


def load_artifact_bundle(
    manifest_path: Path,
    *,
    private_root: Path,
    requirements: Sequence[ArtifactRequirement],
    manifest_type: str = PRIVATE_BUNDLE_MANIFEST_TYPE,
) -> ArtifactBundle:
    """role付きprivate bundleを全件認証し、未知・欠損・重複を拒否する。"""

    root = Path(os.path.abspath(private_root))
    if not root.is_dir() or _has_reparse_attribute(root):
        raise ManifestValidationError("private_rootは通常の実directoryである必要があります")
    root = root.resolve(strict=True)
    manifest = Path(os.path.abspath(manifest_path))
    if not _contained(manifest, root):
        raise ManifestValidationError("manifestはprivate_root内に配置してください")
    try:
        _assert_no_reparse_chain(manifest, root=root)
    except StaticOrchestrationError as exc:
        raise ManifestValidationError(str(exc)) from exc
    if not manifest.is_file():
        raise ManifestValidationError("manifestが通常fileではありません")
    try:
        manifest_data = _read_bounded_regular(
            manifest,
            maximum=1024 * 1024,
            label="bundle manifest",
        )
    except StaticOrchestrationError as exc:
        raise ManifestValidationError(str(exc)) from exc
    document = _load_json_bytes(manifest_data, label="bundle manifest")
    if not isinstance(document, dict):
        raise ManifestValidationError("bundle manifestはobjectである必要があります")
    unknown_top = set(document) - _MANIFEST_KEYS
    missing_top = {"schema_version", "manifest_type", "artifacts"} - set(document)
    if unknown_top or missing_top:
        raise ManifestValidationError(
            f"bundle manifestのkeyが契約外です: unknown={sorted(unknown_top)}, missing={sorted(missing_top)}"
        )
    if document["schema_version"] != 1 or isinstance(document["schema_version"], bool):
        raise ManifestValidationError("schema_versionは整数1である必要があります")
    if document["manifest_type"] != manifest_type:
        raise ManifestValidationError("manifest_typeが期待値と一致しません")
    settings = _validate_settings(document.get("settings"))
    artifacts_value = document["artifacts"]
    if not isinstance(artifacts_value, list) or not artifacts_value:
        raise ManifestValidationError("artifactsは非空listである必要があります")
    requirement_by_role: dict[str, ArtifactRequirement] = {}
    for requirement in requirements:
        if requirement.role in requirement_by_role:
            raise ManifestValidationError(f"requirement roleが重複しています: {requirement.role}")
        requirement_by_role[requirement.role] = requirement
    if not requirement_by_role:
        raise ManifestValidationError("少なくとも1件のrole requirementが必要です")

    loaded: list[LoadedArtifact] = []
    seen_roles: set[str] = set()
    seen_files: list[Path] = []
    for index, item in enumerate(artifacts_value):
        if not isinstance(item, dict):
            raise ManifestValidationError(f"artifacts[{index}]はobjectである必要があります")
        unknown = set(item) - _ARTIFACT_KEYS
        missing = {"role", "path", "sha256", "size", "media_type"} - set(item)
        if unknown or missing:
            raise ManifestValidationError(
                f"artifacts[{index}]のkeyが契約外です: unknown={sorted(unknown)}, missing={sorted(missing)}"
            )
        role = item["role"]
        if not isinstance(role, str) or role not in requirement_by_role:
            raise ManifestValidationError(f"未知のartifact roleです: {role!r}")
        if role in seen_roles:
            raise ManifestValidationError(f"artifact roleが重複しています: {role}")
        seen_roles.add(role)
        requirement = requirement_by_role[role]
        parts = _validate_relative_artifact_path(item["path"])
        artifact_path = root.joinpath(*parts)
        try:
            _assert_no_reparse_chain(artifact_path, root=root)
        except StaticOrchestrationError as exc:
            raise ManifestValidationError(str(exc)) from exc
        if not artifact_path.is_file():
            raise ManifestValidationError(f"artifactが通常fileではありません: {role}")
        resolved_artifact = artifact_path.resolve(strict=True)
        if not _contained(resolved_artifact, root):
            raise ManifestValidationError(f"artifactがprivate_root外を指しています: {role}")
        if any(os.path.samefile(resolved_artifact, previous) for previous in seen_files):
            raise ManifestValidationError("複数roleが同一fileまたはhardlinkを参照しています")
        seen_files.append(resolved_artifact)
        size = item["size"]
        if isinstance(size, bool) or not isinstance(size, int) or size < 0 or size > requirement.max_size:
            raise ManifestValidationError(f"artifact sizeが不正または上限超過です: {role}")
        sha256 = item["sha256"]
        if not isinstance(sha256, str) or not _SHA256_PATTERN.fullmatch(sha256):
            raise ManifestValidationError(f"artifact sha256が不正です: {role}")
        media_type = item["media_type"]
        if media_type != requirement.media_type:
            raise ManifestValidationError(f"artifact media_typeがrole契約と一致しません: {role}")
        try:
            data = _read_bounded_regular(
                resolved_artifact,
                maximum=requirement.max_size,
                label=f"artifact {role}",
            )
        except StaticOrchestrationError as exc:
            raise ManifestValidationError(str(exc)) from exc
        if len(data) != size:
            raise ManifestValidationError(f"artifact sizeが実fileと一致しません: {role}")
        if hashlib.sha256(data).hexdigest() != sha256:
            raise ManifestValidationError(f"artifact sha256が実fileと一致しません: {role}")
        declared_identity = item.get("json_identity")
        expected_identity = requirement.json_identity
        if expected_identity is None:
            if declared_identity is not None:
                raise ManifestValidationError(f"identity契約のないroleへjson_identityは指定できません: {role}")
            if media_type in _JSON_MEDIA_TYPES or media_type.endswith("+json"):
                json_value = _load_json_bytes(data, label=f"artifact {role}")
            else:
                json_value = None
            identity_verified = False
        else:
            if media_type not in _JSON_MEDIA_TYPES and not media_type.endswith("+json"):
                raise ManifestValidationError(f"json_identity roleのmedia_typeがJSONではありません: {role}")
            if not isinstance(declared_identity, dict) or not _is_json_value(declared_identity):
                raise ManifestValidationError(f"json_identityが不正です: {role}")
            if canonical_json_bytes(declared_identity) != canonical_json_bytes(expected_identity):
                raise ManifestValidationError(f"manifestのjson_identityがrole契約と一致しません: {role}")
            json_value = _load_json_bytes(data, label=f"artifact {role}")
            if not _identity_matches(json_value, expected_identity):
                raise ManifestValidationError(f"artifact JSON identityが一致しません: {role}")
            identity_verified = True
        loaded.append(
            LoadedArtifact(
                role=role,
                path=resolved_artifact,
                data=data,
                sha256=sha256,
                size=size,
                media_type=media_type,
                json_value=json_value,
                json_identity_verified=identity_verified,
            )
        )
    missing_roles = sorted(
        role for role, requirement in requirement_by_role.items() if requirement.required and role not in seen_roles
    )
    if missing_roles:
        raise ManifestValidationError(f"必要なartifact roleが欠損しています: {missing_roles}")
    entry_role = settings.get("entry_role")
    if entry_role is not None and (
        not isinstance(entry_role, str) or not _IDENTIFIER_PATTERN.fullmatch(entry_role)
    ):
        raise ManifestValidationError("settings.entry_roleは安全な論理roleで指定してください")
    return ArtifactBundle(
        manifest_path=manifest.resolve(strict=True),
        manifest_sha256=hashlib.sha256(manifest_data).hexdigest(),
        settings=settings,
        artifacts=tuple(loaded),
    )


def pipeline_fingerprint(
    *,
    input_sha256: str,
    bundle_manifest_sha256: str,
    component_sha256: Mapping[str, str],
    options: Mapping[str, Any],
) -> str:
    """入力・bundle・実装component・optionから決定的pipeline fingerprintを返す。"""

    for label, digest in (
        ("input_sha256", input_sha256),
        ("bundle_manifest_sha256", bundle_manifest_sha256),
    ):
        if not isinstance(digest, str) or not _SHA256_PATTERN.fullmatch(digest):
            raise StaticOrchestrationError(f"{label}は小文字SHA-256で指定してください")
    if not isinstance(component_sha256, Mapping) or not component_sha256:
        raise StaticOrchestrationError("component_sha256は非空mappingで指定してください")
    normalized_components: dict[str, str] = {}
    for name, digest in component_sha256.items():
        if not isinstance(name, str) or not _IDENTIFIER_PATTERN.fullmatch(name):
            raise StaticOrchestrationError("component名は安全な識別子で指定してください")
        if not isinstance(digest, str) or not _SHA256_PATTERN.fullmatch(digest):
            raise StaticOrchestrationError(f"component hashが不正です: {name}")
        normalized_components[name] = digest
    payload = {
        "schema_version": 1,
        "input_sha256": input_sha256,
        "bundle_manifest_sha256": bundle_manifest_sha256,
        "component_sha256": normalized_components,
        "options": _thaw_json(options),
    }
    return hashlib.sha256(canonical_json_bytes(payload)).hexdigest()


@dataclass(frozen=True)
class OutputBytes:
    """公開またはprivate rootへ原子的に保存するbytes成果物。"""

    role: str
    destination: Path
    data: bytes = field(repr=False)
    visibility: str

    def __post_init__(self) -> None:
        if not isinstance(self.role, str) or not _IDENTIFIER_PATTERN.fullmatch(self.role):
            raise ValueError("output roleは安全な識別子で指定してください")
        if not isinstance(self.destination, Path):
            raise TypeError("destinationはPathで指定してください")
        if not isinstance(self.data, bytes):
            raise TypeError("output dataはimmutable bytesで指定してください")
        if self.visibility not in {"public", "private"}:
            raise ValueError("visibilityはpublicまたはprivateで指定してください")


@dataclass(frozen=True)
class PublishedArtifact:
    """公開処理後の検証可能な成果物メタデータ。"""

    role: str
    sha256: str
    size: int
    visibility: str

    def public(self) -> dict[str, Any]:
        """pathとbytesを含まない公開用辞書を返す。"""

        return {
            "role": self.role,
            "sha256": self.sha256,
            "size": self.size,
            "visibility": self.visibility,
        }


def _lexical_identity(path: Path) -> str:
    return os.path.normcase(os.path.abspath(path))


def _safe_unlink(path: Path) -> None:
    try:
        path.unlink(missing_ok=True)
    except OSError:
        pass


def publish_bytes_atomically(
    outputs: Sequence[OutputBytes],
    *,
    input_paths: Iterable[Path] = (),
    public_root: Path,
    private_root: Path,
) -> tuple[PublishedArtifact, ...]:
    """全bytesをstageしてから置換し、途中失敗時は全出力を元へ戻す。"""

    if not outputs:
        raise PublicationError("少なくとも1件のoutputが必要です")
    public = Path(os.path.abspath(public_root))
    private = Path(os.path.abspath(private_root))
    if not public.is_dir() or not private.is_dir():
        raise PublicationError("public/private rootは実在するdirectoryが必要です")
    for root in (public, private):
        if _has_reparse_attribute(root):
            raise PublicationError("output rootにsymlink/reparse pointは使用できません")
    public = public.resolve(strict=True)
    private = private.resolve(strict=True)
    if _contained(public, private) or _contained(private, public):
        raise PublicationError("public rootとprivate rootは相互に分離してください")
    input_list = [Path(os.path.abspath(path)) for path in input_paths]
    for path in input_list:
        if not path.is_file() or _has_reparse_attribute(path):
            raise PublicationError("input pathはsymlinkでない実fileが必要です")
        try:
            if path.stat().st_nlink != 1:
                raise PublicationError("input pathにhardlinkは使用できません")
        except OSError as exc:
            raise PublicationError("input pathを検査できません") from exc

    destinations: list[Path] = []
    seen_roles: set[str] = set()
    for output in outputs:
        if output.role in seen_roles:
            raise PublicationError(f"output roleが重複しています: {output.role}")
        seen_roles.add(output.role)
        destination = Path(os.path.abspath(output.destination))
        root = public if output.visibility == "public" else private
        if not _contained(destination, root):
            raise PublicationError(f"outputが指定visibilityのroot外です: {output.role}")
        try:
            _assert_no_reparse_chain(destination, root=root)
        except StaticOrchestrationError as exc:
            raise PublicationError(str(exc)) from exc
        if not destination.parent.is_dir():
            raise PublicationError(f"output parentが存在しません: {output.role}")
        if destination.exists() and not destination.is_file():
            raise PublicationError(f"output先は通常fileではありません: {output.role}")
        if destination.exists() and _has_reparse_attribute(destination):
            raise PublicationError(f"symlink outputは使用できません: {output.role}")
        if destination.exists():
            try:
                if destination.stat().st_nlink != 1:
                    raise PublicationError(f"hardlink outputは使用できません: {output.role}")
            except OSError as exc:
                raise PublicationError(f"outputを検査できません: {output.role}") from exc
        if any(_lexical_identity(destination) == _lexical_identity(path) for path in input_list):
            raise PublicationError("inputとoutputが同じpathです")
        if destination.exists() and any(os.path.samefile(destination, path) for path in input_list):
            raise PublicationError("outputがinputと同一file/hardlinkです")
        for previous in destinations:
            if _lexical_identity(destination) == _lexical_identity(previous):
                raise PublicationError("output destinationが重複しています")
            if destination.exists() and previous.exists() and os.path.samefile(destination, previous):
                raise PublicationError("既存outputが同一file/hardlinkです")
        destinations.append(destination)

    staged: dict[Path, Path] = {}
    backups: dict[Path, Path | None] = {}
    replaced: list[Path] = []
    preserved_backups: set[Path] = set()
    try:
        for output, destination in zip(outputs, destinations, strict=True):
            descriptor, temporary_name = tempfile.mkstemp(prefix=".static-stage-", dir=destination.parent)
            temporary = Path(temporary_name)
            try:
                with os.fdopen(descriptor, "wb") as stream:
                    stream.write(output.data)
                    stream.flush()
                    os.fsync(stream.fileno())
                if output.visibility == "private":
                    os.chmod(temporary, 0o600)
            except Exception:
                _safe_unlink(temporary)
                raise
            staged[destination] = temporary
        for destination in destinations:
            backup: Path | None = None
            if destination.exists():
                descriptor, backup_name = tempfile.mkstemp(prefix=".static-backup-", dir=destination.parent)
                os.close(descriptor)
                backup = Path(backup_name)
                backup.unlink()
                os.replace(destination, backup)
            backups[destination] = backup
            try:
                os.replace(staged[destination], destination)
            except Exception:
                if backup is not None and backup.exists():
                    os.replace(backup, destination)
                    backups[destination] = None
                raise
            replaced.append(destination)
        for backup in backups.values():
            if backup is not None:
                _safe_unlink(backup)
    except Exception as exc:
        rollback_errors: list[str] = []
        for destination in reversed(replaced):
            backup = backups.get(destination)
            try:
                _safe_unlink(destination)
                if backup is not None and backup.exists():
                    os.replace(backup, destination)
                    backups[destination] = None
            except Exception as rollback_exc:
                if backup is not None:
                    preserved_backups.add(backup)
                rollback_errors.append(type(rollback_exc).__name__)
        for destination, backup in backups.items():
            if destination not in replaced and backup is not None and backup.exists():
                try:
                    os.replace(backup, destination)
                    backups[destination] = None
                except Exception as rollback_exc:
                    preserved_backups.add(backup)
                    rollback_errors.append(type(rollback_exc).__name__)
        suffix = f"; rollback_errors={rollback_errors}" if rollback_errors else ""
        raise PublicationError(f"成果物の原子的公開に失敗しました: {type(exc).__name__}{suffix}") from exc
    finally:
        for temporary in staged.values():
            _safe_unlink(temporary)
        for backup in backups.values():
            if backup is not None and backup not in preserved_backups:
                _safe_unlink(backup)
    return tuple(
        PublishedArtifact(
            role=output.role,
            sha256=hashlib.sha256(output.data).hexdigest(),
            size=len(output.data),
            visibility=output.visibility,
        )
        for output in outputs
    )


@dataclass(frozen=True)
class StageDefinition:
    """コード側で固定する静的stage定義。manifestから生成してはならない。"""

    stage_id: str
    handler_id: str
    dependencies: tuple[str, ...] = ()
    required: bool = True

    def __post_init__(self) -> None:
        for label, value in (("stage_id", self.stage_id), ("handler_id", self.handler_id)):
            if not isinstance(value, str) or not _IDENTIFIER_PATTERN.fullmatch(value):
                raise ValueError(f"{label}は安全な識別子で指定してください")
        if not isinstance(self.dependencies, tuple) or not all(
            isinstance(value, str) and _IDENTIFIER_PATTERN.fullmatch(value) for value in self.dependencies
        ):
            raise ValueError("dependenciesは安全なstage IDのtupleで指定してください")
        if len(set(self.dependencies)) != len(self.dependencies) or self.stage_id in self.dependencies:
            raise ValueError("dependenciesに重複または自己参照があります")
        if not isinstance(self.required, bool):
            raise TypeError("requiredはboolで指定してください")


@dataclass(frozen=True)
class StageOutcome:
    """handlerの成功結果。valuesは後続stage専用でpublic reportへ含めない。"""

    public_report: Mapping[str, Any] = field(default_factory=dict)
    values: Mapping[str, Any] = field(default_factory=dict, repr=False)
    partial: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.public_report, Mapping) or not _is_json_value(_thaw_json(self.public_report)):
            raise TypeError("public_reportはbytesを含まないJSON-safe mappingが必要です")
        if not isinstance(self.values, Mapping):
            raise TypeError("valuesはmappingで指定してください")
        if not isinstance(self.partial, bool):
            raise TypeError("partialはboolで指定してください")


@dataclass(frozen=True)
class StageResult:
    """stage状態。private valuesはpublic()へ含めない。"""

    stage_id: str
    handler_id: str
    status: str
    public_report: Mapping[str, Any] = field(default_factory=dict)
    values: Mapping[str, Any] = field(default_factory=dict, repr=False)
    error_type: str | None = None
    blocked_by: tuple[str, ...] = ()

    def public(self) -> dict[str, Any]:
        """raw bytesや例外messageを除外した公開用stage結果を返す。"""

        result: dict[str, Any] = {
            "stage_id": self.stage_id,
            "handler_id": self.handler_id,
            "status": self.status,
            "report": _thaw_json(self.public_report),
        }
        if self.error_type is not None:
            result["error_type"] = self.error_type
        if self.blocked_by:
            result["blocked_by"] = list(self.blocked_by)
        return result


@dataclass(frozen=True)
class StagePipelineResult:
    """静的DAG実行の結果と安全性フラグ。"""

    stages: tuple[StageResult, ...]
    execution_order: tuple[str, ...]

    @property
    def status(self) -> str:
        """required失敗をfailed、部分成功をpartial、それ以外をsucceededとする。"""

        if any(stage.status == "failed" for stage in self.stages):
            return "failed"
        if any(stage.status in {"partial", "blocked"} for stage in self.stages):
            return "partial"
        return "succeeded"

    def public(self) -> dict[str, Any]:
        """sample非実行・network未接続を明示した公開レポートを返す。"""

        return {
            "schema_version": 1,
            "status": self.status,
            "execution_order": list(self.execution_order),
            "stages": [stage.public() for stage in self.stages],
            "safety": {
                "executed_sample": False,
                "network_contacted": False,
                "manifest_selected_callable": False,
                "raw_bytes_in_report": False,
            },
        }


StageHandler = Callable[[StageDefinition, Mapping[str, StageResult]], StageOutcome]


def _topological_order(stages: Sequence[StageDefinition]) -> tuple[StageDefinition, ...]:
    by_id: dict[str, StageDefinition] = {}
    for stage in stages:
        if stage.stage_id in by_id:
            raise StageGraphError(f"stage IDが重複しています: {stage.stage_id}")
        by_id[stage.stage_id] = stage
    if not by_id:
        raise StageGraphError("少なくとも1件のstageが必要です")
    for stage in stages:
        missing = sorted(set(stage.dependencies) - set(by_id))
        if missing:
            raise StageGraphError(f"stage dependencyが欠損しています: {stage.stage_id} -> {missing}")
    pending = {stage.stage_id: set(stage.dependencies) for stage in stages}
    ordered: list[StageDefinition] = []
    while pending:
        ready = sorted(stage_id for stage_id, dependencies in pending.items() if not dependencies)
        if not ready:
            raise StageGraphError("stage dependencyにcycleがあります")
        for stage_id in ready:
            ordered.append(by_id[stage_id])
            del pending[stage_id]
        ready_set = set(ready)
        for dependencies in pending.values():
            dependencies.difference_update(ready_set)
    return tuple(ordered)


def run_stage_dag(
    stages: Sequence[StageDefinition],
    handlers: Mapping[str, StageHandler],
) -> StagePipelineResult:
    """呼出側がallowlistしたPython callableだけで静的stage DAGを実行する。"""

    order = _topological_order(stages)
    expected_handlers = {stage.handler_id for stage in order}
    unknown_handlers = expected_handlers - set(handlers)
    if unknown_handlers:
        raise StageGraphError(f"stage handlerが欠損しています: {sorted(unknown_handlers)}")
    if any(not callable(handlers[handler_id]) for handler_id in expected_handlers):
        raise StageGraphError("stage handlerはPython callableである必要があります")
    results: dict[str, StageResult] = {}
    for stage in order:
        dependencies = {stage_id: results[stage_id] for stage_id in stage.dependencies}
        blocked_by = tuple(
            stage_id
            for stage_id, result in dependencies.items()
            if result.status in {"failed", "blocked"} or (result.status == "partial" and stage.required)
        )
        if blocked_by:
            result = StageResult(
                stage_id=stage.stage_id,
                handler_id=stage.handler_id,
                status="blocked",
                blocked_by=blocked_by,
            )
        else:
            try:
                outcome = handlers[stage.handler_id](stage, MappingProxyType(dependencies))
                if not isinstance(outcome, StageOutcome):
                    raise TypeError("stage handlerはStageOutcomeを返す必要があります")
                result = StageResult(
                    stage_id=stage.stage_id,
                    handler_id=stage.handler_id,
                    status="partial" if outcome.partial else "succeeded",
                    public_report=_freeze_json(_thaw_json(outcome.public_report)),
                    values=MappingProxyType(dict(outcome.values)),
                )
            except Exception as exc:
                result = StageResult(
                    stage_id=stage.stage_id,
                    handler_id=stage.handler_id,
                    status="failed",
                    error_type=type(exc).__name__,
                )
        results[stage.stage_id] = result
    ordered_results = tuple(results[stage.stage_id] for stage in order)
    return StagePipelineResult(
        stages=ordered_results,
        execution_order=tuple(stage.stage_id for stage in order),
    )




