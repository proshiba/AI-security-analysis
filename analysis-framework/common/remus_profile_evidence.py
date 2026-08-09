#!/usr/bin/env python3
"""Remusの能動C2 profileをfield単位のreview済みJSON証拠へ結合する。

証拠はrepository内の通常fileだけを扱い、検体の実行や外部通信は行わない。
profile生成時、監視計画への適用時、実probe直前で同じvalidatorを再利用する。
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import stat
from collections.abc import Mapping, Sequence
from pathlib import Path, PurePosixPath
from typing import Any

from safe_private_output import reject_existing_reparse_components

MAXIMUM_EVIDENCE_BYTES = 64 * 1024
MAXIMUM_FLOW_ARTIFACT_BYTES = 256 * 1024
MAXIMUM_REVIEW_REGISTRY_BYTES = 64 * 1024
MANIFEST_TYPE = "remus_active_profile_evidence"
FLOW_ARTIFACT_TYPE = "remus_active_profile_flow_artifact"
REVIEW_REGISTRY_TYPE = "remus_active_profile_review_registry"
REVIEW_REGISTRY_SOURCE = "analysis-framework/common/remus_active_profile_review_registry.json"
SHA256_RE = re.compile(r"[0-9a-f]{64}")
TAG_RE = re.compile(r"[0-9a-f]{32}")
REVIEW_ID_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,127}")
FIELD_NAMES = (
    "parent_sha256",
    "dump_sha256",
    "recovered_pe_sha256",
    "tag",
    "exp",
    "http_host",
    "pinned_ip",
    "endpoint",
)
FLOW_FIELD_NAMES = frozenset({"tag", "exp", "http_host", "pinned_ip", "endpoint"})
EVIDENCE_POINTERS = {name: f"/fields/{name}/value" for name in FIELD_NAMES}
FLOW_ARTIFACT_POINTERS = {
    "sample_sha256": "/sample/sha256",
    "run_id": "/run/id",
    "dump_sha256": "/artifacts/process_dump/sha256",
    "recovered_pe_sha256": "/artifacts/recovered_pe/sha256",
    "tag": "/flow/tag",
    "exp": "/flow/exp",
    "http_host": "/flow/http_host",
    "pinned_ip": "/flow/pinned_ip",
    "endpoint": "/flow/endpoint",
}


class RemusEvidenceError(ValueError):
    """Remus profileとreview済み証拠の結合条件が成立しない場合のエラー。"""


def canonical_lf_json_sha256(raw: bytes, *, label: str = "text JSON") -> str:
    """UTF-8 JSON textのCRLF/LF差だけを正規化してSHA-256を返す。"""

    if type(raw) is not bytes:
        raise RemusEvidenceError(f"{label} must be bytes")
    try:
        decoded = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise RemusEvidenceError(f"{label} must be strict UTF-8") from exc
    canonical = decoded.replace("\r\n", "\n")
    if "\r" in canonical:
        raise RemusEvidenceError(f"{label} contains an unsupported lone CR")
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def default_repository_root() -> Path:
    """このmoduleが属するrepository rootを返す。"""

    return Path(__file__).resolve().parents[2]


def _required_object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise RemusEvidenceError(f"{label}はobjectである必要があります")
    return value


def _exact_keys(value: Mapping[str, Any], expected: set[str], label: str) -> None:
    observed = set(value)
    if observed != expected:
        raise RemusEvidenceError(
            f"{label}のfieldがcanonical schemaと一致しません: "
            f"不足={sorted(expected - observed)} 余分={sorted(observed - expected)}"
        )


def _normalise_sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value.casefold()) is None:
        raise RemusEvidenceError(f"{label}は64桁hex SHA-256である必要があります")
    return value.casefold()


def _normalise_source_path(value: Any) -> tuple[str, Path]:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or "\\" in value
        or ":" in value
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
    ):
        raise RemusEvidenceError("evidence sourceは安全なrepository相対pathで指定してください")
    pure = PurePosixPath(value)
    if pure.is_absolute() or any(part in {"", ".", ".."} for part in pure.parts):
        raise RemusEvidenceError("evidence sourceにabsolute/traversal pathは指定できません")
    if any(not part or len(part) > 255 for part in pure.parts):
        raise RemusEvidenceError("evidence sourceのpath componentが不正です")
    return pure.as_posix(), Path(*pure.parts)


def _path_key(value: Path) -> str:
    return os.path.normcase(os.path.normpath(os.path.abspath(os.fspath(value))))


def _path_within(root: Path, candidate: Path) -> bool:
    try:
        return os.path.commonpath([_path_key(root), _path_key(candidate)]) == _path_key(root)
    except ValueError:
        return False


def _is_reparse(metadata: os.stat_result) -> bool:
    return bool(getattr(metadata, "st_file_attributes", 0) & 0x400)


def _forbidden_identity(candidate: Path, metadata: os.stat_result, forbidden: Sequence[Path]) -> bool:
    for value in forbidden:
        absolute = Path(os.path.abspath(os.fspath(value)))
        if _path_key(candidate) == _path_key(absolute):
            return True
        try:
            other = absolute.stat(follow_symlinks=False)
        except (FileNotFoundError, OSError):
            continue
        if os.path.samestat(metadata, other):
            return True
    return False


def _read_bounded_json(
    repository_root: Path,
    relative_path: Path,
    *,
    forbidden_paths: Sequence[Path] = (),
    maximum_bytes: int = MAXIMUM_EVIDENCE_BYTES,
    label: str = "evidence JSON",
) -> tuple[dict[str, Any], bytes, Path]:
    """identityと指定byte上限を維持してstrict UTF-8 JSONを読む。"""

    if maximum_bytes <= 0:
        raise RemusEvidenceError(f"{label} byte limit is invalid")
    root = Path(os.path.abspath(os.fspath(repository_root)))
    candidate = root / relative_path
    if not _path_within(root, candidate):
        raise RemusEvidenceError("証拠JSONがrepository root外です")
    try:
        reject_existing_reparse_components(root)
        reject_existing_reparse_components(candidate)
        root_metadata = root.stat(follow_symlinks=False)
        initial = candidate.stat(follow_symlinks=False)
    except (OSError, ValueError) as exc:
        raise RemusEvidenceError("証拠JSONを安全に解決できません") from exc
    if not stat.S_ISDIR(root_metadata.st_mode) or _is_reparse(root_metadata):
        raise RemusEvidenceError("repository rootは通常directoryである必要があります")
    if not stat.S_ISREG(initial.st_mode) or _is_reparse(initial):
        raise RemusEvidenceError("証拠JSONはreparseでない通常fileである必要があります")
    if initial.st_nlink != 1:
        raise RemusEvidenceError("証拠JSONは単一linkの通常fileである必要があります")
    if initial.st_size <= 0:
        raise RemusEvidenceError("証拠JSONは空fileにできません")
    if initial.st_size > maximum_bytes:
        raise RemusEvidenceError(f"{label}が{maximum_bytes} byte上限を超えています")
    if _forbidden_identity(candidate, initial, forbidden_paths):
        raise RemusEvidenceError("証拠JSONはprofile入力・出力自身を参照できません")

    chunks: list[bytes] = []
    total = 0
    try:
        with candidate.open("rb") as stream:
            opened = os.fstat(stream.fileno())
            if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1 or not os.path.samestat(initial, opened):
                raise RemusEvidenceError("証拠JSONが読み取り開始前に置換されました")
            while True:
                chunk = stream.read(min(16 * 1024, maximum_bytes - total + 1))
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
                if total > maximum_bytes:
                    raise RemusEvidenceError(f"{label}が{maximum_bytes} byte上限を超えています")
            opened_after = os.fstat(stream.fileno())
    except RemusEvidenceError:
        raise
    except OSError as exc:
        raise RemusEvidenceError("証拠JSONを読み取れません") from exc

    try:
        reject_existing_reparse_components(candidate)
        final = candidate.stat(follow_symlinks=False)
        resolved_root = root.resolve(strict=True)
        resolved_candidate = candidate.resolve(strict=True)
    except (OSError, RuntimeError, ValueError) as exc:
        raise RemusEvidenceError("証拠JSONの読み取り後検証に失敗しました") from exc
    if (
        any(item.st_nlink != 1 for item in (initial, opened, opened_after, final))
        or any(not stat.S_ISREG(item.st_mode) for item in (initial, opened, opened_after, final))
        or any(_is_reparse(item) for item in (initial, opened, opened_after, final))
        or any(not os.path.samestat(initial, item) for item in (opened, opened_after, final))
        or any(item.st_size != initial.st_size for item in (opened, opened_after, final))
    ):
        raise RemusEvidenceError("証拠JSONが読み取り中に置換またはlink化されました")
    if not _path_within(resolved_root, resolved_candidate):
        raise RemusEvidenceError("証拠JSONがrepository root外へ解決されました")
    if _forbidden_identity(candidate, final, forbidden_paths):
        raise RemusEvidenceError("証拠JSONはprofile入力・出力自身を参照できません")

    raw = b"".join(chunks)
    if len(raw) != initial.st_size:
        raise RemusEvidenceError("証拠JSONのsizeが読み取り中に変化しました")
    try:
        decoded = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise RemusEvidenceError("証拠JSONはstrict UTF-8である必要があります") from exc

    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise RemusEvidenceError(f"証拠JSONに重複keyがあります: {key}")
            value[key] = item
        return value

    try:
        payload = json.loads(
            decoded,
            object_pairs_hook=unique_object,
            parse_constant=lambda value: (_ for _ in ()).throw(
                RemusEvidenceError(f"証拠JSONに非標準数値があります: {value}")
            ),
        )
    except RemusEvidenceError:
        raise
    except json.JSONDecodeError as exc:
        raise RemusEvidenceError("証拠JSONは有効なJSONである必要があります") from exc
    return _required_object(payload, "証拠JSON root"), raw, resolved_candidate


def _resolve_pointer(payload: Any, pointer: str) -> Any:
    if not isinstance(pointer, str) or not pointer.startswith("/"):
        raise RemusEvidenceError("evidence JSON pointerが不正です")
    current = payload
    for raw_token in pointer.split("/")[1:]:
        if re.search(r"~(?![01])", raw_token):
            raise RemusEvidenceError("evidence JSON pointerのescapeが不正です")
        token = raw_token.replace("~1", "/").replace("~0", "~")
        if not isinstance(current, Mapping) or token not in current:
            raise RemusEvidenceError(f"evidence JSON pointerを解決できません: {pointer}")
        current = current[token]
    return current


def _normalise_review_id(value: Any) -> str:
    if not isinstance(value, str) or REVIEW_ID_RE.fullmatch(value) is None:
        raise RemusEvidenceError("review_id is invalid")
    return value


def build_evidence_binding(source: Any, sha256: Any, review_id: Any = "unregistered") -> dict[str, Any]:
    """canonical pointerを固定したprofile用bindingを返す。"""

    normalized_source, _ = _normalise_source_path(source)
    normalized_sha256 = _normalise_sha256(sha256, "evidence sha256")
    return {
        "manifest_type": MANIFEST_TYPE,
        "review_id": _normalise_review_id(review_id),
        "source": normalized_source,
        "sha256": normalized_sha256,
        "pointers": dict(EVIDENCE_POINTERS),
    }


def _normalise_binding(value: Any) -> dict[str, Any]:
    binding = _required_object(value, "evidence_binding")
    _exact_keys(
        binding,
        {"manifest_type", "review_id", "source", "sha256", "pointers"},
        "evidence_binding",
    )
    if binding.get("manifest_type") != MANIFEST_TYPE:
        raise RemusEvidenceError("evidence_binding.manifest_typeが不正です")
    review_id = _normalise_review_id(binding.get("review_id"))
    source, _ = _normalise_source_path(binding.get("source"))
    sha256 = _normalise_sha256(binding.get("sha256"), "evidence_binding.sha256")
    pointers = _required_object(binding.get("pointers"), "evidence_binding.pointers")
    if pointers != EVIDENCE_POINTERS:
        raise RemusEvidenceError("evidence_bindingのJSON pointer集合がcanonical値と一致しません")
    return {
        "manifest_type": MANIFEST_TYPE,
        "review_id": review_id,
        "source": source,
        "sha256": sha256,
        "pointers": dict(EVIDENCE_POINTERS),
    }


def _normalise_run_id(value: Any) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= 128
        or value != value.strip()
        or any(ord(character) < 0x21 or ord(character) > 0x7E for character in value)
    ):
        raise RemusEvidenceError("run_id is invalid")
    return value


def load_remus_review_registry(
    *,
    repository_root: Path | None = None,
    forbidden_paths: Sequence[Path] = (),
) -> dict[str, Any]:
    root = Path(repository_root or default_repository_root())
    source, relative = _normalise_source_path(REVIEW_REGISTRY_SOURCE)
    payload, raw, absolute = _read_bounded_json(
        root,
        relative,
        forbidden_paths=forbidden_paths,
        maximum_bytes=MAXIMUM_REVIEW_REGISTRY_BYTES,
        label="Remus review registry",
    )
    _exact_keys(
        payload,
        {"schema_version", "registry_type", "reviews"},
        "review registry",
    )
    if payload.get("schema_version") != 1 or payload.get("registry_type") != REVIEW_REGISTRY_TYPE:
        raise RemusEvidenceError("Remus review registry schema is invalid")
    values = payload.get("reviews")
    if not isinstance(values, list) or len(values) > 256:
        raise RemusEvidenceError("Remus review registry reviews is invalid")

    reviews: dict[str, dict[str, Any]] = {}
    expected_keys = {
        "review_id",
        "status",
        "manifest_source",
        "manifest_sha256",
        "flow_artifact_source",
        "flow_artifact_sha256",
        "flow_artifact_pointers",
        "sample_sha256",
        "run_id",
        "dump_sha256",
        "recovered_pe_sha256",
    }
    for index, raw_review in enumerate(values):
        review = _required_object(raw_review, f"reviews[{index}]")
        _exact_keys(review, expected_keys, f"reviews[{index}]")
        review_id = _normalise_review_id(review.get("review_id"))
        if review_id in reviews:
            raise RemusEvidenceError("Remus review registry has duplicate review_id")
        if review.get("status") != "approved":
            raise RemusEvidenceError("Remus review registry contains non-approved entry")
        manifest_source, _ = _normalise_source_path(review.get("manifest_source"))
        flow_source, _ = _normalise_source_path(review.get("flow_artifact_source"))
        if len({source, manifest_source, flow_source}) != 3:
            raise RemusEvidenceError("Remus review registry contains self/circular source")
        pointers = _required_object(
            review.get("flow_artifact_pointers"),
            f"reviews[{index}].flow_artifact_pointers",
        )
        if pointers != FLOW_ARTIFACT_POINTERS:
            raise RemusEvidenceError("Remus flow artifact pointers are not canonical")
        reviews[review_id] = {
            "review_id": review_id,
            "status": "approved",
            "manifest_source": manifest_source,
            "manifest_sha256": _normalise_sha256(
                review.get("manifest_sha256"),
                f"reviews[{index}].manifest_sha256",
            ),
            "flow_artifact_source": flow_source,
            "flow_artifact_sha256": _normalise_sha256(
                review.get("flow_artifact_sha256"),
                f"reviews[{index}].flow_artifact_sha256",
            ),
            "flow_artifact_pointers": dict(FLOW_ARTIFACT_POINTERS),
            "sample_sha256": _normalise_sha256(
                review.get("sample_sha256"),
                f"reviews[{index}].sample_sha256",
            ),
            "run_id": _normalise_run_id(review.get("run_id")),
            "dump_sha256": _normalise_sha256(
                review.get("dump_sha256"),
                f"reviews[{index}].dump_sha256",
            ),
            "recovered_pe_sha256": _normalise_sha256(
                review.get("recovered_pe_sha256"),
                f"reviews[{index}].recovered_pe_sha256",
            ),
        }
    return {
        "source": source,
        "sha256": canonical_lf_json_sha256(raw, label="Remus review registry"),
        "reviews": reviews,
        "_resolved_path": absolute,
    }


def resolve_remus_review_trust(
    binding_value: Any,
    *,
    repository_root: Path | None = None,
    forbidden_paths: Sequence[Path] = (),
) -> dict[str, Any]:
    binding = _normalise_binding(binding_value)
    registry = load_remus_review_registry(
        repository_root=repository_root,
        forbidden_paths=forbidden_paths,
    )
    review = registry["reviews"].get(binding["review_id"])
    if review is None:
        raise RemusEvidenceError("review_id is not allowlisted")
    if review["manifest_source"] != binding["source"] or review["manifest_sha256"] != binding["sha256"]:
        raise RemusEvidenceError("manifest binding is not allowlisted by review registry")
    return {
        "binding": binding,
        "review": review,
        "registry_source": registry["source"],
        "registry_sha256": registry["sha256"],
        "_registry_path": registry["_resolved_path"],
    }


def _validate_flow_artifact(
    payload: Mapping[str, Any],
    *,
    review: Mapping[str, Any],
    profile_values: Mapping[str, Any],
) -> None:
    _exact_keys(
        payload,
        {"schema_version", "artifact_type", "sample", "run", "artifacts", "flow"},
        "flow artifact",
    )
    if payload.get("schema_version") != 1 or payload.get("artifact_type") != FLOW_ARTIFACT_TYPE:
        raise RemusEvidenceError("flow artifact schema is invalid")
    sample = _required_object(payload.get("sample"), "flow artifact sample")
    run = _required_object(payload.get("run"), "flow artifact run")
    artifacts = _required_object(payload.get("artifacts"), "flow artifact artifacts")
    process_dump = _required_object(
        artifacts.get("process_dump"),
        "flow artifact process_dump",
    )
    recovered_pe = _required_object(
        artifacts.get("recovered_pe"),
        "flow artifact recovered_pe",
    )
    flow = _required_object(payload.get("flow"), "flow artifact flow")
    _exact_keys(sample, {"sha256"}, "flow artifact sample")
    _exact_keys(run, {"id"}, "flow artifact run")
    _exact_keys(
        artifacts,
        {"process_dump", "recovered_pe"},
        "flow artifact artifacts",
    )
    _exact_keys(process_dump, {"sha256"}, "flow artifact process_dump")
    _exact_keys(recovered_pe, {"sha256"}, "flow artifact recovered_pe")
    _exact_keys(
        flow,
        {"tag", "exp", "http_host", "pinned_ip", "endpoint"},
        "flow artifact flow",
    )
    expected = {
        "sample_sha256": review["sample_sha256"],
        "run_id": review["run_id"],
        "dump_sha256": review["dump_sha256"],
        "recovered_pe_sha256": review["recovered_pe_sha256"],
        "tag": profile_values["tag"],
        "exp": profile_values["exp"],
        "http_host": profile_values["http_host"],
        "pinned_ip": profile_values["pinned_ip"],
        "endpoint": profile_values["endpoint"],
    }
    for name, expected_value in expected.items():
        observed = _resolve_pointer(payload, FLOW_ARTIFACT_POINTERS[name])
        if isinstance(expected_value, str) and name.endswith("sha256"):
            observed = _normalise_sha256(observed, f"flow artifact {name}")
        elif name == "run_id":
            observed = _normalise_run_id(observed)
        if observed != expected_value:
            raise RemusEvidenceError(f"flow artifact {name} identity/value mismatch")


def _profile_samples(profile: Mapping[str, Any]) -> str:
    samples = profile.get("sample_sha256s")
    if not isinstance(samples, list) or len(samples) != 1:
        raise RemusEvidenceError("Remus profileには親検体SHA-256が1件必要です")
    return _normalise_sha256(samples[0], "sample_sha256s[0]")


def _canonical_endpoint(profile: Mapping[str, Any]) -> dict[str, Any]:
    host = profile.get("host")
    port = profile.get("port")
    slot_index = profile.get("selected_slot_index")
    if (
        not isinstance(host, str)
        or not host
        or isinstance(port, bool)
        or not isinstance(port, int)
        or not 1 <= port <= 65535
        or isinstance(slot_index, bool)
        or not isinstance(slot_index, int)
        or not 0 <= slot_index <= 255
    ):
        raise RemusEvidenceError("Remus profileの選択endpointが不正です")
    rendered_host = f"[{host}]" if ":" in host else host
    return {
        "slot_index": slot_index,
        "uri": f"http://{rendered_host}:{port}",
        "scheme": "http",
        "host": host,
        "port": port,
    }


def validate_remus_profile_evidence(
    profile: Mapping[str, Any],
    *,
    repository_root: Path | None = None,
    expected_sha256: str | None = None,
    expected_registry_sha256: str | None = None,
    expected_flow_artifact_sha256: str | None = None,
    forbidden_paths: Sequence[Path] = (),
) -> dict[str, Any]:
    """能動Remus profileとfield-level manifestを完全一致で再検証する。"""

    if not isinstance(profile, Mapping):
        raise RemusEvidenceError("profileはobjectである必要があります")
    if (
        profile.get("family") != "remusstealer"
        or profile.get("protocol") != "remusstealer"
        or profile.get("method") != "remus_registration_task"
        or profile.get("handler") != "remus_registration_task"
        or profile.get("http_path") != "/"
        or type(profile.get("request_budget")) is not int
        or profile.get("request_budget") != 2
        or type(profile.get("timeout_seconds")) is not float
        or profile.get("timeout_seconds") != 3.0
        or type(profile.get("maximum_request_bytes")) is not int
        or profile.get("maximum_request_bytes") != 4096
        or type(profile.get("maximum_response_bytes")) is not int
        or profile.get("maximum_response_bytes") != 8192
    ):
        raise RemusEvidenceError("Remus profileのfamily/protocol/安全境界が不正です")

    parent_sha256 = _profile_samples(profile)
    dump_sha256 = _normalise_sha256(profile.get("dump_sha256"), "dump_sha256")
    recovered_sha256 = _normalise_sha256(profile.get("recovered_pe_sha256"), "recovered_pe_sha256")
    tag = profile.get("tag")
    exp = profile.get("exp")
    http_host = profile.get("http_host")
    pinned = profile.get("pinned_ips")
    if not isinstance(tag, str) or TAG_RE.fullmatch(tag.casefold()) is None:
        raise RemusEvidenceError("Remus profileのtagが不正です")
    if type(exp) is not int or not 946_684_800 <= exp <= 4_102_444_800:
        raise RemusEvidenceError("Remus profileのexpが不正です")
    if http_host != "microsoft.com":
        raise RemusEvidenceError("Remus profileのHTTP Hostがreview済みschemaと一致しません")
    if not isinstance(pinned, list) or len(pinned) != 1 or not isinstance(pinned[0], str):
        raise RemusEvidenceError("Remus profileには単一pinned IPが必要です")
    try:
        pinned_address = ipaddress.ip_address(pinned[0])
    except ValueError as exc:
        raise RemusEvidenceError("Remus pinned IP is invalid") from exc
    if not pinned_address.is_global or str(pinned_address) != pinned[0]:
        raise RemusEvidenceError("Remus pinned IP must be one canonical global IP")
    endpoint = _canonical_endpoint(profile)

    binding = _normalise_binding(profile.get("evidence_binding"))
    root = Path(repository_root or default_repository_root())
    trust = resolve_remus_review_trust(
        binding,
        repository_root=root,
        forbidden_paths=forbidden_paths,
    )
    review_record = trust["review"]
    if profile.get("review_id") != binding["review_id"]:
        raise RemusEvidenceError("profile review_id pin mismatch")
    if profile.get("review_registry_source") != trust["registry_source"]:
        raise RemusEvidenceError("profile review registry source pin mismatch")
    if profile.get("review_registry_sha256") != trust["registry_sha256"]:
        raise RemusEvidenceError("profile review registry digest pin mismatch")
    if profile.get("flow_artifact_source") != review_record["flow_artifact_source"]:
        raise RemusEvidenceError("profile flow artifact source pin mismatch")
    if profile.get("flow_artifact_sha256") != review_record["flow_artifact_sha256"]:
        raise RemusEvidenceError("profile flow artifact digest pin mismatch")
    if expected_registry_sha256 is not None:
        expected_registry = _normalise_sha256(
            expected_registry_sha256,
            "expected review registry sha256",
        )
        if expected_registry != trust["registry_sha256"]:
            raise RemusEvidenceError("plan review registry digest pin mismatch")
    if expected_flow_artifact_sha256 is not None:
        expected_flow = _normalise_sha256(
            expected_flow_artifact_sha256,
            "expected flow artifact sha256",
        )
        if expected_flow != review_record["flow_artifact_sha256"]:
            raise RemusEvidenceError("plan flow artifact digest pin mismatch")
    if (
        review_record["sample_sha256"] != parent_sha256
        or review_record["dump_sha256"] != dump_sha256
        or review_record["recovered_pe_sha256"] != recovered_sha256
    ):
        raise RemusEvidenceError("review registry sample/dump/recovered PE identity mismatch")
    if profile.get("evidence_source") != binding["source"]:
        raise RemusEvidenceError("profileのevidence sourceがbindingと一致しません")
    if profile.get("evidence_sha256") != binding["sha256"]:
        raise RemusEvidenceError("profileのevidence SHA-256がbindingと一致しません")
    expected_source_reference = f"{binding['source']}:{EVIDENCE_POINTERS['endpoint']}"
    if profile.get("source") != expected_source_reference:
        raise RemusEvidenceError("profile sourceがendpoint evidence pointerに固定されていません")
    if expected_sha256 is not None:
        expected = _normalise_sha256(expected_sha256, "expected evidence sha256")
        if expected != binding["sha256"]:
            raise RemusEvidenceError("計画時に固定したevidence SHA-256とprofileが一致しません")

    _, relative_path = _normalise_source_path(binding["source"])
    _, flow_relative_path = _normalise_source_path(review_record["flow_artifact_source"])
    manifest_candidate = root / relative_path
    flow_candidate = root / flow_relative_path
    registry_path = trust["_registry_path"]
    manifest, raw, absolute = _read_bounded_json(
        root,
        relative_path,
        forbidden_paths=tuple(forbidden_paths) + (registry_path, flow_candidate),
        maximum_bytes=MAXIMUM_EVIDENCE_BYTES,
        label="Remus field evidence manifest",
    )
    flow_artifact, flow_raw, flow_absolute = _read_bounded_json(
        root,
        flow_relative_path,
        forbidden_paths=tuple(forbidden_paths) + (registry_path, manifest_candidate),
        maximum_bytes=MAXIMUM_FLOW_ARTIFACT_BYTES,
        label="Remus flow artifact",
    )
    flow_artifact_digest = canonical_lf_json_sha256(flow_raw, label="Remus flow artifact")
    if flow_artifact_digest != review_record["flow_artifact_sha256"]:
        raise RemusEvidenceError("flow artifact SHA-256 pin mismatch")
    digest = canonical_lf_json_sha256(raw, label="Remus field evidence manifest")
    if digest != binding["sha256"]:
        raise RemusEvidenceError("証拠JSONのSHA-256 pinが一致しません")

    _exact_keys(manifest, {"schema_version", "manifest_type", "family", "review", "fields"}, "manifest")
    if (
        manifest.get("schema_version") != 1
        or manifest.get("manifest_type") != MANIFEST_TYPE
        or manifest.get("family") != "remusstealer"
    ):
        raise RemusEvidenceError("証拠JSONのschema/type/familyが不正です")
    review = _required_object(manifest.get("review"), "review")
    _exact_keys(
        review,
        {"status", "same_sample_verified", "same_flow_verified", "flow_evidence_sha256"},
        "review",
    )
    flow_sha256 = _normalise_sha256(review.get("flow_evidence_sha256"), "flow_evidence_sha256")
    if flow_sha256 != flow_artifact_digest:
        raise RemusEvidenceError("manifest flow digest is not the allowlisted flow artifact")
    if (
        review.get("status") != "reviewed"
        or review.get("same_sample_verified") is not True
        or review.get("same_flow_verified") is not True
    ):
        raise RemusEvidenceError("same-sample/same-flow reviewが完了していません")

    fields = _required_object(manifest.get("fields"), "fields")
    _exact_keys(fields, set(FIELD_NAMES), "fields")
    values: dict[str, Any] = {}
    for name in FIELD_NAMES:
        record = _required_object(fields.get(name), f"fields.{name}")
        _exact_keys(record, {"value", "sample_sha256", "flow_evidence_sha256"}, f"fields.{name}")
        record_sample = _normalise_sha256(record.get("sample_sha256"), f"fields.{name}.sample_sha256")
        if record_sample != parent_sha256:
            raise RemusEvidenceError(f"fields.{name}が別sampleへ結合されています")
        record_flow = record.get("flow_evidence_sha256")
        if name in FLOW_FIELD_NAMES:
            if _normalise_sha256(record_flow, f"fields.{name}.flow_evidence_sha256") != flow_sha256:
                raise RemusEvidenceError(f"fields.{name}が別flowへ結合されています")
        elif record_flow is not None:
            raise RemusEvidenceError(f"fields.{name}に不要なflow結合があります")
        pointer_value = _resolve_pointer(manifest, binding["pointers"][name])
        if pointer_value != record.get("value"):
            raise RemusEvidenceError(f"fields.{name}のJSON pointer値が一致しません")
        values[name] = pointer_value

    expected_values = {
        "parent_sha256": parent_sha256,
        "dump_sha256": dump_sha256,
        "recovered_pe_sha256": recovered_sha256,
        "tag": tag.casefold(),
        "exp": exp,
        "http_host": http_host,
        "pinned_ip": pinned[0],
        "endpoint": endpoint,
    }
    for name, expected_value in expected_values.items():
        observed = values[name]
        if isinstance(observed, str) and name in {
            "parent_sha256",
            "dump_sha256",
            "recovered_pe_sha256",
            "tag",
        }:
            observed = observed.casefold()
        if observed != expected_value:
            raise RemusEvidenceError(f"fields.{name}がprofile値と一致しません")
    _validate_flow_artifact(
        flow_artifact,
        review=review_record,
        profile_values=expected_values,
    )

    return {
        "manifest_type": MANIFEST_TYPE,
        "review_id": binding["review_id"],
        "review_registry_source": trust["registry_source"],
        "review_registry_sha256": trust["registry_sha256"],
        "flow_artifact_source": review_record["flow_artifact_source"],
        "flow_artifact_sha256": flow_artifact_digest,
        "flow_artifact_pointers": dict(FLOW_ARTIFACT_POINTERS),
        "run_id": review_record["run_id"],
        "source": binding["source"],
        "sha256": digest,
        "pointers": dict(EVIDENCE_POINTERS),
        "parent_sha256": parent_sha256,
        "dump_sha256": dump_sha256,
        "recovered_pe_sha256": recovered_sha256,
        "endpoint": f"{endpoint['host']}:{endpoint['port']}",
        "flow_evidence_sha256": flow_sha256,
        "resolved_path_published": False,
        "_resolved_path": absolute,
        "_flow_resolved_path": flow_absolute,
        "_registry_resolved_path": registry_path,
    }
