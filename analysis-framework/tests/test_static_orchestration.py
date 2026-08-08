"""静的復元オーケストレーション共通基盤のfail-closed回帰テスト。"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest

from common import static_orchestration as orchestration
from common.static_orchestration import (
    ArtifactRequirement,
    ManifestValidationError,
    OutputBytes,
    PublicationError,
    StageDefinition,
    StageGraphError,
    StageOutcome,
    load_artifact_bundle,
    pipeline_fingerprint,
    publish_bytes_atomically,
    run_stage_dag,
    validate_private_root,
)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _manifest_artifact(
    role: str,
    path: str,
    data: bytes,
    media_type: str,
    *,
    json_identity: dict[str, object] | None = None,
) -> dict[str, object]:
    result: dict[str, object] = {
        "role": role,
        "path": path,
        "sha256": _sha256(data),
        "size": len(data),
        "media_type": media_type,
    }
    if json_identity is not None:
        result["json_identity"] = json_identity
    return result


def _write_manifest(root: Path, artifacts: list[dict[str, object]], **extra: object) -> Path:
    document: dict[str, object] = {
        "schema_version": 1,
        "manifest_type": "static_analysis_private_bundle",
        "settings": {"entry_role": "submission", "allow_structural_reuse": False},
        "artifacts": artifacts,
    }
    document.update(extra)
    path = root / "bundle.json"
    path.write_text(json.dumps(document, ensure_ascii=False), encoding="utf-8")
    return path


def _requirements() -> tuple[ArtifactRequirement, ...]:
    return (
        ArtifactRequirement(
            "recovery_profile",
            "application/json",
            json_identity={"schema_version": 1, "profile_id": "fixture-profile"},
        ),
        ArtifactRequirement("protected_image", "application/octet-stream"),
    )


def _valid_bundle(private_root: Path) -> tuple[Path, bytes, bytes]:
    profile = json.dumps(
        {"schema_version": 1, "profile_id": "fixture-profile", "private_key": "kept-private"},
        separators=(",", ":"),
    ).encode()
    image = b"MZ\x00fixture-protected-image"
    (private_root / "profile.json").write_bytes(profile)
    (private_root / "protected.bin").write_bytes(image)
    manifest = _write_manifest(
        private_root,
        [
            _manifest_artifact(
                "recovery_profile",
                "profile.json",
                profile,
                "application/json",
                json_identity={"schema_version": 1, "profile_id": "fixture-profile"},
            ),
            _manifest_artifact("protected_image", "protected.bin", image, "application/octet-stream"),
        ],
    )
    return manifest, profile, image


def test_bundle_loads_roles_and_public_view_has_no_private_bytes(tmp_path: Path) -> None:
    manifest, profile, image = _valid_bundle(tmp_path)
    bundle = load_artifact_bundle(manifest, private_root=tmp_path, requirements=_requirements())
    assert bundle.require("recovery_profile").json_value["profile_id"] == "fixture-profile"
    assert bundle.require("protected_image").data == image
    serialized = json.dumps(bundle.public(), ensure_ascii=False)
    assert profile.decode() not in serialized
    assert image.decode(errors="ignore") not in serialized
    assert str(tmp_path) not in serialized


@pytest.mark.parametrize("field", ["sha256", "size"])
def test_bundle_rejects_hash_or_size_mismatch(tmp_path: Path, field: str) -> None:
    manifest, _, _ = _valid_bundle(tmp_path)
    document = json.loads(manifest.read_text(encoding="utf-8"))
    document["artifacts"][1][field] = "0" * 64 if field == "sha256" else 999
    manifest.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(ManifestValidationError):
        load_artifact_bundle(manifest, private_root=tmp_path, requirements=_requirements())


def test_bundle_rejects_role_swap_using_json_identity(tmp_path: Path) -> None:
    manifest, _, _ = _valid_bundle(tmp_path)
    second_profile = json.dumps(
        {"schema_version": 1, "profile_id": "different-profile"}, separators=(",", ":")
    ).encode()
    (tmp_path / "other.json").write_bytes(second_profile)
    document = json.loads(manifest.read_text(encoding="utf-8"))
    document["artifacts"][0] = _manifest_artifact(
        "recovery_profile",
        "other.json",
        second_profile,
        "application/json",
        json_identity={"schema_version": 1, "profile_id": "fixture-profile"},
    )
    manifest.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(ManifestValidationError, match="identity"):
        load_artifact_bundle(manifest, private_root=tmp_path, requirements=_requirements())


@pytest.mark.parametrize(
    "bad_path",
    [
        "../protected.bin",
        "sub/../../protected.bin",
        "/protected.bin",
        r"C:\protected.bin",
        r"\\server\share\protected.bin",
        "protected.bin:stream",
    ],
)
def test_bundle_rejects_path_escape_unc_drive_and_ads(tmp_path: Path, bad_path: str) -> None:
    manifest, _, _ = _valid_bundle(tmp_path)
    document = json.loads(manifest.read_text(encoding="utf-8"))
    document["artifacts"][1]["path"] = bad_path
    manifest.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(ManifestValidationError):
        load_artifact_bundle(manifest, private_root=tmp_path, requirements=_requirements())


def test_bundle_rejects_unknown_duplicate_and_missing_roles(tmp_path: Path) -> None:
    manifest, _, _ = _valid_bundle(tmp_path)
    original = json.loads(manifest.read_text(encoding="utf-8"))
    for artifacts in (
        original["artifacts"] + [dict(original["artifacts"][0], role="unknown_role")],
        original["artifacts"] + [dict(original["artifacts"][0])],
        original["artifacts"][:1],
    ):
        manifest.write_text(json.dumps({**original, "artifacts": artifacts}), encoding="utf-8")
        with pytest.raises(ManifestValidationError):
            load_artifact_bundle(manifest, private_root=tmp_path, requirements=_requirements())


def test_bundle_rejects_manifest_execution_settings_and_unknown_keys(tmp_path: Path) -> None:
    manifest, _, _ = _valid_bundle(tmp_path)
    document = json.loads(manifest.read_text(encoding="utf-8"))
    document["settings"]["command"] = "malware.exe"
    manifest.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(ManifestValidationError, match="settings"):
        load_artifact_bundle(manifest, private_root=tmp_path, requirements=_requirements())
    document["settings"].pop("command")
    document["unexpected"] = True
    manifest.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(ManifestValidationError, match="unknown"):
        load_artifact_bundle(manifest, private_root=tmp_path, requirements=_requirements())


def test_bundle_rejects_symlink_artifact_when_supported(tmp_path: Path) -> None:
    target = tmp_path / "target.bin"
    target.write_bytes(b"target")
    link = tmp_path / "linked.bin"
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("この環境ではsymlinkを作成できません")
    profile = json.dumps({"schema_version": 1, "profile_id": "fixture-profile"}).encode()
    (tmp_path / "profile.json").write_bytes(profile)
    manifest = _write_manifest(
        tmp_path,
        [
            _manifest_artifact(
                "recovery_profile",
                "profile.json",
                profile,
                "application/json",
                json_identity={"schema_version": 1, "profile_id": "fixture-profile"},
            ),
            _manifest_artifact("protected_image", "linked.bin", b"target", "application/octet-stream"),
        ],
    )
    with pytest.raises(ManifestValidationError, match="symlink|reparse"):
        load_artifact_bundle(manifest, private_root=tmp_path, requirements=_requirements())


def test_validate_private_root_requires_repository_separation(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    private = tmp_path / "private"
    repository.mkdir()
    private.mkdir()
    assert validate_private_root(private, repository_root=repository) == private.resolve()
    nested = repository / "private"
    nested.mkdir()
    with pytest.raises(orchestration.StaticOrchestrationError):
        validate_private_root(nested, repository_root=repository)


def _publication_roots(tmp_path: Path) -> tuple[Path, Path]:
    public = tmp_path / "repository"
    private = tmp_path / "private"
    public.mkdir()
    private.mkdir()
    return public, private


def test_atomic_publish_replaces_public_and_private_outputs(tmp_path: Path) -> None:
    public, private = _publication_roots(tmp_path)
    public_file = public / "report.json"
    private_file = private / "payload.bin"
    public_file.write_bytes(b"old-public")
    private_file.write_bytes(b"old-private")
    published = publish_bytes_atomically(
        (
            OutputBytes("report", public_file, b"new-public", "public"),
            OutputBytes("payload", private_file, b"new-private", "private"),
        ),
        public_root=public,
        private_root=private,
    )
    assert public_file.read_bytes() == b"new-public"
    assert private_file.read_bytes() == b"new-private"
    assert [item.role for item in published] == ["report", "payload"]
    assert "new-private" not in repr(published)


@pytest.mark.parametrize("failure_call", [1, 2, 3, 4])
def test_atomic_publish_rolls_back_at_each_replace_position(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure_call: int
) -> None:
    public, private = _publication_roots(tmp_path)
    first = public / "first.json"
    second = private / "second.bin"
    first.write_bytes(b"first-old")
    second.write_bytes(b"second-old")
    original_replace = orchestration.os.replace
    counter = 0

    def fail_once(source: str | os.PathLike[str], destination: str | os.PathLike[str]) -> None:
        nonlocal counter
        counter += 1
        if counter == failure_call:
            raise OSError("injected replace failure")
        original_replace(source, destination)

    monkeypatch.setattr(orchestration.os, "replace", fail_once)
    with pytest.raises(PublicationError):
        publish_bytes_atomically(
            (
                OutputBytes("first", first, b"first-new", "public"),
                OutputBytes("second", second, b"second-new", "private"),
            ),
            public_root=public,
            private_root=private,
        )
    assert first.read_bytes() == b"first-old"
    assert second.read_bytes() == b"second-old"


def test_atomic_publish_rejects_input_alias_hardlink_and_symlink_output(tmp_path: Path) -> None:
    public, private = _publication_roots(tmp_path)
    source = private / "source.bin"
    source.write_bytes(b"source")
    with pytest.raises(PublicationError, match="input"):
        publish_bytes_atomically(
            (OutputBytes("same", source, b"new", "private"),),
            input_paths=(source,),
            public_root=public,
            private_root=private,
        )
    hardlink = private / "hardlink.bin"
    try:
        os.link(source, hardlink)
    except OSError:
        pytest.skip("この環境ではhardlinkを作成できません")
    with pytest.raises(PublicationError, match="hardlink"):
        publish_bytes_atomically(
            (OutputBytes("hardlink", hardlink, b"new", "private"),),
            input_paths=(source,),
            public_root=public,
            private_root=private,
        )
    symlink = private / "symlink.bin"
    try:
        symlink.symlink_to(source)
    except OSError:
        return
    with pytest.raises(PublicationError, match="symlink|reparse"):
        publish_bytes_atomically(
            (OutputBytes("symlink", symlink, b"new", "private"),),
            public_root=public,
            private_root=private,
        )


def test_pipeline_fingerprint_is_deterministic_and_sensitive() -> None:
    digest_a = _sha256(b"a")
    digest_b = _sha256(b"b")
    first = pipeline_fingerprint(
        input_sha256=digest_a,
        bundle_manifest_sha256=digest_b,
        component_sha256={"decoder": digest_a, "extractor": digest_b},
        options={"mode": "strict", "limits": {"b": 2, "a": 1}},
    )
    reordered = pipeline_fingerprint(
        input_sha256=digest_a,
        bundle_manifest_sha256=digest_b,
        component_sha256={"extractor": digest_b, "decoder": digest_a},
        options={"limits": {"a": 1, "b": 2}, "mode": "strict"},
    )
    changed = pipeline_fingerprint(
        input_sha256=digest_a,
        bundle_manifest_sha256=digest_b,
        component_sha256={"decoder": digest_a, "extractor": digest_b},
        options={"mode": "review", "limits": {"a": 1, "b": 2}},
    )
    assert first == reordered
    assert first != changed


def test_stage_dag_orders_dependencies_and_keeps_values_private() -> None:
    calls: list[str] = []
    secret = b"unique-private-stage-bytes"

    def produce(stage: StageDefinition, _dependencies):
        calls.append(stage.stage_id)
        return StageOutcome(public_report={"count": 1}, values={"payload": secret})

    def consume(stage: StageDefinition, dependencies):
        calls.append(stage.stage_id)
        assert dependencies["produce"].values["payload"] == secret
        return StageOutcome(public_report={"verified": True})

    result = run_stage_dag(
        (
            StageDefinition("consume", "consume", ("produce",)),
            StageDefinition("produce", "produce"),
        ),
        {"produce": produce, "consume": consume},
    )
    assert calls == ["produce", "consume"]
    assert result.status == "succeeded"
    report = json.dumps(result.public(), ensure_ascii=False)
    assert secret.decode() not in report
    assert result.public()["safety"] == {
        "executed_sample": False,
        "network_contacted": False,
        "manifest_selected_callable": False,
        "raw_bytes_in_report": False,
    }


def test_stage_failure_blocks_dependents_but_independent_stage_runs() -> None:
    calls: list[str] = []

    def fail(stage: StageDefinition, _dependencies):
        calls.append(stage.stage_id)
        raise RuntimeError("private exception text")

    def success(stage: StageDefinition, _dependencies):
        calls.append(stage.stage_id)
        return StageOutcome(public_report={"ok": True})

    result = run_stage_dag(
        (
            StageDefinition("root", "fail"),
            StageDefinition("blocked", "success", ("root",)),
            StageDefinition("independent", "success"),
        ),
        {"fail": fail, "success": success},
    )
    by_id = {stage.stage_id: stage for stage in result.stages}
    assert by_id["root"].status == "failed"
    assert by_id["blocked"].status == "blocked"
    assert by_id["independent"].status == "succeeded"
    assert calls == ["independent", "root"]
    assert "private exception text" not in json.dumps(result.public())


def test_partial_required_dependency_blocks_and_graph_errors_fail_closed() -> None:
    def partial(_stage: StageDefinition, _dependencies):
        return StageOutcome(public_report={"reason": "incomplete"}, partial=True)

    def success(_stage: StageDefinition, _dependencies):
        return StageOutcome(public_report={"ok": True})

    result = run_stage_dag(
        (
            StageDefinition("partial", "partial"),
            StageDefinition("required", "success", ("partial",), required=True),
        ),
        {"partial": partial, "success": success},
    )
    assert [stage.status for stage in result.stages] == ["partial", "blocked"]
    with pytest.raises(StageGraphError, match="重複"):
        run_stage_dag(
            (StageDefinition("same", "success"), StageDefinition("same", "success")),
            {"success": success},
        )
    with pytest.raises(StageGraphError, match="欠損"):
        run_stage_dag(
            (StageDefinition("one", "success", ("missing",)),),
            {"success": success},
        )
    with pytest.raises(StageGraphError, match="cycle"):
        run_stage_dag(
            (
                StageDefinition("one", "success", ("two",)),
                StageDefinition("two", "success", ("one",)),
            ),
            {"success": success},
        )


def test_stage_public_report_rejects_raw_bytes() -> None:
    with pytest.raises(TypeError, match="JSON-safe"):
        StageOutcome(public_report={"raw": b"must-not-leak"})
