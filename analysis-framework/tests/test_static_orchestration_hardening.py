"""静的復元オーケストレーションの境界条件とロールバックを検証する。"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sys

import pytest

from common import static_orchestration as orchestration
from common.static_orchestration import (
    ArtifactRequirement,
    ManifestValidationError,
    OutputBytes,
    PublicationError,
    load_artifact_bundle,
    publish_bytes_atomically,
)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _write_single_artifact_bundle(
    root: Path,
    *,
    artifact_name: str = "payload.bin",
    artifact_data: bytes = b"payload",
    declared_size: int | None = None,
    media_type: str = "application/octet-stream",
    json_identity: dict[str, object] | None = None,
) -> Path:
    document: dict[str, object] = {
        "schema_version": 1,
        "manifest_type": "static_analysis_private_bundle",
        "settings": {},
        "artifacts": [
            {
                "role": "payload",
                "path": artifact_name,
                "sha256": _sha256(artifact_data),
                "size": len(artifact_data) if declared_size is None else declared_size,
                "media_type": media_type,
            }
        ],
    }
    if json_identity is not None:
        document["artifacts"][0]["json_identity"] = json_identity  # type: ignore[index]
    manifest = root / "bundle.json"
    manifest.write_text(json.dumps(document, ensure_ascii=False), encoding="utf-8")
    return manifest


def _binary_requirement(*, max_size: int = 1024) -> tuple[ArtifactRequirement, ...]:
    return (ArtifactRequirement("payload", "application/octet-stream", max_size=max_size),)


def _make_hardlink(source: Path, link: Path) -> None:
    try:
        os.link(source, link)
    except (NotImplementedError, OSError) as exc:
        pytest.skip(f"この環境ではhardlinkを作成できません: {type(exc).__name__}")


@pytest.mark.parametrize("layout", ["same", "public_parent", "private_parent"])
def test_atomic_publish_rejects_overlapping_public_and_private_roots(
    tmp_path: Path, layout: str
) -> None:
    if layout == "same":
        public = private = tmp_path / "shared"
        public.mkdir()
    elif layout == "public_parent":
        public = tmp_path / "public"
        private = public / "private"
        private.mkdir(parents=True)
    else:
        private = tmp_path / "private"
        public = private / "public"
        public.mkdir(parents=True)

    with pytest.raises(PublicationError, match="分離"):
        publish_bytes_atomically(
            (OutputBytes("report", public / "report.json", b"{}", "public"),),
            public_root=public,
            private_root=private,
        )


def test_bundle_rejects_hardlinked_manifest_when_supported(tmp_path: Path) -> None:
    payload = b"payload"
    (tmp_path / "payload.bin").write_bytes(payload)
    manifest = _write_single_artifact_bundle(tmp_path, artifact_data=payload)
    linked_manifest = tmp_path / "bundle-hardlink.json"
    _make_hardlink(manifest, linked_manifest)

    with pytest.raises(ManifestValidationError, match="hardlink"):
        load_artifact_bundle(
            linked_manifest,
            private_root=tmp_path,
            requirements=_binary_requirement(),
        )


def test_bundle_rejects_hardlinked_artifact_when_supported(tmp_path: Path) -> None:
    payload = b"payload"
    original = tmp_path / "payload-original.bin"
    original.write_bytes(payload)
    linked_artifact = tmp_path / "payload.bin"
    _make_hardlink(original, linked_artifact)
    manifest = _write_single_artifact_bundle(tmp_path, artifact_data=payload)

    with pytest.raises(ManifestValidationError, match="hardlink"):
        load_artifact_bundle(
            manifest,
            private_root=tmp_path,
            requirements=_binary_requirement(),
        )


def test_atomic_publish_rolls_back_mixed_existing_and_new_outputs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    public = tmp_path / "public"
    private = tmp_path / "private"
    public.mkdir()
    private.mkdir()
    existing = public / "existing.json"
    newly_created = private / "new.bin"
    existing.write_bytes(b"old-public")
    original_replace = orchestration.os.replace

    def fail_new_output_stage(
        source: str | os.PathLike[str], destination: str | os.PathLike[str]
    ) -> None:
        source_path = Path(source)
        if Path(destination) == newly_created and source_path.name.startswith(".static-stage-"):
            raise OSError("injected new-output replacement failure")
        original_replace(source, destination)

    monkeypatch.setattr(orchestration.os, "replace", fail_new_output_stage)
    with pytest.raises(PublicationError):
        publish_bytes_atomically(
            (
                OutputBytes("report", existing, b"new-public", "public"),
                OutputBytes("payload", newly_created, b"new-private", "private"),
            ),
            public_root=public,
            private_root=private,
        )

    assert existing.read_bytes() == b"old-public"
    assert not newly_created.exists()
    assert not list(tmp_path.rglob(".static-stage-*"))
    assert not list(tmp_path.rglob(".static-backup-*"))


def test_atomic_publish_preserves_backup_when_rollback_restore_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    public = tmp_path / "public"
    private = tmp_path / "private"
    public.mkdir()
    private.mkdir()
    destination = public / "report.json"
    destination.write_bytes(b"recoverable-old-data")
    original_replace = orchestration.os.replace

    def fail_publish_and_restore(
        source: str | os.PathLike[str], target: str | os.PathLike[str]
    ) -> None:
        source_path = Path(source)
        target_path = Path(target)
        if target_path == destination and source_path.name.startswith(
            (".static-stage-", ".static-backup-")
        ):
            raise OSError("injected publish/restore failure")
        original_replace(source, target)

    monkeypatch.setattr(orchestration.os, "replace", fail_publish_and_restore)
    with pytest.raises(PublicationError, match="rollback_errors"):
        publish_bytes_atomically(
            (OutputBytes("report", destination, b"new-data", "public"),),
            public_root=public,
            private_root=private,
        )

    backups = list(public.glob(".static-backup-*"))
    assert not destination.exists()
    assert len(backups) == 1
    assert backups[0].read_bytes() == b"recoverable-old-data"
    assert not list(public.glob(".static-stage-*"))


def test_bundle_rejects_manifest_larger_than_read_limit(tmp_path: Path) -> None:
    manifest = tmp_path / "bundle.json"
    manifest.write_bytes(b"{" + b" " * (1024 * 1024))

    with pytest.raises(ManifestValidationError, match="size上限"):
        load_artifact_bundle(
            manifest,
            private_root=tmp_path,
            requirements=_binary_requirement(),
        )


def test_bundle_rejects_artifact_declared_larger_than_role_limit(tmp_path: Path) -> None:
    payload = b"123456789"
    (tmp_path / "payload.bin").write_bytes(payload)
    manifest = _write_single_artifact_bundle(tmp_path, artifact_data=payload)

    with pytest.raises(ManifestValidationError, match="上限超過"):
        load_artifact_bundle(
            manifest,
            private_root=tmp_path,
            requirements=_binary_requirement(max_size=8),
        )


def test_bundle_rejects_physical_artifact_larger_than_claimed_bounded_size(tmp_path: Path) -> None:
    payload = b"123456789"
    (tmp_path / "payload.bin").write_bytes(payload)
    manifest = _write_single_artifact_bundle(
        tmp_path,
        artifact_data=payload,
        declared_size=8,
    )

    with pytest.raises(ManifestValidationError, match="size上限"):
        load_artifact_bundle(
            manifest,
            private_root=tmp_path,
            requirements=_binary_requirement(max_size=8),
        )


def test_bundle_rejects_excessively_deep_manifest_json(tmp_path: Path) -> None:
    depth = sys.getrecursionlimit() + 100
    manifest = tmp_path / "bundle.json"
    prefix = (
        b'{"schema_version":1,"manifest_type":"static_analysis_private_bundle",'
        b'"settings":'
    )
    suffix = b',"artifacts":[]}'
    manifest.write_bytes(prefix + b"[" * depth + b"0" + b"]" * depth + suffix)

    # PythonのJSON decoderが深さ上限を先に検出する版と、後段schemaで
    # settings型違反として拒否する版の双方で、例外を外へ漏らさずfail-closedにする。
    with pytest.raises(ManifestValidationError, match="JSON|settings"):
        load_artifact_bundle(
            manifest,
            private_root=tmp_path,
            requirements=_binary_requirement(),
        )


def test_bundle_rejects_duplicate_manifest_json_key(tmp_path: Path) -> None:
    manifest = tmp_path / "bundle.json"
    manifest.write_bytes(
        b'{"schema_version":1,"schema_version":1,'
        b'"manifest_type":"static_analysis_private_bundle","settings":{},"artifacts":[]}'
    )

    with pytest.raises(ManifestValidationError, match="重複"):
        load_artifact_bundle(
            manifest,
            private_root=tmp_path,
            requirements=_binary_requirement(),
        )


def test_bundle_rejects_duplicate_key_in_json_artifact(tmp_path: Path) -> None:
    artifact = (
        b'{"schema_version":1,"profile_id":"fixture-profile",'
        b'"profile_id":"substituted-profile"}'
    )
    (tmp_path / "profile.json").write_bytes(artifact)
    identity: dict[str, object] = {
        "schema_version": 1,
        "profile_id": "fixture-profile",
    }
    manifest = _write_single_artifact_bundle(
        tmp_path,
        artifact_name="profile.json",
        artifact_data=artifact,
        media_type="application/json",
        json_identity=identity,
    )
    requirements = (
        ArtifactRequirement(
            "payload",
            "application/json",
            json_identity=identity,
            max_size=1024,
        ),
    )

    with pytest.raises(ManifestValidationError, match="重複"):
        load_artifact_bundle(
            manifest,
            private_root=tmp_path,
            requirements=requirements,
        )
