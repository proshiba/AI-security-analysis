"""GuLoader/XLoader静的一括pipelineのfail-closed境界を検証する。"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[2]
COMMON = ROOT / "analysis-framework" / "common"
FORMBOOK = ROOT / "analysis-framework" / "malware" / "formbook_loader"
MODULE_PATH = (
    ROOT
    / "analysis-framework"
    / "malware"
    / "guloader"
    / "xloader_static_pipeline.py"
)
for module_path in (COMMON, FORMBOOK):
    if str(module_path) not in sys.path:
        sys.path.insert(0, str(module_path))
SPEC = importlib.util.spec_from_file_location("guloader_xloader_static_pipeline", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
PIPE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = PIPE
SPEC.loader.exec_module(PIPE)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _roles(entry_role: str, *, static_report: bool = False) -> list[str]:
    roles = [
        PIPE.LINEAGE_PROFILE,
        PIPE.BASE_KEY,
        PIPE.PRIMARY_KEY_PLAN,
        PIPE.BOOTSTRAP_KEY_PLAN,
        PIPE.INITIAL_RECORD_PLAN,
    ]
    if entry_role in {PIPE.ENTRY_PROTECTED, PIPE.ENTRY_GULOADER}:
        roles.extend([PIPE.PROTECTED_PROFILE, PIPE.NESTED_PROFILE])
    if entry_role == PIPE.ENTRY_GULOADER:
        roles.append(PIPE.INNER_PROFILE)
    if static_report:
        roles.append(PIPE.STATIC_REPORT)
    return roles


def _bundle(
    root: Path,
    image: bytes,
    *,
    entry_role: str = PIPE.ENTRY_FULL,
    expected_input_sha256: str | None = None,
    allow_structural_reuse: bool = False,
    static_report: bool = False,
) -> tuple[Path, Path]:
    private_root = root / "private"
    private_root.mkdir(parents=True)
    artifacts = []
    for role in _roles(entry_role, static_report=static_report):
        if role == PIPE.BASE_KEY:
            data = b"synthetic-private-base-key"
            media_type = "application/octet-stream"
        elif role == PIPE.STATIC_REPORT:
            data = (
                json.dumps(
                    {
                        "schema_version": 1,
                        "analysis_type": "xloader_all_91_wrappers_static_canonical_image",
                        "inventory": {
                            "wrapper_count": 91,
                            "recovered_count": 91,
                            "unresolved_count": 0,
                        },
                        "output": {"sha256": _sha256(image), "size": len(image)},
                    }
                ).encode("utf-8")
            )
            media_type = "application/json"
        else:
            data = b"{}"
            media_type = "application/json"
        path = private_root / f"{role}.dat"
        path.write_bytes(data)
        artifacts.append(
            {
                "role": role,
                "path": path.name,
                "sha256": _sha256(data),
                "size": len(data),
                "media_type": media_type,
            }
        )
    manifest = {
        "schema_version": 1,
        "manifest_type": PIPE.MANIFEST_TYPE,
        "settings": {
            "pipeline_id": PIPE.PIPELINE_ID,
            "family": "guloader-xloader",
            "entry_role": entry_role,
            "expected_input_sha256": expected_input_sha256 or _sha256(image),
            "expected_final_sha256": _sha256(image),
            "expected_final_size": len(image),
            "allow_structural_reuse": allow_structural_reuse,
        },
        "artifacts": artifacts,
    }
    manifest_path = private_root / "bundle.json"
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    return manifest_path, private_root


def _input(root: Path, data: bytes) -> Path:
    path = root / "sample.bin"
    path.write_bytes(data)
    return path


def _c2_report() -> dict[str, object]:
    return {
        "schema_version": 1,
        "analysis_type": "xloader_c2_static_candidate_inventory",
        "observed_counts": {
            "decoded_builder_total": 171,
            "classified_base64_builders": 73,
            "primary_candidate_seed": 64,
            "isolated_bootstrap_seed": 1,
            "classified_network_material_total": 65,
            "excluded_helper": 4,
            "excluded_api": 4,
        },
        "initial_record_table": {
            "attempted": True,
            "reviewed_record_plan": True,
            "record_count": 16,
            "records": [],
        },
        "sample_executed": False,
        "network_contacted": False,
    }


def _install_direct_mocks(monkeypatch: pytest.MonkeyPatch, image: bytes) -> list[object]:
    monkeypatch.setattr(
        PIPE,
        "_structural_probe",
        lambda *_args: {
            "gate": "xloader_builder_inventory",
            "decoded_builder_total": 171,
            "classified_base64_builders": 73,
            "matched": True,
        },
    )
    monkeypatch.setattr(
        PIPE,
        "lineage_profile_from_mapping",
        lambda _value: SimpleNamespace(expected_input_sha256=_sha256(image)),
    )
    monkeypatch.setattr(PIPE, "layered_key_plan_from_mapping", lambda _value: object())
    monkeypatch.setattr(PIPE, "initial_record_plan_from_mapping", lambda _value: object())

    def fake_extract(
        value: bytes,
        _base_key: bytes,
        _lineage: object,
        **options: object,
    ) -> dict[str, object]:
        assert value == image
        private_path = options["private_output_path"]
        assert isinstance(private_path, Path)
        private_path.write_text('{"private":true}\n', encoding="utf-8")
        return _c2_report()

    monkeypatch.setattr(PIPE, "extract_static_c2_inventory", fake_extract)
    published: list[object] = []
    monkeypatch.setattr(
        PIPE,
        "publish_bytes_atomically",
        lambda outputs, **_options: published.extend(outputs),
    )
    return published


def test_exact_direct_chain_reaches_c2_and_commits_as_one_set(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    image = b"MZ-synthetic-fully-recovered-xloader"
    input_path = _input(tmp_path, image)
    manifest, private_root = _bundle(tmp_path, image, static_report=True)
    published = _install_direct_mocks(monkeypatch, image)

    report, code = PIPE.run_pipeline(
        input_path,
        manifest,
        private_root,
        ROOT / ".work" / "static-recovery" / "synthetic-xloader-pipeline-report.json",
    )

    assert code == 0
    assert report["status"] == "complete"
    assert report["post_gates"]["static_recovery"]["recovered_count"] == 91
    assert report["post_gates"]["c2_inventory"]["decoded_builder_total"] == 171
    assert report["post_gates"]["c2_inventory"]["initial_record_count"] == 16
    assert len(published) == 3
    serialized = json.dumps(report, ensure_ascii=False)
    assert str(private_root) not in serialized
    assert "synthetic-private-base-key" not in serialized


def test_input_hash_mismatch_without_structure_is_not_matched(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    image = b"new sample"
    input_path = _input(tmp_path, image)
    manifest, private_root = _bundle(
        tmp_path, image, expected_input_sha256="0" * 64
    )
    monkeypatch.setattr(PIPE, "_structural_probe", lambda *_args: {"matched": False})

    report, code = PIPE.probe_pipeline(input_path, manifest, private_root)

    assert code == 2
    assert report["status"] == "not_matched"
    assert report["lineage"]["profile_reuse_authorized"] is False


def test_structural_match_without_explicit_reuse_stops_as_candidate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    image = b"structurally similar sample"
    input_path = _input(tmp_path, image)
    manifest, private_root = _bundle(
        tmp_path,
        image,
        expected_input_sha256="1" * 64,
        allow_structural_reuse=False,
    )
    monkeypatch.setattr(
        PIPE,
        "_structural_probe",
        lambda *_args: {"gate": "synthetic", "matched": True},
    )

    report, code = PIPE.probe_pipeline(input_path, manifest, private_root)

    assert code == 2
    assert report["status"] in {"candidate_only", "candidate"}
    assert report["lineage"]["profile_reuse_authorized"] is False


def test_failed_stage_blocks_following_stages_and_leaks_no_private_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    image = b"protected mapped image"
    input_path = _input(tmp_path, image)
    manifest, private_root = _bundle(tmp_path, image, entry_role=PIPE.ENTRY_PROTECTED)
    monkeypatch.setattr(
        PIPE,
        "_structural_probe",
        lambda *_args: {"gate": "protected_wrapper_inventory", "matched": True},
    )
    monkeypatch.setattr(
        PIPE, "protected_profile_from_mapping", lambda _value: object()
    )
    monkeypatch.setattr(
        PIPE,
        "recover_protected_functions",
        lambda *_args, **_options: (_ for _ in ()).throw(ValueError("private detail")),
    )
    c2_called = False

    def forbidden_c2(*_args: object, **_options: object) -> dict[str, object]:
        nonlocal c2_called
        c2_called = True
        raise AssertionError("先行stage失敗後にC2 stageを実行してはいけません")

    monkeypatch.setattr(PIPE, "extract_static_c2_inventory", forbidden_c2)
    monkeypatch.setattr(PIPE, "publish_bytes_atomically", lambda *_args, **_options: None)

    try:
        report, code = PIPE.run_pipeline(
            input_path,
            manifest,
            private_root,
            ROOT / ".work" / "static-recovery" / "synthetic-partial-report.json",
        )
    except PIPE.PipelinePartial:
        code = 3
        report = {"status": "partial"}

    assert code == 3
    assert report["status"] == "partial"
    assert c2_called is False
    assert not any(path.name.startswith(".xloader-static-") for path in private_root.iterdir())
    assert not list(private_root.rglob("xloader-c2-private.json"))


def test_safety_flags_explicitly_forbid_execution_and_network(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    image = b"known safe static input"
    input_path = _input(tmp_path, image)
    manifest, private_root = _bundle(tmp_path, image)
    monkeypatch.setattr(PIPE, "_structural_probe", lambda *_args: {"matched": True})

    report, code = PIPE.probe_pipeline(input_path, manifest, private_root)

    assert code == 0
    assert report["safety"] == {
        "sample_executed": False,
        "subprocess_started": False,
        "network_contacted": False,
        "manifest_command_executed": False,
        "secret_material_published": False,
        "private_path_published": False,
    }


@pytest.mark.parametrize("command", ["probe", "run", "verify"])
def test_cli_subcommands_require_explicit_input_bundle_and_roots(command: str) -> None:
    parser = PIPE.build_parser()
    args = parser.parse_args(
        [
            command,
            "--input",
            "sample.bin",
            "--bundle-manifest",
            "bundle.json",
            "--private-output-root",
            "private-output",
            "--public-report",
            "report.json",
        ]
    )

    assert args.command == command
    assert args.input == Path("sample.bin")
    assert args.bundle_manifest == Path("bundle.json")
    assert args.private_output_root == Path("private-output")


def test_cli_has_no_execution_or_network_switch() -> None:
    help_text = PIPE.build_parser().format_help()

    assert "--allow-network" not in help_text
    assert "--execute" not in help_text
