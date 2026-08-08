"""GuLoader/XLoader静的pipeline hardening候補の安全境界を検証する。"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import sys
from pathlib import Path
from types import MappingProxyType, SimpleNamespace

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
SPEC = importlib.util.spec_from_file_location("xloader_pipeline_hardening_v3", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
PIPE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = PIPE
SPEC.loader.exec_module(PIPE)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _c2_report() -> dict[str, object]:
    return {
        "observed_counts": {
            "decoded_builder_total": 171,
            "classified_base64_builders": 73,
            "primary_candidate_seed": 64,
            "isolated_bootstrap_seed": 1,
            "excluded_helper": 4,
            "excluded_api": 4,
        },
        "initial_record_table": {"record_count": 16},
        "sample_executed": False,
        "network_contacted": False,
    }


def test_digest_requires_lowercase_string() -> None:
    assert PIPE._digest("a" * 64, "hash") == "a" * 64
    with pytest.raises(PIPE.PipelineIntegrityError):
        PIPE._digest("A" * 64, "hash")
    with pytest.raises(PIPE.PipelineIntegrityError):
        PIPE._digest(123, "hash")


@pytest.mark.parametrize(
    "raw",
    [b"  raw key  ", b"41424344", b"\x00\xff\x20"],
)
def test_base_key_preserves_raw_bytes(raw: bytes) -> None:
    bundle = SimpleNamespace(require=lambda _role: SimpleNamespace(data=raw))
    assert PIPE._base_key(bundle) == raw


def test_bounded_reader_rejects_hardlink(tmp_path: Path) -> None:
    source = tmp_path / "source.bin"
    alias = tmp_path / "alias.bin"
    source.write_bytes(b"MZ")
    os.link(source, alias)
    with pytest.raises(PIPE.PipelineIntegrityError):
        PIPE._read_bounded_regular_file(
            source,
            maximum=16,
            minimum=1,
            label="test",
        )


@pytest.mark.parametrize(
    "raw",
    [r"\\server\share\sample.bin", r"\\?\C:\sample.bin", r"C:\sample.bin:ads"],
)
def test_nonlocal_and_special_paths_are_rejected(raw: str) -> None:
    with pytest.raises(PIPE.PipelineIntegrityError):
        PIPE._reject_nonlocal_path(Path(raw), "test")


def test_prepared_pipeline_keeps_input_snapshot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    private_root = tmp_path / "private"
    private_root.mkdir()
    input_path = tmp_path / "sample.bin"
    manifest_path = private_root / "bundle.json"
    original = b"original-static-image"
    input_path.write_bytes(original)
    manifest_path.write_text("{}", encoding="utf-8")
    settings = MappingProxyType(
        {
            "pipeline_id": PIPE.PIPELINE_ID,
            "family": "xloader",
            "entry_role": PIPE.ENTRY_FULL,
            "expected_input_sha256": _sha256(original),
            "expected_final_sha256": _sha256(original),
            "expected_final_size": len(original),
            "allow_structural_reuse": False,
        }
    )
    bundle = SimpleNamespace(
        manifest_path=manifest_path,
        manifest_sha256="b" * 64,
        settings=settings,
        artifacts=(),
    )
    monkeypatch.setattr(PIPE, "_load_bundle", lambda *_args: bundle)
    monkeypatch.setattr(PIPE, "_implementation_hashes", lambda: {"code": "c" * 64})
    monkeypatch.setattr(
        PIPE,
        "_runtime_identity",
        lambda: MappingProxyType({"python_version": "test"}),
    )
    monkeypatch.setattr(PIPE, "_structural_probe", lambda *_args: {"matched": True})

    prepared = PIPE._prepare_pipeline(input_path, manifest_path, private_root)
    input_path.write_bytes(b"changed-after-prepare")
    report, code = PIPE._probe_prepared(prepared)

    assert code == 0
    assert prepared.input_image == original
    assert report["input"]["sha256"] == _sha256(original)


def test_c2_report_requires_static_safety_flags() -> None:
    report = _c2_report()
    report["network_contacted"] = True
    with pytest.raises(PIPE.PipelineIntegrityError):
        PIPE._validate_c2_report(report)


@pytest.mark.parametrize(
    "payload",
    [
        b'{"key":1,"key":2}',
        b'{"key":NaN}',
        b'{"key":Infinity}',
        b'{"key":-Infinity}',
    ],
)
def test_public_json_rejects_duplicate_and_nonfinite_values(payload: bytes) -> None:
    with pytest.raises(PIPE.PipelineIntegrityError):
        PIPE._load_public_json(payload)


def test_all_publish_failures_become_commit_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepared = SimpleNamespace(
        input_path=tmp_path / "input.bin",
        manifest_path=tmp_path / "manifest.json",
        private_root=tmp_path,
    )
    monkeypatch.setattr(PIPE, "_validate_public_report_path", lambda path: path)
    monkeypatch.setattr(
        PIPE,
        "publish_bytes_atomically",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("failure")),
    )
    output = PIPE.OutputBytes("public_report", tmp_path / "report.json", b"{}", "public")
    with pytest.raises(PIPE.PipelineCommitError):
        PIPE._publish_outputs(prepared, [output])


def test_verify_requires_exact_roles_and_recomputed_c2(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    final_image = b"MZ-final-image"
    private_c2 = b'{"private":true}\n'
    fingerprint = "f" * 64
    private_root = tmp_path / "private"
    private_root.mkdir()
    final_path = private_root / f"{fingerprint}-xloader-fully-recovered.bin"
    c2_path = private_root / f"{fingerprint}-xloader-c2-private.json"
    final_path.write_bytes(final_image)
    c2_path.write_bytes(private_c2)
    public_path = tmp_path / "report.json"
    c2_report = _c2_report()
    runtime_identity = {"python_version": "test"}
    report = {
        "status": "complete",
        "pipeline_id": PIPE.PIPELINE_ID,
        "analysis_type": "guloader_xloader_static_pipeline",
        "pipeline_fingerprint": fingerprint,
        "entry_role": PIPE.ENTRY_FULL,
        "input": {"sha256": _sha256(final_image), "size": len(final_image)},
        "runtime_identity": runtime_identity,
        "private_outputs_committed": True,
        "safety": {"sample_executed": False, "network_contacted": False},
        "c2_static_report": c2_report,
        "private_outputs": [
            {
                "role": "xloader_fully_recovered_image",
                "sha256": _sha256(final_image),
                "size": len(final_image),
            },
            {
                "role": "xloader_c2_private_material",
                "sha256": _sha256(private_c2),
                "size": len(private_c2),
            },
        ],
    }
    public_path.write_text(json.dumps(report), encoding="utf-8")
    prepared = PIPE.PreparedPipeline(
        input_path=tmp_path / "input.bin",
        input_image=final_image,
        input_sha256=_sha256(final_image),
        manifest_path=tmp_path / "manifest.json",
        private_root=private_root,
        bundle=object(),
        settings=MappingProxyType(
            {
                "expected_final_sha256": _sha256(final_image),
                "expected_final_size": len(final_image),
            }
        ),
        implementation_hashes=MappingProxyType({}),
        runtime_identity=MappingProxyType(runtime_identity),
        pipeline_fingerprint=fingerprint,
    )
    monkeypatch.setattr(
        PIPE,
        "_validate_public_report_path",
        lambda _path, **_kwargs: public_path,
    )
    monkeypatch.setattr(PIPE, "_prepare_pipeline", lambda *_args: prepared)
    monkeypatch.setattr(
        PIPE,
        "_probe_prepared",
        lambda _prepared: (
            {
                "status": "exact_match",
                "entry_role": PIPE.ENTRY_FULL,
                "safety": {
                    "sample_executed": False,
                    "network_contacted": False,
                },
            },
            0,
        ),
    )
    recomputed = {"called": 0}

    def regenerate(*_args: object, **_kwargs: object) -> tuple[dict[str, object], bytes]:
        recomputed["called"] += 1
        return c2_report, private_c2

    monkeypatch.setattr(PIPE, "_regenerate_c2", regenerate)

    result = PIPE.verify_pipeline(
        tmp_path / "input.bin",
        tmp_path / "manifest.json",
        private_root,
        public_path,
    )

    assert result["status"] == "verified"
    assert result["c2_static_recomputed"] is True
    assert recomputed["called"] == 1

    def change_pipeline_id(value: dict[str, object]) -> None:
        value["pipeline_id"] = "tampered"

    def change_analysis_type(value: dict[str, object]) -> None:
        value["analysis_type"] = "tampered"

    def change_entry_role(value: dict[str, object]) -> None:
        value["entry_role"] = PIPE.ENTRY_PROTECTED

    def change_input(value: dict[str, object]) -> None:
        value["input"] = {"sha256": "0" * 64, "size": len(final_image)}

    def change_runtime(value: dict[str, object]) -> None:
        value["runtime_identity"] = {"python_version": "tampered"}

    def change_commit(value: dict[str, object]) -> None:
        value["private_outputs_committed"] = False

    for mutate in (
        change_pipeline_id,
        change_analysis_type,
        change_entry_role,
        change_input,
        change_runtime,
        change_commit,
    ):
        tampered = json.loads(json.dumps(report))
        mutate(tampered)
        public_path.write_text(json.dumps(tampered), encoding="utf-8")
        with pytest.raises(PIPE.PipelineIntegrityError):
            PIPE.verify_pipeline(
                tmp_path / "input.bin",
                tmp_path / "manifest.json",
                private_root,
                public_path,
            )
