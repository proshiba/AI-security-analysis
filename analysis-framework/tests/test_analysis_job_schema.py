from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path


COMMON = Path(__file__).resolve().parents[1] / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

import analysis_job_runner as runner  # noqa: E402


def test_request_schema_is_derived_from_runner_contract() -> None:
    schema = runner.job_request_json_schema()
    properties = schema["properties"]
    options = properties["options"]["properties"]

    assert schema["additionalProperties"] is False
    assert set(properties) == runner.ALLOWED_TOP_LEVEL_KEYS
    assert set(schema["required"]) == runner.REQUIRED_TOP_LEVEL_KEYS
    assert properties["inputs"]["maxItems"] == runner.MAX_REQUEST_INPUTS
    assert options.keys() == runner.ALLOWED_OPTION_KEYS
    assert not (set(options) & runner.FORBIDDEN_OPTION_KEYS)
    assert options["max_files"]["maximum"] == runner.MAX_DISCOVERED_FILES
    assert options["max_file_size"]["maximum"] == runner.MAX_FILE_SIZE
    assert options["max_static_layers"]["maximum"] == runner.MAX_STATIC_LAYERS
    assert options["retry_max_static_layers"]["anyOf"][1]["maximum"] == runner.MAX_RETRY_STATIC_LAYERS
    assert options["family"]["anyOf"][1]["enum"] == sorted(runner._registered_families())


def test_schema_subcommand_returns_machine_readable_json(monkeypatch: object) -> None:
    captured: list[object] = []
    monkeypatch.setattr(  # type: ignore[attr-defined]
        runner,
        "_print_json",
        lambda value, **_kwargs: captured.append(value),
    )
    assert runner.main(["schema"]) == 0
    assert captured == [runner.job_request_json_schema()]


def test_analysis_contract_bundle_is_persisted_and_hashed(tmp_path: Path) -> None:
    job_dir = tmp_path / "job"
    job_dir.mkdir()
    digest = "a" * 64
    manifest = [
        runner.ExpectedInputUnit(
            source_name="sample.bin",
            unit_source_name="sample.bin",
            sha256=digest,
            read_succeeded=True,
        )
    ]

    relative, recorded_sha256 = runner.persist_analysis_contract_bundle(
        job_dir,
        root_contract={"schema_version": 1, "sha256": "b" * 64},
        follow_on_contract={"schema_version": 1, "sha256": "c" * 64},
        input_manifest=manifest,
    )

    payload = (job_dir / relative).read_bytes()
    document = json.loads(payload)
    assert recorded_sha256 == hashlib.sha256(payload).hexdigest()
    assert document["input_manifest"] == [manifest[0].public()]
    assert set(document) == {
        "schema_version",
        "input_manifest",
        "root_analysis_contract",
        "follow_on_analysis_contract",
    }
