"""通常JSON型の要求versionを検査し、数値／boolの同値比較を拒否する。"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

COMMON = Path(__file__).resolve().parents[1] / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

import analysis_job_runner as runner


@pytest.mark.parametrize("version", [True, False, 1.0, 0.0, "1", None, [], {}, 0, 2])
def test_request_rejects_noncanonical_schema_version(version: object) -> None:
    request = {"schema_version": version, "job_id": "typed-schema", "inputs": ["sample.bin"]}
    with pytest.raises(runner.JobContractError) as failure:
        runner.validate_request_object(request)
    assert failure.value.code == "unsupported_schema_version"


def test_request_accepts_current_integer_without_dispatch() -> None:
    result = runner.validate_request_object(
        {"schema_version": 1, "job_id": "typed-schema", "inputs": ["sample.bin"]}
    )
    assert result.job_id == "typed-schema"
    assert result.inputs == ("sample.bin",)


def test_request_schema_declares_version_integer_and_constant() -> None:
    schema = runner.job_request_json_schema()
    assert schema["properties"]["schema_version"] == {"type": "integer", "const": 1}
