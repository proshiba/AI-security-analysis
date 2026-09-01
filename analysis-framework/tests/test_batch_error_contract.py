"""検体単位errorの固定・非機密契約を検証する。"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

COMMON = Path(__file__).resolve().parents[1] / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

import batch_error_contract as contract  # noqa: E402


def test_build_record_drops_exception_message_and_validates() -> None:
    """例外本文を保存せず、安定した型名だけを公開する。"""

    record = contract.build_record(
        input_index=0,
        sha256="a" * 64,
        stage="root_static_analysis",
        error=ValueError("token=secret-value C:\\private\\sample.bin"),
    )

    assert record == {
        "input_index": 0,
        "sha256": "a" * 64,
        "stage": "root_static_analysis",
        "error_code": "root_static_analysis_failed",
        "message": "root静的解析を完了できませんでした (ValueError)",
    }
    assert "secret-value" not in str(record)
    assert contract.validate_record(record) == record


def test_build_record_does_not_publish_custom_exception_class_name() -> None:
    """外部parser由来の任意class名を公開messageへ流さない。"""

    class CredentialNameEmbeddedInError(Exception):
        pass

    record = contract.build_record(
        input_index=0,
        stage="input_read",
        error=CredentialNameEmbeddedInError(),
    )
    assert record["message"] == "入力を安全に読み込めませんでした (Exception)"
    assert "CredentialName" not in record["message"]
    assert contract.validate_record(record) == record


@pytest.mark.parametrize(
    "mutation",
    [
        {"extra": True},
        {"error_code": "input_read_failed"},
        {"sha256": "A" * 64},
        {"message": "root静的解析を完了できませんでした (ValueError): secret"},
        {"input_index": -1},
    ],
)
def test_validate_record_rejects_schema_mapping_and_raw_details(mutation: dict[str, object]) -> None:
    """追加key、stage不一致、path、自由文をfail-closedで拒否する。"""

    value: dict[str, object] = {
        "input_index": 0,
        "sha256": "a" * 64,
        "stage": "root_static_analysis",
        "error_code": "root_static_analysis_failed",
        "message": "root静的解析を完了できませんでした (ValueError)",
    }
    value.update(mutation)

    with pytest.raises(contract.BatchErrorContractError):
        contract.validate_record(value)


def test_build_record_rejects_unregistered_stage_and_invalid_input_index() -> None:
    """未登録stageや不正な入力indexをrecord生成時点で拒否する。"""

    with pytest.raises(contract.BatchErrorContractError):
        contract.build_record(input_index=0, stage="follow_on", error=OSError())
    with pytest.raises(contract.BatchErrorContractError):
        contract.build_record(input_index=-1, stage="input_read", error=OSError())
