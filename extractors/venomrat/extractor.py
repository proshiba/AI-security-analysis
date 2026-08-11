"""VenomRAT終端managed clientの認証済み設定抽出入口。"""

from extractors.venomrat.integrated import (
    family_markers,
    structural_evidence,
)
from extractors.venomrat.integrated import extract as _extract

HANDLER_CONTRACT = {
    "input_formats": ["pe"],
    "minimum_evidence_score": 20_000,
}


def extract(data: bytes, name: str = "sample") -> dict:
    """検証済みVenomRAT統合抽出器を共通handler入口から呼び出す。"""

    return _extract(data, name)


__all__ = ["HANDLER_CONTRACT", "extract", "family_markers", "structural_evidence"]
