"""DCRat終端managed clientの認証済み静的解析入口。"""

from extractors.dcrat.integrated import extract as _extract
from extractors.dcrat.integrated import structural_evidence

HANDLER_CONTRACT = {
    "input_formats": ["pe"],
    "minimum_evidence_score": 20_000,
}


def extract(data: bytes, name: str = "sample") -> dict:
    """検証済みDCRat統合抽出器を共通handler入口から呼び出す。"""

    return _extract(data, name)


__all__ = ["HANDLER_CONTRACT", "extract", "structural_evidence"]