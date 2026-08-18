"""AsyncRAT終端managed clientの検証済み静的解析入口。"""

from extractors.asyncrat.integrated import extract as _extract
from extractors.asyncrat.integrated import structural_evidence

HANDLER_CONTRACT = {
    "input_formats": ["pe"],
    "minimum_evidence_score": 20_000,
}


def extract(data: bytes, name: str = "sample") -> dict:
    """検証済みAsyncRAT統合抽出器を共通handler入口から呼び出す。"""

    return _extract(data, name)


__all__ = ["HANDLER_CONTRACT", "extract", "structural_evidence"]
