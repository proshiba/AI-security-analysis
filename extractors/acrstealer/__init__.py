"""ACRStealer向けの非実行静的抽出器。"""

from .integrated import extract, recover_artifacts

__all__ = ["extract", "recover_artifacts"]
