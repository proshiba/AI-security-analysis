"""StealC設定抽出と新旧module役割判定を統合する。"""

from .integrated import classify_module_role, extract

__all__ = ["classify_module_role", "extract"]
