"""検体を実行しない静的アーティファクト復元API。

個別unpackerのimportで統合パイプライン全体を読み込まないよう、互換用の
パッケージ直下APIは参照時に限って遅延importする。
"""

__all__ = ["recover_profiled_transforms", "unpack_bytes"]


def __getattr__(name: str):
    """固定した公開APIだけを遅延解決し、submodule importを軽量に保つ。"""

    if name == "recover_profiled_transforms":
        from .profiled_transform import recover_profiled_transforms

        return recover_profiled_transforms
    if name == "unpack_bytes":
        from .static_unpacker import unpack_bytes

        return unpack_bytes
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
