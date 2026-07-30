"""classifier単体実行の共有extractor import root回帰テスト。"""

from __future__ import annotations

from classifiers import classify_sample


def test_loader_registers_repository_root_for_shared_extractors() -> None:
    repository_root = str(classify_sample.FRAMEWORK_ROOT.parent)
    original = list(classify_sample.sys.path)
    try:
        classify_sample.sys.path[:] = [item for item in classify_sample.sys.path if item != repository_root]
        classify_sample.clear_classifier_caches()
        detector = classify_sample.load_detector(
            classify_sample.FRAMEWORK_ROOT,
            "malware/shadowpad/detect.py",
            "shadowpad",
        )
        assert callable(detector)
        assert repository_root in classify_sample.sys.path
    finally:
        classify_sample.sys.path[:] = original
        classify_sample.clear_classifier_caches()
