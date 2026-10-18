"""classifier単体実行の共有extractor import root回帰テスト。"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

FRAMEWORK_ROOT = Path(__file__).resolve().parents[1]
if str(FRAMEWORK_ROOT) not in sys.path:
    sys.path.insert(0, str(FRAMEWORK_ROOT))

from classifiers import classify_sample


def _load_direct_detector(path: Path, module_name: str) -> ModuleType:
    """package外のdirect-spec互換経路でdetectorを読み込む。"""

    specification = importlib.util.spec_from_file_location(module_name, path)
    assert specification and specification.loader
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


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


def test_detector_import_does_not_leak_family_search_path() -> None:
    """family helper用の一時sys.pathを後続module解決へ残さない。"""

    family_root = str(classify_sample.FRAMEWORK_ROOT / "malware" / "remcosrat")
    original = list(classify_sample.sys.path)
    try:
        classify_sample.sys.path[:] = [item for item in classify_sample.sys.path if item != family_root]
        classify_sample.clear_classifier_caches()
        detector = classify_sample.load_detector(
            classify_sample.FRAMEWORK_ROOT,
            "malware/remcosrat/detect.py",
            "remcosrat",
        )
        assert callable(detector)
        assert family_root not in classify_sample.sys.path
    finally:
        classify_sample.sys.path[:] = original
        classify_sample.clear_classifier_caches()


def test_family_local_helper_isolated_from_same_named_top_level_module(
    monkeypatch,
) -> None:
    """別family由来の裸名helperが残ってもNoodleRATを誤束縛しない。"""

    poisoned = ModuleType("extract_config")

    def forbidden(_data: bytes):
        raise AssertionError("top-level extract_config must not be used")

    poisoned._analyze = forbidden
    monkeypatch.setitem(sys.modules, "extract_config", poisoned)
    classify_sample.load_detector.cache_clear()

    remcos = classify_sample.load_detector(
        classify_sample.FRAMEWORK_ROOT,
        "malware/remcosrat/detect.py",
        "remcosrat",
    )
    noodle = classify_sample.load_detector(
        classify_sample.FRAMEWORK_ROOT,
        "malware/noodlerat/detect.py",
        "noodlerat",
    )

    assert callable(remcos)
    assert callable(noodle)
    assert remcos.__module__ != noodle.__module__
    assert remcos.__module__.endswith(".detect")
    assert noodle.__module__.endswith(".detect")
    assert noodle.__globals__["_analyze"] is not forbidden
    assert noodle.__globals__["_analyze"].__module__.endswith(".extract_config")
    assert sys.modules["extract_config"] is poisoned


def test_detector_package_reload_does_not_reuse_previous_family_helper() -> None:
    """cache破棄後は固有package childも再生成し、古い束縛を再利用しない。"""

    classify_sample.load_detector.cache_clear()
    first = classify_sample.load_detector(
        classify_sample.FRAMEWORK_ROOT,
        "malware/noodlerat/detect.py",
        "noodlerat",
    )
    first_analyze = first.__globals__["_analyze"]

    classify_sample.load_detector.cache_clear()
    second = classify_sample.load_detector(
        classify_sample.FRAMEWORK_ROOT,
        "malware/noodlerat/detect.py",
        "noodlerat",
    )

    assert second is not first
    assert second.__globals__["_analyze"] is not first_analyze
    assert second.__globals__["_analyze"].__module__ == first_analyze.__module__


def test_direct_spec_detectors_isolate_helpers_and_family_search_paths(monkeypatch) -> None:
    """direct-spec互換でも裸名helperとfamily検索pathを共有しない。"""

    noodle_root = classify_sample.FRAMEWORK_ROOT / "malware" / "noodlerat"
    redc2_root = classify_sample.FRAMEWORK_ROOT / "malware" / "redc2"
    family_roots = {str(noodle_root), str(redc2_root)}
    monkeypatch.setattr(sys, "path", [item for item in sys.path if item not in family_roots])

    poisoned_extract = ModuleType("extract_config")
    poisoned_analysis = ModuleType("analyze_package_set")
    monkeypatch.setitem(sys.modules, "extract_config", poisoned_extract)
    monkeypatch.setitem(sys.modules, "analyze_package_set", poisoned_analysis)
    for module_name in (
        "_analysis_framework_malware_noodlerat_direct",
        "_analysis_framework_malware_noodlerat_direct.extract_config",
        "_analysis_framework_malware_noodlerat_direct.elf_utils",
        "_analysis_framework_malware_redc2_direct",
        "_analysis_framework_malware_redc2_direct.analyze_package_set",
    ):
        monkeypatch.delitem(sys.modules, module_name, raising=False)

    noodle = _load_direct_detector(noodle_root / "detect.py", "noodlerat_direct_spec_test")
    redc2 = _load_direct_detector(redc2_root / "detect.py", "redc2_direct_spec_test")

    assert family_roots.isdisjoint(sys.path)
    assert sys.modules["extract_config"] is poisoned_extract
    assert sys.modules["analyze_package_set"] is poisoned_analysis
    assert noodle._analyze.__module__ == "_analysis_framework_malware_noodlerat_direct.extract_config"
    assert redc2.payload_evidence.__module__ == ("_analysis_framework_malware_redc2_direct.analyze_package_set")
