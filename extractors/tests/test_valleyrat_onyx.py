"""ValleyRAT共通extractorのOnyx adapterをoffline fixtureで検証する。"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
FRAMEWORK_COMMON = REPOSITORY_ROOT / "analysis-framework" / "common"
for import_root in (REPOSITORY_ROOT, FRAMEWORK_COMMON):
    if str(import_root) not in sys.path:
        sys.path.insert(0, str(import_root))

from analysis_contract import handler_result_quality  # noqa: E402

from extractors.valleyrat.extractor import extract  # noqa: E402


def _load_fixture_module():
    path = REPOSITORY_ROOT / "unpackers" / "tests" / "test_onyx_qt_loader.py"
    spec = importlib.util.spec_from_file_location("valleyrat_onyx_fixtures", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


FIXTURES = _load_fixture_module()


def test_common_extractor_recovers_confirmed_onyx_endpoint() -> None:
    """3層復元と4 slot一致をtier 3の静的設定として返す。"""

    shellcode, _ = FIXTURES._terminal_config_fixture()
    result = extract(FIXTURES._fixture(shellcode), "offline-onyx.exe")

    assert result["config"]["variant"] == "onyx_qt_loader_terminal_component"
    assert result["config"]["static_config_recovered"] is True
    assert result["config"]["endpoints"] == ["utuhv.cn:8080"]
    assert result["config"]["onyx_qt_loader"]["repeated_slot_count"] == 4
    assert (
        result["config"]["onyx_qt_loader"]["terminal_family_attribution"]
        == "unresolved"
    )
    assert result["executed"] is False
    assert result["network_contacted"] is False
    assert handler_result_quality(result)["tier"] == 3


def test_common_extractor_rejects_outer_only_onyx_shape() -> None:
    """終端設定がないOnyx-like outerは静的設定へ昇格しない。"""

    result = extract(FIXTURES._fixture(b"\x90" * 128), "outer-only.exe")

    assert result["config"]["variant"] == "unresolved_variant"
    assert result["config"]["static_config_recovered"] is False
    assert result["config"]["endpoints"] == []
    assert handler_result_quality(result)["sufficient"] is False
