"""GuLoaderのpackage importとanalysis contract依存範囲を検証する。"""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
from types import ModuleType

import pytest


FRAMEWORK = Path(__file__).resolve().parents[1]
REPOSITORY = FRAMEWORK.parent
COMMON = FRAMEWORK / "common"
CLASSIFIERS = FRAMEWORK / "classifiers"
REGISTRY = FRAMEWORK / "registry" / "malware_types.json"
for trusted in (REPOSITORY, FRAMEWORK, COMMON, CLASSIFIERS):
    value = str(trusted)
    if value not in sys.path:
        sys.path.insert(0, value)

import analyze_sample  # noqa: E402
import classify_sample  # noqa: E402
from analysis_contract import build_pipeline_fingerprint  # noqa: E402
from handler_catalog import (  # noqa: E402
    clear_handler_caches,
    discover_handlers,
    load_handler,
)


def _guloader_handler_spec():
    return next(
        item
        for item in discover_handlers()
        if item.family == "guloader"
        and item.relative_path.endswith("malware/guloader/extract_config.py")
    )


def test_clean_process_loads_detector_and_handler_without_family_sys_path() -> None:
    """family directoryをsys.pathへ追加しないclean processでも両moduleを読める。"""

    roots = [str(REPOSITORY), str(FRAMEWORK), str(COMMON), str(CLASSIFIERS)]
    script = f"""
import json
from pathlib import Path
import sys
for value in {roots!r}:
    sys.path.insert(0, value)
import classify_sample
from handler_catalog import discover_handlers, load_handler
framework = Path({str(FRAMEWORK)!r})
detector = classify_sample.load_detector(
    framework, "malware/guloader/detect.py", "guloader"
)
spec = next(
    item for item in discover_handlers()
    if item.family == "guloader"
    and item.relative_path.endswith("malware/guloader/extract_config.py")
)
handler, invocation = load_handler(spec)
print(json.dumps({{
    "detector_matched": detector(b"plain fixture", Path("plain.bin"))["matched"],
    "handler_matched": handler(b"plain fixture")["matched"],
    "invocation": invocation,
}}))
"""
    completed = subprocess.run(
        [sys.executable, "-I", "-c", script],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert completed.returncode == 0, completed.stderr
    result = json.loads(completed.stdout)
    assert result == {
        "detector_matched": False,
        "handler_matched": False,
        "invocation": "bytes",
    }


def test_fake_top_level_structure_probe_cannot_collide(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """同名top-level moduleが存在してもpackage-qualified helperだけを使う。"""

    fake = ModuleType("structure_probe")

    def forbidden(*_args, **_kwargs):
        raise AssertionError("top-level structure_probe must not be used")

    fake.katheco_carrier = forbidden
    fake.katheco_script = forbidden
    fake.pe_layout = forbidden
    fake.whole_file_base64 = forbidden
    monkeypatch.setitem(sys.modules, "structure_probe", fake)
    classify_sample.load_detector.cache_clear()
    clear_handler_caches()

    detector = classify_sample.load_detector(
        FRAMEWORK,
        "malware/guloader/detect.py",
        "guloader",
    )
    handler, invocation = load_handler(_guloader_handler_spec())

    assert detector(b"plain fixture", Path("plain.bin"))["matched"] is False
    assert handler(b"plain fixture")["matched"] is False
    assert invocation == "bytes"
    assert sys.modules["structure_probe"] is fake


def test_analysis_contract_contains_all_malware_python_helpers(tmp_path: Path) -> None:
    """直接handler以外のmalware helperもpipeline fingerprintへ含める。"""

    components = analyze_sample._analysis_components(REGISTRY, discover_handlers())
    helper = (FRAMEWORK / "malware" / "guloader" / "structure_probe.py").resolve()
    assert helper in components
    malware_root = (FRAMEWORK / "malware").resolve()
    malware_components = [path for path in components if malware_root in path.parents]
    assert malware_components
    assert all("tests" not in path.parts for path in malware_components)
    assert all(not path.name.startswith("test_") for path in malware_components)

    copied = tmp_path / "structure_probe.py"
    copied.write_bytes(helper.read_bytes())
    first = build_pipeline_fingerprint(
        repository_root=tmp_path,
        components=[copied],
        settings={"mode": "test"},
    )
    copied.write_bytes(copied.read_bytes() + b"\n# contract change\n")
    second = build_pipeline_fingerprint(
        repository_root=tmp_path,
        components=[copied],
        settings={"mode": "test"},
    )
    assert first["sha256"] != second["sha256"]
