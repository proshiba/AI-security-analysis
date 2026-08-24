"""RedC2 npm package静的解析器の安全境界とloader判定を検証する。"""
from __future__ import annotations
from io import BytesIO
import importlib.util
import json
from pathlib import Path
import tarfile
import pytest

FRAMEWORK = Path(__file__).parents[1]
def load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path); assert spec and spec.loader
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module); return module
ANALYZER = load_module(FRAMEWORK / "malware" / "redc2" / "analyze_package_set.py", "redc2_analyzer")
DETECTOR = load_module(FRAMEWORK / "malware" / "redc2" / "detect.py", "redc2_detector")

def make_tar(*, chmod: bool = True, mode: int = 0o644, unsafe_name: str | None = None) -> bytes:
    payload = b"\x7fELF" + b"\x02\x01\x01" + b"\0" * 57; expected = ANALYZER.sha256_bytes(payload)
    loader = ("import cp from 'node:child_process'; import fs from 'node:fs';\n(async () => {\n" +
              f"const expectedHash = '{expected}';\n" + ("fs.chmodSync(binaryPath, 0o755);\n" if chmod else "") +
              "cp.spawn(binaryPath, [], {detached: true, shell: false, stdio: 'pipe'});\n})();").encode()
    files = {"package/package.json": json.dumps({"name": "fixture", "version": "1.0.0", "type": "module"}).encode(),
             "package/dist/index.mjs": loader, unsafe_name or "package/dist/internal/calc.bin": payload}
    stream = BytesIO()
    with tarfile.open(fileobj=stream, mode="w:gz") as archive:
        for name, content in files.items():
            info = tarfile.TarInfo(name); info.size = len(content); info.mode = mode if content is payload else 0o644; archive.addfile(info, BytesIO(content))
    return stream.getvalue()

def test_loader_viability_accounts_for_chmod_and_mode() -> None:
    assert ANALYZER.analyze_package("a.tgz", make_tar(chmod=True))["loader"]["normal_install_execution_viable"] is True
    assert ANALYZER.analyze_package("b.tgz", make_tar(chmod=False))["loader"]["normal_install_execution_viable"] is False
    assert ANALYZER.analyze_package("c.tgz", make_tar(chmod=False, mode=0o755))["loader"]["normal_install_execution_viable"] is True

def test_tar_path_traversal_is_rejected() -> None:
    with pytest.raises(ANALYZER.ArchiveValidationError, match="unsafe archive member path"):
        ANALYZER.analyze_package("unsafe.tgz", make_tar(unsafe_name="../calc.bin"))

def test_detector_requires_exact_hash_or_complete_markers() -> None:
    assert DETECTOR.detect(b"\x7fELF" + b"".join(DETECTOR.MARKERS), Path("fixture"))["matched"] is True
    assert DETECTOR.detect(b"\x7fELFREDSHELL", Path("weak"))["matched"] is False
