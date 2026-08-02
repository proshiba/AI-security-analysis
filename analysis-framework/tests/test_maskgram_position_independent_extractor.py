from __future__ import annotations

import importlib.util
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT / "extractors" / "maskgram_stealer" / "extractor.py"
SPEC = importlib.util.spec_from_file_location("maskgram_position_independent", MODULE)
assert SPEC and SPEC.loader
extractor = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(extractor)


def test_extract_position_independent_layout() -> None:
    chunks = [b"MZ" + b"\0" * 31, extractor.KEY]
    for name, value in reversed(list(extractor.EXPECTED.items())):
        chunks.extend([name.encode("ascii"), extractor.encrypt_embedded(value.encode("ascii")), b"\xff"])
    data = b"".join(chunks)
    result = extractor.extract(data, "variant.exe")
    assert result["family"] == "MaskGramStealer"
    assert len(result["config_endpoints"]) == 3
    assert result["static_evidence"]["all_expected_fields_validated"] is True
    assert result["executed"] is False


def test_extract_rejects_missing_field() -> None:
    data = b"MZ" + extractor.KEY + extractor.encrypt_embedded(extractor.EXPECTED["telegram_host"].encode())
    try:
        extractor.extract(data)
    except ValueError as error:
        assert "暗号化設定値" in str(error)
    else:
        raise AssertionError("不完全設定を拒否しませんでした")
