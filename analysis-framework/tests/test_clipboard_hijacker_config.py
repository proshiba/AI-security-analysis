"""クリップボード置換コード系の静的設定抽出を検証する。"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest


MODULE_PATH = Path(__file__).resolve().parents[1] / "common" / "clipboard_hijacker_config.py"
SPEC = importlib.util.spec_from_file_location("clipboard_hijacker_config", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)


def test_xor_decoding_and_length_rejection() -> None:
    """鍵付き表を正しく復号し、切断したデータを拒否する。"""

    key = b"Ab9_"
    clear = b"bc1qexample"
    encoded = key + bytes(value ^ key[index % 4] for index, value in enumerate(clear))
    assert module.decode_xor_string(encoded, len(clear)) == clear
    with pytest.raises(module.ProfileMismatch):
        module.decode_xor_string(encoded[:-1], len(clear))
    with pytest.raises(module.ProfileMismatch):
        module.decode_xor_string(encoded, 104)


def test_unknown_code_cannot_be_promoted() -> None:
    """任意のPE断片を既知コード系として扱わない。"""

    with pytest.raises(module.ProfileMismatch):
        module.analyze_bytes(b"MZ" + b"\x00" * 100)


def test_cluster_keeps_distinct_configurations() -> None:
    """同じコードでも異なる設定を暗黙に結合しない。"""

    base = {
        "slots": [
            {"slot": 3, "status": "recovered", "asset": "bitcoin", "value": "bc1qexample"},
            {"slot": 4, "status": "disabled"},
        ]
    }
    items = [
        {**base, "sha256": "a" * 64, "config_sha256": "1" * 64},
        {**base, "sha256": "b" * 64, "config_sha256": "1" * 64},
        {**base, "sha256": "c" * 64, "config_sha256": "2" * 64},
    ]
    result = module.build_cluster(items)
    assert result["sample_count"] == 3
    assert result["config_profile_count"] == 2
    assert [group["sample_count"] for group in result["config_groups"]] == [2, 1]
    assert result["wallet_slot_counts"] == {"bitcoin": 3}
    with pytest.raises(ValueError):
        module.build_cluster(items + [items[0]])


def test_supplements_do_not_change_case_wide_artifacts(tmp_path: Path) -> None:
    """既存caseの完全性集合へ補足ファイルを混入させない。"""

    digest = "a" * 64
    case_root = tmp_path / "cases"
    case_dir = case_root / digest
    case_dir.mkdir(parents=True)
    output_root = tmp_path / "collection"
    item = {
        "sha256": digest,
        "code_section_sha256": "b" * 64,
        "config_sha256": "c" * 64,
        "wallet_count": 1,
        "slots": [{"slot": 3, "asset": "bitcoin", "status": "recovered"}],
    }
    module.write_case_supplements(case_root, output_root, [item])
    assert list(case_dir.iterdir()) == []
    assert (output_root / "supplements" / digest / "clipboard-config.json").is_file()
    assert (output_root / "supplements" / digest / "CLIPBOARD-ANALYSIS.md").is_file()
