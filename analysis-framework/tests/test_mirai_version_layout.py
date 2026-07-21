from __future__ import annotations

import importlib.util
import json
from pathlib import Path


COMMON = Path(__file__).resolve().parents[1] / "common"
SPEC = importlib.util.spec_from_file_location("result_layout", COMMON / "result_layout.py")
assert SPEC is not None and SPEC.loader is not None
result_layout = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(result_layout)


def test_embedded_mirai_bot_version_is_approved_version_evidence(tmp_path: Path) -> None:
    case = tmp_path / "case"
    case.mkdir()
    (case / "config.json").write_text(
        json.dumps({"configuration": {"bot_version": "1"}}),
        encoding="utf-8",
    )

    version = result_layout.resolve_malware_version(
        case,
        "mirai-derived-ens-doh-bot",
        tmp_path,
    )

    assert version["status"] == "confirmed"
    assert version["reported"] == "1"
    assert version["normalized_key"] == "v1"
    assert version["reason"] == "sample_embedded_bot_version"
