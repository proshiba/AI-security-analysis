"""GuLoader静的復元facadeの適用判定とfail-closed動作を検証する。"""

from __future__ import annotations

import base64
import importlib.util
import json
from pathlib import Path
import re
import sys


FRAMEWORK = Path(__file__).parents[1]
COMMON = FRAMEWORK / "common"
GULOADER = FRAMEWORK / "malware" / "guloader"
for trusted in (COMMON, GULOADER):
    value = str(trusted)
    if value not in sys.path:
        sys.path.insert(0, value)

from analysis_contract import handler_result_quality  # noqa: E402
from handler_catalog import clear_handler_caches, discover_handlers, load_handler  # noqa: E402


SPEC = importlib.util.spec_from_file_location(
    "guloader_orchestration_facade_test_module",
    GULOADER / "extract_config.py",
)
assert SPEC and SPEC.loader
FACADE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(FACADE)


def _parent(extra: bytes = b"") -> bytes:
    return (
        b"function Katheco($value){$value};function prelab($value){$value};"
        b"$overpol=151775;$daug=15261;$path='Ovenly.Foa';"
        + (b"Katheco 'QQ==' 1;" * 10)
        + extra
    )


def _carrier() -> bytes:
    suffix = (
        b"function hubb{};function hesperideo{};"
        b"Katheco 'QQ==' 1;VirtualAlloc;" + (b"#" * 20_000)
    )
    return base64.b64encode((b"\x90" * 100_000) + suffix)


def _minimal_pe(extra: bytes = b"") -> bytes:
    data = bytearray(0x200)
    data[:2] = b"MZ"
    data[0x3C:0x40] = (0x80).to_bytes(4, "little")
    data[0x80:0x84] = b"PE\0\0"
    data[0x84:0x86] = (0x14C).to_bytes(2, "little")
    data[0x86:0x88] = (1).to_bytes(2, "little")
    data[0x94:0x96] = (0xE0).to_bytes(2, "little")
    data[0x98:0x9A] = (0x10B).to_bytes(2, "little")
    return bytes(data) + extra


def test_handler_discovery_marks_facade_automatic_with_strict_evidence() -> None:
    """family直下facadeを自動発見し、高い構造証拠閾値を維持する。"""

    clear_handler_caches()
    spec = next(
        item
        for item in discover_handlers()
        if item.family == "guloader" and item.relative_path.endswith("guloader/extract_config.py")
    )
    assert spec.automatic is True
    assert spec.input_formats == ("script", "data", "pe")
    assert spec.minimum_evidence_score >= 20_000
    handler, invocation = load_handler(spec)
    assert invocation == "bytes"
    assert handler(_parent())["recovery_entry_role"] == "katheco_parent_script"


def test_parent_and_carrier_are_structural_matches_but_do_not_claim_recovery() -> None:
    """対になる2 roleを識別しても、単一入力だけで完全復元済みにしない。"""

    for data, role in (
        (_parent(), "katheco_parent_script"),
        (_carrier(), "katheco_whole_file_base64_carrier"),
    ):
        result = FACADE.extract_config(data)
        assert result["matched"] is True
        assert result["family"] == "guloader"
        assert result["orchestration_applicability"]["status"] == "structural_match"
        assert result["orchestration_applicability"]["automatic_recovery_authorized"] is False
        assert result["static_config_recovered"] is False
        assert result["recovery_entry_role"] == role
        assert result["blockers"]
        quality = handler_result_quality(
            result, FACADE.HANDLER_CONTRACT["minimum_evidence_score"]
        )
        assert quality["tier_name"] == "structural_corroboration"
        assert quality["sufficient"] is True


def test_unrelated_base64_and_generic_pe_do_not_become_guloader() -> None:
    """全体Base64、MZ、一般loader APIだけではfamilyや復元roleを確定しない。"""

    values = (
        base64.b64encode(b"A" * 120_000),
        _minimal_pe(b"VirtualAlloc CallWindowProc EnumSystemLocales URL Password"),
        b"MZ GuLoader VirtualAlloc CallWindowProc",
    )
    for data in values:
        result = FACADE.extract_config(data)
        assert result["matched"] is False
        assert result["family"] is None
        assert result["orchestration_applicability"]["status"] == "not_matched"
        assert result["recovery_entry_role"] is None
        assert "marker_hits" not in result
        assert handler_result_quality(result)["sufficient"] is False


def test_facade_does_not_read_artifacts_or_publish_input_secrets(monkeypatch) -> None:
    """単一bytes以外を読まず、入力中の資格情報候補を結果へ転記しない。"""

    def forbidden(*_args, **_kwargs):
        raise AssertionError("filesystem access is not allowed")

    monkeypatch.setattr(Path, "read_bytes", forbidden)
    monkeypatch.setattr(Path, "read_text", forbidden)
    secret = b"operator-password-do-not-publish"
    result = FACADE.extract_config(_parent(b";$Password='" + secret + b"'"))
    rendered = json.dumps(result, ensure_ascii=False)
    assert secret.decode() not in rendered
    assert result["safety"]["filesystem_artifact_read"] is False
    assert result["safety"]["secret_material_published"] is False
    explanation = result["orchestration_applicability"]["explanation_ja"]
    assert re.search(r"[ぁ-んァ-ヶ一-龯]", explanation)
