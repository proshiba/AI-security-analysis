"""clipboard DLL行動クラスタの自動解析と監査境界を確認する。"""

from __future__ import annotations

import ast
import sys
from pathlib import Path
from types import SimpleNamespace

import pefile
import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "common"))

from handler_catalog import (  # noqa: E402
    _REVIEWED_SOURCE_CALLS,
    _import_aliases,
    _reviewed_source_call_shape_allowed,
    discover_handlers,
    preflight_handler_for_assessment,
)
from malware.clipboard_replacement_dll import detect as detector  # noqa: E402
from malware.clipboard_replacement_dll import extract_config as extractor  # noqa: E402


API_IMPORTS = sorted(extractor.REQUIRED_CLIPBOARD_APIS)
STRINGS = [
    {"value": "bc1qg73sq2pz05hrcfdxul4kemq5kuew0wtekgzxxp", "pointer_slot_rva": "0x5018", "decoded_length": 42},
    {"value": "0x8b551258684d959831186A09e77F58367b1DF7b0", "pointer_slot_rva": "0x5020", "decoded_length": 42},
]


def _profile_stubs(monkeypatch: pytest.MonkeyPatch, *, apis: list[str] = API_IMPORTS, strings: list[dict[str, object]] = STRINGS) -> None:
    monkeypatch.setattr(extractor, "_pe_import_profile", lambda _data: {"x64_dll": True, "clipboard_imports": apis})
    monkeypatch.setattr(extractor, "recover_strings_from_bytes", lambda _data: {"status": "candidate_strings_recovered", "strings": strings})


def test_auto_handler_detects_behavior_without_vendor_or_c2_claim(monkeypatch: pytest.MonkeyPatch) -> None:
    _profile_stubs(monkeypatch)
    data = b"MZ" + b"\0" * 100
    result = detector.detect(data, Path("sample.dll"))
    extracted = extractor.extract_config(data)
    assert result["matched"] is True
    assert result["supports_family_attribution"] is False
    assert result["campaigns"][0]["attribution_scope"] == "component_handler_route"
    assert result["observations"]["remusstealer_body_confirmed"] is False
    assert extracted["family"] == "clipboard_replacement_dll"
    assert extracted["address_literal_candidates"] == STRINGS
    assert extracted["c2"] == []
    assert extracted["supports_family_attribution"] is False
    assert extracted["terminal_family_confirmed"] is False
    assert extracted["attribution_boundary"]["address_replacement_conditions_confirmed"] is False
    assert extracted["safety"] == {"sample_executed": False, "network_contacted": False}


@pytest.mark.parametrize("missing", ["GetClipboardData", "SetClipboardData", "GetClipboardSequenceNumber"])
def test_incomplete_api_set_fails_closed(monkeypatch: pytest.MonkeyPatch, missing: str) -> None:
    _profile_stubs(monkeypatch, apis=[item for item in API_IMPORTS if item != missing])
    assert detector.detect(b"MZ" + b"\0" * 100, Path("candidate.dll"))["matched"] is False


def test_one_xor_string_and_bad_pe_fail_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    _profile_stubs(monkeypatch, strings=STRINGS[:1])
    assert detector.detect(b"MZ" + b"\0" * 100, Path("candidate.dll"))["matched"] is False
    monkeypatch.setattr(extractor, "_pe_import_profile", lambda _data: (_ for _ in ()).throw(pefile.PEFormatError("invalid")))
    assert detector.detect(b"MZ" + b"\0" * 100, Path("candidate.dll"))["matched"] is False


def test_oversize_input_rejected_before_pe_parse(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(extractor, "_pe_import_profile", lambda _data: pytest.fail("PE parser must not run"))
    data = b"MZ" + b"\0" * (extractor.MAX_INPUT_BYTES - 1)
    assert extractor.profile_evidence(data)["reason"] == "invalid_or_oversize_input"


def test_pe_import_profile_requires_user32_and_amd64_dll(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeImage:
        FILE_HEADER = SimpleNamespace(Machine=0x8664, Characteristics=0x2022)
        OPTIONAL_HEADER = SimpleNamespace(Magic=0x20B)
        DIRECTORY_ENTRY_IMPORT = [
            SimpleNamespace(dll=b"USER32.dll", imports=[SimpleNamespace(name=name.encode()) for name in API_IMPORTS]),
            SimpleNamespace(dll=b"KERNEL32.dll", imports=[SimpleNamespace(name=b"SetClipboardData")]),
        ]

        def close(self) -> None:
            pass

    monkeypatch.setattr(extractor.pefile, "PE", lambda **_kwargs: FakeImage())
    assert extractor._pe_import_profile(b"MZ") == {"x64_dll": True, "clipboard_imports": API_IMPORTS}
    FakeImage.FILE_HEADER = SimpleNamespace(Machine=0x14C, Characteristics=0x2022)
    assert extractor._pe_import_profile(b"MZ")["x64_dll"] is False


def _shape(source: str, key: tuple[str, str, str]) -> bool:
    tree = ast.parse(source)
    scope = next(item for item in tree.body if isinstance(item, ast.FunctionDef))
    call = next(
        item for item in ast.walk(scope)
        if isinstance(item, ast.Call)
        and isinstance(item.func, ast.Attribute)
        and item.func.attr == key[2].split(".")[-1]
    )
    return _reviewed_source_call_shape_allowed(call, key[2], tree, scope, _import_aliases(tree), key=key)


def test_capstone_exception_is_source_and_receiver_scoped() -> None:
    key = ("analysis-framework/common/recover_clipboard_xor_strings.py", "reachable:recover_strings_from_bytes", "decoder.disasm")
    source = """import capstone
def recover_strings_from_bytes(data):
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    decoder.disasm(section.get_data(), base + int(section.VirtualAddress))
"""
    assert key in _REVIEWED_SOURCE_CALLS
    assert _shape(source, key) is True
    assert _shape(source.replace("capstone.Cs", "untrusted.Cs"), key) is False
    assert _shape(source.replace("section.get_data()", "other.read()"), key) is False
    assert ("analysis-framework/malware/other/extract_config.py", key[1], key[2]) not in _REVIEWED_SOURCE_CALLS


def test_pefile_cleanup_and_pointer_read_exceptions_require_in_memory_pe() -> None:
    cleanup = (
        "analysis-framework/malware/clipboard_replacement_dll/extract_config.py",
        "reachable:_pe_import_profile",
        "image.close",
    )
    source = """import pefile
def _pe_import_profile(data):
    image = pefile.PE(data=data, fast_load=False)
    image.close()
"""
    assert _shape(source, cleanup) is True
    assert _shape(source.replace("pefile.PE", "untrusted.PE"), cleanup) is False
    assert _shape(source.replace("fast_load=False", "fast_load=True"), cleanup) is False

    pointer = (
        "analysis-framework/common/recover_clipboard_xor_strings.py",
        "reachable:recover_strings_from_bytes",
        "image.get_qword_at_rva",
    )
    source = """import pefile
def recover_strings_from_bytes(data):
    image = pefile.PE(data=data, fast_load=False)
    image.get_qword_at_rva(slot)
"""
    assert _shape(source, pointer) is True
    assert _shape(source.replace("get_qword_at_rva(slot)", "get_qword_at_rva(user_rva)"), pointer) is False


def test_ror13_capstone_exception_requires_fixed_mode_branch() -> None:
    key = ("analysis-framework/common/recover_ror13_peb_api_hashes.py", "reachable:review_bytes", "decoder.disasm")
    source = """import capstone
def review_bytes(data):
    mode = capstone.CS_MODE_64 if image.FILE_HEADER.Machine == 0x8664 else capstone.CS_MODE_32
    decoder = capstone.Cs(capstone.CS_ARCH_X86, mode)
    decoder.disasm(section.get_data(), base + int(section.VirtualAddress))
"""
    assert key in _REVIEWED_SOURCE_CALLS
    assert _shape(source, key) is True
    assert _shape(source.replace("capstone.CS_MODE_32", "arbitrary_mode"), key) is False


def test_handler_catalog_discovers_constrained_static_handler() -> None:
    spec = next(item for item in discover_handlers() if item.family == "clipboard_replacement_dll" and item.automatic)
    assert spec.input_formats == ("pe",)
    assert spec.minimum_evidence_score == 20_000
    preflight = preflight_handler_for_assessment(spec, actual_format="pe", input_size=15_360)
    assert preflight["eligible"] is True, preflight["blockers"]
