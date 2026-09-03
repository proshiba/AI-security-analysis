from __future__ import annotations

import copy
import importlib.util
import os
import sys
from pathlib import Path

import pytest

MODULE_PATH = (
    Path(__file__).resolve().parents[1]
    / "common"
    / "summarize_daily_news_static.py"
)
SPEC = importlib.util.spec_from_file_location("summarize_daily_news_static", MODULE_PATH)
assert SPEC and SPEC.loader
target = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = target
SPEC.loader.exec_module(target)


def _review_document(
    samples: list[dict],
    *,
    source_date: str = "2026-09-02",
) -> dict:
    return {
        "schema_version": 1,
        "review_type": "verified_static_evidence_supplement",
        "source_date": source_date,
        "safety": {
            "network_contacted": False,
            "online_revocation_checked": False,
            "raw_sample_published": False,
            "sample_executed": False,
        },
        "sample_count": len(samples),
        "samples": samples,
    }


def _verified_function_review(
    sha256: str,
    functions: list[dict[str, str]],
    *,
    source: str = "ghidra_mcp_static_review",
) -> dict:
    return {
        "sha256": sha256,
        "source": source,
        "functions": functions,
        "static_evidence": {
            "schema_version": 1,
            "status": "verified",
            "source": "verified_static_review_supplement",
            "authenticode": {
                "present": False,
                "verified": False,
                "verification_status": "not_present",
                "online_revocation_checked": False,
            },
            "pe_version": {},
            "exports": {"items": []},
            "imports": {"modules": {}},
        },
    }


class _SyntheticDirEntry:
    def __init__(self, name: str, root: Path) -> None:
        self.name = name
        self.path = str(root / name)

    def is_dir(self, *, follow_symlinks: bool) -> bool:
        assert follow_symlinks is False
        return False


class _SyntheticScandir:
    def __init__(self, entries: list[_SyntheticDirEntry]) -> None:
        self._entries = entries

    def __enter__(self):
        return iter(self._entries)

    def __exit__(self, *_args) -> None:
        return None


def test_legacy_case_enumeration_is_bounded_before_sort(
    tmp_path: Path,
    monkeypatch,
) -> None:
    case_root = tmp_path / "cases"
    case_root.mkdir()
    ioc_csv = tmp_path / "iocs.csv"
    ioc_csv.write_text("ioc_type,ioc_value\n", encoding="utf-8")
    monkeypatch.setattr(target, "MAX_SUMMARY_CASES", 2)
    entries = [_SyntheticDirEntry(str(index), case_root) for index in range(3)]
    monkeypatch.setattr(target.os, "scandir", lambda _path: _SyntheticScandir(entries))

    try:
        target.build_summary(case_root, ioc_csv, "2026-08-23")
    except ValueError as error:
        assert "件数" in str(error)
        assert str(tmp_path) not in str(error)
    else:
        raise AssertionError("case上限+1件目が拒否されませんでした")


def test_legacy_case_enumeration_accepts_exact_limit(
    tmp_path: Path,
    monkeypatch,
) -> None:
    case_root = tmp_path / "cases"
    case_root.mkdir()
    ioc_csv = tmp_path / "iocs.csv"
    ioc_csv.write_text("ioc_type,ioc_value\n", encoding="utf-8")
    monkeypatch.setattr(target, "MAX_SUMMARY_CASES", 2)
    entries = [_SyntheticDirEntry(str(index), case_root) for index in range(2)]
    monkeypatch.setattr(target.os, "scandir", lambda _path: _SyntheticScandir(entries))

    assert target.build_summary(case_root, ioc_csv, "2026-08-23")["sample_count"] == 0


def test_legacy_case_root_reparse_or_identity_change_is_redacted(
    tmp_path: Path,
    monkeypatch,
) -> None:
    case_root = tmp_path / "cases"
    case_root.mkdir()
    ioc_csv = tmp_path / "iocs.csv"
    ioc_csv.write_text("ioc_type,ioc_value\n", encoding="utf-8")
    monkeypatch.setattr(target.analysis_contract, "_same_file_identity", lambda *_args: False)

    try:
        target.build_summary(case_root, ioc_csv, "2026-08-23")
    except ValueError as error:
        assert str(tmp_path) not in str(error)
    else:
        raise AssertionError("case root identity変更が拒否されませんでした")

    link = tmp_path / "case-link"
    try:
        os.symlink(case_root, link, target_is_directory=True)
    except OSError:
        return
    try:
        target.build_summary(link, ioc_csv, "2026-08-23")
    except ValueError as error:
        assert str(tmp_path) not in str(error)
    else:
        raise AssertionError("case root reparse pointが拒否されませんでした")


def test_capability_requires_observed_import() -> None:
    triage = {
        "pe": {
            "imports": {
                "KERNEL32.dll": [
                    "CreateProcessW",
                    "IsDebuggerPresent",
                    "FindFirstFileW",
                ],
                "GDI32.dll": ["BitBlt"],
            }
        }
    }

    capabilities = {
        item["id"]: item for item in target.infer_capabilities(triage)
    }

    assert capabilities["process_execution"]["evidence_imports"] == ["createprocessw"]
    assert capabilities["anti_analysis_surface"]["evidence_imports"] == [
        "isdebuggerpresent"
    ]
    assert capabilities["screen_capture"]["evidence_imports"] == ["bitblt"]
    assert "network_client" not in capabilities
    assert all(
        item["confidence"] == "import_surface_only"
        for item in capabilities.values()
    )


def test_imports_are_case_insensitive() -> None:
    triage = {
        "pe": {
            "imports": {
                "WS2_32.dll": ["WSAStartup"],
                "ADVAPI32.dll": ["RegSetValueExW"],
            }
        }
    }

    ids = {item["id"] for item in target.infer_capabilities(triage)}

    assert ids == {"network_client", "registry_change"}


def test_function_review_rejects_duplicate_sample_sha256() -> None:
    digest = "a" * 64
    review = _verified_function_review(digest, [])
    document = _review_document([review, copy.deepcopy(review)])

    with pytest.raises(ValueError, match="SHA-256が重複"):
        target._function_reviews_document(document)


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (
            lambda document: document.update({"unexpected": True}),
            "top-level field集合",
        ),
        (
            lambda document: document.update({"review_type": "unverified_review"}),
            "schema種別",
        ),
        (
            lambda document: document.update({"schema_version": 2}),
            "schema version",
        ),
        (
            lambda document: document.update({"source_date": "2026/09/02"}),
            "source date",
        ),
        (
            lambda document: document["safety"].update({"sample_executed": True}),
            "安全status",
        ),
        (
            lambda document: document["samples"][0].update({"raw": "private"}),
            "sampleのfield集合",
        ),
        (
            lambda document: document["samples"][0]["static_evidence"].update(
                {"status": "draft"}
            ),
            "検証status",
        ),
        (
            lambda document: document["samples"][0].update(
                {"source": r"C:\Users\Analyst\review.json"}
            ),
            "絶対path",
        ),
        (
            lambda document: document["samples"][0].update({"source": "a" * 257}),
            "容量上限",
        ),
    ],
)
def test_function_review_document_schema_and_source_fail_closed(
    mutate,
    message: str,
) -> None:
    document = _review_document([_verified_function_review("b" * 64, [])])
    mutate(document)

    with pytest.raises((TypeError, ValueError), match=message):
        target._function_reviews_document(document)


def test_function_review_source_date_is_bound_to_summary_date() -> None:
    document = _review_document([_verified_function_review("d" * 64, [])])

    with pytest.raises(ValueError, match="source dateが一致"):
        target._function_reviews_document(
            document,
            expected_source_date="2026-09-01",
        )


def _one_function_review_document() -> dict:
    return _review_document(
        [
            _verified_function_review(
                "c" * 64,
                [
                    {
                        "address": "00401000",
                        "name": "FUN_00401000",
                        "role": "設定復元",
                        "evidence": "入力bufferを検証して設定構造へ格納する。",
                    }
                ],
            )
        ]
    )


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (
            lambda function: function.update({"pseudocode": "return 0;"}),
            "関数のfield集合",
        ),
        (
            lambda function: function.update({"address": "ram:00401000"}),
            "16進address",
        ),
        (
            lambda function: function.update({"name": "main()"}),
            "許可済み識別子",
        ),
        (
            lambda function: function.update({"role": "設定\n復元"}),
            "制御文字",
        ),
        (
            lambda function: function.update(
                {"evidence": r"C:\Users\Analyst\private\decomp.cを参照した。"}
            ),
            "絶対path",
        ),
        (
            lambda function: function.update(
                {"evidence": "void FUN_00401000(void) { return 0; }"}
            ),
            "生の逆コンパイル本文",
        ),
        (
            lambda function: function.update({"evidence": "あ" * 683}),
            "容量上限",
        ),
    ],
)
def test_function_review_fields_and_raw_decompilation_fail_closed(
    mutate,
    message: str,
) -> None:
    document = _one_function_review_document()
    mutate(document["samples"][0]["functions"][0])

    with pytest.raises((TypeError, ValueError), match=message):
        target._function_reviews_document(document)


def test_function_review_count_and_duplicate_function_fail_closed() -> None:
    document = _one_function_review_document()
    function = document["samples"][0]["functions"][0]
    document["samples"][0]["functions"] = [
        {**function, "address": f"{index + 1:08x}"}
        for index in range(target.MAX_REVIEWED_FUNCTIONS_PER_SAMPLE + 1)
    ]
    with pytest.raises(ValueError, match="上限内のlist"):
        target._function_reviews_document(document)

    duplicate = _one_function_review_document()
    duplicate["samples"][0]["functions"].append(
        copy.deepcopy(duplicate["samples"][0]["functions"][0])
    )
    with pytest.raises(ValueError, match="関数が重複"):
        target._function_reviews_document(duplicate)


def test_sha1_provider_alias_labels_elf_case(tmp_path: Path) -> None:
    sha1 = "a" * 40
    sha256 = "b" * 64
    ioc_csv = tmp_path / "iocs.csv"
    ioc_csv.write_text(
        "ioc_type,ioc_value,malware,malware_type\n"
        f"file_hash_sha1,{sha1},Dysphoria,botnet\n",
        encoding="utf-8",
    )
    lookups = tmp_path / "lookups.json"
    lookups.write_text(
        __import__("json").dumps({
            "items": [{
                "digest": sha1,
                "hash_type": "sha1",
                "reported_malware": "Dysphoria",
                "found": True,
                "metadata": {"sha1_hash": sha1, "sha256_hash": sha256},
            }]
        }),
        encoding="utf-8",
    )
    case = tmp_path / "cases" / sha256
    case.mkdir(parents=True)
    (case / "generic-triage.json").write_text(
        __import__("json").dumps({
            "sha256": sha256,
            "type": "elf",
            "size": 1234,
            "entropy": 5.4,
            "magic": "7f454c46",
            "elf": {"machine": 40, "bits": 32, "byte_order": "little", "entry_point": "0x8000"},
            "analysis_coverage": {"status": "complete"},
        }),
        encoding="utf-8",
    )
    (case / "static-logic.json").write_text(
        __import__("json").dumps({
            "status": "function_analysis_required",
            "coverage": {"function_count": 0, "call_edge_count": 0, "function_bodies_reviewed": False},
            "limitations": [],
        }),
        encoding="utf-8",
    )

    reviews = tmp_path / "reviews.json"
    reviews.write_text(
        __import__("json").dumps(
            _review_document(
                [
                    _verified_function_review(
                        sha256,
                        [
                            {
                                "address": "0x1000",
                                "name": "main",
                                "role": "起動入口",
                                "evidence": "静的に確認した関数入口である。",
                            }
                        ],
                        source="ghidra_mcp",
                    )
                ],
                source_date="2026-07-29",
            )
        ),
        encoding="utf-8",
    )
    summary = target.build_summary(
        tmp_path / "cases", ioc_csv, "2026-07-29", lookups, reviews
    )

    assert summary["counts"]["elf"] == 1
    assert summary["samples"][0]["reported_malware"] == "Dysphoria"
    assert summary["samples"][0]["source_hash"] == sha1
    assert summary["counts"]["function_analysis_complete"] == 1
    assert summary["counts"]["function_analysis_required"] == 0
    assert summary["samples"][0]["function_review_source"] == "ghidra_mcp"
    markdown = target.render_markdown(summary)
    assert "Dysphoria" in markdown
    assert "NukeSped" not in markdown
    assert "特徴関数レビュー" in markdown
    assert "`main`" in markdown


def _pe_case_document(sha256: str, imports: dict[str, list[str]]) -> dict:
    return {
        "sha256": sha256,
        "generic_triage": {
            "sha256": sha256,
            "type": "pe",
            "size": 4096,
            "entropy": 5.0,
            "magic": "4d5a",
            "pe": {
                "machine": "0x14c",
                "entry_point_rva": "0x1000",
                "imports": imports,
                "is_dotnet": False,
            },
            "analysis_coverage": {"status": "complete"},
        },
        "static_logic": {
            "status": "function_analysis_required",
            "coverage": {
                "function_count": 0,
                "call_edge_count": 0,
                "function_bodies_reviewed": False,
            },
            "limitations": ["代表関数の追加レビューが必要"],
        },
    }


def _netsupport_review(
    sha256: str,
    *,
    original_filename: str,
    product_name: str,
    file_description: str,
    exports: list[str],
    imports: dict[str, list[str]],
    verification_status: str = "VERIFICATION_FLAGS.OK",
) -> dict:
    return {
        "sha256": sha256,
        "source": "ghidra_mcp_and_lief_static_review",
        "functions": [],
        "static_evidence": {
            "schema_version": 1,
            "status": "verified",
            "source": "verified_static_review_supplement",
            "authenticode": {
                "present": True,
                "verified": True,
                "verification_status": verification_status,
                "signer_subject": "CN=NetSupport Ltd, O=NetSupport Ltd",
                "verification_tool": "LIEF",
                "verification_scope": "offline_authenticode_integrity",
                "online_revocation_checked": False,
            },
            "pe_version": {
                "CompanyName": "NetSupport Ltd",
                "ProductName": product_name,
                "FileDescription": file_description,
                "OriginalFilename": original_filename,
                "FileVersion": "12.01",
            },
            "exports": {"items": exports},
            "imports": {"modules": imports},
        },
    }


def test_authenticode_signer_subject_redacts_embedded_email() -> None:
    normalized = target._normalize_authenticode(
        {
            "present": True,
            "verified": True,
            "verification_status": "VERIFICATION_FLAGS.OK",
            "signer_subject": (
                "C=GB, O=NETSUPPORT LTD., CN=NETSUPPORT LTD., "
                "emailAddress=is@netsupportsoftware.com"
            ),
            "online_revocation_checked": False,
        }
    )

    assert normalized["verified"] is True
    assert normalized["signer_subject"] == (
        "C=GB, O=NETSUPPORT LTD., CN=NETSUPPORT LTD., "
        "emailAddress=[redacted-email]"
    )


def test_verified_netsupport_components_are_not_promoted_as_unknown_malware_or_c2() -> None:
    profiles = [
        {
            "sha256": "1" * 64,
            "original_filename": "AudioCaptureWVI.dll",
            "product_name": "NetSupport Audio Capture",
            "file_description": "NetSupport Audio Capture",
            "exports": ["IsCapturing -> 00401000", "StartCapturing", "StopCapturing"],
            "imports": {"KERNEL32.dll": ["CreateThread"]},
            "role": "netsupport_audio_capture_module",
        },
        {
            "sha256": "2" * 64,
            "original_filename": "pcicapi.dll",
            "product_name": "NetSupport Manager",
            "file_description": "NetSupport CAPI Interface",
            "exports": ["CapiOpen", "CapiDial", "CapiSend", "CapiRead"],
            "imports": {"KERNEL32.dll": ["LoadLibraryA"]},
            "role": "netsupport_capi_transport_module",
        },
        {
            "sha256": "3" * 64,
            "original_filename": "client32.exe",
            "product_name": "NetSupport Remote Control",
            "file_description": "NetSupport Client32",
            "exports": [],
            "imports": {"PCICL32.dll": ["_NSMClient32@8"]},
            "role": "netsupport_remote_control_client_bootstrap",
        },
        {
            "sha256": "4" * 64,
            "original_filename": "remcmdstub.exe",
            "product_name": "NetSupport Manager",
            "file_description": "NetSupport Remote Command Prompt",
            "exports": [],
            "imports": {"KERNEL32.dll": ["CreateProcessA", "GetCommandLineA"]},
            "role": "netsupport_remote_command_stub",
        },
    ]
    documents = [
        _pe_case_document(item["sha256"], item["imports"])
        for item in profiles
    ]
    reviews = _review_document(
        [
            _netsupport_review(
                item["sha256"],
                original_filename=item["original_filename"],
                product_name=item["product_name"],
                file_description=item["file_description"],
                exports=item["exports"],
                imports=item["imports"],
            )
            for item in profiles
        ]
    )
    rows = [
        {
            "ioc_type": "file_hash_sha256",
            "ioc_value": item["sha256"],
            "malware": "NetSupport Manager",
            "malware_type": "RAT",
            "category": "abusefile",
            "reference": "https://example.invalid/campaign-report",
            "description": "攻撃チェーンで配置された正規コンポーネント。",
            "confidence": "medium",
        }
        for item in profiles
    ]

    summary = target.build_summary_from_documents(
        documents,
        rows,
        "2026-09-02",
        provider_document=None,
        input_commitment={"source_date": "2026-09-02"},
        function_review_document=reviews,
    )

    assert [item["component_role"]["id"] for item in summary["samples"]] == [
        item["role"] for item in profiles
    ]
    for sample in summary["samples"]:
        assert sample["software_identity"]["status"] == "verified_vendor_component"
        assert sample["software_identity"]["authenticode"]["verified"] is True
        assert sample["component_role"]["status"] == "verified"
        assert sample["campaign_abuse_context"]["relationship"] == (
            "verified_dual_use_component_reported_in_campaign"
        )
        assert sample["maliciousness"]["status"] == (
            "not_established_for_verified_dual_use_component"
        )
        assert sample["maliciousness"]["unknown_malware_body_confirmed"] is False
        assert sample["maliciousness"]["standalone_c2_confirmed"] is False
        assert sample["maliciousness"]["promotion_decision"] == (
            "do_not_promote_as_unknown_malware_or_c2"
        )
    markdown = target.render_markdown(summary)
    assert "ソフトウェア識別・役割・悪用文脈・悪性の分離" in markdown
    assert "未知マルウェア本体やC2へ昇格しない" in markdown
    assert "NetSupportのISDN CAPIトランスポート用モジュール" in markdown


def test_provider_netsupport_signed_tags_do_not_replace_verified_static_evidence() -> None:
    sha256 = "a" * 64
    document = _pe_case_document(
        sha256,
        {"PCICL32.dll": ["_NSMClient32@8"]},
    )
    provider = {
        "source_date": "2026-09-02",
        "items": [{
            "digest": sha256,
            "sha256": sha256,
            "reported_malware": "NetSupport Manager",
            "metadata": {
                "sha256_hash": sha256,
                "signature": "NetSupport Ltd",
                "tags": ["signed", "NetSupport"],
                "file_name": "client32.exe",
            },
        }],
    }

    summary = target.build_summary_from_documents(
        [document],
        [{
            "ioc_type": "file_hash_sha256",
            "ioc_value": sha256,
            "malware": "NetSupport Manager",
            "malware_type": "RAT",
        }],
        "2026-09-02",
        provider_document=provider,
        input_commitment={"source_date": "2026-09-02"},
    )
    sample = summary["samples"][0]

    assert sample["reported_malware"] == "NetSupport Manager"
    assert sample["software_identity"]["status"] == "unresolved"
    assert sample["software_identity"]["authenticode"]["present"] is None
    assert sample["component_role"]["status"] == "unresolved"
    assert sample["maliciousness"]["status"] == "unresolved"
    assert sample["maliciousness"]["promotion_decision"] == (
        "withhold_pending_direct_static_evidence"
    )


def test_verified_identity_without_role_markers_remains_unresolved() -> None:
    sha256 = "b" * 64
    document = _pe_case_document(sha256, {"KERNEL32.dll": ["CreateThread"]})
    review = _netsupport_review(
        sha256,
        original_filename="AudioCaptureWVI.dll",
        product_name="NetSupport Audio Capture",
        file_description="NetSupport Audio Capture",
        exports=["Initialise", "UnInitialise"],
        imports={"KERNEL32.dll": ["CreateThread"]},
    )

    summary = target.build_summary_from_documents(
        [document],
        [],
        "2026-09-02",
        provider_document=None,
        input_commitment={"source_date": "2026-09-02"},
        function_review_document=_review_document([review]),
    )
    sample = summary["samples"][0]

    assert sample["software_identity"]["status"] == "verified_vendor_component"
    assert sample["component_role"]["status"] == "unresolved"
    assert "export:startcapturing" in sample["component_role"]["missing_evidence"]
    assert sample["maliciousness"]["status"] == "unresolved"


def test_authenticode_hash_mismatch_fails_closed() -> None:
    sha256 = "c" * 64
    imports = {"KERNEL32.dll": ["CreateProcessA", "GetCommandLineA"]}
    document = _pe_case_document(sha256, imports)
    review = _netsupport_review(
        sha256,
        original_filename="remcmdstub.exe",
        product_name="NetSupport Manager",
        file_description="NetSupport Remote Command Prompt",
        exports=[],
        imports=imports,
        verification_status="HASH_MISMATCH",
    )

    summary = target.build_summary_from_documents(
        [document],
        [],
        "2026-09-02",
        provider_document=None,
        input_commitment={"source_date": "2026-09-02"},
        function_review_document=_review_document([review]),
    )
    sample = summary["samples"][0]

    assert sample["software_identity"]["authenticode"]["verified"] is False
    assert sample["software_identity"]["status"] == "unresolved"
    assert "verified_authenticode" in sample["software_identity"]["missing_evidence"]
    assert sample["component_role"]["status"] == "unresolved"
    assert sample["maliciousness"]["promotion_decision"] == (
        "withhold_pending_direct_static_evidence"
    )
