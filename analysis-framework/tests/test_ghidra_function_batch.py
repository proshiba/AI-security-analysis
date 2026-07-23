"""Ghidra MCP代表関数静的解析バッチの安全境界と正規化を確認する。"""

from __future__ import annotations

import hashlib
from pathlib import Path
import sys

import pytest


COMMON = Path(__file__).parents[1] / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

import ghidra_function_batch as target  # noqa: E402


class FakeClient:
    """pagination test用の最小Ghidra MCP client。"""

    def __init__(self, pages: list[list[dict[str, object]]]) -> None:
        self.pages = pages
        self.calls: list[tuple[str, dict[str, object]]] = []

    def get(self, endpoint: str, **query: object) -> dict[str, object]:
        """指定offsetに対応するpageを返す。"""

        self.calls.append((endpoint, query))
        offset = int(query["offset"])
        page_index = offset // target.FUNCTION_PAGE_SIZE
        values = self.pages[page_index] if page_index < len(self.pages) else []
        return {
            "functions": values,
            "count": sum(len(page) for page in self.pages),
            "total_matching": sum(len(page) for page in self.pages),
        }


def test_client_accepts_only_local_plain_http() -> None:
    """Ghidra MCP接続先をlocalhostの平文HTTPに限定する。"""

    assert target.GhidraMcpClient("http://127.0.0.1:8089").base_url == "http://127.0.0.1:8089"
    for value in (
        "https://127.0.0.1:8089",
        "http://192.0.2.1:8089",
        "http://user:secret@localhost:8089",
        "http://localhost:8089/?token=secret",
    ):
        with pytest.raises(ValueError):
            target.GhidraMcpClient(value)


def test_client_rejects_mcp_error_object(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """HTTP 200内のMCP error objectを成功扱いしない。"""

    class Response:
        """urlopen responseの最小fixture。"""

        def __enter__(self) -> "Response":
            return self

        def __exit__(self, *args: object) -> None:
            return None

        def read(self) -> bytes:
            return b'{"error":"Program not found"}'

    monkeypatch.setattr(target, "urlopen", lambda *args, **kwargs: Response())

    with pytest.raises(target.GhidraMcpError):
        target.GhidraMcpClient("http://127.0.0.1:8089").get(
            "/analysis_status",
            program="/Malware/Test/missing",
        )


def test_decompile_status_preserves_limits() -> None:
    """逆コンパイル成功、制約、空結果を別状態として残す。"""

    assert target._decompile_status("int f(void) { return 1; }")[0] == "succeeded"
    assert (
        target._decompile_status("/* WARNING: Control flow encountered bad instruction data */")[0]
        == "limited_bad_instruction_or_flow"
    )
    assert target._decompile_status("")[0] == "failed_empty"


def test_all_functions_uses_explicit_selector_and_paginates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """全pageを取得し、すべてのrequestへprogram selectorを渡す。"""

    monkeypatch.setattr(target, "FUNCTION_PAGE_SIZE", 2)
    client = FakeClient(
        [
            [{"address": "0x1000"}, {"address": "0x2000"}],
            [{"address": "0x3000"}],
        ]
    )

    functions = target._all_functions(client, "/Malware/Test/sample")

    assert [item["address"] for item in functions] == ["0x1000", "0x2000", "0x3000"]
    assert [call[1]["program"] for call in client.calls] == [
        "/Malware/Test/sample",
        "/Malware/Test/sample",
    ]


def test_all_endpoint_items_reads_until_terminal_page() -> None:
    """ページ件数が上限の倍数でも空の終端ページまで取得する。"""

    class ContentClient:
        def __init__(self, values: list[object], *, text: bool = False) -> None:
            self.values = values
            self.text = text
            self.calls: list[dict[str, object]] = []

        def get(self, endpoint: str, **query: object) -> object:
            self.calls.append(query)
            offset = int(query["offset"])
            limit = int(query["limit"])
            page = self.values[offset : offset + limit]
            if self.text:
                return "\n".join(str(value) for value in page)
            return page

    selector = "/Malware/Test/sample.quarantine.bin"
    list_client = ContentClient([{"name": f"api_{index}"} for index in range(4)])
    values, coverage = target._all_endpoint_items(
        list_client,
        "/list_imports",
        selector,
        page_size=2,
    )
    text_client = ContentClient([f"0x{index:x}: string_{index}" for index in range(3)], text=True)
    strings, string_coverage = target._all_endpoint_items(
        text_client,
        "/list_strings",
        selector,
        page_size=2,
    )

    assert len(values) == 4
    assert [call["offset"] for call in list_client.calls] == [0, 2, 4]
    assert coverage["page_count"] == 3
    assert coverage["terminal_short_page_observed"] is True
    assert strings == ["0x0: string_0", "0x1: string_1", "0x2: string_2"]
    assert string_coverage["item_count"] == 3
    assert all(call["program"] == selector for call in list_client.calls + text_client.calls)


def test_opcode_hash_inventory_records_unavailable_functions() -> None:
    """hash取得不能な関数も欠落させず状態付きで残す。"""

    selector = "/Malware/Test/sample.quarantine.bin"
    value = {
        "functions": [
            {"address": "0x1000", "hash": "b" * 64, "instruction_count": 8},
            {"address": "orphan", "hash": "c" * 64, "instruction_count": 4},
        ],
        "endpoint_returned": 2,
    }
    completed = target._complete_opcode_hash_inventory(
        value,
        [
            {"address": "0x1000", "name": "entry"},
            {"address": "0x2000", "name": "helper"},
        ],
        selector,
    )

    assert completed["returned"] == 2
    assert completed["all_functions_recorded"] is True
    assert completed["functions"][0]["hash_status"] == "available"
    assert completed["functions"][1]["hash_status"] == "unavailable_recorded"
    assert completed["functions"][1]["program_selector"] == selector
    assert completed["unmatched_response_rows"][0]["address"] == "orphan"


def test_decompile_all_respects_server_batch_limit_and_records_every_function(
    tmp_path: Path,
) -> None:
    """20件上限のbatchを3 workerで処理し、全関数をJSONLへ保存する。"""

    class DecompileClient:
        def __init__(self) -> None:
            self.calls: list[tuple[str, dict[str, object]]] = []

        def get(self, endpoint: str, **query: object) -> object:
            self.calls.append((endpoint, query))
            assert query["program"] == "/Malware/Test/sample.quarantine.bin"
            if endpoint == "/batch_decompile":
                addresses = str(query["functions"]).split(",")
                assert len(addresses) <= 20
                return {
                    address: f"void f_{address}(void) {{ return; }}"
                    for address in addresses
                }
            raise AssertionError(f"予期しないendpoint: {endpoint}")

    client = DecompileClient()
    functions = [
        {
            "address": f"0x{index:04x}",
            "name": f"function_{index}",
            "isExternal": False,
            "isThunk": False,
        }
        for index in range(45)
    ]
    raw_path = tmp_path / "decompilations.raw.jsonl"

    records = target._decompile_all(
        client,
        "/Malware/Test/sample.quarantine.bin",
        functions,
        raw_path,
    )

    assert len(records) == 45
    assert len(target._read_jsonl_rows(raw_path)) == 45
    batch_calls = [call for call in client.calls if call[0] == "/batch_decompile"]
    assert len(batch_calls) == 3
    assert all(record["status"] == "succeeded" for record in records.values())


def test_program_records_keep_every_function_and_call_edge(tmp_path: Path) -> None:
    """内部関数とexternal関数を全件保持し、call edgeと制約を記録する。"""

    digest = "a" * 64
    selector = "/Malware/Test/sample.quarantine.bin"
    program = target.ProgramObject(
        sha256=digest,
        input_path=tmp_path / "sample.quarantine.bin",
        size=10,
        relationships=[
            {
                "case_sha256": digest,
                "depth": 0,
                "transform": "root",
            }
        ],
    )
    functions = [
        {
            "address": "0x1000",
            "name": "WinMain",
            "isExternal": False,
            "isThunk": False,
        },
        {
            "address": "0x2000",
            "name": "connect",
            "isExternal": True,
            "isThunk": False,
        },
    ]
    records = target._program_records(
        program,
        selector,
        functions,
        {
            "0x1000": {
                "status": "limited_bad_instruction_or_flow",
                "pseudocode": ("/* WARNING: Control flow encountered bad instruction data */\nconnect();"),
                "warnings": ["WARNING: Control flow encountered bad instruction data"],
            }
        },
        {
            "edges": [
                {
                    "caller_addr": "0x1000",
                    "callee_addr": "0x2000",
                    "callee_name": "connect",
                },
                {
                    "caller_addr": "0x1000",
                    "callee_addr": "external",
                    "callee_name": "InternetOpenW",
                },
            ]
        },
        {
            "functions": [
                {
                    "address": "0x1000",
                    "hash": "b" * 64,
                    "instruction_count": 12,
                }
            ]
        },
    )

    assert len(records) == 2
    assert all(item["program_selector"] == selector for item in records)
    assert set(records[0]["callees"]) == {
        f"{digest}:ghidra:0x2000",
        "InternetOpenW",
    }
    assert records[0]["api_calls"] == ["InternetOpenW"]
    assert records[0]["next_analysis"]
    assert records[1]["decompilation_status"] == "excluded_external_or_thunk"


def test_characteristic_selection_covers_roles_and_respects_limit() -> None:
    """入口・挙動役割・中心関数を選び、上限を超えない。"""

    functions = [
        {
            "address": f"0x{index:04x}",
            "name": name,
            "isExternal": False,
            "isThunk": False,
        }
        for index, name in enumerate(
            ["WinMain", "decrypt_config", "connect_server", "dispatch_command"]
            + [f"FUN_{index:04x}" for index in range(20)]
        )
    ]
    graph = {
        "edges": [
            {
                "caller_addr": "0x0000",
                "callee_addr": "0x0001",
                "callee_name": "decrypt_config",
            },
            {
                "caller_addr": "0x0001",
                "callee_addr": "0x0002",
                "callee_name": "connect_server",
            },
        ]
    }
    selected = target.select_characteristic_functions(
        functions,
        graph,
        "entry @ 0x0000 [Function]",
        {"functions": []},
        max_count=6,
    )

    assert len(selected) == 6
    assert {item["preliminary_role"] for item in selected} >= {
        "entrypoint",
        "config_or_data_transform",
        "network_communication",
        "command_dispatch_or_handler",
    }
    assert all(item["selection_reasons"] for item in selected)


def test_characteristic_selection_uses_structural_fallback_without_body() -> None:
    """内部関数がないprogramはexternalを構造代表とし、解析成功とは扱わない。"""

    records = [
        {
            "function_id": "sample:ghidra:external",
            "analysis_kind": "ghidra_native_or_loader_view",
            "decompilation_status": "excluded_external_or_thunk",
            "role": "external_api_or_thunk",
            "name": "external",
        }
    ]

    selected = target._mark_characteristic_records(records)

    assert selected == ["sample:ghidra:external"]
    assert records[0]["selected_for_characteristic_analysis"] is True
    assert "no_internal_body_structural_fallback" in records[0]["selection_reasons"]

def test_overall_logic_documents_phases_without_inventing_edges() -> None:
    """代表関数の役割を処理段階へ整理し、未観測edgeを生成しない。"""

    report = {
        "sha256": "a" * 64,
        "functions": [
            {
                "function_id": "entry",
                "role": "entrypoint",
                "function_analysis": {"decompilation_status": "succeeded"},
            },
            {
                "function_id": "network",
                "role": "network_communication",
                "function_analysis": {"decompilation_status": "succeeded"},
            },
        ],
        "call_edges": [],
    }

    overall = target._build_overall_logic(report)

    assert [item["phase_id"] for item in overall["phases"]] == ["startup", "communication"]
    assert overall["observed_call_edges"] == []
    assert "断定しません" in overall["phase_order_basis"]


def test_overall_logic_records_program_structure_when_no_function_body() -> None:
    """関数本体0件でも架空関数を作らずprogram構造限定結果を記録する。"""

    report = {
        "sha256": "a" * 64,
        "functions": [],
        "call_edges": [],
        "program_evidence": [
            {
                "program_selector": "/Malware/Test/sample",
                "entry_points": [{"name": "entry", "address": "0x1000"}],
                "imports": [{"name": "LoadLibraryW"}, {"name": "GetProcAddress"}],
            }
        ],
    }

    overall = target._build_overall_logic(report)

    assert overall["selected_function_count"] == 0
    assert overall["phases"][0]["phase_id"] == "program_structure"
    assert overall["phases"][0]["function_ids"] == []
    assert "2件のimport" in overall["phases"][0]["description_ja"]
    assert overall["phases"][1]["phase_id"] == "import_capability_execution"
    assert overall["phases"][1]["import_evidence"] == ["LoadLibraryW"]
    assert "関数本体" in overall["summary_ja"]


def test_program_evidence_parses_ghidra_entry_point_text() -> None:
    """Ghidraの@形式entry point応答をprogram evidenceへ保持する。"""

    result = {
        "sha256": "a" * 64,
        "program_selector": "/Malware/Test/sample",
        "relationships": [{"depth": 0}],
        "entry_points": (
            "entry @ 00401000 [Label] [external entry]\n"
            "IMAGE_DOS_HEADER_00400000 @ 00400000 [Label] [program entry]"
        ),
        "metadata": {},
        "functions": [],
        "opcode_hashes": {"functions": []},
        "imports": [],
    }

    evidence = target._program_evidence(result)

    assert [item["address"] for item in evidence["entry_points"]] == [
        "00401000",
        "00400000",
    ]


def test_markdown_does_not_publish_raw_pseudocode() -> None:
    """人向け要約へ生の逆コンパイル本文を出さない。"""

    report = {
        "sha256": "a" * 64,
        "status": "characteristic_function_static_analysis_complete",
        "coverage": {
            "ghidra_program_count": 1,
            "ghidra_function_inventory_count": 1,
            "managed_method_inventory_count": 0,
            "ghidra_programs_with_valid_mcp_responses": 1,
            "function_inventory_count": 1,
            "discovered_function_inventory_count": 5,
            "characteristic_function_selected_count": 1,
            "decompilation_attempted_count": 1,
            "decompilation_succeeded_count": 1,
            "decompilation_limited_or_failed_count": 0,
            "decompilation_excluded_count": 0,
            "call_edge_count": 0,
        },
        "program_evidence": [
            {
                "program_selector": "/Malware/Test/sample",
                "relationship": "root_program",
                "function_count": 1,
                "ghidra_function_count": 1,
                "managed_method_count": 0,
                "mcp_responses_valid": True,
                "function_hashes": [],
            }
        ],
        "functions": [
            {
                "function_id": "a:ghidra:0x1000",
                "role": "entrypoint",
                "address_or_token": "0x1000",
                "summary_ja": "入口関数です。",
                "logic_steps_ja": ["初期化します。\n続行します。"],
                "callers": [],
                "callees": [],
                "api_calls": ["LineOne\nLineTwo"],
                "pseudocode": "SECRET_RAW_PSEUDOCODE",
                "selection": {"selected": True, "reasons": ["entry_point"]},
                "function_analysis": {
                    "decompilation_status": "succeeded",
                    "next_analysis": "",
                },
            }
        ],
    }

    rendered = target._render_markdown(report)

    assert "SECRET_RAW_PSEUDOCODE" not in rendered
    assert "LineOne LineTwo" in rendered
    assert "LineOne\nLineTwo" not in rendered
    assert "初期化します。 続行します。" in rendered
    assert "初期化します。\n続行します。" not in rendered
    assert "発見関数／メソッドinventory: 5" in rendered
    assert "選定理由" in rendered


def test_private_artifact_validation_requires_all_selected_static_results(
    tmp_path: Path,
) -> None:
    """全代表関数の本文と選定CIL本体が保存された場合だけ完了とする。"""

    digest = "a" * 64
    selector = "/Malware/Test/sample.quarantine.bin"
    object_dir = tmp_path / "objects" / digest
    object_dir.mkdir(parents=True)
    result = {
        "sha256": digest,
        "mcp_responses_valid": True,
        "all_static_analysis_content_retained": True,
        "call_graph_augmented_from_decompilation": True,
        "program_selector": selector,
        "imports": [],
        "exports": [],
        "segments": [],
        "retrieval_coverage": {
            name: {
                "endpoint": f"/list_{name}",
                "program_selector": selector,
                "page_size": 1000,
                "page_count": 1,
                "item_count": 0,
                "terminal_short_page_observed": True,
                "complete": True,
            }
            for name in ("imports", "exports", "strings", "segments")
        },
        "ghidra_function_inventory_count": 2,
        "managed_method_count": 1,
        "function_inventory_count": 3,
        "characteristic_function_ids": [
            f"{digest}:ghidra:0x1000",
            f"{digest}:cil:0x06000001",
        ],
        "characteristic_function_count": 2,
        "functions": [
            {
                "function_id": f"{digest}:ghidra:0x1000",
                "address": "0x1000",
                "analysis_kind": "ghidra_native_or_loader_view",
                "selected_for_characteristic_analysis": True,
                "selection_reasons": ["entry_point"],
            },
            {
                "function_id": f"{digest}:ghidra:0x2000",
                "address": "0x2000",
                "analysis_kind": "ghidra_native_or_loader_view",
                "selected_for_characteristic_analysis": False,
            },
            {
                "function_id": f"{digest}:cil:0x06000001",
                "token": "0x06000001",
                "analysis_kind": "managed_cil",
                "decompilation_status": "succeeded",
                "selected_for_characteristic_analysis": True,
                "selection_reasons": ["role:entrypoint"],
            },
        ],
    }
    target._json_dump(object_dir / "program-result.json", result)
    target._json_dump(
        object_dir / "ghidra-raw-index.json",
        {
            "program_selector": selector,
            "metadata": {},
            "analysis_status": {},
            "functions": [
                {
                    "address": "0x1000",
                    "isExternal": False,
                    "isThunk": False,
                },
                {
                    "address": "0x2000",
                    "isExternal": True,
                    "isThunk": False,
                },
            ],
            "call_graph": {},
            "imports": [],
            "exports": [],
            "strings": [],
            "segments": [],
            "entry_points": [],
            "anti_analysis": [],
            "api_call_chains": [],
            "opcode_hashes": {
                "functions": [
                    {"address": "0x1000", "hash": "b" * 64, "instruction_count": 1, "hash_status": "available", "program_selector": selector},
                    {"address": "0x2000", "hash": "c" * 64, "instruction_count": 1, "hash_status": "available", "program_selector": selector},
                ],
                "returned": 2,
                "total_matching": 2,
                "all_functions_recorded": True,
            },
            "all_static_analysis_content_retained": True,
            "characteristic_function_ids": [
                f"{digest}:ghidra:0x1000",
                f"{digest}:cil:0x06000001",
            ],
            "characteristic_selection": [
                {"function_id": f"{digest}:ghidra:0x1000"},
                {"function_id": f"{digest}:cil:0x06000001"},
            ],
            "retrieval_coverage": {
                name: {
                    "endpoint": f"/list_{name}",
                    "program_selector": selector,
                    "page_size": 1000,
                    "page_count": 1,
                    "item_count": 0,
                    "terminal_short_page_observed": True,
                    "complete": True,
                }
                for name in ("imports", "exports", "strings", "segments")
            },
        },
    )
    target._append_jsonl(
        object_dir / "decompilations.raw.jsonl",
        [
            {
                "address": "0x1000",
                "status": "succeeded",
                "pseudocode": "void f(void) {}",
                "program_selector": selector,
            }
        ],
    )
    target._append_jsonl(
        object_dir / "cil-instructions.raw.jsonl",
        [
            {
                "token": "0x06000001",
                "status": "succeeded",
                "instructions": [{"opcode": "ret"}],
            }
        ],
    )

    validation = target.validate_private_artifacts({digest: result}, tmp_path)

    assert validation["complete"] is True
    assert validation["totals"] == {
        "imports_items": 0,
        "exports_items": 0,
        "strings_items": 0,
        "segments_items": 0,
        "programs": 1,
        "native_functions": 2,
        "characteristic_native_decompilations": 1,
        "managed_methods": 1,
        "managed_method_bodies": 1,
    }

    (object_dir / "decompilations.raw.jsonl").unlink()
    validation = target.validate_private_artifacts({digest: result}, tmp_path)
    assert validation["complete"] is False
    assert "逆コンパイル行がない代表関数があります" in "\n".join(validation["programs"][0]["errors"])


def test_private_artifact_validation_rejects_empty_or_missing_programs(
    tmp_path: Path,
) -> None:
    """空集合と期待数未満の集合を完了扱いしない。"""

    empty = target.validate_private_artifacts(
        {},
        tmp_path,
        expected_program_count=128,
    )

    assert empty["complete"] is False
    assert "検証対象programがありません" in empty["global_errors"]
    assert "program数が期待値と一致しません" in "\n".join(empty["global_errors"])


def test_call_graph_augmentation_recovers_internal_import_and_unresolved_edges() -> None:
    """Ghidra graphが空でも逆コンパイルcall式から3種のedgeを復元する。"""

    digest = "a" * 64
    result = {
        "call_graph": {"edge_count": 0, "caller_count": 0, "edges": []},
        "imports": [{"address": "EXTERNAL:1", "name": "CreateFileW"}],
        "functions": [
            {
                "function_id": f"{digest}:ghidra:0x1000",
                "name": "entry",
                "address": "0x1000",
                "pseudocode": ("void entry(void) { helper(); CreateFileW(); indirect_target(); }"),
                "analysis_kind": "ghidra_native_or_loader_view",
            },
            {
                "function_id": f"{digest}:ghidra:0x2000",
                "name": "helper",
                "address": "0x2000",
                "pseudocode": "void helper(void) { return; }",
                "analysis_kind": "ghidra_native_or_loader_view",
            },
        ],
    }

    counts = target.augment_program_result_call_graph(result)

    assert counts == {
        "edges": 3,
        "ghidra_edges": 0,
        "internal_edges": 1,
        "import_edges": 1,
        "unresolved_edges": 1,
    }
    assert result["ghidra_call_graph"]["edge_count"] == 0
    assert result["call_graph"]["edge_count"] == 3
    assert result["call_graph_augmented_from_decompilation"] is True
    assert result["functions"][0]["api_calls"] == ["CreateFileW"]
    assert result["functions"][1]["callers"] == [f"{digest}:ghidra:0x1000"]


def test_validate_prepared_scope_requires_exact_collection(tmp_path: Path) -> None:
    """再開cacheのcollection IDとcase集合の取り違えを拒否する。"""

    digest = "a" * 64
    collection = tmp_path / "analysis-results" / "collections" / "scope-a"
    target._json_dump(
        collection / "manifest.json",
        {"cases": [{"case_id": f"sha256:{digest}"}]},
    )
    private = tmp_path / "private"
    target._json_dump(
        private / "input-relationships.json",
        {
            "collection_id": "scope-a",
            "relationships": [{"case_sha256": digest}],
        },
    )

    target.validate_prepared_scope(collection, private)

    target._json_dump(
        private / "input-relationships.json",
        {
            "collection_id": "scope-b",
            "relationships": [{"case_sha256": digest}],
        },
    )
    with pytest.raises(ValueError, match="collection ID"):
        target.validate_prepared_scope(collection, private)


def test_load_prepared_inputs_verifies_hashes_and_relationships(
    tmp_path: Path,
) -> None:
    """再開cacheを再展開せずSHA-256検証して復元する。"""

    root_data = b"MZ-root"
    layer_data = b"MZ-layer"
    root_digest = hashlib.sha256(root_data).hexdigest()
    layer_digest = hashlib.sha256(layer_data).hexdigest()
    script_digest = hashlib.sha256(b"script").hexdigest()
    short_root = tmp_path.parents[2] / ("resume-" + hashlib.sha256(str(tmp_path).encode()).hexdigest()[:8])
    input_root = short_root / "samples" / root_digest / "ghidra-input"
    (input_root / "layers").mkdir(parents=True)
    (input_root / f"{root_digest}.quarantine.bin").write_bytes(root_data)
    (input_root / "layers" / f"{layer_digest}.quarantine.bin").write_bytes(layer_data)
    private = short_root / "private"
    target._json_dump(
        private / "input-relationships.json",
        {
            "unique_pe_objects": 2,
            "relationships": [
                {
                    "case_sha256": root_digest,
                    "layer_sha256": root_digest,
                    "depth": 0,
                    "size": len(root_data),
                    "is_pe": True,
                    "transform": "root",
                },
                {
                    "case_sha256": root_digest,
                    "layer_sha256": layer_digest,
                    "depth": 1,
                    "size": len(layer_data),
                    "is_pe": True,
                    "transform": "embedded-pe",
                },
                {
                    "case_sha256": root_digest,
                    "layer_sha256": script_digest,
                    "depth": 1,
                    "size": 6,
                    "is_pe": False,
                    "transform": "script",
                },
            ],
        },
    )

    objects, non_pe = target.load_prepared_inputs(short_root / "samples", private)

    assert set(objects) == {root_digest, layer_digest}
    assert objects[layer_digest].input_path.name == f"{layer_digest}.quarantine.bin"
    assert non_pe[root_digest][0]["layer_sha256"] == script_digest

    objects[layer_digest].input_path.write_bytes(b"tampered")
    with pytest.raises(ValueError, match="SHA-256が一致しません"):
        target.load_prepared_inputs(short_root / "samples", private)
