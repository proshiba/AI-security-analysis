"""Ghidra MCP代表関数静的解析バッチの安全境界と正規化を確認する。"""

from __future__ import annotations

import hashlib
import logging
from pathlib import Path
import sys

import pytest


COMMON = Path(__file__).parents[1] / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

import analysis_contract  # noqa: E402
import ghidra_function_batch as target  # noqa: E402


def _minimal_pe(marker: bytes) -> bytes:
    """実行不能だがPE parserで検証できる最小headerを返す。"""

    data = bytearray(0x200)
    data[:2] = b"MZ"
    pe_offset = 0x80
    data[0x3C:0x40] = pe_offset.to_bytes(4, "little")
    data[pe_offset : pe_offset + 4] = b"PE\0\0"
    coff = pe_offset + 4
    data[coff : coff + 2] = (0x14C).to_bytes(2, "little")
    data[coff + 16 : coff + 18] = (0xE0).to_bytes(2, "little")
    optional = pe_offset + 24
    data[optional : optional + 2] = (0x10B).to_bytes(2, "little")
    data[optional + 92 : optional + 96] = (16).to_bytes(4, "little")
    return bytes(data) + marker


def test_is_pe_rejects_truncated_mz_candidate() -> None:
    """MZだけを持つ切断resourceをGhidra import対象へ昇格しない。"""

    assert target._is_pe(b"MZ") is False
    assert target._is_pe(b"MZ" + bytes(193)) is False
    assert target._is_pe(b"not-a-pe") is False


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


def test_managed_cil_parser_diagnostics_do_not_leak(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    """壊れた.NET metadataのparser診断を標準エラーへ漏らさない。"""

    def noisy_parser(**_kwargs: object) -> None:
        logging.getLogger("dnfile").error("SECRET_DNFILE_DIAGNOSTIC")
        return None

    monkeypatch.setattr(target.dnfile, "dnPE", noisy_parser)

    assert (
        target._managed_cil_records(
            b"MZ",
            tmp_path / "cil-instructions.raw.jsonl",
            "a" * 64,
        )
        == []
    )
    captured = capsys.readouterr()
    assert "SECRET_DNFILE_DIAGNOSTIC" not in captured.out
    assert "SECRET_DNFILE_DIAGNOSTIC" not in captured.err


def test_managed_program_uses_cil_primary_without_auto_analysis(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """managed PEはGhidra auto-analysisを起動せずCIL正本で処理する。"""

    class ManagedClient:
        def __init__(self) -> None:
            self.calls: list[tuple[str, str, dict[str, object]]] = []
            self.imported = False

        def get(self, endpoint: str, **query: object) -> object:
            self.calls.append(("get", endpoint, query))
            if endpoint == "/open_program":
                raise target.GhidraMcpError("not imported")
            if endpoint == "/analysis_status":
                if not self.imported:
                    raise target.GhidraMcpError("not imported")
                return {
                    "analyzing": False,
                    "analyzed": False,
                    "should_ask_to_analyze": True,
                }
            if endpoint in {
                "/get_metadata",
                "/list_imports",
                "/list_exports",
                "/list_strings",
                "/list_segments",
                "/get_entry_points",
                "/save_all_programs",
            }:
                return [] if endpoint != "/get_metadata" else {}
            raise AssertionError(f"予期しないGET endpoint: {endpoint}")

        def post(
            self,
            endpoint: str,
            body: dict[str, object],
            **query: object,
        ) -> object:
            self.calls.append(("post", endpoint, {**query, "body": body}))
            if endpoint == "/import_file":
                if "language" not in body:
                    raise target.GhidraMcpError("標準loaderで読み込めません")
                self.imported = True
                assert body["auto_analyze"] is False
                assert body["language"] == "x86:LE:64:default"
                assert body["compiler_spec"] == "windows"
                return {"path": (f"/Malware/Test/{digest[:8]}/{input_path.name}")}
            if endpoint == "/close_program":
                return {}
            raise AssertionError(f"予期しないPOST endpoint: {endpoint}")

    data = b"MZ" + b"\x00" * 510
    digest = hashlib.sha256(data).hexdigest()
    input_path = tmp_path / f"{digest}.quarantine.bin"
    input_path.write_bytes(data)
    item = target.ProgramObject(
        sha256=digest,
        input_path=input_path,
        size=len(data),
        relationships=[
            {
                "case_sha256": digest,
                "depth": 0,
                "transform": "root",
            }
        ],
    )
    monkeypatch.setattr(target, "_is_managed_pe", lambda _data: True)
    monkeypatch.setattr(
        target,
        "_raw_pe_import_parameters",
        lambda _data: {
            "language": "x86:LE:64:default",
            "compiler_spec": "windows",
        },
    )
    monkeypatch.setattr(
        target,
        "_all_functions",
        lambda _client, _program: pytest.fail("managed CIL正本経路でGhidra疑似関数を列挙してはならない"),
    )
    monkeypatch.setattr(target, "_managed_cil_records", lambda *_args: [])

    client = ManagedClient()
    result = target.analyze_program(
        client,
        item,
        tmp_path / "private",
        "/Malware/Test",
        analysis_timeout=1,
    )

    assert result["analysis_mode"] == "managed_cil_primary_with_ghidra_structure"
    assert result["import_mode"] == "raw_pe_fallback"
    assert result["mcp_responses_valid"] is True
    assert all(call[1] != "/run_analysis" for call in client.calls)
    assert all(call[1] != "/get_full_call_graph" for call in client.calls)
    assert all(call[1] != "/list_strings" for call in client.calls)
    assert all(call[1] != "/get_entry_points" for call in client.calls)
    assert all(call[1] != "/save_program" for call in client.calls)


def test_import_timeout_does_not_trigger_duplicate_raw_fallback(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """import応答のタイムアウト時に同じPEをraw形式で再登録しない。"""

    class TimeoutImportClient:
        def __init__(self) -> None:
            self.import_calls = 0

        def get(self, endpoint: str, **_query: object) -> object:
            assert endpoint in {"/analysis_status", "/open_program"}
            raise target.GhidraMcpError("programは未登録です")

        def post(
            self,
            endpoint: str,
            _body: dict[str, object],
            **_query: object,
        ) -> object:
            assert endpoint == "/import_file"
            self.import_calls += 1
            try:
                raise TimeoutError("Ghidraの応答待ちが時間切れです")
            except TimeoutError as error:
                raise target.GhidraMcpError("POST /import_file failed") from error

    data = b"MZ" + b"\x00" * 510
    digest = hashlib.sha256(data).hexdigest()
    input_path = tmp_path / f"{digest}.quarantine.bin"
    input_path.write_bytes(data)
    item = target.ProgramObject(
        sha256=digest,
        input_path=input_path,
        size=len(data),
        relationships=[{"case_sha256": digest, "depth": 0, "transform": "root"}],
    )
    monkeypatch.setattr(target, "_is_managed_pe", lambda _data: False)
    monkeypatch.setattr(
        target,
        "_raw_pe_import_parameters",
        lambda _data: {"language": "x86:LE:64:default", "compiler_spec": "windows"},
    )

    client = TimeoutImportClient()
    with pytest.raises(target.GhidraMcpError, match="import_file"):
        target.analyze_program(
            client,
            item,
            tmp_path / "private",
            "/Malware/Test",
            analysis_timeout=1,
        )
    assert client.import_calls == 1


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
                return {address: f"void f_{address}(void) {{ return; }}" for address in addresses}
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
            "entry @ 00401000 [Label] [external entry]\nIMAGE_DOS_HEADER_00400000 @ 00400000 [Label] [program entry]"
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
                    {
                        "address": "0x1000",
                        "hash": "b" * 64,
                        "instruction_count": 1,
                        "hash_status": "available",
                        "program_selector": selector,
                    },
                    {
                        "address": "0x2000",
                        "hash": "c" * 64,
                        "instruction_count": 1,
                        "hash_status": "available",
                        "program_selector": selector,
                    },
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


def test_load_prepared_inputs_allows_missing_cache_for_complete_result(
    tmp_path: Path,
) -> None:
    """MCP検証済み完了結果があるprogramだけ、削除済み生成cacheから再開できる。"""

    data = b"MZ-complete"
    digest = hashlib.sha256(data).hexdigest()
    short_root = tmp_path.parents[2] / ("resume-complete-" + hashlib.sha256(str(tmp_path).encode()).hexdigest()[:8])
    private = short_root / "private"
    target._json_dump(
        private / "input-relationships.json",
        {
            "unique_pe_objects": 1,
            "relationships": [
                {
                    "case_sha256": digest,
                    "layer_sha256": digest,
                    "depth": 0,
                    "size": len(data),
                    "is_pe": True,
                    "transform": "root",
                }
            ],
        },
    )
    target._json_dump(
        private / "objects" / digest / "program-result.json",
        {
            "status": "complete",
            "mcp_responses_valid": True,
        },
    )

    objects, _ = target.load_prepared_inputs(short_root / "samples", private)

    assert set(objects) == {digest}
    assert objects[digest].size == len(data)
    assert not objects[digest].input_path.exists()

    (private / "objects" / digest / "program-result.json").unlink()
    with pytest.raises(FileNotFoundError, match="再開用PE cacheがありません"):
        target.load_prepared_inputs(short_root / "samples", private)


def test_finalize_case_report_promotes_only_function_analysis_blocker(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Ghidra反映後は唯一の代表関数blockerを除きreportを再封印する。"""

    digest = "8" * 64
    case_dir = tmp_path / digest
    case_dir.mkdir()
    target._json_dump(case_dir / "static-logic.json", {"status": "complete"})
    report = {
        "classification": {"selected_families": []},
        "case_state": {
            "status": "partial",
            "complete": False,
            "resumable": False,
            "blockers": [target.FUNCTION_ANALYSIS_BLOCKER],
        },
        "artifact_sha256": {
            "static-logic.json": hashlib.sha256((case_dir / "static-logic.json").read_bytes()).hexdigest()
        },
    }
    analysis_contract.seal_report(report)
    target._json_dump(case_dir / "report.json", report)
    validation_calls: list[dict[str, object]] = []

    def no_errors(*args: object, **kwargs: object) -> list[str]:
        validation_calls.append(kwargs)
        return []

    monkeypatch.setattr(target, "case_integrity_errors", no_errors)

    assert target.finalize_case_report(case_dir) == "triaged_unknown"
    refreshed = target.load_json_object_strict(case_dir / "report.json")
    assert refreshed["case_state"] == {
        "status": "triaged_unknown",
        "complete": True,
        "resumable": True,
        "blockers": [],
    }
    assert analysis_contract.verify_report_semantics(refreshed) == []
    assert validation_calls == [{"expected_digest": digest, "require_resumable": True}]


def test_finalize_case_report_accepts_ghidra_superseded_string_limit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Ghidraの完全証跡がある場合だけ汎用文字列保持上限を補完済みとする。"""

    digest = "7" * 64
    case_dir = tmp_path / digest
    case_dir.mkdir()
    target._json_dump(
        case_dir / "generic-triage.json",
        {
            "analysis_coverage": {"status": "partial"},
            "pe": {"string_scan": {"truncated": True}},
        },
    )
    target._json_dump(
        case_dir / "static-logic.json",
        {
            "status": "characteristic_function_static_analysis_complete",
            "coverage": {
                "all_characteristic_functions_attempted": True,
                "all_characteristic_functions_explained": True,
                "all_discovered_functions_inventoried": True,
                "all_static_analysis_content_retained": True,
                "function_bodies_reviewed": True,
                "ghidra_program_count": 3,
                "ghidra_programs_with_valid_mcp_responses": 3,
            },
        },
    )
    report = {
        "classification": {"selected_families": []},
        "generic_triage": "partial",
        "limitations": [],
        "case_state": {
            "status": "partial",
            "complete": False,
            "resumable": False,
            "blockers": ["generic_triage_partial", target.FUNCTION_ANALYSIS_BLOCKER],
        },
        "artifact_sha256": {
            name: hashlib.sha256((case_dir / name).read_bytes()).hexdigest()
            for name in ("generic-triage.json", "static-logic.json")
        },
    }
    analysis_contract.seal_report(report)
    target._json_dump(case_dir / "report.json", report)
    validation_calls: list[dict[str, object]] = []

    def no_errors(*args: object, **kwargs: object) -> list[str]:
        validation_calls.append(kwargs)
        return []

    monkeypatch.setattr(target, "case_integrity_errors", no_errors)

    assert target.finalize_case_report(case_dir) == "triaged_unknown"
    refreshed = target.load_json_object_strict(case_dir / "report.json")
    assert refreshed["case_state"] == {
        "status": "triaged_unknown",
        "complete": True,
        "resumable": True,
        "blockers": [],
    }
    assert "Ghidra MCP" in refreshed["limitations"][-1]
    assert refreshed["generic_triage"] == "complete"
    assert analysis_contract.verify_report_semantics(refreshed) == []
    assert validation_calls == [{"expected_digest": digest, "require_resumable": True}]


def _write_complete_generic_container_fixture(
    case_dir: Path,
    *,
    layer_format: str,
    coverage_issue: str,
    child_format: str = "pe",
) -> tuple[str, str]:
    """container委譲の既知制限fixtureを作成する。"""

    layer_sha = "8" * 64
    child_sha = "9" * 64
    result: dict[str, object] = {
        "analysis_coverage": {"status": "partial", "issues": [coverage_issue]},
        "type": layer_format,
    }
    if layer_format == "rar":
        result["format_specific_analysis"] = "delegated_to_static_layer_pipeline"
    target._json_dump(
        case_dir / "generic-triage.json",
        {
            "analysis_coverage": {
                "status": "partial",
                "failed_layers": 0,
                "partial_layers": 1,
            },
            "recovered_layer_triage": [
                {
                    "status": "partial",
                    "issues": ["root:coverage:partial"],
                    "layer": {"sha256": layer_sha, "format": layer_format},
                    "result": result,
                }
            ],
        },
    )
    report: dict[str, object] = {}
    accepted_children: list[dict[str, str]] = []
    layers = [{"sha256": layer_sha}]
    if layer_format == "ole":
        report["ole"] = {
            "status": "artifacts_recovered",
            "inventory": [{"status": "inspected"}],
        }
        accepted_children = [{"sha256": child_sha, "format": child_format}]
        layers.append({"sha256": child_sha})
    elif layer_format == "rar":
        report["sevenzip"] = {
            "status": "partially_extracted",
            "archive_unlock_attempt_count": 2,
            "retained_members": 0,
            "inventory": [{"status": "empty_file"}],
        }
    target._json_dump(
        case_dir / "static-layers.json",
        {
            "layers": layers,
            "steps": [
                {
                    "status": "succeeded",
                    "input_layer": {"sha256": layer_sha},
                    "accepted_children": accepted_children,
                    "report": report,
                }
            ],
        },
    )
    target._json_dump(
        case_dir / "static-logic.json",
        {
            "coverage": {
                "all_characteristic_functions_attempted": True,
                "all_characteristic_functions_explained": True,
                "all_discovered_functions_inventoried": True,
                "all_static_analysis_content_retained": True,
                "function_bodies_reviewed": True,
                "ghidra_program_count": 1,
                "ghidra_programs_with_valid_mcp_responses": 1,
            }
        },
    )
    return layer_sha, child_sha


def test_known_generic_container_limits_accepts_recovered_ole(tmp_path: Path) -> None:
    """OLE inventoryとPE/CAB子の再帰解析が揃う場合だけ既知制限として返す。"""

    case_dir = tmp_path / ("8" * 64)
    case_dir.mkdir()
    layer_sha, _ = _write_complete_generic_container_fixture(
        case_dir,
        layer_format="ole",
        coverage_issue="root:ole_format_analysis_not_implemented",
    )

    assert target._ghidra_documents_known_generic_container_limits(case_dir) == [
        f"{layer_sha}:ole_inventory_and_executable_children_recovered"
    ]


def test_known_generic_container_limits_rejects_unrouted_ole_child(tmp_path: Path) -> None:
    """OLE子が実行形式またはCABとしてroutingされない場合は完了へ昇格しない。"""

    case_dir = tmp_path / ("7" * 64)
    case_dir.mkdir()
    _write_complete_generic_container_fixture(
        case_dir,
        layer_format="ole",
        coverage_issue="root:ole_format_analysis_not_implemented",
        child_format="data",
    )

    assert target._ghidra_documents_known_generic_container_limits(case_dir) == []


def test_known_generic_container_limits_accepts_bounded_rar_delegation(tmp_path: Path) -> None:
    """RAR inventory委譲は、有界再試行済み静的制限と組み合わさる場合だけ閉じる。"""

    case_dir = tmp_path / ("6" * 64)
    case_dir.mkdir()
    layer_sha, _ = _write_complete_generic_container_fixture(
        case_dir,
        layer_format="rar",
        coverage_issue="root:rar_inventory_only",
    )
    assert target._ghidra_documents_known_generic_container_limits(case_dir) == [
        f"{layer_sha}:rar_inventory_delegated_to_bounded_static_recovery"
    ]
    layers_path = case_dir / "static-layers.json"
    layers = target.load_json_object_strict(layers_path)
    layers["steps"][0]["report"]["sevenzip"]["archive_unlock_attempt_count"] = 1
    target._json_dump(layers_path, layers)
    assert target._ghidra_documents_known_generic_container_limits(case_dir) == []


def test_finalize_case_report_closes_documented_ole_generic_limit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """完全回収したOLE委譲だけを解析済み未分類へ遷移させる。"""

    digest = "5" * 64
    case_dir = tmp_path / digest
    case_dir.mkdir()
    layer_sha, _ = _write_complete_generic_container_fixture(
        case_dir,
        layer_format="ole",
        coverage_issue="root:ole_format_analysis_not_implemented",
    )
    report = {
        "classification": {"selected_families": []},
        "generic_triage": "partial",
        "limitations": [],
        "case_state": {
            "status": "partial",
            "complete": False,
            "resumable": False,
            "blockers": ["generic_triage_partial", target.FUNCTION_ANALYSIS_BLOCKER],
        },
        "artifact_sha256": {
            name: hashlib.sha256((case_dir / name).read_bytes()).hexdigest()
            for name in ("generic-triage.json", "static-layers.json", "static-logic.json")
        },
    }
    analysis_contract.seal_report(report)
    target._json_dump(case_dir / "report.json", report)
    monkeypatch.setattr(target, "case_integrity_errors", lambda *args, **kwargs: [])

    assert target.finalize_case_report(case_dir) == "triaged_unknown"
    refreshed = target.load_json_object_strict(case_dir / "report.json")
    assert refreshed["case_state"]["blockers"] == []
    assert refreshed["generic_triage_completion"]["basis"] == (
        "ghidra_complete_coverage_and_bounded_container_recovery"
    )
    assert refreshed["generic_triage_completion"]["documented_container_limits"] == [
        f"{layer_sha}:ole_inventory_and_executable_children_recovered"
    ]


@pytest.mark.parametrize(
    ("issue", "steps", "documented"),
    [
        (
            "steps[0].report.pe.managed_il_triage.status:analyzed_partial_budget",
            [],
            True,
        ),
        (
            "steps[4].report.sevenzip.status:partially_extracted",
            [
                {
                    "report": {
                        "sevenzip": {
                            "status": "partially_extracted",
                            "archive_unlock_attempt_count": 2,
                            "retained_members": 0,
                            "inventory": [{"name": "eee.exe", "status": "empty_file"}],
                        }
                    }
                }
            ],
            True,
        ),
        ("steps[0].report.dotnet_bundle.status:parse_failed", [], False),
    ],
)
def test_ghidra_documents_only_known_exhausted_static_limits(
    tmp_path: Path,
    issue: str,
    steps: list[dict[str, object]],
    documented: bool,
) -> None:
    """未知のparse失敗や未試行の展開失敗を完了扱いにしない。"""

    case_dir = tmp_path / hashlib.sha256(issue.encode()).hexdigest()
    case_dir.mkdir()
    target._json_dump(
        case_dir / "static-logic.json",
        {
            "coverage": {
                "all_characteristic_functions_attempted": True,
                "all_characteristic_functions_explained": True,
                "all_discovered_functions_inventoried": True,
                "all_static_analysis_content_retained": True,
                "function_bodies_reviewed": True,
                "ghidra_program_count": 2,
                "ghidra_programs_with_valid_mcp_responses": 2,
            }
        },
    )
    target._json_dump(case_dir / "static-layers.json", {"steps": steps})
    result = target._ghidra_documents_known_static_limits(
        case_dir,
        {"static_layer_issues": [issue]},
    )
    assert bool(result) is documented


def test_finalize_case_report_promotes_documented_managed_budget_limit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Ghidra完全coverageが管理コード予算上限を補完した場合だけ完了させる。"""

    digest = "6" * 64
    case_dir = tmp_path / digest
    case_dir.mkdir()
    target._json_dump(
        case_dir / "static-logic.json",
        {
            "coverage": {
                "all_characteristic_functions_attempted": True,
                "all_characteristic_functions_explained": True,
                "all_discovered_functions_inventoried": True,
                "all_static_analysis_content_retained": True,
                "function_bodies_reviewed": True,
                "ghidra_program_count": 1,
                "ghidra_programs_with_valid_mcp_responses": 1,
            }
        },
    )
    issue = "steps[0].report.pe.managed_il_triage.status:analyzed_partial_budget"
    report = {
        "classification": {"selected_families": []},
        "limitations": [],
        "case_state": {
            "status": "partial",
            "complete": False,
            "resumable": False,
            "blockers": [target.FUNCTION_ANALYSIS_BLOCKER, "static_layer_incomplete"],
            "detector_error_families": [],
            "static_layer_issues": [issue],
            "incomplete_selected_layer_attempts": [],
        },
        "artifact_sha256": {
            "static-logic.json": hashlib.sha256((case_dir / "static-logic.json").read_bytes()).hexdigest()
        },
    }
    analysis_contract.seal_report(report)
    target._json_dump(case_dir / "report.json", report)
    monkeypatch.setattr(target, "case_integrity_errors", lambda *_args, **_kwargs: [])

    assert target.finalize_case_report(case_dir) == "triaged_unknown"
    refreshed = target.load_json_object_strict(case_dir / "report.json")
    assert refreshed["case_state"]["blockers"] == []
    assert refreshed["case_state"]["static_layer_issues"] == []
    assert refreshed["documented_static_layer_issues"] == [issue]
    assert refreshed["static_layer_analysis_completion"]["raw_evidence"] == "static-layers.json"
    assert "Ghidra MCP" in refreshed["limitations"][-1]


def test_finalize_case_report_preserves_unrelated_blocker(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Ghidra完了でhandler失敗などを消さずpartialのまま再封印する。"""

    digest = "9" * 64
    case_dir = tmp_path / digest
    case_dir.mkdir()
    target._json_dump(case_dir / "static-logic.json", {"status": "complete"})
    report = {
        "case_state": {
            "status": "partial",
            "complete": False,
            "resumable": False,
            "blockers": ["handler_failed", target.FUNCTION_ANALYSIS_BLOCKER],
        },
        "artifact_sha256": {
            "static-logic.json": hashlib.sha256((case_dir / "static-logic.json").read_bytes()).hexdigest()
        },
    }
    analysis_contract.seal_report(report)
    target._json_dump(case_dir / "report.json", report)
    validation_calls: list[dict[str, object]] = []

    def no_errors(*args: object, **kwargs: object) -> list[str]:
        validation_calls.append(kwargs)
        return []

    monkeypatch.setattr(target, "case_integrity_errors", no_errors)

    assert target.finalize_case_report(case_dir) == "partial"
    refreshed = target.load_json_object_strict(case_dir / "report.json")
    assert refreshed["case_state"] == {
        "status": "partial",
        "complete": False,
        "resumable": False,
        "blockers": ["handler_failed"],
    }
    assert analysis_contract.verify_report_semantics(refreshed) == []
    assert validation_calls == [{"expected_digest": digest, "require_resumable": False}]


def test_finalize_collection_registers_partial_case_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """解析がpartialでもidentityを登録し、完了状態はpartialのまま保持する。"""

    # Windowsではpytestのテスト名付き一時パスと64桁digestの組み合わせが
    # MAX_PATHを超えることがある。意味上は同じ一時領域内で短いrootを使う。
    short_root = tmp_path.parents[2] / (
        "fc-" + hashlib.sha256(str(tmp_path).encode()).hexdigest()[:8]
    )
    repository = short_root / "r"
    digest = "a" * 64
    case_dir = repository / "analysis-results" / "malware" / "unclassified" / "versions" / "unknown" / "cases" / digest
    case_dir.mkdir(parents=True)
    target._json_dump(case_dir / "metadata.json", {"family": "unclassified"})
    target._json_dump(
        case_dir / "report.json",
        {"case_state": {"status": "partial", "blockers": ["generic_triage_partial"]}},
    )
    collection = repository / "analysis-results" / "collections" / "batch-test"
    collection.mkdir(parents=True)
    target._json_dump(
        collection / "manifest.json",
        {"cases": [{"case_id": f"sha256:{digest}"}]},
    )
    target._json_dump(collection / "publication-summary.json", {})
    (collection / "README.md").write_text(
        "# テスト\n- 公開段階: `analysis_followup_pending`\n",
        encoding="utf-8",
    )
    registrations: list[tuple[str, list[Path]]] = []

    def record_registration(context: object, paths: list[Path]) -> dict[str, int]:
        registrations.append((getattr(context, "family"), list(paths)))
        return {"cases": len(paths)}

    monkeypatch.setattr(target, "register_publication_cases", record_registration)

    result = target.finalize_collection_publication(repository, collection)

    assert registrations == [("unclassified", [case_dir])]
    assert result["analysis_complete"] is False
    assert result["publication_stage"] == "partial_followup_required"
    assert result["case_state_counts"] == {"partial": 1}
    manifest = target.load_json_object_strict(collection / "manifest.json")
    assert manifest["complete"] is False
    assert manifest["analysis_complete"] is False
    assert manifest["case_state_counts"] == {"partial": 1}
    assert manifest["case_blocker_counts"] == {"generic_triage_partial": 1}
    readme = (collection / "README.md").read_text(encoding="utf-8")
    assert "partial_followup_required" in readme
    assert "`generic_triage_partial` | 1" in readme


def test_prepare_inputs_skips_replay_and_validates_static_tool_contract(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """封印済みroot-onlyは再走査せず、外部tool契約は引き続き検証する。"""

    from types import SimpleNamespace

    root_data = _minimal_pe(b"static-tool-contract")
    digest = hashlib.sha256(root_data).hexdigest()
    short_root = tmp_path.parents[2] / ("tool-contract-" + hashlib.sha256(str(tmp_path).encode()).hexdigest()[:8])
    repository = short_root / "r"
    case_dir = repository / "analysis-results" / "malware" / "test-family" / "versions" / "unknown" / "cases" / digest
    case_dir.mkdir(parents=True)
    collection = repository / "analysis-results" / "collections" / "test-collection"
    target._json_dump(
        collection / "manifest.json",
        {"cases": [{"case_id": f"sha256:{digest}"}]},
    )
    sample_root = short_root / "s"
    archive = sample_root / digest / f"{digest}.zip"
    archive.parent.mkdir(parents=True)
    archive.write_bytes(b"fixture archive")
    target._json_dump(
        sample_root / "manifest.json",
        {"items": [{"sha256": digest, "zip_path": str(archive)}]},
    )
    tools = {}
    for name in ("upx", "sevenzip", "diec"):
        tool = short_root / f"{name}.exe"
        tool.write_bytes(f"fixture-{name}".encode("ascii"))
        tools[name] = tool.resolve()
    identities = {name: target._static_tool_identity(tool) for name, tool in tools.items()}
    target._json_dump(
        case_dir / "report.json",
        {
            "analysis_contract": {
                "settings": {"static_tools": identities},
            }
        },
    )
    target._json_dump(
        case_dir / "static-layers.json",
        {
            "layers": [
                {
                    "sha256": digest,
                    "size": len(root_data),
                    "depth": 0,
                    "transform": "submission",
                }
            ]
        },
    )
    sealed_report = target.load_json_object_strict(case_dir / "report.json")
    sealed_report["artifact_sha256"] = {
        "static-layers.json": hashlib.sha256((case_dir / "static-layers.json").read_bytes()).hexdigest()
    }
    analysis_contract.seal_report(sealed_report)
    target._json_dump(case_dir / "report.json", sealed_report)
    unit = SimpleNamespace(data=root_data, source_name="sample.exe")
    observed: list[dict[str, Path | None]] = []

    monkeypatch.setattr(target, "read_input_unit", lambda *args, **kwargs: unit)

    def fake_recover_static_layers(
        value: object,
        **kwargs: Path | None,
    ) -> tuple[list[object], dict[str, object]]:
        raise AssertionError("root-only caseでlayer再走査が呼ばれました")

    monkeypatch.setattr(target, "recover_static_layers", fake_recover_static_layers)

    objects, non_pe = target.prepare_inputs(
        repository,
        collection,
        sample_root,
        short_root / "p",
        upx=tools["upx"],
        sevenzip=tools["sevenzip"],
        diec=tools["diec"],
    )

    assert set(objects) == {digest}
    assert not non_pe
    assert observed == []
    relationships = target.load_json_object_strict(short_root / "p" / "input-relationships.json")
    assert relationships["static_tools"] == identities
    assert {item["reconstruction_mode"] for item in relationships["relationships"]} == {"authenticated_root_only"}

    with pytest.raises(ValueError, match="sevenzip"):
        target.prepare_inputs(
            repository,
            collection,
            sample_root,
            short_root / "pm",
            upx=tools["upx"],
            diec=tools["diec"],
        )
    assert not observed


def test_static_tool_cli_arguments_remain_optional(tmp_path: Path) -> None:
    """既存CLIは追加optionなしでparseでき、必要時だけtool pathを受け取る。"""

    parser = target.build_parser()
    common = [
        "--sample-root",
        str(tmp_path / "samples"),
        "--private-output",
        str(tmp_path / "private"),
    ]

    defaults = parser.parse_args(common)
    assert defaults.upx is None
    assert defaults.sevenzip is None
    assert defaults.diec is None
    assert defaults.skip_auto_analysis_sha256 == []

    selected = parser.parse_args(
        common
        + [
            "--upx",
            str(tmp_path / "upx.exe"),
            "--sevenzip",
            str(tmp_path / "7z.exe"),
            "--diec",
            str(tmp_path / "diec.exe"),
            "--skip-auto-analysis-sha256",
            "A" * 64,
            "--skip-auto-analysis-sha256",
            "b" * 64,
        ]
    )
    assert selected.upx == tmp_path / "upx.exe"
    assert selected.sevenzip == tmp_path / "7z.exe"
    assert selected.diec == tmp_path / "diec.exe"
    assert selected.skip_auto_analysis_sha256 == ["a" * 64, "b" * 64]


def test_prepare_inputs_replays_child_layers_with_same_tools(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """子layerがあるcaseは同一toolで完全再現し、公開集合との一致を要求する。"""

    from types import SimpleNamespace

    root_data = _minimal_pe(b"root-with-child")
    child_data = _minimal_pe(b"recovered-child")
    digest = hashlib.sha256(root_data).hexdigest()
    child_digest = hashlib.sha256(child_data).hexdigest()
    short_root = tmp_path.parents[2] / ("child-replay-" + hashlib.sha256(str(tmp_path).encode()).hexdigest()[:8])
    repository = short_root / "r"
    case_dir = repository / "analysis-results" / "malware" / "test-family" / "versions" / "unknown" / "cases" / digest
    case_dir.mkdir(parents=True)
    collection = repository / "analysis-results" / "collections" / "test-collection"
    target._json_dump(
        collection / "manifest.json",
        {"cases": [{"case_id": f"sha256:{digest}"}]},
    )
    sample_root = short_root / "s"
    archive = sample_root / digest / f"{digest}.zip"
    archive.parent.mkdir(parents=True)
    archive.write_bytes(b"fixture archive")
    target._json_dump(
        sample_root / "manifest.json",
        {"items": [{"sha256": digest, "zip_path": str(archive)}]},
    )
    static_layers = {
        "layers": [
            {
                "sha256": digest,
                "size": len(root_data),
                "depth": 0,
                "transform": "submission",
            },
            {
                "sha256": child_digest,
                "size": len(child_data),
                "depth": 1,
                "transform": "embedded-pe",
            },
        ]
    }
    target._json_dump(case_dir / "static-layers.json", static_layers)
    identities = {"upx": None, "sevenzip": None, "diec": None}
    report = {
        "analysis_contract": {"settings": {"static_tools": identities}},
        "artifact_sha256": {
            "static-layers.json": hashlib.sha256((case_dir / "static-layers.json").read_bytes()).hexdigest()
        },
    }
    analysis_contract.seal_report(report)
    target._json_dump(case_dir / "report.json", report)
    unit = SimpleNamespace(data=root_data, source_name="sample.exe")
    root_layer = SimpleNamespace(
        data=root_data,
        sha256=digest,
        depth=0,
        transform="submission",
        parent_sha256=None,
        name="sample.exe",
    )
    child_layer = SimpleNamespace(
        data=child_data,
        sha256=child_digest,
        depth=1,
        transform="embedded-pe",
        parent_sha256=digest,
        name="child.exe",
    )
    observed: list[dict[str, Path | None]] = []
    monkeypatch.setattr(target, "read_input_unit", lambda *args, **kwargs: unit)

    def replay_layers(
        value: object,
        **kwargs: Path | None,
    ) -> tuple[list[object], dict[str, object]]:
        assert value is unit
        observed.append(kwargs)
        return [root_layer, child_layer], {}

    monkeypatch.setattr(target, "recover_static_layers", replay_layers)
    objects, non_pe = target.prepare_inputs(
        repository,
        collection,
        sample_root,
        short_root / "p",
    )

    assert set(objects) == {digest, child_digest}
    assert not non_pe
    assert observed == [identities]
    relationships = target.load_json_object_strict(short_root / "p" / "input-relationships.json")
    assert {item["reconstruction_mode"] for item in relationships["relationships"]} == {"full_static_layer_replay"}

    monkeypatch.setattr(
        target,
        "recover_static_layers",
        lambda *args, **kwargs: ([root_layer], {}),
    )
    with pytest.raises(ValueError, match="一致しません"):
        target.prepare_inputs(
            repository,
            collection,
            sample_root,
            short_root / "pm",
        )


def test_prepare_inputs_replays_adaptive_static_layer_contract(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """公開側で層上限再試行が発火したcaseを同じ上限で再現する。"""

    from types import SimpleNamespace

    root_data = _minimal_pe(b"adaptive-root")
    child_data = _minimal_pe(b"adaptive-child")
    digest = hashlib.sha256(root_data).hexdigest()
    child_digest = hashlib.sha256(child_data).hexdigest()
    short_root = tmp_path.parents[2] / ("adaptive-replay-" + hashlib.sha256(str(tmp_path).encode()).hexdigest()[:8])
    repository = short_root / "r"
    case_dir = repository / "analysis-results" / "malware" / "test-family" / "versions" / "unknown" / "cases" / digest
    case_dir.mkdir(parents=True)
    collection = repository / "analysis-results" / "collections" / "test-collection"
    target._json_dump(collection / "manifest.json", {"cases": [{"case_id": f"sha256:{digest}"}]})
    sample_root = short_root / "s"
    archive = sample_root / digest / f"{digest}.zip"
    archive.parent.mkdir(parents=True)
    archive.write_bytes(b"fixture archive")
    target._json_dump(
        sample_root / "manifest.json",
        {"items": [{"sha256": digest, "zip_path": str(archive)}]},
    )
    target._json_dump(
        case_dir / "static-layers.json",
        {
            "layers": [
                {"sha256": digest, "size": len(root_data), "depth": 0, "transform": "submission"},
                {
                    "sha256": child_digest,
                    "size": len(child_data),
                    "depth": 1,
                    "transform": "embedded-pe",
                },
            ]
        },
    )
    report = {
        "analysis_contract": {
            "settings": {
                "static_tools": {"upx": None, "sevenzip": None, "diec": None},
                "force_container_probe": False,
                "max_static_layers": 64,
                "retry_max_static_layers": 256,
            }
        },
        "artifact_sha256": {
            "static-layers.json": hashlib.sha256((case_dir / "static-layers.json").read_bytes()).hexdigest()
        },
    }
    analysis_contract.seal_report(report)
    target._json_dump(case_dir / "report.json", report)
    unit = SimpleNamespace(data=root_data, source_name="sample.exe")
    root_layer = SimpleNamespace(
        data=root_data,
        sha256=digest,
        depth=0,
        transform="submission",
        parent_sha256=None,
        name="sample.exe",
    )
    child_layer = SimpleNamespace(
        data=child_data,
        sha256=child_digest,
        depth=1,
        transform="embedded-pe",
        parent_sha256=digest,
        name="child.exe",
    )
    observed: list[int] = []
    monkeypatch.setattr(target, "read_input_unit", lambda *args, **kwargs: unit)

    def replay_layers(value: object, **kwargs: object):
        assert value is unit
        observed.append(int(kwargs["max_static_layers"]))
        if len(observed) == 1:
            return [root_layer], {"limit_events": [{"reason": "layer_count_limit"}]}
        return [root_layer, child_layer], {"limit_events": []}

    monkeypatch.setattr(target, "recover_static_layers", replay_layers)

    objects, non_pe = target.prepare_inputs(
        repository,
        collection,
        sample_root,
        short_root / "p",
    )

    assert set(objects) == {digest, child_digest}
    assert not non_pe
    assert observed == [64, 256]
    relationships = target.load_json_object_strict(short_root / "p" / "input-relationships.json")
    assert {item["reconstruction_mode"] for item in relationships["relationships"]} == {"adaptive_static_layer_replay"}


@pytest.mark.parametrize(
    "mutation",
    [
        "missing_report_seal",
        "missing_artifact_seal",
        "malformed_artifact_seal",
        "artifact_hash_mismatch",
    ],
)
def test_authenticated_public_layers_reject_invalid_or_missing_seals(
    tmp_path: Path,
    mutation: str,
) -> None:
    """reportまたはstatic-layersのseal欠落・破損・不一致をfail-closedで拒否する。"""

    root_data = b"MZ-sealed-root"
    digest = hashlib.sha256(root_data).hexdigest()
    case_dir = tmp_path / digest
    case_dir.mkdir()
    static_layers = {
        "layers": [
            {
                "sha256": digest,
                "size": len(root_data),
                "depth": 0,
                "transform": "submission",
            }
        ]
    }
    target._json_dump(case_dir / "static-layers.json", static_layers)
    report = {
        "analysis_contract": {"settings": {"static_tools": {"upx": None, "sevenzip": None, "diec": None}}},
        "artifact_sha256": {
            "static-layers.json": hashlib.sha256((case_dir / "static-layers.json").read_bytes()).hexdigest()
        },
    }
    analysis_contract.seal_report(report)
    if mutation == "missing_report_seal":
        report.pop("report_semantic_sha256")
    elif mutation == "missing_artifact_seal":
        report["artifact_sha256"].pop("static-layers.json")
        analysis_contract.seal_report(report)
    elif mutation == "malformed_artifact_seal":
        report["artifact_sha256"]["static-layers.json"] = "A" * 64
        analysis_contract.seal_report(report)
    elif mutation == "artifact_hash_mismatch":
        static_layers["layers"][0]["size"] += 1
        target._json_dump(case_dir / "static-layers.json", static_layers)
    else:
        raise AssertionError(f"未対応のmutationです: {mutation}")
    target._json_dump(case_dir / "report.json", report)

    with pytest.raises(ValueError, match="seal"):
        target._load_authenticated_public_layers(case_dir)


def test_refresh_promotes_short_initial_cache_after_project_rotation(
    tmp_path: Path,
) -> None:
    """project退避後も要求上限未満の初回応答から完全取得証跡を復元する。"""

    digest = "a" * 64
    program = f"/Malware/Test/{digest[:8]}/{digest}.quarantine.bin"
    object_dir = tmp_path / "objects" / digest
    object_dir.mkdir(parents=True)
    target._json_dump(
        object_dir / "ghidra-raw-index.json",
        {
            "program_selector": program,
            "functions": [],
            "imports": [{"name": "CreateFileW"}],
            "exports": "entry -> 00401000",
            "strings": "config.dat\nPOST /gate",
            "segments": ".text: 00401000 - 00401fff",
            "opcode_hashes": {"functions": []},
        },
    )
    result = {
        "status": "complete",
        "mcp_responses_valid": True,
        "sha256": digest,
        "program_selector": program,
        "analysis_mode": "native_ghidra_with_optional_cil",
        "functions": [],
        "opcode_hashes": {"functions": []},
    }

    class RotatedProjectClient:
        def get(self, endpoint: str, **_query: object) -> object:
            raise AssertionError(f"終端到達済みキャッシュではGETしてはいけません: {endpoint}")

        def post(
            self,
            endpoint: str,
            body: dict[str, object],
            **_query: object,
        ) -> object:
            raise AssertionError(f"退避済みprogramへPOSTしてはいけません: {endpoint} {body}")

    totals = target.refresh_complete_program_artifacts(
        RotatedProjectClient(),
        {digest: result},
        tmp_path,
    )

    assert totals["programs"] == 1
    assert totals["promoted_cached_programs"] == 1
    saved = target.load_json_object_strict(object_dir / "program-result.json")
    assert saved["all_static_analysis_content_retained"] is True
    assert saved["retrieval_coverage"]["imports"]["complete"] is True
    assert saved["retrieval_coverage"]["imports"]["source"] == "authenticated_initial_response_cache"
    assert saved["retrieval_coverage"]["strings"]["item_count"] == 2


def test_refresh_rejects_truncated_initial_cache_after_project_rotation(
    tmp_path: Path,
) -> None:
    """要求上限と同数の初回応答は完全と推測せずfail-closedにする。"""

    digest = "b" * 64
    program = f"/Malware/Test/{digest[:8]}/{digest}.quarantine.bin"
    object_dir = tmp_path / "objects" / digest
    object_dir.mkdir(parents=True)
    target._json_dump(
        object_dir / "ghidra-raw-index.json",
        {
            "program_selector": program,
            "functions": [],
            "imports": [{} for _ in range(10000)],
            "exports": [],
            "strings": [],
            "segments": [],
            "opcode_hashes": {"functions": []},
        },
    )
    result = {
        "status": "complete",
        "mcp_responses_valid": True,
        "sha256": digest,
        "program_selector": program,
        "analysis_mode": "native_ghidra_with_optional_cil",
        "functions": [],
        "opcode_hashes": {"functions": []},
    }

    class MissingProgramClient:
        def get(self, endpoint: str, **_query: object) -> object:
            assert endpoint == "/open_program"
            raise target.GhidraMcpError("programは退避済み")

    with pytest.raises(target.GhidraMcpError, match="退避済み"):
        target.refresh_complete_program_artifacts(
            MissingProgramClient(),
            {digest: result},
            tmp_path,
        )


def test_run_can_prepare_without_contacting_mcp(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """上限0では入力を準備し、MCPへ接続せず再開可能な進捗を保存する。"""

    digest = "c" * 64
    item = target.ProgramObject(
        sha256=digest,
        input_path=tmp_path / "sample.quarantine.bin",
        size=16,
    )
    repository = tmp_path / "repository"
    collection = repository / "analysis-results" / "collections" / "batch"
    sample_root = tmp_path / "samples"
    private_output = tmp_path / "private"
    collection.mkdir(parents=True)
    sample_root.mkdir()
    monkeypatch.setattr(
        target,
        "prepare_inputs",
        lambda *args, **kwargs: ({digest: item}, {}),
    )
    monkeypatch.setattr(target, "validate_prepared_scope", lambda *args: None)
    monkeypatch.setattr(
        target,
        "analyze_program",
        lambda *args, **kwargs: pytest.fail("MCP解析を呼び出してはいけません"),
    )
    arguments = target.build_parser().parse_args(
        [
            "--repository",
            str(repository),
            "--collection",
            str(collection),
            "--sample-root",
            str(sample_root),
            "--private-output",
            str(private_output),
            "--max-new-programs",
            "0",
        ]
    )

    result = target.run(arguments)

    assert result["status"] == "ghidra_chunk_pending"
    assert result["newly_analyzed_programs"] == 0
    assert result["pending_programs"] == [digest]
    saved = target.load_json_object_strict(private_output / "run-progress.json")
    assert saved["pending_programs"] == [digest]
