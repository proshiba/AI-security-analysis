"""Ghidra MCP代表関数静的解析バッチの安全境界と正規化を確認する。"""

from __future__ import annotations

import hashlib
import io
import json
import logging
import os
import sys
from email.message import Message
from pathlib import Path
from types import SimpleNamespace
from urllib.request import HTTPHandler, ProxyHandler, Request, build_opener
from urllib.response import addinfourl

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


def _write_prepared_inventory(
    private_output: Path,
    *,
    collection_id: str,
    digests: list[str],
) -> str:
    """自動再開test用の最小prepared input inventoryを保存する。"""

    path = private_output / "input-relationships.json"
    target._json_dump(
        path,
        {
            "schema_version": target.SCHEMA_VERSION,
            "collection_id": collection_id,
            "relationships": [
                {
                    "case_sha256": digest,
                    "layer_sha256": digest,
                    "is_pe": True,
                }
                for digest in digests
            ],
            "unique_pe_objects": len(set(digests)),
            "static_tools": {},
            "sample_executed": False,
            "network_contacted": False,
        },
    )
    return target._bounded_json_snapshot(path).sha256


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
    private_output = tmp_path / "private"
    input_snapshot = target._immutable_staging_snapshot(private_output, digest, data)
    input_path = input_snapshot.path
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
        input_snapshot=input_snapshot,
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
        private_output,
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
    private_output = tmp_path / "private"
    input_snapshot = target._immutable_staging_snapshot(private_output, digest, data)
    input_path = input_snapshot.path
    item = target.ProgramObject(
        sha256=digest,
        input_path=input_path,
        size=len(data),
        relationships=[{"case_sha256": digest, "depth": 0, "transform": "root"}],
        input_snapshot=input_snapshot,
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
            private_output,
            "/Malware/Test",
            analysis_timeout=1,
        )
    assert client.import_calls == 1


def test_client_accepts_only_numeric_loopback_plain_http() -> None:
    """Ghidra MCP接続先をDNS名ではなくnumeric loopbackの平文HTTPに限定する。"""

    assert target.GhidraMcpClient("http://127.0.0.1:8089").base_url == "http://127.0.0.1:8089"
    assert target.GhidraMcpClient("http://[::1]:8089").base_url == "http://[::1]:8089"
    for value in (
        "https://127.0.0.1:8089",
        "http://192.0.2.1:8089",
        "http://localhost:8089",
        "http://user:secret@127.0.0.1:8089",
        "http://localhost:8089/?token=secret",
        "http://127.0.0.1:not-a-port",
    ):
        with pytest.raises(ValueError):
            target.GhidraMcpClient(value)


def test_client_uses_proxy_free_opener_and_preserves_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """環境proxyを無視する専用openerでHTTP 200をbounded readする。"""

    monkeypatch.setenv("HTTP_PROXY", "http://198.51.100.10:3128")
    monkeypatch.setenv("HTTPS_PROXY", "http://198.51.100.11:3128")
    handlers: list[object] = []
    opened: list[tuple[Request, int]] = []

    class Response:
        def __enter__(self) -> "Response":
            return self

        def __exit__(self, *args: object) -> None:
            return None

        def read(self, amount: int = -1) -> bytes:
            assert amount == target.MAX_MCP_RESPONSE_BYTES + 1
            return b'{"ok":true}'

    class Opener:
        def open(self, request: Request, *, timeout: int) -> Response:
            opened.append((request, timeout))
            return Response()

    def fake_build_opener(*values: object) -> Opener:
        handlers.extend(values)
        return Opener()

    monkeypatch.setattr(target, "build_opener", fake_build_opener)
    client = target.GhidraMcpClient("http://127.0.0.1:8089", timeout=7)

    assert client.get("/analysis_status", program="/Malware/Test/sample") == {"ok": True}
    proxy_handlers = [value for value in handlers if isinstance(value, ProxyHandler)]
    assert len(proxy_handlers) == 1
    assert proxy_handlers[0].proxies == {}
    assert any(isinstance(value, target._RejectMcpRedirectHandler) for value in handlers)
    assert len(opened) == 1
    request, timeout = opened[0]
    assert request.full_url.startswith("http://127.0.0.1:8089/analysis_status?")
    assert timeout == 7


def test_client_rejects_mcp_error_object(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """HTTP 200内のMCP error objectを成功扱いしない。"""

    class Response:
        def __enter__(self) -> "Response":
            return self

        def __exit__(self, *args: object) -> None:
            return None

        def read(self, _amount: int = -1) -> bytes:
            return b'{"error":"Program not found"}'

    class Opener:
        def open(self, _request: Request, *, timeout: int) -> Response:
            assert timeout == 180
            return Response()

    monkeypatch.setattr(target, "_build_ghidra_mcp_opener", lambda: Opener())
    with pytest.raises(target.GhidraMcpError):
        target.GhidraMcpClient("http://127.0.0.1:8089").get(
            "/analysis_status",
            program="/Malware/Test/missing",
        )


@pytest.mark.parametrize(
    ("status_code", "destination"),
    [
        (301, "http://198.51.100.10/collect"),
        (302, "http://127.0.0.1:8090/next"),
        (303, "http://198.51.100.10/collect"),
        (307, "http://127.0.0.1:8090/next"),
        (308, "http://198.51.100.10/collect"),
    ],
)
def test_mcp_opener_rejects_redirect_before_destination_request(
    status_code: int,
    destination: str,
) -> None:
    """external／同一loopback redirectを拒否し、auth headerを転送しない。"""

    opened: list[tuple[str, dict[str, str]]] = []

    class RedirectingHttpHandler(HTTPHandler):
        def http_open(self, request: Request) -> object:
            opened.append((request.full_url, dict(request.header_items())))
            if len(opened) != 1:
                pytest.fail("redirect destinationをopenしました")
            headers = Message()
            headers["Location"] = destination
            response = addinfourl(
                io.BytesIO(b""),
                headers,
                request.full_url,
                code=status_code,
            )
            response.msg = "Synthetic redirect"
            return response

    opener = build_opener(
        ProxyHandler({}),
        target._RejectMcpRedirectHandler(),
        RedirectingHttpHandler(),
    )
    request = Request(
        "http://127.0.0.1:8089/analysis_status",
        headers={"Authorization": "Bearer synthetic-secret"},
    )

    with pytest.raises(target.GhidraMcpError, match="redirect"):
        opener.open(request, timeout=1)
    assert len(opened) == 1
    assert opened[0][0] == "http://127.0.0.1:8089/analysis_status"
    assert opened[0][1]["Authorization"] == "Bearer synthetic-secret"
    assert destination not in [value[0] for value in opened]


def test_client_rejects_oversize_response_before_decode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """小さくpatchしたresponse上限のlimit+1をJSON decode前に拒否する。"""

    monkeypatch.setattr(target, "MAX_MCP_RESPONSE_BYTES", 16)

    class Response:
        def __enter__(self) -> "Response":
            return self

        def __exit__(self, *args: object) -> None:
            return None

        def read(self, amount: int = -1) -> bytes:
            assert amount == 17
            return b"{" + b"x" * 16

    class Opener:
        def open(self, _request: Request, *, timeout: int) -> Response:
            assert timeout == 180
            return Response()

    monkeypatch.setattr(target, "_build_ghidra_mcp_opener", lambda: Opener())
    with pytest.raises(target.GhidraMcpError, match="bytes上限"):
        target.GhidraMcpClient("http://127.0.0.1:8089").get("/analysis_status")


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


def test_non_pe_only_case_accepts_static_script_function_evidence() -> None:
    """PE programがなくても静的script関数があれば公開対象として受理する。"""

    case_sha = "a" * 64
    records = target._selected_script_records(
        {
            case_sha: [
                {
                    "script_function_records": [
                        {
                            "function_id": "script:entry",
                            "analysis_kind": "script_static",
                        }
                    ]
                }
            ]
        },
        case_sha,
    )

    target._require_case_static_evidence(case_sha, [], records, [])
    assert records == [
        {
            "function_id": "script:entry",
            "analysis_kind": "script_static",
            "selected_for_characteristic_analysis": True,
            "selection_score": 1_000,
            "selection_reasons": ["static_script_entry_or_function"],
        }
    ]


def test_unresolved_function_gate_accepts_only_canonical_states() -> None:
    """未分類caseでは未宣言または静的解析済みの正規状態だけを許可する。"""

    assert target._valid_unresolved_function_gate(
        {"required": None, "satisfied": False, "observed": None, "status": "not_declared"}
    )
    assert target._valid_unresolved_function_gate(
        {"required": None, "satisfied": True, "observed": None, "status": "satisfied"}
    )
    assert not target._valid_unresolved_function_gate(
        {"required": True, "satisfied": True, "observed": None, "status": "satisfied"}
    )


def test_non_pe_layer_only_evidence_is_accepted_for_legacy_checkpoint() -> None:
    """旧checkpointでも非PE layer証跡があれば構造限定解析へ進める。"""

    target._require_case_static_evidence(
        "b" * 64,
        [],
        [],
        [{"is_pe": False, "format": "script"}],
    )


def test_case_without_static_evidence_is_rejected() -> None:
    """program、script関数、非PE layerがすべてないcaseは拒否する。"""

    with pytest.raises(ValueError, match="非PE layer証跡"):
        target._require_case_static_evidence("c" * 64, [], [], [])


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


def test_load_prepared_inputs_rejects_hardlinked_inventory(tmp_path: Path) -> None:
    """repository外fileへのhardlinkをprepared inventoryとして受理しない。"""

    external = tmp_path / "external-inventory.json"
    private = tmp_path / "private"
    private.mkdir()
    target._json_dump(
        external,
        {
            "unique_pe_objects": 1,
            "relationships": [],
        },
    )
    try:
        os.link(external, private / "input-relationships.json")
    except OSError as exc:
        pytest.skip(f"hardlinkを作成できない環境です: {exc}")

    with pytest.raises(ValueError, match="hardlink"):
        target.load_prepared_inputs(tmp_path / "samples", private)


def test_load_prepared_inputs_rejects_external_hardlink_cache(
    tmp_path: Path,
) -> None:
    """sample root外fileへのhardlinkを検証済みPE cacheとして受理しない。"""

    data = b"MZ-external-hardlink"
    digest = hashlib.sha256(data).hexdigest()
    short_root = tmp_path.parents[2] / (
        "cache-hardlink-" + hashlib.sha256(str(tmp_path).encode()).hexdigest()[:8]
    )
    sample_root = short_root / "s"
    input_path = (
        sample_root
        / digest
        / "ghidra-input"
        / f"{digest}.quarantine.bin"
    )
    input_path.parent.mkdir(parents=True)
    external = short_root / "external-cache.bin"
    external.parent.mkdir(parents=True, exist_ok=True)
    external.write_bytes(data)
    try:
        os.link(external, input_path)
    except OSError as exc:
        pytest.skip(f"hardlinkを作成できない環境です: {exc}")
    private = short_root / "p"
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
                }
            ],
        },
    )

    with pytest.raises(ValueError, match="hardlink"):
        target.load_prepared_inputs(sample_root, private)


def test_regular_snapshot_detects_same_content_identity_replacement(
    tmp_path: Path,
) -> None:
    """同一bytesへの差替えでも固定済みfile identityの変更を拒否する。"""

    path = tmp_path / "bound.bin"
    replacement = tmp_path / "replacement.bin"
    data = b"same-content"
    path.write_bytes(data)
    replacement.write_bytes(data)
    _, snapshot = target._bounded_regular_file_snapshot(
        path,
        max_bytes=len(data),
    )
    os.replace(replacement, path)

    with pytest.raises(ValueError, match="競合変更"):
        target._assert_regular_snapshot_unchanged(
            snapshot,
            context="test",
        )


def test_archive_manifest_index_accepts_contained_absolute_and_relative_paths(
    tmp_path: Path,
) -> None:
    """sample root内の絶対／相対archiveだけを決定的に索引化する。"""

    sample_root = tmp_path / "samples"
    first = sample_root / "a" / "first.zip"
    second = sample_root / "b" / "second.zip"
    first.parent.mkdir(parents=True)
    second.parent.mkdir(parents=True)
    first.write_bytes(b"first")
    second.write_bytes(b"second")
    first_digest = "a" * 64
    second_digest = "b" * 64

    index = target._archive_manifest_index(
        sample_root,
        {
            "items": [
                {"sha256": first_digest, "zip_path": str(first)},
                {"sha256": second_digest, "zip_path": "b/second.zip"},
            ]
        },
    )

    assert index[first_digest].path == first.resolve()
    assert index[second_digest].path == second.resolve()


def test_archive_manifest_index_rejects_absolute_path_outside_root(
    tmp_path: Path,
) -> None:
    """絶対zip_pathでもsample root外のfileを入力へ使用しない。"""

    sample_root = tmp_path / "samples"
    sample_root.mkdir()
    outside = tmp_path / "outside.zip"
    outside.write_bytes(b"outside")

    with pytest.raises(ValueError, match="sample root外"):
        target._archive_manifest_index(
            sample_root,
            {"items": [{"sha256": "a" * 64, "zip_path": str(outside)}]},
        )


def test_archive_manifest_index_rejects_parent_traversal(tmp_path: Path) -> None:
    """相対zip_pathの親directory traversalを解決前に拒否する。"""

    sample_root = tmp_path / "samples"
    sample_root.mkdir()
    (tmp_path / "outside.zip").write_bytes(b"outside")

    with pytest.raises(ValueError, match="親directory参照"):
        target._archive_manifest_index(
            sample_root,
            {"items": [{"sha256": "a" * 64, "zip_path": "../outside.zip"}]},
        )


def test_archive_manifest_index_rejects_hardlinked_archive(tmp_path: Path) -> None:
    """sample root外fileへのhardlinkをarchive入力として受理しない。"""

    sample_root = tmp_path / "samples"
    sample_root.mkdir()
    outside = tmp_path / "outside.zip"
    archive = sample_root / "archive.zip"
    outside.write_bytes(b"same-volume")
    try:
        os.link(outside, archive)
    except OSError as exc:
        pytest.skip(f"hardlinkを作成できない環境です: {exc}")

    with pytest.raises(ValueError, match="hardlink"):
        target._archive_manifest_index(
            sample_root,
            {"items": [{"sha256": "a" * 64, "zip_path": str(archive)}]},
        )


def test_archive_manifest_index_rejects_reparse_archive(tmp_path: Path) -> None:
    """sample root内のsymlinkから外部archiveへ到達しない。"""

    sample_root = tmp_path / "samples"
    sample_root.mkdir()
    outside = tmp_path / "outside.zip"
    archive = sample_root / "archive.zip"
    outside.write_bytes(b"outside")
    try:
        archive.symlink_to(outside)
    except OSError as exc:
        pytest.skip(f"symlinkを作成できない環境です: {exc}")

    with pytest.raises(ValueError, match="reparse point"):
        target._archive_manifest_index(
            sample_root,
            {"items": [{"sha256": "a" * 64, "zip_path": str(archive)}]},
        )


def test_manifest_snapshot_rejects_hardlink_and_oversize(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """入力manifestもhardlinkと読取上限を同じsnapshot境界で拒否する。"""

    sample_root = tmp_path / "samples"
    sample_root.mkdir()
    external = tmp_path / "external-manifest.json"
    external.write_text('{"items": []}', encoding="utf-8")
    manifest = sample_root / "manifest.json"
    try:
        os.link(external, manifest)
    except OSError as exc:
        pytest.skip(f"hardlinkを作成できない環境です: {exc}")
    with pytest.raises(ValueError, match="hardlink"):
        target._bounded_json_snapshot(manifest)

    manifest.unlink()
    external.unlink()
    manifest.write_text('{"padding":"' + ("x" * 80) + '"}', encoding="utf-8")
    monkeypatch.setattr(target, "MAX_JSON_OBJECT_SIZE", 64)
    with pytest.raises(ValueError, match="上限"):
        target._bounded_json_snapshot(manifest)


def test_read_manifest_archive_rejects_same_bytes_identity_swap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """snapshot後に同一bytesへ差し替えてもarchive bindingを拒否する。"""

    archive = tmp_path / "archive.zip"
    replacement = tmp_path / "replacement.zip"
    data = b"fixture archive"
    archive.write_bytes(data)
    replacement.write_bytes(data)
    digest = "a" * 64
    entry = target._ArchiveManifestEntry(
        sha256=digest,
        path=archive,
        expected_zip_sha256=hashlib.sha256(data).hexdigest(),
        expected_zip_size=len(data),
    )

    def swap_after_snapshot(path: object, **_kwargs: object) -> SimpleNamespace:
        assert isinstance(path, target._SnapshotInputPath)
        assert path.open().read() == data
        os.replace(replacement, archive)
        return SimpleNamespace(
            data=b"root",
            outer_sha256=hashlib.sha256(data).hexdigest(),
            outer_size=len(data),
        )

    monkeypatch.setattr(target, "read_input_unit", swap_after_snapshot)
    with pytest.raises(ValueError, match="競合変更"):
        target._read_manifest_archive(entry)


def test_read_manifest_archive_rejects_oversize_before_archive_parse(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ZIP読取上限超過はarchive parserへ渡す前に拒否する。"""

    archive = tmp_path / "archive.zip"
    archive.write_bytes(b"0123456789")
    entry = target._ArchiveManifestEntry(
        sha256="a" * 64,
        path=archive,
        expected_zip_sha256=None,
        expected_zip_size=None,
    )
    monkeypatch.setattr(target, "MAX_PREPARED_INPUT_BYTES", 8)
    monkeypatch.setattr(
        target,
        "read_input_unit",
        lambda *_args, **_kwargs: pytest.fail("過大ZIPをparserへ渡してはいけません"),
    )

    with pytest.raises(ValueError, match="上限"):
        target._read_manifest_archive(entry)


def test_immutable_staging_is_private_reusable_and_never_overwrites_tamper(
    tmp_path: Path,
) -> None:
    """private stagingは同一bytesだけ再利用し、第三者bytesを上書きしない。"""

    private = tmp_path / "private"
    data = b"MZ-staging"
    digest = hashlib.sha256(data).hexdigest()
    first = target._immutable_staging_snapshot(private, digest, data)
    second = target._immutable_staging_snapshot(private, digest, data)
    assert first.path == second.path
    assert private in first.path.parents

    first.path.write_bytes(b"third-party")
    with pytest.raises(ValueError, match="SHA-256"):
        target._immutable_staging_snapshot(private, digest, data)
    assert first.path.read_bytes() == b"third-party"


def test_private_jsonl_positive_tamper_and_oversize(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """private JSONLは正常系を保持し、tamperとsize超過をfail-closedにする。"""

    path = tmp_path / "raw.jsonl"
    target._append_jsonl(path, [{"address": "0x1", "value": "ok"}])
    assert target._load_jsonl(path)["0x1"]["value"] == "ok"

    path.write_text("not-json\n", encoding="utf-8")
    with pytest.raises(ValueError, match="JSONLが不正"):
        target._load_jsonl(path)

    path.write_bytes(b"{}\n" * 8)
    monkeypatch.setattr(target, "MAX_PRIVATE_RAW_BYTES", 8)
    with pytest.raises(ValueError, match="上限"):
        target._bounded_jsonl_snapshot(path)


def test_private_jsonl_atomic_update_rejects_identity_swap(tmp_path: Path) -> None:
    """raw cache snapshot後の同一bytes path差替えをatomic commitで拒否する。"""

    path = tmp_path / "raw.jsonl"
    replacement = tmp_path / "replacement.jsonl"
    data = b'{"address":"0x1"}\n'
    path.write_bytes(data)
    replacement.write_bytes(data)
    _, snapshot = target._bounded_jsonl_snapshot(path)
    os.replace(replacement, path)

    with pytest.raises(ValueError, match="競合変更"):
        target._atomic_replace_bytes(
            path,
            b'{"address":"0x2"}\n',
            expected_snapshot=snapshot,
            maximum_bytes=target.MAX_PRIVATE_RAW_BYTES,
        )
    assert path.read_bytes() == data


def test_private_jsonl_streaming_positive_and_replace(tmp_path: Path) -> None:
    """末尾改行なしの既存fileもstream追記でき、全置換もstrictに読める。"""

    path = tmp_path / "raw.jsonl"
    path.write_bytes(b'{"address":"0x1","value":"first"}')

    target._append_jsonl(path, [{"address": "0x2", "value": "second"}])
    loaded = target._load_jsonl(path)
    assert sorted(loaded) == ["0x1", "0x2"]
    assert loaded["0x2"]["value"] == "second"

    target._replace_jsonl(path, [{"address": "0x3", "value": "replacement"}])
    assert target._load_jsonl(path) == {
        "0x3": {"address": "0x3", "value": "replacement"}
    }
    assert target.MAX_PRIVATE_RAW_BYTES <= 64 * 1024 * 1024


def test_private_jsonl_total_limit_plus_one_uses_small_fixture(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """小さなfixtureとmonkeypatchで総bytesのlimit+1を拒否する。"""

    path = tmp_path / "raw.jsonl"
    data = b'{"address":"0x1"}\n'
    path.write_bytes(data)
    monkeypatch.setattr(target, "MAX_PRIVATE_RAW_BYTES", len(data) - 1)

    with pytest.raises(ValueError, match="総bytes上限"):
        target._bounded_jsonl_snapshot(path)


def test_private_jsonl_line_and_record_limits(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """1行bytesとJSON record件数を独立して制限する。"""

    path = tmp_path / "raw.jsonl"
    line = b'{"address":"0x1","value":"long"}\n'
    path.write_bytes(line)
    monkeypatch.setattr(target, "MAX_PRIVATE_RAW_BYTES", 4_096)
    monkeypatch.setattr(target, "MAX_PRIVATE_RAW_LINE_BYTES", len(line) - 1)
    with pytest.raises(ValueError, match="1行bytes上限"):
        target._bounded_jsonl_snapshot(path)

    monkeypatch.setattr(target, "MAX_PRIVATE_RAW_LINE_BYTES", 4_096)
    monkeypatch.setattr(target, "MAX_PRIVATE_RAW_RECORDS", 2)
    path.write_bytes(
        b'{"address":"0x1"}\n'
        b'{"address":"0x2"}\n'
        b'{"address":"0x3"}\n'
    )
    with pytest.raises(ValueError, match="record数上限"):
        target._bounded_jsonl_snapshot(path)


@pytest.mark.parametrize(
    "payload",
    [
        b'{"address":"0x1","address":"0x2"}\n',
        b'{"address":"0x1","value":NaN}\n',
        b'{"address":"0x1","value":Infinity}\n',
    ],
)
def test_private_jsonl_rejects_duplicate_and_non_finite(
    tmp_path: Path,
    payload: bytes,
) -> None:
    """duplicate keyとNaN／Infinityをstrict parserで拒否する。"""

    path = tmp_path / "raw.jsonl"
    path.write_bytes(payload)
    with pytest.raises(ValueError, match="JSONLが不正"):
        target._bounded_jsonl_snapshot(path)


def test_private_jsonl_depth_limit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """JSON container深度の上限超過を拒否する。"""

    path = tmp_path / "raw.jsonl"
    path.write_bytes(b'{"address":"0x1","a":{"b":{"c":1}}}\n')
    monkeypatch.setattr(target, "MAX_PRIVATE_RAW_JSON_DEPTH", 2)

    with pytest.raises(ValueError, match="JSONLが不正"):
        target._bounded_jsonl_snapshot(path)


def test_private_jsonl_generator_size_over_preserves_existing_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """generatorの累積size超過時もatomic置換前のfileを変更しない。"""

    path = tmp_path / "raw.jsonl"
    target._append_jsonl(path, [{"address": "0x1"}])
    before = path.read_bytes()
    extra = {"address": "0x2"}
    encoded_extra = (
        json.dumps(extra, ensure_ascii=False, sort_keys=True, allow_nan=False) + "\n"
    ).encode("utf-8")
    monkeypatch.setattr(
        target,
        "MAX_PRIVATE_RAW_BYTES",
        len(before) + len(encoded_extra) - 1,
    )

    def values() -> object:
        yield extra

    with pytest.raises(ValueError, match="総bytes上限"):
        target._append_jsonl(path, values())
    assert path.read_bytes() == before
    assert not list(tmp_path.glob(".jsonl-*.tmp"))


def test_private_jsonl_streaming_does_not_use_whole_snapshot_helper(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """parse、hash再検証、atomic追記でwhole-file snapshot helperを使わない。"""

    path = tmp_path / "raw.jsonl"
    target._append_jsonl(path, [{"address": "0x1"}])
    monkeypatch.setattr(
        target,
        "_bounded_regular_file_snapshot",
        lambda *_args, **_kwargs: pytest.fail("whole snapshotを使用しました"),
    )

    rows, snapshot = target._bounded_jsonl_snapshot(path)
    assert rows == [{"address": "0x1"}]
    target._assert_jsonl_snapshot_unchanged(snapshot)
    target._append_jsonl(path, [{"address": "0x2"}])
    assert sorted(target._load_jsonl(path)) == ["0x1", "0x2"]

def test_private_jsonl_parse_rehash_rejects_mixed_view_with_restored_metadata(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """parse後の別stream viewが異なるhashなら同一metadataでも拒否する。"""

    path = tmp_path / "raw.jsonl"
    data = b'{"address":"0x1"}\n'
    path.write_bytes(data)
    metadata = path.lstat()
    calls = 0

    def mismatched_digest(
        requested: Path,
        *,
        maximum_bytes: int,
        destination: object | None = None,
    ) -> object:
        nonlocal calls
        calls += 1
        assert maximum_bytes >= len(data)
        assert destination is None
        return target._RegularFileSnapshot(
            path=requested.resolve(),
            sha256="f" * 64,
            size=len(data),
            metadata=metadata,
        )

    monkeypatch.setattr(target, "_stream_private_raw_digest", mismatched_digest)
    with pytest.raises(ValueError, match="競合変更"):
        target._bounded_jsonl_snapshot(path)
    assert calls == 1



def test_private_jsonl_atomic_rewrite_rejects_identity_swap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """commit直前の同一bytes identity差替えをstreaming rewriteでも拒否する。"""

    path = tmp_path / "raw.jsonl"
    replacement = tmp_path / "replacement.jsonl"
    data = b'{"address":"0x1"}\n'
    path.write_bytes(data)
    replacement.write_bytes(data)
    original_assert = target._assert_jsonl_snapshot_unchanged
    swapped = False

    def swap_then_assert(snapshot: object) -> None:
        nonlocal swapped
        if not swapped:
            os.replace(replacement, path)
            swapped = True
        original_assert(snapshot)

    monkeypatch.setattr(target, "_assert_jsonl_snapshot_unchanged", swap_then_assert)
    with pytest.raises(ValueError, match="競合変更"):
        target._append_jsonl(path, [{"address": "0x2"}])
    assert path.read_bytes() == data
    assert not list(tmp_path.glob(".jsonl-*.tmp"))


@pytest.mark.skipif(os.name != "nt", reason="Windows deny-write/delete共有の検証です")
def test_staging_lock_blocks_path_swap_during_import_window(tmp_path: Path) -> None:
    """WindowsではMCP import window中のstaging差替えをOS handleで拒否する。"""

    private = tmp_path / "private"
    data = b"MZ-locked"
    digest = hashlib.sha256(data).hexdigest()
    snapshot = target._immutable_staging_snapshot(private, digest, data)
    replacement = tmp_path / "replacement.bin"
    replacement.write_bytes(data)

    with target._hold_staging_read_lock(snapshot):
        with pytest.raises(OSError):
            os.replace(replacement, snapshot.path)
    assert snapshot.path.read_bytes() == data


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
        "complete": False,
        "resumable": False,
        "blockers": [],
    }
    assert analysis_contract.verify_report_semantics(refreshed) == []
    assert validation_calls == [{"expected_digest": digest, "require_resumable": False}]
def test_finalize_case_report_preserves_unresolved_orchestration(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Preserve unresolved orchestration while closing only the function blocker."""

    digest = "9" * 64
    case_dir = tmp_path / digest
    case_dir.mkdir()
    target._json_dump(case_dir / "static-logic.json", {"status": "complete"})
    outcome = {
        "schema_version": target.ORCHESTRATION_SCHEMA_VERSION,
        "sample_sha256": digest,
        "status": "partial",
        "family_resolution": {
            "status": "unresolved",
            "family": None,
            "reason": "no_candidate_met_evidence_threshold",
            "candidates": [],
        },
        "quality_gates": {
            "function_analysis": {
                "required": None,
                "satisfied": False,
                "observed": None,
                "status": "not_declared",
            }
        },
        "blockers": ["family_resolution"],
        "next_actions_ja": ["add structural evidence for a family candidate"],
        "automation": {
            "ai_used": False,
            "sample_executed": False,
            "network_contacted": False,
        },
    }
    target._json_dump(case_dir / "orchestration.json", outcome)
    orchestration_before = (case_dir / "orchestration.json").read_bytes()
    report = {
        "classification": {"selected_families": []},
        "orchestration": "orchestration.json",
        "case_state": {
            "status": "partial",
            "complete": False,
            "resumable": False,
            "blockers": [target.FUNCTION_ANALYSIS_BLOCKER],
        },
        "artifact_sha256": {
            name: hashlib.sha256((case_dir / name).read_bytes()).hexdigest()
            for name in ("static-logic.json", "orchestration.json")
        },
    }
    analysis_contract.seal_report(report)
    target._json_dump(case_dir / "report.json", report)
    monkeypatch.setattr(target, "case_integrity_errors", lambda *_args, **_kwargs: [])

    assert target.finalize_case_report(case_dir) == "triaged_unknown"
    assert (case_dir / "orchestration.json").read_bytes() == orchestration_before
    refreshed = target.load_json_object_strict(case_dir / "report.json")
    assert refreshed["case_state"] == {
        "status": "triaged_unknown",
        "complete": False,
        "resumable": False,
        "blockers": [],
    }
    assert refreshed["artifact_sha256"]["orchestration.json"] == hashlib.sha256(
        orchestration_before
    ).hexdigest()




def _write_finalize_orchestration_fixture(
    case_dir: Path,
    *,
    family: str,
    terminal_payload_missing: bool,
) -> dict[str, object]:
    """Ghidra後reconciliation用のschema 2 orchestrationを作成する。"""

    if terminal_payload_missing:
        requirements = {
            "config_required": False,
            "network_required": False,
            "terminal_payload_required": True,
            "function_analysis_required": True,
        }
        config_gate = {
            "required": False,
            "satisfied": False,
            "observed": None,
            "status": "not_applicable",
        }
        network_gate = {
            "required": False,
            "satisfied": False,
            "observed": False,
            "status": "not_applicable",
        }
        terminal_gate = {
            "required": True,
            "satisfied": False,
            "observed": None,
            "status": "required_missing",
        }
        blockers = ["function_analysis", "terminal_payload"]
        next_actions = [
            target.FUNCTION_ANALYSIS_NEXT_ACTION_JA,
            "後段payloadの静的復元処理を追加してください。",
        ]
    else:
        requirements = {
            "config_required": True,
            "network_required": True,
            "terminal_payload_required": False,
            "function_analysis_required": True,
        }
        config_gate = {
            "required": True,
            "satisfied": True,
            "observed": None,
            "status": "satisfied",
        }
        network_gate = {
            "required": True,
            "satisfied": True,
            "observed": True,
            "status": "satisfied",
        }
        terminal_gate = {
            "required": False,
            "satisfied": False,
            "observed": None,
            "status": "not_applicable",
        }
        blockers = ["function_analysis"]
        next_actions = [target.FUNCTION_ANALYSIS_NEXT_ACTION_JA]
    satisfied_gate = {
        "required": True,
        "satisfied": True,
        "observed": None,
        "status": "satisfied",
    }
    outcome: dict[str, object] = {
        "schema_version": target.ORCHESTRATION_SCHEMA_VERSION,
        "sample_sha256": case_dir.name,
        "status": "partial",
        "family_resolution": {
            "status": "resolved",
            "family": family,
            "requirements": requirements,
            "candidates": [{"family": family, "sentinel": "preserve-resolution"}],
        },
        "outputs": {"sentinel": "preserve-outputs"},
        "candidate_outputs": {"sentinel": "preserve-candidate-outputs"},
        "handler_evidence": {"sentinel": "preserve-handler-evidence"},
        "quality_gates": {
            "generic_triage": dict(satisfied_gate),
            "static_layers": dict(satisfied_gate),
            "family_resolution": dict(satisfied_gate),
            "handler_evidence": dict(satisfied_gate),
            "config": config_gate,
            "network": network_gate,
            "terminal_payload": terminal_gate,
            "function_analysis": {
                "required": True,
                "satisfied": False,
                "observed": None,
                "status": "required_missing",
            },
            "requirements_policy": {
                "required": True,
                "satisfied": True,
                "observed": True,
                "status": "satisfied",
            },
        },
        "blockers": blockers,
        "next_actions_ja": next_actions,
        "automation": {
            "ai_used": False,
            "sample_executed": False,
            "network_contacted": False,
        },
        "extension": {"sentinel": "preserve-extension"},
    }
    target._json_dump(case_dir / "orchestration.json", outcome)
    return outcome


def _write_orchestration_finalize_report(
    case_dir: Path,
    *,
    family: str,
    blockers: list[str],
) -> None:
    """orchestration参照とhashを持つpartial reportを作成する。"""

    target._json_dump(case_dir / "static-logic.json", {"status": "complete"})
    report = {
        "classification": {"selected_families": [family]},
        "orchestration": "orchestration.json",
        "case_state": {
            "status": "partial",
            "complete": False,
            "resumable": False,
            "blockers": blockers,
        },
        "artifact_sha256": {
            name: hashlib.sha256((case_dir / name).read_bytes()).hexdigest()
            for name in ("static-logic.json", "orchestration.json")
        },
    }
    analysis_contract.seal_report(report)
    target._json_dump(case_dir / "report.json", report)


def test_finalize_case_report_reconciles_njrat_orchestration_to_complete(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """functionだけが不足する解決済みNJRat形は全gate完了へ遷移する。"""

    digest = "a" * 64
    case_dir = tmp_path / digest
    case_dir.mkdir()
    outcome = _write_finalize_orchestration_fixture(
        case_dir,
        family="njrat",
        terminal_payload_missing=False,
    )
    _write_orchestration_finalize_report(
        case_dir,
        family="njrat",
        blockers=[target.ORCHESTRATION_FUNCTION_ANALYSIS_BLOCKER],
    )
    original_hash = hashlib.sha256((case_dir / "orchestration.json").read_bytes()).hexdigest()
    preserved = {
        name: outcome[name]
        for name in (
            "family_resolution",
            "outputs",
            "candidate_outputs",
            "handler_evidence",
            "extension",
        )
    }
    preserved_gates = {
        name: gate
        for name, gate in outcome["quality_gates"].items()
        if name != "function_analysis"
    }
    validation_calls: list[tuple[Path, str]] = []
    integrity_calls: list[dict[str, object]] = []

    def valid_function_analysis(path: Path, sha256: str) -> SimpleNamespace:
        validation_calls.append((path, sha256))
        return SimpleNamespace(valid=True, findings=[])

    def no_integrity_errors(*args: object, **kwargs: object) -> list[str]:
        integrity_calls.append(kwargs)
        return []

    monkeypatch.setattr(target, "validate_function_case", valid_function_analysis)
    monkeypatch.setattr(target, "case_integrity_errors", no_integrity_errors)

    assert target.finalize_case_report(case_dir) == "complete"
    refreshed_outcome = target.load_json_object_strict(case_dir / "orchestration.json")
    refreshed_report = target.load_json_object_strict(case_dir / "report.json")
    assert refreshed_outcome["quality_gates"]["function_analysis"] == {
        "required": True,
        "satisfied": True,
        "observed": None,
        "status": "satisfied",
    }
    assert refreshed_outcome["status"] == "complete"
    assert refreshed_outcome["blockers"] == []
    assert refreshed_outcome["next_actions_ja"] == []
    assert {name: refreshed_outcome[name] for name in preserved} == preserved
    assert {
        name: gate
        for name, gate in refreshed_outcome["quality_gates"].items()
        if name != "function_analysis"
    } == preserved_gates
    assert refreshed_report["case_state"] == {
        "status": "complete",
        "complete": True,
        "resumable": True,
        "blockers": [],
    }
    refreshed_hash = hashlib.sha256((case_dir / "orchestration.json").read_bytes()).hexdigest()
    assert refreshed_hash != original_hash
    assert refreshed_report["artifact_sha256"]["orchestration.json"] == refreshed_hash
    assert analysis_contract.verify_report_semantics(refreshed_report) == []
    assert validation_calls == [(case_dir, digest)]
    assert integrity_calls == [{"expected_digest": digest, "require_resumable": True}]


def test_finalize_case_report_preserves_dotnet_terminal_payload_blocker(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """dotnet loader形はfunctionだけを閉じ、terminal payload不足を保持する。"""

    digest = "b" * 64
    case_dir = tmp_path / digest
    case_dir.mkdir()
    outcome = _write_finalize_orchestration_fixture(
        case_dir,
        family="dotnet_resource_loader",
        terminal_payload_missing=True,
    )
    preserved_gates = {
        name: gate
        for name, gate in outcome["quality_gates"].items()
        if name != "function_analysis"
    }
    preserved_outputs = outcome["outputs"]
    preserved_resolution = outcome["family_resolution"]
    _write_orchestration_finalize_report(
        case_dir,
        family="dotnet_resource_loader",
        blockers=[
            target.ORCHESTRATION_FUNCTION_ANALYSIS_BLOCKER,
            "orchestration:terminal_payload",
        ],
    )
    monkeypatch.setattr(
        target,
        "validate_function_case",
        lambda *_args: SimpleNamespace(valid=True, findings=[]),
    )
    monkeypatch.setattr(target, "case_integrity_errors", lambda *_args, **_kwargs: [])

    assert target.finalize_case_report(case_dir) == "partial"
    refreshed_outcome = target.load_json_object_strict(case_dir / "orchestration.json")
    refreshed_report = target.load_json_object_strict(case_dir / "report.json")
    assert refreshed_outcome["status"] == "partial"
    assert refreshed_outcome["blockers"] == ["terminal_payload"]
    assert refreshed_outcome["next_actions_ja"] == [
        "後段payloadの静的復元処理を追加してください。"
    ]
    assert {
        name: gate
        for name, gate in refreshed_outcome["quality_gates"].items()
        if name != "function_analysis"
    } == preserved_gates
    assert refreshed_outcome["outputs"] == preserved_outputs
    assert refreshed_outcome["family_resolution"] == preserved_resolution
    assert refreshed_report["case_state"] == {
        "status": "partial",
        "complete": False,
        "resumable": False,
        "blockers": ["orchestration:terminal_payload"],
    }
    assert refreshed_report["artifact_sha256"]["orchestration.json"] == hashlib.sha256(
        (case_dir / "orchestration.json").read_bytes()
    ).hexdigest()
    assert analysis_contract.verify_report_semantics(refreshed_report) == []


def test_finalize_case_report_rejects_invalid_function_analysis_without_writes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """function成果物の完了検証失敗時はorchestration/reportを変更しない。"""

    digest = "c" * 64
    case_dir = tmp_path / digest
    case_dir.mkdir()
    _write_finalize_orchestration_fixture(
        case_dir,
        family="njrat",
        terminal_payload_missing=False,
    )
    _write_orchestration_finalize_report(
        case_dir,
        family="njrat",
        blockers=[target.ORCHESTRATION_FUNCTION_ANALYSIS_BLOCKER],
    )
    orchestration_before = (case_dir / "orchestration.json").read_bytes()
    report_before = (case_dir / "report.json").read_bytes()
    monkeypatch.setattr(
        target,
        "validate_function_case",
        lambda *_args: SimpleNamespace(valid=False, findings=["coverage不足"]),
    )

    with pytest.raises(ValueError, match="代表関数解析の完了検証に失敗"):
        target.finalize_case_report(case_dir)
    assert (case_dir / "orchestration.json").read_bytes() == orchestration_before
    assert (case_dir / "report.json").read_bytes() == report_before


def test_finalize_case_report_rolls_back_both_files_after_integrity_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """後段integrity失敗時はorchestration/reportを元bytesへatomicに戻す。"""

    digest = "d" * 64
    case_dir = tmp_path / digest
    case_dir.mkdir()
    _write_finalize_orchestration_fixture(
        case_dir,
        family="njrat",
        terminal_payload_missing=False,
    )
    _write_orchestration_finalize_report(
        case_dir,
        family="njrat",
        blockers=[target.ORCHESTRATION_FUNCTION_ANALYSIS_BLOCKER],
    )
    orchestration_before = (case_dir / "orchestration.json").read_bytes()
    report_before = (case_dir / "report.json").read_bytes()
    observed_updated_bytes: list[tuple[bytes, bytes]] = []
    monkeypatch.setattr(
        target,
        "validate_function_case",
        lambda *_args: SimpleNamespace(valid=True, findings=[]),
    )

    def injected_integrity_failure(*_args: object, **_kwargs: object) -> list[str]:
        observed_updated_bytes.append(
            (
                (case_dir / "orchestration.json").read_bytes(),
                (case_dir / "report.json").read_bytes(),
            )
        )
        return ["injected_integrity_failure"]

    monkeypatch.setattr(target, "case_integrity_errors", injected_integrity_failure)

    with pytest.raises(ValueError, match="injected_integrity_failure"):
        target.finalize_case_report(case_dir)
    assert len(observed_updated_bytes) == 1
    assert observed_updated_bytes[0][0] != orchestration_before
    assert observed_updated_bytes[0][1] != report_before
    assert (case_dir / "orchestration.json").read_bytes() == orchestration_before
    assert (case_dir / "report.json").read_bytes() == report_before
    assert list(case_dir.glob(".*.tmp")) == []


def test_finalize_case_report_verifies_entire_manifest_before_update(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """orchestration以外の既存成果物hash不一致も更新前に拒否する。"""

    digest = "e" * 64
    case_dir = tmp_path / digest
    case_dir.mkdir()
    _write_finalize_orchestration_fixture(
        case_dir,
        family="njrat",
        terminal_payload_missing=False,
    )
    _write_orchestration_finalize_report(
        case_dir,
        family="njrat",
        blockers=[target.ORCHESTRATION_FUNCTION_ANALYSIS_BLOCKER],
    )
    orchestration_before = (case_dir / "orchestration.json").read_bytes()
    report_before = (case_dir / "report.json").read_bytes()
    target._json_dump(case_dir / "static-logic.json", {"status": "tampered"})
    validation_called = False

    def unexpected_validation(*_args: object) -> SimpleNamespace:
        nonlocal validation_called
        validation_called = True
        return SimpleNamespace(valid=True, findings=[])

    monkeypatch.setattr(target, "validate_function_case", unexpected_validation)

    with pytest.raises(ValueError, match="更新前の全成果物hash検証に失敗"):
        target.finalize_case_report(case_dir)
    assert validation_called is False
    assert (case_dir / "orchestration.json").read_bytes() == orchestration_before
    assert (case_dir / "report.json").read_bytes() == report_before


def test_finalize_case_report_preserves_competing_orchestration_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """prepare後の第三者変更を拒否し、そのbytesをrollbackで上書きしない。"""

    digest = "f" * 64
    case_dir = tmp_path / digest
    case_dir.mkdir()
    _write_finalize_orchestration_fixture(
        case_dir,
        family="njrat",
        terminal_payload_missing=False,
    )
    _write_orchestration_finalize_report(
        case_dir,
        family="njrat",
        blockers=[target.ORCHESTRATION_FUNCTION_ANALYSIS_BLOCKER],
    )
    orchestration_before = (case_dir / "orchestration.json").read_bytes()
    report_before = (case_dir / "report.json").read_bytes()
    competing_bytes: list[bytes] = []

    def mutate_after_prepare(*_args: object) -> SimpleNamespace:
        path = case_dir / "orchestration.json"
        competing = target.load_json_object_strict(path)
        competing["extension"]["competing_writer"] = "preserve-these-bytes"
        target._json_dump(path, competing)
        competing_bytes.append(path.read_bytes())
        return SimpleNamespace(valid=True, findings=[])

    def unexpected_integrity(*_args: object, **_kwargs: object) -> list[str]:
        pytest.fail("競合変更時にcase integrityへ進んではならない")

    monkeypatch.setattr(target, "validate_function_case", mutate_after_prepare)
    monkeypatch.setattr(target, "case_integrity_errors", unexpected_integrity)

    with pytest.raises(ValueError, match="transaction commit直前で競合変更"):
        target.finalize_case_report(case_dir)
    assert len(competing_bytes) == 1
    assert competing_bytes[0] != orchestration_before
    assert (case_dir / "orchestration.json").read_bytes() == competing_bytes[0]
    assert (case_dir / "report.json").read_bytes() == report_before
    assert list(case_dir.glob(".*.tmp")) == []


@pytest.mark.parametrize("name", ["report.json", "orchestration.json"])
def test_bounded_json_snapshot_rejects_oversize(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    name: str,
) -> None:
    """transaction対象JSONは読取前に64MiB超を拒否する。"""

    path = tmp_path / name
    path.write_bytes(b"{}")
    observed: list[tuple[Path, int]] = []

    def reject_oversize(candidate: Path, *, max_bytes: int) -> bytes:
        observed.append((candidate, max_bytes))
        raise ValueError(
            f"成果物が{max_bytes} bytes上限を超えています: {candidate}"
        )

    monkeypatch.setattr(
        target,
        "_read_regular_file_snapshot",
        reject_oversize,
    )

    with pytest.raises(ValueError, match="bytes上限を超えています"):
        target._bounded_json_snapshot(path)
    assert observed == [(path, 64 * 1024 * 1024)]


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
        "complete": False,
        "resumable": False,
        "blockers": [],
    }
    assert "Ghidra MCP" in refreshed["limitations"][-1]
    assert refreshed["generic_triage"] == "complete"
    assert analysis_contract.verify_report_semantics(refreshed) == []
    assert validation_calls == [{"expected_digest": digest, "require_resumable": False}]


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


def test_finalize_case_report_documents_exhaustive_handler_no_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """全対象層の正常なno-evidenceは解析完了とし、帰属の限界を残す。"""

    digest = "4" * 64
    layer_sha = "5" * 64
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
    handler_id = "stealc:extractors.stealc.extractor.py:extract"
    report = {
        "classification": {"selected_families": ["stealc"]},
        "handler_executions": [
            {
                "handler_id": handler_id,
                "status": "no_evidence",
                "selected_evidence": {"sufficient": False},
                "attempts": [
                    {
                        "status": "succeeded",
                        "routing_role": "selected_family_layer",
                        "evidence_status": "insufficient",
                        "evidence": {"sufficient": False},
                        "layer": {"sha256": layer_sha},
                    }
                ],
            }
        ],
        "limitations": [],
        "case_state": {
            "status": "partial",
            "complete": False,
            "resumable": False,
            "blockers": [
                "handler_no_evidence",
                target.FUNCTION_ANALYSIS_BLOCKER,
                "selected_family_has_no_valid_handler_evidence:stealc",
                "selected_family_layer_incomplete",
            ],
            "detector_error_families": [],
            "static_layer_issues": [],
            "incomplete_selected_layer_attempts": [
                {"handler_id": handler_id, "layer_sha256": layer_sha, "status": "succeeded"}
            ],
        },
        "artifact_sha256": {
            "static-logic.json": hashlib.sha256((case_dir / "static-logic.json").read_bytes()).hexdigest()
        },
    }
    analysis_contract.seal_report(report)
    target._json_dump(case_dir / "report.json", report)
    monkeypatch.setattr(target, "case_integrity_errors", lambda *_args, **_kwargs: [])

    assert target.finalize_case_report(case_dir) == "complete"
    refreshed = target.load_json_object_strict(case_dir / "report.json")
    assert refreshed["case_state"]["blockers"] == []
    assert refreshed["case_state"]["incomplete_selected_layer_attempts"] == []
    documented = refreshed["documented_handler_no_evidence"]
    assert documented["family"] == "stealc"
    assert documented["attempted_layer_sha256"] == [layer_sha]
    assert documented["attribution_effect"].startswith("provider_label_retained")
    assert "静的確認済み属性へは昇格させません" in refreshed["limitations"][-1]


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
    archive_sha256 = hashlib.sha256(b"fixture archive").hexdigest()
    unit = SimpleNamespace(
        data=root_data,
        source_name="sample.exe",
        outer_sha256=archive_sha256,
        outer_size=len(b"fixture archive"),
    )
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
    assert defaults.minimum_free_bytes == target.DEFAULT_MINIMUM_FREE_BYTES
    assert defaults.disk_guard_path == []

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
            "--minimum-free-bytes",
            str(target.MINIMUM_CONFIGURABLE_FREE_BYTES),
            "--disk-guard-path",
            str(tmp_path),
            "--skip-auto-analysis-sha256",
            "b" * 64,
        ]
    )
    assert selected.upx == tmp_path / "upx.exe"
    assert selected.sevenzip == tmp_path / "7z.exe"
    assert selected.diec == tmp_path / "diec.exe"
    assert selected.skip_auto_analysis_sha256 == ["a" * 64, "b" * 64]
    assert selected.minimum_free_bytes == target.MINIMUM_CONFIGURABLE_FREE_BYTES
    assert selected.disk_guard_path == [tmp_path]


def test_cli_rejects_disabling_the_disk_reserve(tmp_path: Path) -> None:
    """CLIから容量reserveを安全下限未満へ無効化できない。"""

    with pytest.raises(ValueError, match="--minimum-free-bytes"):
        target.main(
            [
                "--sample-root",
                str(tmp_path / "samples"),
                "--private-output",
                str(tmp_path / "private"),
                "--minimum-free-bytes",
                str(target.MINIMUM_CONFIGURABLE_FREE_BYTES - 1),
            ]
        )


@pytest.mark.parametrize(
    ("status", "expected_exit_code"),
    [
        ("complete", 0),
        ("ghidra_chunk_pending", target.RETRYABLE_INCOMPLETE_EXIT_CODE),
    ],
)
def test_cli_exit_code_distinguishes_complete_and_retryable_results(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    status: str,
    expected_exit_code: int,
) -> None:
    """CLI callerが完了と再試行可能な途中停止を終了codeで区別できる。"""

    monkeypatch.setattr(
        target,
        "run",
        lambda _args: {
            "status": status,
            "retryable": status == "ghidra_chunk_pending",
        },
    )

    exit_code = target.main(
        [
            "--sample-root",
            str(tmp_path / "samples"),
            "--private-output",
            str(tmp_path / "private"),
        ]
    )

    assert exit_code == expected_exit_code


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
    archive_sha256 = hashlib.sha256(b"fixture archive").hexdigest()
    unit = SimpleNamespace(
        data=root_data,
        source_name="sample.exe",
        outer_sha256=archive_sha256,
        outer_size=len(b"fixture archive"),
    )
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
    storage_checks: list[tuple[str, str, int]] = []
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
        storage_guard=lambda phase, role, planned: storage_checks.append(
            (phase, role, planned)
        ),
    )

    assert set(objects) == {digest, child_digest}
    assert not non_pe
    assert observed == [identities]
    assert storage_checks[:8] == [
        ("before_input_copy", "sample_root", len(root_data)),
        ("after_input_copy", "sample_root", 0),
        ("before_ghidra_staging_write", "private_output", len(root_data)),
        ("after_ghidra_staging_write", "private_output", 0),
        ("before_input_copy", "sample_root", len(child_data)),
        ("after_input_copy", "sample_root", 0),
        ("before_ghidra_staging_write", "private_output", len(child_data)),
        ("after_ghidra_staging_write", "private_output", 0),
    ]
    assert storage_checks[8][0:2] == (
        "before_prepared_inventory_write",
        "private_output",
    )
    assert storage_checks[8][2] > 0
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
    archive_sha256 = hashlib.sha256(b"fixture archive").hexdigest()
    unit = SimpleNamespace(
        data=root_data,
        source_name="sample.exe",
        outer_sha256=archive_sha256,
        outer_size=len(b"fixture archive"),
    )
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


def test_storage_budget_observation_is_path_private_and_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """容量確認失敗を不足扱いにし、進捗へ実local pathを含めない。"""

    repository = tmp_path / "repository"
    private = tmp_path / "private"
    repository.mkdir()
    private.mkdir()

    def observe(path: Path) -> tuple[tuple[int, str], int]:
        if path == repository:
            return (1, "volume-a"), target.DEFAULT_MINIMUM_FREE_BYTES + 1
        raise OSError("fixture failure")

    monkeypatch.setattr(target, "_observe_filesystem", observe)

    observed = target._storage_budget_observation(
        [("repository", repository), ("private_output", private)],
        minimum_free_bytes=target.DEFAULT_MINIMUM_FREE_BYTES,
        phase="test",
    )

    assert observed == {
        "phase": "test",
        "minimum_free_bytes": target.DEFAULT_MINIMUM_FREE_BYTES,
        "sufficient": False,
        "filesystems": [
            {
                "filesystem_id": "filesystem_1",
                "roles": ["repository"],
                "free_bytes": target.DEFAULT_MINIMUM_FREE_BYTES + 1,
                "sufficient": True,
                "error": None,
            },
            {
                "filesystem_id": "filesystem_2",
                "roles": ["private_output"],
                "free_bytes": None,
                "sufficient": False,
                "error": "disk_usage_unavailable",
            },
        ],
    }
    assert str(tmp_path) not in str(observed)


def test_storage_budget_deduplicates_roles_on_the_same_filesystem(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """同一filesystemの複数書込み先へreserveを重複計上しない。"""

    paths = []
    for name in ("repository", "samples", "private"):
        path = tmp_path / name
        path.mkdir()
        paths.append(path)
    monkeypatch.setattr(
        target,
        "_observe_filesystem",
        lambda _path: ((7, "same-volume"), target.DEFAULT_MINIMUM_FREE_BYTES),
    )

    observed = target._storage_budget_observation(
        [
            ("repository", paths[0]),
            ("sample_root", paths[1]),
            ("private_output", paths[2]),
        ],
        minimum_free_bytes=target.DEFAULT_MINIMUM_FREE_BYTES,
        phase="test",
    )

    assert observed["sufficient"] is True
    assert observed["filesystems"] == [
        {
            "filesystem_id": "filesystem_1",
            "roles": ["repository", "sample_root", "private_output"],
            "free_bytes": target.DEFAULT_MINIMUM_FREE_BYTES,
            "sufficient": True,
            "error": None,
        }
    ]


def test_storage_guard_includes_input_copy_destination(tmp_path: Path) -> None:
    """repository外のsample_rootも入力copy前のguard対象に含める。"""

    repository = tmp_path / "repository"
    sample_root = tmp_path / "samples"
    private_output = tmp_path / "private"
    repository.mkdir()
    sample_root.mkdir()
    arguments = target.build_parser().parse_args(
        [
            "--repository",
            str(repository),
            "--sample-root",
            str(sample_root),
            "--private-output",
            str(private_output),
        ]
    )

    observed = target._storage_guard_paths(
        arguments,
        repository,
        sample_root,
        private_output,
    )

    assert observed[:3] == [
        ("repository", repository),
        ("sample_root", sample_root),
        ("private_output", private_output),
    ]


def test_planned_write_reserve_accounts_for_copy_size() -> None:
    """現在値が下限以上でもcopy後にreserveを割るwriteは開始しない。"""

    minimum = target.MINIMUM_CONFIGURABLE_FREE_BYTES
    observation = {
        "phase": "before_input_copy",
        "minimum_free_bytes": minimum,
        "sufficient": True,
        "filesystems": [
            {
                "filesystem_id": "filesystem_1",
                "roles": ["sample_root"],
                "free_bytes": minimum + 63,
                "sufficient": True,
                "error": None,
            }
        ],
    }

    guarded = target._apply_planned_write_reserve(
        observation,
        role="sample_root",
        planned_write_bytes=64,
    )

    assert guarded["sufficient"] is False
    assert guarded["planned_write_sufficient"] is False
    assert guarded["filesystems"][0]["planned_write_bytes"] == 64
    assert "path" not in str(guarded).casefold()


def test_run_rejects_sample_root_equal_to_repository(tmp_path: Path) -> None:
    """検体copy先とrepositoryが同一または相互包含する構成を拒否する。"""

    repository = tmp_path / "repository"
    collection = repository / "analysis-results" / "collections" / "batch"
    collection.mkdir(parents=True)
    arguments = target.build_parser().parse_args(
        [
            "--repository",
            str(repository),
            "--collection",
            str(collection),
            "--sample-root",
            str(repository),
            "--private-output",
            str(tmp_path / "private"),
        ]
    )

    with pytest.raises(ValueError, match="相互に包含"):
        target.run(arguments)


def test_guarded_path_resolution_rejects_reparse_component(tmp_path: Path) -> None:
    """resolveで透過する前にsymlink／junction相当を拒否する。"""

    target_root = tmp_path / "target"
    link = tmp_path / "link"
    target_root.mkdir()
    try:
        link.symlink_to(target_root, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"directory symlinkを作成できない環境です: {exc}")

    with pytest.raises(ValueError, match="reparse point"):
        target._resolve_without_reparse(link / "private")


def test_filesystem_observation_rejects_identity_change(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """disk usage照会前後にdirectoryが差し替わった場合はfail-closedにする。"""

    monkeypatch.setattr(target, "_same_path_identity", lambda *_args: False)

    with pytest.raises(OSError, match="identity"):
        target._observe_filesystem(tmp_path)


def test_run_progress_schema_is_stable_across_checkpoint_phases() -> None:
    """準備前・program待ち・後処理待ち・完了でfield集合を変えない。"""

    digest = "0" * 64
    common = {
        "collection_id": "batch",
        "disk_space": {},
    }
    documents = [
        target._run_progress_document(
            **common,
            status="ghidra_chunk_pending",
            stop_reason="minimum_free_space_not_met",
            retryable=True,
            inventory_prepared=False,
            prepared_inventory_sha256=None,
            unique_pe_programs=None,
            complete_programs=0,
            cached_programs=0,
            newly_analyzed_programs=0,
            pending_programs=[],
            postprocessing_pending=False,
            prepared_inputs_reused=False,
            resume_mode="fresh",
        ),
        target._run_progress_document(
            **common,
            status="ghidra_chunk_pending",
            stop_reason="max_new_programs_reached",
            retryable=True,
            inventory_prepared=True,
            prepared_inventory_sha256=digest,
            unique_pe_programs=1,
            complete_programs=0,
            cached_programs=0,
            newly_analyzed_programs=0,
            pending_programs=[digest],
            postprocessing_pending=False,
            prepared_inputs_reused=True,
            resume_mode="prepared_inputs",
        ),
        target._run_progress_document(
            **common,
            status="ghidra_chunk_pending",
            stop_reason="postprocessing_in_progress",
            retryable=True,
            inventory_prepared=True,
            prepared_inventory_sha256=digest,
            unique_pe_programs=1,
            complete_programs=1,
            cached_programs=1,
            newly_analyzed_programs=0,
            pending_programs=[],
            postprocessing_pending=True,
            prepared_inputs_reused=True,
            resume_mode="postprocessing_only",
        ),
        target._run_progress_document(
            **common,
            status="complete",
            stop_reason=None,
            retryable=False,
            inventory_prepared=True,
            prepared_inventory_sha256=digest,
            unique_pe_programs=1,
            complete_programs=1,
            cached_programs=1,
            newly_analyzed_programs=0,
            pending_programs=[],
            postprocessing_pending=False,
            prepared_inputs_reused=True,
            resume_mode="prepared_inputs",
        ),
    ]

    assert all(set(document) == set(documents[0]) for document in documents)
    assert all(
        document["schema_version"] == target.RUN_PROGRESS_SCHEMA_VERSION
        for document in documents
    )


def test_resume_checkpoint_rejects_schema_drift(tmp_path: Path) -> None:
    """field欠落や固定安全値の変更があるcheckpointを自動再開に使わない。"""

    private_output = tmp_path / "private"
    progress = target._run_progress_document(
        collection_id="batch",
        status="ghidra_chunk_pending",
        stop_reason="minimum_free_space_not_met",
        retryable=True,
        inventory_prepared=False,
        prepared_inventory_sha256=None,
        unique_pe_programs=None,
        complete_programs=0,
        cached_programs=0,
        newly_analyzed_programs=0,
        pending_programs=[],
        postprocessing_pending=False,
        prepared_inputs_reused=False,
        resume_mode="fresh",
        disk_space={},
    )
    progress["safety"]["network_contacted"] = True
    target._write_run_progress(private_output, progress)

    with pytest.raises(ValueError, match="field集合|固定安全値"):
        target._load_resume_checkpoint(private_output, collection_id="batch")


def test_legacy_run_progress_is_strictly_migrated_for_resume(tmp_path: Path) -> None:
    """既存schema 1の正規checkpointをschema 2へ正規化して再利用する。"""

    digest = "a" * 64
    private_output = tmp_path / "private"
    inventory_sha256 = _write_prepared_inventory(
        private_output,
        collection_id="batch",
        digests=[digest],
    )
    target._write_run_progress(
        private_output,
        {
            "schema_version": target.LEGACY_RUN_PROGRESS_SCHEMA_VERSION,
            "collection_id": "batch",
            "status": "ghidra_chunk_pending",
            "unique_pe_programs": 1,
            "complete_programs": 0,
            "cached_programs": 0,
            "newly_analyzed_programs": 0,
            "pending_programs": [digest],
            "prepared_inputs_reused": False,
            "safety": {
                "sample_executed": False,
                "network_contacted": False,
                "arbitrary_ghidra_scripts_enabled": False,
                "mcp_localhost_only": True,
            },
        },
    )

    migrated = target._load_resume_checkpoint(
        private_output,
        collection_id="batch",
    )

    assert migrated is not None
    assert migrated["schema_version"] == target.RUN_PROGRESS_SCHEMA_VERSION
    assert migrated["resume_mode"] == "prepared_inputs"
    assert migrated["pending_programs"] == [digest]
    assert migrated["prepared_inventory_sha256"] == inventory_sha256


def test_prepared_checkpoint_requires_bound_input_inventory(tmp_path: Path) -> None:
    """preparedを名乗るcheckpointだけでは自動再開せずinventory欠落を拒否する。"""

    digest = "d" * 64
    private_output = tmp_path / "private"
    target._write_run_progress(
        private_output,
        target._run_progress_document(
            collection_id="batch",
            status="ghidra_chunk_pending",
            stop_reason="max_new_programs_reached",
            retryable=True,
            inventory_prepared=True,
            prepared_inventory_sha256=digest,
            unique_pe_programs=1,
            complete_programs=0,
            cached_programs=0,
            newly_analyzed_programs=0,
            pending_programs=[digest],
            postprocessing_pending=False,
            prepared_inputs_reused=False,
            resume_mode="fresh",
            disk_space={},
        ),
    )

    with pytest.raises((FileNotFoundError, ValueError)):
        target._load_resume_checkpoint(private_output, collection_id="batch")


def test_prepared_checkpoint_rejects_inventory_binding_change(
    tmp_path: Path,
) -> None:
    """checkpoint作成後に変更されたprepared inventoryを自動再開へ使わない。"""

    digest = "e" * 64
    private_output = tmp_path / "private"
    inventory_sha256 = _write_prepared_inventory(
        private_output,
        collection_id="batch",
        digests=[digest],
    )
    target._write_run_progress(
        private_output,
        target._run_progress_document(
            collection_id="batch",
            status="ghidra_chunk_pending",
            stop_reason="max_new_programs_reached",
            retryable=True,
            inventory_prepared=True,
            prepared_inventory_sha256=inventory_sha256,
            unique_pe_programs=1,
            complete_programs=0,
            cached_programs=0,
            newly_analyzed_programs=0,
            pending_programs=[digest],
            postprocessing_pending=False,
            prepared_inputs_reused=False,
            resume_mode="fresh",
            disk_space={},
        ),
    )
    inventory_path = private_output / "input-relationships.json"
    inventory = target.load_json_object_strict(inventory_path)
    inventory["static_tools"] = {"changed": None}
    target._json_dump(inventory_path, inventory)

    with pytest.raises(ValueError, match="binding SHA-256"):
        target._load_resume_checkpoint(private_output, collection_id="batch")


def test_run_stops_before_input_preparation_when_disk_reserve_is_low(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """開始時のreserve不足では入力copyもMCP接触も行わず再開情報を保存する。"""

    repository = tmp_path / "repository"
    collection = repository / "analysis-results" / "collections" / "batch"
    sample_root = tmp_path / "samples"
    private_output = tmp_path / "private"
    collection.mkdir(parents=True)
    sample_root.mkdir()
    monkeypatch.setattr(
        target,
        "prepare_inputs",
        lambda *args, **kwargs: pytest.fail("入力準備を呼び出してはいけません"),
    )
    monkeypatch.setattr(
        target,
        "GhidraMcpClient",
        lambda *args, **kwargs: pytest.fail("MCP clientを初期化してはいけません"),
    )
    monkeypatch.setattr(
        target,
        "_storage_budget_observation",
        lambda *args, **kwargs: {
            "phase": kwargs["phase"],
            "minimum_free_bytes": kwargs["minimum_free_bytes"],
            "sufficient": False,
            "filesystems": [
                {
                    "filesystem_id": "filesystem_1",
                    "roles": ["repository", "sample_root", "private_output"],
                    "free_bytes": 1,
                    "sufficient": False,
                    "error": None,
                }
            ],
        },
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
        ]
    )

    result = target.run(arguments)

    assert result["status"] == "ghidra_chunk_pending"
    assert result["stop_reason"] == "minimum_free_space_not_met"
    assert result["inventory_prepared"] is False
    assert result["retryable"] is True
    assert result["resume_mode"] == "fresh"
    assert result["safety"]["network_contacted"] is False
    assert target.load_json_object_strict(private_output / "run-progress.json") == result
    assert list(private_output.glob(".*.tmp")) == []


def test_run_checkpoints_before_preparation_copy_would_cross_reserve(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """batch途中の次copyを開始せず、既存prepared fileを保持してatomic停止する。"""

    repository = tmp_path / "repository"
    collection = repository / "analysis-results" / "collections" / "batch"
    sample_root = tmp_path / "samples"
    private_output = tmp_path / "private"
    collection.mkdir(parents=True)
    sample_root.mkdir()
    preserved = sample_root / "preserved.quarantine.bin"
    next_copy = sample_root / "next.quarantine.bin"

    def prepare(*_args: object, **kwargs: object) -> object:
        preserved.write_bytes(b"already prepared")
        guard = kwargs["storage_guard"]
        assert callable(guard)
        guard("before_input_copy", "sample_root", 64)
        next_copy.write_bytes(b"must not be written")
        raise AssertionError("容量停止後もprepare_inputsが継続しました")

    monkeypatch.setattr(target, "prepare_inputs", prepare)
    monkeypatch.setattr(
        target,
        "GhidraMcpClient",
        lambda *args, **kwargs: pytest.fail("入力準備の容量停止時にMCP clientを初期化してはいけません"),
    )
    minimum = target.MINIMUM_CONFIGURABLE_FREE_BYTES

    def storage_observation(*_args: object, **kwargs: object) -> dict[str, object]:
        return {
            "phase": kwargs["phase"],
            "minimum_free_bytes": kwargs["minimum_free_bytes"],
            "sufficient": True,
            "filesystems": [
                {
                    "filesystem_id": "filesystem_1",
                    "roles": ["repository", "sample_root", "private_output"],
                    "free_bytes": minimum + 63,
                    "sufficient": True,
                    "error": None,
                }
            ],
        }

    monkeypatch.setattr(target, "_storage_budget_observation", storage_observation)
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
            "--minimum-free-bytes",
            str(minimum),
        ]
    )

    result = target.run(arguments)

    assert result["status"] == "ghidra_chunk_pending"
    assert result["inventory_prepared"] is False
    assert result["prepared_inventory_sha256"] is None
    assert result["disk_space"]["planned_write_bytes"] == 64
    assert result["disk_space"]["planned_write_sufficient"] is False
    assert preserved.read_bytes() == b"already prepared"
    assert not next_copy.exists()
    assert target.load_json_object_strict(private_output / "run-progress.json") == result
    assert list(private_output.glob(".*.tmp")) == []


def test_low_space_recheck_preserves_existing_prepared_checkpoint(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """容量不足のまま再実行しても準備済みinventoryとpending一覧を失わない。"""

    digest = "b" * 64
    repository = tmp_path / "repository"
    collection = repository / "analysis-results" / "collections" / "batch"
    sample_root = tmp_path / "samples"
    private_output = tmp_path / "private"
    collection.mkdir(parents=True)
    sample_root.mkdir()
    inventory_sha256 = _write_prepared_inventory(
        private_output,
        collection_id="batch",
        digests=[digest],
    )
    target._write_run_progress(
        private_output,
        target._run_progress_document(
            collection_id="batch",
            status="ghidra_chunk_pending",
            stop_reason="max_new_programs_reached",
            retryable=True,
            inventory_prepared=True,
            prepared_inventory_sha256=inventory_sha256,
            unique_pe_programs=1,
            complete_programs=0,
            cached_programs=0,
            newly_analyzed_programs=0,
            pending_programs=[digest],
            postprocessing_pending=False,
            prepared_inputs_reused=False,
            resume_mode="fresh",
            disk_space={},
        ),
    )
    monkeypatch.setattr(
        target,
        "GhidraMcpClient",
        lambda *args, **kwargs: pytest.fail("低容量時にMCP clientを初期化してはいけません"),
    )
    monkeypatch.setattr(
        target,
        "prepare_inputs",
        lambda *args, **kwargs: pytest.fail("低容量時にinput準備してはいけません"),
    )
    monkeypatch.setattr(
        target,
        "load_prepared_inputs",
        lambda *args, **kwargs: pytest.fail("低容量時にinput cacheを読んではいけません"),
    )
    monkeypatch.setattr(
        target,
        "_storage_budget_observation",
        lambda *args, **kwargs: {
            "phase": kwargs["phase"],
            "minimum_free_bytes": kwargs["minimum_free_bytes"],
            "sufficient": False,
            "filesystems": [],
        },
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
        ]
    )

    result = target.run(arguments)

    assert result["inventory_prepared"] is True
    assert result["unique_pe_programs"] == 1
    assert result["pending_programs"] == [digest]
    assert result["prepared_inputs_reused"] is False
    assert result["resume_mode"] == "prepared_inputs"


def test_run_stops_between_programs_and_preserves_completed_cache(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """program完了後のreserve不足では次programを開始せずcheckpointを残す。"""

    digests = ["1" * 64, "2" * 64]
    objects = {
        digest: target.ProgramObject(
            sha256=digest,
            input_path=tmp_path / f"{digest}.quarantine.bin",
            size=index,
        )
        for index, digest in enumerate(digests, start=1)
    }
    repository = tmp_path / "repository"
    collection = repository / "analysis-results" / "collections" / "batch"
    sample_root = tmp_path / "samples"
    private_output = tmp_path / "private"
    collection.mkdir(parents=True)
    sample_root.mkdir()
    _write_prepared_inventory(
        private_output,
        collection_id="batch",
        digests=digests,
    )
    monkeypatch.setattr(target, "prepare_inputs", lambda *args, **kwargs: (objects, {}))
    monkeypatch.setattr(
        target,
        "validate_prepared_scope",
        lambda *args, **kwargs: None,
    )
    phases: list[str] = []

    def storage_observation(*args: object, **kwargs: object) -> dict[str, object]:
        phase = str(kwargs["phase"])
        phases.append(phase)
        sufficient = phase != "after_program"
        return {
            "phase": phase,
            "minimum_free_bytes": kwargs["minimum_free_bytes"],
            "sufficient": sufficient,
            "filesystems": [],
        }

    analyzed: list[str] = []

    def analyze(_client: object, item: target.ProgramObject, *_args: object, **_kwargs: object):
        analyzed.append(item.sha256)
        result = {
            "status": "complete",
            "mcp_responses_valid": True,
            "sha256": item.sha256,
        }
        target._json_dump(
            private_output / "objects" / item.sha256 / "program-result.json",
            result,
        )
        return result

    monkeypatch.setattr(target, "_storage_budget_observation", storage_observation)
    monkeypatch.setattr(target, "analyze_program", analyze)
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
        ]
    )

    result = target.run(arguments)

    assert analyzed == [digests[0]]
    assert phases == [
        "before_input_preparation",
        "after_input_preparation",
        "before_program",
        "after_program",
    ]
    assert result["stop_reason"] == "minimum_free_space_not_met"
    assert result["complete_programs"] == 1
    assert result["newly_analyzed_programs"] == 1
    assert result["pending_programs"] == [digests[1]]
    assert (private_output / "objects" / digests[0] / "program-result.json").is_file()


def test_run_defers_postprocessing_without_rewriting_complete_cache(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """全program完了後のreserve不足ではcacheを変更せず後処理だけ保留する。"""

    digest = "3" * 64
    item = target.ProgramObject(
        sha256=digest,
        input_path=tmp_path / f"{digest}.quarantine.bin",
        size=1,
    )
    repository = tmp_path / "repository"
    collection = repository / "analysis-results" / "collections" / "batch"
    sample_root = tmp_path / "samples"
    private_output = tmp_path / "private"
    collection.mkdir(parents=True)
    sample_root.mkdir()
    _write_prepared_inventory(
        private_output,
        collection_id="batch",
        digests=[digest],
    )
    result_path = private_output / "objects" / digest / "program-result.json"
    cached = {
        "status": "complete",
        "mcp_responses_valid": True,
        "sha256": digest,
        "functions": [],
        "characteristic_function_ids": [],
        "characteristic_function_count": 0,
    }
    target.ensure_characteristic_selection(cached)
    target._json_dump(result_path, cached)
    original = result_path.read_bytes()
    monkeypatch.setattr(target, "prepare_inputs", lambda *args, **kwargs: ({digest: item}, {}))
    monkeypatch.setattr(
        target,
        "validate_prepared_scope",
        lambda *args, **kwargs: None,
    )

    def storage_observation(*args: object, **kwargs: object) -> dict[str, object]:
        phase = str(kwargs["phase"])
        sufficient = phase != "before_postprocessing"
        return {
            "phase": phase,
            "minimum_free_bytes": kwargs["minimum_free_bytes"],
            "sufficient": sufficient,
            "filesystems": [],
        }

    monkeypatch.setattr(target, "_storage_budget_observation", storage_observation)
    monkeypatch.setattr(
        target,
        "analyze_program",
        lambda *args, **kwargs: pytest.fail("完了cacheをMCPへ再投入してはいけません"),
    )
    monkeypatch.setattr(
        target,
        "refresh_complete_program_artifacts",
        lambda *args, **kwargs: pytest.fail("空き容量不足時に後処理を開始してはいけません"),
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
        ]
    )

    result = target.run(arguments)

    assert result["stop_reason"] == "minimum_free_space_not_met"
    assert result["pending_programs"] == []
    assert result["postprocessing_pending"] is True
    assert result["complete_programs"] == 1
    assert result["cached_programs"] == 1
    assert result_path.read_bytes() == original


def test_run_automatically_reuses_prepared_inputs_after_capacity_stop(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """容量停止checkpointがあれば手動flagなしで準備済みinputを再利用する。"""

    digest = "4" * 64
    item = target.ProgramObject(
        sha256=digest,
        input_path=tmp_path / f"{digest}.quarantine.bin",
        size=1,
    )
    repository = tmp_path / "repository"
    collection = repository / "analysis-results" / "collections" / "batch"
    sample_root = tmp_path / "samples"
    private_output = tmp_path / "private"
    collection.mkdir(parents=True)
    sample_root.mkdir()
    inventory_sha256 = _write_prepared_inventory(
        private_output,
        collection_id="batch",
        digests=[digest],
    )
    checkpoint = target._run_progress_document(
        collection_id="batch",
        status="ghidra_chunk_pending",
        stop_reason="minimum_free_space_not_met",
        retryable=True,
        inventory_prepared=True,
        prepared_inventory_sha256=inventory_sha256,
        unique_pe_programs=1,
        complete_programs=0,
        cached_programs=0,
        newly_analyzed_programs=0,
        pending_programs=[digest],
        postprocessing_pending=False,
        prepared_inputs_reused=False,
        resume_mode="fresh",
        disk_space={},
    )
    target._write_run_progress(private_output, checkpoint)
    monkeypatch.setattr(
        target,
        "prepare_inputs",
        lambda *args, **kwargs: pytest.fail("準備済みinputを再作成してはいけません"),
    )
    monkeypatch.setattr(
        target,
        "load_prepared_inputs",
        lambda *args, **kwargs: ({digest: item}, {}),
    )
    monkeypatch.setattr(
        target,
        "validate_prepared_scope",
        lambda *args, **kwargs: None,
    )

    def storage_observation(*args: object, **kwargs: object) -> dict[str, object]:
        phase = str(kwargs["phase"])
        return {
            "phase": phase,
            "minimum_free_bytes": kwargs["minimum_free_bytes"],
            "sufficient": phase == "before_input_preparation",
            "filesystems": [],
        }

    monkeypatch.setattr(target, "_storage_budget_observation", storage_observation)
    monkeypatch.setattr(
        target,
        "analyze_program",
        lambda *args, **kwargs: pytest.fail("容量不足時にMCP解析してはいけません"),
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
        ]
    )

    result = target.run(arguments)

    assert result["resume_mode"] == "prepared_inputs"
    assert result["prepared_inputs_reused"] is True
    assert result["pending_programs"] == [digest]


def test_run_automatically_resumes_postprocessing_without_program_analysis(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """後処理checkpointからinput再準備やprogram解析をせず後処理へ進む。"""

    digest = "5" * 64
    item = target.ProgramObject(
        sha256=digest,
        input_path=tmp_path / f"{digest}.quarantine.bin",
        size=1,
    )
    repository = tmp_path / "repository"
    collection = repository / "analysis-results" / "collections" / "batch"
    sample_root = tmp_path / "samples"
    private_output = tmp_path / "private"
    collection.mkdir(parents=True)
    sample_root.mkdir()
    inventory_sha256 = _write_prepared_inventory(
        private_output,
        collection_id="batch",
        digests=[digest],
    )
    target._write_run_progress(
        private_output,
        target._run_progress_document(
            collection_id="batch",
            status="ghidra_chunk_pending",
            stop_reason="postprocessing_in_progress",
            retryable=True,
            inventory_prepared=True,
            prepared_inventory_sha256=inventory_sha256,
            unique_pe_programs=1,
            complete_programs=1,
            cached_programs=1,
            newly_analyzed_programs=0,
            pending_programs=[],
            postprocessing_pending=True,
            prepared_inputs_reused=True,
            resume_mode="postprocessing_only",
            disk_space={},
        ),
    )
    cached = {
        "status": "complete",
        "mcp_responses_valid": True,
        "sha256": digest,
        "functions": [],
    }
    target.ensure_characteristic_selection(cached)
    target._json_dump(
        private_output / "objects" / digest / "program-result.json",
        cached,
    )
    monkeypatch.setattr(
        target,
        "prepare_inputs",
        lambda *args, **kwargs: pytest.fail("postprocessing再開でinput準備してはいけません"),
    )
    monkeypatch.setattr(
        target,
        "load_prepared_inputs",
        lambda *args, **kwargs: ({digest: item}, {}),
    )
    monkeypatch.setattr(
        target,
        "validate_prepared_scope",
        lambda *args, **kwargs: None,
    )
    monkeypatch.setattr(
        target,
        "_storage_budget_observation",
        lambda *args, **kwargs: {
            "phase": kwargs["phase"],
            "minimum_free_bytes": kwargs["minimum_free_bytes"],
            "sufficient": True,
            "filesystems": [],
        },
    )
    monkeypatch.setattr(
        target,
        "analyze_program",
        lambda *args, **kwargs: pytest.fail("postprocessing再開でprogram解析してはいけません"),
    )

    def postprocessing_reached(*_args: object, **_kwargs: object) -> dict[str, int]:
        progress = target.load_json_object_strict(private_output / "run-progress.json")
        assert progress["postprocessing_pending"] is True
        assert progress["resume_mode"] == "postprocessing_only"
        raise RuntimeError("postprocessing reached")

    monkeypatch.setattr(
        target,
        "refresh_complete_program_artifacts",
        postprocessing_reached,
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
        ]
    )

    with pytest.raises(RuntimeError, match="postprocessing reached"):
        target.run(arguments)


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
    _write_prepared_inventory(
        private_output,
        collection_id="batch",
        digests=[digest],
    )
    monkeypatch.setattr(
        target,
        "prepare_inputs",
        lambda *args, **kwargs: ({digest: item}, {}),
    )
    monkeypatch.setattr(
        target,
        "validate_prepared_scope",
        lambda *args, **kwargs: None,
    )
    monkeypatch.setattr(
        target,
        "analyze_program",
        lambda *args, **kwargs: pytest.fail("MCP解析を呼び出してはいけません"),
    )
    monkeypatch.setattr(
        target,
        "GhidraMcpClient",
        lambda *args, **kwargs: pytest.fail("入力準備だけのrunでMCP clientを初期化してはいけません"),
    )
    monkeypatch.setattr(
        target,
        "_storage_budget_observation",
        lambda *args, **kwargs: {
            "phase": kwargs["phase"],
            "minimum_free_bytes": kwargs["minimum_free_bytes"],
            "sufficient": True,
            "filesystems": [],
        },
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
