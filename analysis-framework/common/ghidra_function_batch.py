#!/usr/bin/env python3
"""Ghidra MCPとCIL parserで検体集合の代表関数と全体ロジックを記録する。

検体は不活性byte列としてだけ読み込み、実行、emulation、外部通信を行わない。
Ghidra操作はlocalhostのMCP endpointだけを使用し、program単位の全requestへ
明示的なproject pathを渡す。生の逆コンパイル本文とCIL命令列はリポジトリ外へ
保持し、公開成果物には秘匿値を除去した処理構造とfingerprintだけを保存する。
"""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
import hashlib
import json
import os
from pathlib import Path
import re
import time
from typing import Any, Iterable, Mapping
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlparse
from urllib.request import Request, urlopen

import dnfile
from dncil.cil.body.reader import read_method_body_from_bytes
import pefile

from analyze_sample import read_input_unit, recover_static_layers
from static_logic import (
    build_static_logic_report,
    extract_script_function_records,
    redact_static_text,
)
from validate_function_analysis import validate_collection


SCHEMA_VERSION = 1
DEFAULT_COLLECTION_ID = "malwarebazaar-windows-20260723-0100"
DEFAULT_MCP_URL = "http://127.0.0.1:8089"
DEFAULT_PROJECT_ROOT = "/Malware/MalwareBazaarWindows/20260723"
LOCAL_MCP_HOSTS = {"127.0.0.1", "localhost", "::1"}
FUNCTION_PAGE_SIZE = 10_000
STRUCTURE_PAGE_SIZE = 1_000
DECOMPILE_BATCH_SIZE = 20
DECOMPILE_WORKERS = 3
MAX_CHARACTERISTIC_FUNCTIONS_PER_PROGRAM = 32

EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
FATAL_DECOMPILE_MARKERS = (
    "decompilation failed",
    "failed to decompile",
    "timeout",
    "no function",
)
LIMITED_DECOMPILE_MARKERS = (
    "control flow encountered bad instruction data",
    "bad instruction",
    "could not recover jumptable",
    "truncating control flow",
)
ROLE_PATTERNS = (
    (
        "entrypoint",
        re.compile(r"(?i)(?:^|[_.<>])(main|winmain|wmain|dllmain|entry|startup)(?:$|[_.<>])"),
    ),
    (
        "network_communication",
        re.compile(
            r"(?i)(socket|connect|send|recv|http|internet|winhttp|wininet|webclient|"
            r"download|upload|dns|ping|smtp|ftp|websocket)"
        ),
    ),
    (
        "command_dispatch_or_handler",
        re.compile(r"(?i)(command|dispatch|handler|interactive|shell|execute|task|job|request)"),
    ),
    (
        "config_or_data_transform",
        re.compile(r"(?i)(config|setting|parse|decode|decrypt|unpack|deserialize|resource|payload)"),
    ),
    (
        "cryptographic_transform",
        re.compile(r"(?i)(aes|rsa|rc4|chacha|xor|base64|crypt|cipher|hash|sha\d*|md5)"),
    ),
    (
        "process_or_memory_operation",
        re.compile(
            r"(?i)(process|thread|inject|virtualalloc|writeprocessmemory|"
            r"createremotethread|queueuserapc|loadlibrary|mapview|hollow)"
        ),
    ),
    (
        "persistence",
        re.compile(r"(?i)(persist|startup|autorun|registry|regset|service|schtask|runkey)"),
    ),
    (
        "anti_analysis",
        re.compile(
            r"(?i)(anti|debug|isdebugger|virtualbox|vmware|sandbox|sleep|timing|"
            r"queryperformance|cpuid|ntqueryinformation)"
        ),
    ),
    (
        "file_operation",
        re.compile(r"(?i)(createfile|readfile|writefile|deletefile|directory|filepath|stream|file)"),
    ),
)
LIBRARY_RE = re.compile(
    r"(?i)^(?:__|_?mem(?:cpy|set|move|cmp)|_?str(?:len|cpy|cmp)|"
    r"_?wcs|operator(?:new|delete)|std::|crt|security_check_cookie|"
    r"guard_|tls_callback|\.?ctor|\.?cctor)"
)
IMPORT_CAPABILITY_PATTERNS = {
    "configuration": re.compile(
        r"(?i)^(?:Crypt(?:Decrypt|UnprotectData|StringToBinary)|BCrypt|NCrypt|RtlDecompressBuffer)"
    ),
    "evasion": re.compile(
        r"(?i)^(?:IsDebuggerPresent|CheckRemoteDebuggerPresent|NtQueryInformationProcess|"
        r"QueryPerformanceCounter|GetTickCount(?:64)?|Sleep(?:Ex)?)$"
    ),
    "persistence": re.compile(
        r"(?i)^(?:Reg(?:Create|Open|Set|Delete)|CreateService|StartService|"
        r"OpenSCManager|CoCreateInstance)$"
    ),
    "execution": re.compile(
        r"(?i)^(?:VirtualAlloc(?:Ex)?|VirtualProtect(?:Ex)?|WriteProcessMemory|"
        r"CreateRemoteThread|QueueUserAPC|NtMapViewOfSection|CreateProcess|"
        r"ShellExecute|WinExec|LoadLibrary|CreateThread)"
    ),
    "communication": re.compile(
        r"(?i)^(?:socket|connect|send|recv|select|WSAStartup|Internet|WinHttp|"
        r"DnsQuery|gethostbyname|inet_addr|URLDownloadToFile)"
    ),
    "file_activity": re.compile(
        r"(?i)^(?:CreateFile|ReadFile|WriteFile|DeleteFile|MoveFile|CopyFile|"
        r"FindFirstFile|FindNextFile|PathFileExists)"
    ),
}
SUMMARY_BY_ROLE = {
    "entrypoint": "初期化と主要処理への分岐を行う入口関数です。",
    "network_communication": "通信初期化、送受信、またはendpoint処理に関係する関数です。",
    "command_dispatch_or_handler": "commandの解釈、分配、または個別処理を担当する関数です。",
    "config_or_data_transform": "設定、resource、payloadなどの解析・変換を行う関数です。",
    "cryptographic_transform": "暗号、hash、encoding、または復号処理に関係する関数です。",
    "process_or_memory_operation": "process、thread、module、またはmemory操作に関係する関数です。",
    "persistence": "自動起動または永続化に関係する処理を含む関数です。",
    "anti_analysis": "debugger、仮想環境、sandbox、または時間差の確認に関係する関数です。",
    "file_operation": "fileまたはdirectoryの読書き・管理に関係する関数です。",
    "compiler_or_library_code": "compiler生成処理または汎用library処理とみられる関数です。",
    "external_api_or_thunk": "外部APIまたはthunkであり、検体固有の関数本体を持ちません。",
    "managed_method_without_body": "metadata上に存在しますが、解析対象となるCIL本体を持たないmethodです。",
    "general_internal_logic": "検体内部の一般処理を実装する関数です。",
}


class GhidraMcpError(RuntimeError):
    """Ghidra MCP requestの失敗を表す。"""


def _json_dump(path: Path, value: Any) -> None:
    """JSONを決定的にUTF-8で保存する。"""

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _safe_project_path(value: str) -> str:
    """Ghidra project pathを絶対pathへ正規化する。"""

    rendered = "/" + value.replace("\\", "/").strip("/")
    if ".." in rendered.split("/"):
        raise ValueError("Ghidra project pathに親directory参照は使用できません")
    return rendered


class GhidraMcpClient:
    """localhost限定Ghidra MCP HTTP client。"""

    def __init__(self, base_url: str, *, timeout: int = 180) -> None:
        parsed = urlparse(base_url)
        if parsed.scheme != "http" or parsed.hostname not in LOCAL_MCP_HOSTS:
            raise ValueError("Ghidra MCP URLはlocalhostのHTTP endpointに限定します")
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("Ghidra MCP URLへ資格情報、query、fragmentは指定できません")
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def _request(
        self,
        method: str,
        path: str,
        *,
        query: Mapping[str, Any] | None = None,
        body: Mapping[str, Any] | None = None,
        timeout: int | None = None,
    ) -> Any:
        url = self.base_url + path
        clean_query = {key: value for key, value in (query or {}).items() if value is not None}
        if clean_query:
            url += "?" + urlencode(clean_query)
        data = None
        headers = {"Accept": "application/json"}
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        request = Request(url, data=data, headers=headers, method=method)
        try:
            with urlopen(request, timeout=timeout or self.timeout) as response:
                raw = response.read()
        except HTTPError as error:
            detail = error.read().decode("utf-8", errors="replace")
            raise GhidraMcpError(f"{method} {path} failed: HTTP {error.code}: {detail[:1000]}") from error
        except (OSError, URLError) as error:
            raise GhidraMcpError(f"{method} {path} failed: {type(error).__name__}") from error
        if not raw:
            return None
        text = raw.decode("utf-8", errors="replace")
        try:
            value = json.loads(text)
        except json.JSONDecodeError:
            return text
        if isinstance(value, Mapping) and value.get("error"):
            raise GhidraMcpError(f"{method} {path} returned an MCP error object")
        return value

    def get(self, endpoint: str, **query: Any) -> Any:
        return self._request("GET", endpoint, query=query, body=None)

    def post(
        self,
        endpoint: str,
        body: Mapping[str, Any],
        **query: Any,
    ) -> Any:
        return self._request("POST", endpoint, query=query, body=body)


@dataclass
class ProgramObject:
    """1つのunique PE layerとcaseへの関係を保持する。"""

    sha256: str
    input_path: Path
    size: int
    relationships: list[dict[str, Any]] = field(default_factory=list)

    @property
    def primary(self) -> dict[str, Any]:
        return sorted(
            self.relationships,
            key=lambda item: (int(item["depth"]), item["case_sha256"], item["transform"]),
        )[0]


def _case_index(repository: Path) -> dict[str, Path]:
    index: dict[str, Path] = {}
    root = repository / "analysis-results" / "malware"
    for path in root.glob("*/versions/*/cases/*"):
        if path.is_dir() and SHA256_RE.fullmatch(path.name.casefold()):
            index[path.name.casefold()] = path
    return index


def _is_pe(data: bytes) -> bool:
    if not data.startswith(b"MZ"):
        return False
    try:
        pefile.PE(data=data, fast_load=True)
    except Exception:
        return True
    return True


def prepare_inputs(
    repository: Path,
    collection_dir: Path,
    sample_root: Path,
    private_output: Path,
) -> tuple[dict[str, ProgramObject], dict[str, list[dict[str, Any]]]]:
    """root検体と復元layerを隔離保存し、Ghidra対象をdeduplicateする。"""

    collection = json.loads((collection_dir / "manifest.json").read_text(encoding="utf-8-sig"))
    acquisition = json.loads((sample_root / "manifest.json").read_text(encoding="utf-8-sig"))
    archive_by_sha = {str(item["sha256"]).casefold(): Path(item["zip_path"]) for item in acquisition.get("items", [])}
    case_paths = _case_index(repository)
    requested = [str(item["case_id"]).removeprefix("sha256:").casefold() for item in collection.get("cases", [])]
    if not requested or len(set(requested)) != len(requested):
        raise ValueError("collectionには1件以上の重複しないSHA-256が必要です")
    objects: dict[str, ProgramObject] = {}
    non_pe: dict[str, list[dict[str, Any]]] = defaultdict(list)
    relationships: list[dict[str, Any]] = []

    for case_number, case_sha in enumerate(requested, start=1):
        archive = archive_by_sha.get(case_sha)
        if archive is None or not archive.is_file():
            raise FileNotFoundError(f"archiveが見つかりません: {case_sha}")
        case_dir = case_paths.get(case_sha)
        if case_dir is None:
            raise FileNotFoundError(f"公開caseが見つかりません: {case_sha}")
        unit = read_input_unit(
            archive,
            password="infected",
            archive_mode="malwarebazaar",
            max_file_size=512 * 1024 * 1024,
        )
        if hashlib.sha256(unit.data).hexdigest() != case_sha:
            raise ValueError(f"root検体hashが一致しません: {case_sha}")
        layers, _ = recover_static_layers(unit)
        public_layers = json.loads((case_dir / "static-layers.json").read_text(encoding="utf-8-sig")).get("layers", [])
        expected = {
            (
                str(item["sha256"]).casefold(),
                int(item["size"]),
                int(item["depth"]),
                str(item["transform"]),
            )
            for item in public_layers
        }
        actual = {(layer.sha256, len(layer.data), layer.depth, layer.transform) for layer in layers}
        if expected != actual:
            raise ValueError(f"静的layer再現結果が公開成果物と一致しません: {case_sha}")

        for layer in layers:
            if layer.depth == 0:
                destination = sample_root / case_sha / "ghidra-input" / f"{layer.sha256}.quarantine.bin"
            else:
                destination = sample_root / case_sha / "ghidra-input" / "layers" / f"{layer.sha256}.quarantine.bin"
            destination.parent.mkdir(parents=True, exist_ok=True)
            if destination.is_file():
                if _sha256_file(destination) != layer.sha256:
                    raise ValueError(f"既存の隔離input hashが一致しません: {destination}")
            else:
                destination.write_bytes(layer.data)
            relation = {
                "case_sha256": case_sha,
                "layer_sha256": layer.sha256,
                "depth": layer.depth,
                "transform": layer.transform,
                "parent_sha256": layer.parent_sha256,
                "size": len(layer.data),
                "is_pe": _is_pe(layer.data),
            }
            relationships.append(relation)
            if relation["is_pe"]:
                item = objects.setdefault(
                    layer.sha256,
                    ProgramObject(layer.sha256, destination, len(layer.data)),
                )
                item.relationships.append(relation)
            else:
                if layer.transform == "pe-resource-script":
                    script_records = extract_script_function_records(layer.data, layer.name)
                    for record in script_records:
                        record["function_id"] = f"{layer.sha256}:script:{record['function_id']}"
                        record["source_program_sha256"] = layer.sha256
                        record["analysis_kind"] = "bounded_script_static_parser"
                        record["decompilation_status"] = "succeeded"
                        record["relationship"] = "statically_recovered_script"
                    relation["script_function_records"] = script_records
                non_pe[case_sha].append(relation)
        print(
            json.dumps(
                {
                    "phase": "prepare",
                    "case": case_number,
                    "total": len(requested),
                    "sha256": case_sha,
                    "layers": len(layers),
                    "executed": False,
                },
                ensure_ascii=False,
            ),
            flush=True,
        )

    _json_dump(
        private_output / "input-relationships.json",
        {
            "schema_version": SCHEMA_VERSION,
            "collection_id": collection_dir.name,
            "relationships": relationships,
            "unique_pe_objects": len(objects),
            "sample_executed": False,
            "network_contacted": False,
        },
    )
    return objects, non_pe


def _parse_metadata(value: Any) -> dict[str, str]:
    if not isinstance(value, str):
        return {}
    output = {}
    for line in value.splitlines():
        if ":" not in line:
            continue
        key, rendered = line.split(":", 1)
        output[key.strip().casefold().replace(" ", "_")] = rendered.strip()
    output.pop("executable_path", None)
    return output


def load_prepared_inputs(
    sample_root: Path,
    private_output: Path,
) -> tuple[dict[str, ProgramObject], dict[str, list[dict[str, Any]]]]:
    """SHA-256検証済みcacheから再展開せずprogram inventoryを復元する。"""

    relationship_path = private_output / "input-relationships.json"
    document = json.loads(relationship_path.read_text(encoding="utf-8-sig"))
    relationships = document.get("relationships", [])
    objects: dict[str, ProgramObject] = {}
    non_pe: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for raw in relationships:
        if not isinstance(raw, Mapping):
            raise ValueError("input relationshipがJSON objectではありません")
        relation = dict(raw)
        digest = str(relation.get("layer_sha256") or "").casefold()
        case_sha = str(relation.get("case_sha256") or "").casefold()
        if not SHA256_RE.fullmatch(digest) or not SHA256_RE.fullmatch(case_sha):
            raise ValueError("input relationshipのSHA-256が不正です")
        if not bool(relation.get("is_pe")):
            non_pe[case_sha].append(relation)
            continue
        input_root = sample_root / case_sha / "ghidra-input"
        input_path = (
            input_root / f"{digest}.quarantine.bin"
            if int(relation.get("depth") or 0) == 0
            else input_root / "layers" / f"{digest}.quarantine.bin"
        )
        if not input_path.is_file():
            raise FileNotFoundError(f"再開用PE cacheがありません: {input_path}")
        if input_path.stat().st_size != int(relation.get("size") or -1):
            raise ValueError(f"再開用PE cacheのsizeが一致しません: {digest}")
        hasher = hashlib.sha256()
        with input_path.open("rb") as handle:
            while chunk := handle.read(1024 * 1024):
                hasher.update(chunk)
        if hasher.hexdigest() != digest:
            raise ValueError(f"再開用PE cacheのSHA-256が一致しません: {digest}")
        if digest not in objects:
            objects[digest] = ProgramObject(
                sha256=digest,
                input_path=input_path,
                size=input_path.stat().st_size,
            )
        objects[digest].relationships.append(relation)
    expected = int(document.get("unique_pe_objects") or 0)
    if expected <= 0 or len(objects) != expected:
        raise ValueError(f"再開用PE program数が一致しません: {len(objects)} != {expected}")
    print(
        json.dumps(
            {
                "phase": "reuse_prepared_inputs",
                "unique_pe_programs": len(objects),
                "relationships": len(relationships),
                "executed": False,
            },
            ensure_ascii=False,
        ),
        flush=True,
    )
    return objects, non_pe


def validate_prepared_scope(
    collection_dir: Path,
    private_output: Path,
) -> None:
    """再開cacheのcollection IDとcase集合が対象manifestに完全一致するか確認する。"""

    collection = json.loads((collection_dir / "manifest.json").read_text(encoding="utf-8-sig"))
    expected = {
        str(item.get("case_id") or "").removeprefix("sha256:").casefold()
        for item in collection.get("cases", [])
        if isinstance(item, Mapping)
    }
    document = json.loads(
        (private_output / "input-relationships.json").read_text(encoding="utf-8-sig")
    )
    if str(document.get("collection_id") or "") != collection_dir.name:
        raise ValueError("再開cacheのcollection IDが対象directoryと一致しません")
    observed = {
        str(item.get("case_sha256") or "").casefold()
        for item in document.get("relationships", [])
        if isinstance(item, Mapping)
    }
    if not expected or observed != expected:
        raise ValueError(
            f"再開cacheのcase集合が対象collectionと一致しません: {len(observed)} != {len(expected)}"
        )


def _all_functions(client: GhidraMcpClient, program: str) -> list[dict[str, Any]]:
    functions: list[dict[str, Any]] = []
    offset = 0
    while True:
        page = client.get(
            "/list_functions_enhanced",
            offset=offset,
            limit=FUNCTION_PAGE_SIZE,
            program=program,
        )
        values = list((page or {}).get("functions", []))
        functions.extend(value for value in values if isinstance(value, dict))
        total = int((page or {}).get("count", len(functions)))
        offset += len(values)
        if not values or offset >= total:
            break
    return functions


def _all_opcode_hashes(
    client: GhidraMcpClient,
    program: str,
    function_inventory: list[dict[str, Any]],
) -> dict[str, Any]:
    functions: list[dict[str, Any]] = []
    offset = 0
    while True:
        page = client.get(
            "/get_bulk_function_hashes",
            offset=offset,
            limit=FUNCTION_PAGE_SIZE,
            filter="",
            program=program,
        )
        values = list((page or {}).get("functions", []))
        functions.extend(value for value in values if isinstance(value, dict))
        total = int((page or {}).get("total_matching", len(function_inventory)))
        offset += len(values)
        if not values or offset >= total:
            break
    return _complete_opcode_hash_inventory(
        {
            "program": program,
            "functions": functions,
            "endpoint_returned": len(functions),
        },
        function_inventory,
        program,
    )


def _complete_opcode_hash_inventory(
    value: Mapping[str, Any] | None,
    function_inventory: Iterable[Mapping[str, Any]],
    program: str,
) -> dict[str, Any]:
    """hash取得不能な関数も理由付きrecordとして全件inventory化する。"""

    raw_rows = [dict(item) for item in (value or {}).get("functions", []) if isinstance(item, Mapping)]
    rows_by_address: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in raw_rows:
        rows_by_address[str(row.get("address") or "")].append(row)
    completed = []
    for function in function_inventory:
        address = str(function.get("address") or "")
        candidates = rows_by_address.get(address, [])
        row = candidates.pop(0) if candidates else {}
        row.setdefault("address", address)
        row.setdefault("name", str(function.get("name") or "unknown"))
        digest = str(row.get("hash") or "").casefold()
        instruction_count = int(row.get("instruction_count") or 0)
        row["hash_status"] = (
            "available"
            if SHA256_RE.fullmatch(digest) and digest != EMPTY_SHA256 and instruction_count > 0
            else "unavailable_recorded"
        )
        row["program_selector"] = program
        completed.append(row)
    unmatched = [
        dict(item)
        for item in (value or {}).get("unmatched_response_rows", [])
        if isinstance(item, Mapping)
    ]
    unmatched.extend(row for rows in rows_by_address.values() for row in rows)
    return {
        "program": program,
        "functions": completed,
        "returned": len(completed),
        "endpoint_returned": int((value or {}).get("endpoint_returned") or len(raw_rows)),
        "total_matching": len(completed),
        "available_hashes": sum(row["hash_status"] == "available" for row in completed),
        "all_functions_recorded": True,
        "unmatched_response_rows": unmatched,
    }


def _page_values(page: Any, endpoint: str) -> list[Any]:
    """ページ応答を内容を捨てずにlistへ正規化する。"""

    if page is None:
        return []
    if isinstance(page, list):
        return list(page)
    if isinstance(page, str):
        rendered = page.strip()
        if not rendered:
            return []
        try:
            decoded = json.loads(rendered)
        except json.JSONDecodeError:
            return [line for line in page.splitlines() if line.strip()]
        if isinstance(decoded, list):
            return list(decoded)
        raise GhidraMcpError(f"{endpoint}の文字列応答がJSON listまたは行形式ではありません")
    if isinstance(page, Mapping):
        for key in ("items", "results", "imports", "exports", "strings", "segments"):
            values = page.get(key)
            if isinstance(values, list):
                return list(values)
        raise GhidraMcpError(f"{endpoint}のobject応答にlist項目がありません")
    raise GhidraMcpError(f"{endpoint}の応答形式を解釈できません: {type(page).__name__}")


def _all_endpoint_items(
    client: GhidraMcpClient,
    endpoint: str,
    program: str,
    *,
    page_size: int = STRUCTURE_PAGE_SIZE,
) -> tuple[list[Any], dict[str, Any]]:
    """offset/limit型endpointを空ページまで取得し、完全取得証跡を返す。"""

    values: list[Any] = []
    offset = 0
    page_count = 0
    seen_page_hashes: set[str] = set()
    while True:
        page = client.get(
            endpoint,
            offset=offset,
            limit=page_size,
            program=program,
        )
        page_values = _page_values(page, endpoint)
        page_count += 1
        page_hash = hashlib.sha256(
            json.dumps(page_values, ensure_ascii=False, sort_keys=True).encode("utf-8")
        ).hexdigest()
        if page_values and page_hash in seen_page_hashes:
            raise GhidraMcpError(f"{endpoint}がoffsetを無視した重複ページを返しました")
        seen_page_hashes.add(page_hash)
        values.extend(page_values)
        offset += len(page_values)
        if len(page_values) < page_size:
            break
    return values, {
        "endpoint": endpoint,
        "program_selector": program,
        "page_size": page_size,
        "page_count": page_count,
        "item_count": len(values),
        "terminal_short_page_observed": True,
        "complete": True,
    }


CHARACTERISTIC_PHASES = (
    ("startup", "起動・初期化", {"entrypoint"}),
    ("configuration", "設定・payload復元", {"config_or_data_transform", "cryptographic_transform"}),
    ("evasion", "解析回避・環境判定", {"anti_analysis"}),
    ("persistence", "永続化", {"persistence"}),
    ("execution", "process・memory操作", {"process_or_memory_operation"}),
    ("communication", "通信", {"network_communication"}),
    ("dispatch", "command分配・処理", {"command_dispatch_or_handler"}),
    ("file_activity", "file操作", {"file_operation"}),
    ("support", "補助処理", {"general_internal_logic", "compiler_or_library_code", "external_api_or_thunk", "managed_method_without_body"}),
)


def _entry_point_addresses(entry_points: Any) -> set[str]:
    """Ghidraのentry point応答からaddress候補を抽出する。"""

    values: set[str] = set()
    if isinstance(entry_points, str):
        values.update(re.findall(r"(?i)(?:@|address\s*[:=])\s*([0-9a-fx:]+)", entry_points))
    elif isinstance(entry_points, Mapping):
        values.update(
            str(value)
            for key, value in entry_points.items()
            if "address" in str(key).casefold() and value
        )
    elif isinstance(entry_points, Iterable):
        for item in entry_points:
            if isinstance(item, Mapping):
                value = item.get("address") or item.get("entry")
                if value:
                    values.add(str(value))
            elif isinstance(item, str):
                values.update(re.findall(r"(?i)(?:@|address\s*[:=])\s*([0-9a-fx:]+)", item))
    return {value.casefold().removeprefix("0x") for value in values}


def _call_graph_degrees(call_graph: Mapping[str, Any]) -> tuple[Counter[str], Counter[str], dict[str, list[str]]]:
    """call graphから入次数、出次数、callee名をaddress単位で集計する。"""

    inbound: Counter[str] = Counter()
    outbound: Counter[str] = Counter()
    callees: dict[str, list[str]] = defaultdict(list)
    for edge in call_graph.get("edges", []) if isinstance(call_graph, Mapping) else []:
        if not isinstance(edge, Mapping):
            continue
        caller = str(edge.get("caller_addr") or "")
        callee = str(edge.get("callee_addr") or "")
        callee_name = str(edge.get("callee_name") or callee)
        if caller:
            outbound[caller] += 1
            if callee_name:
                callees[caller].append(callee_name)
        if callee:
            inbound[callee] += 1
    return inbound, outbound, callees


def _characteristic_candidates(
    functions: Iterable[Mapping[str, Any]],
    call_graph: Mapping[str, Any],
    entry_points: Any,
    opcode_hashes: Mapping[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """関数inventoryを代表関数候補へ採点する。"""

    inbound, outbound, callees = _call_graph_degrees(call_graph)
    entries = _entry_point_addresses(entry_points)
    instruction_counts = {
        str(item.get("address") or ""): int(item.get("instruction_count") or 0)
        for item in (opcode_hashes or {}).get("functions", [])
        if isinstance(item, Mapping)
    }
    candidates: list[dict[str, Any]] = []
    for source in functions:
        item = dict(source)
        if bool(item.get("isExternal")) or bool(item.get("isThunk")):
            continue
        address = str(item.get("address") or "")
        name = str(item.get("name") or "unknown")
        related = callees.get(address, [])
        role = _classify_role(name, related, "")
        in_degree = inbound[address]
        out_degree = outbound[address]
        instructions = instruction_counts.get(address, int(item.get("instruction_count") or 0))
        reasons: list[str] = []
        score = 0
        normalized_address = address.casefold().removeprefix("0x")
        if normalized_address in entries or role == "entrypoint":
            score += 10_000
            reasons.append("entry_point")
        if role not in {"general_internal_logic", "compiler_or_library_code"}:
            score += 3_000
            reasons.append(f"role:{role}")
        if in_degree or out_degree:
            score += min(2_000, (in_degree + out_degree) * 40)
            reasons.append(f"call_graph_centrality:in={in_degree},out={out_degree}")
        if instructions:
            score += min(1_500, instructions)
            if instructions >= 64:
                reasons.append(f"large_function:instructions={instructions}")
        if not re.match(r"(?i)^(?:FUN_|sub_|func_0x)", name):
            score += 200
            reasons.append("meaningful_symbol_name")
        if role == "compiler_or_library_code":
            score -= 2_000
        if not reasons:
            reasons.append("context_representative")
        item.update(
            {
                "preliminary_role": role,
                "selection_score": score,
                "selection_reasons": reasons,
                "in_degree": in_degree,
                "out_degree": out_degree,
                "instruction_count": instructions,
            }
        )
        candidates.append(item)
    return candidates


def select_characteristic_functions(
    functions: Iterable[Mapping[str, Any]],
    call_graph: Mapping[str, Any],
    entry_points: Any,
    opcode_hashes: Mapping[str, Any] | None = None,
    *,
    max_count: int = MAX_CHARACTERISTIC_FUNCTIONS_PER_PROGRAM,
) -> list[dict[str, Any]]:
    """役割の網羅と中心性を両立する代表関数集合を返す。"""

    candidates = _characteristic_candidates(functions, call_graph, entry_points, opcode_hashes)
    if len(candidates) <= max_count:
        for item in candidates:
            item["selection_reasons"] = sorted(
                set([*item["selection_reasons"], "small_program_complete_context"])
            )
        return sorted(candidates, key=lambda item: str(item.get("address") or ""))
    ranked = sorted(
        candidates,
        key=lambda item: (
            -int(item["selection_score"]),
            -int(item["instruction_count"]),
            str(item.get("address") or ""),
        ),
    )
    selected: dict[str, dict[str, Any]] = {}
    for role in {phase_role for _, _, roles in CHARACTERISTIC_PHASES for phase_role in roles}:
        representative = next((item for item in ranked if item["preliminary_role"] == role), None)
        if representative:
            selected[str(representative["address"])] = representative
    for item in ranked:
        if len(selected) >= max_count:
            break
        selected.setdefault(str(item["address"]), item)
    return sorted(selected.values(), key=lambda item: (-int(item["selection_score"]), str(item["address"])))


def _record_selection_score(record: Mapping[str, Any]) -> tuple[int, list[str]]:
    """解析済みrecordを代表関数として再評価する。"""

    role = str(record.get("role") or "general_internal_logic")
    reasons = [str(value) for value in record.get("selection_reasons", []) if value]
    score = int(record.get("selection_score") or 0)
    if role == "entrypoint":
        score += 10_000
        reasons.append("entry_point")
    elif role not in {"general_internal_logic", "compiler_or_library_code", "external_api_or_thunk", "managed_method_without_body"}:
        score += 3_000
        reasons.append(f"role:{role}")
    degree = len(record.get("callers") or []) + len(record.get("callees") or []) + len(record.get("api_calls") or [])
    if degree:
        score += min(2_000, degree * 40)
        reasons.append(f"reviewed_call_centrality:{degree}")
    instructions = int(record.get("instruction_count") or 0)
    score += min(1_500, instructions)
    if instructions >= 64:
        reasons.append(f"large_function:instructions={instructions}")
    if not reasons:
        reasons.append("context_representative")
    return score, sorted(set(reasons))


def _mark_characteristic_records(
    records: list[dict[str, Any]],
    *,
    max_count: int = MAX_CHARACTERISTIC_FUNCTIONS_PER_PROGRAM,
) -> list[str]:
    """nativeとmanagedの各recordへ選定状態・理由を付与する。"""

    selected_ids: list[str] = []
    for analysis_kind in ("ghidra_native_or_loader_view", "managed_cil"):
        eligible = [
            item
            for item in records
            if item.get("analysis_kind") == analysis_kind
            and item.get("decompilation_status") not in {"excluded_external_or_thunk", "no_managed_body"}
        ]
        structural_fallback = [
            item
            for item in records
            if item.get("analysis_kind") == analysis_kind
            and item.get("decompilation_status") in {"excluded_external_or_thunk", "no_managed_body"}
        ]
        already = [item for item in eligible if item.get("selected_for_characteristic_analysis") is True]
        pool = already or eligible or structural_fallback
        selection_limit = max_count if (already or eligible) else min(4, max_count)
        scored = []
        for item in pool:
            score, reasons = _record_selection_score(item)
            item["selection_score"] = score
            item["selection_reasons"] = reasons
            scored.append(item)
        ranked = sorted(
            scored,
            key=lambda item: (-int(item.get("selection_score") or 0), str(item.get("function_id") or "")),
        )
        chosen: dict[str, dict[str, Any]] = {}
        for role in {phase_role for _, _, roles in CHARACTERISTIC_PHASES for phase_role in roles}:
            representative = next((item for item in ranked if item.get("role") == role), None)
            if representative:
                chosen[str(representative["function_id"])] = representative
        for item in ranked:
            if len(chosen) >= selection_limit:
                break
            chosen.setdefault(str(item["function_id"]), item)
        for item in [*eligible, *structural_fallback]:
            selected = str(item.get("function_id") or "") in chosen
            item["selected_for_characteristic_analysis"] = selected
            if selected and eligible and len(eligible) <= max_count:
                item["selection_reasons"] = sorted(
                    set([*item.get("selection_reasons", []), "small_program_complete_context"])
                )
            if selected and not eligible:
                item["selection_reasons"] = sorted(
                    set([*item.get("selection_reasons", []), "no_internal_body_structural_fallback"])
                )
            if selected:
                selected_ids.append(str(item["function_id"]))
    for item in records:
        item.setdefault("selected_for_characteristic_analysis", False)
        item.setdefault("selection_reasons", [])
    return sorted(set(selected_ids))

def ensure_characteristic_selection(result: dict[str, Any]) -> list[str]:
    """cacheを含むprogram結果へ代表関数選定情報を付与する。"""

    records = [item for item in result.get("functions", []) if isinstance(item, dict)]
    selected_ids = _mark_characteristic_records(records)
    result["characteristic_function_ids"] = selected_ids
    result["characteristic_function_count"] = len(selected_ids)
    result["selection_policy"] = {
        "name": "role_entrypoint_callgraph_size_representatives",
        "maximum_per_analysis_kind": MAX_CHARACTERISTIC_FUNCTIONS_PER_PROGRAM,
        "required_dimensions": [
            "entry_point",
            "malware_behavior_role",
            "call_graph_centrality",
            "function_size",
            "symbol_quality",
        ],
        "all_functions_decompilation_required": False,
        "unselected_scope_recorded": True,
    }
    return selected_ids

def _decompile_status(pseudocode: str) -> tuple[str, list[str]]:
    lowered = pseudocode.casefold()
    warnings = [value.strip() for value in re.findall(r"/\*\s*(WARNING:[^*]+)\*/", pseudocode, re.IGNORECASE)]
    if not pseudocode.strip():
        return "failed_empty", warnings
    if any(marker in lowered for marker in FATAL_DECOMPILE_MARKERS):
        return "failed", warnings
    if any(marker in lowered for marker in LIMITED_DECOMPILE_MARKERS):
        return "limited_bad_instruction_or_flow", warnings
    return "succeeded", warnings


def _load_jsonl(path: Path) -> dict[str, dict[str, Any]]:
    output: dict[str, dict[str, Any]] = {}
    if not path.is_file():
        return output
    for line in path.read_text(encoding="utf-8-sig").splitlines():
        if not line.strip():
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict) and item.get("address"):
            output[str(item["address"])] = item
    return output


def _append_jsonl(path: Path, values: Iterable[Mapping[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8", newline="\n") as handle:
        for value in values:
            handle.write(json.dumps(dict(value), ensure_ascii=False, sort_keys=True) + "\n")
        handle.flush()


def _decompile_chunk(
    client: GhidraMcpClient,
    program: str,
    chunk: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """MCP上限内の関数群を逆コンパイルし、失敗状態を含む全recordを返す。"""

    addresses = ",".join(str(item["address"]) for item in chunk)
    try:
        response = client.get(
            "/batch_decompile",
            functions=addresses,
            program=program,
        )
    except GhidraMcpError:
        response = {}
    if not isinstance(response, Mapping):
        response = {}
    rows = []
    for item in chunk:
        address = str(item["address"])
        pseudocode = str(response.get(address) or "")
        if not pseudocode:
            try:
                pseudocode = str(
                    client.get(
                        "/decompile_function",
                        address=address,
                        program=program,
                        timeout=120,
                    )
                    or ""
                )
            except GhidraMcpError as error:
                pseudocode = ""
                error_text = type(error).__name__
            else:
                error_text = None
        else:
            error_text = None
        status, warnings = _decompile_status(pseudocode)
        rows.append(
            {
                "address": address,
                "name": str(item.get("name") or "unknown"),
                "status": status,
                "warnings": warnings,
                "error": error_text,
                "pseudocode": pseudocode,
                "program_selector": program,
            }
        )
    return rows


def _decompile_all(
    client: GhidraMcpClient,
    program: str,
    functions: list[dict[str, Any]],
    raw_path: Path,
) -> dict[str, dict[str, Any]]:
    existing = _load_jsonl(raw_path)
    targets = [
        item
        for item in functions
        if not bool(item.get("isExternal"))
        and not bool(item.get("isThunk"))
        and str(item.get("address")) not in existing
    ]
    chunks = [
        targets[start : start + DECOMPILE_BATCH_SIZE]
        for start in range(0, len(targets), DECOMPILE_BATCH_SIZE)
    ]
    initial_saved = len(existing)
    processed = 0
    if not chunks:
        return existing
    with ThreadPoolExecutor(
        max_workers=min(DECOMPILE_WORKERS, len(chunks)),
        thread_name_prefix="ghidra-decompile",
    ) as executor:
        futures = [
            executor.submit(_decompile_chunk, client, program, chunk)
            for chunk in chunks
        ]
        for future in as_completed(futures):
            rows = future.result()
            _append_jsonl(raw_path, rows)
            for row in rows:
                existing[str(row["address"])] = row
            processed += len(rows)
            print(
                json.dumps(
                    {
                        "phase": "decompile",
                        "program_selector": program,
                        "completed": processed,
                        "total": len(targets),
                        "previously_saved": initial_saved,
                        "overall_completed": initial_saved + processed,
                        "overall_total": initial_saved + len(targets),
                        "workers": min(DECOMPILE_WORKERS, len(chunks)),
                        "batch_size": DECOMPILE_BATCH_SIZE,
                        "executed": False,
                    },
                    ensure_ascii=False,
                ),
                flush=True,
            )
    return existing

def _token_value(operand: Any) -> Any:
    value = getattr(operand, "value", operand)
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, (list, tuple)):
        return [_token_value(item) for item in value]
    return str(value)


def _method_owner_map(pe: dnfile.dnPE) -> dict[int, str]:
    owners: dict[int, str] = {}
    table = getattr(getattr(pe.net, "mdtables", None), "TypeDef", None)
    for row in getattr(table, "rows", []) or []:
        full_name = ".".join(value for value in (str(row.TypeNamespace), str(row.TypeName)) if value)
        for reference in getattr(row, "MethodList", ()) or ():
            owners[int(reference.row_index)] = full_name
    return owners


def _token_name(pe: dnfile.dnPE, token: int) -> str:
    table_id = (token >> 24) & 0xFF
    row_id = token & 0xFFFFFF
    names = {0x06: "MethodDef", 0x0A: "MemberRef", 0x2B: "MethodSpec"}
    table_name = names.get(table_id)
    table = getattr(getattr(pe.net, "mdtables", None), table_name, None) if table_name else None
    rows = getattr(table, "rows", None)
    if not rows or not 1 <= row_id <= len(rows):
        return f"token:0x{token:08x}"
    row = rows[row_id - 1]
    name = str(getattr(row, "Name", f"row_{row_id}"))
    owner = getattr(row, "Class", None) or getattr(row, "Method", None)
    owner_row = getattr(owner, "row", None)
    owner_name = ""
    if owner_row is not None:
        owner_name = ".".join(
            str(value)
            for value in (
                getattr(owner_row, "TypeNamespace", ""),
                getattr(owner_row, "TypeName", ""),
            )
            if value
        )
    return f"{owner_name}.{name}".strip(".")


def _managed_cil_records(data: bytes, raw_path: Path, layer_sha256: str) -> list[dict[str, Any]]:
    """全managed methodのCILを静的に列挙し、raw命令列をprivate JSONLへ保存する。"""

    try:
        pe = dnfile.dnPE(data=data, clr_lazy_load=True)
    except Exception:
        return []
    if not getattr(pe, "net", None):
        return []
    method_table = getattr(getattr(pe.net, "mdtables", None), "MethodDef", None)
    rows = getattr(method_table, "rows", None)
    if not rows:
        return []
    owners = _method_owner_map(pe)
    records = []
    raw_rows = []
    for index, row in enumerate(rows, start=1):
        token = 0x06000000 | index
        token_text = f"0x{token:08x}"
        owner = owners.get(index, "")
        name = str(getattr(row, "Name", f"method_{index}"))
        rva = int(getattr(row, "Rva", 0) or 0)
        function_id = f"{layer_sha256}:cil:{token_text}"
        if not rva:
            records.append(
                {
                    "function_id": function_id,
                    "name": f"{owner}.{name}".strip("."),
                    "token": token_text,
                    "role": "managed_method_without_body",
                    "summary_ja": SUMMARY_BY_ROLE["managed_method_without_body"],
                    "logic_steps_ja": [
                        "CLR metadataのMethodDefを確認しました。",
                        "RVAがないためCIL本体の逆アセンブル対象外として記録しました。",
                    ],
                    "source": "dnfile/dncil",
                    "tool": "bounded_managed_cil_static_parser",
                    "program_selector": f"sha256:{layer_sha256}",
                    "confidence": "confirmed_metadata_inventory",
                    "decompilation_status": "no_managed_body",
                    "analysis_kind": "managed_cil",
                    "source_program_sha256": layer_sha256,
                }
            )
            continue
        instructions = []
        calls = []
        normalized = []
        error_name = None
        try:
            offset = int(pe.get_offset_from_rva(rva))
            body = read_method_body_from_bytes(data[offset:])
            for instruction in list(getattr(body, "instructions", ()) or ()):
                opcode = str(getattr(getattr(instruction, "opcode", None), "name", "unknown"))
                operand = _token_value(getattr(instruction, "operand", None))
                rendered_operand: Any = operand
                if opcode.casefold() == "ldstr":
                    rendered_operand = "<str>"
                elif opcode.casefold() in {"call", "callvirt", "newobj"} and isinstance(operand, int):
                    rendered_operand = _token_name(pe, operand)
                    calls.append(rendered_operand)
                elif isinstance(operand, (int, float)):
                    rendered_operand = "<num>"
                elif isinstance(operand, list):
                    rendered_operand = ["<target>" for _ in operand]
                instructions.append(
                    {
                        "offset": str(getattr(instruction, "offset", "")),
                        "opcode": opcode,
                        "operand": operand,
                    }
                )
                normalized.append(f"{opcode} {rendered_operand}" if rendered_operand is not None else opcode)
        except Exception as error:
            error_name = type(error).__name__
        status = "succeeded" if error_name is None else "failed_malformed_cil"
        role = _classify_role(f"{owner}.{name}", calls, "\n".join(normalized))
        steps = _logic_steps("\n".join(normalized), calls, status, analysis_kind="managed_cil")
        records.append(
            {
                "function_id": function_id,
                "name": f"{owner}.{name}".strip("."),
                "token": token_text,
                "role": role,
                "summary_ja": SUMMARY_BY_ROLE[role],
                "logic_steps_ja": steps,
                "pseudocode": "\n".join(normalized),
                "callees": sorted(set(calls)),
                "api_calls": sorted(set(calls)),
                "source": "dnfile/dncil",
                "tool": "bounded_managed_cil_static_parser",
                "program_selector": f"sha256:{layer_sha256}",
                "confidence": (
                    "confirmed_static_cil_disassembly"
                    if status == "succeeded"
                    else "confirmed_metadata_cil_parse_failed"
                ),
                "decompilation_status": status,
                "decompilation_error": error_name,
                "analysis_kind": "managed_cil",
                "source_program_sha256": layer_sha256,
                "instruction_count": len(instructions),
                "next_analysis": (
                    ""
                    if status == "succeeded"
                    else "metadata保護または破損境界を確認し、別のstatic CIL parserでcross-checkします。"
                ),
            }
        )
        raw_rows.append(
            {
                "function_id": function_id,
                "token": token_text,
                "owner": owner,
                "name": name,
                "rva": hex(rva),
                "status": status,
                "error": error_name,
                "instructions": instructions,
                "executed": False,
                "emulated": False,
            }
        )
    raw_path.unlink(missing_ok=True)
    _append_jsonl(raw_path, raw_rows)
    return records


def _classify_role(name: str, calls: Iterable[str], pseudocode: str) -> str:
    combined = "\n".join([name, *calls, pseudocode[:50_000]])
    if LIBRARY_RE.search(name):
        return "compiler_or_library_code"
    if ROLE_PATTERNS[0][1].search(name):
        return "entrypoint"
    for role, pattern in ROLE_PATTERNS[1:]:
        if pattern.search(name):
            return role
    for role, pattern in ROLE_PATTERNS[1:]:
        if pattern.search(combined):
            return role
    return "general_internal_logic"


def _logic_steps(
    pseudocode: str,
    callees: Iterable[str],
    status: str,
    *,
    analysis_kind: str = "ghidra_native",
) -> list[str]:
    steps = [
        (
            "dnfile/dncilでmetadata tokenとCIL method境界を確認しました。"
            if analysis_kind == "managed_cil"
            else "Ghidra MCPで明示的なprogram selectorを指定し、関数境界を確認しました。"
        )
    ]
    if status == "succeeded":
        steps.append("関数本体を静的に逆コンパイルまたは逆アセンブルしました。")
    elif status in {"no_managed_body", "excluded_external_or_thunk"}:
        steps.append("関数本体を持たない対象としてinventoryへ残しました。")
    else:
        steps.append("逆コンパイルを試行し、失敗または不完全なcontrol flowを記録しました。")
    lowered = pseudocode.casefold()
    if re.search(r"\bif\b|\bswitch\b|\bcase\b|\bbr(?:true|false)?\b", lowered):
        steps.append("条件分岐またはdispatcher形状を確認しました。")
    if re.search(r"\bfor\b|\bwhile\b|\bdo\b|\bloop\b|\bbr\.s\b", lowered):
        steps.append("反復または後方分岐を含むcontrol flowを確認しました。")
    unique_calls = sorted({str(value) for value in callees if value})[:16]
    if unique_calls:
        steps.append(
            "主要call関係を確認しました: " + "、".join(redact_static_text(value) for value in unique_calls) + "。"
        )
    if re.search(r"\btry\b|\bcatch\b|\bthrow\b|\bleave\b", lowered):
        steps.append("例外処理または異常終了経路を確認しました。")
    if re.search(r"\breturn\b|\bret\b", lowered):
        steps.append("return経路と結果の利用境界を確認しました。")
    return steps


def _next_analysis(status: str, pseudocode: str) -> str:
    if status == "succeeded":
        return ""
    if ".net clr managed code" in pseudocode.casefold():
        return "native表示ではなくCLR metadataとCIL method bodyを優先して確認します。"
    if status == "limited_bad_instruction_or_flow":
        return "packer／VM／indirect flowの影響を確認し、復元layerまたは追加disassemblyで再解析します。"
    return "対象addressの境界、language、loader、packer状態を再確認して個別decompileします。"


def _program_records(
    program_object: ProgramObject,
    program_selector: str,
    functions: list[dict[str, Any]],
    decompilations: Mapping[str, Mapping[str, Any]],
    call_graph: Mapping[str, Any],
    opcode_hashes: Mapping[str, Any],
    selection_by_address: Mapping[str, Mapping[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    address_to_function = {
        str(item["address"]): f"{program_object.sha256}:ghidra:{item['address']}" for item in functions
    }
    callers: dict[str, list[str]] = defaultdict(list)
    callees: dict[str, list[str]] = defaultdict(list)
    api_calls: dict[str, list[str]] = defaultdict(list)
    for edge in call_graph.get("edges", []) if isinstance(call_graph, Mapping) else []:
        if not isinstance(edge, Mapping):
            continue
        caller_addr = str(edge.get("caller_addr") or "")
        callee_addr = str(edge.get("callee_addr") or "")
        callee_name = str(edge.get("callee_name") or callee_addr)
        caller_id = address_to_function.get(caller_addr)
        callee_id = address_to_function.get(callee_addr)
        if not caller_id:
            continue
        if callee_id:
            callees[caller_addr].append(callee_id)
            callers[callee_addr].append(caller_id)
        elif callee_name:
            callees[caller_addr].append(callee_name)
            api_calls[caller_addr].append(callee_name)
    hashes = {
        str(item.get("address")): item for item in opcode_hashes.get("functions", []) if isinstance(item, Mapping)
    }
    records = []
    for item in functions:
        address = str(item.get("address") or "unknown")
        name = str(item.get("name") or "unknown")
        external_or_thunk = bool(item.get("isExternal")) or bool(item.get("isThunk"))
        decompiled = dict(decompilations.get(address, {}))
        pseudocode = str(decompiled.get("pseudocode") or "")
        status = (
            "excluded_external_or_thunk"
            if external_or_thunk
            else str(decompiled.get("status") or "failed_not_attempted")
        )
        related_calls = sorted(set(callees[address]))
        related_apis = sorted(set(api_calls[address]))
        role = (
            "external_api_or_thunk"
            if external_or_thunk
            else _classify_role(name, related_calls + related_apis, pseudocode)
        )
        hash_row = hashes.get(address, {})
        selection = dict((selection_by_address or {}).get(address, {}))
        records.append(
            {
                "function_id": f"{program_object.sha256}:ghidra:{address}",
                "name": name,
                "address": address,
                "role": role,
                "summary_ja": SUMMARY_BY_ROLE[role],
                "logic_steps_ja": _logic_steps(
                    pseudocode,
                    related_calls + related_apis,
                    status,
                ),
                "pseudocode": pseudocode,
                "callers": sorted(set(callers[address])),
                "callees": related_calls,
                "api_calls": related_apis,
                "source": "ghidra-mcp",
                "tool": "ghidra-mcp",
                "program_selector": program_selector,
                "confidence": (
                    "confirmed_static_decompilation"
                    if status == "succeeded"
                    else "confirmed_boundary_with_documented_decompile_limit"
                ),
                "decompilation_status": status,
                "decompilation_warnings": list(decompiled.get("warnings") or []),
                "decompilation_error": decompiled.get("error"),
                "analysis_kind": "ghidra_native_or_loader_view",
                "source_program_sha256": program_object.sha256,
                "relationship": (
                    "root_program" if int(program_object.primary["depth"]) == 0 else "statically_recovered_program"
                ),
                "opcode_sha256": str(hash_row.get("hash") or ""),
                "instruction_count": int(hash_row.get("instruction_count") or 0),
                "next_analysis": _next_analysis(status, pseudocode),
                "selected_for_characteristic_analysis": bool(selection),
                "selection_reasons": list(selection.get("selection_reasons") or []),
                "selection_score": int(selection.get("selection_score") or 0),
            }
        )
    return records


def _wait_for_analysis(
    client: GhidraMcpClient,
    program: str,
    *,
    timeout_seconds: int,
) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_seconds
    last: dict[str, Any] = {}
    while time.monotonic() < deadline:
        value = client.get("/analysis_status", program=program)
        if isinstance(value, Mapping):
            last = dict(value)
            if not bool(value.get("analyzing")):
                return last
        time.sleep(2)
    raise TimeoutError(f"Ghidra auto-analysis timeout: {program}")


def analyze_program(
    client: GhidraMcpClient,
    item: ProgramObject,
    private_output: Path,
    project_root: str,
    *,
    analysis_timeout: int,
) -> dict[str, Any]:
    """1つのPE layerをGhidra MCPで解析し、private raw成果物を保存する。"""

    output_dir = private_output / "objects" / item.sha256
    result_path = output_dir / "program-result.json"
    if result_path.is_file():
        cached = json.loads(result_path.read_text(encoding="utf-8-sig"))
        if cached.get("status") == "complete" and cached.get("mcp_responses_valid") is True:
            ensure_characteristic_selection(cached)
            _json_dump(result_path, cached)
            return cached
    primary = item.primary
    case_sha = str(primary["case_sha256"])
    if int(primary["depth"]) == 0:
        folder = _safe_project_path(f"{project_root}/{case_sha[:8]}")
    else:
        folder = _safe_project_path(f"{project_root}/{case_sha[:8]}/layers/{item.sha256[:8]}")
    expected_program = _safe_project_path(f"{folder}/{item.input_path.name}")
    try:
        opened = client.get("/open_program", path=expected_program, auto_analyze=False)
        program = str((opened or {}).get("path") or expected_program)
    except GhidraMcpError:
        imported = client.post(
            "/import_file",
            {
                "file_path": str(item.input_path.resolve()),
                "project_folder": folder,
                "auto_analyze": True,
            },
        )
        if not isinstance(imported, Mapping) or not imported.get("path"):
            raise GhidraMcpError(f"import responseにprogram pathがありません: {item.sha256}")
        program = _safe_project_path(str(imported["path"]))
    if program != expected_program:
        raise GhidraMcpError(f"program selectorが予期したpathと一致しません: {program} != {expected_program}")
    status = _wait_for_analysis(
        client,
        program,
        timeout_seconds=analysis_timeout,
    )
    if bool(status.get("should_ask_to_analyze")) or not bool(status.get("analyzed", True)):
        client.post("/run_analysis", {}, program=program)
        status = _wait_for_analysis(
            client,
            program,
            timeout_seconds=analysis_timeout,
        )
    functions = _all_functions(client, program)
    metadata_raw = client.get("/get_metadata", program=program)
    call_graph = client.get(
        "/get_full_call_graph",
        format="json_edges",
        limit=0,
        program=program,
    ) or {"edges": []}
    imports = client.get("/list_imports", offset=0, limit=10000, program=program)
    exports = client.get("/list_exports", offset=0, limit=10000, program=program)
    strings = client.get("/list_strings", offset=0, limit=100000, program=program)
    segments = client.get("/list_segments", offset=0, limit=10000, program=program)
    entry_points = client.get("/get_entry_points", program=program)
    anti_analysis = client.get("/find_anti_analysis_techniques", program=program)
    api_chains = client.get("/analyze_api_call_chains", program=program)
    opcode_hashes = _all_opcode_hashes(client, program, functions)
    selected_native = select_characteristic_functions(
        functions,
        call_graph if isinstance(call_graph, Mapping) else {},
        entry_points,
        opcode_hashes if isinstance(opcode_hashes, Mapping) else {},
    )
    selection_by_address = {
        str(item["address"]): item for item in selected_native if item.get("address")
    }
    decompilations = _decompile_all(
        client,
        program,
        selected_native,
        output_dir / "decompilations.raw.jsonl",
    )
    data = item.input_path.read_bytes()
    if hashlib.sha256(data).hexdigest() != item.sha256:
        raise ValueError(f"Ghidra input hashが解析直前に一致しません: {item.sha256}")
    cil_records = _managed_cil_records(
        data,
        output_dir / "cil-instructions.raw.jsonl",
        item.sha256,
    )
    for record in cil_records:
        record["program_selector"] = program
    records = _program_records(
        item,
        program,
        functions,
        decompilations,
        call_graph if isinstance(call_graph, Mapping) else {},
        opcode_hashes if isinstance(opcode_hashes, Mapping) else {},
        selection_by_address,
    )
    records.extend(cil_records)
    selected_ids = _mark_characteristic_records(records)
    raw_index = {
        "schema_version": SCHEMA_VERSION,
        "sha256": item.sha256,
        "program_selector": program,
        "metadata": metadata_raw,
        "analysis_status": status,
        "functions": functions,
        "call_graph": call_graph,
        "imports": imports,
        "exports": exports,
        "strings": strings,
        "segments": segments,
        "entry_points": entry_points,
        "anti_analysis": anti_analysis,
        "api_call_chains": api_chains,
        "opcode_hashes": opcode_hashes,
        "characteristic_function_ids": selected_ids,
        "characteristic_function_count": len(selected_ids),
        "characteristic_selection": [
            {
                "function_id": item.get("function_id"),
                "address_or_token": item.get("address") or item.get("token"),
                "role": item.get("role"),
                "selection_score": item.get("selection_score"),
                "selection_reasons": item.get("selection_reasons"),
            }
            for item in records
            if item.get("selected_for_characteristic_analysis") is True
        ],
        "decompilation_artifact": "decompilations.raw.jsonl",
        "cil_artifact": "cil-instructions.raw.jsonl" if cil_records else None,
        "sample_executed": False,
        "network_contacted": False,
    }
    _json_dump(output_dir / "ghidra-raw-index.json", raw_index)
    result = {
        "schema_version": SCHEMA_VERSION,
        "status": "complete",
        "mcp_responses_valid": True,
        "sha256": item.sha256,
        "size": item.size,
        "program_selector": program,
        "metadata": _parse_metadata(metadata_raw),
        "relationships": item.relationships,
        "functions": records,
        "function_inventory_count": len(records),
        "ghidra_function_inventory_count": len(functions),
        "managed_method_count": len(cil_records),
        "characteristic_function_ids": selected_ids,
        "characteristic_function_count": len(selected_ids),
        "call_graph": call_graph,
        "entry_points": entry_points,
        "imports": imports,
        "exports": exports,
        "segments": segments,
        "anti_analysis": anti_analysis,
        "api_call_chains": api_chains,
        "opcode_hashes": opcode_hashes,
        "safety": {
            "sample_executed": False,
            "network_contacted": False,
            "arbitrary_ghidra_scripts_enabled": False,
            "raw_results_private": True,
        },
    }
    ensure_characteristic_selection(result)
    _json_dump(result_path, result)
    try:
        client.get("/save_all_programs")
        client.post("/close_program", {"name": program})
    except GhidraMcpError:
        pass
    return result


def refresh_complete_program_artifacts(
    client: GhidraMcpClient,
    program_results: Mapping[str, dict[str, Any]],
    private_output: Path,
) -> dict[str, int]:
    """全programのページング対象を終端まで再取得し、生成果物へ保存する。"""

    totals: Counter[str] = Counter()
    endpoints = {
        "imports": "/list_imports",
        "exports": "/list_exports",
        "strings": "/list_strings",
        "segments": "/list_segments",
    }
    for index, (digest, result) in enumerate(sorted(program_results.items()), start=1):
        program = _safe_project_path(str(result.get("program_selector") or ""))
        opened = client.get("/open_program", path=program, auto_analyze=False)
        opened_program = _safe_project_path(str((opened or {}).get("path") or program))
        if opened_program != program:
            raise GhidraMcpError(
                f"完全取得時のprogram selectorが一致しません: {opened_program} != {program}"
            )
        retrieved: dict[str, list[Any]] = {}
        coverage: dict[str, dict[str, Any]] = {}
        for name, endpoint in endpoints.items():
            items, endpoint_coverage = _all_endpoint_items(client, endpoint, program)
            retrieved[name] = items
            coverage[name] = endpoint_coverage
            totals[name] += len(items)
        object_dir = private_output / "objects" / digest
        raw_index_path = object_dir / "ghidra-raw-index.json"
        raw_index = json.loads(raw_index_path.read_text(encoding="utf-8-sig"))
        opcode_hashes = _complete_opcode_hash_inventory(
            raw_index.get("opcode_hashes") if isinstance(raw_index, Mapping) else {},
            [item for item in raw_index.get("functions", []) if isinstance(item, Mapping)],
            program,
        )
        raw_index["opcode_hashes"] = opcode_hashes
        result["opcode_hashes"] = opcode_hashes
        for name, items in retrieved.items():
            raw_index[name] = items
        raw_index["retrieval_coverage"] = coverage
        raw_index["all_static_analysis_content_retained"] = True
        result["imports"] = retrieved["imports"]
        result["exports"] = retrieved["exports"]
        result["segments"] = retrieved["segments"]
        result["retrieval_coverage"] = coverage
        result["all_static_analysis_content_retained"] = True
        _json_dump(raw_index_path, raw_index)
        _json_dump(object_dir / "program-result.json", result)
        try:
            client.post("/close_program", {"name": program})
        except GhidraMcpError:
            pass
        totals["programs"] += 1
        print(
            json.dumps(
                {
                    "phase": "complete_static_artifact_refresh",
                    "program": index,
                    "total": len(program_results),
                    "sha256": digest,
                    "counts": {name: len(items) for name, items in retrieved.items()},
                    "executed": False,
                },
                ensure_ascii=False,
            ),
            flush=True,
        )
    return dict(totals)


def _read_jsonl_rows(path: Path) -> list[dict[str, Any]]:
    """JSONLを欠損行も検出できる形で読み込む。"""

    rows: list[dict[str, Any]] = []
    if not path.is_file():
        return rows
    for line_number, line in enumerate(
        path.read_text(encoding="utf-8-sig").splitlines(),
        start=1,
    ):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as error:
            rows.append(
                {
                    "_invalid_json_line": line_number,
                    "_error": str(error),
                }
            )
            continue
        if isinstance(value, dict):
            rows.append(value)
        else:
            rows.append(
                {
                    "_invalid_json_line": line_number,
                    "_error": "JSON objectではありません",
                }
            )
    return rows


CALL_EXPRESSION_RE = re.compile(r"(?<![\w])([A-Za-z_?$][A-Za-z0-9_.$@?<>:-]*)\s*\(")
IGNORED_CALL_EXPRESSIONS = {
    "if",
    "for",
    "while",
    "switch",
    "return",
    "sizeof",
    "typeof",
    "catch",
}


def augment_program_result_call_graph(result: dict[str, Any]) -> dict[str, int]:
    """逆コンパイルcall式でGhidra call graphの欠落を補完する。"""

    records = [
        item
        for item in result.get("functions", [])
        if isinstance(item, dict) and item.get("analysis_kind") == "ghidra_native_or_loader_view"
    ]
    name_to_records: dict[str, list[dict[str, Any]]] = defaultdict(list)
    address_to_record: dict[str, dict[str, Any]] = {}
    for record in records:
        name_to_records[str(record.get("name") or "").casefold()].append(record)
        address_to_record[str(record.get("address") or "")] = record
    import_by_name = {
        str(item.get("name") or "").casefold(): dict(item)
        for item in result.get("imports", [])
        if isinstance(item, Mapping) and item.get("name")
    }
    ghidra_graph = result.get("ghidra_call_graph")
    if not isinstance(ghidra_graph, Mapping):
        current = result.get("call_graph")
        ghidra_graph = dict(current) if isinstance(current, Mapping) else {"edges": []}
        result["ghidra_call_graph"] = ghidra_graph
    edges: dict[tuple[str, str, str], dict[str, Any]] = {}
    for value in ghidra_graph.get("edges", []):
        if not isinstance(value, Mapping):
            continue
        edge = dict(value)
        edge.setdefault("source", "ghidra_full_call_graph")
        key = (
            str(edge.get("caller_addr") or ""),
            str(edge.get("callee_addr") or ""),
            str(edge.get("callee_name") or ""),
        )
        edges[key] = edge
    for record in records:
        caller_addr = str(record.get("address") or "")
        caller_name = str(record.get("name") or "")
        pseudocode = str(record.get("pseudocode") or "")
        for call_name in CALL_EXPRESSION_RE.findall(pseudocode):
            lowered = call_name.casefold()
            if lowered in IGNORED_CALL_EXPRESSIONS or lowered == caller_name.casefold():
                continue
            candidates = name_to_records.get(lowered, [])
            if len(candidates) == 1:
                callee = candidates[0]
                callee_addr = str(callee.get("address") or "")
                edge = {
                    "caller_addr": caller_addr,
                    "caller_name": caller_name,
                    "callee_addr": callee_addr,
                    "callee_name": str(callee.get("name") or call_name),
                    "edge_kind": "internal",
                    "source": "decompiler_call_expression",
                    "unresolved": False,
                }
            elif lowered in import_by_name:
                imported = import_by_name[lowered]
                edge = {
                    "caller_addr": caller_addr,
                    "caller_name": caller_name,
                    "callee_addr": str(imported.get("address") or ""),
                    "callee_name": str(imported.get("name") or call_name),
                    "edge_kind": "import",
                    "source": "decompiler_call_expression",
                    "unresolved": False,
                }
            else:
                edge = {
                    "caller_addr": caller_addr,
                    "caller_name": caller_name,
                    "callee_addr": "",
                    "callee_name": call_name,
                    "edge_kind": "unresolved",
                    "source": "decompiler_call_expression",
                    "unresolved": True,
                }
            key = (
                str(edge["caller_addr"]),
                str(edge["callee_addr"]),
                str(edge["callee_name"]),
            )
            edges.setdefault(key, edge)
    sorted_edges = [edges[key] for key in sorted(edges, key=lambda value: tuple(part.casefold() for part in value))]
    callers: dict[str, set[str]] = defaultdict(set)
    callees: dict[str, set[str]] = defaultdict(set)
    api_calls: dict[str, set[str]] = defaultdict(set)
    for edge in sorted_edges:
        caller_addr = str(edge.get("caller_addr") or "")
        callee_addr = str(edge.get("callee_addr") or "")
        callee_name = str(edge.get("callee_name") or callee_addr)
        if callee_addr in address_to_record:
            callee_id = str(address_to_record[callee_addr].get("function_id") or callee_addr)
            caller_id = str(address_to_record.get(caller_addr, {}).get("function_id") or caller_addr)
            callees[caller_addr].add(callee_id)
            callers[callee_addr].add(caller_id)
        elif callee_name:
            callees[caller_addr].add(callee_name)
            if str(edge.get("edge_kind") or "") == "import":
                api_calls[caller_addr].add(callee_name)
    for record in records:
        address = str(record.get("address") or "")
        record["callers"] = sorted(callers[address])
        record["callees"] = sorted(callees[address])
        record["api_calls"] = sorted(api_calls[address])
    source_counts = Counter(str(edge.get("source") or "unknown") for edge in sorted_edges)
    result["call_graph"] = {
        "edge_count": len(sorted_edges),
        "caller_count": len({str(edge.get("caller_addr") or "") for edge in sorted_edges}),
        "edges": sorted_edges,
        "source_counts": dict(sorted(source_counts.items())),
    }
    result["call_graph_augmented_from_decompilation"] = True
    return {
        "edges": len(sorted_edges),
        "ghidra_edges": sum(edge.get("source") == "ghidra_full_call_graph" for edge in sorted_edges),
        "internal_edges": sum(edge.get("edge_kind") == "internal" for edge in sorted_edges),
        "import_edges": sum(edge.get("edge_kind") == "import" for edge in sorted_edges),
        "unresolved_edges": sum(edge.get("edge_kind") == "unresolved" for edge in sorted_edges),
    }


def augment_private_call_graphs(
    program_results: Mapping[str, dict[str, Any]],
    private_output: Path,
) -> dict[str, int]:
    """全programのcall graphを補完し、private成果物へ永続化する。"""

    totals: Counter[str] = Counter()
    for digest, result in sorted(program_results.items()):
        counts = augment_program_result_call_graph(result)
        selected_ids = ensure_characteristic_selection(result)
        totals.update(counts)
        totals["characteristic_functions"] += len(selected_ids)
        object_dir = private_output / "objects" / digest
        raw_index_path = object_dir / "ghidra-raw-index.json"
        raw_index = json.loads(raw_index_path.read_text(encoding="utf-8-sig"))
        if "ghidra_call_graph" not in raw_index:
            raw_index["ghidra_call_graph"] = raw_index.get("call_graph", {"edges": []})
        raw_index["call_graph"] = result["call_graph"]
        raw_index["call_graph_augmented_from_decompilation"] = True
        raw_index["characteristic_function_ids"] = selected_ids
        raw_index["characteristic_function_count"] = len(selected_ids)
        raw_index["characteristic_selection"] = [
            {
                "function_id": item.get("function_id"),
                "address_or_token": item.get("address") or item.get("token"),
                "role": item.get("role"),
                "selection_score": item.get("selection_score"),
                "selection_reasons": item.get("selection_reasons"),
            }
            for item in result.get("functions", [])
            if isinstance(item, Mapping)
            and item.get("selected_for_characteristic_analysis") is True
        ]
        _json_dump(raw_index_path, raw_index)
        _json_dump(object_dir / "program-result.json", result)
        totals["programs"] += 1
    return dict(totals)


def validate_private_artifacts(
    program_results: Mapping[str, Mapping[str, Any]],
    private_output: Path,
    *,
    expected_program_count: int | None = None,
) -> dict[str, Any]:
    """全programのinventoryと代表関数解析成果物が欠落なく保存されたか検証する。"""

    required_raw_keys = {
        "metadata",
        "analysis_status",
        "functions",
        "call_graph",
        "imports",
        "exports",
        "strings",
        "segments",
        "entry_points",
        "anti_analysis",
        "api_call_chains",
        "opcode_hashes",
        "retrieval_coverage",
        "characteristic_function_ids",
        "characteristic_selection",
    }
    programs: list[dict[str, Any]] = []
    totals: Counter[str] = Counter()
    for digest, result in sorted(program_results.items()):
        errors: list[str] = []
        object_dir = private_output / "objects" / digest
        result_path = object_dir / "program-result.json"
        raw_index_path = object_dir / "ghidra-raw-index.json"
        decompilation_path = object_dir / "decompilations.raw.jsonl"
        cil_path = object_dir / "cil-instructions.raw.jsonl"
        if result.get("call_graph_augmented_from_decompilation") is not True:
            errors.append("逆コンパイルcall式によるcall graph補完証跡がありません")
        if result.get("mcp_responses_valid") is not True:
            errors.append("MCP成功証跡がありません")
        if result.get("all_static_analysis_content_retained") is not True:
            errors.append("全静的解析内容の保持証跡がありません")
        if str(result.get("sha256") or "").casefold() != digest.casefold():
            errors.append("program-resultのSHA-256が対象と一致しません")
        if not result_path.is_file():
            errors.append("program-result.jsonがありません")
        try:
            raw_index = json.loads(raw_index_path.read_text(encoding="utf-8-sig"))
        except (OSError, json.JSONDecodeError) as error:
            raw_index = {}
            errors.append(f"ghidra-raw-index.jsonを読めません: {type(error).__name__}")
        if isinstance(raw_index, Mapping):
            missing_raw_keys = sorted(required_raw_keys - set(raw_index))
            if missing_raw_keys:
                errors.append("Ghidra raw項目が不足しています: " + ", ".join(missing_raw_keys))
            if raw_index.get("program_selector") != result.get("program_selector"):
                errors.append("raw indexとprogram-resultのprogram selectorが一致しません")
        else:
            raw_index = {}
            errors.append("ghidra-raw-index.jsonがJSON objectではありません")

        retrieval_coverage = raw_index.get("retrieval_coverage", {})
        if result.get("retrieval_coverage") != retrieval_coverage:
            errors.append("raw indexとprogram-resultのページング取得証跡が一致しません")
        if raw_index.get("all_static_analysis_content_retained") is not True:
            errors.append("raw indexに全静的解析内容の保持証跡がありません")
        if not isinstance(retrieval_coverage, Mapping):
            errors.append("ページング取得証跡がJSON objectではありません")
            retrieval_coverage = {}
        for name in ("imports", "exports", "strings", "segments"):
            evidence = retrieval_coverage.get(name)
            values = raw_index.get(name)
            if not isinstance(evidence, Mapping):
                errors.append(f"{name}: ページング取得証跡がありません")
                continue
            if evidence.get("complete") is not True or evidence.get("terminal_short_page_observed") is not True:
                errors.append(f"{name}: 終端までの完全取得証跡がありません")
            if evidence.get("program_selector") != result.get("program_selector"):
                errors.append(f"{name}: ページング取得時のprogram selectorが一致しません")
            if not isinstance(values, list):
                errors.append(f"{name}: raw内容がlistではありません")
            elif int(evidence.get("item_count") or 0) != len(values):
                errors.append(f"{name}: 取得件数と保存件数が一致しません")
            totals[f"{name}_items"] += len(values) if isinstance(values, list) else 0
            if name != "strings" and result.get(name) != values:
                errors.append(f"{name}: raw indexとprogram-resultの保存内容が一致しません")

        raw_functions = [item for item in raw_index.get("functions", []) if isinstance(item, Mapping)]
        native_records = [
            item
            for item in result.get("functions", [])
            if isinstance(item, Mapping) and item.get("analysis_kind") == "ghidra_native_or_loader_view"
        ]
        managed_records = [
            item
            for item in result.get("functions", [])
            if isinstance(item, Mapping) and item.get("analysis_kind") == "managed_cil"
        ]
        selected_ids = {
            str(value) for value in result.get("characteristic_function_ids", []) if value
        }
        raw_selected_ids = {
            str(value) for value in raw_index.get("characteristic_function_ids", []) if value
        }
        if selected_ids != raw_selected_ids:
            errors.append("代表関数IDがraw indexとprogram-resultで一致しません")
        record_ids = {
            str(item.get("function_id"))
            for item in result.get("functions", [])
            if isinstance(item, Mapping) and item.get("function_id")
        }
        eligible_count = sum(
            not bool(item.get("isExternal")) and not bool(item.get("isThunk"))
            for item in raw_functions
        ) + sum(
            item.get("decompilation_status") != "no_managed_body"
            for item in managed_records
        )
        if eligible_count and not selected_ids:
            errors.append("解析可能な関数があるのに代表関数が選定されていません")
        if selected_ids - record_ids:
            errors.append("代表関数IDに対応する関数recordがありません")
        selected_native_addresses = {
            str(item.get("address"))
            for item in native_records
            if item.get("address")
            and item.get("selected_for_characteristic_analysis") is True
            and item.get("decompilation_status") != "excluded_external_or_thunk"
        }
        for item in result.get("functions", []):
            if not isinstance(item, Mapping) or item.get("selected_for_characteristic_analysis") is not True:
                continue
            if not item.get("selection_reasons"):
                errors.append(f"{item.get('function_id')}: 代表関数の選定理由がありません")
        decompilation_rows = _read_jsonl_rows(decompilation_path)
        invalid_decompilation_lines = [row for row in decompilation_rows if "_invalid_json_line" in row]
        if invalid_decompilation_lines:
            errors.append(f"逆コンパイルJSONLに不正行があります: {len(invalid_decompilation_lines)}")
        decompilation_by_address = {str(row.get("address")): row for row in decompilation_rows if row.get("address")}
        missing_addresses = sorted(selected_native_addresses - set(decompilation_by_address))
        if missing_addresses:
            errors.append(f"逆コンパイル行がない代表関数があります: {len(missing_addresses)}")
        for address in sorted(selected_native_addresses & set(decompilation_by_address)):
            row = decompilation_by_address[address]
            if "pseudocode" not in row:
                errors.append(f"{address}: 逆コンパイル本文fieldがありません")
            if str(row.get("status") or "") in {
                "",
                "unknown",
                "failed_not_attempted",
            }:
                errors.append(f"{address}: 逆コンパイル試行状態が不正です")
            if row.get("program_selector") != result.get("program_selector"):
                errors.append(f"{address}: program selectorが一致しません")

        if len(native_records) != len(raw_functions):
            errors.append(
                f"Ghidra関数inventoryと公開元record数が一致しません: {len(raw_functions)} != {len(native_records)}"
            )
        if int(result.get("ghidra_function_inventory_count") or 0) != len(raw_functions):
            errors.append("Ghidra関数inventory countが一致しません")
        if int(result.get("managed_method_count") or 0) != len(managed_records):
            errors.append("managed method inventory countが一致しません")
        if int(result.get("function_inventory_count") or 0) != len(native_records + managed_records):
            errors.append("全関数inventory countが一致しません")
        opcode_hashes = raw_index.get("opcode_hashes")
        if not isinstance(opcode_hashes, Mapping):
            errors.append("opcode hash成果物がJSON objectではありません")
        else:
            opcode_functions = [
                item for item in opcode_hashes.get("functions", []) if isinstance(item, Mapping)
            ]
            if int(opcode_hashes.get("returned") or 0) != len(opcode_functions):
                errors.append("opcode hashのreturned件数と保存件数が一致しません")
            if int(opcode_hashes.get("total_matching") or 0) != len(raw_functions):
                errors.append("opcode hashの対象関数数とGhidra関数inventoryが一致しません")
            if len(opcode_functions) != len(raw_functions):
                errors.append("全Ghidra関数のopcode hash状態recordがありません")
            if opcode_hashes.get("all_functions_recorded") is not True:
                errors.append("全関数opcode hash inventoryの完了証跡がありません")
            for item in opcode_functions:
                if item.get("hash_status") not in {"available", "unavailable_recorded"}:
                    errors.append("opcode hash状態が未記録の関数があります")
                    break
                if item.get("program_selector") != result.get("program_selector"):
                    errors.append("opcode hash recordのprogram selectorが一致しません")
                    break

        cil_body_tokens = {
            str(item.get("token"))
            for item in managed_records
            if item.get("token")
            and item.get("selected_for_characteristic_analysis") is True
            and item.get("decompilation_status") != "no_managed_body"
        }
        cil_rows = _read_jsonl_rows(cil_path)
        invalid_cil_lines = [row for row in cil_rows if "_invalid_json_line" in row]
        if invalid_cil_lines:
            errors.append(f"CIL JSONLに不正行があります: {len(invalid_cil_lines)}")
        cil_tokens = {str(row.get("token")) for row in cil_rows if row.get("token")}
        missing_cil_tokens = sorted(cil_body_tokens - cil_tokens)
        if missing_cil_tokens:
            errors.append(f"CIL命令列がないmethodがあります: {len(missing_cil_tokens)}")
        for row in cil_rows:
            if row.get("token") and "instructions" not in row:
                errors.append(f"{row['token']}: CIL instructions fieldがありません")

        totals["programs"] += 1
        totals["native_functions"] += len(raw_functions)
        totals["characteristic_native_decompilations"] += len(selected_native_addresses)
        totals["managed_methods"] += len(managed_records)
        totals["managed_method_bodies"] += len(cil_body_tokens)
        programs.append(
            {
                "sha256": digest,
                "valid": not errors,
                "errors": errors,
                "native_function_count": len(raw_functions),
                "characteristic_native_decompilation_count": len(selected_native_addresses),
                "managed_method_count": len(managed_records),
                "managed_method_body_count": len(cil_body_tokens),
                "artifacts": {
                    "program_result": str(result_path),
                    "ghidra_raw_index": str(raw_index_path),
                    "decompilations": str(decompilation_path),
                    "cil_instructions": str(cil_path) if cil_body_tokens else None,
                },
            }
        )
    global_errors = []
    if not programs:
        global_errors.append("検証対象programがありません")
    if expected_program_count is not None and len(programs) != expected_program_count:
        global_errors.append(f"program数が期待値と一致しません: {len(programs)} != {expected_program_count}")
    output = {
        "schema_version": SCHEMA_VERSION,
        "complete": not global_errors and all(item["valid"] for item in programs),
        "global_errors": global_errors,
        "valid_programs": sum(item["valid"] for item in programs),
        "invalid_programs": sum(not item["valid"] for item in programs),
        "totals": dict(totals),
        "programs": programs,
    }
    _json_dump(private_output / "private-artifact-validation.json", output)
    return output


def _program_evidence(result: Mapping[str, Any]) -> dict[str, Any]:
    metadata = result.get("metadata", {})
    entries = []
    raw_entries = result.get("entry_points")
    if isinstance(raw_entries, str):
        for line in raw_entries.splitlines():
            match = re.match(r"\s*(.+?)\s*[-=]>\s*([0-9a-fA-F:]+)", line)
            if not match:
                match = re.match(r"\s*(.+?)\s+@\s+([0-9a-fA-F:]+)", line)
            if match:
                entries.append(
                    {
                        "name": match.group(1),
                        "address": match.group(2),
                        "kind": "entry_point",
                    }
                )
    hashes = [
        item
        for item in (result.get("opcode_hashes", {}) or {}).get("functions", [])
        if isinstance(item, Mapping)
        and int(item.get("instruction_count") or 0) > 0
        and str(item.get("hash") or "") != EMPTY_SHA256
    ]
    imports = []
    for item in result.get("imports", []):
        if isinstance(item, Mapping):
            name = str(item.get("name") or item.get("symbol") or "").strip()
        else:
            name = str(item).strip()
        if name:
            imports.append(redact_static_text(name))
    return {
        "program_id": f"sha256:{result['sha256']}",
        "program_selector": result["program_selector"],
        "relationship": (
            "root_program"
            if any(int(item["depth"]) == 0 for item in result.get("relationships", []))
            else "statically_recovered_program"
        ),
        "name": str(result["sha256"]),
        "architecture": str(metadata.get("architecture") or "unknown"),
        "compiler": str(metadata.get("compiler") or "unknown"),
        "language": str(metadata.get("language") or "unknown"),
        "endian": str(metadata.get("endian") or "unknown"),
        "address_size": str(metadata.get("address_size") or "unknown"),
        "base_address": str(metadata.get("base_address") or "unknown"),
        "memory_blocks": int(re.search(r"\d+", str(metadata.get("memory_blocks") or "0")).group())
        if re.search(r"\d+", str(metadata.get("memory_blocks") or "0"))
        else 0,
        "total_memory_size": int(re.search(r"\d+", str(metadata.get("total_memory_size") or "0")).group())
        if re.search(r"\d+", str(metadata.get("total_memory_size") or "0"))
        else 0,
        "function_count": int(result.get("characteristic_function_count") or 0),
        "ghidra_function_count": int(result.get("ghidra_function_inventory_count") or 0),
        "managed_method_count": int(result.get("managed_method_count") or 0),
        "mcp_responses_valid": result.get("mcp_responses_valid") is True,
        "symbol_count": int(re.search(r"\d+", str(metadata.get("symbol_count") or "0")).group())
        if re.search(r"\d+", str(metadata.get("symbol_count") or "0"))
        else 0,
        "entry_points": entries,
        "imports": imports,
        "retrieval_coverage": dict(result.get("retrieval_coverage") or {}),
        "function_hashes": hashes,
        "function_hash_coverage": {
            "total_functions": len([item for item in result.get("functions", []) if isinstance(item, Mapping)]),
            "valid_opcode_hashes": len(hashes),
            "all_functions_requested": True,
        },
        "confidence": "confirmed_program_structure",
    }


def _build_overall_logic(report: Mapping[str, Any]) -> dict[str, Any]:
    """代表関数と観測call edgeから検体全体の処理像を構成する。"""

    functions = [item for item in report.get("functions", []) if isinstance(item, Mapping)]
    programs = [
        item for item in report.get("program_evidence", []) if isinstance(item, Mapping)
    ]
    phase_descriptions = {
        "startup": "entry pointから初期化と後続処理への移行を確認します。",
        "configuration": "設定、resource、payload、暗号化データの復元・変換を確認します。",
        "evasion": "debugger、sandbox、仮想環境、時間差などの判定を確認します。",
        "persistence": "自動起動や永続化に関係する設定変更を確認します。",
        "execution": "process、thread、module、memory操作と実行移行を確認します。",
        "communication": "通信初期化、endpoint処理、送受信の役割を確認します。",
        "dispatch": "受信commandやtaskの解釈、分配、個別handlerへの移行を確認します。",
        "file_activity": "fileやdirectoryの作成、読書き、削除を確認します。",
        "support": "主要処理を支える一般内部関数またはlibrary処理を確認します。",
    }
    phases = []
    phase_by_function: dict[str, str] = {}
    for phase_id, title, roles in CHARACTERISTIC_PHASES:
        matched = [item for item in functions if str(item.get("role") or "") in roles]
        if not matched:
            continue
        function_ids = [str(item.get("function_id") or "") for item in matched]
        for function_id in function_ids:
            phase_by_function[function_id] = phase_id
        constrained = any(
            str(item.get("function_analysis", {}).get("decompilation_status") or "") != "succeeded"
            for item in matched
        )
        phases.append(
            {
                "phase_id": phase_id,
                "title_ja": title,
                "description_ja": phase_descriptions[phase_id],
                "function_ids": function_ids,
                "roles": sorted({str(item.get("role") or "unknown") for item in matched}),
                "confidence": (
                    "confirmed_static_function_evidence_with_limits"
                    if constrained
                    else "confirmed_static_function_evidence"
                ),
            }
        )
    if not phases and functions:
        function_ids = [str(item.get("function_id") or "") for item in functions]
        phases.append(
            {
                "phase_id": "support",
                "title_ja": "分類未確定の代表関数",
                "description_ja": (
                    "代表関数は取得できましたが、静的証跡だけでは主要な処理段階へ"
                    "自動分類できませんでした。"
                ),
                "function_ids": function_ids,
                "roles": sorted(
                    {str(item.get("role") or "unclassified") for item in functions}
                ),
                "confidence": "confirmed_static_function_evidence_with_classification_limit",
            }
        )
        phase_by_function.update(
            {function_id: "support" for function_id in function_ids}
        )
    if not phases:
        entry_point_count = sum(
            len(item.get("entry_points") or []) for item in programs
        )
        import_names: set[str] = set()
        for item in programs:
            for value in item.get("imports", []):
                if isinstance(value, Mapping):
                    name = str(value.get("name") or value.get("symbol") or "")
                else:
                    name = str(value)
                if name.strip():
                    import_names.add(name.strip())
        imports = sorted(import_names)
        phases.append(
            {
                "phase_id": "program_structure",
                "title_ja": "program構造限定解析",
                "description_ja": (
                    f"Ghidra MCPで{len(programs)}個のprogram、"
                    f"{entry_point_count}件のentry point、{len(imports)}件のimportを"
                    "確認しましたが、解析可能な関数本体は認識されませんでした。"
                ),
                "function_ids": [],
                "roles": ["program_structure_without_function_body"],
                "confidence": "confirmed_program_structure_with_function_recovery_limit",
            }
        )
        for phase_id, title, roles in CHARACTERISTIC_PHASES:
            pattern = IMPORT_CAPABILITY_PATTERNS.get(phase_id)
            if pattern is None:
                continue
            hits = [name for name in imports if pattern.search(name)]
            if not hits:
                continue
            phases.append(
                {
                    "phase_id": f"import_capability_{phase_id}",
                    "title_ja": f"import上の能力候補：{title}",
                    "description_ja": (
                        "import表に関連APIが存在します。能力候補を示す証跡であり、"
                        "実行経路や悪性動作の成立を単独では証明しません。"
                    ),
                    "function_ids": [],
                    "roles": sorted(roles),
                    "import_evidence": hits[:64],
                    "confidence": "confirmed_import_presence_not_execution",
                }
            )
    observed_edges = []
    for edge in report.get("call_edges", []):
        if not isinstance(edge, Mapping):
            continue
        caller = str(edge.get("caller") or "")
        callee = str(edge.get("callee") or "")
        observed_edges.append(
            {
                "caller": caller,
                "callee": callee,
                "caller_phase": phase_by_function.get(caller, "unclassified"),
                "callee_phase": phase_by_function.get(callee, "unclassified"),
                "confidence": "confirmed_static_call_relationship",
            }
        )
    active_titles = [str(item["title_ja"]) for item in phases if item["phase_id"] != "support"]
    if not functions:
        capability_titles = [
            str(item["title_ja"]).removeprefix("import上の能力候補：")
            for item in phases
            if str(item.get("phase_id") or "").startswith("import_capability_")
        ]
        summary = (
            "Ghidra MCPでprogram構造を取得しましたが、解析可能な関数本体は"
            "認識されなかったため、関数ロジックを断定せず構造限定結果を記録します。"
        )
        if capability_titles:
            summary += (
                " import表から、"
                + "、".join(capability_titles)
                + "に関連する能力候補を整理しました。"
            )
    elif active_titles:
        summary = (
            "代表関数の静的証跡から、"
            + "、".join(active_titles)
            + "の処理群を確認しました。"
        )
    else:
        summary = "代表関数から主要なmalware処理段階を自動分類できませんでした。"
    limitations = [
        "選定外関数は全体inventoryへ残しますが、関数本体の個別解説対象にはしていません。",
        "indirect call、難読化、packer、VM、壊れたcontrol flowによりcall関係が欠落する場合があります。",
        "文書は静的解析に基づき、検体実行や外部通信による動的確認は行っていません。",
    ]
    if not functions:
        limitations.insert(
            0,
            "Ghidraで関数本体を認識できなかったため、entry point、import、export、segment等のprogram構造だけを確認しています。",
        )
    return {
        "schema_version": 1,
        "summary_ja": summary,
        "phase_order_basis": (
            "phaseの掲載順は解析上の整理順です。observed_call_edgesがない段階間の実行順を断定しません。"
        ),
        "phases": phases,
        "observed_call_edges": observed_edges,
        "selected_function_count": len(functions),
        "selection_dimensions": [
            "entry point",
            "malware固有の役割",
            "call graph中心性",
            "関数規模",
            "symbol名の情報量",
        ],
        "limitations_ja": limitations,
    }


def _markdown_code_value(value: Any) -> str:
    """識別子を内容を変えずMarkdownの1行code表示へ整える。"""

    rendered = re.sub(r"\s+", " ", redact_static_text(str(value))).strip()
    return rendered.replace("`", "'") or "未記録"


def _render_overall_logic(report: Mapping[str, Any]) -> str:
    """全体ロジックを日本語の独立文書へ描画する。"""

    overall = report.get("overall_logic", {})
    functions = {
        str(item.get("function_id") or ""): item
        for item in report.get("functions", [])
        if isinstance(item, Mapping)
    }
    lines = [
        f"# 全体ロジック：{report['sha256']}",
        "",
        str(overall.get("summary_ja") or "全体ロジックを構成できませんでした。"),
        "",
        "## 読み方",
        "",
        f"- {overall.get('phase_order_basis', '')}",
        "- 詳細な関数解説とfingerprintは[STATIC-LOGIC.md](STATIC-LOGIC.md)を参照してください。",
        "",
        "## 処理段階",
        "",
    ]
    for index, phase in enumerate(overall.get("phases", []), start=1):
        lines.extend(
            [
                f"### {index}. {phase['title_ja']}",
                "",
                str(phase["description_ja"]),
                f"確度: `{phase['confidence']}`",
                "",
            ]
        )
        for function_id in phase.get("function_ids", []):
            function = functions.get(str(function_id), {})
            analysis = function.get("function_analysis", {})
            reasons = function.get("selection", {}).get("reasons", [])
            lines.append(
                f"- `{function_id}` — {function.get('summary_ja', '要約なし')} "
                f"状態: `{analysis.get('decompilation_status', 'unknown')}`、"
                f"選定理由: {', '.join(f'`{value}`' for value in reasons) or '記録なし'}"
            )
        import_evidence = list(phase.get("import_evidence", []))
        if import_evidence:
            lines.append(
                "- import証跡: "
                + ", ".join(f"`{_markdown_code_value(value)}`" for value in import_evidence)
            )
        lines.append("")
    lines.extend(["## 観測したcall関係", ""])
    edges = list(overall.get("observed_call_edges", []))
    if not edges:
        lines.append("- 代表関数間で直接解決できた呼出関係はありません。")
    for edge in edges[:200]:
        lines.append(
            f"- `{edge['caller']}` → `{edge['callee']}` "
            f"（`{edge['caller_phase']}` → `{edge['callee_phase']}`）"
        )
    if len(edges) > 200:
        lines.append(f"- 残り{len(edges) - 200}件は`static-logic.json`に記録しています。")
    lines.extend(["", "## 解析範囲と制約", ""])
    lines.extend(f"- {value}" for value in overall.get("limitations_ja", []))
    lines.append("")
    return "\n".join(lines)

def _render_markdown(report: Mapping[str, Any]) -> str:
    coverage = report["coverage"]
    functions = list(report.get("functions", []))
    roles = Counter(str(item["role"]) for item in functions)
    failures = [
        item
        for item in functions
        if str(item.get("function_analysis", {}).get("decompilation_status", ""))
        not in {
            "succeeded",
            "no_managed_body",
            "excluded_external_or_thunk",
            "static_script_structure_recorded",
        }
    ]
    high_signal = functions
    lines = [
        f"# 静的ロジック解析：{report['sha256']}",
        "",
        "選定可能な代表関数の逆コンパイル／CIL解析、call関係、API参照、",
        "役割、処理順、fingerprint、選定理由を記録しました。機械可読結果は",
        "`static-logic.json`に保存し、生の逆コンパイル本文は公開していません。",
        "",
        "## 解析状態",
        "",
        f"- 状態: `{report['status']}`",
        f"- Ghidraプログラム: {coverage['ghidra_program_count']}",
        f"- 発見関数／メソッドinventory: {coverage['discovered_function_inventory_count']}",
        f"- 代表関数: {coverage['characteristic_function_selected_count']}",
        f"- Ghidra関数: {coverage['ghidra_function_inventory_count']}",
        f"- managedメソッド: {coverage['managed_method_inventory_count']}",
        f"- MCP成功証跡付きプログラム: {coverage['ghidra_programs_with_valid_mcp_responses']}",
        f"- 逆コンパイル／CIL解析試行: {coverage['decompilation_attempted_count']}",
        f"- 成功: {coverage['decompilation_succeeded_count']}",
        f"- 制約付き／失敗: {coverage['decompilation_limited_or_failed_count']}",
        f"- external／thunk／本体なし: {coverage['decompilation_excluded_count']}",
        f"- 呼出関係: {coverage['call_edge_count']}",
        "",
        "## プログラム取得範囲",
        "",
        "| プログラムselector | 関係 | 代表関数 | Ghidra inventory | CIL inventory | MCP | opcode hash |",
        "|---|---|---:|---:|---:|---|---:|",
    ]
    for program in report.get("program_evidence", []):
        lines.append(
            f"| `{program['program_selector']}` | `{program['relationship']}` | "
            f"{program['function_count']} | {program['ghidra_function_count']} | "
            f"{program['managed_method_count']} | "
            f"{'成功' if program['mcp_responses_valid'] else '失敗'} | "
            f"{len(program['function_hashes'])} |"
        )
    lines.extend(
        [
            "",
            "## 役割別集計",
            "",
            "| 役割 | 件数 |",
            "|---|---:|",
        ]
    )
    for role, count in sorted(roles.items(), key=lambda value: (-value[1], value[0])):
        lines.append(f"| `{role}` | {count} |")
    lines.extend(["", "## 重要関数", ""])
    if not high_signal:
        lines.append(
            "- Ghidraで解析可能な関数本体を認識できなかったため、"
            "program構造限定の解析結果を記録しました。"
        )
    for function in high_signal[:100]:
        analysis = function.get("function_analysis", {})
        lines.extend(
            [
                f"### `{function['function_id']}`",
                "",
                f"- 役割: `{function['role']}`",
                f"- アドレス／トークン: `{function['address_or_token']}`",
                f"- 状態: `{analysis.get('decompilation_status', 'unknown')}`",
                f"- 要約: {function['summary_ja']}",
                f"- 選定理由: {', '.join(f'`{_markdown_code_value(value)}`' for value in function.get('selection', {}).get('reasons', [])) or '記録なし'}",
                f"- 呼出元: {', '.join(f'`{_markdown_code_value(value)}`' for value in function['callers'][:16]) or 'なし'}",
                f"- 呼出先／API: {', '.join(f'`{_markdown_code_value(value)}`' for value in (function['callees'] + function['api_calls'])[:16]) or 'なし'}",
                "",
            ]
        )
        lines.extend(
            f"{index}. {_markdown_code_value(step)}"
            for index, step in enumerate(function.get("logic_steps_ja", []), start=1)
        )
        lines.append("")
    if len(high_signal) > 100:
        lines.append(f"- 残り{len(high_signal) - 100}件の代表関数は`static-logic.json`に記録しています。")
        lines.append("")
    lines.extend(["## 逆コンパイル制約", ""])
    if not functions:
        lines.append(
            "- 関数inventoryが0件のため逆コンパイル対象はありません。"
            "entry point、import、export、segment等の構造取得結果は保持しています。"
        )
    elif not failures:
        lines.append("- 制約付きまたは失敗として残った関数はありません。")
    for function in failures[:100]:
        analysis = function.get("function_analysis", {})
        lines.append(
            f"- `{function['function_id']}`: "
            f"`{analysis.get('decompilation_status', 'unknown')}`。"
            f"{analysis.get('next_analysis') or '追加解析方針はrecord内に記録しています。'}"
        )
    if len(failures) > 100:
        lines.append(f"- 残り{len(failures) - 100}件の制約は`static-logic.json`に記録しています。")
    lines.extend(
        [
            "",
            "## 安全境界",
            "",
            "- 検体、復元layer、CIL、逆コンパイル結果を実行またはemulateしていません。",
            "- 検体由来のnetwork endpointへ接続していません。",
            "- Ghidraの任意script実行は有効化していません。",
            "- 生の逆コンパイル本文とCIL命令列はリポジトリ外へ保持しています。",
            "",
        ]
    )
    return "\n".join(lines)


def _enrich_normalized_functions(
    report: dict[str, Any],
    source_records: Iterable[Mapping[str, Any]],
) -> None:
    source_by_id = {
        str(item["function_id"]): item
        for item in source_records
        if isinstance(item, Mapping) and item.get("function_id")
    }
    for function in report.get("functions", []):
        source = source_by_id.get(str(function["function_id"]), {})
        is_script = str(source.get("tool") or "") == "bounded_script_static_parser"
        function["function_analysis"] = {
            "analysis_kind": str(source.get("analysis_kind") or "unknown"),
            "source_program_sha256": str(source.get("source_program_sha256") or ""),
            "relationship": str(source.get("relationship") or ""),
            "decompilation_status": str(
                source.get("decompilation_status") or ("static_script_structure_recorded" if is_script else "unknown")
            ),
            "decompilation_warnings": [
                redact_static_text(str(value)) for value in source.get("decompilation_warnings", [])
            ],
            "decompilation_error": str(source.get("decompilation_error") or ""),
            "opcode_sha256": str(source.get("opcode_sha256") or ""),
            "instruction_count": int(source.get("instruction_count") or 0),
            "next_analysis": str(
                source.get("next_analysis")
                or ("必要に応じてscript ASTと難読化解除結果を手動確認します。" if is_script else "")
            ),
            "static_analysis_fields_retained": True,
            "source_field_counts": {
                "logic_steps": len(source.get("logic_steps_ja") or []),
                "callers": len(source.get("callers") or []),
                "callees": len(source.get("callees") or []),
                "api_calls": len(source.get("api_calls") or []),
                "constants": len(source.get("constants") or []),
                "decompilation_warnings": len(source.get("decompilation_warnings") or []),
            },
        }


def publish_cases(
    repository: Path,
    collection_dir: Path,
    program_results: Mapping[str, Mapping[str, Any]],
    non_pe: Mapping[str, list[dict[str, Any]]],
) -> dict[str, Any]:
    """対象caseの代表関数解析と全体ロジック成果物を更新する。"""

    case_paths = _case_index(repository)
    collection = json.loads((collection_dir / "manifest.json").read_text(encoding="utf-8-sig"))
    requested = [
        str(item["case_id"]).removeprefix("sha256:").casefold()
        for item in collection.get("cases", [])
    ]
    status_counts: Counter[str] = Counter()
    totals: Counter[str] = Counter()
    per_case: dict[str, dict[str, Any]] = {}
    mutable_results = {
        digest: dict(result) for digest, result in program_results.items()
    }
    for result in mutable_results.values():
        ensure_characteristic_selection(result)

    for case_sha in requested:
        related = [
            result
            for result in mutable_results.values()
            if any(str(item["case_sha256"]) == case_sha for item in result.get("relationships", []))
        ]
        if not related:
            raise ValueError(f"caseへ対応するGhidra programがありません: {case_sha}")
        invalid_mcp = [
            str(result.get("sha256") or "unknown")
            for result in related
            if result.get("mcp_responses_valid") is not True
        ]
        if invalid_mcp:
            raise ValueError(f"MCP成功証跡のないprogramを公開できません: {case_sha}: {invalid_mcp}")

        records: list[dict[str, Any]] = []
        for result in related:
            for function in result.get("functions", []):
                if not isinstance(function, Mapping):
                    continue
                if function.get("selected_for_characteristic_analysis") is not True:
                    continue
                record = dict(function)
                if record.get("analysis_kind") == "managed_cil":
                    record["program_selector"] = str(result["program_selector"])
                records.append(record)
        script_records: list[dict[str, Any]] = []
        for relation in non_pe.get(case_sha, []):
            for record in relation.get("script_function_records", []):
                if not isinstance(record, Mapping):
                    continue
                selected = dict(record)
                selected["selected_for_characteristic_analysis"] = True
                selected["selection_score"] = 1_000
                selected["selection_reasons"] = ["static_script_entry_or_function"]
                script_records.append(selected)
        records.extend(script_records)
        discovered_count = sum(
            int(result.get("function_inventory_count") or len(result.get("functions", [])))
            for result in related
        ) + len(script_records)
        if not records and discovered_count:
            raise ValueError(
                f"発見済み関数から代表関数を選定できないcaseです: {case_sha}"
            )
        structure_only = not records
        case_dir = case_paths[case_sha]
        metadata = json.loads((case_dir / "metadata.json").read_text(encoding="utf-8-sig"))
        report = build_static_logic_report(
            sha256=case_sha,
            family=str(metadata.get("family") or "unknown"),
            source_name=f"{case_sha}.quarantine.bin",
            records=records,
            program_evidence=[_program_evidence(result) for result in related],
            analysis_source="ghidra_mcp_characteristic_functions_and_managed_cil",
        )
        _enrich_normalized_functions(report, records)
        statuses = [
            function["function_analysis"]["decompilation_status"]
            for function in report["functions"]
        ]
        succeeded = sum(value == "succeeded" for value in statuses)
        excluded = sum(
            value in {
                "no_managed_body",
                "excluded_external_or_thunk",
                "static_script_structure_recorded",
            }
            for value in statuses
        )
        limited = len(statuses) - succeeded - excluded
        attempted = len(statuses) - excluded
        selected_count = len(statuses)
        unselected_count = max(0, discovered_count - selected_count)
        report["coverage"].update(
            {
                "function_inventory_count": selected_count,
                "discovered_function_inventory_count": discovered_count,
                "characteristic_function_selected_count": selected_count,
                "characteristic_function_analyzed_count": selected_count,
                "characteristic_function_attempted_count": attempted,
                "decompilation_attempted_count": attempted,
                "decompilation_succeeded_count": succeeded,
                "decompilation_limited_or_failed_count": limited,
                "decompilation_excluded_count": excluded,
                "unselected_function_count": unselected_count,
                "all_discovered_functions_inventoried": True,
                "all_characteristic_functions_attempted": True,
                "all_characteristic_functions_explained": True,
                "non_pe_recovered_layers_recorded": len(non_pe.get(case_sha, [])),
                "raw_private_artifacts_retained": True,
                "ghidra_function_inventory_count": sum(
                    int(result.get("ghidra_function_inventory_count") or 0)
                    for result in related
                ),
                "managed_method_inventory_count": sum(
                    int(result.get("managed_method_count") or 0)
                    for result in related
                ),
                "ghidra_programs_with_valid_mcp_responses": len(related),
            }
        )
        report["selection_policy"] = {
            "name": "role_entrypoint_callgraph_size_representatives",
            "maximum_per_program_and_analysis_kind": MAX_CHARACTERISTIC_FUNCTIONS_PER_PROGRAM,
            "dimensions": [
                "entry point",
                "malware固有の役割",
                "call graph中心性",
                "関数規模",
                "symbol名の情報量",
            ],
            "all_functions_decompilation_required": False,
            "unselected_scope_recorded": True,
        }
        report["retention"] = {
            "all_discovered_functions_in_public_result": False,
            "all_selected_functions_in_public_result": True,
            "all_selected_normalized_logic_in_public_result": True,
            "all_selected_call_relationships_in_public_result": True,
            "full_function_inventory_retained_private": True,
            "full_raw_ghidra_index_retained_private": True,
            "all_acquired_raw_decompilations_retained_private": True,
            "all_acquired_managed_cil_retained_private": True,
            "static_analysis_content_discarded": False,
            "public_sanitization_only": [
                "具体的なIOC",
                "資格情報",
                "token",
                "復号秘密値",
                "生の逆コンパイル本文",
            ],
        }
        report["coverage"]["all_static_analysis_content_retained"] = True
        report["status"] = (
            "characteristic_function_static_analysis_complete"
            if limited == 0 and not structure_only
            else "characteristic_function_static_analysis_complete_with_documented_limits"
        )
        report["limitations"] = [
            "全関数／methodのinventoryは保持し、入口・挙動役割・call graph中心性・規模から代表関数を選定しました。",
            "選定した代表関数はすべて逆コンパイル、CIL解析、または静的script構造解析を試行しました。",
            "選定外関数は個別解説の対象外であり、件数と選定方針を明示しています。",
            "packer、VM、破損CIL、indirect flowで不完全な代表関数は失敗理由と次の解析を関数recordへ残しました。",
            "fingerprint一致だけではファミリー、actor、campaignを確定しません。",
        ]
        if structure_only:
            report["limitations"].insert(
                0,
                "Ghidra MCPでprogram構造は取得しましたが、解析可能な関数本体を認識できなかったため構造限定解析としました。",
            )
        report["safety"].update(
            {
                "raw_pseudocode_retained_outside_repository": True,
                "arbitrary_ghidra_scripts_enabled": False,
            }
        )
        report["overall_logic"] = _build_overall_logic(report)
        _json_dump(case_dir / "static-logic.json", report)
        (case_dir / "STATIC-LOGIC.md").write_text(
            _render_markdown(report),
            encoding="utf-8",
        )
        (case_dir / "OVERALL-LOGIC.md").write_text(
            _render_overall_logic(report),
            encoding="utf-8",
        )

        analysis_path = case_dir / "analysis.json"
        analysis = json.loads(analysis_path.read_text(encoding="utf-8-sig"))
        analysis["case"]["declarative_status"] = report["status"]
        analysis["case"]["function_analysis"] = {
            key: report["coverage"][key]
            for key in (
                "discovered_function_inventory_count",
                "characteristic_function_selected_count",
                "characteristic_function_analyzed_count",
                "decompilation_attempted_count",
                "decompilation_succeeded_count",
                "decompilation_limited_or_failed_count",
                "ghidra_program_count",
                "ghidra_function_inventory_count",
                "managed_method_inventory_count",
                "ghidra_programs_with_valid_mcp_responses",
                "unselected_function_count",
            )
        }
        analysis["limitations"] = [
            value
            for value in analysis.get("limitations", [])
            if value
            not in {
                "関数本体未レビューのbinaryは完了扱いにしていない。",
                "関数単位の静的解析は完了し、復元不能箇所は理由と次の解析を記録した。",
            }
        ]
        analysis["limitations"].append(
            "代表関数の静的解析と全体ロジック整理を完了し、選定外範囲と制約を記録した。"
        )
        _json_dump(analysis_path, analysis)

        readme_path = case_dir / "README.md"
        readme = readme_path.read_text(encoding="utf-8-sig")
        readme = re.sub(
            r"(?m)^- 静的ロジック状態: `[^`]+`$",
            f"- 静的ロジック状態: `{report['status']}`",
            readme,
        )
        detail_line = (
            "特徴的な代表関数の選定理由・処理内容は[STATIC-LOGIC.md](STATIC-LOGIC.md)、"
            "検体全体の処理段階とcall関係は[OVERALL-LOGIC.md](OVERALL-LOGIC.md)を参照してください。"
        )
        readme = re.sub(
            r"(?m)^.*\[STATIC-LOGIC\.md\]\(STATIC-LOGIC\.md\)を参照してください。$",
            detail_line,
            readme,
        )
        if "[OVERALL-LOGIC.md](OVERALL-LOGIC.md)" not in readme:
            readme = readme.rstrip() + "\n\n" + detail_line + "\n"
        readme_path.write_text(readme, encoding="utf-8")

        status_counts[report["status"]] += 1
        totals["discovered_functions"] += discovered_count
        totals["characteristic_functions"] += selected_count
        totals["attempted"] += attempted
        totals["succeeded"] += succeeded
        totals["limited"] += limited
        totals["excluded"] += excluded
        totals["unselected"] += unselected_count
        totals["programs"] += len(related)
        totals["ghidra_functions"] += report["coverage"]["ghidra_function_inventory_count"]
        totals["managed_methods"] += report["coverage"]["managed_method_inventory_count"]
        totals["valid_mcp_programs"] += report["coverage"]["ghidra_programs_with_valid_mcp_responses"]
        per_case[case_sha] = {
            "status": report["status"],
            "coverage": report["coverage"],
        }

    summary_path = collection_dir / "publication-summary.json"
    summary = json.loads(summary_path.read_text(encoding="utf-8-sig"))
    summary["static_logic_status"] = dict(sorted(status_counts.items()))
    summary["function_analysis"] = {
        "root_cases": len(requested),
        "unique_pe_programs": len(program_results),
        "discovered_function_inventory_count": totals["discovered_functions"],
        "characteristic_function_selected_count": totals["characteristic_functions"],
        "characteristic_function_attempted_count": totals["attempted"],
        "decompilation_succeeded_count": totals["succeeded"],
        "decompilation_limited_or_failed_count": totals["limited"],
        "decompilation_excluded_count": totals["excluded"],
        "unselected_function_count": totals["unselected"],
        "all_characteristic_functions_attempted": True,
        "raw_private_artifacts_retained": True,
        "all_static_analysis_content_retained": True,
        "ghidra_function_inventory_count": totals["ghidra_functions"],
        "managed_method_inventory_count": totals["managed_methods"],
        "ghidra_programs_with_valid_mcp_responses": totals["valid_mcp_programs"],
    }
    for item in summary.get("cases", []):
        sha = str(item.get("sha256") or "").casefold()
        if sha in per_case:
            item["static_logic_status"] = per_case[sha]["status"]
            item["function_analysis"] = per_case[sha]["coverage"]
    _json_dump(summary_path, summary)

    readme_path = collection_dir / "README.md"
    readme = readme_path.read_text(encoding="utf-8-sig")
    replacement = [
        "## 静的ロジック状態",
        "",
        f"- 代表関数解析完了case: `{len(requested)}`",
        f"- Ghidra／CILプログラム: `{len(program_results)}`件の固有PE",
        f"- 発見関数／メソッドinventory: `{totals['discovered_functions']}`",
        f"- 代表関数: `{totals['characteristic_functions']}`",
        f"- 選定外関数: `{totals['unselected']}`",
        f"- Ghidra関数: `{totals['ghidra_functions']}`",
        f"- managedメソッド: `{totals['managed_methods']}`",
        f"- MCP成功証跡付きプログラム: `{totals['valid_mcp_programs']}`",
        f"- 逆コンパイル／CIL解析試行: `{totals['attempted']}`",
        f"- 成功: `{totals['succeeded']}`",
        f"- 制約付き／失敗: `{totals['limited']}`",
        "",
        "全関数inventoryを保持しつつ、特徴的な代表関数を選定して解析しました。",
        "各caseのSTATIC-LOGIC.mdに関数解説、OVERALL-LOGIC.mdに全体処理を記録しています。",
        "生の逆コンパイル本文とCIL命令列はリポジトリ外へ保持しています。",
        "",
    ]
    readme = re.sub(
        r"## 静的ロジック状態\n.*?(?=\n個別のPE構造)",
        "\n".join(replacement),
        readme,
        flags=re.DOTALL,
    )
    readme_path.write_text(readme, encoding="utf-8")
    return {
        "schema_version": SCHEMA_VERSION,
        "cases": len(requested),
        "status_counts": dict(status_counts),
        "totals": dict(totals),
    }

def run(args: argparse.Namespace) -> dict[str, Any]:
    """全入力を準備・解析・公開し、collection集計を返す。"""

    repository = args.repository.resolve()
    collection_dir = args.collection.resolve()
    sample_root = args.sample_root.resolve()
    private_output = args.private_output.resolve()
    if repository in private_output.parents or private_output == repository:
        raise ValueError("private outputはrepository外に置く必要があります")
    if not sample_root.is_dir() or not collection_dir.is_dir():
        raise FileNotFoundError("sample rootまたはcollection directoryが見つかりません")
    if os.environ.get("GHIDRA_MCP_ALLOW_SCRIPTS", "").strip().casefold() in {
        "1",
        "true",
        "yes",
        "on",
    }:
        raise RuntimeError("任意Ghidra script実行が有効な環境では処理を開始しません")
    client = GhidraMcpClient(args.mcp_url, timeout=args.request_timeout)
    if args.reuse_prepared_inputs:
        objects, non_pe = load_prepared_inputs(sample_root, private_output)
    else:
        objects, non_pe = prepare_inputs(
            repository,
            collection_dir,
            sample_root,
            private_output,
        )
    validate_prepared_scope(collection_dir, private_output)
    results: dict[str, dict[str, Any]] = {}
    ordered = sorted(objects.values(), key=lambda item: (item.size, item.sha256))
    for index, item in enumerate(ordered, start=1):
        print(
            json.dumps(
                {
                    "phase": "ghidra",
                    "program": index,
                    "total": len(ordered),
                    "sha256": item.sha256,
                    "size": item.size,
                },
                ensure_ascii=False,
            ),
            flush=True,
        )
        results[item.sha256] = analyze_program(
            client,
            item,
            private_output,
            args.project_root,
            analysis_timeout=args.analysis_timeout,
        )
    complete_artifact_refresh = refresh_complete_program_artifacts(
        client,
        results,
        private_output,
    )
    call_graph_augmentation = augment_private_call_graphs(results, private_output)
    private_validation = validate_private_artifacts(
        results,
        private_output,
        expected_program_count=len(objects),
    )
    if not private_validation["complete"]:
        raise RuntimeError(f"生の静的解析成果物に欠落があります: {private_validation['invalid_programs']}")
    publication = publish_cases(repository, collection_dir, results, non_pe)
    validation = validate_collection(repository, collection_dir)
    if not validation["complete"]:
        raise RuntimeError(f"代表関数解析の完了条件を満たさないcaseがあります: {validation['invalid_cases']}")
    run_summary = {
        "schema_version": SCHEMA_VERSION,
        "collection_id": collection_dir.name,
        "unique_pe_programs": len(results),
        "publication": publication,
        "private_artifact_validation": {
            "complete": private_validation["complete"],
            "valid_programs": private_validation["valid_programs"],
            "invalid_programs": private_validation["invalid_programs"],
            "totals": private_validation["totals"],
        },
        "complete_artifact_refresh": complete_artifact_refresh,
        "call_graph_augmentation": call_graph_augmentation,
        "validation": {
            "complete": validation["complete"],
            "valid_cases": validation["valid_cases"],
            "invalid_cases": validation["invalid_cases"],
        },
        "safety": {
            "sample_executed": False,
            "network_contacted": False,
            "arbitrary_ghidra_scripts_enabled": False,
            "mcp_localhost_only": True,
        },
    }
    _json_dump(private_output / "run-summary.json", run_summary)
    return run_summary


class JapaneseArgumentParser(argparse.ArgumentParser):
    """argparseの固定見出しを日本語へ置換する。"""

    def format_help(self) -> str:
        return (
            super()
            .format_help()
            .replace("usage:", "使用法:")
            .replace("options:", "オプション:")
            .replace("show this help message and exit", "このhelpを表示して終了します")
        )


def build_parser() -> argparse.ArgumentParser:
    """CLI引数parserを構築する。"""

    repository = Path(__file__).resolve().parents[2]
    parser = JapaneseArgumentParser(description=__doc__)
    parser.add_argument(
        "--repository",
        type=Path,
        default=repository,
        help="repository rootを指定します",
    )
    parser.add_argument(
        "--collection",
        type=Path,
        default=repository / "analysis-results" / "collections" / DEFAULT_COLLECTION_ID,
        help="対象collection directoryを指定します",
    )
    parser.add_argument(
        "--sample-root",
        required=True,
        type=Path,
        help="暗号化archiveを保持するrepository外directoryを指定します",
    )
    parser.add_argument(
        "--private-output",
        required=True,
        type=Path,
        help="生の逆コンパイル成果物を保持するrepository外directoryを指定します",
    )
    parser.add_argument(
        "--mcp-url",
        default=DEFAULT_MCP_URL,
        help="localhostのGhidra MCP URLを指定します",
    )
    parser.add_argument(
        "--project-root",
        default=DEFAULT_PROJECT_ROOT,
        help="Ghidra project内の保存先rootを指定します",
    )
    parser.add_argument(
        "--reuse-prepared-inputs",
        action="store_true",
        help="SHA-256検証済みghidra-input cacheから再開します",
    )
    parser.add_argument(
        "--request-timeout",
        type=int,
        default=3600,
        help="1つのMCP requestのtimeout秒数を指定します",
    )
    parser.add_argument(
        "--analysis-timeout",
        type=int,
        default=3600,
        help="1 programのauto-analysis timeout秒数を指定します",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint。"""

    args = build_parser().parse_args(argv)
    result = run(args)
    print(json.dumps(result, ensure_ascii=False, indent=2), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
