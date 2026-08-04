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
import sys
import time
from typing import Any, Iterable, Mapping
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlparse
from urllib.request import Request, urlopen

import dnfile
from dncil.cil.body.reader import read_method_body_from_bytes
import pefile

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from unpackers.managed_il_triage import _contain_parser_diagnostics  # noqa: E402

from analysis_contract import (  # noqa: E402
    artifact_hashes,
    case_integrity_errors,
    load_json_object_strict,
    resolve_case_artifact,
    seal_report,
    verify_artifact_hashes,
    verify_report_semantics,
)
from analyze_sample import (  # noqa: E402
    StaticLayer,
    _layer_count_limit_reached,
    read_input_unit,
    recover_static_layers,
)
from overall_logic_diagrams import (  # noqa: E402
    load_static_layers,
    render_overall_logic_markdown,
)
from result_publication import detect_publication_context, register_publication_cases  # noqa: E402
from static_logic import (  # noqa: E402
    build_static_logic_report,
    extract_script_function_records,
    redact_static_text,
)
from validate_function_analysis import validate_collection  # noqa: E402


SCHEMA_VERSION = 1
DEFAULT_COLLECTION_ID = "malwarebazaar-windows-20260723-0100"
DEFAULT_MCP_URL = "http://127.0.0.1:8089"
DEFAULT_PROJECT_ROOT = "/Malware/MalwareBazaarWindows/20260723"
LOCAL_MCP_HOSTS = {"127.0.0.1", "localhost", "::1"}
FUNCTION_PAGE_SIZE = 500
STRUCTURE_PAGE_SIZE = 1_000
DECOMPILE_BATCH_SIZE = 20
DECOMPILE_WORKERS = 3
MAX_CHARACTERISTIC_FUNCTIONS_PER_PROGRAM = 32
FUNCTION_ANALYSIS_BLOCKER = "representative_function_analysis_required"

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


def _request_timed_out(error: BaseException) -> bool:
    """例外連鎖に通信タイムアウトが含まれるかを判定する。"""

    current: BaseException | None = error
    visited: set[int] = set()
    while current is not None and id(current) not in visited:
        visited.add(id(current))
        if isinstance(current, TimeoutError):
            return True
        if isinstance(current, URLError) and isinstance(current.reason, TimeoutError):
            return True
        current = current.__cause__ or current.__context__
    return False


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
        return False
    return True


def _is_managed_pe(data: bytes) -> bool:
    """PEのCLI header directoryからmanaged PEかを軽量判定する。"""

    if not data.startswith(b"MZ"):
        return False
    pe: pefile.PE | None = None
    try:
        pe = pefile.PE(data=data, fast_load=True)
        directories = pe.OPTIONAL_HEADER.DATA_DIRECTORY
        index = pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR"]
        if index >= len(directories):
            return False
        descriptor = directories[index]
        return bool(int(getattr(descriptor, "VirtualAddress", 0) or 0) and int(getattr(descriptor, "Size", 0) or 0))
    except Exception:
        return False
    finally:
        if pe is not None:
            pe.close()


def _raw_pe_import_parameters(data: bytes) -> dict[str, str] | None:
    """標準loaderで読めないx86 PE向けのraw import指定を返す。"""

    if not data.startswith(b"MZ"):
        return None
    pe: pefile.PE | None = None
    try:
        pe = pefile.PE(data=data, fast_load=True)
        language = {
            0x014C: "x86:LE:32:default",
            0x8664: "x86:LE:64:default",
        }.get(int(pe.FILE_HEADER.Machine))
        if language is None:
            return None
        return {"language": language, "compiler_spec": "windows"}
    except Exception:
        return None
    finally:
        if pe is not None:
            pe.close()


def _normalize_static_tool(value: Path | None, label: str) -> Path | None:
    """明示指定した外部静的toolを実在する通常fileへ限定する。"""

    if value is None:
        return None
    try:
        resolved = value.expanduser().resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ValueError(f"{label}が見つかりません: {value}") from exc
    if not resolved.is_file():
        raise ValueError(f"{label}は通常fileで指定してください: {value}")
    return resolved


def _static_tool_identity(path: Path | None) -> dict[str, Any] | None:
    """外部静的toolのpathを公開せず、名前・size・内容hashを返す。"""

    if path is None:
        return None
    hasher = hashlib.sha256()
    size = 0
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            hasher.update(chunk)
            size += len(chunk)
    return {
        "name": path.name,
        "size": size,
        "sha256": hasher.hexdigest(),
    }


def _validate_static_tool_contract(
    case_dir: Path,
    actual: Mapping[str, dict[str, Any] | None],
) -> None:
    """layer再現へ使う外部toolが公開解析契約と同一であることを確認する。"""

    report = load_json_object_strict(case_dir / "report.json")
    contract = report.get("analysis_contract")
    settings = contract.get("settings") if isinstance(contract, Mapping) else None
    expected = settings.get("static_tools") if isinstance(settings, Mapping) else None
    if not isinstance(expected, Mapping):
        raise ValueError(f"公開解析契約にstatic_toolsがありません: {case_dir.name}")
    mismatched = [name for name in ("upx", "sevenzip", "diec") if expected.get(name) != actual.get(name)]
    if mismatched:
        raise ValueError(f"外部静的tool設定が公開解析契約と一致しません: {case_dir.name}: {','.join(mismatched)}")


def _load_authenticated_public_layers(
    case_dir: Path,
) -> tuple[list[dict[str, Any]], set[tuple[str, int, int, str]]]:
    """reportと成果物のsealを検証し、公開layer集合を厳密に読み込む。"""

    report = load_json_object_strict(case_dir / "report.json")
    semantic_errors = verify_report_semantics(report)
    if semantic_errors:
        raise ValueError(f"公開report sealを検証できません: {case_dir.name}: {semantic_errors}")
    manifest = report.get("artifact_sha256")
    if not isinstance(manifest, Mapping):
        raise ValueError(f"公開成果物hash manifestがありません: {case_dir.name}")
    sealed_digest = manifest.get("static-layers.json")
    if not isinstance(sealed_digest, str) or SHA256_RE.fullmatch(sealed_digest) is None:
        raise ValueError(f"static-layers.jsonのsealが不正です: {case_dir.name}")
    seal_errors = verify_artifact_hashes(
        case_dir,
        {"static-layers.json": sealed_digest},
    )
    if seal_errors:
        raise ValueError(f"static-layers.jsonのsealを検証できません: {case_dir.name}: {seal_errors}")
    document = load_json_object_strict(resolve_case_artifact(case_dir, "static-layers.json"))
    raw_layers = document.get("layers")
    if not isinstance(raw_layers, list) or not raw_layers:
        raise ValueError(f"公開静的layer一覧が不正です: {case_dir.name}")

    layers: list[dict[str, Any]] = []
    identities: list[tuple[str, int, int, str]] = []
    for index, raw in enumerate(raw_layers):
        if not isinstance(raw, Mapping):
            raise ValueError(f"公開静的layerがJSON objectではありません: {case_dir.name}: {index}")
        digest = raw.get("sha256")
        size = raw.get("size")
        depth = raw.get("depth")
        transform = raw.get("transform")
        if not isinstance(digest, str) or SHA256_RE.fullmatch(digest) is None:
            raise ValueError(f"公開静的layerのSHA-256が不正です: {case_dir.name}: {index}")
        if type(size) is not int or size < 0:
            raise ValueError(f"公開静的layerのsizeが不正です: {case_dir.name}: {index}")
        if type(depth) is not int or depth < 0:
            raise ValueError(f"公開静的layerのdepthが不正です: {case_dir.name}: {index}")
        if not isinstance(transform, str) or not transform:
            raise ValueError(f"公開静的layerのtransformが不正です: {case_dir.name}: {index}")
        layers.append(dict(raw))
        identities.append((digest, size, depth, transform))
    if len(set(identities)) != len(identities):
        raise ValueError(f"公開静的layer一覧に重複があります: {case_dir.name}")
    return layers, set(identities)


def prepare_inputs(
    repository: Path,
    collection_dir: Path,
    sample_root: Path,
    private_output: Path,
    *,
    upx: Path | None = None,
    sevenzip: Path | None = None,
    diec: Path | None = None,
) -> tuple[dict[str, ProgramObject], dict[str, list[dict[str, Any]]]]:
    """root検体と復元layerを隔離保存し、Ghidra対象をdeduplicateする。"""

    upx = _normalize_static_tool(upx, "UPX")
    sevenzip = _normalize_static_tool(sevenzip, "7-Zip")
    diec = _normalize_static_tool(diec, "Detect It Easy CLI")
    static_tools = {
        "upx": _static_tool_identity(upx),
        "sevenzip": _static_tool_identity(sevenzip),
        "diec": _static_tool_identity(diec),
    }
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
        _validate_static_tool_contract(case_dir, static_tools)
        analysis_report = load_json_object_strict(case_dir / "report.json")
        contract = analysis_report.get("analysis_contract")
        settings = contract.get("settings") if isinstance(contract, Mapping) else None
        if not isinstance(settings, Mapping):
            raise ValueError(f"解析契約settingsがありません: {case_sha}")
        public_layers, expected = _load_authenticated_public_layers(case_dir)
        unit = read_input_unit(
            archive,
            password="infected",
            archive_mode="malwarebazaar",
            max_file_size=512 * 1024 * 1024,
        )
        if hashlib.sha256(unit.data).hexdigest() != case_sha:
            raise ValueError(f"root検体hashが一致しません: {case_sha}")
        authenticated_root = (
            case_sha,
            len(unit.data),
            0,
            "submission",
        )
        if len(public_layers) == 1 and expected == {authenticated_root}:
            layers = [
                StaticLayer(
                    name=unit.source_name,
                    data=unit.data,
                    sha256=case_sha,
                    parent_sha256=None,
                    depth=0,
                    transform="submission",
                )
            ]
            reconstruction_mode = "authenticated_root_only"
        else:
            replay_kwargs: dict[str, Any] = {
                "upx": upx,
                "sevenzip": sevenzip,
                "diec": diec,
            }
            if "force_container_probe" in settings:
                replay_kwargs["force_container_probe"] = bool(settings["force_container_probe"])
            if "max_static_layers" in settings:
                replay_kwargs["max_static_layers"] = int(settings["max_static_layers"])
            layers, layer_report = recover_static_layers(unit, **replay_kwargs)
            retry_limit = settings.get("retry_max_static_layers")
            if retry_limit is not None and _layer_count_limit_reached(layer_report):
                replay_kwargs["max_static_layers"] = int(retry_limit)
                layers, _ = recover_static_layers(unit, **replay_kwargs)
                reconstruction_mode = "adaptive_static_layer_replay"
            else:
                reconstruction_mode = "full_static_layer_replay"
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
                "reconstruction_mode": reconstruction_mode,
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
                    "reconstruction_mode": reconstruction_mode,
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
            "static_tools": static_tools,
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
        expected_size = int(relation.get("size") or -1)
        cache_present = input_path.is_file()
        if cache_present:
            if input_path.stat().st_size != expected_size:
                raise ValueError(f"再開用PE cacheのsizeが一致しません: {digest}")
            hasher = hashlib.sha256()
            with input_path.open("rb") as handle:
                while chunk := handle.read(1024 * 1024):
                    hasher.update(chunk)
            if hasher.hexdigest() != digest:
                raise ValueError(f"再開用PE cacheのSHA-256が一致しません: {digest}")
        else:
            result_path = private_output / "objects" / digest / "program-result.json"
            cached = load_json_object_strict(result_path) if result_path.is_file() else {}
            if not (cached.get("status") == "complete" and cached.get("mcp_responses_valid") is True):
                raise FileNotFoundError(f"再開用PE cacheがありません: {input_path}")
        if digest not in objects:
            objects[digest] = ProgramObject(
                sha256=digest,
                input_path=input_path,
                size=expected_size,
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
    document = json.loads((private_output / "input-relationships.json").read_text(encoding="utf-8-sig"))
    if str(document.get("collection_id") or "") != collection_dir.name:
        raise ValueError("再開cacheのcollection IDが対象directoryと一致しません")
    observed = {
        str(item.get("case_sha256") or "").casefold()
        for item in document.get("relationships", [])
        if isinstance(item, Mapping)
    }
    if not expected or observed != expected:
        raise ValueError(f"再開cacheのcase集合が対象collectionと一致しません: {len(observed)} != {len(expected)}")


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
    unmatched = [dict(item) for item in (value or {}).get("unmatched_response_rows", []) if isinstance(item, Mapping)]
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
    (
        "support",
        "補助処理",
        {"general_internal_logic", "compiler_or_library_code", "external_api_or_thunk", "managed_method_without_body"},
    ),
)


def _entry_point_addresses(entry_points: Any) -> set[str]:
    """Ghidraのentry point応答からaddress候補を抽出する。"""

    values: set[str] = set()
    if isinstance(entry_points, str):
        values.update(re.findall(r"(?i)(?:@|address\s*[:=])\s*([0-9a-fx:]+)", entry_points))
    elif isinstance(entry_points, Mapping):
        values.update(str(value) for key, value in entry_points.items() if "address" in str(key).casefold() and value)
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
            item["selection_reasons"] = sorted(set([*item["selection_reasons"], "small_program_complete_context"]))
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
    elif role not in {
        "general_internal_logic",
        "compiler_or_library_code",
        "external_api_or_thunk",
        "managed_method_without_body",
    }:
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
    chunks = [targets[start : start + DECOMPILE_BATCH_SIZE] for start in range(0, len(targets), DECOMPILE_BATCH_SIZE)]
    initial_saved = len(existing)
    processed = 0
    if not chunks:
        return existing
    with ThreadPoolExecutor(
        max_workers=min(DECOMPILE_WORKERS, len(chunks)),
        thread_name_prefix="ghidra-decompile",
    ) as executor:
        futures = [executor.submit(_decompile_chunk, client, program, chunk) for chunk in chunks]
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


@_contain_parser_diagnostics
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
    skip_auto_analysis: bool = False,
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
    data = item.input_path.read_bytes()
    if hashlib.sha256(data).hexdigest() != item.sha256:
        raise ValueError(f"Ghidra input hashが解析直前に一致しません: {item.sha256}")
    managed_cil_primary = _is_managed_pe(data)
    primary = item.primary
    case_sha = str(primary["case_sha256"])
    if int(primary["depth"]) == 0:
        folder = _safe_project_path(f"{project_root}/{case_sha[:8]}")
    else:
        folder = _safe_project_path(f"{project_root}/{case_sha[:8]}/layers/{item.sha256[:8]}")
    expected_program = _safe_project_path(f"{folder}/{item.input_path.name}")
    program: str | None = None
    import_mode = "preexisting_program"
    preopened_status_raw: Any = None
    try:
        preopened_status_raw = client.get("/analysis_status", program=expected_program)
        program = expected_program
    except GhidraMcpError:
        pass
    if program is None:
        try:
            opened = client.get("/open_program", path=expected_program, auto_analyze=False)
            program = str((opened or {}).get("path") or expected_program)
            import_mode = "opened_existing_program"
        except GhidraMcpError:
            import_body: dict[str, Any] = {
                "file_path": str(item.input_path.resolve()),
                "project_folder": folder,
                "auto_analyze": not managed_cil_primary and not skip_auto_analysis,
            }
            try:
                imported = client.post("/import_file", import_body)
                import_mode = "automatic_loader"
            except GhidraMcpError as automatic_error:
                # import処理は応答タイムアウト後もGhidra側で完了し得る。ここで
                # raw importへ切り替えると、同じ検体が「.0」付きで重複登録される。
                # 通信タイムアウトは再実行時の既存program検出に委ねる。
                if _request_timed_out(automatic_error):
                    raise
                raw_parameters = _raw_pe_import_parameters(data)
                if raw_parameters is None:
                    raise automatic_error
                imported = client.post(
                    "/import_file",
                    {**import_body, **raw_parameters},
                )
                import_mode = "raw_pe_fallback"
            if not isinstance(imported, Mapping) or not imported.get("path"):
                raise GhidraMcpError(f"import responseにprogram pathがありません: {item.sha256}")
            program = _safe_project_path(str(imported["path"]))
    if program != expected_program:
        raise GhidraMcpError(f"program selectorが予期したpathと一致しません: {program} != {expected_program}")

    def _program_get(endpoint: str, **query: Any) -> Any:
        if managed_cil_primary:
            print(
                json.dumps(
                    {
                        "phase": "managed_ghidra_structure",
                        "state": "request",
                        "sha256": item.sha256,
                        "endpoint": endpoint,
                    },
                    ensure_ascii=False,
                ),
                flush=True,
            )
        response = client.get(endpoint, program=program, **query)
        if managed_cil_primary:
            print(
                json.dumps(
                    {
                        "phase": "managed_ghidra_structure",
                        "state": "complete",
                        "sha256": item.sha256,
                        "endpoint": endpoint,
                    },
                    ensure_ascii=False,
                ),
                flush=True,
            )
        return response

    if managed_cil_primary:
        raw_status = preopened_status_raw if preopened_status_raw is not None else _program_get("/analysis_status")
        status = dict(raw_status) if isinstance(raw_status, Mapping) else {}
        analysis_mode = "managed_cil_primary_with_ghidra_structure"
    elif skip_auto_analysis:
        raw_status = preopened_status_raw if preopened_status_raw is not None else _program_get("/analysis_status")
        status = dict(raw_status) if isinstance(raw_status, Mapping) else {}
        status["documented_limit"] = "auto_analysis_skipped_after_repeated_timeout"
        analysis_mode = "native_ghidra_limited_without_auto_analysis"
    else:
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
        analysis_mode = "native_ghidra_with_optional_cil"
    functions = [] if managed_cil_primary else _all_functions(client, program)
    metadata_raw = _program_get("/get_metadata")
    imports = _program_get("/list_imports", offset=0, limit=10000)
    exports = _program_get("/list_exports", offset=0, limit=10000)
    strings = [] if managed_cil_primary else client.get("/list_strings", offset=0, limit=100000, program=program)
    segments = _program_get("/list_segments", offset=0, limit=10000)
    entry_points = [] if managed_cil_primary else client.get("/get_entry_points", program=program)
    if managed_cil_primary:
        call_graph = {
            "edges": [],
            "analysis_mode": analysis_mode,
            "note": "managed method間のcallはCIL recordから保持する",
        }
        anti_analysis = {
            "status": "not_run_managed_cil_primary",
            "reason": "managed methodはCIL静的解析を正本とする",
        }
        api_chains = {
            "status": "not_run_managed_cil_primary",
            "reason": "managed methodのAPI callはCIL recordへ保持する",
        }
        opcode_hashes = _complete_opcode_hash_inventory(
            {"functions": [], "endpoint_returned": 0},
            functions,
            program,
        )
        selected_native = []
    else:
        call_graph = client.get(
            "/get_full_call_graph",
            format="json_edges",
            limit=0,
            program=program,
        ) or {"edges": []}
        anti_analysis = client.get("/find_anti_analysis_techniques", program=program)
        api_chains = client.get("/analyze_api_call_chains", program=program)
        opcode_hashes = _all_opcode_hashes(client, program, functions)
        selected_native = select_characteristic_functions(
            functions,
            call_graph if isinstance(call_graph, Mapping) else {},
            entry_points,
            opcode_hashes if isinstance(opcode_hashes, Mapping) else {},
        )
    selection_by_address = {str(item["address"]): item for item in selected_native if item.get("address")}
    decompilations = (
        {}
        if managed_cil_primary
        else _decompile_all(
            client,
            program,
            selected_native,
            output_dir / "decompilations.raw.jsonl",
        )
    )
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
        "analysis_mode": analysis_mode,
        "import_mode": import_mode,
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
        "analysis_mode": analysis_mode,
        "import_mode": import_mode,
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
        if not managed_cil_primary:
            client.get("/save_program", program=program)
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
    initial_limits = {
        "imports": 10000,
        "exports": 10000,
        "strings": 100000,
        "segments": 10000,
    }
    for index, (digest, result) in enumerate(sorted(program_results.items()), start=1):
        program = _safe_project_path(str(result.get("program_selector") or ""))
        object_dir = private_output / "objects" / digest
        raw_index_path = object_dir / "ghidra-raw-index.json"
        raw_index = json.loads(raw_index_path.read_text(encoding="utf-8-sig"))
        opened_program: str | None = None
        open_error: GhidraMcpError | None = None
        initial_cache_terminal = all(
            len(_page_values(raw_index.get(name), endpoint)) < initial_limits[name]
            for name, endpoint in endpoints.items()
        )
        if initial_cache_terminal:
            open_error = GhidraMcpError("初回MCP応答で全ページング対象の終端到達を確認済みです")
        else:
            try:
                opened = client.get("/open_program", path=program, auto_analyze=False)
                opened_program = _safe_project_path(str((opened or {}).get("path") or program))
                if opened_program != program:
                    raise GhidraMcpError(f"完全取得時のprogram selectorが一致しません: {opened_program} != {program}")
            except GhidraMcpError as error:
                open_error = error
        retrieved: dict[str, list[Any]] = {}
        coverage: dict[str, dict[str, Any]] = {}
        for name, endpoint in endpoints.items():
            if result.get("analysis_mode") == "managed_cil_primary_with_ghidra_structure" and name == "strings":
                items = []
                endpoint_coverage = {
                    "endpoint": endpoint,
                    "program_selector": program,
                    "page_size": 0,
                    "page_count": 0,
                    "item_count": 0,
                    "terminal_short_page_observed": False,
                    "complete": True,
                    "source": "managed_cil_primary",
                    "endpoint_invoked": False,
                    "reason": (
                        "managed文字列はCIL instruction recordと一次静的解析結果を正本とし、"
                        "Ghidraの疑似native文字列全列挙は実行しない"
                    ),
                }
            elif open_error is not None:
                items = _page_values(raw_index.get(name), endpoint)
                page_size = initial_limits[name]
                if len(items) >= page_size:
                    raise open_error
                endpoint_coverage = {
                    "endpoint": endpoint,
                    "program_selector": program,
                    "page_size": page_size,
                    "page_count": 1,
                    "item_count": len(items),
                    "terminal_short_page_observed": True,
                    "complete": True,
                    "source": "authenticated_initial_response_cache",
                    "endpoint_invoked": True,
                    "reason": ("初回MCP応答の項目数が要求上限未満であり、同一応答内で終端到達を確認した"),
                }
            else:
                items, endpoint_coverage = _all_endpoint_items(client, endpoint, program)
            retrieved[name] = items
            coverage[name] = endpoint_coverage
            totals[name] += len(items)
        if open_error is not None:
            totals["promoted_cached_programs"] += 1
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
        if opened_program is not None:
            try:
                client.post("/close_program", {"name": opened_program})
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
                    "source": (
                        "authenticated_initial_response_cache" if open_error is not None else "ghidra_endpoint_refresh"
                    ),
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
            if isinstance(item, Mapping) and item.get("selected_for_characteristic_analysis") is True
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
            if evidence.get("complete") is not True:
                errors.append(f"{name}: 完全取得または正本代替の証跡がありません")
            endpoint_skipped = evidence.get("endpoint_invoked") is False
            managed_cil_alternative = (
                endpoint_skipped
                and name == "strings"
                and result.get("analysis_mode") == "managed_cil_primary_with_ghidra_structure"
                and evidence.get("source") == "managed_cil_primary"
            )
            if endpoint_skipped and not managed_cil_alternative:
                errors.append(f"{name}: 未許可のendpoint省略証跡です")
            if not endpoint_skipped and evidence.get("terminal_short_page_observed") is not True:
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
        selected_ids = {str(value) for value in result.get("characteristic_function_ids", []) if value}
        raw_selected_ids = {str(value) for value in raw_index.get("characteristic_function_ids", []) if value}
        if selected_ids != raw_selected_ids:
            errors.append("代表関数IDがraw indexとprogram-resultで一致しません")
        record_ids = {
            str(item.get("function_id"))
            for item in result.get("functions", [])
            if isinstance(item, Mapping) and item.get("function_id")
        }
        eligible_count = sum(
            not bool(item.get("isExternal")) and not bool(item.get("isThunk")) for item in raw_functions
        ) + sum(item.get("decompilation_status") != "no_managed_body" for item in managed_records)
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
            opcode_functions = [item for item in opcode_hashes.get("functions", []) if isinstance(item, Mapping)]
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


def _ghidra_supersedes_generic_string_limit(case_dir: Path) -> bool:
    """Return whether complete Ghidra evidence covers the sole generic string limit."""

    generic_path = case_dir / "generic-triage.json"
    static_path = case_dir / "static-logic.json"
    if not generic_path.exists() or not static_path.exists():
        return False
    generic = load_json_object_strict(generic_path)
    static_logic = load_json_object_strict(static_path)
    coverage = static_logic.get("coverage")
    if not isinstance(coverage, Mapping):
        return False
    required = (
        "all_characteristic_functions_attempted",
        "all_characteristic_functions_explained",
        "all_discovered_functions_inventoried",
        "all_static_analysis_content_retained",
        "function_bodies_reviewed",
    )
    if not all(coverage.get(key) is True for key in required):
        return False
    program_count = coverage.get("ghidra_program_count")
    if not isinstance(program_count, int) or program_count < 1:
        return False
    if coverage.get("ghidra_programs_with_valid_mcp_responses") != program_count:
        return False

    issues: list[str] = []

    def collect(value: object) -> None:
        if isinstance(value, Mapping):
            for key, item in value.items():
                if key == "string_scan" and isinstance(item, Mapping):
                    if item.get("truncated") is True:
                        issues.append("string_scan_truncated")
                elif key == "base64_scan" and isinstance(item, Mapping):
                    if item.get("truncated") is True:
                        issues.append("base64_scan_truncated")
                elif key == "parse_error" or key.endswith("_error"):
                    issues.append(key)
                elif key != "analysis_coverage":
                    collect(item)
            return
        if isinstance(value, list):
            for item in value:
                collect(item)

    collect(generic)
    return issues == ["string_scan_truncated"]


def _ghidra_documents_known_static_limits(
    case_dir: Path,
    state: Mapping[str, Any],
) -> list[str]:
    """Ghidra証拠と再試行記録で説明済みとなる限定的な静的制限を返す。"""

    static_path = case_dir / "static-logic.json"
    if not static_path.exists():
        return []
    static_logic = load_json_object_strict(static_path)
    coverage = static_logic.get("coverage")
    if not isinstance(coverage, Mapping):
        return []
    required = (
        "all_characteristic_functions_attempted",
        "all_characteristic_functions_explained",
        "all_discovered_functions_inventoried",
        "all_static_analysis_content_retained",
        "function_bodies_reviewed",
    )
    if not all(coverage.get(key) is True for key in required):
        return []
    program_count = coverage.get("ghidra_program_count")
    if not isinstance(program_count, int) or program_count < 1:
        return []
    if coverage.get("ghidra_programs_with_valid_mcp_responses") != program_count:
        return []

    issues = state.get("static_layer_issues")
    if not isinstance(issues, list) or not issues:
        return []
    managed_suffix = ".report.pe.managed_il_triage.status:analyzed_partial_budget"
    sevenzip_suffix = ".report.sevenzip.status:partially_extracted"
    if any(not isinstance(issue, str) or not issue.endswith((managed_suffix, sevenzip_suffix)) for issue in issues):
        return []

    sevenzip_issues = [issue for issue in issues if issue.endswith(sevenzip_suffix)]
    if sevenzip_issues:
        layers_path = case_dir / "static-layers.json"
        if not layers_path.exists():
            return []
        static_layers = load_json_object_strict(layers_path)
        exhausted = []
        for step in static_layers.get("steps", []):
            report = step.get("report") if isinstance(step, Mapping) else None
            sevenzip = report.get("sevenzip") if isinstance(report, Mapping) else None
            if not isinstance(sevenzip, Mapping) or sevenzip.get("status") != "partially_extracted":
                continue
            inventory = sevenzip.get("inventory")
            exhausted.append(
                int(sevenzip.get("archive_unlock_attempt_count") or 0) >= 2
                and sevenzip.get("retained_members") == 0
                and isinstance(inventory, list)
                and bool(inventory)
                and all(isinstance(item, Mapping) and item.get("status") == "empty_file" for item in inventory)
            )
        if len(exhausted) != len(sevenzip_issues) or not all(exhausted):
            return []
    return sorted(set(issues))


def _ghidra_documents_known_generic_container_limits(case_dir: Path) -> list[str]:
    """完全な静的coverageで補完済みの限定的なcontainer委譲だけを返す。"""

    generic_path = case_dir / "generic-triage.json"
    layers_path = case_dir / "static-layers.json"
    static_path = case_dir / "static-logic.json"
    if not generic_path.exists() or not layers_path.exists() or not static_path.exists():
        return []
    static_logic = load_json_object_strict(static_path)
    coverage = static_logic.get("coverage")
    if not isinstance(coverage, Mapping):
        return []
    required = (
        "all_characteristic_functions_attempted",
        "all_characteristic_functions_explained",
        "all_discovered_functions_inventoried",
        "all_static_analysis_content_retained",
        "function_bodies_reviewed",
    )
    if not all(coverage.get(key) is True for key in required):
        return []
    program_count = coverage.get("ghidra_program_count")
    if not isinstance(program_count, int) or program_count < 1:
        return []
    if coverage.get("ghidra_programs_with_valid_mcp_responses") != program_count:
        return []

    generic = load_json_object_strict(generic_path)
    generic_coverage = generic.get("analysis_coverage")
    if not isinstance(generic_coverage, Mapping):
        return []
    if int(generic_coverage.get("failed_layers") or 0) != 0:
        return []
    entries = generic.get("recovered_layer_triage")
    if not isinstance(entries, list):
        return []
    partial_entries = [item for item in entries if isinstance(item, Mapping) and item.get("status") == "partial"]
    if len(partial_entries) != int(generic_coverage.get("partial_layers") or 0) or not partial_entries:
        return []

    static_layers = load_json_object_strict(layers_path)
    steps = static_layers.get("steps")
    if not isinstance(steps, list):
        return []
    steps_by_sha: dict[str, Mapping[str, Any]] = {}
    for step in steps:
        if not isinstance(step, Mapping):
            continue
        input_layer = step.get("input_layer")
        if isinstance(input_layer, Mapping) and input_layer.get("sha256"):
            steps_by_sha[str(input_layer["sha256"])] = step
    layer_hashes = {
        str(item.get("sha256"))
        for item in static_layers.get("layers", [])
        if isinstance(item, Mapping) and item.get("sha256")
    }
    documented: list[str] = []
    for entry in partial_entries:
        if entry.get("issues") != ["root:coverage:partial"]:
            return []
        layer = entry.get("layer")
        result = entry.get("result")
        if not isinstance(layer, Mapping) or not isinstance(result, Mapping):
            return []
        layer_sha = str(layer.get("sha256") or "")
        layer_format = str(layer.get("format") or result.get("type") or "")
        analysis_coverage = result.get("analysis_coverage")
        if not isinstance(analysis_coverage, Mapping):
            return []
        step = steps_by_sha.get(layer_sha)
        if not isinstance(step, Mapping) or step.get("status") != "succeeded":
            return []
        report = step.get("report")
        if not isinstance(report, Mapping):
            return []
        if layer_format == "rar":
            sevenzip = report.get("sevenzip")
            inventory = sevenzip.get("inventory") if isinstance(sevenzip, Mapping) else None
            if (
                result.get("format_specific_analysis") != "delegated_to_static_layer_pipeline"
                or analysis_coverage.get("issues") != ["root:rar_inventory_only"]
                or not isinstance(sevenzip, Mapping)
                or sevenzip.get("status") != "partially_extracted"
                or int(sevenzip.get("archive_unlock_attempt_count") or 0) < 2
                or sevenzip.get("retained_members") != 0
                or not isinstance(inventory, list)
                or not inventory
                or not all(isinstance(item, Mapping) and item.get("status") == "empty_file" for item in inventory)
            ):
                return []
            documented.append(f"{layer_sha}:rar_inventory_delegated_to_bounded_static_recovery")
            continue
        if layer_format == "ole":
            ole = report.get("ole")
            inventory = ole.get("inventory") if isinstance(ole, Mapping) else None
            children = step.get("accepted_children")
            if (
                analysis_coverage.get("issues") != ["root:ole_format_analysis_not_implemented"]
                or not isinstance(ole, Mapping)
                or ole.get("status") != "artifacts_recovered"
                or not isinstance(inventory, list)
                or not inventory
                or not all(isinstance(item, Mapping) and item.get("status") == "inspected" for item in inventory)
                or not isinstance(children, list)
                or not children
                or not all(
                    isinstance(child, Mapping)
                    and child.get("sha256") in layer_hashes
                    and child.get("format") in {"cab", "pe"}
                    for child in children
                )
            ):
                return []
            documented.append(f"{layer_sha}:ole_inventory_and_executable_children_recovered")
            continue
        return []
    return sorted(documented)


def finalize_case_report(case_dir: Path) -> str:
    """代表関数解析後も未解決blockerを保持し、reportを再封印する。"""

    report = load_json_object_strict(case_dir / "report.json")
    state = report.get("case_state")
    if not isinstance(state, dict):
        raise ValueError(f"case_stateがありません: {case_dir.name}")
    blockers = state.get("blockers")
    if not isinstance(blockers, list):
        raise ValueError(f"case_state.blockersが配列ではありません: {case_dir.name}")
    status = state.get("status")
    generic_limit_superseded = _ghidra_supersedes_generic_string_limit(case_dir)
    documented_static_issues = _ghidra_documents_known_static_limits(case_dir, state)
    documented_generic_limits = _ghidra_documents_known_generic_container_limits(case_dir)
    if status == "partial":
        remaining = [value for value in blockers if value != FUNCTION_ANALYSIS_BLOCKER]
        if "generic_triage_partial" in remaining and (generic_limit_superseded or documented_generic_limits):
            remaining.remove("generic_triage_partial")
        if "static_layer_incomplete" in remaining and documented_static_issues:
            remaining.remove("static_layer_incomplete")
            state["static_layer_issues"] = []
            report["documented_static_layer_issues"] = documented_static_issues
            report["static_layer_analysis_completion"] = {
                "basis": "ghidra_complete_coverage_and_exhausted_bounded_static_recovery",
                "raw_evidence": "static-layers.json",
                "supplementary_evidence": "static-logic.json",
            }
            limitation = (
                "静的復元には管理コード解析予算または暗号化RAR復元の文書化済み制限があります。"
                "利用可能な候補を有界に再試行し、Ghidra MCPで全関数台帳と代表関数解析を補完しました。"
            )
            limitations = report.setdefault("limitations", [])
            if limitation not in limitations:
                limitations.append(limitation)
        if remaining:
            state.update(
                {
                    "status": "partial",
                    "complete": False,
                    "resumable": False,
                    "blockers": remaining,
                }
            )
        else:
            classification = report.get("classification")
            selected = classification.get("selected_families") if isinstance(classification, Mapping) else None
            if not isinstance(selected, list):
                raise ValueError(f"selected_familiesがありません: {case_dir.name}")
            state.update(
                {
                    "status": "complete" if selected else "triaged_unknown",
                    "complete": True,
                    "resumable": True,
                    "blockers": [],
                }
            )
    elif not (
        status in {"complete", "triaged_unknown"}
        and state.get("complete") is True
        and state.get("resumable") is True
        and blockers == []
    ):
        raise ValueError(f"Ghidra反映対象外のcase stateです: {case_dir.name}: {status}")
    if report.get("generic_triage") == "partial" and (generic_limit_superseded or documented_generic_limits):
        report["generic_triage"] = "complete"
        report["generic_triage_completion"] = {
            "basis": (
                "ghidra_complete_static_artifact_supersedes_string_retention_limit"
                if generic_limit_superseded
                else "ghidra_complete_coverage_and_bounded_container_recovery"
            ),
            "original_status": "partial",
            "raw_evidence": "generic-triage.json",
            "supplementary_evidence": "static-logic.json",
            "documented_container_limits": documented_generic_limits,
        }
        limitation = (
            "汎用文字列走査は保持上限に達しましたが、Ghidra MCPによる全関数インベントリと"
            "代表関数解析、完全静的成果物で補完しました。"
        )
        if documented_generic_limits:
            limitation = (
                "汎用containerトリアージの限定的な未実装箇所は、静的layer pipelineの完全inventory、"
                "有界な回収試行、再帰解析、およびGhidra MCPの完全coverageで補完しました。"
            )
        limitations = report.setdefault("limitations", [])
        if limitation not in limitations:
            limitations.append(limitation)
    manifest = report.get("artifact_sha256")
    if not isinstance(manifest, dict) or not manifest:
        raise ValueError(f"成果物hash manifestがありません: {case_dir.name}")
    report["artifact_sha256"] = artifact_hashes(case_dir, manifest)
    seal_report(report)
    _json_dump(case_dir / "report.json", report)
    resumable = state.get("status") in {"complete", "triaged_unknown"}
    errors = case_integrity_errors(
        case_dir,
        report,
        expected_digest=case_dir.name,
        require_resumable=resumable,
    )
    if errors:
        raise ValueError(f"Ghidra反映後のcase整合性検証に失敗しました: {case_dir.name}: {errors}")
    return str(state["status"])


def finalize_collection_publication(
    repository: Path,
    collection_dir: Path,
) -> dict[str, Any]:
    """全case完了時だけ索引登録し、残余blockerがあればpartialを明示する。"""

    manifest_path = collection_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8-sig"))
    requested = [
        str(item.get("case_id") or "").removeprefix("sha256:").casefold()
        for item in manifest.get("cases", [])
        if isinstance(item, Mapping)
    ]
    case_paths = _case_index(repository)
    by_family: dict[str, list[Path]] = defaultdict(list)
    state_counts: Counter[str] = Counter()
    blocker_counts: Counter[str] = Counter()
    for digest in requested:
        case_dir = case_paths.get(digest)
        if case_dir is None:
            raise FileNotFoundError(f"正式公開するcaseが見つかりません: {digest}")
        metadata = json.loads((case_dir / "metadata.json").read_text(encoding="utf-8-sig"))
        family = str(metadata.get("family") or "")
        if not family:
            raise ValueError(f"case metadataにfamilyがありません: {digest}")
        report = load_json_object_strict(case_dir / "report.json")
        state = report.get("case_state")
        status = str(state.get("status") if isinstance(state, Mapping) else "invalid")
        state_counts[status] += 1
        blockers = state.get("blockers") if isinstance(state, Mapping) else []
        if isinstance(blockers, list):
            blocker_counts.update(str(blocker) for blocker in blockers if isinstance(blocker, str) and blocker.strip())
        by_family[family].append(case_dir)
    complete_statuses = {"complete", "triaged_unknown"}
    all_complete = bool(requested) and set(state_counts) <= complete_statuses
    publication_stage = "complete" if all_complete else "partial_followup_required"
    registrations = {}
    for family, paths in sorted(by_family.items()):
        aggregate = collection_dir / "sources" / family
        context = detect_publication_context(aggregate, family)
        if context is None:
            raise ValueError(f"collection公開contextを解決できません: {family}")
        registrations[family] = register_publication_cases(context, paths)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8-sig"))
    manifest.update(
        {
            "analysis_complete": all_complete,
            "complete": all_complete,
            "publication_stage": publication_stage,
            "case_state_counts": dict(sorted(state_counts.items())),
            "case_blocker_counts": dict(sorted(blocker_counts.items())),
        }
    )
    _json_dump(manifest_path, manifest)
    summary_path = collection_dir / "publication-summary.json"
    summary = json.loads(summary_path.read_text(encoding="utf-8-sig"))
    summary.update(
        {
            "analysis_complete": all_complete,
            "publication_stage": publication_stage,
            "case_state_counts": dict(sorted(state_counts.items())),
            "case_blocker_counts": dict(sorted(blocker_counts.items())),
        }
    )
    _json_dump(summary_path, summary)
    readme_path = collection_dir / "README.md"
    readme = readme_path.read_text(encoding="utf-8-sig")
    readme = re.sub(r"(?m)^- case状態:.*\n?", "", readme)
    readme = re.sub(
        r"(?s)\n<!-- publication-followup:start -->.*?<!-- publication-followup:end -->\n?",
        "\n",
        readme,
    )
    state_summary = " / ".join(
        f"{status} {state_counts.get(status, 0)}" for status in ("complete", "partial", "triaged_unknown")
    )
    readme = re.sub(
        r"(?m)^- 公開段階: `[^`]+`$",
        f"- 公開段階: `{publication_stage}`\n- case状態: {state_summary}",
        readme,
    )
    if blocker_counts:
        descriptions = {
            "generic_triage_partial": "汎用トリアージまで完了し、ファミリー固有設定または終端C2の静的回収が未完了",
            "static_layer_incomplete": "静的復元層に追加追跡が必要",
        }
        followup_lines = [
            "",
            "<!-- publication-followup:start -->",
            "## 未完了項目",
            "",
            "関数単位の静的解析とは別に、設定抽出・終端C2・ファミリー帰属の追加確認が必要な項目を示します。関数解析が完了していても、これらの残余項目があればcollection全体を完了扱いにしません。",
            "",
            "| 理由 | case数 | 内容 |",
            "|---|---:|---|",
        ]
        for blocker, count in sorted(blocker_counts.items()):
            description = descriptions.get(blocker, "追加の静的確認が必要")
            followup_lines.append(f"| `{blocker}` | {count} | {description} |")
        followup_lines.extend(
            [
                "",
                "確認済み静的C2観測は抽出証拠を表し、到達性確認を意味しません。この実行ではC2／配布先への能動接続を行っていません。",
                "<!-- publication-followup:end -->",
                "",
            ]
        )
        readme = readme.rstrip() + "\n" + "\n".join(followup_lines)
    readme_path.write_text(readme, encoding="utf-8")
    return {
        "analysis_complete": all_complete,
        "publication_stage": publication_stage,
        "registrations": registrations,
        "cases": len(requested),
        "case_state_counts": dict(sorted(state_counts.items())),
        "case_blocker_counts": dict(sorted(blocker_counts.items())),
    }


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
    programs = [item for item in report.get("program_evidence", []) if isinstance(item, Mapping)]
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
            str(item.get("function_analysis", {}).get("decompilation_status") or "") != "succeeded" for item in matched
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
                    "代表関数は取得できましたが、静的証跡だけでは主要な処理段階へ自動分類できませんでした。"
                ),
                "function_ids": function_ids,
                "roles": sorted({str(item.get("role") or "unclassified") for item in functions}),
                "confidence": "confirmed_static_function_evidence_with_classification_limit",
            }
        )
        phase_by_function.update({function_id: "support" for function_id in function_ids})
    if not phases:
        entry_point_count = sum(len(item.get("entry_points") or []) for item in programs)
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
            summary += " import表から、" + "、".join(capability_titles) + "に関連する能力候補を整理しました。"
    elif active_titles:
        summary = "代表関数の静的証跡から、" + "、".join(active_titles) + "の処理群を確認しました。"
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
        "visualization_contract_version": 1,
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


def _render_overall_logic(
    report: Mapping[str, Any],
    static_layers: Mapping[str, Any] | None = None,
) -> str:
    """全体ロジックと3種類の静的Mermaid図を日本語文書へ描画する。"""

    return render_overall_logic_markdown(report, static_layers)


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
        lines.append("- Ghidraで解析可能な関数本体を認識できなかったため、program構造限定の解析結果を記録しました。")
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
    requested = [str(item["case_id"]).removeprefix("sha256:").casefold() for item in collection.get("cases", [])]
    status_counts: Counter[str] = Counter()
    totals: Counter[str] = Counter()
    per_case: dict[str, dict[str, Any]] = {}
    mutable_results = {digest: dict(result) for digest, result in program_results.items()}
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
            int(result.get("function_inventory_count") or len(result.get("functions", []))) for result in related
        ) + len(script_records)
        if not records and discovered_count:
            raise ValueError(f"発見済み関数から代表関数を選定できないcaseです: {case_sha}")
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
        statuses = [function["function_analysis"]["decompilation_status"] for function in report["functions"]]
        succeeded = sum(value == "succeeded" for value in statuses)
        excluded = sum(
            value
            in {
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
                    int(result.get("ghidra_function_inventory_count") or 0) for result in related
                ),
                "managed_method_inventory_count": sum(
                    int(result.get("managed_method_count") or 0) for result in related
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
            _render_overall_logic(report, load_static_layers(case_dir)),
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
        analysis["limitations"].append("代表関数の静的解析と全体ロジック整理を完了し、選定外範囲と制約を記録した。")
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
        finalized_case_state = finalize_case_report(case_dir)

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
            "case_state": finalized_case_state,
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
            item["case_state"] = per_case[sha]["case_state"]
            item["publication_stage"] = (
                "complete"
                if per_case[sha]["case_state"] in {"complete", "triaged_unknown"}
                else "partial_followup_required"
            )
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
            upx=args.upx,
            sevenzip=args.sevenzip,
            diec=args.diec,
        )
    validate_prepared_scope(collection_dir, private_output)
    results: dict[str, dict[str, Any]] = {}
    ordered = sorted(objects.values(), key=lambda item: (item.size, item.sha256))
    max_new_programs = args.max_new_programs
    newly_analyzed = 0
    cached_programs = 0
    pending_programs: list[str] = []
    for index, item in enumerate(ordered, start=1):
        result_path = private_output / "objects" / item.sha256 / "program-result.json"
        cached_complete = False
        if result_path.is_file():
            cached = load_json_object_strict(result_path)
            cached_complete = cached.get("status") == "complete" and cached.get("mcp_responses_valid") is True
        if not cached_complete and max_new_programs is not None and newly_analyzed >= max_new_programs:
            pending_programs.append(item.sha256)
            continue
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
            skip_auto_analysis=item.sha256 in args.skip_auto_analysis_sha256,
        )
        if cached_complete:
            cached_programs += 1
        else:
            newly_analyzed += 1
    if pending_programs:
        progress = {
            "schema_version": SCHEMA_VERSION,
            "collection_id": collection_dir.name,
            "status": "ghidra_chunk_pending",
            "unique_pe_programs": len(ordered),
            "complete_programs": len(results),
            "cached_programs": cached_programs,
            "newly_analyzed_programs": newly_analyzed,
            "pending_programs": pending_programs,
            "prepared_inputs_reused": bool(args.reuse_prepared_inputs),
            "safety": {
                "sample_executed": False,
                "network_contacted": False,
                "arbitrary_ghidra_scripts_enabled": False,
                "mcp_localhost_only": True,
            },
        }
        _json_dump(private_output / "run-progress.json", progress)
        return progress
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
    final_publication = finalize_collection_publication(repository, collection_dir)
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
        "final_publication": final_publication,
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
        "--upx",
        type=Path,
        help="公開解析契約と同一のUPX実行fileを指定します",
    )
    parser.add_argument(
        "--sevenzip",
        type=Path,
        help="公開解析契約と同一の7-Zip実行fileを指定します",
    )
    parser.add_argument(
        "--diec",
        type=Path,
        help="公開解析契約と同一のDetect It Easy CLI実行fileを指定します",
    )
    parser.add_argument(
        "--reuse-prepared-inputs",
        action="store_true",
        help="SHA-256検証済みghidra-input cacheから再開します",
    )
    parser.add_argument(
        "--max-new-programs",
        type=int,
        help=("今回新規にMCP解析するprogram数の上限。0は入力準備だけを行い、省略時は全programを処理します"),
    )
    parser.add_argument(
        "--skip-auto-analysis-sha256",
        action="append",
        default=[],
        type=str.lower,
        metavar="SHA256",
        help="反復timeoutを確認したprogramをauto-analysisなしの限定解析として処理します",
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
    if args.max_new_programs is not None and args.max_new_programs < 0:
        raise ValueError("--max-new-programsは0以上で指定してください")
    invalid_hashes = [value for value in args.skip_auto_analysis_sha256 if not SHA256_RE.fullmatch(value)]
    if invalid_hashes:
        raise ValueError("--skip-auto-analysis-sha256は64文字のSHA-256で指定してください")
    result = run(args)
    print(json.dumps(result, ensure_ascii=False, indent=2), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
