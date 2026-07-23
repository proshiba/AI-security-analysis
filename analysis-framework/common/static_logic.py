#!/usr/bin/env python3
"""関数単位の静的ロジックとコード類似性fingerprintを標準化する。"""

from __future__ import annotations

from collections import Counter
import hashlib
import json
from pathlib import Path
import re
from typing import Any, Iterable, Mapping


SCHEMA_VERSION = 1
SHA256_RE = re.compile(r"^[0-9a-f]{64}$", re.IGNORECASE)
URL_RE = re.compile(r"(?i)\b(?:https?|ftp)://[^\s<>`\"']+")
EMAIL_RE = re.compile(r"(?i)\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,63}\b")
IPV4_RE = re.compile(r"(?<![0-9])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9])")
FULL_HASH_RE = re.compile(r"(?i)(?<![0-9a-f])[0-9a-f]{32,64}(?![0-9a-f])")
AUTO_SYMBOL_RE = re.compile(
    r"(?i)\b(?:fun|sub|loc|lab|unk|off|byte|word|dword|qword)_[0-9a-f]+\b"
)
LOCAL_SYMBOL_RE = re.compile(r"(?i)\b(?:local|param|var|arg|tmp|stack)_[0-9a-f]+\b")
NUMBER_RE = re.compile(r"(?i)\b(?:0x[0-9a-f]+|\d+)\b")
TOKEN_RE = re.compile(
    r"<str>|<num>|<auto_fn>|<local>|[a-z_][a-z0-9_.$@]*|"
    r"==|!=|<=|>=|<<|>>|&&|\|\||\^|&|\||\+|-|\*|/|%|=|<|>",
    re.IGNORECASE,
)
SCRIPT_EXTENSIONS = {".bat", ".cmd", ".js", ".jse", ".ps1", ".py", ".sh", ".vbs"}
CONTROL_WORDS = {
    "break",
    "case",
    "catch",
    "continue",
    "do",
    "else",
    "except",
    "finally",
    "for",
    "foreach",
    "goto",
    "if",
    "return",
    "switch",
    "throw",
    "try",
    "while",
}
IGNORED_CALLS = CONTROL_WORDS | {"function", "sizeof", "typeof"}


def _redact_public_text(value: str) -> str:
    output = URL_RE.sub("[URL省略]", value)
    output = EMAIL_RE.sub("[メール省略]", output)
    output = IPV4_RE.sub("[IP省略]", output)
    return FULL_HASH_RE.sub("[hash省略]", output)


def normalize_logic_text(value: str) -> str:
    """address、literal、decompiler仮名を正規化し、比較可能なロジックへ変換する。"""

    output = re.sub(r'"(?:\\.|[^"\\])*"', " <str> ", value)
    output = re.sub(r"'(?:\\.|[^'\\])*'", " <str> ", output)
    output = re.sub(r"/\*.*?\*/", " ", output, flags=re.DOTALL)
    output = re.sub(r"(?m)//.*$", " ", output)
    output = _redact_public_text(output)
    output = AUTO_SYMBOL_RE.sub("<auto_fn>", output)
    output = LOCAL_SYMBOL_RE.sub("<local>", output)
    output = NUMBER_RE.sub("<num>", output)
    output = output.casefold()
    output = re.sub(r"\s+", " ", output).strip()
    return output


def semantic_tokens(value: str) -> list[str]:
    """制御構造、演算子、call形状を比較用token列へ変換する。"""

    normalized = normalize_logic_text(value)
    output = []
    for match in TOKEN_RE.finditer(normalized):
        token = match.group(0).casefold()
        remainder = normalized[match.end() :]
        is_call = bool(re.match(r"\s*\(", remainder))
        if token in CONTROL_WORDS:
            output.append(f"kw:{token}")
        elif is_call and token not in IGNORED_CALLS:
            output.append("call:<auto>" if token == "<auto_fn>" else f"call:{token}")
        elif token.startswith("<") or not re.match(r"[a-z_]", token):
            output.append(token)
    return output


def _simhash64(tokens: Iterable[str]) -> str:
    values = list(tokens)
    if not values:
        return "0" * 16
    weights = Counter(values)
    vector = [0] * 64
    for token, weight in weights.items():
        bits = int.from_bytes(hashlib.sha256(token.encode("utf-8")).digest()[:8], "big")
        for index in range(64):
            vector[index] += weight if bits & (1 << index) else -weight
    result = sum(1 << index for index, value in enumerate(vector) if value >= 0)
    return f"{result:016x}"


def simhash_similarity(left: str, right: str) -> float:
    """2つの64-bit SimHash間の0.0～1.0類似度を返す。"""

    if not re.fullmatch(r"[0-9a-f]{16}", left) or not re.fullmatch(
        r"[0-9a-f]{16}", right
    ):
        raise ValueError("simhash must be a 16-character hexadecimal value")
    distance = (int(left, 16) ^ int(right, 16)).bit_count()
    return round(1.0 - (distance / 64.0), 6)


def _string_list(value: Any, *, limit: int = 256) -> list[str]:
    if not isinstance(value, list):
        return []
    output = []
    for item in value:
        if isinstance(item, (str, int, float)):
            rendered = _redact_public_text(str(item)).strip()
            if rendered:
                output.append(rendered[:500])
        if len(output) >= limit:
            break
    return output


def _extract_calls(value: str) -> list[str]:
    output = []
    for name in re.findall(r"(?i)\b([a-z_][a-z0-9_.$@]*)\s*\(", value):
        lowered = name.casefold()
        if lowered in IGNORED_CALLS:
            continue
        normalized = "<auto>" if AUTO_SYMBOL_RE.fullmatch(lowered) else lowered
        if normalized not in output:
            output.append(normalized)
    return output[:256]


def _structural_identifier(value: str, *, prefix: str) -> str:
    """日本語レビュー項目を比較可能な安全な識別子へ変換する。"""

    normalized = normalize_logic_text(value)
    rendered = re.sub(r"[^a-z0-9_]+", "_", normalized).strip("_")
    if rendered and re.match(r"[a-z_]", rendered):
        return f"{prefix}_{rendered[:80]}"
    digest = hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:16]
    return f"{prefix}_{digest}"


def _review_structure_pseudocode(
    *,
    name: str,
    role: str,
    summary: str,
    steps: list[str],
    callees: list[str],
    api_calls: list[str],
) -> str:
    """生の逆コンパイル本文がないレビューから構造fingerprint入力を作る。"""

    calls = [
        _structural_identifier(name, prefix="function"),
        _structural_identifier(role, prefix="role"),
        _structural_identifier(summary, prefix="summary"),
    ]
    calls.extend(_structural_identifier(step, prefix="step") for step in steps)
    calls.extend(_structural_identifier(callee, prefix="callee") for callee in callees)
    calls.extend(_structural_identifier(api, prefix="api") for api in api_calls)
    return "\n".join(f"{call}();" for call in calls)


def _control_flow(value: str) -> dict[str, int]:
    lowered = value.casefold()
    return {
        "condition_count": len(re.findall(r"\bif\b|\bswitch\b|\bcase\b", lowered)),
        "loop_count": len(re.findall(r"\bfor(?:each)?\b|\bwhile\b|\bdo\b", lowered)),
        "exception_count": len(re.findall(r"\btry\b|\bcatch\b|\bexcept\b", lowered)),
        "return_count": len(re.findall(r"\breturn\b", lowered)),
    }


def normalize_function_record(record: Mapping[str, Any], index: int) -> dict[str, Any]:
    """レビュー済み関数recordを公開・比較用の標準形式へ変換する。"""

    name = str(record.get("name") or record.get("function_name") or f"function_{index:04d}")
    address = str(record.get("address") or record.get("offset") or record.get("token") or "unknown")
    function_id = str(record.get("function_id") or f"{name}@{address}")
    steps = _string_list(record.get("logic_steps_ja") or record.get("logic_steps"))
    role = str(record.get("role") or "unclassified")
    summary = _redact_public_text(
        str(record.get("summary_ja") or "処理内容は関数単位の追加レビューが必要です。")
    )[:1000]
    callees = _string_list(record.get("callees"))
    api_calls = _string_list(record.get("api_calls"))
    explicit_pseudocode = (
        record.get("pseudocode")
        or record.get("logic_text")
        or record.get("normalized_logic")
    )
    pseudocode = (
        str(explicit_pseudocode)
        if explicit_pseudocode
        else _review_structure_pseudocode(
            name=name,
            role=role,
            summary=summary,
            steps=steps,
            callees=callees,
            api_calls=api_calls,
        )
    )
    normalized = normalize_logic_text(pseudocode)
    tokens = semantic_tokens(pseudocode)
    calls = [call for call in _extract_calls(pseudocode) if call.casefold() != name.casefold()]
    for call in calls:
        if call != "<auto>" and call not in api_calls:
            api_calls.append(call)
    return {
        "function_id": function_id,
        "name": name,
        "address_or_token": address,
        "role": role,
        "summary_ja": summary,
        "logic_steps_ja": steps,
        "callers": _string_list(record.get("callers")),
        "callees": callees,
        "api_calls": api_calls[:256],
        "constants": _string_list(record.get("constants"), limit=64),
        "control_flow": (
            dict(record["control_flow"])
            if isinstance(record.get("control_flow"), Mapping)
            else _control_flow(pseudocode)
        ),
        "fingerprints": {
            "normalized_logic_sha256": hashlib.sha256(normalized.encode("utf-8")).hexdigest(),
            "semantic_sequence_sha256": hashlib.sha256(
                "\n".join(tokens).encode("utf-8")
            ).hexdigest(),
            "semantic_simhash64": _simhash64(tokens),
            "semantic_token_count": len(tokens),
        },
        "normalized_logic": normalized[:4000],
        "raw_pseudocode_exported": False,
        "evidence": {
            "source": str(record.get("source") or "analyst_review"),
            "tool": str(record.get("tool") or "unknown"),
            "program_selector": str(record.get("program_selector") or "not_recorded"),
            "confidence": str(record.get("confidence") or "review_required"),
        },
    }


def _decode_script(data: bytes, source_name: str) -> str | None:
    if len(data) > 2 * 1024 * 1024 or data.count(b"\x00") > max(4, len(data) // 100):
        return None
    suffix = Path(source_name).suffix.casefold()
    for encoding in ("utf-8-sig", "utf-16", "cp932", "latin-1"):
        try:
            text = data.decode(encoding)
        except UnicodeDecodeError:
            continue
        printable = sum(character.isprintable() or character.isspace() for character in text)
        if text and printable / len(text) >= 0.85:
            if suffix in SCRIPT_EXTENSIONS or re.search(
                r"(?i)(?:powershell|function\s+|#!/|createobject|wscript|frombase64string)",
                text,
            ):
                return text
    return None


def _logic_steps_for_script(body: str) -> list[str]:
    patterns = (
        (r"(?i)base64", "Base64表現を変換する処理を含みます。"),
        (r"(?i)\baes(?:-cbc|-gcm)?\b", "AES関連の復号・暗号処理を含みます。"),
        (r"(?i)\bxor\b|\^", "XORを用いる変換処理を含みます。"),
        (r"(?i)powershell", "PowerShell処理を構築または呼び出します。"),
        (r"(?i)process\.start|start-process|shellexecute|wscript\.shell", "子processまたはshellを起動する処理を含みます。"),
        (r"(?i)download|stringdownload|webclient|invoke-webrequest|curl|wget", "外部resourceを取得する処理を含みます。"),
        (r"(?i)regwrite|currentversion\\run|schtasks|startup", "永続化に関係する設定変更を含みます。"),
        (r"(?i)virtualalloc|writeprocessmemory|createremotethread", "memory確保またはprocess注入APIを扱います。"),
    )
    output = [description for pattern, description in patterns if re.search(pattern, body)]
    if re.search(r"(?i)\bif\b|\bswitch\b", body):
        output.append("条件分岐により処理経路を選択します。")
    if re.search(r"(?i)\bfor(?:each)?\b|\bwhile\b", body):
        output.append("反復処理を含みます。")
    return output


def extract_script_function_records(data: bytes, source_name: str) -> list[dict[str, Any]]:
    """scriptを実行せず、関数境界と比較用ロジックを上限付きで抽出する。"""

    text = _decode_script(data, source_name)
    if text is None:
        return []
    definitions = list(
        re.finditer(
            r"(?im)^\s*(?:function\s+([a-z_][\w.-]*)|def\s+([a-z_]\w*)\s*\(|"
            r"(?:async\s+)?function\s+([a-z_$][\w$]*)\s*\()",
            text,
        )
    )
    spans: list[tuple[str, str]] = []
    if definitions:
        for index, match in enumerate(definitions):
            name = next(value for value in match.groups() if value)
            end = definitions[index + 1].start() if index + 1 < len(definitions) else len(text)
            spans.append((name, text[match.start() : end][:100_000]))
    else:
        spans.append(("script_top_level", text[:200_000]))
    return [
        {
            "function_id": f"script:{name}",
            "name": name,
            "address": "script_token",
            "role": "script_top_level" if name == "script_top_level" else "script_function",
            "summary_ja": "静的script構文から抽出した処理単位です。",
            "logic_steps_ja": _logic_steps_for_script(body),
            "pseudocode": body,
            "callees": _extract_calls(body),
            "control_flow": _control_flow(body),
            "source": source_name,
            "tool": "bounded_script_static_parser",
            "program_selector": "not_applicable",
            "confidence": "automated_static_structure",
        }
        for name, body in spans[:512]
    ]


def build_static_logic_report(
    *,
    sha256: str,
    family: str | None,
    source_name: str,
    data: bytes | None = None,
    records: Iterable[Mapping[str, Any]] | None = None,
    analysis_source: str = "one_shot_static_analysis",
) -> dict[str, Any]:
    """reviewed recordまたはscript構造からcase単位のロジック成果物を構築する。"""

    digest = sha256.casefold()
    if not SHA256_RE.fullmatch(digest):
        raise ValueError("sha256 must be a 64-character hexadecimal value")
    source_records = list(records or [])
    automated = False
    if not source_records and data is not None:
        source_records = extract_script_function_records(data, source_name)
        automated = bool(source_records)
    functions = [
        normalize_function_record(record, index)
        for index, record in enumerate(source_records, start=1)
        if isinstance(record, Mapping)
    ]
    aliases: dict[str, str] = {}
    for item in functions:
        for alias in (
            item["function_id"],
            item["name"],
            item["address_or_token"],
        ):
            if alias and alias != "unknown":
                aliases.setdefault(alias.casefold(), item["function_id"])
    call_edges = sorted(
        {
            (item["function_id"], aliases[callee.casefold()])
            for item in functions
            for callee in item["callees"]
            if callee.casefold() in aliases
            and aliases[callee.casefold()] != item["function_id"]
        }
        | {
            (aliases[caller.casefold()], item["function_id"])
            for item in functions
            for caller in item["callers"]
            if caller.casefold() in aliases
            and aliases[caller.casefold()] != item["function_id"]
        }
    )
    review_complete = bool(functions) and all(
        item["role"] != "unclassified"
        and bool(item["logic_steps_ja"])
        and item["evidence"]["tool"] != "unknown"
        and item["evidence"]["program_selector"] != "not_recorded"
        and item["evidence"]["confidence"] != "review_required"
        for item in functions
    )
    if not functions:
        status = "function_analysis_required"
        limitations = [
            "関数境界、call graph、逆コンパイル結果はまだ記録されていません。",
            "binaryはGhidra MCP等による明示的な関数レビューが必要です。",
        ]
    elif automated:
        status = "automated_script_structure"
        limitations = [
            "script構文から自動抽出した処理単位であり、意味付けは追加レビューが必要です。",
            "生script本文は出力せず、正規化ロジックとfingerprintだけを保存しています。",
        ]
    elif not review_complete:
        status = "function_logic_review_required"
        limitations = [
            "役割、処理順、解析tool、program selector、確度のいずれかが未記録です。",
            "不足項目を補うまで関数ロジックのレビュー完了とは扱いません。",
        ]
    else:
        status = "reviewed_function_logic"
        limitations = [
            "fingerprint一致はコード共有の手掛かりであり、同一actorや同一campaignを単独では証明しません。"
        ]
    return {
        "schema_version": SCHEMA_VERSION,
        "case_id": f"sha256:{digest}",
        "sha256": digest,
        "family": family or "unknown",
        "analysis_source": analysis_source,
        "status": status,
        "coverage": {
            "function_count": len(functions),
            "call_edge_count": len(call_edges),
            "function_bodies_reviewed": bool(functions and not automated and review_complete),
            "call_graph_recorded": bool(call_edges),
        },
        "functions": functions,
        "call_edges": [
            {"caller": caller, "callee": callee} for caller, callee in call_edges
        ],
        "limitations": limitations,
        "safety": {
            "sample_executed": False,
            "network_contacted": False,
            "raw_pseudocode_exported": False,
        },
    }


def render_static_logic_markdown(report: Mapping[str, Any]) -> str:
    """関数ロジックreportを日本語の人向け成果物へ描画する。"""

    lines = [
        f"# 静的ロジック解析：{report['sha256']}",
        "",
        "関数・処理単位の役割、call関係、制御構造、正規化fingerprintを記録します。",
        "具体的なIOC、資格情報、生の逆コンパイル全文は含めません。",
        "",
        "## 解析状態",
        "",
        f"- 状態: `{report['status']}`",
        f"- ファミリー: `{report['family']}`",
        f"- 関数・処理単位: {report['coverage']['function_count']}",
        f"- 呼出関係: {report['coverage']['call_edge_count']}",
        "",
        "## 関数一覧",
        "",
        "| 関数ID | 役割 | 要約 | SimHash |",
        "|---|---|---|---|",
    ]
    for function in report.get("functions", []):
        summary = str(function["summary_ja"]).replace("|", "\\|")
        lines.append(
            f"| `{function['function_id']}` | `{function['role']}` | {summary} | "
            f"`{function['fingerprints']['semantic_simhash64']}` |"
        )
    if not report.get("functions"):
        lines.append("| - | - | 関数単位の静的解析が必要です。 | - |")
    for function in report.get("functions", []):
        lines.extend(
            [
                "",
                f"## `{function['function_id']}`",
                "",
                f"- アドレス／トークン: `{function['address_or_token']}`",
                f"- 役割: `{function['role']}`",
                f"- 要約: {function['summary_ja']}",
                f"- 呼出先: {', '.join(f'`{item}`' for item in function['callees']) or '未記録'}",
                f"- API／call: {', '.join(f'`{item}`' for item in function['api_calls']) or '未記録'}",
                f"- 正規化ロジック SHA-256: `{function['fingerprints']['normalized_logic_sha256']}`",
                f"- 意味列 SHA-256: `{function['fingerprints']['semantic_sequence_sha256']}`",
                f"- 意味列 SimHash64: `{function['fingerprints']['semantic_simhash64']}`",
                "",
                "### 処理順",
                "",
            ]
        )
        steps = function.get("logic_steps_ja", [])
        lines.extend(f"{index}. {step}" for index, step in enumerate(steps, start=1))
        if not steps:
            lines.append("- 処理順は追加レビューが必要です。")
    lines.extend(["", "## 制約", ""])
    lines.extend(f"- {item}" for item in report.get("limitations", []))
    lines.append("")
    return "\n".join(lines)


def load_function_records(path: Path) -> list[Mapping[str, Any]]:
    """review済みsource JSONから関数record配列を読込む。"""

    value = json.loads(path.read_text(encoding="utf-8-sig"))
    if isinstance(value, list):
        records = value
    elif isinstance(value, Mapping) and isinstance(value.get("functions"), list):
        records = value["functions"]
    else:
        raise ValueError("source JSON must be a function list or contain functions")
    if not all(isinstance(item, Mapping) for item in records):
        raise ValueError("all function records must be objects")
    return records
