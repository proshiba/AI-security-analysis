#!/usr/bin/env python3
"""静的解析証跡から全体ロジック文書とMermaid図を生成する。

図は観測済みの関係と未解決の関係を区別し、静的証跡にない実行順、
感染経路、親子関係を補完しない。
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any

MAX_EXECUTION_PHASES = 12
MAX_INFECTION_LAYERS = 16
MAX_MODULES = 12
SHA256_RE = re.compile(r"(?i)\b[0-9a-f]{64}\b")
IPV4_RE = re.compile(r"(?<![0-9])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9])")
URL_RE = re.compile(r"(?i)\b(?:https?|ftp)://[^\s]+")


def load_static_layers(case_dir: Path) -> dict[str, Any]:
    """caseの公開static-layers.jsonを読み、欠落時は空objectを返す。"""

    path = case_dir / "static-layers.json"
    if not path.is_file():
        return {}
    value = json.loads(path.read_text(encoding="utf-8-sig"))
    return value if isinstance(value, dict) else {}


def _safe_label(value: Any, *, limit: int = 96) -> str:
    """任意文字列をMermaidのquoted labelへ安全に埋め込める形へ整える。"""

    rendered = re.sub(r"\s+", " ", str(value or "")).strip()
    rendered = URL_RE.sub("[URL省略]", rendered)
    rendered = IPV4_RE.sub("[IP省略]", rendered)
    rendered = SHA256_RE.sub(
        lambda match: f"sha256:{match.group(0)[:12]}…",
        rendered,
    )
    rendered = rendered.translate(
        str.maketrans(
            {
                '"': "'",
                "`": "'",
                "<": "＜",
                ">": "＞",
                "[": "［",
                "]": "］",
                "{": "｛",
                "}": "｝",
                "|": "／",
                "\\": "／",
                "\x00": "",
            }
        )
    )
    return (rendered or "未記録")[:limit]


def _basename(value: Any) -> str:
    parts = re.split(r"[\\/]", str(value or ""))
    return parts[-1] if parts else ""


def _markdown_code(value: Any, *, limit: int = 512) -> str:
    """既存の公開識別子を省略せずMarkdownのinline codeへ整える。"""

    rendered = re.sub(r"\s+", " ", str(value or "")).strip()
    return (rendered.replace("`", "'") or "未記録")[:limit]

def _short_artifact_name(value: Any) -> str:
    name = _basename(value)
    if re.fullmatch(r"(?i)[0-9a-f]{64}(?:\.[a-z0-9._-]+)?", name):
        suffix = name[64:]
        return f"sha256:{name[:12]}…{suffix}"
    return _safe_label(name or "名称未記録", limit=64)


def _phase_records(report: Mapping[str, Any]) -> list[dict[str, str]]:
    overall = report.get("overall_logic")
    if not isinstance(overall, Mapping):
        return []
    output: list[dict[str, str]] = []
    for index, phase in enumerate(overall.get("phases", []), start=1):
        if not isinstance(phase, Mapping):
            continue
        phase_id = str(
            phase.get("phase_id")
            or phase.get("phase")
            or f"phase_{index:02d}"
        )
        output.append(
            {
                "phase_id": phase_id,
                "title": str(
                    phase.get("title_ja")
                    or phase.get("phase")
                    or f"処理段階{index}"
                ),
                "description": str(
                    phase.get("description_ja")
                    or phase.get("summary_ja")
                    or "説明未記録"
                ),
                "confidence": str(phase.get("confidence") or "unknown"),
            }
        )
    return output


def render_execution_flow_mermaid(report: Mapping[str, Any]) -> str:
    """観測call edgeだけを実線にした実行フロー図を返す。"""

    phases = _phase_records(report)
    shown = phases[:MAX_EXECUTION_PHASES]
    lines = ["```mermaid", "flowchart TD"]
    if not shown:
        lines.extend(
            [
                '  exec_target["解析対象"]',
                '  exec_unknown["実行フローは未解決"]',
                "  exec_target -.-> exec_unknown",
                "  class exec_target confirmed",
                "  class exec_unknown unresolved",
            ]
        )
    else:
        phase_nodes: dict[str, str] = {}
        for index, phase in enumerate(shown, start=1):
            node_id = f"exec_{index:02d}"
            phase_nodes[phase["phase_id"]] = node_id
            label = _safe_label(phase["title"])
            lines.append(f'  {node_id}["{label}"]')
        overall = report.get("overall_logic")
        raw_edges = (
            overall.get("observed_call_edges", [])
            if isinstance(overall, Mapping)
            else []
        )
        observed: set[tuple[str, str]] = set()
        for edge in raw_edges:
            if not isinstance(edge, Mapping):
                continue
            source = phase_nodes.get(str(edge.get("caller_phase") or ""))
            target = phase_nodes.get(str(edge.get("callee_phase") or ""))
            if source and target and source != target:
                observed.add((source, target))
        for source, target in sorted(observed):
            lines.append(f"  {source} --> {target}")
        connected = {node for edge in observed for node in edge}
        unresolved = [
            phase_nodes[phase["phase_id"]]
            for phase in shown
            if phase_nodes[phase["phase_id"]] not in connected
        ]
        if unresolved:
            lines.append('  exec_unknown["段階間の実行順は未解決"]')
            lines.extend(f"  exec_unknown -.-> {node}" for node in unresolved)
            lines.append("  class exec_unknown unresolved")
        if len(phases) > len(shown):
            if not unresolved:
                lines.append('  exec_unknown["段階間の実行順は未解決"]')
                lines.append("  class exec_unknown unresolved")
            lines.append(
                f'  exec_more["その他{len(phases) - len(shown)}段階は詳細節を参照"]'
            )
            lines.append("  exec_unknown -.-> exec_more")
            lines.append("  class exec_more unresolved")
        lines.append(
            "  class "
            + ",".join(phase_nodes.values())
            + " confirmed"
        )
    lines.extend(
        [
            "  classDef confirmed fill:#e8f5e9,stroke:#2e7d32,color:#1b1b1b",
            "  classDef unresolved fill:#fff8e1,stroke:#f9a825,color:#1b1b1b,stroke-dasharray:5 5",
            "```",
        ]
    )
    return "\n".join(lines)


def _layer_records(static_layers: Mapping[str, Any]) -> list[dict[str, Any]]:
    output = [
        dict(layer)
        for layer in static_layers.get("layers", [])
        if isinstance(layer, Mapping)
    ]
    return sorted(
        output,
        key=lambda item: (
            int(item.get("depth") or 0),
            str(item.get("name") or ""),
            str(item.get("sha256") or ""),
        ),
    )


def render_infection_chain_mermaid(
    report: Mapping[str, Any],
    static_layers: Mapping[str, Any] | None = None,
) -> str:
    """提出検体と静的復元層から感染チェーン図を返す。"""

    layers = _layer_records(static_layers or {})
    shown = layers[:MAX_INFECTION_LAYERS]
    lines = [
        "```mermaid",
        "flowchart TD",
        '  chain_initial["初期侵入・配布経路は未観測"]',
    ]
    if not shown:
        digest = str(report.get("sha256") or "")
        label = f"解析対象 / sha256:{digest[:12]}…" if digest else "解析対象"
        lines.extend(
            [
                f'  chain_target["{_safe_label(label)}"]',
                '  chain_unknown["後続stageは未解決"]',
                "  chain_initial -.-> chain_target",
                "  chain_target -.-> chain_unknown",
                "  class chain_target confirmed",
                "  class chain_initial,chain_unknown unresolved",
            ]
        )
    else:
        nodes_by_sha: dict[str, str] = {}
        root_nodes: list[str] = []
        child_count: dict[str, int] = {}
        for index, layer in enumerate(shown, start=1):
            node_id = f"chain_{index:02d}"
            digest = str(layer.get("sha256") or "")
            nodes_by_sha[digest] = node_id
            parent = str(layer.get("parent_sha256") or "")
            if parent:
                child_count[parent] = child_count.get(parent, 0) + 1
            else:
                root_nodes.append(node_id)
            depth = int(layer.get("depth") or 0)
            prefix = "提出検体" if depth == 0 else f"静的復元層 {depth}"
            label = (
                f"{prefix} / {_short_artifact_name(layer.get('name'))} / "
                f"{_safe_label(layer.get('format') or '形式不明', limit=24)}"
            )
            lines.append(f'  {node_id}["{_safe_label(label)}"]')
        for layer in shown:
            digest = str(layer.get("sha256") or "")
            parent = str(layer.get("parent_sha256") or "")
            source = nodes_by_sha.get(parent)
            target = nodes_by_sha.get(digest)
            if source and target:
                transform = _safe_label(
                    layer.get("transform") or "静的復元",
                    limit=32,
                )
                lines.append(f"  {source} -->|{transform}| {target}")
        lines.extend(f"  chain_initial -.-> {node}" for node in root_nodes)
        terminal_nodes = [
            nodes_by_sha[str(layer.get("sha256") or "")]
            for layer in shown
            if child_count.get(str(layer.get("sha256") or ""), 0) == 0
        ]
        if len(layers) > len(shown):
            lines.append(
                f'  chain_more["その他{len(layers) - len(shown)}層はstatic-layers.jsonを参照"]'
            )
            lines.extend(f"  {node} -.-> chain_more" for node in terminal_nodes)
            lines.append("  class chain_more unresolved")
        else:
            lines.append('  chain_unknown["後続stageは未解決"]')
            lines.extend(f"  {node} -.-> chain_unknown" for node in terminal_nodes)
            lines.append("  class chain_unknown unresolved")
        lines.append(
            "  class "
            + ",".join(nodes_by_sha.values())
            + " confirmed"
        )
        lines.append("  class chain_initial unresolved")
    lines.extend(
        [
            "  classDef confirmed fill:#e8f5e9,stroke:#2e7d32,color:#1b1b1b",
            "  classDef unresolved fill:#fff8e1,stroke:#f9a825,color:#1b1b1b,stroke-dasharray:5 5",
            "```",
        ]
    )
    return "\n".join(lines)


def _program_digest(program: Mapping[str, Any]) -> str:
    for field in ("program_id", "name", "program_selector"):
        match = SHA256_RE.search(str(program.get(field) or ""))
        if match:
            return match.group(0).casefold()
    return ""


def render_module_relationship_mermaid(
    report: Mapping[str, Any],
    static_layers: Mapping[str, Any] | None = None,
) -> str:
    """program evidenceとlayer親子関係からモジュール関係図を返す。"""

    programs = [
        dict(program)
        for program in report.get("program_evidence", [])
        if isinstance(program, Mapping)
    ]
    shown = programs[:MAX_MODULES]
    layers = {
        str(layer.get("sha256") or "").casefold(): layer
        for layer in _layer_records(static_layers or {})
    }
    lines = [
        "```mermaid",
        "flowchart TD",
        '  module_scope["解析対象のprogram構造"]',
    ]
    if not shown:
        lines.extend(
            [
                '  module_unknown["内包モジュール関係は未解決"]',
                "  module_scope -.-> module_unknown",
                "  class module_scope confirmed",
                "  class module_unknown unresolved",
            ]
        )
    else:
        nodes_by_digest: dict[str, str] = {}
        root_nodes: list[str] = []
        unresolved_nodes: list[str] = []
        for index, program in enumerate(shown, start=1):
            node_id = f"module_{index:02d}"
            digest = _program_digest(program)
            if digest:
                nodes_by_digest[digest] = node_id
            relationship = str(program.get("relationship") or "関係未記録")
            name = (
                program.get("name")
                or _basename(program.get("program_selector"))
                or program.get("program_id")
            )
            architecture = str(
                program.get("architecture")
                or program.get("language")
                or "architecture不明"
            )
            label = (
                f"{_short_artifact_name(name)} / {_safe_label(architecture, limit=32)} / "
                f"{_safe_label(relationship, limit=40)}"
            )
            lines.append(f'  {node_id}["{_safe_label(label)}"]')
            if "root" in relationship or "primary" in relationship:
                root_nodes.append(node_id)
            else:
                unresolved_nodes.append(node_id)
        linked_children: set[str] = set()
        for digest, target in nodes_by_digest.items():
            layer = layers.get(digest)
            if not isinstance(layer, Mapping):
                continue
            source = nodes_by_digest.get(
                str(layer.get("parent_sha256") or "").casefold()
            )
            if source and source != target:
                lines.append(f"  {source} -->|静的復元| {target}")
                linked_children.add(target)
        lines.extend(f"  module_scope --> {node}" for node in root_nodes)
        unresolved = [
            node for node in unresolved_nodes if node not in linked_children
        ]
        if unresolved:
            lines.append('  module_parent_unknown["復元元・親moduleは未特定"]')
            lines.extend(
                f"  module_parent_unknown -.-> {node}" for node in unresolved
            )
            lines.append("  class module_parent_unknown unresolved")
        if len(programs) > len(shown):
            lines.append(
                f'  module_more["その他{len(programs) - len(shown)}moduleはstatic-logic.jsonを参照"]'
            )
            lines.append("  module_scope -.-> module_more")
            lines.append("  class module_more unresolved")
        lines.append("  class module_scope confirmed")
        lines.append(
            "  class "
            + ",".join(f"module_{index:02d}" for index in range(1, len(shown) + 1))
            + " confirmed"
        )
    lines.extend(
        [
            "  classDef confirmed fill:#e8f5e9,stroke:#2e7d32,color:#1b1b1b",
            "  classDef unresolved fill:#fff8e1,stroke:#f9a825,color:#1b1b1b,stroke-dasharray:5 5",
            "```",
        ]
    )
    return "\n".join(lines)


def render_overall_logic_markdown(
    report: Mapping[str, Any],
    static_layers: Mapping[str, Any] | None = None,
) -> str:
    """全体ロジック、3種類の静的図、詳細な処理段階をMarkdownへ描画する。"""

    overall = report.get("overall_logic")
    overall = overall if isinstance(overall, Mapping) else {}
    functions = {
        str(item.get("function_id") or ""): item
        for item in report.get("functions", [])
        if isinstance(item, Mapping)
    }
    lines = [
        f"# 全体ロジック：{report.get('sha256') or '未記録'}",
        "",
        str(overall.get("summary_ja") or "全体ロジックを構成できませんでした。"),
        "",
        "## 読み方",
        "",
        f"- {overall.get('phase_order_basis') or '処理順の根拠は未記録です。'}",
        "- 図の実線は静的に観測した関係、点線と黄色のノードは未観測・未解決の関係を示します。",
        "- 図は静的な要約であり、動的実行を再現するものではありません。",
        "- 詳細な関数解説とfingerprintは[STATIC-LOGIC.md](STATIC-LOGIC.md)を参照してください。",
        "",
        "## 静的可視化",
        "",
        "### 実行フロー",
        "",
        render_execution_flow_mermaid(report),
        "",
        "### 感染チェーン",
        "",
        render_infection_chain_mermaid(report, static_layers),
        "",
        "### モジュール関係",
        "",
        render_module_relationship_mermaid(report, static_layers),
        "",
        "## 処理段階",
        "",
    ]
    phases = [
        phase
        for phase in overall.get("phases", [])
        if isinstance(phase, Mapping)
    ]
    if not phases:
        lines.extend(["- 処理段階は未解決です。", ""])
    for index, phase in enumerate(phases, start=1):
        title = str(
            phase.get("title_ja")
            or phase.get("phase")
            or f"処理段階{index}"
        )
        description = str(
            phase.get("description_ja")
            or phase.get("summary_ja")
            or "説明未記録"
        )
        lines.extend(
            [
                f"### {index}. {title}",
                "",
                description,
                f"確度: `{phase.get('confidence') or 'unknown'}`",
                "",
            ]
        )
        for function_id in phase.get("function_ids", []):
            function = functions.get(str(function_id), {})
            analysis = function.get("function_analysis", {})
            analysis = analysis if isinstance(analysis, Mapping) else {}
            selection = function.get("selection", {})
            selection = selection if isinstance(selection, Mapping) else {}
            reasons = selection.get("reasons", [])
            reason_text = (
                ", ".join(f"`{_safe_label(value)}`" for value in reasons)
                if isinstance(reasons, list)
                else ""
            )
            lines.append(
                f"- `{_markdown_code(function_id)}` — "
                f"{function.get('summary_ja') or '要約なし'} "
                f"状態: `{analysis.get('decompilation_status') or 'unknown'}`、"
                f"選定理由: {reason_text or '記録なし'}"
            )
        import_evidence = phase.get("import_evidence", [])
        if isinstance(import_evidence, list) and import_evidence:
            lines.append(
                "- import証跡: "
                + ", ".join(
                    f"`{_markdown_code(value)}`" for value in import_evidence
                )
            )
        lines.append("")
    lines.extend(["## 観測したcall関係", ""])
    edges = [
        edge
        for edge in overall.get("observed_call_edges", [])
        if isinstance(edge, Mapping)
    ]
    if not edges:
        lines.append("- 代表関数間で直接解決できた呼出関係はありません。")
    for edge in edges[:200]:
        lines.append(
            f"- `{_markdown_code(edge.get('caller'))}` → "
            f"`{_markdown_code(edge.get('callee'))}` "
            f"（`{_markdown_code(edge.get('caller_phase'))}` → "
            f"`{_markdown_code(edge.get('callee_phase'))}`）"
        )
    if len(edges) > 200:
        lines.append(
            f"- 残り{len(edges) - 200}件は`static-logic.json`に記録しています。"
        )
    limitations = overall.get("limitations_ja")
    if not isinstance(limitations, list):
        limitations = report.get("limitations", [])
    lines.extend(["", "## 解析範囲と制約", ""])
    if not limitations:
        lines.append("- 制約は未記録です。")
    else:
        lines.extend(f"- {value}" for value in limitations)
    lines.append("")
    return "\n".join(lines)
