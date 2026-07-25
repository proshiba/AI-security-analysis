#!/usr/bin/env python3
"""マルウェア解析ブラウザUI用のデータファイル(ui/data.js)を生成する。

analysis-results/catalog/cases.json を正本として全caseを列挙し、
各caseの metadata.json / features.json / iocs.json / IOC-LIST.md / README.md、
ファミリ単位の文書(README/OSINT/TECHNICAL-ANALYSIS/VERSIONS等)と
YARA/Sigmaルール、analysis_history.yaml の解析履歴を統合する。

検体本体には一切触れず、リポジトリ内の公開可能な成果物だけを読み取る。

使い方:
    python3 ui/generate_ui_data.py            # ui/data.js を再生成
    python3 ui/generate_ui_data.py --check    # 差分があれば終了コード1
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
RESULTS = REPO_ROOT / "analysis-results"
OUTPUT = Path(__file__).resolve().parent / "data.js"

FAMILY_DOC_FILES = [
    ("readme", "README.md", "概要"),
    ("osint", "OSINT.md", "OSINT"),
    ("technical", "TECHNICAL-ANALYSIS.md", "技術解析"),
    ("versions", "VERSIONS.md", "版情報"),
    ("campaigns", "CAMPAIGNS.md", "キャンペーン"),
    ("behavior_c2", "BEHAVIOR-C2.md", "挙動・C2"),
]

# 全文をUIへ埋め込むcase文書。FEATURES.md/STATIC-LOGIC.mdは構造化データと
# 重複またはサイズ過大のため、ファイル一覧からのリンク参照に留める。
CASE_DOC_FILES = [
    ("readme", "README.md"),
]


def read_text(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None


def read_json(path: Path):
    text = read_text(path)
    if text is None:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None


def parse_ioc_list(md: str) -> list[dict]:
    """IOC-LIST.md の5列標準表(種別/値/役割/確度/根拠)を行ごとに読み取る。"""
    entries = []
    for line in md.splitlines():
        line = line.strip()
        if not line.startswith("|"):
            continue
        cells = [c.strip() for c in line.strip("|").split("|")]
        if len(cells) != 5:
            continue
        if cells[0].startswith("種別") or set(cells[0]) <= {"-", ":", " "}:
            continue
        value = cells[1].strip("`")
        if not value:
            continue
        entries.append(
            {
                "type": cells[0],
                "value": value,
                "role": cells[2],
                "confidence": cells[3],
                "source": cells[4],
            }
        )
    return entries


def collect_rules(rules_dir: Path, rel_base: Path) -> list[dict]:
    rules = []
    if not rules_dir.is_dir():
        return rules
    for path in sorted(rules_dir.rglob("*")):
        if not path.is_file():
            continue
        if path.suffix.lower() in (".yar", ".yara"):
            kind = "yara"
        elif path.suffix.lower() in (".yml", ".yaml"):
            kind = "sigma"
        else:
            continue
        text = read_text(path)
        if text is None:
            continue
        rules.append(
            {
                "kind": kind,
                "name": path.name,
                "path": str(path.relative_to(rel_base)),
                "text": text,
            }
        )
    return rules


def family_labels_from_index() -> dict[str, str]:
    """analysis-results/README.md のファミリ一覧から表示名を得る。"""
    labels: dict[str, str] = {}
    text = read_text(RESULTS / "README.md") or ""
    for match in re.finditer(r"^- \[(.+?)\]\(malware/([^/)]+)/README\.md\)", text, re.M):
        labels[match.group(2)] = match.group(1)
    return labels


def family_title_alias(readme: str | None) -> tuple[str | None, str | None]:
    if not readme:
        return None, None
    title = None
    alias = None
    for line in readme.splitlines():
        if title is None and line.startswith("# "):
            title = line[2:].strip()
        if alias is None and line.startswith("別名"):
            alias = line.split("：", 1)[-1].split(":", 1)[-1].strip()
    return title, alias


def load_history() -> dict[str, list[dict]]:
    data = yaml.safe_load(read_text(REPO_ROOT / "analysis_history.yaml") or "") or {}
    by_sha: dict[str, list[dict]] = {}
    for entry in data.get("analyses", []):
        sha = str(entry.get("sample_sha256") or "").lower()
        if not sha:
            continue
        by_sha.setdefault(sha, []).append(
            {
                "analyzed_at": str(entry.get("analyzed_at") or ""),
                "malware_type": entry.get("malware_type"),
                "analysis_level": entry.get("analysis_level"),
                "campaign_type": entry.get("campaign_type"),
                "matched_patterns": entry.get("matched_patterns") or [],
                "c2": [str(c) for c in (entry.get("c2") or [])],
                "notes": entry.get("notes"),
                "result_path": entry.get("result_path"),
            }
        )
    for items in by_sha.values():
        items.sort(key=lambda e: e["analyzed_at"], reverse=True)
    return by_sha


def build() -> dict:
    catalog = read_json(RESULTS / "catalog" / "cases.json") or {}
    cases_catalog: dict[str, dict] = catalog.get("cases", {})
    history = load_history()
    labels = family_labels_from_index()

    families: dict[str, dict] = {}
    cases: list[dict] = []

    for sha, cat in sorted(cases_catalog.items()):
        rel_path = cat.get("canonical_path") or ""
        case_dir = REPO_ROOT / rel_path
        family = cat.get("family") or "unclassified"
        metadata = read_json(case_dir / "metadata.json") or {}
        features = read_json(case_dir / "features.json") or {}
        iocs_json = read_json(case_dir / "iocs.json") or {}
        ioc_md = read_text(case_dir / "IOC-LIST.md")
        ioc_entries = parse_ioc_list(ioc_md) if ioc_md else []

        reported = (metadata.get("source") or {}).get("reported_metadata") or {}
        attribution = metadata.get("attribution") or {}
        assessment = features.get("analysis_assessment") or {}

        behaviors = [
            {
                "id": b.get("id"),
                "category": b.get("category"),
                "label": b.get("label"),
                "confidence": b.get("confidence"),
                "evidence": b.get("evidence"),
            }
            for b in features.get("behaviors") or []
        ]
        characteristics = [
            {
                "id": c.get("id"),
                "category": c.get("category"),
                "label": c.get("label"),
                "confidence": c.get("confidence"),
                "evidence": c.get("evidence"),
                "value": c.get("value"),
            }
            for c in features.get("sample_characteristics") or []
        ]

        docs = {}
        for key, filename in CASE_DOC_FILES:
            text = read_text(case_dir / filename)
            if text:
                docs[key] = text
        artifacts = sorted(
            str(p.relative_to(case_dir))
            for p in case_dir.rglob("*")
            if p.is_file()
        )

        case_history = history.get(sha, [])
        c2_values = sorted(
            {c for h in case_history for c in h["c2"]}
            | {
                e["value"]
                for e in ioc_entries
                if "c2" in e["role"].lower() or e["type"] in ("接続先", "ipv4", "ipv6", "ドメイン", "domain", "url")
            }
        )

        case = {
            "sha256": sha,
            "family": family,
            "version_key": cat.get("version_key") or "unknown",
            "case_kind": cat.get("case_kind"),
            "path": rel_path,
            "file_name": reported.get("file_name"),
            "file_type": reported.get("file_type"),
            "file_size": reported.get("file_size"),
            "first_seen": reported.get("first_seen"),
            "provider": (metadata.get("source") or {}).get("provider"),
            "reported_signature": attribution.get("reported_signature"),
            "tags": attribution.get("reported_tags") or [],
            "collections": metadata.get("collections") or [],
            "campaign_type": features.get("campaign_type"),
            "assessment": {
                "score": assessment.get("score"),
                "max": assessment.get("maximum_score"),
                "status": assessment.get("status"),
                "unresolved": assessment.get("unresolved") or [],
                "next_actions": assessment.get("next_actions") or [],
            },
            "behaviors": behaviors,
            "characteristics": characteristics,
            "iocs": ioc_entries,
            "ioc_assessment": iocs_json.get("assessment"),
            "c2": c2_values,
            "history": case_history,
            "rules": collect_rules(case_dir / "rules", REPO_ROOT),
            "docs": docs,
            "artifacts": artifacts,
        }
        cases.append(case)

        fam = families.setdefault(
            family,
            {
                "key": family,
                "label": labels.get(family),
                "title": None,
                "aliases": None,
                "docs": {},
                "doc_titles": {},
                "rules": [],
                "case_count": 0,
            },
        )
        fam["case_count"] += 1

    # ファミリ単位の文書とルール
    for key, fam in families.items():
        fam_dir = RESULTS / "malware" / key
        if not fam_dir.is_dir():
            continue
        for doc_key, filename, doc_title in FAMILY_DOC_FILES:
            text = read_text(fam_dir / filename)
            if text:
                fam["docs"][doc_key] = text
                fam["doc_titles"][doc_key] = doc_title
        title, aliases = family_title_alias(fam["docs"].get("readme"))
        fam["title"] = title
        fam["aliases"] = aliases
        if fam["label"] is None:
            fam["label"] = title or key
        fam["rules"] = collect_rules(fam_dir / "rules", REPO_ROOT)

    # 履歴のうちcatalogに載っていないもの(調査ページ等)は対象外とし、件数だけ持つ
    known_shas = set(cases_catalog)
    orphan_history = sum(1 for sha in history if sha not in known_shas)

    stats = {
        "case_total": len(cases),
        "family_total": len(families),
        "ioc_total": sum(len(c["iocs"]) for c in cases),
        "rule_total": sum(len(f["rules"]) for f in families.values())
        + sum(len(c["rules"]) for c in cases),
        "history_total": sum(len(v) for v in history.values()),
        "orphan_history": orphan_history,
    }

    return {
        "schema_version": 1,
        "stats": stats,
        "families": families,
        "cases": cases,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="既存data.jsとの差分を確認する")
    args = parser.parse_args()

    data = build()
    payload = "window.MALDB = " + json.dumps(
        data, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ) + ";\n"

    if args.check:
        current = read_text(OUTPUT)
        if current != payload:
            print("ui/data.js is out of date. Run: python3 ui/generate_ui_data.py", file=sys.stderr)
            return 1
        print("ui/data.js is up to date.")
        return 0

    OUTPUT.write_text(payload, encoding="utf-8")
    size_mb = OUTPUT.stat().st_size / (1024 * 1024)
    print(f"wrote {OUTPUT} ({size_mb:.1f} MiB)")
    print(json.dumps(data["stats"], ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
