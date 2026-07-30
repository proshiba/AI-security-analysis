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
import itertools
import json
import os
import re
import subprocess
import sys
from collections import Counter
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


# IOC-LIST.md の種別・役割の表記はケースによって揺れる(`url`/`URL`、`ドメイン`/
# `Domain`/`Host`、役割は `c2` を含まない `beacon_or_tasking`、`file_exfiltration`、
# `credential_exfiltration` など)。ラベルの綴りに依存すると取りこぼすため、
# 値の形を主な判定材料にする。spec v1向けの厳密な型判定は
# `build_portal_index.py` の classify_value() 側に持つ。
HASH_OR_FILE_TYPES = {
    "sha256", "sha-256", "sha1", "sha-1", "md5", "imphash",
    "file_name", "filename", "ethereumアドレス",
}
NETWORK_TYPE_HINTS = {
    "接続先", "ドメイン", "domain", "url", "host", "hostname",
    "endpoint", "ip", "ipv4", "ipv6",
}
NETWORK_ROLE_HINTS = (
    "c2", "beacon", "tasking", "exfil", "distribution", "download",
    "stage", "host", "endpoint", "network", "config",
)
_URL_VALUE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*://\S+$")
_IPV4_VALUE_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_HOSTPORT_VALUE_RE = re.compile(r"^[A-Za-z0-9_.-]+:\d{1,5}$")
_HOSTNAME_VALUE_RE = re.compile(r"^[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)+$")


def is_network_indicator(entry: dict) -> bool:
    """IOC-LIST.mdの1行が、C2・通信欄へ出すネットワーク指標かを判定する。"""
    ioc_type = str(entry.get("type") or "").strip().lower()
    if ioc_type in HASH_OR_FILE_TYPES:
        return False
    value = str(entry.get("value") or "").strip()
    if not value:
        return False
    # 値の形だけで通信先と分かるものは、種別・役割の表記に関係なく採用する
    if (
        _URL_VALUE_RE.match(value)
        or _IPV4_VALUE_RE.match(value)
        or _HOSTPORT_VALUE_RE.match(value)
    ):
        return True
    # ホスト名の形は、ファイル名と紛れるため種別か役割の裏付けを要求する
    if not _HOSTNAME_VALUE_RE.match(value):
        return False
    role = str(entry.get("role") or "").strip().lower()
    return ioc_type in NETWORK_TYPE_HINTS or any(h in role for h in NETWORK_ROLE_HINTS)


def structured_network_values(iocs_json: dict) -> set[str]:
    """`iocs.json` の network 配列から通信先を組み立てる。

    IOC-LIST.mdは生成物で表記が揺れるが、この配列はhost/ip/domain/url/portを
    分けて持つ構造化データなので、取りこぼしを防ぐために併用する。
    """
    values: set[str] = set()
    for entry in iocs_json.get("network") or []:
        if not isinstance(entry, dict):
            continue
        url = str(entry.get("url") or "").strip()
        if url:
            values.add(url)
        host = str(entry.get("host") or entry.get("ip") or entry.get("domain") or "").strip()
        if not host:
            continue
        port = entry.get("port")
        values.add(f"{host}:{port}" if port else host)
    return values


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
                # OS依存のセパレータを避ける。Windows生成とCI(Linux)生成で
                # 出力が変わり、--check が環境によって落ちるため。
                "path": path.relative_to(rel_base).as_posix(),
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


# コード完全一致groupがこのcase数を超える場合、library/compiler由来の可能性が
# 高いためcase間リンクの生成対象から除外する。
CODE_GROUP_CASE_CAP = 20


def load_intel(known_shas: set[str]) -> dict:
    """intelligence調査が参照するcampaign相関候補とコード類似索引を集約する。

    - campaign候補: analysis-results/research/campaigns/correlated-*/campaigns.json
      の最新版(ディレクトリ名の辞書順末尾)を使う。
    - コード類似: catalog/code-similarity.json のexact group(意味トークン列の
      SHA-256完全一致)だけをcase間リンクへ集約する。SimHash近似は含めない。
    """
    campaigns: list[dict] = []
    labels: dict[str, list] = {}
    source = None

    camp_root = RESULTS / "research" / "campaigns"
    candidates = sorted(p for p in camp_root.glob("correlated-*") if p.is_dir())
    if candidates:
        latest = candidates[-1]
        source = latest.name
        data = read_json(latest / "campaigns.json") or {}
        for c in data.get("campaigns", []):
            cid = c.get("campaign_id")
            if not cid:
                continue
            cdir = latest / cid
            campaigns.append(
                {
                    "id": cid,
                    "classification": c.get("classification"),
                    "confidence": c.get("confidence"),
                    "families": c.get("families") or [],
                    "members": [m for m in (c.get("members") or []) if m in known_shas],
                    "member_count": c.get("member_count"),
                    "shared_indicators": c.get("shared_indicators") or [],
                    "shared_feature_ids": c.get("shared_feature_ids") or [],
                    "edge_count": c.get("edge_count"),
                    "max_pair_score": c.get("maximum_pair_score"),
                    "limitations": c.get("limitations") or [],
                    "path": cdir.relative_to(REPO_ROOT).as_posix() if cdir.is_dir() else None,
                    "rules": collect_rules(cdir / "rules", REPO_ROOT),
                    "readme": read_text(cdir / "README.md"),
                }
            )
        for sha, entries in (data.get("labels") or {}).items():
            if sha in known_shas:
                labels[sha] = [e.get("campaign_id") for e in entries if e.get("campaign_id")]

    code_links: list[list] = []
    code_meta = {"exact_groups": 0, "skipped_wide_groups": 0}
    cs = read_json(RESULTS / "catalog" / "code-similarity.json")
    if cs:
        rec_case = {
            r["record_id"]: r["sha256"]
            for r in cs.get("function_records", [])
            if r.get("record_id") and r.get("sha256")
        }
        pair_counts: Counter = Counter()
        for g in cs.get("exact_groups", []):
            cases = sorted({rec_case[m] for m in g.get("members", []) if m in rec_case})
            cases = [s for s in cases if s in known_shas]
            if len(cases) < 2:
                continue
            code_meta["exact_groups"] += 1
            if len(cases) > CODE_GROUP_CASE_CAP:
                code_meta["skipped_wide_groups"] += 1
                continue
            for a, b in itertools.combinations(cases, 2):
                pair_counts[(a, b)] += 1
        code_links = [
            [a, b, n]
            for (a, b), n in sorted(pair_counts.items(), key=lambda kv: -kv[1])
        ]

    return {
        "source": source,
        "campaigns": campaigns,
        "labels": labels,
        "code_links": code_links,
        "code_meta": code_meta,
    }


def detect_repo() -> dict | None:
    """GitHubリポジトリのHTML baseとbranchを推定する。

    GitHub Pagesのような軽量配信では成果物ファイル本体を同梱しないため、
    ケースの結果ディレクトリや成果物へのリンクをGitHub上の該当ファイルへ
    向ける。ローカル配信時に検出できなければNoneを返し、UIは相対パスへ
    フォールバックする。
    """
    slug = os.environ.get("MALDB_REPO_SLUG")
    if not slug:
        try:
            url = subprocess.run(
                ["git", "-C", str(REPO_ROOT), "remote", "get-url", "origin"],
                capture_output=True,
                text=True,
                check=True,
            ).stdout.strip()
            match = re.search(r"[/:]([^/:]+/[^/:]+?)(?:\.git)?$", url)
            if match:
                slug = match.group(1)
        except (OSError, subprocess.SubprocessError):
            slug = None
    if not slug:
        return None
    branch = os.environ.get("MALDB_REPO_BRANCH") or "main"
    return {"html_base": "https://github.com/" + slug, "branch": branch}


def _filesystem_case_index() -> dict[str, dict]:
    """UI対象の固定レイアウトcaseを実体から厳格に列挙する。"""

    discovered: dict[str, dict] = {}
    specifications = [
        (
            "malware/*/versions/*/cases/*",
            lambda parts: {
                "canonical_path": None,
                "case_id": None,
                "case_kind": "unclassified" if parts[1] == "unclassified" else "malware",
                "family": parts[1],
                "version_key": parts[3],
            },
        ),
        (
            "research/supply-chain/npm/axios-plain-crypto-js-2026/cases/*",
            lambda _parts: {
                "canonical_path": None,
                "case_id": None,
                "case_kind": "supply_chain_payload",
                "family": "npm-supply-chain",
                "version_key": None,
            },
        ),
    ]
    for pattern, identity_builder in specifications:
        for path in sorted(RESULTS.glob(pattern)):
            if not path.is_dir() or path.is_symlink():
                continue
            digest = path.name
            if not re.fullmatch(r"[0-9a-f]{64}", digest):
                raise ValueError(f"不正なcaseディレクトリ名です: {path}")
            if digest in discovered:
                raise ValueError(f"同一SHA-256のcaseが重複しています: {digest}")
            parts = path.relative_to(RESULTS).parts
            identity = identity_builder(parts)
            identity["canonical_path"] = path.relative_to(REPO_ROOT).as_posix()
            identity["case_id"] = f"sha256:{digest}"
            discovered[digest] = identity
    return discovered


def discover_cases() -> dict[str, dict]:
    """catalogと固定レイアウトの完全一致を検証し、正本の全case一覧を返す。"""

    catalog = read_json(RESULTS / "catalog" / "cases.json")
    if not isinstance(catalog, dict) or catalog.get("schema_version") != 1:
        raise ValueError("analysis-results/catalog/cases.json が不正です")
    catalog_cases = catalog.get("cases")
    if not isinstance(catalog_cases, dict):
        raise ValueError("catalog cases はmappingでなければなりません")
    filesystem_cases = _filesystem_case_index()
    catalog_ids = set(catalog_cases)
    filesystem_ids = set(filesystem_cases)
    missing = sorted(filesystem_ids - catalog_ids)
    extra = sorted(catalog_ids - filesystem_ids)
    if missing or extra:
        raise ValueError(
            "catalogとcase実体が一致しません: "
            f"未登録={len(missing)} {missing[:3]}, 実体なし={len(extra)} {extra[:3]}"
        )
    for digest, expected in filesystem_cases.items():
        entry = catalog_cases[digest]
        if not isinstance(entry, dict):
            raise ValueError(f"catalog entryがobjectではありません: {digest}")
        mismatched = [
            key for key, value in expected.items() if entry.get(key) != value
        ]
        if mismatched:
            raise ValueError(
                f"catalog identityがcase実体と一致しません: {digest}: {mismatched}"
            )
    return dict(catalog_cases)


def build() -> dict:
    cases_catalog = discover_cases()
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

        source = metadata.get("source")
        if not isinstance(source, dict):
            source = {"provider": source} if source else {}
        reported = source.get("reported_metadata") or {}
        attribution = metadata.get("attribution") or {}
        if not isinstance(attribution, dict):
            attribution = {}
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
            p.relative_to(case_dir).as_posix()
            for p in case_dir.rglob("*")
            if p.is_file()
        )

        case_history = history.get(sha, [])
        c2_values = sorted(
            {c for h in case_history for c in h["c2"]}
            | {e["value"] for e in ioc_entries if is_network_indicator(e)}
            | structured_network_values(iocs_json)
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
            "provider": source.get("provider"),
            "reported_signature": attribution.get("reported_signature"),
            "tags": attribution.get("reported_tags") or [],
            "collections": metadata.get("collections") or [],
            # "unknown" は情報を持たないため表示・グラフの対象から外す
            "campaign_type": features.get("campaign_type")
            if features.get("campaign_type") not in (None, "", "unknown")
            else None,
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
            # README見出しは「<名前> 解析概要」形式のため接尾辞を除いて表示名にする
            label = re.sub(r"[ 　]*(の)?解析概要$", "", title) if title else None
            fam["label"] = label or key
        fam["rules"] = collect_rules(fam_dir / "rules", REPO_ROOT)

    # 履歴のうちcatalogに載っていないもの(調査ページ等)は対象外とし、件数だけ持つ
    known_shas = set(cases_catalog)
    orphan_history = sum(1 for sha in history if sha not in known_shas)

    intel = load_intel(known_shas)

    stats = {
        "case_total": len(cases),
        "family_total": len(families),
        "ioc_total": sum(len(c["iocs"]) for c in cases),
        "rule_total": sum(len(f["rules"]) for f in families.values())
        + sum(len(c["rules"]) for c in cases),
        "history_total": sum(len(v) for v in history.values()),
        "orphan_history": orphan_history,
        "campaign_candidates": len(intel["campaigns"]),
        "code_links": len(intel["code_links"]),
    }

    return {
        "schema_version": 1,
        "repo": detect_repo(),
        "stats": stats,
        "families": families,
        "cases": cases,
        "intel": intel,
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
