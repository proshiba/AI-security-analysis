#!/usr/bin/env python3
"""ポータル連携仕様v1の静的インデックス(ui/api/v1/)を生成する。

`generate_ui_data.py` と同じ入力(catalog、caseディレクトリ、campaign相関、
analysis_history.yaml)から、横断ポータルが `fetch()` する軽量な索引を作る。
本文(README／STATIC-LOGIC／FEATURES)は含めず、結合キーになる値と最小限の
属性・関係だけを出力する。

`ui/data.js` は変更しない。UIはそちらに依存し続ける。

使い方:
    python3 ui/build_portal_index.py            # ui/api/v1/*.json を再生成
    python3 ui/build_portal_index.py --check    # 差分があれば終了コード1
    python3 ui/build_portal_index.py --validate # 仕様v1の自己検証のみ実行
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from generate_ui_data import REPO_ROOT, build  # noqa: E402

OUTPUT_DIR = Path(__file__).resolve().parent / "api" / "v1"
META_PATH = OUTPUT_DIR / "meta.json"
SEARCH_PATH = OUTPUT_DIR / "search.json"

SPEC_VERSION = "1.0"
APP_ID = "ai-security-analysis"
SITE_URL = "https://proshiba.github.io/AI-security-analysis/ui/"
REPOSITORY = "https://github.com/proshiba/AI-security-analysis"

# data.js のIOC種別 → 仕様v1のtype。ここに無い種別は索引へ入れない。
# file_name と Ethereumアドレス は結合キーとして誤結合を招くため除外する。
IOC_TYPE_MAP = {
    "sha256": "ioc.sha256",
    "SHA-256": "ioc.sha256",
    "sha1": "ioc.sha1",
    "md5": "ioc.md5",
    "url": "ioc.url",
    "URL": "ioc.url",
    "ipv4": "ioc.ipv4",
    "ipv6": "ioc.ipv6",
    "ドメイン": "ioc.domain",
    "domain": "ioc.domain",
    # 「接続先」は値の形から endpoint / ipv4 / domain を判定する
    "接続先": None,
}
EXCLUDED_IOC_TYPES = {"file_name", "Ethereumアドレス"}

# 指標ではないが過去のIOC-LIST生成で紛れ込んだ値。結合キーにすると誤結合するため除く。
# `http.title` はShodanのクエリfield名であり、ホスト名ではない。
NON_INDICATOR_VALUES = {"http.title"}

IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
IPV6_RE = re.compile(r"^[0-9A-Fa-f:]+:[0-9A-Fa-f:]*$")
HEX64_RE = re.compile(r"^[0-9A-Fa-f]{64}$")
HEX40_RE = re.compile(r"^[0-9A-Fa-f]{40}$")
HEX32_RE = re.compile(r"^[0-9A-Fa-f]{32}$")
URL_RE = re.compile(r"^([A-Za-z][A-Za-z0-9+.-]*)://(.+)$", re.S)
HOSTPORT_RE = re.compile(r"^([^\s:/?#]+):(\d{1,5})$")
HOSTNAME_RE = re.compile(r"^[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)+$")
TRANSPORT_SUFFIX_RE = re.compile(r"/(?:TCP|UDP)$", re.I)


def strip_transport(value: str) -> str:
    """`45.66.228.114:7000/TCP` のような表記から転送プロトコル接尾辞を落とす。"""
    return TRANSPORT_SUFFIX_RE.sub("", value.strip()).strip()


def classify_value(value: str) -> tuple[str, str] | None:
    """値から (type, 正規化済みvalue) を決める。索引対象外ならNone。"""
    raw = strip_transport(value)
    if not raw or raw in NON_INDICATOR_VALUES:
        return None

    match = URL_RE.match(raw)
    if match:
        # URLはスキームだけ小文字化し、パスの大小は保持する
        return "ioc.url", match.group(1).lower() + "://" + match.group(2)

    if IPV4_RE.match(raw):
        return "ioc.ipv4", raw
    if HEX64_RE.match(raw):
        return "ioc.sha256", raw.lower()
    if HEX40_RE.match(raw):
        return "ioc.sha1", raw.lower()
    if HEX32_RE.match(raw):
        return "ioc.md5", raw.lower()
    if "@" in raw and HOSTNAME_RE.match(raw.split("@")[-1]):
        return "ioc.email", raw.lower()

    match = HOSTPORT_RE.match(raw)
    if match:
        host = match.group(1).lower().rstrip(".")
        if IPV4_RE.match(host) or HOSTNAME_RE.match(host):
            return "ioc.endpoint", host + ":" + match.group(2)
        return None

    if IPV6_RE.match(raw) and raw.count(":") >= 2:
        return "ioc.ipv6", raw.lower()
    if HOSTNAME_RE.match(raw):
        return "ioc.domain", raw.lower().rstrip(".")
    return None


def classify_typed(declared_type: str, value: str) -> tuple[str, str] | None:
    """data.js の宣言済み種別を優先しつつ、値の形と矛盾する場合は値を信じる。"""
    if declared_type in EXCLUDED_IOC_TYPES:
        return None
    detected = classify_value(value)
    if detected is None:
        return None
    mapped = IOC_TYPE_MAP.get(declared_type)
    if mapped is None:
        # 未知種別と「接続先」は値からの判定に委ねる
        return detected
    # 宣言がhash種別で値も同じ長さのhexなら宣言を採用する。
    # それ以外で宣言と検出が食い違う場合(例: `ドメイン` にIPが入る)は検出を優先する。
    if mapped.startswith("ioc.sha") or mapped == "ioc.md5":
        return (mapped, detected[1]) if detected[0].startswith("ioc.") and re.fullmatch(
            r"[0-9a-f]+", detected[1]
        ) else detected
    if mapped == detected[0]:
        return detected
    return detected


def host_entity_of(entity_type: str, value: str) -> tuple[str, str] | None:
    """endpoint／URLから、単体のホストエンティティ(IPまたはドメイン)を導出する。

    これがないと `1.2.3.4:8080` と `1.2.3.4` が別物のまま残り、
    IPでのピボットが効かない。
    """
    host = None
    if entity_type == "ioc.endpoint":
        match = HOSTPORT_RE.match(value)
        if match:
            host = match.group(1)
    elif entity_type == "ioc.url":
        match = URL_RE.match(value)
        if match:
            host = re.split(r"[/?#]", match.group(2), 1)[0]
            host = host.split("@")[-1]  # userinfoは索引しない
            host = re.sub(r":\d+$", "", host)
    if not host:
        return None
    host = host.lower().rstrip(".")
    if IPV4_RE.match(host):
        return "ioc.ipv4", host
    if HOSTNAME_RE.match(host):
        return "ioc.domain", host
    return None


# 名前ではなく状態を表す語。単独では結合キーにしない。
QUALIFIER_TOKENS = {
    "暫定", "暫定名", "暫定分類", "暫定クラスタ", "候補", "系", "概要",
    "マルウェア概要", "解析概要", "クラスタ", "群",
}
# README見出し由来の接尾辞。ファミリ名の一部ではない。
TITLE_NOISE_RE = re.compile(r"(?:マルウェア)?(?:解析)?概要$")


# 名前の末尾に付く状態語。`TBOT候補` → `TBOT` のように落とす。
TRAILING_QUALIFIER_RE = re.compile(r"(?:候補|クラスタ|系|群|マルウェア)+$")


def _clean_name(name: str) -> str | None:
    name = name.strip().strip("　")
    stripped = TRAILING_QUALIFIER_RE.sub("", name).strip()
    if len(stripped) >= 3:
        name = stripped
    if len(name) < 3 or name in QUALIFIER_TOKENS:
        return None
    return name


def split_aliases(raw: str | None) -> list[str]:
    """別名フィールドの文字列を分解する。横串の精度に直結する。"""
    if not raw:
        return []
    out = []
    for part in re.split(r"[、,／]|\s{2,}", raw):
        cleaned = _clean_name(part)
        if cleaned and cleaned not in out:
            out.append(cleaned)
    return out


def derive_name_aliases(label: str) -> list[str]:
    """表示名から結合キーになる別名を導出する。

    このリポジトリの表示名には `ACRStealer／Amatera`、`CHUD Bot（暫定）`、
    `PUTA v3（Putita）マルウェア概要` のような形が混ざる。ポータルは
    英数字のみを小文字化して突き合わせるため、分解しないと結合できない。
    """
    base = TITLE_NOISE_RE.sub("", label).strip()
    parenthetical = re.findall(r"[（(]([^）)]*)[）)]", base)
    outside = re.sub(r"[（(][^）)]*[）)]", " ", base).strip()

    out: list[str] = []

    def push(name: str | None) -> None:
        cleaned = _clean_name(name or "")
        if cleaned and cleaned not in out:
            out.append(cleaned)

    for chunk in [outside, *parenthetical]:
        for part in re.split(r"[、,／]", chunk):
            part = part.strip()
            if not part:
                continue
            push(part)
            # ASCIIスラッシュは `PNG/registry cache loader` のように名前の区切り
            # でない場合がある。両側が空白を含まない短い名前のときだけ分解する。
            if "/" in part:
                sides = [s.strip() for s in part.split("/")]
                if all(s and " " not in s and len(s) >= 3 for s in sides):
                    for side in sides:
                        push(side)
    return out


def head_commit_time() -> str:
    """generated_at にHEADのcommit時刻を使い、再生成の冪等性を保つ。"""
    try:
        stamp = subprocess.run(
            ["git", "-C", str(REPO_ROOT), "log", "-1", "--format=%cd",
             "--date=format-local:%Y-%m-%dT%H:%M:%SZ"],
            capture_output=True,
            text=True,
            check=True,
            env={"TZ": "UTC", "PATH": "/usr/bin:/bin:/usr/local/bin"},
        ).stdout.strip()
        if stamp:
            return stamp
    except (OSError, subprocess.SubprocessError):
        pass
    return "1970-01-01T00:00:00Z"


class IocIndex:
    """値ごとに1エンティティへ畳み込み、観測元caseへのrefsを集約する。"""

    def __init__(self) -> None:
        self.entities: dict[str, dict] = {}

    def key(self, entity_type: str, value: str) -> str:
        return entity_type + "|" + value

    def add(self, entity_type: str, value: str, role: str | None, case_sha: str | None) -> str:
        eid = self.key(entity_type, value)
        entity = self.entities.get(eid)
        if entity is None:
            entity = {
                "type": entity_type,
                "id": eid,
                "label": value,
                "value": value,
                "detail": value,
                "_roles": [],
                "_refs": {},
            }
            self.entities[eid] = entity
        if role and role not in entity["_roles"]:
            entity["_roles"].append(role)
        if case_sha:
            target = "case:" + case_sha
            rel = role or "観測"
            entity["_refs"].setdefault(target, rel)
        return eid

    def link_host(self, entity_id: str, host_id: str) -> None:
        self.entities[entity_id]["_refs"].setdefault(host_id, "ホスト")


def build_entities(data: dict) -> list[dict]:
    entities: list[dict] = []
    own_hashes = {c["sha256"] for c in data["cases"]}

    # 1. case
    for case in data["cases"]:
        attrs = {}
        family_label = (data["families"].get(case["family"]) or {}).get("label") or case["family"]
        attrs["ファミリ"] = family_label
        if case.get("version_key") and case["version_key"] != "unknown":
            attrs["版"] = case["version_key"]
        if case.get("file_type"):
            attrs["形式"] = case["file_type"]
        if case.get("first_seen"):
            attrs["初観測"] = case["first_seen"]
        if case.get("provider"):
            attrs["提供元"] = case["provider"]
        if case.get("campaign_type"):
            attrs["分類"] = case["campaign_type"]
        status = (case.get("assessment") or {}).get("status")
        if status:
            attrs["判定"] = status
        if case.get("tags"):
            attrs["タグ"] = "、".join(case["tags"])
        entities.append(
            {
                "type": "case",
                "id": "case:" + case["sha256"],
                "label": case["sha256"],
                "value": case["sha256"],
                "detail": case["sha256"],
                "attrs": attrs,
                "refs": [{"rel": "ファミリ", "target": "family:" + case["family"]}],
            }
        )

    # 2. malware(ファミリ)
    for key, family in sorted(data["families"].items()):
        label = family.get("label") or family.get("title") or key
        aliases: list[str] = []
        for alias in split_aliases(family.get("aliases")) + derive_name_aliases(label):
            if alias != label and alias not in aliases:
                aliases.append(alias)
        if key != label and key not in aliases:
            aliases.append(key)
        attrs = {"ケース数": str(family.get("case_count") or 0)}
        if family.get("rules"):
            attrs["ルール数"] = str(len(family["rules"]))
        entity = {
            "type": "malware",
            "id": "family:" + key,
            "label": label,
            "value": label,
            "detail": key,
            "attrs": attrs,
        }
        if aliases:
            entity["aliases"] = aliases
        entities.append(entity)

    # 3. campaign(相関候補)
    for group in data["intel"]["campaigns"]:
        attrs = {}
        if group.get("classification"):
            attrs["分類"] = group["classification"]
        if group.get("confidence"):
            attrs["確度"] = group["confidence"]
        attrs["構成数"] = str(group.get("member_count") or len(group.get("members") or []))
        refs = [
            {"rel": "相関ケース", "target": "case:" + sha}
            for sha in group.get("members", [])
            if sha in own_hashes
        ]
        refs += [
            {"rel": "ファミリ", "target": "family:" + fam}
            for fam in group.get("families", [])
            if fam in data["families"]
        ]
        entities.append(
            {
                "type": "campaign",
                "id": "intel:" + group["id"],
                "label": group["id"],
                "value": group["id"],
                "detail": group["id"],
                "attrs": attrs,
                "refs": refs,
            }
        )

    # 4. ioc.*(IOC一覧とc2配列。同じ値は1エンティティへ畳む)
    index = IocIndex()

    def register(entity_type: str, value: str, role: str | None, case_sha: str | None) -> None:
        eid = index.add(entity_type, value, role, case_sha)
        host = host_entity_of(entity_type, value)
        if host:
            host_id = index.add(host[0], host[1], role, case_sha)
            if host_id != eid:
                index.link_host(eid, host_id)

    for case in data["cases"]:
        sha = case["sha256"]
        for entry in case["iocs"]:
            classified = classify_typed(entry.get("type", ""), entry.get("value", ""))
            if classified is None:
                continue
            entity_type, value = classified
            # 検体自身のhashはcaseエンティティと重複するため索引しない
            if entity_type.startswith("ioc.sha") and value in own_hashes:
                continue
            register(entity_type, value, entry.get("role"), sha)
        for raw in case.get("c2", []):
            classified = classify_value(raw)
            if classified is None:
                continue
            entity_type, value = classified
            if entity_type.startswith("ioc.sha") and value in own_hashes:
                continue
            register(entity_type, value, "C2/通信", sha)

    for entity in index.entities.values():
        roles = entity.pop("_roles")
        refs = entity.pop("_refs")
        if roles:
            entity["attrs"] = {"役割": "、".join(roles)}
        entity["refs"] = [{"rel": rel, "target": target} for target, rel in sorted(refs.items())]
        entities.append(entity)

    return entities


def build_meta(data: dict, entities: list[dict], generated_at: str) -> dict:
    counts = Counter(e["type"] for e in entities)
    ioc_total = sum(n for t, n in counts.items() if t.startswith("ioc."))
    return {
        "spec_version": SPEC_VERSION,
        "app_id": APP_ID,
        "name": "マルウェア解析",
        "description": "検体の静的解析結果・IOC・検出ルールの索引。",
        "generated_at": generated_at,
        "repository": REPOSITORY,
        "site_url": SITE_URL,
        "endpoints": {"search": "api/v1/search.json"},
        "deep_links": {
            "case": "#/case/{detail}",
            "malware": "#/family/{detail}",
            "campaign": "#/intel/{detail}",
            "ioc.ipv4": "#/iocs?q={detail}",
            "ioc.ipv6": "#/iocs?q={detail}",
            "ioc.domain": "#/iocs?q={detail}",
            "ioc.url": "#/iocs?q={detail}",
            "ioc.endpoint": "#/iocs?q={detail}",
            "ioc.md5": "#/iocs?q={detail}",
            "ioc.sha1": "#/iocs?q={detail}",
            "ioc.sha256": "#/iocs?q={detail}",
            "ioc.email": "#/iocs?q={detail}",
            # `_graph` は出さない。グラフ調査はポータル(research_bench)側の
            # workbenchに集約したため、ポータルの graphLink() がこちらへ
            # 送り出さないようにする。
        },
        "capabilities": ["iframe", "deep-link"],
        # iframe埋め込み時にポータル側のクロームと二重にならないよう、
        # このUIのヘッダー・フッターを隠す。
        "embed_css": (
            "header.topbar, footer.footer { display: none !important; } "
            "#app { padding-top: 0 !important; }"
        ),
        "stats": {
            "case": counts.get("case", 0),
            "malware": counts.get("malware", 0),
            "campaign": counts.get("campaign", 0),
            "ioc": ioc_total,
        },
    }


def validate(meta: dict, search: dict) -> tuple[list[str], list[str]]:
    """仕様v1の必須条件を自己検証する。(errors, warnings) を返す。"""
    errors: list[str] = []
    warnings: list[str] = []

    for field in ("spec_version", "app_id", "generated_at", "repository", "site_url",
                  "endpoints", "deep_links"):
        if field not in meta:
            errors.append(f"meta.json に必須フィールドがありません: {field}")
    if not str(meta.get("site_url", "")).endswith("/"):
        errors.append("meta.site_url は末尾スラッシュが必要です")
    if meta.get("endpoints", {}).get("search") != "api/v1/search.json":
        errors.append("meta.endpoints.search が site_url からの相対パスになっていません")

    entities = search.get("entities")
    if not isinstance(entities, list) or not entities:
        errors.append("search.entities が空です")
        return errors, warnings

    ids: set[str] = set()
    defang = re.compile(r"\[\.\]|\[:\]|hxxp|\(\.\)", re.I)
    with_value = 0
    types = Counter()

    for entity in entities:
        eid = entity.get("id")
        etype = entity.get("type")
        label = entity.get("label")
        types[etype] += 1
        for field in ("type", "id", "label"):
            if not entity.get(field):
                errors.append(f"必須フィールド欠落: {field} in {eid or entity}")
        if eid in ids:
            errors.append(f"id が重複しています: {eid}")
        ids.add(eid)
        value = entity.get("value", label)
        if value:
            with_value += 1
        for text in (str(value), str(label)):
            if defang.search(text):
                errors.append(f"defang表記が残っています: {eid} / {text}")
        for key in (entity.get("attrs") or {}):
            if key.startswith("_"):
                errors.append(f"attrs に `_` 始まりのキーがあります: {eid} / {key}")
        # 型ごとの表記ゆれ
        if etype in ("ioc.md5", "ioc.sha1", "ioc.sha256") and not re.fullmatch(
            r"[0-9a-f]+", str(value)
        ):
            errors.append(f"hash値が小文字16進ではありません: {eid}")
        if etype == "ioc.domain" and str(value) != str(value).lower().rstrip("."):
            errors.append(f"ドメインが正規化されていません: {eid}")
        if etype == "ioc.endpoint" and not HOSTPORT_RE.match(str(value)):
            errors.append(f"endpointが host:port 形式ではありません: {eid}")
        if etype and etype.startswith("ioc.") and TRANSPORT_SUFFIX_RE.search(str(value)):
            errors.append(f"/TCP または /UDP の接尾辞が残っています: {eid}")

    for entity in entities:
        for ref in entity.get("refs") or []:
            if ref.get("target") not in ids:
                errors.append(
                    f"refs.target が解決できません: {entity.get('id')} → {ref.get('target')}"
                )

    rate = with_value / len(entities) * 100
    if rate < 95:
        warnings.append(f"結合キー率が95%未満です: {rate:.1f}%")

    return errors, warnings


def dump(payload: dict) -> str:
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True) + "\n"


def read_json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="既存の索引との差分を確認する")
    parser.add_argument("--validate", action="store_true", help="仕様v1の自己検証だけを行う")
    args = parser.parse_args()

    data = build()
    entities = build_entities(data)
    generated_at = head_commit_time()
    meta = build_meta(data, entities, generated_at)
    search = {
        "spec_version": SPEC_VERSION,
        "app_id": APP_ID,
        "generated_at": generated_at,
        "entities": entities,
    }

    errors, warnings = validate(meta, search)
    counts = Counter(e["type"] for e in entities)
    summary = {
        "entities": len(entities),
        "by_type": dict(sorted(counts.items())),
        "meta_bytes": len(dump(meta).encode("utf-8")),
        "search_bytes": len(dump(search).encode("utf-8")),
    }

    if args.validate:
        print(json.dumps(summary, ensure_ascii=False, indent=2))
        for warning in warnings:
            print("WARNING: " + warning, file=sys.stderr)
        for error in errors:
            print("ERROR: " + error, file=sys.stderr)
        print(f"errors={len(errors)} warnings={len(warnings)}")
        return 1 if errors else 0

    if errors:
        for error in errors[:20]:
            print("ERROR: " + error, file=sys.stderr)
        print(f"仕様v1の検証に失敗しました: errors={len(errors)}", file=sys.stderr)
        return 1

    meta_text = dump(meta)
    search_text = dump(search)

    if args.check:
        stale = []
        # generated_at はHEAD commit時刻に追従するため比較から除外する
        for path, payload in ((META_PATH, meta), (SEARCH_PATH, search)):
            current = read_json(path)
            if current is None:
                stale.append(f"{path} がありません")
                continue
            expected = dict(payload)
            actual = dict(current)
            expected.pop("generated_at", None)
            actual.pop("generated_at", None)
            if dump(expected) != dump(actual):
                stale.append(f"{path} が最新ではありません")
        if stale:
            for item in stale:
                print(item, file=sys.stderr)
            print("Run: python3 ui/build_portal_index.py", file=sys.stderr)
            return 1
        print("ui/api/v1 is up to date.")
        return 0

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    META_PATH.write_text(meta_text, encoding="utf-8")
    SEARCH_PATH.write_text(search_text, encoding="utf-8")
    print(f"wrote {META_PATH} ({summary['meta_bytes']} B)")
    print(f"wrote {SEARCH_PATH} ({summary['search_bytes'] / 1024 / 1024:.2f} MiB)")
    print(json.dumps(summary["by_type"], ensure_ascii=False, indent=2))
    for warning in warnings:
        print("WARNING: " + warning, file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
