from __future__ import annotations

"""Malware-Traffic-Analysis.netからWindows感染PCAPの取得候補を列挙する。"""

import argparse
import json
import re
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path


BASE = "https://www.malware-traffic-analysis.net/"
POST_RE = re.compile(r"/(?P<year>20\d{2})/(?P<month>\d{2})/(?P<day>\d{2})/index\.html$")


class AnchorParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.anchors: list[dict[str, str]] = []
        self._href: str | None = None
        self._text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() != "a":
            return
        values = dict(attrs)
        self._href = values.get("href")
        self._text = []

    def handle_data(self, data: str) -> None:
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "a" and self._href is not None:
            self.anchors.append({"href": self._href, "text": "".join(self._text).strip()})
            self._href = None
            self._text = []


def fetch(url: str) -> str:
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "AI-security-analysis/1.0 (+offline-PCAP-research)"},
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        return response.read().decode("utf-8", errors="replace")


def anchors(url: str) -> list[dict[str, str]]:
    parser = AnchorParser()
    parser.feed(fetch(url))
    return parser.anchors


def main() -> int:
    parser = argparse.ArgumentParser(description="公開日が新しい順にWindows感染系PCAPアーカイブの台帳を作成します。")
    parser.add_argument("--count", type=int, default=50)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--years", nargs="+", type=int, default=[2026, 2025, 2024])
    args = parser.parse_args()
    if args.count < 1:
        parser.error("--count は1以上にしてください")

    posts: dict[str, dict[str, str]] = {}
    for year in args.years:
        index_url = urllib.parse.urljoin(BASE, f"{year}/index.html")
        for item in anchors(index_url):
            url = urllib.parse.urljoin(index_url, item["href"])
            match = POST_RE.search(urllib.parse.urlparse(url).path)
            if not match:
                continue
            date = f"{match.group('year')}-{match.group('month')}-{match.group('day')}"
            posts[url] = {"date": date, "title": item["text"], "page_url": url}

    candidates: list[dict[str, str]] = []
    for post in sorted(posts.values(), key=lambda item: (item["date"], item["page_url"]), reverse=True):
        for item in anchors(post["page_url"]):
            url = urllib.parse.urljoin(post["page_url"], item["href"])
            path = urllib.parse.urlparse(url).path
            label = f"{Path(path).name} {item['text']}".lower()
            if not path.lower().endswith(".zip"):
                continue
            if "pcap" not in label:
                continue
            if any(word in label for word in ("screenshot", "image", "ioc", "malware-sample")):
                continue
            if any(word in label for word in ("scans-and-probes", "web-server", "macos", "shub-stealer", "amos-infection", "macsync-stealer", "android", "files-exported")):
                continue
            candidates.append(
                {
                    "published_date": post["date"],
                    "page_title": post["title"],
                    "page_url": post["page_url"],
                    "archive_url": url,
                    "archive_name": Path(path).name,
                    "link_text": item["text"],
                }
            )

    unique: list[dict[str, str]] = []
    seen: set[str] = set()
    for item in candidates:
        if item["archive_url"] in seen:
            continue
        seen.add(item["archive_url"])
        unique.append(item)

    selected = unique[: args.count]
    payload = {
        "schema_version": 1,
        "source": BASE,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "selection": "published_date_descending",
        "requested": args.count,
        "available": len(unique),
        "selected": len(selected),
        "items": selected,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({k: payload[k] for k in ("requested", "available", "selected")}, ensure_ascii=False))
    return 0 if len(selected) == args.count else 1


if __name__ == "__main__":
    raise SystemExit(main())
