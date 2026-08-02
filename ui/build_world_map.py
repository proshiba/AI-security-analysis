#!/usr/bin/env python3
"""世界地図の輪郭を、外部ライブラリ不要のSVGパスとして ui/worldmap.js へ書き出す。

出典は Natural Earth (public domain) の `ne_110m_admin_0_countries`。
UIは外部CDNを一切読まないため、投影済みのパスを同梱します。

    python3 ui/build_world_map.py --source <geojson>   # 生成
    python3 ui/build_world_map.py --check              # 差分確認

投影は等距円筒(equirectangular)です。地図の輪郭とC2のプロット点へ同じ変換を
かけるので、点と国の位置は必ず一致します。
"""
from __future__ import annotations

import argparse
import json
import math
import sys
import urllib.request
from pathlib import Path

UI_ROOT = Path(__file__).resolve().parent
OUTPUT = UI_ROOT / "worldmap.js"
SOURCE_URL = (
    "https://raw.githubusercontent.com/nvkelso/natural-earth-vector/master"
    "/geojson/ne_110m_admin_0_countries.geojson"
)
ATTRIBUTION = "Natural Earth (public domain) / ne_110m_admin_0_countries"

# 南極は面積の割に情報量が無く、描画領域を圧迫するので緯度で切る
MIN_LAT = -58.0
MAX_LAT = 84.0
WIDTH = 1000.0
# 経度360度に対する幅から、緯度1度あたりの高さを揃える(等距円筒)
SCALE = WIDTH / 360.0
HEIGHT = round((MAX_LAT - MIN_LAT) * SCALE, 2)
# 出力サイズを抑えるための量子化とリング除去のしきい値(投影後の単位)
QUANTIZE = 1
MIN_RING_AREA = 0.12


def project(lon: float, lat: float) -> tuple[float, float]:
    x = (lon + 180.0) * SCALE
    y = (MAX_LAT - lat) * SCALE
    return x, y


def ring_area(points: list[tuple[float, float]]) -> float:
    total = 0.0
    for index in range(len(points)):
        x1, y1 = points[index]
        x2, y2 = points[(index + 1) % len(points)]
        total += x1 * y2 - x2 * y1
    return abs(total) / 2.0


def encode_ring(ring: list[list[float]]) -> str | None:
    points: list[tuple[float, float]] = []
    previous: tuple[float, float] | None = None
    for position in ring:
        lon = float(position[0])
        lat = max(MIN_LAT, min(MAX_LAT, float(position[1])))
        point = project(lon, lat)
        rounded = (round(point[0], QUANTIZE), round(point[1], QUANTIZE))
        if rounded != previous:
            points.append(rounded)
            previous = rounded
    if len(points) < 3 or ring_area(points) < MIN_RING_AREA:
        return None
    return "M" + "L".join(f"{x:g},{y:g}" for x, y in points) + "Z"


def polygons(geometry: dict) -> list[list[list[float]]]:
    kind = geometry.get("type")
    if kind == "Polygon":
        return geometry.get("coordinates") or []
    if kind == "MultiPolygon":
        rings: list[list[list[float]]] = []
        for polygon in geometry.get("coordinates") or []:
            rings.extend(polygon)
        return rings
    return []


def pick(properties: dict, *names: str) -> str | None:
    for name in names:
        value = properties.get(name)
        if isinstance(value, str) and value and value != "-99":
            return value
    return None


def build(geojson: dict) -> dict:
    countries: list[dict] = []
    for feature in geojson.get("features") or []:
        properties = feature.get("properties") or {}
        paths = [
            encoded
            for ring in polygons(feature.get("geometry") or {})
            if (encoded := encode_ring(ring))
        ]
        if not paths:
            continue
        countries.append(
            {
                "iso": pick(properties, "ISO_A3", "ISO_A3_EH", "ADM0_A3") or "",
                "cc": pick(properties, "ISO_A2", "ISO_A2_EH") or "",
                "name": pick(properties, "NAME_JA", "NAME_EN", "NAME", "ADMIN") or "",
                "d": "".join(paths),
            }
        )
    countries.sort(key=lambda item: (item["iso"], item["name"]))
    return {
        "attribution": ATTRIBUTION,
        "source_url": SOURCE_URL,
        "projection": "equirectangular",
        "width": WIDTH,
        "height": HEIGHT,
        "bounds": {"min_lon": -180.0, "max_lon": 180.0, "min_lat": MIN_LAT, "max_lat": MAX_LAT},
        "countries": countries,
    }


def render(payload: dict) -> str:
    return (
        "window.WORLD_MAP = "
        + json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
        + ";\n"
    )


def load_source(source: str | None) -> dict:
    if source and not source.startswith("http"):
        return json.loads(Path(source).read_text(encoding="utf-8"))
    url = source or SOURCE_URL
    with urllib.request.urlopen(url, timeout=60) as response:
        return json.loads(response.read().decode("utf-8"))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", help="GeoJSONのパスまたはURL(既定はNatural Earth 110m)")
    parser.add_argument("--check", action="store_true", help="既存 worldmap.js との差分を確認する")
    args = parser.parse_args()

    payload = render(build(load_source(args.source)))
    if args.check:
        if OUTPUT.is_file() and OUTPUT.read_text(encoding="utf-8") == payload:
            print("ui/worldmap.js is up to date.")
            return 0
        print("ui/worldmap.js is out of date. Run: python3 ui/build_world_map.py", file=sys.stderr)
        return 1

    OUTPUT.write_text(payload, encoding="utf-8")
    size_kb = OUTPUT.stat().st_size / 1024
    print(f"wrote {OUTPUT} ({size_kb:.0f} KiB)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
