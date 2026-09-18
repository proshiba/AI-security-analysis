"""同一コード系クリップボード置換PEの設定を実行せずに復元する。"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import struct
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

import pefile


PROFILE_ID = "clipboard_xor_pointer_table_20260918"
TEXT_SHA256 = "5a69a9aeb0a8c59178b755d9c28c9cf87b0003801198dfa7bf99f5a3edefb7e7"
IMPHASH = "c64a9aaa58707c34f0569020880351cb"

# 各長さは代表検体の全関数逆コンパイルと、46件の静的照合で確認する。
SLOTS: dict[int, tuple[str, int, str]] = {
    0: ("cardano", 103, r"addr1[ac-hj-np-z02-9]{98}"),
    1: ("bitcoin_cash", 42, r"q[ac-hj-np-z02-9]{41}"),
    3: ("bitcoin", 42, r"bc1[ac-hj-np-z02-9]{39}"),
    4: ("ethereum", 42, r"0x[0-9A-Fa-f]{40}"),
    5: ("litecoin", 43, r"ltc1[ac-hj-np-z02-9]{39}"),
    6: ("ton", 48, r"[A-Za-z0-9_-]{48}"),
    7: ("tron", 34, r"T[1-9A-HJ-NP-Za-km-z]{33}"),
    8: ("xrp", 34, r"r[1-9A-HJ-NP-Za-km-z]{33}"),
    9: ("monero", 95, r"[48][1-9A-HJ-NP-Za-km-z]{94}"),
}


class ProfileMismatch(ValueError):
    """既知コード系の構造または設定値と一致しない。"""


def decode_xor_string(raw: bytes, length: int) -> bytes:
    """4-byte鍵付き表をGhidraで確認した式だけで復号する。"""

    if length < 1 or length > 103 or len(raw) != length + 4:
        raise ProfileMismatch("符号化文字列の長さが不正です")
    return bytes(raw[index + 4] ^ raw[index % 4] for index in range(length))


def _section(pe: pefile.PE, name: bytes) -> Any:
    found = [part for part in pe.sections if part.Name.rstrip(b"\x00") == name]
    if len(found) != 1:
        raise ProfileMismatch(f"節{name!r}を一意に確認できません")
    return found[0]


def analyze_bytes(data: bytes) -> dict[str, Any]:
    """厳格に固定したPEコード系にだけ設定復号を適用する。"""

    if len(data) != 15360:
        raise ProfileMismatch("既知コード系のファイル長ではありません")
    try:
        pe = pefile.PE(data=data, fast_load=True)
        text_section = _section(pe, b".text")
        data_section = _section(pe, b".data")
        rdata_section = _section(pe, b".rdata")
        text_sha256 = hashlib.sha256(text_section.get_data()).hexdigest()
        if text_sha256 != TEXT_SHA256:
            raise ProfileMismatch("実行コード節が既知コード系と一致しません")
        pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]]
        )
        if pe.get_imphash() != IMPHASH:
            raise ProfileMismatch("import構造が既知コード系と一致しません")
        if data_section.VirtualAddress != 0x5000:
            raise ProfileMismatch("設定ポインタ表のRVAが一致しません")
        pointer_bytes = pe.get_data(0x5000, 80)
        if len(pointer_bytes) != 80:
            raise ProfileMismatch("設定ポインタ表が途中で切れています")
        pointers = struct.unpack("<10Q", pointer_bytes)
        image_base = pe.OPTIONAL_HEADER.ImageBase
        slot_results: list[dict[str, Any]] = []
        for slot, pointer in enumerate(pointers):
            rva = pointer - image_base
            length = SLOTS[slot][1] if slot in SLOTS else 1
            if not (
                rdata_section.VirtualAddress <= rva
                and rva + length + 4
                <= rdata_section.VirtualAddress + rdata_section.SizeOfRawData
            ):
                raise ProfileMismatch(f"slot {slot} の参照先が.rdata外です")
            raw = pe.get_data(rva, length + 4)
            value = decode_xor_string(raw, length)
            if not value[0]:
                slot_results.append({"slot": slot, "status": "disabled"})
                continue
            if slot not in SLOTS:
                raise ProfileMismatch(f"未知の有効slot {slot} を検出しました")
            kind, _, pattern = SLOTS[slot]
            try:
                decoded = value.decode("ascii")
            except UnicodeDecodeError as exc:
                raise ProfileMismatch(f"slot {slot} はASCIIで復号できません") from exc
            if re.fullmatch(pattern, decoded) is None:
                raise ProfileMismatch(f"slot {slot} の形式または長さが一致しません")
            slot_results.append(
                {"slot": slot, "status": "recovered", "asset": kind, "value": decoded}
            )
        config = {
            row["asset"]: row["value"]
            for row in slot_results
            if row["status"] == "recovered"
        }
        canonical = json.dumps(config, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        return {
            "schema_version": 1,
            "sha256": hashlib.sha256(data).hexdigest(),
            "profile_id": PROFILE_ID,
            "code_section_sha256": text_sha256,
            "imphash": IMPHASH,
            "config_sha256": hashlib.sha256(canonical.encode("ascii")).hexdigest(),
            "slots": slot_results,
            "wallet_count": len(config),
            "behavior": "clipboard_address_replacement",
            "family": "unresolved",
            "c2": "not_observed_in_reviewed_root_code",
            "evidence_boundary": {
                "same_code_proves_same_operator": False,
                "wallet_address_is_c2": False,
                "root_code_c2_assessment_is_live_confirmation": False,
            },
            "safety": {"sample_executed": False, "network_contacted": False},
        }
    except pefile.PEFormatError as exc:
        raise ProfileMismatch("PE構造を解析できません") from exc


def analyze_file(path: Path) -> dict[str, Any]:
    """検体をデータとしてのみ読み、ファイル名と内容のhashを照合する。"""

    if not re.fullmatch(r"[0-9a-f]{64}\.quarantine\.bin", path.name):
        raise ProfileMismatch("検体のファイル名がSHA-256形式ではありません")
    result = analyze_bytes(path.read_bytes())
    if result["sha256"] != path.name.split(".")[0]:
        raise ProfileMismatch("検体の名前と内容のSHA-256が一致しません")
    return result


def build_cluster(results: list[dict[str, Any]]) -> dict[str, Any]:
    """検体別設定と共通プロファイルを公開可能な形に集計する。"""

    if len({item["sha256"] for item in results}) != len(results):
        raise ValueError("重複した検体SHA-256があります")
    groups: dict[str, list[str]] = defaultdict(list)
    slot_counts: Counter[str] = Counter()
    for result in results:
        groups[result["config_sha256"]].append(result["sha256"])
        slot_counts.update(
            row["asset"] for row in result["slots"] if row["status"] == "recovered"
        )
    return {
        "schema_version": 1,
        "profile_id": PROFILE_ID,
        "code_section_sha256": TEXT_SHA256,
        "sample_count": len(results),
        "config_profile_count": len(groups),
        "wallet_slot_counts": dict(sorted(slot_counts.items())),
        "config_groups": [
            {"config_sha256": digest, "sample_count": len(hashes), "sha256": sorted(hashes)}
            for digest, hashes in sorted(groups.items(), key=lambda pair: (-len(pair[1]), pair[0]))
        ],
        "cases": sorted(results, key=lambda item: item["sha256"]),
        "safety": {"sample_executed": False, "network_contacted": False},
    }


def write_case_supplements(
    case_root: Path, output_root: Path, results: list[dict[str, Any]]
) -> None:
    """case本体のmanifestを変えずcollection配下へ補足を保存する。"""

    for result in results:
        sha256 = result["sha256"]
        case_dir = case_root / sha256
        if not case_dir.is_dir() or case_dir.is_symlink():
            raise ValueError(f"対象caseが存在しないかlinkです: {sha256}")
        supplement_dir = output_root / "supplements" / sha256
        supplement_dir.mkdir(parents=True, exist_ok=True)
        (supplement_dir / "clipboard-config.json").write_text(
            json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
        lines = [
            f"# クリップボード置換の追加静的解析：{sha256}",
            "",
            f"- 検体SHA-256: `{sha256}`",
            f"- 実行コード節SHA-256: `{result['code_section_sha256']}`",
            f"- 設定SHA-256: `{result['config_sha256']}`",
            f"- 回収した置換先: `{result['wallet_count']}`件",
            "- 検体実行・外部通信: なし",
            "",
            "Ghidraで全5関数を逆コンパイル済みの同一`.text`コード系です。入口関数は",
            "クリップボードの変化を待ち、取得したUnicode文字列を内部関数で置換した後、",
            "`SetClipboardData(CF_UNICODETEXT)`へ戻します。設定は`.data`のポインタ表と",
            "`.rdata`の4-byte XOR表から静的に復元しました。値は`clipboard-config.json`を参照してください。",
            "",
            "このroot codeでネットワークAPIやC2処理は確認されていません。ただし既存の",
            "`c2-analysis.json`は未解決のままであり、本補足は外部通信の実測やファミリー帰属を",
            "主張しません。同じコードと設定の共有だけで同一運営者とも判断しません。",
            "",
            "| 設定種別 | 状態 |",
            "|---|---|",
        ]
        for row in result["slots"]:
            label = row.get("asset", f"slot_{row['slot']}")
            lines.append(f"| `{label}` | `{row['status']}` |")
        lines.append("")
        (supplement_dir / "CLIPBOARD-ANALYSIS.md").write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    """私有入力を読み取り、指定した公開可能なJSONと日本語要約を生成する。"""

    parser = argparse.ArgumentParser(description="既知コード系クリップボード置換PEを静的に一括解析します。")
    parser.add_argument("--input-dir", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--case-root", type=Path)
    args = parser.parse_args()
    paths = sorted(args.input_dir.glob("*.quarantine.bin"))
    results = []
    for path in paths:
        try:
            results.append(analyze_file(path))
        except ProfileMismatch:
            continue
    if not results:
        raise SystemExit("一致する検体がありません")
    cluster = build_cluster(results)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    if args.case_root is not None:
        write_case_supplements(args.case_root, args.output_dir, results)
    (args.output_dir / "clipboard-hijacker-cluster.json").write_text(
        json.dumps(cluster, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    lines = [
        "# クリップボード置換コード系の追加静的解析",
        "",
        f"- 対象検体: `{cluster['sample_count']}`件",
        f"- 独立した設定組: `{cluster['config_profile_count']}`種類",
        f"- 共通`.text` SHA-256: `{TEXT_SHA256}`",
        "- 検体実行・外部通信: なし",
        "",
        f"{cluster['sample_count']}件の同一`.text`と同一import構造を確認し、`.data`の10ポインタから",
        "`.rdata`の4-byte XOR表を静的に復号しました。設定の全値と検体別対応は",
        "`clipboard-hijacker-cluster.json`に記録しています。ウォレットアドレスは",
        "送金先候補であり、C2 endpointとして扱いません。コード一致だけで同一運営者とも判断しません。",
        "",
        "入口関数は`GetClipboardSequenceNumber`で変化を監視し、`GetClipboardData`で取得した",
        "Unicode文字列を内部の置換関数へ渡します。置換時は`EmptyClipboard`と",
        "`SetClipboardData(CF_UNICODETEXT)`で内容を書き換えます。`Sleep(1)`を含む",
        "無限ループがあり、長時間常駐する設計です。共通の5関数はGhidraで全件解析済みです。",
        "静的に調べたroot codeにネットワークAPIやC2処理は確認されませんでした。",
        "ただしファミリー名、配布経路、実環境での動作は未確認です。",
        "",
        "## 設定組別件数",
        "",
        "| 設定SHA-256 | 検体数 |",
        "|---|---:|",
    ]
    for group in cluster["config_groups"]:
        lines.append(f"| `{group['config_sha256']}` | {group['sample_count']} |")
    lines.extend(["", "## 設定スロット別件数", "", "| 種別 | 検体数 |", "|---|---:|"])
    for kind, count in cluster["wallet_slot_counts"].items():
        lines.append(f"| `{kind}` | {count} |")
    lines.extend(["", "## 検体別の補足解析", "", "| 検体SHA-256 | 設定SHA-256 | 置換先件数 |", "|---|---|---:|"])
    for item in cluster["cases"]:
        case_link = f"supplements/{item['sha256']}/CLIPBOARD-ANALYSIS.md"
        lines.append(
            f"| [`{item['sha256']}`]({case_link}) | `{item['config_sha256']}` | "
            f"{item['wallet_count']} |"
        )
    lines.append("")
    (args.output_dir / "CLIPBOARD-HIJACKER-CLUSTER.md").write_text(
        "\n".join(lines), encoding="utf-8"
    )
    print(json.dumps({"sample_count": len(results), "config_profile_count": len(cluster["config_groups"])}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
