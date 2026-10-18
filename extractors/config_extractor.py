"""対応済みマルウェア設定抽出器を統合するCLIとディスパッチャー。"""

from __future__ import annotations

import argparse
import json
import os
import stat
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path

if __package__ in {None, ""}:
    # repository直下からfile pathで起動した場合も、module起動と同じimport
    # 境界にそろえる。検体や抽出器を実行する前のbootstrapだけを行う。
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from extractors.acrstealer import extract as extract_acrstealer
from extractors.agenttesla import extract as extract_agenttesla
from extractors.amadey import extract as extract_amadey
from extractors.amosstealer import extract as extract_amosstealer
from extractors.atlascross import extract as extract_atlascross
from extractors.darkcomet import extract as extract_darkcomet
from extractors.donutloader import extract as extract_donutloader
from extractors.formbook import extract as extract_formbook
from extractors.latrodectus import extract as extract_latrodectus
from extractors.lummastealer import extract as extract_lummastealer
from extractors.npm_supply_chain import extract as extract_npm_supply_chain
from extractors.profiled_family import extractor_for, load_profiles
from extractors.purehvnc import extract as extract_purehvnc
from extractors.purelogs import extract as extract_purelogs
from extractors.quasarrat import extract as extract_quasarrat
from extractors.remcosrat import extract as extract_remcosrat
from extractors.remusstealer import extract as extract_remusstealer
from extractors.shadowpad import extract as extract_shadowpad
from extractors.snakekeylogger import extract as extract_snakekeylogger
from extractors.spyglace import extract as extract_spyglace
from extractors.stealc import extract as extract_stealc
from extractors.unclassified.mx_go import extract as extract_mx_go
from extractors.valleyrat import extract as extract_valleyrat
from extractors.venomrat import extract as extract_venomrat
from extractors.vidar import extract as extract_vidar

Extractor = Callable[[bytes, str], dict]
MAX_INPUT_BYTES = 64 * 1024 * 1024

PROFILED_EXTRACTORS: dict[str, Extractor] = {
    family: extractor_for(family) for family in load_profiles()
}
EXTRACTORS: dict[str, Extractor] = {
    "acrstealer": extract_acrstealer,
    "agenttesla": extract_agenttesla,
    "amadey": extract_amadey,
    "atlascross": extract_atlascross,
    "amosstealer": extract_amosstealer,
    "npm_supply_chain": extract_npm_supply_chain,
    "formbook": extract_formbook,
    "latrodectus": extract_latrodectus,
    "lummastealer": extract_lummastealer,
    "donutloader": extract_donutloader,
    "purehvnc": extract_purehvnc,
    "purelogs": extract_purelogs,
    "remcosrat": extract_remcosrat,
    "remusstealer": extract_remusstealer,
    "spyglace": extract_spyglace,
    "shadowpad": extract_shadowpad,
    "stealc": extract_stealc,
    "valleyrat": extract_valleyrat,
    "venomrat": extract_venomrat,
    "vidar": extract_vidar,
    "mx-go": extract_mx_go,
    **PROFILED_EXTRACTORS,
    "snakekeylogger": extract_snakekeylogger,
    "darkcomet": extract_darkcomet,
    "quasarrat": extract_quasarrat,
}
ALIASES = {
    "acr-stealer": "acrstealer",
    "amos": "amosstealer",
    "atomicstealer": "amosstealer",
    "atlas": "atlascross",
    "latro": "latrodectus",
    "lumma": "lummastealer",
    "npm-supply-chain": "npm_supply_chain",
    "donut": "donutloader",
    "purerat": "purehvnc",
    "pure rat": "purehvnc",
    "pure_rat": "purehvnc",
    "pure-hvnc": "purehvnc",
    "pure hvnc": "purehvnc",
    "pure_hvnc": "purehvnc",
    "purelogsstealer": "purelogs",
    "pure-logs": "purelogs",
    "remcos": "remcosrat",
    "remus": "remusstealer",
    "spygrace": "spyglace",
    "shadow-pad": "shadowpad",
    "steal-c": "stealc",
    "venom": "venomrat",
    "mx_go": "mx-go",
    "async-rat": "asyncrat",
    "async rat": "asyncrat",
    "async_rat": "asyncrat",
    "valley-rat": "valleyrat",
    "valley rat": "valleyrat",
    "valley_rat": "valleyrat",
    "x-worm": "xworm",
    "quasar": "quasarrat",
    "quasar-rat": "quasarrat",
    "nj-rat": "njrat",
    "bladabindi": "njrat",
    "dark-comet": "darkcomet",
    "dc-rat": "dcrat",
    "redline": "redlinestealer",
    "snake": "snakekeylogger",
    "cloud eye": "guloader",
    "idatloader": "hijackloader",
}

AMBIGUOUS_ALIASES: dict[str, tuple[str, ...]] = {
    "pure": ("purehvnc", "purelogs"),
}


def normalize_family(value: str) -> str:
    """受理したファミリー別名を定義IDへ正規化する。"""
    lowered = value.strip().lower()
    return ALIASES.get(lowered, lowered)


def get_extractor(family: str) -> Extractor:
    """対応する抽出器を返し、未対応時は明確なエラーを送出する。"""
    normalized = normalize_family(family)
    if normalized in AMBIGUOUS_ALIASES:
        choices = ", ".join(AMBIGUOUS_ALIASES[normalized])
        raise ValueError(f"ambiguous family alias: {family}; choose one of: {choices}")
    if normalized not in EXTRACTORS:
        raise ValueError(
            f"unsupported family: {family}; supported: {', '.join(sorted(EXTRACTORS))}"
        )
    return EXTRACTORS[normalized]


def extract_file(family: str, sample: Path) -> dict:
    """検体を一度だけ読み込み、オフラインのファミリー抽出器を実行する。"""
    data = _read_bounded_regular_file(sample)
    return get_extractor(family)(data, sample.name)


def _read_bounded_regular_file(path: Path) -> bytes:
    """regular fileを単一handleから共通hard上限内で読み込む。"""

    path_stat = path.stat()
    if not stat.S_ISREG(path_stat.st_mode):
        raise ValueError("input must be a regular file")
    with path.open("rb") as stream:
        file_stat = os.fstat(stream.fileno())
        if not stat.S_ISREG(file_stat.st_mode):
            raise ValueError("input must be a regular file")
        if file_stat.st_size > MAX_INPUT_BYTES:
            raise ValueError("input exceeds the common byte limit")
        data = stream.read(MAX_INPUT_BYTES + 1)
    if len(data) > MAX_INPUT_BYTES:
        raise ValueError("input exceeds the common byte limit")
    return data


def _reject_input_output_alias(sample: Path, output: Path) -> None:
    """同一path、symlink解決先、既存hardlinkへの出力を拒否する。"""

    if sample.resolve(strict=False) == output.resolve(strict=False):
        raise ValueError("input and output must not refer to the same file")
    try:
        if sample.samefile(output):
            raise ValueError("input and output must not refer to the same file")
    except FileNotFoundError:
        return


def _write_json_atomic(path: Path, result: dict) -> None:
    """sampleをtruncateしないよう同一directoryの一時fileから置換する。"""

    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent,
        prefix=f".{path.name}.",
        suffix=".tmp",
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_name, path)
    except BaseException:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise


def build_parser() -> argparse.ArgumentParser:
    """統合抽出器CLIの引数解析器を構築する。"""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--family", required=True)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    """抽出器を1件実行し、決定的なJSONを書き出す。"""
    args = build_parser().parse_args(argv)
    _reject_input_output_alias(args.input, args.output)
    result = extract_file(args.family, args.input)
    _reject_input_output_alias(args.input, args.output)
    _write_json_atomic(args.output, result)
    print(
        json.dumps(
            {
                "output": str(args.output),
                "family": result["family"],
                "findings": len(result["findings"]),
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
