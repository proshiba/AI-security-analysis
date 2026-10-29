#!/usr/bin/env python3
"""PureLogs／PureRAT固定コホートの共通静的評価CLI。"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence

from evaluate_purelogs_cohort import main as evaluate_main
from pure_cohort_profiles import PROFILES, get_profile


def main(argv: Sequence[str] | None = None) -> int:
    """allowlist済みprofileを選び、共有評価engineへ残りの引数を渡す。"""

    arguments = list(sys.argv[1:] if argv is None else argv)
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("-h", "--help", action="store_true")
    parser.add_argument("--profile", choices=sorted(PROFILES))
    args, remaining = parser.parse_known_args(arguments)
    if args.profile is None:
        if args.help:
            parser.print_help()
            print("\nprofileを選ぶとfamily固有の全オプションを表示します。")
            return 0
        parser.error("--profileを指定してください")
    if args.help:
        remaining.insert(0, "--help")
    return evaluate_main(remaining, profile=get_profile(args.profile))


if __name__ == "__main__":
    raise SystemExit(main())
