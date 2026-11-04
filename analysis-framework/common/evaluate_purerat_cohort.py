#!/usr/bin/env python3
"""PureRAT／PureHVNC固定コホートを厳格に静的評価するCLI。"""

from __future__ import annotations

from collections.abc import Sequence

from evaluate_purelogs_cohort import main as evaluate_main
from pure_cohort_profiles import PURERAT_PROFILE


def main(argv: Sequence[str] | None = None) -> int:
    """PureRAT profileを固定し、共有評価engineを実行する。"""

    return evaluate_main(argv, profile=PURERAT_PROFILE)


if __name__ == "__main__":
    raise SystemExit(main())
