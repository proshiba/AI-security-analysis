#!/usr/bin/env python3
"""旧import経路からNmap配下の正式adapterを参照する互換bridge。"""

from __future__ import annotations

import sys
from pathlib import Path

FRAMEWORK_ROOT = Path(__file__).resolve().parents[1]
if str(FRAMEWORK_ROOT) not in sys.path:
    sys.path.insert(0, str(FRAMEWORK_ROOT))

from nmap.nmap_c2_detector import probe_target_with_nmap  # noqa: E402

__all__ = ("probe_target_with_nmap",)
