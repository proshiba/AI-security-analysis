from __future__ import annotations

import sys
from pathlib import Path


AGENTTESLA = Path(__file__).parents[1] / "malware" / "agenttesla"
if str(AGENTTESLA) not in sys.path:
    sys.path.insert(0, str(AGENTTESLA))
