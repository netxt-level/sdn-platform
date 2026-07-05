from __future__ import annotations

import sys
from pathlib import Path


ANALYZER_ROOT = Path(__file__).resolve().parents[1]
if str(ANALYZER_ROOT) not in sys.path:
    sys.path.insert(0, str(ANALYZER_ROOT))
