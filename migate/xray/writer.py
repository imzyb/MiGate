from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def write_xray_config(config: dict[str, Any], target: str | Path) -> Path:
    path = Path(target)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(config, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return path
