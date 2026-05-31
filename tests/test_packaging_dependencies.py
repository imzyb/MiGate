from __future__ import annotations

import tomllib
from pathlib import Path


def _project_dependencies() -> set[str]:
    data = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))
    return {dependency.split(">=", 1)[0].split("==", 1)[0] for dependency in data["project"]["dependencies"]}


def test_fastapi_form_runtime_dependency_is_declared() -> None:
    assert "python-multipart" in _project_dependencies()
