"""One name: the package installs `mcp_rbac_gateway` and the `mcp-rbac-gateway` command.

The old `mcp_sentinel` / `mcp-sentinel` names clash with the unrelated
`mcp-sentinel-cli` package, so they must not creep back into code or docs.
"""

from __future__ import annotations

import importlib.util
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OLD = re.compile(r"mcp[_-]sentinel(?![-_]cli)")
REPO_URL = "github.com/pavankalyan-Maturi/mcp-sentinel"


def files() -> list[Path]:
    out = [ROOT / "README.md", ROOT / "pyproject.toml", ROOT / "RELEASING.md"]
    for folder in ("src", "examples", "docs"):
        out += [
            p for p in (ROOT / folder).rglob("*") if p.suffix in {".py", ".md", ".yaml", ".json"}
        ]
    return [p for p in out if p.exists()]


def test_old_name_is_gone() -> None:
    hits = []
    for path in files():
        for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if OLD.search(line.replace(REPO_URL, "")):
                hits.append(f"{path.relative_to(ROOT)}:{n}: {line.strip()}")
    assert hits == []


def test_no_mcp_sentinel_module_is_shipped() -> None:
    assert importlib.util.find_spec("mcp_rbac_gateway") is not None
    assert not (ROOT / "src" / "mcp_sentinel").exists()
