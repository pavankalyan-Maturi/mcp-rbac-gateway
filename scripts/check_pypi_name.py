"""Check whether PyPI would reject a project name as too similar to an existing one.

PyPI normalizes names (drops ``.``, ``_`` and ``-``, lowercases, and treats
``l``/``i``/``1`` and ``o``/``0`` as identical), then rejects any name that collides
with an existing project. This script downloads the full simple index (about 45 MB)
and does the same comparison.

    python scripts/check_pypi_name.py mcp-rbac-gateway [more names...]

Exit code 0 means every name is free under that rule, 1 means at least one collides.
PyPI may still refuse a name for other reasons (prohibited names, standard-library
module names).
"""

from __future__ import annotations

import json
import re
import sys
import urllib.request

INDEX = "https://pypi.org/simple/"
_CONFUSABLE = str.maketrans({"o": "0", "l": "1", "i": "1"})


def ultranormalize(name: str) -> str:
    return re.sub(r"[-_.]+", "", name.lower()).translate(_CONFUSABLE)


def main(argv: list[str]) -> int:
    if not argv:
        print(__doc__)
        return 2
    request = urllib.request.Request(
        INDEX, headers={"Accept": "application/vnd.pypi.simple.v1+json"}
    )
    with urllib.request.urlopen(request, timeout=120) as resp:  # noqa: S310
        projects = [p["name"] for p in json.load(resp)["projects"]]
    taken: dict[str, list[str]] = {}
    for project in projects:
        taken.setdefault(ultranormalize(project), []).append(project)

    status = 0
    for name in argv:
        clash = taken.get(ultranormalize(name))
        if clash:
            status = 1
            print(f"{name}: TAKEN (collides with {', '.join(clash)})")
        else:
            print(f"{name}: free")
    return status


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
