"""Shared workspace — the canonical files tools read from and write to.

The design rule: **bulk data chains between tools through files in the
workspace, not through the LLM.** A tool returns a small envelope (status +
counts + the path it wrote); the next tool reads that path. The harness's brain
orchestrates by *reference* — it never has to hold thousands of hosts in
context.

Canonical layout (under `settings.workspace_dir`, default `/workspace`):

    subdomains.txt     merged + deduped discovery output
    live_hosts.txt     httpx survivors
    urls.txt           crawled / historical URLs
    ports.json         naabu + nmap results
    findings/          one JSON file per structured finding (Stage 4)
    scope_include.txt  in-scope patterns (optional; see scope.py)
    scope_exclude.txt  out-of-scope patterns (optional; see scope.py)

Data hygiene — dedup, normalization, merging — happens here in deterministic
code, never in the LLM.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable

from .config import settings


def workspace_root() -> Path:
    """Return the workspace directory, creating it if needed.

    Falls back to a local `./workspace` when the configured dir (e.g.
    `/workspace` in Docker) isn't writable — handy for host-side dev and tests.
    """
    root = Path(settings.workspace_dir)
    try:
        root.mkdir(parents=True, exist_ok=True)
        return root
    except (OSError, PermissionError):
        local = Path.cwd() / "workspace"
        local.mkdir(parents=True, exist_ok=True)
        return local


def path(name: str) -> Path:
    """Resolve a canonical workspace file/dir name to an absolute Path."""
    return workspace_root() / name


# --- Line-list files (subdomains, hosts, urls) --------------------------

def read_lines(name: str) -> list[str]:
    """Read a workspace line-list file; empty list if it doesn't exist."""
    p = path(name)
    if not p.exists():
        return []
    return [
        line.strip()
        for line in p.read_text(encoding="utf-8", errors="ignore").splitlines()
        if line.strip()
    ]


def write_lines(name: str, items: Iterable[str]) -> Path:
    """Write a sorted, de-duplicated line-list file. Returns the path."""
    unique = sorted({i.strip() for i in items if i and i.strip()})
    p = path(name)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("\n".join(unique) + ("\n" if unique else ""), encoding="utf-8")
    return p


def merge_lines(name: str, new_items: Iterable[str]) -> tuple[Path, int, int]:
    """Union `new_items` into an existing line-list, deduped.

    Returns (path, total_after, added_count). This is how several discovery
    sources consolidate into one canonical file without duplicates.
    """
    existing = set(read_lines(name))
    before = len(existing)
    existing.update(i.strip() for i in new_items if i and i.strip())
    p = write_lines(name, existing)
    return p, len(existing), len(existing) - before


# --- JSON files (ports, structured data) --------------------------------

def read_json(name: str, default: Any = None) -> Any:
    """Read a workspace JSON file; `default` if missing or malformed."""
    p = path(name)
    if not p.exists():
        return default
    try:
        return json.loads(p.read_text(encoding="utf-8", errors="ignore"))
    except (json.JSONDecodeError, OSError):
        return default


def write_json(name: str, data: Any) -> Path:
    """Write `data` as pretty JSON to a workspace file. Returns the path."""
    p = path(name)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
    return p
