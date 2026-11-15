"""Shared workspace — the canonical files tools read from and write to.

The design rule: **bulk data chains between tools through files in the
workspace, not through the LLM.** A tool returns a small envelope (status +
counts + the path it wrote); the next tool reads that path. The harness's brain
orchestrates by *reference* — it never has to hold thousands of hosts in
context.

Per-target layout. The workspace root holds **global** files shared by every
scan, and each scan target gets its **own subfolder** so two targets never
collide:

    <root>/
      scope_include.txt    GLOBAL in-scope patterns (optional; see scope.py)
      scope_exclude.txt    GLOBAL out-of-scope patterns (optional)
      .active_project      pointer to the current target folder (managed here)
      <target>/            one folder per scanned target (e.g. example.com/)
        subdomains.txt     merged + deduped discovery output
        live_hosts.txt     httpx survivors
        urls.txt           crawled / historical URLs
        ports.json         naabu + nmap results
        http_probe.json    httpx detail
        findings/          one JSON file per structured finding
        findings.json      correlated, ranked findings
        report.html        generated report
        scope_include.txt  OPTIONAL per-target scope (added to the global one)

The active target is selected with `set_project()` (tools pass a `project=` or
let it derive from their target); every `path()` then resolves inside that
folder, so all the reads/writes below are namespaced with no per-tool change.
Data hygiene — dedup, normalization, merging — happens here in deterministic
code, never in the LLM.

NOTE: the active project is process-global state (a module var backed by the
`.active_project` pointer file). This assumes one scan is driven at a time,
which matches the single-brain, sequential tool-calling model. Pass an explicit
`project=` on every call to keep concurrent engagements apart.
"""

from __future__ import annotations

import json
import re
import threading
from pathlib import Path
from typing import Any, Iterable

from .config import settings

DEFAULT_PROJECT = "default"
POINTER_FILE = ".active_project"

_lock = threading.Lock()
_active_project: str | None = None


def workspace_root() -> Path:
    """Return the workspace ROOT directory, creating it if needed.

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


def _slug(value: str) -> str:
    """Turn a target (host / URL / IP) into a safe folder name, or "" if none.

    Strips scheme, path, query and a trailing :port, lowercases, and replaces
    anything outside [a-z0-9._-] with "_". "https://Example.com:8443/x" -> "example.com".
    """
    v = (value or "").strip().lower()
    if not v:
        return ""
    v = v.split("://", 1)[-1]          # drop scheme
    v = v.split("/", 1)[0]             # drop path
    v = v.split("?", 1)[0]             # drop query
    m = re.match(r"^(.*?):(\d+)$", v)  # drop a trailing :port (not IPv6-safe, fine here)
    if m:
        v = m.group(1)
    v = re.sub(r"[^a-z0-9._-]", "_", v).strip("._-")
    return v


def active_project() -> str:
    """The current target folder name — module var, else the pointer file, else default."""
    global _active_project
    if _active_project:
        return _active_project
    try:
        p = workspace_root() / POINTER_FILE
        if p.exists():
            name = p.read_text(encoding="utf-8").strip()
            if name:
                _active_project = name
                return name
    except OSError:
        pass
    return DEFAULT_PROJECT


def set_project(project: str = "", target: str = "") -> str:
    """Select the active per-target workspace folder and persist the choice.

    Precedence: an explicit `project` wins, else it's derived from `target`.
    If both are empty the current active project is left unchanged (so chained
    tools that only read a workspace file inherit the scan already in progress).
    Returns the active project name.
    """
    global _active_project
    name = _slug(project) or _slug(target)
    if not name:
        return active_project()
    with _lock:
        _active_project = name
        try:
            (workspace_root() / POINTER_FILE).write_text(name + "\n", encoding="utf-8")
        except OSError:
            pass
    return name


# Tools call this; kept as an alias for readability at call sites.
use_project = set_project


def project_root() -> Path:
    """The active target's folder (created on demand)."""
    root = workspace_root() / active_project()
    root.mkdir(parents=True, exist_ok=True)
    return root


def path(name: str) -> Path:
    """Resolve a canonical file/dir name inside the ACTIVE target's folder."""
    return project_root() / name


def root_path(name: str) -> Path:
    """Resolve a file at the workspace ROOT, shared across all targets."""
    return workspace_root() / name


def read_root_lines(name: str) -> list[str]:
    """Read a line-list file from the workspace ROOT (global, not per-target)."""
    p = root_path(name)
    if not p.exists():
        return []
    return [
        line.strip()
        for line in p.read_text(encoding="utf-8", errors="ignore").splitlines()
        if line.strip()
    ]


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
