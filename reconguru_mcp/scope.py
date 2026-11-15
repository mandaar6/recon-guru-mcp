"""Scope control — keep scans inside what you're authorized to test.

For bug bounty this is not optional: touching an out-of-scope host can break a
program's rules. `validate_target` already guards the *format* of a target;
this module adds the *authorization* layer on top.

Scope is read from two optional plain-text files (one pattern per line — the
format bug hunters already keep scope in), so there's no parser dependency and
they're trivial to generate:

    scope_include.txt   in-scope patterns (allowlist)
    scope_exclude.txt   out-of-scope patterns (denylist)

Each is read from TWO places and unioned: the workspace ROOT (a global scope
that applies to every target — this is where the setup script seeds them) and
the active target's own folder (an optional per-target addition). So you can set
one global boundary once, and still tighten or extend scope per engagement.

Pattern forms (case-insensitive):
    example.com            exact host
    *.example.com          host and any subdomain
    192.0.2.0/24           CIDR range (matched when the target is an IP)

Rules:
  * If an exclude file exists and the target matches it → OUT of scope.
  * If an include file exists and is non-empty, the target must match it to be
    IN scope. If no include file exists, everything not excluded is allowed
    (so scope is opt-in; a fresh clone isn't locked down by surprise).
"""

from __future__ import annotations

import ipaddress

from . import workspace

INCLUDE_FILE = "scope_include.txt"
EXCLUDE_FILE = "scope_exclude.txt"


def _matches(host: str, pattern: str) -> bool:
    host = host.strip().lower().rstrip(".")
    pattern = pattern.strip().lower().rstrip(".")
    if not host or not pattern:
        return False

    # CIDR pattern — only meaningful when the host is an IP address.
    if "/" in pattern:
        try:
            net = ipaddress.ip_network(pattern, strict=False)
            return ipaddress.ip_address(host) in net
        except ValueError:
            return False

    # Wildcard: "*.example.com" matches example.com and any subdomain.
    if pattern.startswith("*."):
        base = pattern[2:]
        return host == base or host.endswith("." + base)

    return host == pattern


def _patterns(name: str) -> list[str]:
    """Union a scope file from the workspace root (global) + the active target."""
    return workspace.read_root_lines(name) + workspace.read_lines(name)


def in_scope(host: str) -> bool:
    """Return True if `host` is allowed by the current scope files."""
    excludes = _patterns(EXCLUDE_FILE)
    if any(_matches(host, p) for p in excludes):
        return False

    includes = _patterns(INCLUDE_FILE)
    if includes:  # allowlist is active → must match something in it
        return any(_matches(host, p) for p in includes)

    return True  # no allowlist configured → allow anything not excluded


def filter_in_scope(hosts: list[str]) -> list[str]:
    """Keep only the in-scope hosts from a list (used by discovery tools)."""
    return [h for h in hosts if in_scope(h)]
