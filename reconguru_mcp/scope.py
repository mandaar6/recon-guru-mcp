"""Scope control — keep scans inside what you're authorized to test.

For bug bounty this is not optional: touching an out-of-scope host can break a
program's rules. `validate_target` already guards the *format* of a target;
this module adds the *authorization* layer on top.

Scope is read from two optional plain-text files in the workspace (one pattern
per line — the format bug hunters already keep scope in), so there's no parser
dependency and they're trivial to generate:

    scope_include.txt   in-scope patterns (allowlist)
    scope_exclude.txt   out-of-scope patterns (denylist)

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


def in_scope(host: str) -> bool:
    """Return True if `host` is allowed by the current scope files."""
    excludes = workspace.read_lines(EXCLUDE_FILE)
    if any(_matches(host, p) for p in excludes):
        return False

    includes = workspace.read_lines(INCLUDE_FILE)
    if includes:  # allowlist is active → must match something in it
        return any(_matches(host, p) for p in includes)

    return True  # no allowlist configured → allow anything not excluded


def filter_in_scope(hosts: list[str]) -> list[str]:
    """Keep only the in-scope hosts from a list (used by discovery tools)."""
    return [h for h in hosts if in_scope(h)]
