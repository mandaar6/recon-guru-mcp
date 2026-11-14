"""Target validation.

The `target` of any scan is the one input that matters for *scope* — "don't
scan something I'm not authorized to test." So it is always a separate, typed,
validated parameter, never folded into a free-form `extra_args` string.

We accept a hostname, an IP address, or a CIDR range, and reject anything
containing shell metacharacters or whitespace. Because tools are always run
with an argument *list* (never a shell string), this validation is defense in
depth rather than the sole barrier — but it keeps obviously malformed or
injection-shaped targets out entirely.
"""

from __future__ import annotations

import ipaddress
import re

# A conservative RFC-1123-ish hostname matcher: labels of 1-63 chars, no
# leading/trailing hyphen, total length <= 253.
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)"
    r"(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$"
)

# Characters that must never appear in a target. None of these are valid in a
# hostname/IP/CIDR, and all of them are meaningful to a shell — so rejecting
# them removes any ambiguity.
_DISALLOWED = set(" \t\r\n;|&$`<>()'\"\\!*?{}[]")


class InvalidTarget(ValueError):
    """Raised when a target is not a valid, in-scope hostname / IP / CIDR."""


def validate_target(target: str) -> str:
    """Return a cleaned target string, or raise InvalidTarget.

    Accepts: "example.com", "192.0.2.10", "2001:db8::1", "10.0.0.0/24".
    Rejects: empty strings, URLs with scheme/path, and anything containing
    shell metacharacters or whitespace.
    """
    t = (target or "").strip()
    if not t:
        raise InvalidTarget("target is empty")

    bad = _DISALLOWED.intersection(t)
    if bad:
        raise InvalidTarget(
            f"target contains disallowed characters {sorted(bad)!r}: {target!r}"
        )

    # Plain IP address (v4 or v6).
    try:
        ipaddress.ip_address(t)
        return t
    except ValueError:
        pass

    # CIDR network (e.g. 10.0.0.0/24). strict=False tolerates host bits set.
    if "/" in t:
        try:
            ipaddress.ip_network(t, strict=False)
            return t
        except ValueError:
            pass

    # Hostname.
    if _HOSTNAME_RE.match(t):
        return t

    # host:port — a hostname or IPv4 with an explicit port (web apps on
    # non-standard ports). IPv6 literals were already accepted above.
    if ":" in t:
        host, _, port = t.rpartition(":")
        if host and port.isdigit() and 1 <= int(port) <= 65535:
            try:
                validate_target(host)
                return t
            except InvalidTarget:
                pass

    raise InvalidTarget(
        f"target is not a valid hostname, IP address, or CIDR range: {target!r}"
    )
