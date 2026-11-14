"""Authenticated recon — inject a user-supplied session into HTTP tools.

**The toolkit never logs in.** The user authenticates in their own browser (or
the harness's), and the resulting session cookie / bearer token is handed in —
per call via a tool's ``auth`` argument, or globally via
``RECONGURU_AUTH_HEADER``. It is injected as an HTTP header, kept in ``.env``
(git-ignored), and never logged (httpx request logging is silenced in config).

An auth value is one or more raw HTTP header lines, e.g.::

    Cookie: session=abc123
    Authorization: Bearer eyJhbGci...

(several lines separated by newlines). Precedence: a tool's per-call ``auth``
argument wins over the global ``RECONGURU_AUTH_HEADER``.
"""

from __future__ import annotations

from .config import settings


def resolve(per_call: str = "") -> str:
    """Return the effective auth value: per-call argument, else the config."""
    return per_call.strip() if per_call.strip() else settings.auth_header.strip()


def _lines(auth: str) -> list[str]:
    return [ln.strip() for ln in auth.splitlines() if ln.strip() and ":" in ln]


def header_dict(per_call: str = "") -> dict[str, str]:
    """{name: value} headers for an httpx client, from the resolved auth value."""
    out: dict[str, str] = {}
    for ln in _lines(resolve(per_call)):
        name, val = ln.split(":", 1)
        out[name.strip()] = val.strip()
    return out


def cli_args(per_call: str = "") -> list[str]:
    """['-H', 'Name: value', ...] for subprocess tools that accept -H headers."""
    args: list[str] = []
    for ln in _lines(resolve(per_call)):
        args += ["-H", ln]
    return args
