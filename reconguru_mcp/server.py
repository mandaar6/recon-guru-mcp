"""Server entrypoint.

Loads all tools (so they register on the FastMCP instance), runs the
tool-poisoning registration linter, and runs the server.

Transport:
  * stdio (default) — the harness launches this process and talks over a pipe.
    This is what you use locally and while developing.
  * streamable-http — set RECONGURU_TRANSPORT=http to listen on a port instead,
    for a shared/remote deployment. Set RECONGURU_HTTP_AUTH_TOKEN to require a
    bearer token on that endpoint.
"""

from __future__ import annotations

import sys

from . import prompts  # noqa: F401 — registers the recon_help prompt
from .app import mcp
from .config import settings
from .linter import lint_mcp
from .tools import load_tools


def _log(msg: str) -> None:
    # Logs go to stderr so they never corrupt the stdio MCP channel on stdout.
    print(f"[reconguru-mcp] {msg}", flush=True, file=sys.stderr)


def main() -> None:
    loaded = load_tools()
    _log(f"loaded tool modules: {', '.join(loaded) or '(none)'}")

    # Registration linter: warn about suspicious tool metadata (tool poisoning).
    flagged = lint_mcp(mcp)
    for name, warns in flagged.items():
        for w in warns:
            _log(f"WARNING tool '{name}': {w}")
    if flagged:
        _log(f"registration linter flagged {len(flagged)} tool(s) — review before trusting them")

    transport = settings.transport.strip().lower()
    if transport in ("http", "streamable-http"):
        _run_http()
    else:
        mcp.run()  # stdio


def _run_http() -> None:
    """Serve over streamable-http, with optional bearer-token auth.

    FastMCP's ASGI app is wrapped with a small middleware that requires
    `Authorization: Bearer <RECONGURU_HTTP_AUTH_TOKEN>` on every request. With
    no token set the endpoint is unauthenticated (only safe behind network
    isolation), and we say so loudly.
    """
    import hmac

    import uvicorn
    from starlette.middleware.base import BaseHTTPMiddleware
    from starlette.responses import JSONResponse

    app = mcp.streamable_http_app()
    token = settings.http_auth_token

    if token:
        class _BearerAuth(BaseHTTPMiddleware):
            async def dispatch(self, request, call_next):
                header = request.headers.get("authorization", "")
                expected = f"Bearer {token}"
                # constant-time comparison to avoid token-timing leaks
                if not hmac.compare_digest(header, expected):
                    return JSONResponse({"error": "unauthorized"}, status_code=401)
                return await call_next(request)

        app.add_middleware(_BearerAuth)
        _log(f"HTTP transport on {settings.http_host}:{settings.http_port} — bearer auth ON")
    else:
        _log(f"WARNING: HTTP transport on {settings.http_host}:{settings.http_port} with no "
             "RECONGURU_HTTP_AUTH_TOKEN — endpoint is UNAUTHENTICATED. Set a token "
             "or keep it network-isolated.")

    uvicorn.run(app, host=settings.http_host, port=settings.http_port, log_level="warning")


if __name__ == "__main__":
    main()
