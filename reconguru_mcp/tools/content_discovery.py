"""content_discovery — directory/file brute-forcing via ffuf.

Fuzzes a host's URL space against a wordlist to find hidden directories and
files (admin panels, backups, configs, API paths). Discovered URLs are merged
into ``/workspace/urls.txt`` and detail is written to ``/workspace/content.json``.

**Tier 2** (active: many requests). Needs the ``ffuf`` binary + a wordlist (both
in the Docker image). Per-host — the brain points it at interesting hosts rather
than fuzzing everything. Supports `auth` for authenticated areas.
"""

from __future__ import annotations

import json

from .. import auth as _auth
from .. import scope, workspace
from ..app import mcp
from ..config import settings
from ..sandbox import run_tool
from ..validate import InvalidTarget, validate_target

URLS_FILE = "urls.txt"
OUT_FILE = "content.json"
TMP_OUT = "_ffuf_out.json"
DEFAULT_MATCH = "200,204,301,302,307,401,403"


@mcp.tool()
async def content_discovery(target: str, wordlist: str = "", extensions: str = "",
                            match_codes: str = "", auth: str = "", project: str = "") -> dict:
    """Brute-force directories/files on a host with ffuf.

    Args:
        target: A single host or URL to fuzz (e.g. "example.com" or
            "https://example.com"). The FUZZ keyword is appended as a path.
        wordlist: Path to a wordlist inside the container. Defaults to the
            configured content wordlist (SecLists common.txt).
        extensions: Optional comma-separated extensions to try, e.g.
            ".php,.bak,.old" (ffuf -e).
        match_codes: Comma-separated status codes to treat as hits. Defaults to
            common content codes (200,204,301,302,307,401,403).
        auth: Optional raw HTTP header(s) for authenticated fuzzing.

    Returns:
        An envelope: hits found, counts by status, newly added URLs, a sample,
        and the output file path. Full detail is written to content.json.
    """
    workspace.use_project(project, target)
    try:
        host = validate_target(target.split("://", 1)[-1].split("/", 1)[0])
    except InvalidTarget as e:
        return {"ok": False, "error": str(e)}
    if not scope.in_scope(host):
        return {"ok": False, "error": f"{host} is out of scope"}

    base = target if target.startswith(("http://", "https://")) else f"https://{host}"
    base = base.rstrip("/")
    wl = wordlist.strip() or settings.content_wordlist
    out_path = workspace.path(TMP_OUT)

    argv = [
        "ffuf", "-u", f"{base}/FUZZ", "-w", wl,
        "-mc", (match_codes.strip() or DEFAULT_MATCH),
        "-of", "json", "-o", str(out_path), "-s",
    ]
    if extensions.strip():
        argv += ["-e", extensions.strip()]
    argv += _auth.cli_args(auth)

    result = await run_tool(argv, timeout_s=settings.timeout_for("ffuf"))
    if not result.ok and "not installed" in (result.note or ""):
        return {
            "ok": False,
            "error": "ffuf binary not available — run in the Docker image",
            "note": result.note,
        }

    parsed = workspace.read_json(TMP_OUT, {}) or {}
    results = parsed.get("results", []) if isinstance(parsed, dict) else []
    hits = []
    by_status: dict[str, int] = {}
    for r in results:
        url = r.get("url", "")
        status = r.get("status")
        if url:
            hits.append({"url": url, "status": status, "length": r.get("length")})
            by_status[str(status)] = by_status.get(str(status), 0) + 1

    workspace.write_json(OUT_FILE, {host: hits})
    _, total_after, added = workspace.merge_lines(URLS_FILE, [h["url"] for h in hits])

    return {
        "ok": True,
        "target": host,
        "hits": len(hits),
        "by_status": dict(sorted(by_status.items())),
        "new_urls": added,
        "total_urls_known": total_after,
        "output_file": str(workspace.path(OUT_FILE)),
        "sample": [h["url"] for h in hits[:20]],
        "note": "",
    }
