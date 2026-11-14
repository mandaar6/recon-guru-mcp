"""url_collect — historical URLs for a domain via gau (getallurls).

Pulls known URLs from public archives (Wayback Machine, Common Crawl, OTX,
URLScan) for a domain — **passive (Tier 0)**, no traffic to the target. These
URLs seed content discovery and JS/secret analysis. Writes the deduplicated set
to ``/workspace/urls.txt``.

Needs the ``gau`` binary (in the Docker image); degrades gracefully if absent.
"""

from __future__ import annotations

from .. import scope, workspace
from ..app import mcp
from ..config import settings
from ..sandbox import run_tool
from ..validate import InvalidTarget, validate_target

URLS_FILE = "urls.txt"


@mcp.tool()
async def url_collect(target: str, include_subs: bool = True) -> dict:
    """Collect historical URLs for a domain from public archives (gau).

    Args:
        target: The root domain, e.g. "example.com".
        include_subs: Include subdomains' URLs too (gau --subs). Default True.

    Returns:
        An envelope: total URLs collected, how many were newly added, a sample,
        and the output file path. The full set is written to urls.txt.
    """
    try:
        domain = validate_target(target)
    except InvalidTarget as e:
        return {"ok": False, "error": str(e)}
    if not scope.in_scope(domain):
        return {"ok": False, "error": f"{domain} is out of scope"}

    argv = ["gau", "--threads", str(min(settings.max_concurrency, 10))]
    if include_subs:
        argv.append("--subs")
    argv.append(domain)

    result = await run_tool(argv, timeout_s=settings.timeout_for("gau"))
    if not result.ok and "not installed" in (result.note or ""):
        return {
            "ok": False,
            "error": "gau binary not available — run in the Docker image",
            "note": result.note,
        }

    urls = [
        ln.strip()
        for ln in result.stdout.splitlines()
        if ln.strip().startswith(("http://", "https://"))
    ]
    out_path, total_after, added = workspace.merge_lines(URLS_FILE, urls)

    return {
        "ok": True,
        "collected_this_run": len(set(urls)),
        "new": added,
        "total_known": total_after,
        "output_file": str(out_path),
        "sample": sorted(set(urls))[:20],
        "note": "" if result.ok else "gau exited non-zero; partial results kept",
    }
