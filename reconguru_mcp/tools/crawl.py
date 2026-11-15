"""crawl — active web crawling via katana.

Crawls live hosts to discover endpoints, parameters, and JavaScript files
(including by parsing JS). This is genuinely new vs recon-guru — it finds the
URLs that content-discovery, parameter, and JS-secret tools then work on.
Discovered URLs are merged into ``/workspace/urls.txt``.

**Tier 1–2** (active: it fetches and follows links). Needs the ``katana``
binary (in the Docker image); degrades gracefully if absent. Supports `auth`
for crawling behind a login.
"""

from __future__ import annotations

from .. import auth as _auth
from .. import scope, workspace
from ..app import mcp
from ..config import settings
from ..sandbox import run_tool
from ..validate import InvalidTarget, validate_target

SOURCE_DEFAULT = "live_hosts.txt"
URLS_FILE = "urls.txt"
TARGETS_TMP = "_katana_targets.txt"


def _to_url(host: str) -> str:
    return host if host.startswith(("http://", "https://")) else f"https://{host}"


@mcp.tool()
async def crawl(target: str = "", source_file: str = SOURCE_DEFAULT,
                depth: int = 2, auth: str = "", project: str = "") -> dict:
    """Crawl live hosts for endpoints and JS files (katana).

    Args:
        target: Optional single host/URL or comma-separated list. When empty,
            hosts are read from the workspace file.
        source_file: Workspace file to read hosts from when `target` is empty.
            Defaults to "live_hosts.txt" (what http_probe writes).
        depth: Crawl depth (katana -d). Default 2.
        auth: Optional raw HTTP header(s) to crawl behind a login, e.g.
            "Cookie: session=…". Overrides RECONGURU_AUTH_HEADER.

    Returns:
        An envelope: URLs discovered, newly added, JS-file count, a sample, and
        the output file path. The full set is merged into urls.txt.
    """
    workspace.use_project(project, target)
    if target.strip():
        raw = [h.strip() for h in target.split(",") if h.strip()]
    else:
        raw = workspace.read_lines(source_file)
        if not raw:
            return {
                "ok": False,
                "error": (
                    f"no hosts: workspace file '{source_file}' is empty. "
                    "Run http_probe first, or pass target=..."
                ),
            }

    # Validate the host part (strip scheme for the scope/format check).
    valid: list[str] = []
    for h in raw:
        bare = h.split("://", 1)[-1].split("/", 1)[0]
        try:
            validate_target(bare)
        except InvalidTarget:
            continue
        if scope.in_scope(bare):
            valid.append(h)
    if not valid:
        return {"ok": False, "error": "no valid, in-scope hosts to crawl"}

    urls = sorted({_to_url(h) for h in valid})
    targets_path = workspace.write_lines(TARGETS_TMP, urls)

    argv = [
        "katana", "-list", str(targets_path),
        "-silent", "-no-color", "-jc", "-d", str(depth),
        "-c", str(min(settings.max_concurrency, 10)),
    ] + _auth.cli_args(auth)

    result = await run_tool(argv, timeout_s=settings.timeout_for("katana"))
    if not result.ok and "not installed" in (result.note or ""):
        return {
            "ok": False,
            "error": "katana binary not available — run in the Docker image",
            "note": result.note,
        }

    found = [
        ln.strip()
        for ln in result.stdout.splitlines()
        if ln.strip().startswith(("http://", "https://"))
    ]
    out_path, total_after, added = workspace.merge_lines(URLS_FILE, found)
    js_count = sum(1 for u in set(found) if u.split("?")[0].endswith(".js"))

    return {
        "ok": True,
        "seeds": len(urls),
        "urls_found": len(set(found)),
        "new": added,
        "total_known": total_after,
        "js_files": js_count,
        "output_file": str(out_path),
        "sample": sorted(set(found))[:20],
        "note": "",
    }
