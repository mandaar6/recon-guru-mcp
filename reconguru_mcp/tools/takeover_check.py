"""takeover_check — subdomain takeover detection via nuclei takeover templates.

Flags subdomains whose DNS points at an unclaimed third-party service (dangling
CNAME → takeoverable). Uses nuclei's `takeover`-tagged templates (no extra
binary) and annotates each hit with the CNAME recorded by ``dns_enum``, which
is the signal that makes a takeover actionable. Results → ``/workspace/takeover.json``
and into the findings model via ``collect_findings``. **Tier 3** (read-only).
"""

from __future__ import annotations

from .. import scope, workspace
from ..app import mcp
from ..validate import InvalidTarget, validate_target
from .vuln_scan import run_nuclei

SOURCE_DEFAULT = "subdomains.txt"
OUT_FILE = "takeover.json"


@mcp.tool()
async def takeover_check(target: str = "", source_file: str = SOURCE_DEFAULT, project: str = "") -> dict:
    """Check subdomains for takeover (dangling CNAME) with nuclei.

    Args:
        target: Optional single host or comma list. When empty, hosts are read
            from the workspace file.
        source_file: Workspace file to read hosts from when `target` is empty.
            Defaults to "subdomains.txt".

    Returns:
        An envelope: hosts checked, takeovers flagged (with service + CNAME), and
        the output file path. Detail → takeover.json (feeds collect_findings).
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
                    "Run subdomain_enum first, or pass target=..."
                ),
            }

    hosts = []
    for h in raw:
        bare = h.split("://", 1)[-1].split("/", 1)[0]
        try:
            validate_target(bare)
        except InvalidTarget:
            continue
        if scope.in_scope(bare):
            hosts.append(bare)
    if not hosts:
        return {"ok": False, "error": "no valid, in-scope hosts to check"}

    results, available = await run_nuclei(hosts, tags="takeover")
    if not available:
        return {
            "ok": False,
            "error": "nuclei binary not available — run in the Docker image",
        }

    # Annotate each hit with the CNAME dns_enum recorded (the actionable signal).
    dns = workspace.read_json("dns.json", {}) or {}
    takeovers = []
    for r in results:
        host = r["host"].split("://", 1)[-1].split("/", 1)[0]
        cnames = dns.get(host, {}).get("cname", [])
        takeovers.append({
            "host": host,
            "service": r["name"],
            "template": r["template"],
            "cname": cnames,
        })

    workspace.write_json(OUT_FILE, takeovers)

    return {
        "ok": True,
        "hosts_checked": len(hosts),
        "takeovers_flagged": len(takeovers),
        "takeovers": takeovers[:20],
        "output_file": str(workspace.path(OUT_FILE)),
        "note": "no takeovers detected" if not takeovers else "",
    }
