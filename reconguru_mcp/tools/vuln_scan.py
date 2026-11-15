"""vuln_scan — templated vulnerability scanning via nuclei.

Runs nuclei's community templates (CVEs, misconfigurations, exposures, default
credentials, …) against live hosts and records each match with its built-in
severity. Results go to ``/workspace/nuclei.json`` and flow into the findings
model via ``collect_findings``. This is the Tier-3 ceiling: read-only templated
checks, no exploitation.

Needs the ``nuclei`` binary + templates (both in the Docker image). Supports
`auth` for scanning behind a login.
"""

from __future__ import annotations

import json

from .. import auth as _auth
from .. import scope, workspace
from ..app import mcp
from ..config import settings
from ..sandbox import run_tool
from ..validate import InvalidTarget, validate_target

SOURCE_DEFAULT = "live_hosts.txt"
OUT_FILE = "nuclei.json"
TARGETS_TMP = "_nuclei_targets.txt"


async def run_nuclei(hosts: list[str], *, severity: str = "", tags: str = "",
                     extra: list[str] | None = None, auth: str = "") -> tuple[list[dict], bool]:
    """Run nuclei over `hosts`, return (findings, available)."""
    targets_path = workspace.write_lines(TARGETS_TMP, hosts)
    argv = [
        "nuclei", "-l", str(targets_path),
        "-jsonl", "-silent", "-no-color", "-disable-update-check",
    ]
    sev = severity.strip() or settings.nuclei_severity.strip()
    if sev:
        argv += ["-severity", sev]
    if tags.strip():
        argv += ["-tags", tags.strip()]
    if settings.nuclei_templates.strip():
        argv += ["-t", settings.nuclei_templates.strip()]
    argv += (extra or []) + _auth.cli_args(auth)

    result = await run_tool(argv, timeout_s=settings.timeout_for("nuclei"))
    available = "not installed" not in (result.note or "")
    out = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            d = json.loads(line)
        except json.JSONDecodeError:
            continue
        info = d.get("info", {}) or {}
        out.append({
            "template": d.get("template-id", ""),
            "name": info.get("name", ""),
            "severity": (info.get("severity") or "info").lower(),
            "host": d.get("host", ""),
            "matched_at": d.get("matched-at", d.get("matched", "")),
            "type": d.get("type", ""),
            "tags": info.get("tags", []),
        })
    return out, available


@mcp.tool()
async def vuln_scan(target: str = "", source_file: str = SOURCE_DEFAULT,
                    severity: str = "", tags: str = "", auth: str = "", project: str = "") -> dict:
    """Scan live hosts for known vulnerabilities and exposures (nuclei).

    Args:
        target: Optional single host/URL or comma list. When empty, hosts are
            read from the workspace file.
        source_file: Workspace file to read hosts from when `target` is empty.
            Defaults to "live_hosts.txt".
        severity: Comma-separated severities to include, e.g. "high,critical"
            (nuclei -severity). Empty uses the configured default (all).
        tags: Comma-separated template tags to restrict to, e.g. "cve,exposure".
        auth: Optional raw HTTP header(s) for authenticated scanning.

    Returns:
        An envelope: total matches, counts by severity, the top findings, and
        the output file path. Full detail → nuclei.json (feeds collect_findings).
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

    hosts = []
    for h in raw:
        bare = h.split("://", 1)[-1].split("/", 1)[0]
        try:
            validate_target(bare)
        except InvalidTarget:
            continue
        if scope.in_scope(bare):
            hosts.append(h)
    if not hosts:
        return {"ok": False, "error": "no valid, in-scope hosts to scan"}

    results, available = await run_nuclei(hosts, severity=severity, tags=tags, auth=auth)
    if not available:
        return {
            "ok": False,
            "error": "nuclei binary not available — run in the Docker image",
        }

    workspace.write_json(OUT_FILE, results)
    by_sev: dict[str, int] = {}
    for r in results:
        by_sev[r["severity"]] = by_sev.get(r["severity"], 0) + 1
    top = [
        {"severity": r["severity"], "name": r["name"], "host": r["host"],
         "template": r["template"]}
        for r in results
        if r["severity"] in ("critical", "high", "medium")
    ][:25]

    return {
        "ok": True,
        "hosts_scanned": len(hosts),
        "matches": len(results),
        "by_severity": dict(sorted(by_sev.items())),
        "top": top,
        "output_file": str(workspace.path(OUT_FILE)),
        "note": "" if results else "no template matches",
    }
