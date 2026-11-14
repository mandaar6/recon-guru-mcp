"""waf_detect — identify a WAF/CDN in front of a host via wafw00f.

Knowing the WAF shapes later steps (rate limits, evasion is out of scope, but
the brain can note it and back off). **Tier 1.** Needs the ``wafw00f`` CLI
(pip-installed in the image). Writes ``/workspace/waf.json``.
"""

from __future__ import annotations

from .. import scope, workspace
from ..app import mcp
from ..config import settings
from ..sandbox import run_tool
from ..validate import InvalidTarget, validate_target

OUT_FILE = "waf.json"
TMP_OUT = "_wafw00f_out.json"


@mcp.tool()
async def waf_detect(target: str) -> dict:
    """Detect the WAF/CDN protecting a host (wafw00f).

    Args:
        target: A single host or URL, e.g. "example.com".

    Returns:
        An envelope: whether a WAF was detected and its name, plus the output
        file path. Detail is written to waf.json.
    """
    try:
        host = validate_target(target.split("://", 1)[-1].split("/", 1)[0])
    except InvalidTarget as e:
        return {"ok": False, "error": str(e)}
    if not scope.in_scope(host):
        return {"ok": False, "error": f"{host} is out of scope"}

    url = target if target.startswith(("http://", "https://")) else f"https://{host}"
    out_path = workspace.path(TMP_OUT)

    result = await run_tool(
        ["wafw00f", url, "-a", "-f", "json", "-o", str(out_path)],
        timeout_s=settings.timeout_for("wafw00f"),
    )
    if not result.ok and "not installed" in (result.note or ""):
        return {
            "ok": False,
            "error": "wafw00f not available — run in the Docker image",
            "note": result.note,
        }

    parsed = workspace.read_json(TMP_OUT, [])
    entries = parsed if isinstance(parsed, list) else [parsed] if parsed else []
    wafs = []
    for e in entries:
        if isinstance(e, dict) and e.get("detected"):
            wafs.append(e.get("firewall") or e.get("manufacturer") or "unknown")

    workspace.write_json(OUT_FILE, {host: entries})

    return {
        "ok": True,
        "target": host,
        "waf_detected": bool(wafs),
        "wafs": wafs,
        "output_file": str(workspace.path(OUT_FILE)),
        "note": "no WAF detected" if not wafs else "",
    }
