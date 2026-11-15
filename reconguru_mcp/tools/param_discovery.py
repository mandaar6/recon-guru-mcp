"""param_discovery — find hidden HTTP parameters via arjun.

Discovers query/body parameters a page accepts but doesn't advertise — extra
attack surface for the brain to reason about. **Tier 2** (active: sends many
probe requests). Needs the ``arjun`` CLI (pip-installed in the image). Writes
``/workspace/params.json``. Supports `auth`.
"""

from __future__ import annotations

from .. import auth as _auth
from .. import scope, workspace
from ..app import mcp
from ..config import settings
from ..sandbox import run_tool
from ..validate import InvalidTarget, validate_target

OUT_FILE = "params.json"
TMP_OUT = "_arjun_out.json"


@mcp.tool()
async def param_discovery(target: str, auth: str = "", project: str = "") -> dict:
    """Discover hidden HTTP parameters on a URL (arjun).

    Args:
        target: A single host or URL to probe, e.g. "https://example.com/search".
        auth: Optional raw HTTP header(s) for authenticated probing.

    Returns:
        An envelope: parameters found, a sample, and the output file path.
        Detail is written to params.json.
    """
    workspace.use_project(project, target)
    try:
        host = validate_target(target.split("://", 1)[-1].split("/", 1)[0])
    except InvalidTarget as e:
        return {"ok": False, "error": str(e)}
    if not scope.in_scope(host):
        return {"ok": False, "error": f"{host} is out of scope"}

    url = target if target.startswith(("http://", "https://")) else f"https://{host}"
    out_path = workspace.path(TMP_OUT)

    argv = ["arjun", "-u", url, "-oJ", str(out_path), "-q"]
    extra = _auth.cli_args(auth)
    if extra:
        # arjun takes headers as "Name: value" via --headers (newline-joined).
        argv += ["--headers", "\n".join(a for a in extra if a != "-H")]

    result = await run_tool(argv, timeout_s=settings.timeout_for("arjun"))
    if not result.ok and "not installed" in (result.note or ""):
        return {
            "ok": False,
            "error": "arjun not available — run in the Docker image",
            "note": result.note,
        }

    parsed = workspace.read_json(TMP_OUT, {}) or {}
    # arjun output shape varies; collect any 'params' lists found.
    params: list[str] = []
    if isinstance(parsed, dict):
        for v in parsed.values():
            if isinstance(v, dict) and isinstance(v.get("params"), list):
                params.extend(v["params"])
        if isinstance(parsed.get("params"), list):
            params.extend(parsed["params"])
    params = sorted(set(p for p in params if p))

    workspace.write_json(OUT_FILE, {url: params})

    return {
        "ok": True,
        "target": url,
        "params_found": len(params),
        "params": params[:40],
        "output_file": str(workspace.path(OUT_FILE)),
        "note": "no hidden parameters found" if not params else "",
    }
