"""tech_stack — fingerprint the technology behind each live host.

For each host (by default read from ``/workspace/live_hosts.txt``) it:
  * captures response headers (``httpx``, native) and derives tech hints plus
    **missing security-header findings** — this half works with no extra
    binaries;
  * runs ``whatweb`` (subprocess, via the sandbox) for deeper fingerprinting —
    this half degrades gracefully to "binary not available" until ``whatweb``
    is baked into the Docker image.

Per-host detail is written to ``/workspace/tech_stack.json``; a compact
summary is returned. **Tier 2.**

Ported from recon-guru's TechStack (wappalyzer dropped — whatweb + httpx's own
detection cover tech fingerprinting).
"""

from __future__ import annotations

import asyncio
import json

import httpx

from .. import auth as _auth
from .. import scope, workspace
from ..app import mcp
from ..config import settings
from ..sandbox import run_tool
from ..validate import InvalidTarget, validate_target

SOURCE_DEFAULT = "live_hosts.txt"
OUT_FILE = "tech_stack.json"
PROBE_TIMEOUT = 10

CAPTURED_HEADERS = [
    "Server",
    "X-Powered-By",
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
]
SECURITY_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
]


async def _whatweb(url: str) -> tuple[list[str], bool]:
    """Run whatweb on a URL. Returns (technologies, available)."""
    res = await run_tool(
        ["whatweb", "--quiet", "--log-json=-", url],
        timeout_s=settings.timeout_for("whatweb"),
    )
    available = "not installed" not in (res.note or "")
    if not res.ok:
        return [], available
    techs: list[str] = []
    for line in res.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            continue
        entries = data if isinstance(data, list) else [data]
        for entry in entries:
            if isinstance(entry, dict):
                techs.extend((entry.get("plugins", {}) or {}).keys())
    return list(dict.fromkeys(techs)), available


async def _analyze(client: httpx.AsyncClient, sem: asyncio.Semaphore, host: str):
    """Return (host, result_dict, whatweb_available)."""
    async with sem:
        technologies: list[str] = []
        captured: dict[str, str | None] = {h: None for h in CAPTURED_HEADERS}
        scheme = None

        for sch in ("https", "http"):
            try:
                r = await client.get(
                    f"{sch}://{host}", timeout=PROBE_TIMEOUT, follow_redirects=True
                )
                for h in CAPTURED_HEADERS:
                    captured[h] = r.headers.get(h)  # case-insensitive lookup
                scheme = sch
                server = captured.get("Server") or ""
                powered = captured.get("X-Powered-By") or ""
                if server:
                    technologies.append(server.split("/")[0].strip())
                if powered:
                    technologies.append(powered.split("/")[0].strip())
                break
            except Exception:
                continue

        ww_techs, ww_available = await _whatweb(f"{scheme or 'https'}://{host}")
        technologies.extend(ww_techs)
        technologies = list(dict.fromkeys(t for t in technologies if t))

        missing = [h for h in SECURITY_HEADERS if not captured.get(h)]
        findings = [
            {"type": "missing_header", "header": h, "severity": "medium"}
            for h in missing
        ]
        return host, {
            "scheme": scheme,
            "reachable": scheme is not None,
            "technologies": technologies,
            "headers": captured,
            "missing_headers": missing,
            "findings": findings,
        }, ww_available


@mcp.tool()
async def tech_stack(target: str = "", source_file: str = SOURCE_DEFAULT,
                     auth: str = "") -> dict:
    """Fingerprint the tech stack and security headers of live hosts.

    Captures response headers and flags missing security headers (native), and
    runs whatweb for deeper fingerprinting (requires the whatweb binary in the
    image; until then that half is skipped cleanly).

    Args:
        target: Optional single host or comma-separated hosts. When empty, the
            host list is read from the workspace file.
        source_file: Workspace file to read hosts from when `target` is empty.
            Defaults to "live_hosts.txt" (what live_probe writes).
        auth: Optional raw HTTP header(s) for authenticated fingerprinting, e.g.
            "Cookie: session=…". Overrides RECONGURU_AUTH_HEADER. Applies to the
            header-capture requests. The toolkit never logs in.

    Returns:
        An envelope: hosts analyzed, whether whatweb was available, total
        missing-header findings, a per-host summary sample, and the output file
        path. Full per-host detail is written to tech_stack.json.
    """
    if target.strip():
        raw_hosts = [h.strip() for h in target.split(",") if h.strip()]
    else:
        raw_hosts = workspace.read_lines(source_file)
        if not raw_hosts:
            return {
                "ok": False,
                "error": (
                    f"no hosts: workspace file '{source_file}' is empty. "
                    "Run live_probe first, or pass target=..."
                ),
            }

    valid: list[str] = []
    for h in raw_hosts:
        try:
            valid.append(validate_target(h))
        except InvalidTarget:
            pass
    hosts = scope.filter_in_scope(sorted(set(valid)))
    if not hosts:
        return {"ok": False, "error": "no valid, in-scope hosts to analyze"}

    sem = asyncio.Semaphore(settings.max_concurrency)
    async with httpx.AsyncClient(
        verify=False,
        headers={"User-Agent": settings.user_agent, **_auth.header_dict(auth)},
    ) as client:
        results = await asyncio.gather(*(_analyze(client, sem, h) for h in hosts))

    data = {host: info for host, info, _ in results}
    whatweb_available = any(avail for _, _, avail in results)
    out_path = workspace.write_json(OUT_FILE, data)

    total_missing = sum(len(v["missing_headers"]) for v in data.values())
    summary = {
        host: {
            "technologies": info["technologies"][:8],
            "missing_headers": info["missing_headers"],
        }
        for host, info in list(data.items())[:20]
    }

    note_bits = []
    if not whatweb_available:
        note_bits.append(
            "whatweb binary not available — tech derived from headers only "
            "(add whatweb to the Docker image for deeper fingerprinting)"
        )
    unreachable = sum(1 for v in data.values() if not v["reachable"])
    if unreachable:
        note_bits.append(f"{unreachable} host(s) did not respond")

    return {
        "ok": True,
        "hosts": len(hosts),
        "whatweb_available": whatweb_available,
        "total_missing_header_findings": total_missing,
        "output_file": str(out_path),
        "summary": summary,
        "note": "; ".join(note_bits),
    }
