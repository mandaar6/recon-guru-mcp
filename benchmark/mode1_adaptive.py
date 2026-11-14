"""Mode 1 — the adaptive (brain-on) run from BENCHMARK.md.

The selection, order, and tuning below are a *brain's* decisions, informed by
http_probe observing a single Nginx/PHP web app on a non-standard port: skip the
6 tools that can't apply (no subdomains / DNS pivots / archives / other ports /
CNAME / Shodan surface), and run nuclei WITHOUT info-level templates to cut noise
and time. Compare against Mode 2 (`python -m reconguru_mcp.cli <target>`), which
runs everything blindly.

    docker run --rm -e PYTHONPATH=/app -v bench-mode1:/workspace \
      -v "$PWD/benchmark/mode1_adaptive.py:/mode1.py:ro" --entrypoint python \
      reconguru-mcp:latest /mode1.py
"""
import asyncio
import time

from reconguru_mcp import workspace
from reconguru_mcp.tools.collect_findings import collect_findings
from reconguru_mcp.tools.content_discovery import content_discovery
from reconguru_mcp.tools.crawl import crawl
from reconguru_mcp.tools.http_probe import http_probe
from reconguru_mcp.tools.param_discovery import param_discovery
from reconguru_mcp.tools.report_gen import report_gen
from reconguru_mcp.tools.secret_scan import secret_scan
from reconguru_mcp.tools.vuln_scan import vuln_scan
from reconguru_mcp.tools.waf_detect import waf_detect

HOSTPORT = "pentest-ground.com:4280"
URL = "https://pentest-ground.com:4280"


async def main():
    workspace.merge_lines("subdomains.txt", [HOSTPORT])
    steps = [
        ("http_probe",        lambda: http_probe(HOSTPORT)),
        ("waf_detect",        lambda: waf_detect(URL)),
        ("crawl",             lambda: crawl()),
        ("content_discovery", lambda: content_discovery(URL)),
        ("param_discovery",   lambda: param_discovery(URL)),
        # adaptive: skip info-level templates (noise) — focus on actionable
        ("vuln_scan",         lambda: vuln_scan(severity="low,medium,high,critical")),
        ("secret_scan",       lambda: secret_scan()),
        ("collect_findings",  lambda: collect_findings()),
        ("report_gen",        lambda: report_gen(URL)),
    ]
    print(f"[mode1] adaptive brain-on recon of {URL} — {len(steps)} steps (6 skipped)\n")
    t0 = time.monotonic()
    for name, f in steps:
        s = time.monotonic()
        try:
            e = await f(); ok = bool(e.get("ok"))
        except Exception as ex:
            e = {"ok": False, "error": f"{type(ex).__name__}: {ex}"}; ok = False
        detail = e.get("error") or e.get("note") or ""
        print(f"  [{'ok ' if ok else 'ERR'}] {name:<17} {time.monotonic()-s:6.1f}s  {str(detail)[:55]}")
    total = time.monotonic() - t0
    fnd = workspace.read_json("findings.json", []) or []
    by_sev = {}
    for x in fnd:
        by_sev[x.get("severity", "info")] = by_sev.get(x.get("severity", "info"), 0) + 1
    print(f"\n[mode1] done in {total:.1f}s — {len(fnd)} findings {by_sev}; 9 steps run, 6 skipped")


if __name__ == "__main__":
    asyncio.run(main())
