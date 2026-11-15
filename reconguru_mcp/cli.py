"""Mode 2 — the brain-off linear runner (benchmark control).

Runs reconguru-mcp's tools in a fixed order with **no LLM** deciding anything:
every tool, every time, regardless of whether it's relevant. This is the
deterministic baseline the agentic (brain-on) mode is benchmarked against — same
tools, brain off — so the only variable is the LLM orchestration.

    python -m reconguru_mcp.cli <target>

It is deliberately *dumb*: it does not skip irrelevant steps, re-scope on
findings, retry, or triage. That's exactly what the brain adds in Mode 1.
"""

from __future__ import annotations

import asyncio
import sys
import time

from . import workspace
from .tools.collect_findings import collect_findings
from .tools.content_discovery import content_discovery
from .tools.crawl import crawl
from .tools.dns_enum import dns_enum
from .tools.exploit_lookup import exploit_lookup
from .tools.http_probe import http_probe
from .tools.nmap import nmap_scan  # noqa: F401 (kept available; port_scan is primary)
from .tools.param_discovery import param_discovery
from .tools.port_scan import port_scan
from .tools.report_gen import report_gen
from .tools.secret_scan import secret_scan
from .tools.shodan_enrich import shodan_enrich
from .tools.subdomain_enum import subdomain_enum
from .tools.takeover_check import takeover_check
from .tools.url_collect import url_collect
from .tools.vuln_scan import vuln_scan
from .tools.waf_detect import waf_detect


def _pipeline(target: str):
    """The fixed, no-LLM order. Each entry is (name, coroutine factory)."""
    return [
        ("subdomain_enum", lambda: subdomain_enum(target)),
        ("dns_enum",        lambda: dns_enum()),
        ("http_probe",      lambda: http_probe()),
        ("port_scan",       lambda: port_scan()),
        ("waf_detect",      lambda: waf_detect(target)),
        ("content_discovery", lambda: content_discovery(target)),
        ("param_discovery", lambda: param_discovery(target)),
        ("crawl",           lambda: crawl()),
        ("url_collect",     lambda: url_collect(target)),
        ("secret_scan",     lambda: secret_scan()),
        ("vuln_scan",       lambda: vuln_scan()),
        ("takeover_check",  lambda: takeover_check()),
        ("exploit_lookup",  lambda: exploit_lookup()),
        ("shodan_enrich",   lambda: shodan_enrich()),
        ("collect_findings", lambda: collect_findings()),
        ("report_gen",      lambda: report_gen(target)),
    ]


async def run(target: str) -> dict:
    steps = _pipeline(target)
    results: list[dict] = []
    t0 = time.monotonic()

    # Namespace this run's workspace under the target folder, then seed the
    # target (keeping any explicit :port) so the chain works for a single host
    # too: http_probe reads subdomains.txt, subdomain_enum then merges anything
    # it discovers on top. Tools inherit this active project (no project= arg).
    workspace.set_project(target=target)
    hostport = target.split("://", 1)[-1].split("/", 1)[0]
    workspace.merge_lines("subdomains.txt", [hostport])

    print(f"[mode2] linear brain-off recon of {target} — {len(steps)} steps\n")
    for name, factory in steps:
        start = time.monotonic()
        try:
            env = await factory()
            ok = bool(env.get("ok"))
        except Exception as e:  # a failing step never stops the pipeline
            env = {"ok": False, "error": f"{type(e).__name__}: {e}"}
            ok = False
        dur = time.monotonic() - start
        results.append({"step": name, "ok": ok, "seconds": round(dur, 1), "env": env})
        status = "ok " if ok else "ERR"
        detail = env.get("error") or env.get("note") or ""
        print(f"  [{status}] {name:<17} {dur:6.1f}s  {str(detail)[:60]}")

    total = time.monotonic() - t0
    findings = workspace.read_json("findings.json", []) or []
    by_sev: dict[str, int] = {}
    for f in findings:
        by_sev[f.get("severity", "info")] = by_sev.get(f.get("severity", "info"), 0) + 1

    print(f"\n[mode2] done in {total:.1f}s — {len(findings)} findings {by_sev}")
    report = workspace.path("report.html")
    print(f"[mode2] report: {report}")
    return {
        "mode": "linear-brain-off",
        "target": target,
        "total_seconds": round(total, 1),
        "steps": [{"step": r["step"], "ok": r["ok"], "seconds": r["seconds"]} for r in results],
        "findings_total": len(findings),
        "findings_by_severity": by_sev,
        "report": str(report),
    }


def main() -> None:
    if len(sys.argv) < 2:
        print("usage: python -m reconguru_mcp.cli <target>", file=sys.stderr)
        raise SystemExit(2)
    asyncio.run(run(sys.argv[1]))


if __name__ == "__main__":
    main()
