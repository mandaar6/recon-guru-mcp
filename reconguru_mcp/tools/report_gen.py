"""report_gen — render an HTML report from whatever is in the workspace.

An **any-time** tool, not a fixed final stage: it reads the canonical workspace
files that happen to exist (subdomains, live hosts, tech stack, ports+CVEs,
exploits) and renders a single self-contained ``report.html``. It is tolerant
of partial data — run it after one tool or after the whole chain, and it
reports only what's there.

Ported from recon-guru's ReportGen, adapted to read the shared workspace and to
work with any subset of the data.
"""

from __future__ import annotations

import html
from datetime import datetime, timezone

from .. import workspace
from ..app import mcp

OUT_DEFAULT = "report.html"


def _esc(s) -> str:
    return html.escape(str(s if s is not None else ""))


def _load() -> dict:
    return {
        "subdomains": workspace.read_lines("subdomains.txt"),
        # http_probe.json supplies both liveness/status and tech/headers.
        "live": workspace.read_json("http_probe.json", {}) or {},
        "tech": workspace.read_json("http_probe.json", {}) or {},
        "ports": workspace.read_json("ports.json", {}) or {},
        "exploits": workspace.read_json("exploits.json", {}) or {},
        "shodan": workspace.read_json("shodan.json", {}) or {},
        "findings": workspace.read_json("findings.json", []) or [],
    }


def _findings_section(items: list) -> str:
    """Ranked findings table (from collect_findings). Empty string if none."""
    if not items:
        return ""
    rows = ""
    for f in items:
        sev = f.get("severity", "info")
        loc = _esc(f.get("host", ""))
        if f.get("port"):
            loc += f':{_esc(f.get("port"))}'
        val = ('<span class="ok">✓ observed</span>' if f.get("validated")
               else '<span class="muted">inferred</span>')
        rows += (
            f'<tr><td><span class="sev sev-{sev}">{_esc(sev)}</span></td>'
            f'<td>{_esc(f.get("type"))}</td><td class="host">{loc}</td>'
            f'<td><code>{_esc(f.get("ref") or f.get("service") or "")}</code></td>'
            f'<td>{val}</td></tr>'
        )
    return f"""
  <h2>Findings <span class="muted">({len(items)})</span></h2>
  <table class="tbl"><thead><tr><th>Severity</th><th>Type</th><th>Location</th>
  <th>Reference</th><th>Grounding</th></tr></thead><tbody>{rows}</tbody></table>"""


def _stat_card(num, label, cls="") -> str:
    return (
        f'<div class="stat {cls}"><div class="stat-num">{num}</div>'
        f'<div class="stat-label">{_esc(label)}</div></div>'
    )


def _host_card(host: str, data: dict) -> str:
    live = data["live"].get(host, {})
    tech = data["tech"].get(host, {})
    ports_info = data["ports"].get(host, {})
    ip = ports_info.get("ip", "")
    status = live.get("status")
    bucket = live.get("bucket", "")

    technologies = tech.get("technologies", [])
    headers = tech.get("headers", {})
    missing = set(tech.get("missing_headers", []))
    open_ports = ports_info.get("open_ports", [])
    has_cve = any(p.get("cves") for p in open_ports)

    badge_cls = "card-critical" if has_cve else (
        "card-live" if bucket == "2xx" else "card-neutral"
    )

    tech_badges = "".join(
        f'<span class="badge">{_esc(t)}</span>' for t in technologies[:12]
    ) or '<span class="muted">none detected</span>'

    header_rows = ""
    for h, val in headers.items():
        if val:
            disp = f'<code>{_esc(str(val)[:120])}</code>'
            rc = ""
        elif h in missing:
            disp = '<span class="warn">⚠ MISSING</span>'
            rc = "row-warn"
        else:
            disp = '<span class="muted">—</span>'
            rc = ""
        header_rows += f'<tr class="{rc}"><td class="k">{_esc(h)}</td><td>{disp}</td></tr>'

    port_rows = ""
    for p in open_ports:
        cves = p.get("cves", [])
        cve_html = "".join(f'<span class="cve">{_esc(c)}</span>' for c in cves) or \
            '<span class="muted">—</span>'
        rc = "row-vuln" if cves else ""
        port_rows += (
            f'<tr class="{rc}"><td><b>{_esc(p.get("port"))}</b>/{_esc(p.get("protocol","tcp"))}</td>'
            f'<td>{_esc(p.get("service"))}</td><td><code>{_esc(p.get("version"))}</code></td>'
            f'<td>{cve_html}</td></tr>'
        )
    ports_table = (
        '<table class="tbl"><thead><tr><th>Port</th><th>Service</th>'
        f'<th>Version</th><th>CVEs</th></tr></thead><tbody>{port_rows}</tbody></table>'
        if open_ports else '<div class="muted">no open ports recorded</div>'
    )

    meta = []
    if ip:
        meta.append(f'<span class="pill">{_esc(ip)}</span>')
    if status is not None:
        meta.append(f'<span class="pill">HTTP {_esc(status)}</span>')
    if open_ports:
        meta.append(f'<span class="pill">{len(open_ports)} port(s)</span>')
    if has_cve:
        n = sum(len(p.get("cves", [])) for p in open_ports)
        meta.append(f'<span class="pill vuln">⚠ {n} CVE(s)</span>')

    return f"""
<div class="card {badge_cls}">
  <div class="card-head" onclick="this.parentNode.classList.toggle('open')">
    <span class="host">{_esc(host)}</span>
    <span class="meta">{''.join(meta)}</span>
  </div>
  <div class="card-body">
    <div class="sec"><h4>Technologies</h4><div class="badges">{tech_badges}</div></div>
    <div class="sec"><h4>Response Headers</h4>
      <table class="tbl hdr"><tbody>{header_rows or '<tr><td class="muted">no header data</td></tr>'}</tbody></table>
    </div>
    <div class="sec"><h4>Open Ports &amp; Services</h4>{ports_table}</div>
  </div>
</div>"""


def _build_html(target: str, data: dict) -> str:
    subs = data["subdomains"]
    live = data["live"]
    buckets: dict[str, int] = {}
    for info in live.values():
        buckets[info.get("bucket", "other")] = buckets.get(info.get("bucket", "other"), 0) + 1
    live_count = sum(v for k, v in buckets.items() if k != "dead")

    total_ports = sum(len(v.get("open_ports", [])) for v in data["ports"].values())
    total_cves = sum(
        len(p.get("cves", []))
        for v in data["ports"].values()
        for p in v.get("open_ports", [])
    )
    total_exploits = sum(len(e.get("exploits", [])) for e in data["exploits"].values())

    hosts = sorted(
        set(data["tech"]) | set(data["ports"])
        | {h for h, i in live.items() if i.get("bucket") != "dead"}
    )
    cards = "".join(_host_card(h, data) for h in hosts) or \
        '<div class="muted empty">No host-level data yet. Run live_probe / tech_stack / port_scan.</div>'

    sub_rows = ""
    for s in sorted(subs):
        b = live.get(s, {}).get("bucket", "")
        cls = {"2xx": "ok", "3xx": "redir"}.get(b, "dead" if b in ("4xx", "5xx", "dead") else "")
        sub_rows += f'<tr><td>{_esc(s)}</td><td class="{cls}">{_esc(b or "—")}</td></tr>'

    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    label = _esc(target or "workspace")

    return f"""<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>reconguru-mcp report — {label}</title>
<style>
:root{{--bg:#0d0d14;--bg2:#13131e;--bg3:#1a1a2e;--bd:#252540;--ac:#7c6af7;--ac2:#5af7c6;
--grn:#2adc7a;--yel:#f7c35a;--red:#f75a5a;--blu:#5aa8f7;--tx:#e8e8f0;--mut:#6c6c8a}}
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:'Segoe UI',system-ui,sans-serif;background:var(--bg);color:var(--tx);line-height:1.6}}
.hd{{background:linear-gradient(135deg,#1a0a3e,#0d0d14 55%,#0a2e1a);border-bottom:1px solid var(--bd);padding:22px 24px;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px}}
.logo{{font-size:1.5rem;font-weight:800}} .logo b{{color:var(--ac)}} .logo i{{color:var(--ac2);font-style:normal}}
.hd .sub{{color:var(--mut);font-size:.85rem}}
.wrap{{max-width:1200px;margin:0 auto;padding:28px 24px}}
h2{{font-size:1.15rem;margin:28px 0 14px;padding-bottom:8px;border-bottom:1px solid var(--bd)}}
.stats{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:14px}}
.stat{{background:var(--bg2);border:1px solid var(--bd);border-radius:12px;padding:18px;text-align:center}}
.stat-num{{font-size:2.2rem;font-weight:800;background:linear-gradient(135deg,var(--ac),var(--ac2));-webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:transparent}}
.stat.cve .stat-num{{background:linear-gradient(135deg,var(--red),#f7a05a);-webkit-background-clip:text;background-clip:text}}
.stat.live .stat-num{{background:linear-gradient(135deg,var(--grn),var(--ac2));-webkit-background-clip:text;background-clip:text}}
.stat-label{{font-size:.75rem;color:var(--mut);text-transform:uppercase;letter-spacing:.05em}}
.breakdown{{display:flex;gap:10px;flex-wrap:wrap;margin-top:14px}}
.bk{{background:var(--bg3);border:1px solid var(--bd);border-radius:8px;padding:8px 14px;font-size:.85rem}}
.bk b{{margin-left:6px}} .ok,.bk.ok b{{color:var(--grn)}} .redir{{color:var(--yel)}} .dead{{color:var(--red)}}
.card{{background:var(--bg2);border:1px solid var(--bd);border-left:3px solid var(--mut);border-radius:12px;margin-bottom:12px;overflow:hidden}}
.card.card-live{{border-left-color:var(--grn)}} .card.card-critical{{border-left-color:var(--red)}}
.card-head{{display:flex;justify-content:space-between;align-items:center;gap:10px;padding:14px 18px;cursor:pointer;flex-wrap:wrap}}
.card-head:hover{{background:rgba(124,106,247,.06)}}
.host{{font-family:'Courier New',monospace;font-weight:600}}
.pill{{font-size:.72rem;background:var(--bg3);border:1px solid var(--bd);color:var(--mut);padding:2px 8px;border-radius:4px;margin-left:5px}}
.pill.vuln{{color:var(--red);border-color:rgba(247,90,90,.4)}}
.card-body{{display:none;padding:16px 18px;border-top:1px solid var(--bd)}}
.card.open .card-body{{display:block}}
.sec{{margin-bottom:16px}} .sec h4{{font-size:.72rem;text-transform:uppercase;letter-spacing:.06em;color:var(--mut);margin-bottom:8px}}
.badges{{display:flex;flex-wrap:wrap;gap:6px}}
.badge{{font-size:.74rem;background:rgba(124,106,247,.12);border:1px solid rgba(124,106,247,.25);color:var(--ac);padding:3px 10px;border-radius:20px}}
.tbl{{width:100%;border-collapse:collapse;font-size:.82rem}}
.tbl th{{text-align:left;padding:7px 10px;font-size:.7rem;text-transform:uppercase;color:var(--mut);background:var(--bg3);border-bottom:1px solid var(--bd)}}
.tbl td{{padding:7px 10px;border-bottom:1px solid rgba(37,37,64,.5);vertical-align:top}}
.tbl .k{{color:var(--mut);white-space:nowrap;width:38%}}
.row-warn td{{background:rgba(247,195,90,.05)}} .warn{{color:var(--yel);font-weight:600;font-size:.75rem}}
.row-vuln td{{background:rgba(247,90,90,.05)}}
.cve{{display:inline-block;font-size:.7rem;background:rgba(247,90,90,.15);border:1px solid rgba(247,90,90,.3);color:var(--red);padding:1px 6px;border-radius:4px;margin:1px;font-family:monospace}}
.sev{{display:inline-block;font-size:.68rem;font-weight:700;padding:2px 8px;border-radius:4px;text-transform:uppercase}}
.sev-critical{{background:rgba(247,90,90,.22);color:#ff6b6b;border:1px solid var(--red)}}
.sev-high{{background:rgba(247,90,90,.12);color:var(--red)}}
.sev-medium{{background:rgba(247,195,90,.12);color:var(--yel)}}
.sev-low{{background:rgba(90,168,247,.12);color:var(--blu)}}
.sev-info{{background:var(--bg3);color:var(--mut)}}
.muted{{color:var(--mut);font-size:.82rem}} .empty{{text-align:center;padding:40px}}
code{{font-family:'Courier New',monospace;font-size:.78rem;word-break:break-all}}
.foot{{text-align:center;color:var(--mut);font-size:.78rem;padding:24px;border-top:1px solid var(--bd)}}
</style></head><body>
<div class="hd">
  <div class="logo"><b>recon</b><i>guru</i>-mcp</div>
  <div class="sub">Target: <b>{label}</b> · Generated {ts}</div>
</div>
<div class="wrap">
  <h2>Summary</h2>
  <div class="stats">
    {_stat_card(len(subs), "Subdomains")}
    {_stat_card(live_count, "Live", "live")}
    {_stat_card(total_ports, "Open Ports")}
    {_stat_card(total_cves, "CVEs", "cve")}
    {_stat_card(sum(1 for f in data["findings"] if f.get("severity") in ("critical", "high")), "Crit/High", "cve")}
  </div>
  <div class="breakdown">
    {''.join(f'<span class="bk">{_esc(k)}<b>{v}</b></span>' for k, v in sorted(buckets.items())) or '<span class="muted">no liveness data</span>'}
  </div>
  {_findings_section(data["findings"])}

  <h2>Hosts <span class="muted">({len(hosts)})</span></h2>
  {cards}

  <h2>All Subdomains <span class="muted">({len(subs)})</span></h2>
  <table class="tbl"><thead><tr><th>Subdomain</th><th>Status</th></tr></thead>
  <tbody>{sub_rows or '<tr><td colspan="2" class="muted">none discovered</td></tr>'}</tbody></table>
</div>
<div class="foot">reconguru-mcp — for authorized security testing only</div>
</body></html>"""


@mcp.tool()
async def report_gen(target: str = "", output_file: str = OUT_DEFAULT, project: str = "") -> dict:
    """Render a self-contained HTML report from the current workspace data.

    Reads whichever canonical files exist (subdomains.txt, live_probe.json,
    tech_stack.json, ports.json, exploits.json, shodan.json) and writes a
    single report.html. Safe to run at any point — it reports only what's
    present.

    Args:
        target: Optional label for the report title (e.g. the root domain).
        output_file: Workspace filename to write. Defaults to "report.html".

    Returns:
        An envelope: the output path, a stats summary, and which data files
        were present.
    """
    workspace.use_project(project, target)
    data = _load()
    present = [
        name
        for name, key in [
            ("subdomains.txt", "subdomains"), ("http_probe.json", "live"),
            ("ports.json", "ports"), ("exploits.json", "exploits"),
            ("shodan.json", "shodan"), ("findings.json", "findings"),
        ]
        if data[key]
    ]
    if not present:
        return {
            "ok": False,
            "error": "workspace is empty — run at least one recon tool first",
        }

    html_text = _build_html(target, data)
    out_path = workspace.path(output_file)
    out_path.write_text(html_text, encoding="utf-8")

    total_cves = sum(
        len(p.get("cves", []))
        for v in data["ports"].values()
        for p in v.get("open_ports", [])
    )
    return {
        "ok": True,
        "output_file": str(out_path),
        "stats": {
            "subdomains": len(data["subdomains"]),
            "live": sum(1 for i in data["live"].values() if i.get("bucket") != "dead"),
            "open_ports": sum(len(v.get("open_ports", [])) for v in data["ports"].values()),
            "cves": total_cves,
            "hosts_in_report": len(set(data["tech"]) | set(data["ports"])),
        },
        "data_used": present,
        "note": f"report rendered from {len(present)} workspace file(s)",
    }
