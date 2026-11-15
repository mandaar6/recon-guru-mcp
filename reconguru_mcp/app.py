"""The shared FastMCP instance.

Every tool module imports `mcp` from here and registers itself with the
`@mcp.tool()` decorator. This instance *is* the tool registry: FastMCP
auto-generates each tool's JSON schema from its type hints and docstring,
and advertises the whole set to any connected harness (Claude Code, Codex,
Cursor, etc.).

To add a tool: create a file in `reconguru_mcp/tools/`, import this `mcp`,
and decorate a function with `@mcp.tool()`. The loader in `tools/__init__.py`
imports every module in that package at startup, so the tool self-registers
with no central wiring to edit.
"""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

# `instructions` is surfaced to the connected harness/LLM — it's how the brain
# learns what this server is, what it can do, and how to drive it well. (It's a
# description of *this server's own* tools and workflow, not an external
# methodology/playbook.)
INSTRUCTIONS = """\
reconguru-mcp is a web & API **reconnaissance** toolserver. Its 18 tools run in
an isolated sandbox and chain their results through a shared /workspace into one
ranked, de-duplicated findings model (see collect_findings / report_gen).

Tools by phase:
- Discover: subdomain_enum, dns_enum, url_collect, crawl
- Probe:    http_probe (liveness, status buckets, tech, headers, content-hash dedup)
- Enumerate: port_scan, nmap_scan, content_discovery, param_discovery, waf_detect
- Analyze:  vuln_scan (nuclei), takeover_check, exploit_lookup, secret_scan, shodan_enrich
- Correlate: collect_findings (join on host/ip/port/service), validate_finding
- Report:   report_gen (any-time HTML report)

How to drive it well:
- Only scan AUTHORIZED targets. Honor the scope files (scope_include.txt /
  scope_exclude.txt in the workspace).
- A sensible full-recon order: subdomain_enum -> http_probe -> port_scan ->
  content_discovery/crawl -> vuln_scan -> collect_findings -> report_gen.
- Be adaptive, don't run everything blindly: if the user already gave specific
  in-scope hosts (or the scope list is pre-populated), SKIP subdomain_enum/dns_enum
  and go straight to http_probe on those hosts. Skip tools with no surface (e.g.
  takeover_check without CNAMEs). Tune heavy tools (e.g. vuln_scan severity=) to
  cut info-level noise.
- This server is RECON only — it does not exploit (no SQLi/XSS payloads). When you
  find something exploitable, report it for the user to pursue; don't try to exploit.
- Authenticated targets: the server NEVER logs in. If a target returns 401/403 or
  redirects to a login, tell the user to log in themselves and pass their session
  via a tool's `auth` argument (or RECONGURU_AUTH_HEADER).
- If the user's request is vague, offer a short menu before scanning, e.g.:
  "Want subdomain discovery, a liveness probe, a port scan, a vuln (nuclei) scan,
  or the full chain?" — then act on their choice.
"""

# The server name is what harnesses display for this toolset.
mcp = FastMCP("reconguru-mcp", instructions=INSTRUCTIONS)
