"""User-invokable MCP prompts.

Prompts are things the *user* can trigger in the harness (e.g. a slash command
like `/reconguru:recon_help` in Claude Code). `recon_help` is a welcome/menu so a
new user can see what the server does and what to ask for.
"""

from __future__ import annotations

from .app import mcp

_HELP = """\
# reconguru-mcp — web & API reconnaissance

18 recon tools in an isolated sandbox that chain into one ranked findings model.
Just ask in plain language, e.g. *"recon example.com and give me a findings report."*

**What I can do (by phase):**
- **Discover** — subdomains (`subdomain_enum`), DNS (`dns_enum`), historical URLs
  (`url_collect`), crawl endpoints/JS (`crawl`)
- **Probe** — liveness + tech + headers in one pass (`http_probe`)
- **Enumerate** — ports/services (`port_scan`), hidden paths (`content_discovery`),
  hidden params (`param_discovery`), WAF (`waf_detect`)
- **Analyze** — templated vuln scan (`vuln_scan`/nuclei), subdomain takeover
  (`takeover_check`), CVE lookup (`exploit_lookup`), JS secrets (`secret_scan`),
  Shodan (`shodan_enrich`)
- **Correlate & report** — `collect_findings` (ranked findings.json),
  `validate_finding`, `report_gen` (HTML report any time)

**Try one of these:**
- "Enumerate subdomains of example.com."
- "Probe these hosts and tell me which are live."
- "Port-scan app.example.com and map the services to CVEs."
- "Run the full recon chain on example.com and give me a ranked report."

**Good to know:** authorized targets only; it's recon (no exploitation); for
login-gated sites, log in yourself and give me your session cookie.
"""


@mcp.prompt(name="recon_help", description="What reconguru-mcp can do + example asks.")
def recon_help() -> str:
    return _HELP
