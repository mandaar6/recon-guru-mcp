# reconguru-mcp

> **⚠️ Authorized security testing only.** Only scan hosts you own or have explicit
> written permission to test. For practice, use the nmap project's public host
> `scanme.nmap.org`.

An extensible, sandboxed **MCP toolserver for web & API reconnaissance.** It ships
18 recon tools that run inside an isolated Docker sandbox, correlate their results
into one ranked findings model, and are driven by any MCP-compatible harness
(Claude Code, Codex, Cursor, …).

**You ship the tools; the harness brings the brain.** reconguru-mcp is a
*tool-provider* (MCP "Setup 2"), not a standalone agent — the intelligence
(which tool to run, in what order, how to triage) comes from the connected
harness's LLM. That's what makes it more than the old linear recon pipeline it
grew out of: the brain adapts the scan to what it finds, and the server turns raw
tool output into a grounded, de-duplicated, severity-ranked findings list instead
of a wall of text.

---

## Quickstart

Requires **Docker** (nothing else — all tool binaries are baked into the image).

```bash
git clone https://github.com/mandaar6/recon-guru-mcp.git
cd recon-guru-mcp
docker build -t reconguru-mcp:latest .
```

Now tell your harness the container exists. **Claude Code can do this for you in
one command** (no file to find or edit) — run it in the folder where you want
reconguru available:

```bash
claude mcp add reconguru -- docker run -i --rm -v reconguru-workspace:/workspace reconguru-mcp:latest
```

Prefer to edit the config by hand (or use a different harness)? Add this block:

```json
{
  "mcpServers": {
    "reconguru": {
      "command": "docker",
      "args": ["run", "-i", "--rm",
               "-v", "reconguru-workspace:/workspace",
               "reconguru-mcp:latest"]
    }
  }
}
```

**Where that config lives** (it's a normal user file — no admin/root needed):

| Harness | File | Location |
|---|---|---|
| Claude Code (per project) | `.mcp.json` | your project's root folder |
| Claude Code (global) | managed by `claude mcp add` | `~/.claude.json` |
| Claude Desktop (macOS) | `claude_desktop_config.json` | `~/Library/Application Support/Claude/` |
| Claude Desktop (Windows) | `claude_desktop_config.json` | `%APPDATA%\Claude\` |

> **Why not just *ask* the harness to configure itself?** It can't: a harness can
> only call a server it already knows about, and it doesn't know about reconguru
> until this entry exists — a chicken-and-egg. `claude mcp add` is the automation:
> it writes that entry for you, then every new session picks it up.

That's the whole install — no package to install into the harness, no separate
service to start. Once the entry is there, your harness **launches the container
itself** over stdio and discovers the tools automatically. Just start a new
session and ask, in plain language:

> *"Use reconguru to recon example.com — enumerate subdomains, probe which are
> live, scan the live hosts, and give me a ranked findings report."*

The harness's LLM calls the tools in order, each writing to a shared workspace,
and `report_gen` renders a self-contained HTML report.

**Not sure what to ask?** The server tells your harness its capabilities
automatically (so the brain knows how to drive it), and you can run the built-in
**`recon_help`** prompt — e.g. `/reconguru:recon_help` in Claude Code — for a menu
of what it does and example asks. If your request is vague, the agent will offer
you options (subdomain discovery / liveness probe / port scan / vuln scan / the
full chain) before it starts.

---

## What it does — the recon chain

The 18 tools form a chain. Data flows **host-to-host through a shared `/workspace`
volume** (not through the LLM's context); each tool returns a small status
"envelope" so the brain knows what happened and what to do next.

```
 discover ──► probe ──► enumerate ──► analyze ──► correlate ──► report
```

| Phase | Tools |
|---|---|
| **Discover** | `subdomain_enum` (passive OSINT), `dns_enum` (dnsx resolve/brute), `url_collect` (gau), `crawl` (katana) |
| **Probe** | `http_probe` (httpx — liveness, status buckets, tech, title, CDN, **content-hash dedup**, security-header findings) |
| **Enumerate** | `port_scan` (naabu + nmap), `nmap_scan`, `content_discovery` (ffuf), `param_discovery` (arjun), `waf_detect` (wafw00f) |
| **Analyze** | `vuln_scan` (nuclei), `takeover_check` (nuclei takeover templates), `exploit_lookup` (NVD + searchsploit), `secret_scan` (trufflehog over JS), `shodan_enrich` |
| **Correlate** | `collect_findings` (join on host/ip/port/service → ranked `findings.json`), `validate_finding` (persist the brain's validation-gate verdict) |
| **Report** | `report_gen` (any-time, partial-data-tolerant HTML report) |

### The findings model (the differentiator)

`collect_findings` joins every tool's output by `host / ip / port / service` into
one de-duplicated, **CVSS-severity-ranked** `findings.json`. Each finding carries:

- a stable content-hash **`id`** (re-running a tool updates, doesn't duplicate),
- an **`output_hash`** over its factual fields (integrity — a verifier, not the LLM, confirms it),
- a **`validated` / `confidence`** grounding flag: directly-observed facts (open
  ports, missing headers) are validated on sight; version-inferred ones (CVEs,
  takeovers) await the brain's **validation gate** (`validate_finding`).

So the brain triages a grounded list by lookup instead of re-deriving it from raw
output — and `report_gen` leads with it.

---

## Configuration & scope

**You never edit files *inside* the container** (no `docker exec`, no SSH). You
create two things **on your own machine** and hand them to the container when it
starts:

**1. `.env` — settings & API keys** (copy `.env.example`, all vars are
`RECONGURU_`-namespaced):

```bash
cp .env.example .env    # then edit on your host
```

- **API keys** (blank = that source is skipped): Shodan, VirusTotal,
  SecurityTrails, URLScan, Censys, GitHub, Chaos, NVD (an NVD key makes
  `exploit_lookup` much more useful).
- Timeouts (global + per-tool, e.g. `RECONGURU_TIMEOUT_NUCLEI`), concurrency,
  rate-limit, stealth, user-agent, wordlist paths.
- **Authenticated recon:** `RECONGURU_AUTH_HEADER` (or a tool's `auth` argument)
  injects a session you captured yourself — the toolkit **never logs in for you**.

**2. Scope files — what's in/out of bounds.** Put `scope_include.txt` and/or
`scope_exclude.txt` in a **host folder you bind-mount as the workspace**, one
pattern per line (`example.com`, `*.example.com`, `192.0.2.0/24`). Discovery tools
filter their output to in-scope hosts; active tools refuse out-of-scope targets.

> **What's "bind-mounting"?** Just sharing one folder between your PC and the
> container. `-v /host/folder:/workspace` means "the container's `/workspace` *is*
> my `/host/folder`." So you edit `scope_include.txt` in a normal folder on your
> machine with any text editor, and the container sees it instantly — no
> `docker exec`, no SSH, nothing *inside* the container to touch. Reports and
> `findings.json` appear back in that same folder. (The quickstart used a *named
> volume* — `reconguru-workspace:/workspace` — which Docker manages for you but
> hides on disk; a bind-mount to a real folder is what you want once you care
> about editing scope and reading reports.)

**Wire both into the run** by bind-mounting a host folder as `/workspace` (so your
scope files go in and the reports/findings come back out) and passing `--env-file`:

```bash
mkdir -p ./workspace
echo '*.example.com' > ./workspace/scope_include.txt
```

```json
{
  "mcpServers": {
    "reconguru": {
      "command": "docker",
      "args": ["run", "-i", "--rm",
               "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
               "--pids-limit", "512", "--memory", "2g", "--cpus", "2",
               "--env-file", "/abs/path/to/recon-guru-mcp/.env",
               "-v", "/abs/path/to/recon-guru-mcp/workspace:/workspace",
               "reconguru-mcp:latest"]
    }
  }
}
```

This is the **recommended** config — it includes the least-privilege flags from
[Run it hardened](#run-it-hardened) below, so you're sandboxed by default. Now
`report.html`, `findings.json`, and every tool's output land in your
`./workspace` folder, and you edit `.env` / scope files any time by just editing
them on your host and restarting the harness session.

> **On scope and the agent (FAQ):** scope files *constrain what gets scanned* —
> they don't automatically make the agent skip steps. But the server's
> instructions tell the brain that **if you've pre-listed specific in-scope hosts,
> it should skip `subdomain_enum`/`dns_enum` and go straight to probing them.** So
> a capable harness will do the right thing; it's guidance, not a hard rule.

---

## Run it hardened

**What's already secure by default:** the image bakes in the safe parts — it runs
as a **non-root user**, ships no setuid binaries, and (in `vuln_scan` etc.) runs
tools as an unprivileged process. Those travel *inside* the image, so you always
get them.

**What Docker makes you opt into:** the runtime isolation flags below —
`--cap-drop`, `--security-opt no-new-privileges`, and the CPU/memory/process caps.
An image **cannot force these on itself**; by Docker's design they're supplied by
whoever runs `docker run`. That's why they live here and not in the build. Two
ways to always get them:

- **stdio / local:** use the recommended config in
  [Configuration & scope](#configuration--scope) above — it already includes these
  flags, so copy that one and you're hardened by default.
- **hosted / HTTP:** `docker compose up` — the shipped
  [`docker-compose.yml`](docker-compose.yml) applies all of them (plus a read-only
  root filesystem) with no extra typing.

To add them to a plain `docker run` yourself — least-privilege, with capped
CPU/memory/process count so a runaway scan can't starve or harm the host:

```bash
docker run -i --rm \
  --cap-drop ALL --security-opt no-new-privileges \
  --pids-limit 512 --memory 2g --cpus 2 \
  -v reconguru-workspace:/workspace \
  reconguru-mcp:latest
```

> SYN scans (`nmap -sS`, raw `naabu`) need raw sockets — add `--cap-add=NET_RAW`.
> The defaults use unprivileged TCP connect scans. See [SECURITY.md](SECURITY.md)
> for the full model (sandbox, scope, tool-poisoning linter, HTTP auth).

**Shared/remote hosting** (`RECONGURU_TRANSPORT=http`): set
`RECONGURU_HTTP_AUTH_TOKEN` to require `Authorization: Bearer <token>` on every
request. It binds loopback by default; put TLS / a reverse proxy in front for real
exposure.

---

## Architecture

```
  Harness (Claude Code / Codex / …) + its LLM        ← the brain
        │  MCP  (stdio locally, or HTTP when hosted)
        ▼
  reconguru-mcp server  (FastMCP = the tool registry)
        │  advertises every tool's schema (from type hints + docstrings)
        ▼
  tools/*.py ──► sandbox runner ──► subprocess (nuclei, httpx, nmap, …)
       │          (arg-list exec, per-tool timeout, output cap)
       ▼
  shared /workspace  ← tools chain data here; collect_findings correlates it
```

`reconguru_mcp/app.py` holds the FastMCP instance (the registry). The loader in
`reconguru_mcp/tools/__init__.py` imports every module in `tools/`, so each tool
self-registers — **adding a tool = adding a file.**

---

## Local development (no Docker)

For hacking on the server itself (Python 3.11+):

```bash
python -m venv .venv && . .venv/Scripts/activate   # or: source .venv/bin/activate
pip install -r requirements.txt
python -m reconguru_mcp          # run the server over stdio
```

Native tools (subdomain_enum, http header capture, etc.) work, but the
binary-backed tools (nuclei, httpx, naabu, …) report "binary not available"
unless those binaries are on your PATH — which is exactly why the Docker image
exists. A `.venv` harness config (nmap must be on your host):

```json
{
  "mcpServers": {
    "reconguru": {
      "command": "/absolute/path/to/recon-guru-mcp/.venv/bin/python",
      "args": ["-m", "reconguru_mcp"],
      "cwd": "/absolute/path/to/recon-guru-mcp"
    }
  }
}
```

---

## Add your own tool

Create `reconguru_mcp/tools/mytool.py`:

```python
from ..app import mcp
from .. import scope, workspace
from ..config import settings
from ..sandbox import run_tool
from ..validate import InvalidTarget, validate_target


@mcp.tool()
async def mytool_scan(target: str, extra_args: str = "") -> dict:
    """One-line description the agent reads to decide when to use this tool."""
    try:
        host = validate_target(target)
    except InvalidTarget as e:
        return {"ok": False, "error": str(e)}
    if not scope.in_scope(host):
        return {"ok": False, "error": f"{host} is out of scope"}

    import shlex
    args = shlex.split(extra_args) if extra_args.strip() else ["--default-flag"]
    result = await run_tool(["mytool", *args, host], timeout_s=settings.timeout_for("mytool"))
    # write bulk output to the workspace; return a small envelope
    return result.to_dict()
```

Add the `mytool` binary to the `Dockerfile`, rebuild, and the loader registers it
automatically.

> **Security note.** Tools run with the server's privileges and a tool's
> name/description is sent to the LLM — a malicious description is prompt injection
> ("tool poisoning"). Review any tool you didn't write. A startup **registration
> linter** warns about suspicious tool metadata, and the Docker sandbox is the
> backstop. See [SECURITY.md](SECURITY.md).

---

## Methodology skills (optional)

reconguru-mcp gives your harness the **tools**; the *methodology* (which tool to
run next, how to pivot, how to judge a finding) comes from the harness's own LLM
plus any **skills** you install in it. Skills are a harness feature (Claude Code
loads `SKILL.md` files) — this server doesn't ship or serve them, but these
open-source skill sets pair well:

- **[Claude-Red](https://github.com/SnailSploit/Claude-Red)** (MIT) — the recon /
  web-API slice helps the brain interpret and validate findings.
- **[osint-agent-skills](https://github.com/frangelbarrera/osint-agent-skills)** —
  its `domain-to-infrastructure` / `ip-to-attribution` pivots fit the web/infra scope.

Install them in your harness, not in this server; the brain combines them with
reconguru-mcp's tools at runtime.

---

## Status & roadmap

**Complete.** All build stages are done — framework → Docker sandbox → the 18-tool
suite → findings model → authenticated recon → hardening → packaging. (A planned
"methodology skills" stage was intentionally folded into *optional external
skills* rather than built in — see the section above.) Full detail, design
decisions, and the tiered tool catalog are in **[ROADMAP.md](ROADMAP.md)**.

### Does the brain actually help?

Same 18 tools, same target (`testasp.vulnweb.com`), brain off vs on — the only
variable is the LLM orchestration:

| | Brain-off (linear CLI) | Brain-on (agentic) |
|---|---|---|
| Tools run | 16 (4 wasted/errored) | **12** (0 errors) |
| Wall-clock | 453 s | **306 s (−32%)** |
| Findings reported | 15 | 6 |
| &nbsp;&nbsp;· info-level noise | **10 (67%)** | **0** |

The agentic mode isn't faster because it scans faster (identical binaries) — it's
faster and cleaner because it **skips irrelevant tools** and **tunes out noise**.
Full methodology and an honest "why vuln-labs under-represent recon" note in
[BENCHMARK.md](BENCHMARK.md).
