# reconguru-mcp

> **⚠️ Authorized security testing only.** Only scan hosts you own or have explicit
> permission to test. For practice, use the nmap project's public host
> `scanme.nmap.org`.

An extensible, sandboxed **MCP toolserver for web reconnaissance**. It ships a set
of recon tools and lets anyone add their own (custom or industry-standard) in a few
lines — then drive them from any MCP-compatible harness (Claude Code, Codex, Cursor,
etc.). You ship tools; the harness brings the brain.

This is **Setup 2**: a tool-provider, not a standalone agent. The intelligence
(deciding which tool to run, in what order, and triaging results) comes from the
connected harness's LLM.

---

## Status — Stage 1

| Piece | State |
|---|---|
| FastMCP server (stdio + optional HTTP) | ✅ |
| Async sandbox runner (arg-list, timeout, output cap) | ✅ |
| Target validation (host / IP / CIDR, no shell metacharacters) | ✅ |
| `target + extra_args` tool pattern | ✅ |
| Example tool: `nmap_scan` | ✅ |
| Docker sandbox (nmap baked in, non-root, isolated) | ✅ |
| Ported reconGuru tools (subdomains, probe, tech, …) | ⏳ Stage 3 |
| Structured/traceable findings + triage | ⏳ Stage 4 |

---

## Architecture

```
  Harness (Claude Code / Codex / …) + its LLM
        │  MCP  (stdio locally, or HTTP when hosted)
        ▼
  reconguru-mcp server
        │  FastMCP advertises every registered tool
        ▼
  tools/*.py   ──►  sandbox runner  ──►  subprocess (nmap, …)
  (@mcp.tool)        (timeout, caps)      runs on the host (Stage 1)
                                          or in Docker (Stage 2)
```

The FastMCP instance in `reconguru_mcp/app.py` **is the registry**: it builds each
tool's schema from the function's type hints + docstring. The loader in
`reconguru_mcp/tools/__init__.py` imports every module in `tools/`, so each tool
self-registers.

---

## Requirements

- **Python 3.11+**  (not currently installed on this machine — see below)
- `nmap` on your PATH to run the example tool locally at Stage 1
  (Stage 2's Docker image will provide it instead)

### Installing Python on Windows

```powershell
winget install -e --id Python.Python.3.12
```

Then **open a new terminal** so `python` resolves. If Windows still launches the
Store stub, turn off the alias in *Settings → Apps → Advanced app settings →
App execution aliases* (disable `python.exe` / `python3.exe`).

---

## Setup & run

```bash
# from the reconguru-mcp/ directory
python -m venv .venv
.\.venv\Scripts\Activate.ps1          # PowerShell;  or  source .venv/bin/activate
pip install -r requirements.txt
```

Smoke test (no harness needed):

```bash
python tests/smoke_test.py
```

Run the server over stdio:

```bash
python -m reconguru_mcp
```

---

## Run with Docker (recommended)

The image bundles the tool binaries (nmap, …) so scans run in an isolated Linux
sandbox on any host — no local nmap needed.

```bash
docker build -t reconguru-mcp:latest .

# smoke test (runs a live scan of scanme.nmap.org inside the container)
docker run --rm --entrypoint python reconguru-mcp:latest tests/smoke_test.py

# run the MCP server over stdio (a harness attaches to this)
docker run -i --rm reconguru-mcp:latest
```

Hardened run (drops privileges/capabilities, limits resources, isolates the
workspace):

```bash
docker run -i --rm \
  --user 1000:1000 --cap-drop ALL --security-opt no-new-privileges \
  --pids-limit 512 --memory 1g --cpus 2 \
  -v reconguru-workspace:/workspace \
  reconguru-mcp:latest
```

> SYN scans (`-sS`) need raw sockets; add `--cap-add=NET_RAW` if you want them.
> The default scan uses a TCP connect scan, which works unprivileged.

## Connect a harness (Claude Code / Claude Desktop)

Add to your MCP client config (e.g. `claude_desktop_config.json`).

**Docker (recommended)** — the harness launches the container over stdio:

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

**Local venv (no Docker)** — note nmap must be installed on your host:

```json
{
  "mcpServers": {
    "reconguru": {
      "command": "C:\\Projects\\ReconGuru\\reconguru-mcp\\.venv\\Scripts\\python.exe",
      "args": ["-m", "reconguru_mcp"],
      "cwd": "C:\\Projects\\ReconGuru\\reconguru-mcp"
    }
  }
}
```

Then ask the harness something like: *"Use reconguru to scan scanme.nmap.org and
summarize the open ports."*

---

## Add your own tool

Create `reconguru_mcp/tools/mytool.py`:

```python
from ..app import mcp
from ..sandbox import run_tool
from ..validate import InvalidTarget, validate_target

@mcp.tool()
async def mytool_scan(target: str, extra_args: str = "") -> dict:
    """One-line description the agent reads to decide when to use this tool."""
    try:
        tgt = validate_target(target)
    except InvalidTarget as e:
        return {"ok": False, "error": str(e)}
    import shlex
    args = shlex.split(extra_args) if extra_args.strip() else ["--default-flag"]
    return (await run_tool(["mytool", *args, tgt])).to_dict()
```

Make sure the `mytool` binary is on PATH (Stage 1) or in the Docker image (Stage 2).
That's it — the loader registers it automatically.

> **Security note.** Tools you add run with the server's privileges. Only add tools
> you trust, and review any tool definition you did not write yourself — a tool's
> name and description are shown to the LLM, so a malicious description is a form of
> prompt injection ("tool poisoning"). The Docker sandbox is the backstop that
> limits what any tool can do, and a startup **registration linter** warns about
> suspicious tool metadata.

---

## Methodology skills (optional)

reconguru-mcp gives your harness the **tools**; the *methodology* (which tool to
run next, how to pivot, how to judge a finding) comes from your harness's own LLM
plus any **skills** you install in it. Skills are a harness feature (e.g. Claude
Code loads `SKILL.md` files) — reconguru-mcp doesn't ship or serve them, but these
open-source skill sets pair well if you want methodology scaffolding:

- **[Claude-Red](https://github.com/SnailSploit/Claude-Red)** (MIT) — the recon /
  web-API slice (`offensive-osint`, `offensive-api-security`, and the web-vuln
  skills) helps the brain interpret and validate what these tools find.
- **[osint-agent-skills](https://github.com/frangelbarrera/osint-agent-skills)** —
  its `domain-to-infrastructure` and `ip-to-attribution` pivot playbooks fit the
  web/infra recon scope (the identity-OSINT pivots are out of scope here).

Install them in your harness (not in this server); the brain combines them with
reconguru-mcp's tools at runtime.
