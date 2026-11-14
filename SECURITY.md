# Security model

reconguru-mcp runs offensive recon tools, so its security posture matters in two
directions: protecting **the host it runs on** from the tools, and protecting
**the operator** from a malicious tool definition. Here's how it's layered.

> **Authorized testing only.** Only scan hosts you own or have explicit written
> permission to test. The scope controls below help, but they are your safety net,
> not your authorization.

## 1. The sandbox (primary containment)

Everything — the MCP server and every tool binary — runs **inside a Docker
container**. Tools execute as subprocesses in that isolated Linux environment,
with no access to the host filesystem beyond the mounted `/workspace` volume.

Run it hardened:

```bash
docker run -i --rm \
  --user 1000:1000 --cap-drop ALL --security-opt no-new-privileges \
  --pids-limit 512 --memory 2g --cpus 2 \
  -v reconguru-workspace:/workspace \
  reconguru-mcp:latest
```

- **Non-root:** the image runs as the unprivileged `recon` user (uid 1000).
- **Dropped capabilities / no-new-privileges:** no privilege escalation.
- **Resource limits:** `--pids-limit`, `--memory`, `--cpus` bound a runaway scan.
- SYN scans (`nmap -sS`, raw `naabu`) need `--cap-add=NET_RAW`; the defaults use
  unprivileged TCP connect scans so you don't have to grant it.

## 2. Command execution (no shell injection)

Tools never build a shell string. `reconguru_mcp/sandbox.py` runs every binary
with an **argument list** via `asyncio.create_subprocess_exec` — there is no
shell for a target or flag to inject into. A per-tool **timeout** kills hung
scans and output is **size-capped** so a huge scan can't flood the harness.

## 3. Scope control (authorization layer)

`reconguru_mcp/validate.py` rejects malformed / injection-shaped targets.
`reconguru_mcp/scope.py` adds an **allow/deny** layer on top: optional
`scope_include.txt` / `scope_exclude.txt` in the workspace (patterns like
`example.com`, `*.example.com`, `192.0.2.0/24`). Discovery tools filter their
output; active tools refuse out-of-scope targets.

## 4. Tool poisoning (protecting the operator)

A tool's name and description are sent **verbatim to the connected LLM**, so a
malicious tool definition is a prompt-injection vector. Two mitigations:

- A startup **registration linter** (`reconguru_mcp/linter.py`) scans every
  registered tool's metadata for injection phrases ("ignore previous
  instructions"), hidden/zero-width characters, and anomalies, and **warns on
  stderr** before a harness ever calls the tool. It's a warning, not hard
  enforcement — the sandbox is the real backstop — but it surfaces a bad tool.
- **Review any tool you didn't write.** Adding a tool = adding a file in
  `tools/`; treat third-party tools like any other dependency.

## 5. Secrets & credentials

- API keys live in a git-ignored `.env` (`RECONGURU_*`), never in the repo.
- httpx request-URL logging is **silenced** so a Shodan-style key-in-URL can't
  leak into logs.
- **Authenticated recon:** the toolkit never logs in or creates accounts. You
  supply a session you captured yourself (cookie/bearer) via `RECONGURU_AUTH_HEADER`
  or a tool's `auth` argument; it is injected as a header and never logged.

## 6. HTTP transport (shared hosting)

stdio (the default) is the safest mode — the harness launches the process, no
network listener. For shared/remote hosting (`RECONGURU_TRANSPORT=http`):

- Set **`RECONGURU_HTTP_AUTH_TOKEN`** — every request then needs
  `Authorization: Bearer <token>` (constant-time compared). Without it the server
  warns loudly that the endpoint is unauthenticated.
- It binds **loopback (`127.0.0.1`) by default**, not `0.0.0.0`.
- Put it behind TLS / a reverse proxy for real exposure; the bearer token is a
  floor, not a complete auth system.

## Reporting

This is a portfolio/self-hosted project, not a hosted service. If you find an
issue, open an issue on the repository.
