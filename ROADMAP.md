# reconguru-mcp — Roadmap

> An extensible, sandboxed **MCP toolserver for web & API reconnaissance**.
> You ship tools *and* playbooks; the connected harness brings the brain.
>
> **Status:** Stage 1 ✅ (framework) · Stage 2 ✅ (Docker sandbox + `nmap_scan`, verified against a live harness). This document is the plan for Stage 3 onward.

---

## 1. Vision

reconguru-mcp is **Setup 2**: a tool-provider that any MCP harness (Claude Code / Codex / Cursor / …) connects to and drives with its own LLM. It is a portfolio / open-source project that cloners self-host and extend with their own tools.

The goal is an **"ultimate bug-bounty recon toolkit"** — but scoped deliberately (see §7). "Ultimate" means *depth + correlation + a methodology layer*, **not** a kitchen sink of every offensive tool on GitHub.

### The core realization (from surveying 8 reference projects)

A bundle of tools is **not** a toolkit. A toolkit is **two layers**:

| Layer | What it is | How MCP carries it | Who provides it today |
|---|---|---|---|
| **1. Tools** | Binaries/APIs that *do* the scanning | MCP **tools** (`@mcp.tool()`) | AutoAR, Strix, OpenOSINT, mcp-recon |
| **2. Playbooks** | Methodology: when to pivot, what to chain, how to validate, when to stop | MCP **prompts** + **resources** | osint-agent-skills, Claude-Red, Agentic-Bug-Hunter |

The first four repos we studied (AutoAR, Strix, mcp-recon, ai4eh) are strong on Layer 1 and **have no Layer 2** — they dump tool output into the agent and hope it connects the dots. The second four (Agentic-Bug-Hunter, OpenOSINT, osint-agent-skills, Claude-Red) show Layer 2 is where the real intelligence lives. **reconguru-mcp ships both.** That is the differentiator.

---

## 2. Architecture

```
  Harness (Claude Code / Codex / …) + its LLM  ← the brain
        │  MCP  (stdio locally, or HTTP when hosted)
        ▼
  reconguru-mcp server  (FastMCP = the registry)
        ├─ TOOLS      tools/*.py   → sandbox runner → subprocess (nmap, nuclei, …)
        ├─ PROMPTS    prompts/*.py → pivot playbooks, validation gate, correlation guidance
        └─ RESOURCES  findings schema, wordlist index, ethics/scope rules
        │
        ▼
  Shared /workspace  ← tools chain data here (NOT through the LLM)
```

Two orthogonal axes to keep straight:

- **Delivery stage** (§6) = the order we *build* things.
- **Safety tier** (§4) = runtime risk metadata stamped on *each tool*, so the brain and the user know what is safe to run broadly vs what needs explicit authorization.

---

## 3. The data problem reconguru-mcp solves that the references don't

Old recon-guru (and AutoAR, and Strix) never **correlate across tools** — e.g. "tech-stack says Jenkins on 8080 + port scan says 8080 open + that Jenkins version has an RCE = investigate." The pipeline/shell approach keeps those streams separate.

The fix is a **structured, traceable findings schema** keyed on a shared join key, written to `/workspace/findings/`:

```jsonc
{
  "id": "finding-0001",
  "target": "app.example.com",
  "host": "app.example.com",
  "ip": "203.0.113.5",
  "port": 8080,
  "service": "http",
  "tech": ["Jenkins 2.346"],
  "tool": "nuclei",
  "type": "cve",
  "ref": "CVE-2024-XXObjectXX",
  "severity": "high",
  "evidence": "…raw output excerpt…",
  "output_hash": "sha256:…",   // integrity — a verifier, not the LLM, confirms it
  "validated": false,          // flips true only after the validation gate
  "confidence": "unconfirmed"
}
```

With this, correlation becomes a **lookup over shared keys**, not an LLM guess. The brain does *judgment* ("is this exploitable in context, what's next"); the schema + tools do the *facts*.

---

## 4. Safety-tiered tool catalog

Every tool is stamped with a tier in its metadata so the brain and the user know what's safe to run broadly. **Scope stops at recon + read-only templated vuln scanning (Tier 3).** Tier 4 active/intrusive exploitation is explicitly out (see §7).

### Tier 0 — Passive OSINT (no packets to target)
Existing recon-guru API sources (crt.sh, HackerTarget, OTX, URLScan, Wayback, VirusTotal, SecurityTrails) · **subfinder** (passive subdomain enum) · **gau** / **waybackurls** (historical URLs) · **asnmap** (ASN→IP ranges) · **Shodan** (keep recon-guru's) · **Censys** *(optional)*

### Tier 1 — Active enumeration (touches target, benign)
**httpx** (live probe + fingerprint; replaces aiohttp) · **dnsx** (DNS resolve/brute; replaces dnspython) · **naabu** (port sweep; replaces masscan) · **nmap** (service/version ✅) · **katana** (crawl) · **wafw00f** (WAF/CDN detect)

### Tier 2 — Fingerprint & content discovery (low–medium)
tech detection via **httpx `-td`** (in `http_probe`) · **ffuf** + **SecLists** (content & dir discovery) · **arjun** (hidden-param discovery) · **trufflehog** (secrets in downloaded JS)

### Tier 3 — Read-only vulnerability scanning (sends benign probes — this is the ceiling)
**nuclei** (templated CVEs/misconfigs/exposures — *the* high-value anchor; templates pre-baked in the image) · takeover: **nuclei's takeover templates** (not a separate tool — lean) + CNAME context from dns_enum · passive CVE map: **searchsploit** + **NVD** (keep recon-guru's exploit_lookup)

> **Cut as redundant:** `wappalyzer` + `whatweb` (httpx `-td` covers tech detection; dropped whatweb's Ruby too, Stage 5) · `subjack` + `DNSReaper` (nuclei's takeover templates cover dangling-CNAME detection — no separate tool) · `gitleaks` (trufflehog covers secrets) · **`Retire.js`** (Node runtime too heavy for the value — same call as gowitness/whatweb; nuclei templates cover outdated-JS detection).

> The **ProjectDiscovery suite** (subfinder · dnsx · naabu · httpx · katana · nuclei · asnmap) is the consensus backbone across every reference project — it's the spine, prioritized accordingly.
>
> **Cut from scope (2026-11-12):** Tier 4 active/intrusive (dalfox, sqlmap, OWASP ZAP, nuclei intrusive templates, 403-bypass fuzzing) — too heavy, and past the recon line. Identity-OSINT sub-tier (sherlock, holehe, phoneinfoga, theHarvester, breach APIs) — out of the web/API recon focus.

---

## 5. The playbook layer (Layer 2)

Shipped as MCP **prompts** and **resources** — this is what the first four reference repos lack. **We do not author these from scratch — we reuse the existing skill repos** and wire them in, pointing the brain at adapted versions:

- **Pivot playbooks** — reuse **osint-agent-skills'** playbooks (`domain → infrastructure`, `ip → attribution`) + the recon-relevant slice of **Claude-Red's** web/API methodology skills (SQLi/XSS/SSRF/IDOR/GraphQL/JWT/API-Top-10 *as reasoning guidance*, not as tools). Exposed as MCP prompts keyed to triggers.
- **Correlation prompt:** instructs the brain to join findings across tools by `host/ip/port` before triaging.
- **Validation gate:** reuse **Agentic-Bug-Hunter's** "7-Question Gate" pattern + osint-agent-skills' output-hash integrity — a finding flips `validated: true` only after passing the checklist. Kills hallucinated findings.
- **Scope / ethics resource:** authorized-testing rules and tier explanations.

---

## 6. Delivery stages

| Stage | Deliverable | Notes |
|---|---|---|
| **1 ✅** | Framework: server, sandbox runner, validation, `nmap_scan` | Done |
| **2 ✅** | Docker image, nmap baked in, live harness-verified | Done |
| **3 ✅** | **Port recon-guru's tools** into the registry (7 tools) | subdomain_enum, live_probe, tech_stack, port_scan (naabu+nmap), exploit_lookup, shodan_enrich, report_gen — reading/writing `/workspace`. **screenshot/gowitness dropped** (least agent-usable, heaviest dep — Chromium; see §7) |
| **4** | **Structured findings schema + correlation + validation gate** | §3 + §5. The differentiator. Build *before* piling on tools |
| **5** | **ProjectDiscovery backbone** (Tier 0–1) | httpx, dnsx, naabu, subfinder, katana, gau — bake into Docker image |
| **6 ✅** | **Content discovery (Tier 2)** | ffuf + SecLists, wafw00f, arjun, trufflehog (secret_scan over JS). Retire.js dropped |
| **7 ✅** | **nuclei (Tier 3)** + takeover | vuln_scan (nuclei, severity/tags) + takeover_check (nuclei takeover templates). Both → findings. DNSReaper dropped (nuclei covers it) |
| **8** | **Playbook layer** — MCP prompts + resources | **Reuse** osint-agent-skills + Claude-Red (recon slice) + Agentic-Bug-Hunter's validation gate; wire in, don't author |
| **8** | **Methodology skills** | Collapsed: skills are harness-side (user-installed), we author none — README points to optional Claude-Red / osint-agent-skills |
| **9 ✅** | **Hardening & hosting** | Registration linter (tool-poisoning), HTTP bearer auth (loopback default), SECURITY.md, resource limits |
| **10** | **Portfolio packaging** | README polish, demo, "add your own tool/playbook" guide, example harness configs |

> **Cut:** former Stage 9 (active/intrusive tier) and Stage 10 (OSINT/identity tier) are out of scope — see §4 and §7.

Ordering principle: **schema (Stage 4) before volume (Stage 5+)** — structured findings make every later tool more valuable and the brain's correlation reliable.

---

## 7. Scope boundaries (what reconguru-mcp is NOT)

Claude-Red's 78 skills sprawl into wireless, Active Directory, IoT, cloud, C2 frameworks, exploit dev, and EDR evasion. **We deliberately exclude all of that.** reconguru-mcp stays focused on:

- ✅ **Web + API reconnaissance** (the core)
- ✅ **Read-only templated vuln scanning** (nuclei, takeover, CVE mapping) — the ceiling, Tier 3
- ✅ **A reused methodology/playbook layer** that makes the brain effective
- ❌ **No active/intrusive exploitation** — no sqlmap, OWASP ZAP, dalfox, or payload-sending fuzzing (too heavy; past the recon line). Authenticated recon doesn't change this: scanning behind a login is still recon; *exploiting* a found SQLi with sqlmap is not.
- ❌ **No identity OSINT** — no sherlock/holehe/theHarvester/breach APIs (outside web/API focus)
- ❌ **No screenshots / visual capture** — gowitness dropped entirely (Chromium-heavy; and images aren't usable by the brain in our text-envelope model — visual triage is a human task the report already supports structurally)
- ❌ Not wireless / hardware / RF, not Active Directory / internal network, not C2 / post-exploitation / evasion, not mobile/firmware, not exploit development

"Ultimate" = **depth and correlation within web/API recon**, plus the reused playbook layer no one else ships — not maximal surface area. Everything shipped either *gathers information* or runs *read-only templated checks*; nothing tries to break the target.

---

## 8. Reference projects surveyed

**Layer-1 (tools):** [AutoAR](https://github.com/h0tak88r/AutoAR) (CLI pipeline orchestrator) · [Strix](https://github.com/usestrix/strix) (raw-shell Kali sandbox) · [mcp-recon](https://github.com/nickpending/mcp-recon) (minimal MCP server — closest to our model) · [ai4eh](https://github.com/ethiack/ai4eh) (workshop; AI-assisted wrappers, EyeBaller screenshot CNN)

**Layer-2 (playbooks) & hybrids:** [Agentic-Bug-Hunter](https://github.com/awarexone/Agentic-Bug-Hunter) (plugin+CLI+MCP, validation gate) · [OpenOSINT](https://github.com/OpenOSINT/OpenOSINT) (21-tool passive-by-default OSINT MCP) · [osint-agent-skills](https://github.com/frangelbarrera/osint-agent-skills) (pivot-playbook knowledge base) · [Claude-Red](https://github.com/SnailSploit/Claude-Red) (78 offensive methodology skills — scope cautionary tale)

---

## 9. Execution & output model (decisions of record)

How tools run, chain, and get configured. These decisions drive how every Stage-3 tool is written.

### 9.1 What the brain sees vs what stays in the workspace

An MCP tool call is **synchronous**: the brain calls a tool, the call blocks, and on completion returns a small **result envelope** — that return *is* the completion signal. A layer is done when every call fired for it has returned.

- **To the brain (small):** status, exit code, duration, counts, a one-line `note`, and the `/workspace` file path(s) written. Capped at `RECONGURU_MAX_OUTPUT_CHARS`.
- **To `/workspace` (bulk):** the actual subdomains, raw scan XML, crawl output. Passed tool→tool by path. The brain orchestrates **by reference** and never holds big lists in context.

> Earlier shorthand "the LLM never reads output" means the **bulk** output — it always gets the envelope.

### 9.2 Data hygiene is deterministic code, never the LLM

Merging multiple sources (subfinder + crt.sh + …), normalizing, and **deduping** happen in tool code via `workspace.merge_lines()` (set-union). One canonical file per data type:

```
/workspace/  subdomains.txt · live_hosts.txt · urls.txt · ports.json
             findings/*.json · scope_include.txt · scope_exclude.txt
```

Discovery is **one `subdomain_enum` tool** that fans out to sources concurrently and returns a merged, deduped set — porting recon-guru's existing `by_source` + normalize logic. A slow source is bounded by a **per-source timeout** and the tool returns the union of whatever finished, naming any that timed out (so a slow subfinder never gates a fast crt.sh).

### 9.3 Scope control (`scope.py`)

Authorization layer on top of `validate_target`'s format check. Optional `scope_include.txt` / `scope_exclude.txt` (one pattern per line: `example.com`, `*.example.com`, `192.0.2.0/24`). Excluded → out; if an allowlist exists the target must match it; no allowlist → everything not excluded is allowed (opt-in, no surprise lockdown). Discovery tools filter results; active tools refuse out-of-scope targets.

### 9.4 Timeouts & partial results

- **Per-tool timeouts**, not one global: `settings.timeout_for(tool)` (nuclei 1800s, ffuf 900s, …; default 300s), overridable via `RECONGURU_TIMEOUT_<TOOL>`.
- **Incremental output to disk** for heavy tools (nuclei `-jsonl -o`, httpx `-o`) so a timeout kill never loses already-found results.
- **Scope-then-deepen:** the brain scans shallow-wide, triages, then runs heavy tools only on interesting hosts — avoiding blind mega-scans.

### 9.5 Modularity, on-demand reporting, smart triage

Every tool is independently callable — "just port scan X", "just subdomains", "tech of one host" run that tool alone (no pipeline delay). Partial results in `/workspace` + the envelopes in context let the brain answer follow-ups and **recommend next steps / prioritize** ("8080 runs old Jenkins — the one worth attention"). `report_gen` is an **any-time tool**, not a fixed final stage: it renders whatever exists in `/workspace`, scoped to what the user asks (recon-guru's report is already partial-data-tolerant).

### 9.6 Configuration (`config.py` + `.env`)

Everything tunable lives in env vars / a git-ignored `.env` (copy `.env.example`), loaded by a typed pydantic `Settings`. Namespaced `RECONGURU_`. Configurable: transport · timeouts (global + per-tool) · output cap · concurrency / rate-limit / stealth / user-agent · workspace dir · wordlist paths · nuclei severity+templates · optional API keys (Shodan, VirusTotal, SecurityTrails, URLScan, Censys, GitHub, Chaos — blank = that source is skipped). No code edits to configure; works via `--env-file` in Docker or the harness config's `env` block.

### 9.7 Three consumption modes (same registry)

1. **MCP server** (Setup 2) — harness brings the brain. ✅ current.
2. **Plain CLI / library** — call tools directly, no LLM (deterministic, = linear recon-guru). Doubles as the **benchmark control**: brain off vs on, same tools.
3. **Standalone agent** (Setup 3) — built-in loop + BYO key. *Deferred — not now.*

### 9.8 Benchmarking (portfolio)

AI version optimizes **analyst time + result quality**, not raw scan throughput (same binaries underneath). Compare Mode 2 (brain off) vs Mode 1 (brain on) on a known-vulnerable target: **precision** (actionable ÷ reported), correlation findings single tools miss, false-positive rate, wasted scans avoided, **time-to-first-actionable-finding**, report read-time. Be honest: on small targets linear can be faster; AI wins on large/messy targets via pruning, and on total time-to-signal. Trade-offs to state: token cost, less-perfect reproducibility (mitigate with temp 0 + logged decisions).

### 9.9 Authenticated recon (implemented)

Many targets gate content behind a login. **The toolkit never logs in or creates accounts** — that would mean handling the user's real credentials, which is both a safety line and pointless for headless CLI scanners. Instead it *consumes* a session the user already has:

- The **user authenticates themselves** and a **session cookie / bearer token** is captured — in their own browser, or (smoothest) in the harness's browser, which can open the login page and read the session after the user signs in. The agent never types the password.
- The session is handed to the toolkit as a **raw HTTP header** — per call via a tool's `auth` argument, or globally via **`RECONGURU_AUTH_HEADER`** (git-ignored `.env`, never logged — §9.6 hygiene). Per-call overrides global.
- HTTP tools **inject it as a header**: native tools (`live_probe`, `tech_stack`) via httpx, subprocess tools via `-H` (`auth.cli_args()`). Helper: `reconguru_mcp/auth.py` (`header_dict`, `cli_args`, `resolve`).
- The **brain flags** auth-gated targets (401/403, login redirects seen by `live_probe`) and asks the user to supply/capture a session — it does not attempt the login itself.

**Why not a browser in the container:** the server is headless, so a bundled browser is invisible to the user (can't log in to it); making it visible needs noVNC + a full Chromium (the bloat we dropped gowitness to avoid) and only helps harnesses with no browser of their own. So the browser stays on the harness/user side; the container just consumes the captured session. **Limitation:** `httpOnly` session cookies aren't readable by page JS (`document.cookie`) — fully-automatic capture needs the harness browser's cookie-store/CDP access; otherwise it's a one-time devtools copy.

**Status:** `auth` param on `live_probe` + `tech_stack`, `RECONGURU_AUTH_HEADER` config, and `auth.py` are implemented and tested. Later HTTP/subprocess tools (httpx, katana, nuclei, ffuf) adopt `auth.cli_args()` as they're added.
