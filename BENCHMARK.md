# Benchmark: brain-on vs brain-off

Does the LLM orchestration actually add value, or is reconguru-mcp just a tool
bundle? To isolate that, we run **the same tools** two ways and compare:

- **Mode 2 (brain-off)** — `reconguru_mcp/cli.py`: runs all 16 tools in a fixed
  order, no LLM, no skipping or tuning. The deterministic baseline.
- **Mode 1 (brain-on)** — a model (acting as the harness's brain) picks which
  tools to run, in what order, and tunes them, based on what it observes
  (script: [`benchmark/mode1_adaptive.py`](benchmark/mode1_adaptive.py)).

Same image, same tools, same target — the **only variable is the brain.**

## Results — `http://testasp.vulnweb.com` (old IIS/ASP test app)

| Metric | Mode 2 — brain-off | Mode 1 — brain-on |
|---|---|---|
| Tools run | **16** (4 errored/wasted) | **12** (0 errors) |
| Wall-clock | **452.7 s** | **305.8 s** (−32%) |
| nuclei time | 322.8 s (all severities) | 121.1 s (info excluded) |
| Findings reported | **15** | **6** |
| &nbsp;&nbsp;· info-level noise | **10 (67%)** | **0** |
| &nbsp;&nbsp;· actionable (low+) | 5 | 5 |

The brain, having observed a single web app on a standard port, **skipped 4 tools
with no surface here** (`subdomain_enum`, `dns_enum`, `takeover_check`,
`shodan_enrich`), ran the rest with correct inputs (Mode 2 wasted `url_collect` +
`secret_scan` by feeding a URL where a domain was needed), and **ran nuclei
without info-level templates** — which alone cut ~200 s and all 10 noise findings.

## What this proves

Same binaries, so the brain isn't scanning *faster*. It wins by doing **less
useless work** (skip irrelevant tools, feed correct inputs) and **reporting less
noise** (drop info-level matches) — turning "run everything, report everything"
into "run what's relevant, report what matters." That's the thing the old linear
recon-guru structurally could not do.

## An honest note on the findings (why the counts are low)

Both modes found only 5 real issues (missing security headers) and a pile of
info. **That's the target, not the tools.** The public "vulnerable web app" sites
— DVWA, Juice Shop, *and* the Vulnweb family (testphp/testasp) — are
**exploitation labs**: their real vulns are SQLi / XSS / file-upload in forms,
which (a) need **active exploitation** (sqlmap/dalfox — deliberately out of our
recon scope) and (b) are **invisible to nuclei**, which matches *known signatures*,
not app-logic bugs. A recon toolkit correctly finds their *surface*, not their
vulns.

Recon shines on different issues — CVE'd software, subdomain takeovers, exposed
secrets, misconfigured panels — which these labs don't have. To see those, point
it at a target that *has* them (a self-hosted old WordPress/Jenkins, or your own
domain) and set an **NVD API key** so `exploit_lookup` can map versions to CVEs
(it was throttled here without one).

So this benchmark measures **orchestration value** (brain on vs off), which it
shows cleanly; it is *not* a measure of absolute vulnerability yield.

## Reproduce

```bash
# Mode 2 (brain-off, all tools)
docker run --rm -v bench-m2:/workspace --entrypoint python \
  reconguru-mcp:latest -m reconguru_mcp.cli http://testasp.vulnweb.com

# Mode 1 (brain-on, adaptive selection)
docker run --rm -e PYTHONPATH=/app -v bench-m1:/workspace \
  -v "$PWD/benchmark/mode1_adaptive.py:/mode1.py:ro" --entrypoint python \
  reconguru-mcp:latest /mode1.py
```
