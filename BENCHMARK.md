# Benchmark: brain-on vs brain-off

Does the LLM orchestration actually add value, or is reconguru-mcp just a tool
bundle? To isolate that, we run **the same tools** two ways and compare:

- **Mode 2 (brain-off)** — `reconguru_mcp/cli.py`: runs all 16 tools in a fixed
  order, no LLM, no skipping or tuning. The deterministic baseline.
- **Mode 1 (brain-on)** — a model (acting as the harness's brain) picks which
  tools to run, in what order, and tunes them, based on what it observes.

Same image, same tools, same target — the **only variable is the brain.**

> **Caveat up front.** This was one run of each against a *live, remote* target,
> so some numbers (especially nuclei's) carry run-to-run variance. The
> deterministic wins (which tools ran, info-noise suppression) are reproducible;
> treat the exact finding counts as indicative, not exact. A controlled local
> target run repeatedly would tighten them.

## Setup

- **Target:** `https://pentest-ground.com:4280` — a DVWA instance on Pentest-Ground,
  a purpose-built authorized testing playground.
- **Brain's observation that drove Mode 1:** `http_probe` saw a single Nginx/PHP
  web app on a non-standard port — no subdomains, no DNS pivots, no archives, no
  CNAME, no Shodan surface. So the brain **skipped 6 tools** (`subdomain_enum`,
  `dns_enum`, `url_collect`, `port_scan`, `takeover_check`, `shodan_enrich`) and
  ran nuclei **without info-level templates** (noise). Script:
  [`benchmark/mode1_adaptive.py`](benchmark/mode1_adaptive.py).

## Results

| Metric | Mode 2 — brain-off | Mode 1 — brain-on |
|---|---|---|
| Tools run | **16** (all) | **9** (6 skipped as irrelevant) |
| Errored / no-op steps | 5 errored + several no-ops | **0 errors** |
| Wall-clock | **239.2 s** | **188.3 s** (−21%) |
| nuclei time | 176.4 s (all severities) | 129.2 s (info excluded) |
| Findings reported | **14** | **6** |
| &nbsp;&nbsp;· info-level noise | **9** (64%) | **0** |
| &nbsp;&nbsp;· low (missing headers) | 5 | 5 |
| &nbsp;&nbsp;· high (DVWA setup page) | 0 \* | **1** |
| Precision (non-noise ÷ reported) | 5/14 = **36%** | 6/6 = **100%** |

\* The high-severity `dvwa-setup` match appeared in Mode 1's run and not Mode 2's.
On a live target that's within nuclei's run-to-run variance (and Mode 2's heavier
all-templates scan may have been throttled) — so we **don't** claim the brain
"found what the dumb mode missed"; we claim the brain's list was cleaner and its
scan lighter.

## What the brain actually bought (and what it didn't)

**Reproducible wins (deterministic brain decisions):**

1. **No wasted work.** Mode 2 fired 7 tools that can't apply to a single web app
   (5 of them *errored*); Mode 1 skipped them and ran 9 relevant tools with zero
   errors. Cleaner execution, and less traffic to the target.
2. **Signal over noise.** Mode 2 reported 14 findings, **64% of them info-level
   noise** (tech-detect, readme.md, robots.txt). Mode 1 tuned nuclei to drop info
   templates, so every one of its findings is low-or-higher — a list an analyst
   can act on without wading through chaff.
3. **~21% faster**, mostly from the focused nuclei pass and no wasted-tool overhead.

**Honestly, what it did *not* buy here:** on this target the skipped tools
errored fast, so the time saving came mainly from the nuclei tuning, not from
avoiding slow wasted scans. The dramatic "wasted scans avoided" time win shows up
on *large* targets (hundreds of dead subdomains), not a single host.

## Takeaway

Same tools, brain off vs on: the brain turns "run everything, report everything"
into "run what's relevant, report what matters." The agentic version isn't faster
because it scans faster (identical binaries) — it's faster and cleaner because it
does **less useless work** and **reports less noise**. That's the thing the old
linear recon-guru structurally could not do.

## Reproduce

```bash
# Mode 2 (brain-off, all tools)
docker run --rm -v bench-mode2:/workspace --entrypoint python \
  reconguru-mcp:latest -m reconguru_mcp.cli https://pentest-ground.com:4280

# Mode 1 (brain-on, adaptive selection)
docker run --rm -e PYTHONPATH=/app -v bench-mode1:/workspace \
  -v "$PWD/benchmark/mode1_adaptive.py:/mode1.py:ro" --entrypoint python \
  reconguru-mcp:latest /mode1.py
```
