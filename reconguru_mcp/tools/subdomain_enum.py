"""subdomain_enum — passive subdomain discovery from OSINT sources.

Fans out to several public passive sources concurrently, normalizes and
deduplicates the hostnames, scope-filters them, and merges them into the
canonical ``/workspace/subdomains.txt``. It returns a small *envelope*
(counts, per-source breakdown, a sample, the file path) — the full list lives
in the workspace file, not in the model's context.

This is the worked example of a *native* tool (ported from recon-guru): unlike
``nmap_scan`` it doesn't shell out to a binary, it makes HTTP API calls
directly. It is **passive (Tier 0)**: it queries third-party databases *about*
the domain and sends no probes to the target itself. Active DNS brute-forcing
is a separate tool (``dnsx``, Stage 5).
"""

from __future__ import annotations

import asyncio
import re
from urllib.parse import urlparse

import httpx

from .. import scope, workspace
from ..app import mcp
from ..config import settings
from ..validate import InvalidTarget, validate_target

SUBS_FILE = "subdomains.txt"
PER_SOURCE_TIMEOUT = 25  # seconds budget per source (a straggler can't gate the rest)

# Which config attribute holds the key for a keyed source (skipped if blank).
_KEY_FOR = {
    "securitytrails": "securitytrails_api_key",
    "virustotal": "virustotal_api_key",
}

_VALID_LABEL = re.compile(r"^[a-z0-9][a-z0-9.\-]+[a-z0-9]$")


def _normalize(name: str, domain: str) -> str | None:
    """Clean one raw hostname and keep it only if it belongs to the target."""
    name = (name or "").strip().lower().lstrip("*.")
    if "://" in name:
        name = urlparse(name).hostname or ""
    name = name.strip(".")
    if not name:
        return None
    if not (name == domain or name.endswith("." + domain)):
        return None
    if not _VALID_LABEL.match(name):
        return None
    return name


# --- per-source fetchers: each returns a list of raw hostnames ----------

async def _crtsh(client: httpx.AsyncClient, domain: str) -> list[str]:
    r = await client.get(f"https://crt.sh/?q={domain}&output=json")
    r.raise_for_status()
    out: set[str] = set()
    for entry in r.json():
        for nm in (entry.get("name_value", "") or "").splitlines():
            out.add(nm)
    return list(out)


async def _hackertarget(client: httpx.AsyncClient, domain: str) -> list[str]:
    r = await client.get(f"https://api.hackertarget.com/hostsearch/?q={domain}")
    r.raise_for_status()
    return [line.split(",")[0].strip() for line in r.text.splitlines() if line.strip()]


async def _alienvault_otx(client: httpx.AsyncClient, domain: str) -> list[str]:
    r = await client.get(
        f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
    )
    r.raise_for_status()
    return [e.get("hostname", "") for e in r.json().get("passive_dns", [])]


async def _wayback(client: httpx.AsyncClient, domain: str) -> list[str]:
    r = await client.get(
        "https://web.archive.org/cdx/search/cdx"
        f"?url=*.{domain}&output=json&fl=original&collapse=urlkey"
    )
    r.raise_for_status()
    rows = r.json()
    out: set[str] = set()
    for row in rows[1:]:  # first row is the header
        host = urlparse(row[0]).hostname if row else None
        if host:
            out.add(host)
    return list(out)


async def _urlscan(client: httpx.AsyncClient, domain: str) -> list[str]:
    headers = {}
    if settings.urlscan_api_key:
        headers["API-Key"] = settings.urlscan_api_key
    r = await client.get(
        f"https://urlscan.io/api/v1/search/?q=domain:{domain}", headers=headers
    )
    r.raise_for_status()
    out: set[str] = set()
    for res in r.json().get("results", []):
        d = res.get("page", {}).get("domain", "")
        if d:
            out.add(d)
    return list(out)


async def _securitytrails(client: httpx.AsyncClient, domain: str) -> list[str]:
    r = await client.get(
        f"https://api.securitytrails.com/v1/domain/{domain}/subdomains",
        headers={"APIKEY": settings.securitytrails_api_key},
    )
    r.raise_for_status()
    return [f"{s}.{domain}" for s in r.json().get("subdomains", [])]


async def _virustotal(client: httpx.AsyncClient, domain: str) -> list[str]:
    # First page only, to stay within a single per-source budget.
    r = await client.get(
        f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains?limit=40",
        headers={"x-apikey": settings.virustotal_api_key},
    )
    r.raise_for_status()
    return [item.get("id", "") for item in r.json().get("data", [])]


_FETCHERS = {
    "crtsh": _crtsh,
    "hackertarget": _hackertarget,
    "alienvault_otx": _alienvault_otx,
    "wayback": _wayback,
    "urlscan": _urlscan,
    "securitytrails": _securitytrails,
    "virustotal": _virustotal,
}


@mcp.tool()
async def subdomain_enum(target: str, sources: str = "") -> dict:
    """Discover subdomains of a domain from passive OSINT sources.

    Queries public databases *about* the domain (certificate transparency,
    passive DNS, web archives) — it does not touch the target itself. Results
    are normalized, de-duplicated, scope-filtered, and merged into the shared
    workspace file ``subdomains.txt`` for later tools (httpx, dnsx, …) to use.

    Args:
        target: The root domain to enumerate, e.g. "example.com".
        sources: Optional comma-separated subset of sources to use. When empty,
            all available sources run. Valid names: crtsh, hackertarget,
            alienvault_otx, wayback, urlscan, securitytrails, virustotal.
            (securitytrails and virustotal only run if their API key is set;
            urlscan uses its key if present.)

    Returns:
        An envelope with the count found, how many were newly added to the
        workspace file, a per-source breakdown, which sources succeeded /
        failed / were skipped, a small sample, and the output file path. The
        full subdomain list is written to the workspace, not returned inline.
    """
    try:
        domain = validate_target(target)
    except InvalidTarget as e:
        return {"ok": False, "error": str(e)}

    # Select sources.
    if sources.strip():
        requested = [s.strip().lower() for s in sources.split(",") if s.strip()]
        unknown = [s for s in requested if s not in _FETCHERS]
        if unknown:
            return {
                "ok": False,
                "error": f"unknown source(s) {unknown}; valid: {list(_FETCHERS)}",
            }
        selected = requested
    else:
        selected = list(_FETCHERS)

    # Drop keyed sources whose key isn't configured.
    skipped: dict[str, str] = {}
    runnable: list[str] = []
    for name in selected:
        key_attr = _KEY_FOR.get(name)
        if key_attr and not getattr(settings, key_attr):
            skipped[name] = "no API key configured"
        else:
            runnable.append(name)

    if not runnable:
        return {
            "ok": False,
            "error": "no runnable sources (all selected sources need an API key)",
            "sources_skipped": skipped,
        }

    # Fan out concurrently, each source bounded by its own timeout.
    async def run_one(name: str):
        try:
            raw = await asyncio.wait_for(
                _FETCHERS[name](client, domain), timeout=PER_SOURCE_TIMEOUT
            )
            return name, raw, None
        except asyncio.TimeoutError:
            return name, None, "timed out"
        except Exception as e:  # a failing source never fails the whole tool
            return name, None, f"{type(e).__name__}: {e}"

    async with httpx.AsyncClient(
        headers={"User-Agent": settings.user_agent},
        timeout=PER_SOURCE_TIMEOUT,
        follow_redirects=True,
    ) as client:
        results = await asyncio.gather(*(run_one(n) for n in runnable))

    # Normalize + dedup (deterministic — never the LLM's job).
    all_subs: dict[str, set[str]] = {}
    by_source: dict[str, int] = {}
    sources_ok: list[str] = []
    sources_failed: dict[str, str] = {}

    for name, raw, err in results:
        if err is not None:
            sources_failed[name] = err
            continue
        found: set[str] = set()
        for host in raw:
            nm = _normalize(host, domain)
            if nm:
                all_subs.setdefault(nm, set()).add(name)
                found.add(nm)
        by_source[name] = len(found)
        sources_ok.append(name)

    discovered = sorted(all_subs)
    in_scope = scope.filter_in_scope(discovered)
    out_of_scope = len(discovered) - len(in_scope)

    out_path, total_after, added = workspace.merge_lines(SUBS_FILE, in_scope)

    note_bits = []
    if skipped:
        note_bits.append(f"{len(skipped)} source(s) skipped (no key)")
    if sources_failed:
        note_bits.append(f"{len(sources_failed)} source(s) failed/timed out")
    if out_of_scope:
        note_bits.append(f"{out_of_scope} out-of-scope host(s) dropped")

    return {
        "ok": bool(sources_ok),
        "target": domain,
        "found_this_run": len(in_scope),
        "new": added,
        "total_known": total_after,
        "output_file": str(out_path),
        "by_source": by_source,
        "sources_ok": sources_ok,
        "sources_failed": sources_failed,
        "sources_skipped": skipped,
        "sample": in_scope[:20],
        "note": "; ".join(note_bits),
    }
