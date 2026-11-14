"""http_probe — rich HTTP probing via ProjectDiscovery httpx.

Replaces the old native `live_probe` **and** `tech_stack` with a single faster,
richer tool. For each host (by default from ``/workspace/subdomains.txt``) it
runs the ``httpx`` binary once and records, per host: status + class bucket,
title, web server, **technologies** (httpx -td), content length, **body hash**
(for de-duplicating identical pages), CDN, redirect location, IP, and the
security-relevant response headers — from which it derives **missing-header
findings** (the one unique thing the old tech_stack did, folded in here).

Writes the responders to ``/workspace/live_hosts.txt`` (the canonical fan-out
file downstream tools read) and the full per-host detail to
``/workspace/http_probe.json``. **Tier 1.** Needs the ``httpx`` binary (in the
Docker image); degrades gracefully if it's absent.

Status-code routing (3xx dedup, 4xx retry, 5xx defer) is deliberately left to
the brain's control flow — this tool just gives it the buckets + rich signals.
"""

from __future__ import annotations

import json

from .. import auth as _auth
from .. import scope, workspace
from ..app import mcp
from ..config import settings
from ..sandbox import run_tool

SOURCE_DEFAULT = "subdomains.txt"
LIVE_FILE = "live_hosts.txt"
OUT_FILE = "http_probe.json"
TARGETS_TMP = "_httpx_targets.txt"

SECURITY_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
]


def _bucket(status) -> str:
    try:
        s = int(status)
    except (TypeError, ValueError):
        return "dead"
    if 200 <= s < 300:
        return "2xx"
    if 300 <= s < 400:
        return "3xx"
    if 400 <= s < 500:
        return "4xx"
    if 500 <= s < 600:
        return "5xx"
    return "other"


def _first(d: dict, *keys, default=None):
    """Return the first present, non-None field among keys (httpx JSON varies)."""
    for k in keys:
        if k in d and d[k] not in (None, ""):
            return d[k]
    return default


def _canon(s: str) -> str:
    """Canonicalize a header name: lowercase, strip non-alphanumerics.

    httpx normalizes header keys to snake_case ('content_security_policy'), so
    we compare on alphanumerics only to match 'Content-Security-Policy'.
    """
    return "".join(ch for ch in s.lower() if ch.isalnum())


def _parse_line(line: str) -> dict | None:
    try:
        d = json.loads(line)
    except json.JSONDecodeError:
        return None
    if d.get("failed"):
        return None  # httpx marks hosts it couldn't reach
    host = _first(d, "input", "url", default="")

    raw_headers = _first(d, "header", "headers", default={}) or {}
    headers: dict[str, str | None] = {}
    if isinstance(raw_headers, dict):
        canon = {_canon(k): v for k, v in raw_headers.items()}
        for h in SECURITY_HEADERS:
            headers[h] = canon.get(_canon(h))
    missing = [h for h in SECURITY_HEADERS if not headers.get(h)]

    status = _first(d, "status_code", "status-code")

    hash_field = d.get("hash") or {}
    body_hash = hash_field.get("body_sha256", "") if isinstance(hash_field, dict) else ""

    ip = d.get("host_ip") or ""
    if not ip and isinstance(d.get("a"), list) and d["a"]:
        ip = d["a"][0]

    return {
        "host": host,
        "url": _first(d, "url", default=""),
        "scheme": _first(d, "scheme", default=""),
        "status": status,
        "bucket": _bucket(status),
        "title": _first(d, "title", default=""),
        "webserver": _first(d, "webserver", "web_server", "server", default=""),
        "technologies": _first(d, "tech", "technologies", default=[]) or [],
        "content_length": _first(d, "content_length", "content-length"),
        "body_hash": body_hash,
        "cdn": _first(d, "cdn_name", "cdn", default=""),
        "location": _first(d, "location", default=""),
        "ip": ip,
        "headers": headers,
        "missing_headers": missing,
        "reachable": status is not None,
    }


@mcp.tool()
async def http_probe(target: str = "", source_file: str = SOURCE_DEFAULT,
                     auth: str = "") -> dict:
    """Probe hosts over HTTP(S) with httpx: liveness, tech, headers, dedup.

    One fast pass per host returns status + class bucket, title, web server,
    detected technologies, content length, body hash (for de-duplication),
    CDN, redirect location, and the security headers (→ missing-header
    findings). Responders are written to live_hosts.txt; full detail to
    http_probe.json.

    Args:
        target: Optional single host or comma-separated hosts. When empty, the
            host list is read from the workspace file.
        source_file: Workspace file to read hosts from when `target` is empty.
            Defaults to "subdomains.txt".
        auth: Optional raw HTTP header(s) for authenticated probing, e.g.
            "Cookie: session=…". Overrides RECONGURU_AUTH_HEADER. The toolkit
            never logs in.

    Returns:
        An envelope: probed/live counts, per-status-class buckets, content-hash
        duplicate groups, a tech summary, total missing-header findings, a
        sample, and the output file paths.
    """
    if target.strip():
        raw_hosts = [h.strip() for h in target.split(",") if h.strip()]
    else:
        raw_hosts = workspace.read_lines(source_file)
        if not raw_hosts:
            return {
                "ok": False,
                "error": (
                    f"no hosts: workspace file '{source_file}' is empty. "
                    "Run subdomain_enum first, or pass target=..."
                ),
            }

    hosts = scope.filter_in_scope(sorted(set(
        h.strip() for h in raw_hosts if h.strip()
    )))
    if not hosts:
        return {"ok": False, "error": "no valid, in-scope hosts to probe"}

    targets_path = workspace.write_lines(TARGETS_TMP, hosts)

    argv = [
        "httpx", "-l", str(targets_path),
        "-json", "-silent", "-no-color",
        "-status-code", "-content-length", "-title", "-tech-detect",
        "-web-server", "-location", "-cdn", "-hash", "sha256",
        "-include-response-header",
    ] + _auth.cli_args(auth)

    result = await run_tool(argv, timeout_s=settings.timeout_for("httpx"))
    if not result.ok and "not installed" in (result.note or ""):
        return {
            "ok": False,
            "error": "httpx binary not available — run in the Docker image",
            "note": result.note,
        }

    data: dict[str, dict] = {}
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        rec = _parse_line(line)
        if rec and rec["host"]:
            data[rec["host"]] = rec

    workspace.write_json(OUT_FILE, data)
    responders = sorted(h for h, r in data.items() if r["bucket"] != "dead")
    workspace.merge_lines(LIVE_FILE, responders)

    # Content-hash dedup: identical pages across different hosts (wildcard/CDN).
    by_hash: dict[str, list[str]] = {}
    for host, r in data.items():
        if r.get("body_hash"):
            by_hash.setdefault(r["body_hash"], []).append(host)
    dup_groups = [sorted(v) for v in by_hash.values() if len(v) > 1]

    buckets: dict[str, int] = {}
    for r in data.values():
        buckets[r["bucket"]] = buckets.get(r["bucket"], 0) + 1
    total_missing = sum(len(r["missing_headers"]) for r in data.values())
    tech_seen = sorted({t for r in data.values() for t in r["technologies"]})

    note_bits = []
    if dup_groups:
        note_bits.append(
            f"{len(dup_groups)} duplicate-content group(s) — likely wildcard/CDN"
        )
    if not result.ok and result.stdout.strip() == "":
        note_bits.append("httpx returned no output")

    return {
        "ok": True,
        "probed": len(hosts),
        "live": len(responders),
        "buckets": dict(sorted(buckets.items())),
        "duplicate_groups": dup_groups[:10],
        "technologies": tech_seen[:40],
        "total_missing_header_findings": total_missing,
        "output_file": str(workspace.path(OUT_FILE)),
        "live_file": str(workspace.path(LIVE_FILE)),
        "sample_live": responders[:20],
        "note": "; ".join(note_bits),
    }
